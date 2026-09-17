"""Scored, capped, TTL'd auto-blocklist. See docs/decisions/0004 for why
dry-run is the default and docs/decisions/0003 for why this targets a NACL
rather than a Security Group.

AWS Security Groups are allow-only, so blocking requires NACL deny entries,
and a NACL caps out around 20 rules by default. With thousands of observed
attacker IPs and ~18 usable slots, this forces real design: score every
candidate, keep only the top N, evict the lowest-scored on contention, and
expire blocks after a TTL so the list stays current.

Blocking on the sensor itself would cut off the data the sensor exists to
collect, so `--enforce` is required to mutate anything; without it this
only writes to the audit log what it *would* do.
"""
from __future__ import annotations

import argparse
import ipaddress
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from secu import statefile
from secu.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("respond")

RULE_NUMBER_BASE = 100

FINDING_WEIGHTS = {
    "SUCCESSFUL_LOGIN": 40,
    "POST_EXPLOIT_EXEC": 35,
    "PAYLOAD_STAGING": 35,
    "PASSWORD_SPRAY": 15,
    "BRUTE_FORCE": 10,
}


def _is_allowlisted(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return True
    for cidr in settings.responder_allowlist:
        if addr in ipaddress.ip_network(cidr, strict=False):
            return True
    return False


def compute_scores(findings: list[dict], enrich_cache: dict[str, dict]) -> dict[str, float]:
    scores: dict[str, float] = defaultdict(float)
    for f in findings:
        ip = f.get("src_ip")
        if ip:
            scores[ip] += FINDING_WEIGHTS.get(f["rule_id"], 5)

    for ip, entry in enrich_cache.items():
        confidence = entry.get("abuseipdb", {}).get("abuseConfidenceScore")
        if confidence:
            scores[ip] += confidence * 0.3  # weighted down, not 1:1; our own findings lead

    return dict(scores)


def rank_candidates(scores: dict[str, float]) -> list[str]:
    ranked = [ip for ip, _ in sorted(scores.items(), key=lambda kv: -kv[1])]
    return [ip for ip in ranked if not _is_allowlisted(ip)]


def _load_active() -> dict[str, dict]:
    return statefile.load("responder_blocks", {})


def _audit(action: str, ip: str, extra: dict | None = None) -> None:
    from secu.config import STATE_DIR
    entry = {"ts": datetime.now(timezone.utc).isoformat(), "action": action, "ip": ip, **(extra or {})}
    path = STATE_DIR / "audit.jsonl"
    with path.open("a") as f:
        import json
        f.write(json.dumps(entry) + "\n")


def reconcile(candidates: list[str], scores: dict[str, float]) -> dict:
    """Decide what should be blocked given current active blocks, the
    ranked candidate list, and the rule-number cap. Returns a plan, does
    not touch AWS."""
    active = _load_active()
    now = datetime.now(timezone.utc)

    expired = [ip for ip, b in active.items() if datetime.fromisoformat(b["expires_at"]) < now]
    to_add: list[str] = []
    to_evict: list[str] = list(expired)

    still_active = {ip: b for ip, b in active.items() if ip not in expired}
    top_n = candidates[: settings.responder_max_rules]

    for ip in top_n:
        if ip not in still_active:
            to_add.append(ip)

    # if adding would exceed the cap, evict the lowest-scored currently-active
    # entries not already being evicted, to make room. highest priority wins.
    projected_count = len(still_active) - len(to_evict) + len(to_add)
    if projected_count > settings.responder_max_rules:
        overflow = projected_count - settings.responder_max_rules
        evictable = sorted(
            (ip for ip in still_active if ip not in to_evict),
            key=lambda ip: scores.get(ip, 0),
        )
        to_evict.extend(evictable[:overflow])

    return {"to_add": to_add, "to_evict": to_evict, "active_before": active}


def _next_free_rule_number(active: dict[str, dict]) -> int | None:
    used = {b["rule_number"] for b in active.values()}
    pool = range(RULE_NUMBER_BASE, RULE_NUMBER_BASE + settings.responder_max_rules)
    for n in pool:
        if n not in used:
            return n
    return None


def apply_plan(plan: dict, scores: dict[str, float], enforce: bool) -> None:
    import boto3

    active = dict(plan["active_before"])
    client = None
    if enforce:
        session = boto3.Session(profile_name=settings.aws_profile or None, region_name=settings.aws_region)
        client = session.client("ec2")

    for ip in plan["to_evict"]:
        block = active.get(ip)
        if not block:
            continue
        if enforce and client:
            client.delete_network_acl_entry(
                NetworkAclId=settings.responder_nacl_id,
                RuleNumber=block["rule_number"],
                Egress=False,
            )
        _audit("evict" if enforce else "evict_dry_run", ip, {"rule_number": block["rule_number"]})
        active.pop(ip, None)

    ttl_expiry = datetime.now(timezone.utc) + timedelta(hours=settings.responder_block_ttl_hours)
    for ip in plan["to_add"]:
        rule_number = _next_free_rule_number(active)
        if rule_number is None:
            _audit("skip_no_slot", ip)
            continue
        if enforce and client:
            client.create_network_acl_entry(
                NetworkAclId=settings.responder_nacl_id,
                RuleNumber=rule_number,
                Protocol="-1",
                RuleAction="deny",
                Egress=False,
                CidrBlock=f"{ip}/32",
            )
        active[ip] = {
            "rule_number": rule_number,
            "score": scores.get(ip, 0),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": ttl_expiry.isoformat(),
        }
        _audit("block" if enforce else "block_dry_run", ip, {"rule_number": rule_number, "score": scores.get(ip, 0)})

    statefile.save("responder_blocks", active)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enforce", action="store_true", help="actually mutate the AWS NACL (default: dry-run)")
    args = parser.parse_args()

    findings_data = statefile.load("findings", {"findings": []})
    enrich_cache = statefile.load("enrich_cache", {})

    scores = compute_scores(findings_data.get("findings", []), enrich_cache)
    candidates = rank_candidates(scores)
    plan = reconcile(candidates, scores)

    log.info(
        "%s: %d to add, %d to evict (of %d candidates, %d already active)",
        "ENFORCING" if args.enforce else "DRY RUN",
        len(plan["to_add"]), len(plan["to_evict"]), len(candidates), len(plan["active_before"]),
    )
    apply_plan(plan, scores, enforce=args.enforce)


if __name__ == "__main__":
    main()
