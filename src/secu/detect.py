"""Detection rules over the canonical event store, plus two original
analyses that go beyond a generic honeypot writeup:

  - botnet family clustering (credential-set + client-version similarity)
  - Mirai credential-list provenance (% of attempts matching Mirai's
    publicly documented hardcoded table)

Findings: {rule_id, severity, src_ip, evidence, attack_technique, first_seen, last_seen}
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta

from secu import events, statefile

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("detect")

BRUTE_FORCE_THRESHOLD = 20
BRUTE_FORCE_WINDOW = timedelta(minutes=10)
SPRAY_MIN_USERNAMES = 5
CLUSTER_JACCARD_THRESHOLD = 0.5
DOWNLOAD_COMMAND_PATTERNS = ("wget", "curl", "tftp", "ftpget")

# A representative subset of Mirai's publicly documented hardcoded
# credential table (widely published since the 2016 source leak).
MIRAI_CREDENTIALS = {
    ("root", "xc3511"), ("root", "vizxv"), ("root", "admin"),
    ("admin", "admin"), ("root", "888888"), ("root", "xmhdipc"),
    ("root", "default"), ("root", "juantech"), ("root", "123456"),
    ("root", "54321"), ("support", "support"), ("root", "root"),
    ("root", "12345"), ("user", "user"), ("admin", "password"),
    ("root", "pass"), ("admin", "admin1234"), ("root", "1234"),
    ("guest", "guest"), ("root", "klv123"), ("Administrator", "admin"),
    ("service", "service"), ("root", "666666"), ("root", "password"),
    ("root", "1111"), ("admin", "1111111"), ("tech", "tech"),
    ("mother", "fucker"),
}


def _parse_ts(e: dict) -> datetime | None:
    ts = e.get("timestamp")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _load_events() -> list[dict]:
    evs = [e for e in events.read_all() if _parse_ts(e)]
    evs.sort(key=_parse_ts)
    return evs


def detect_brute_force(evs: list[dict]) -> list[dict]:
    findings = []
    by_ip = defaultdict(list)
    for e in evs:
        if e.get("eventid") == "cowrie.login.failed":
            by_ip[e["src_ip"]].append(_parse_ts(e))

    for ip, timestamps in by_ip.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            window = [t for t in timestamps[i:] if t - timestamps[i] <= BRUTE_FORCE_WINDOW]
            if len(window) >= BRUTE_FORCE_THRESHOLD:
                findings.append({
                    "rule_id": "BRUTE_FORCE",
                    "severity": "medium",
                    "src_ip": ip,
                    "evidence": f"{len(window)} failed logins within {BRUTE_FORCE_WINDOW}",
                    "attack_technique": "T1110.001",
                    "first_seen": timestamps[i].isoformat(),
                    "last_seen": window[-1].isoformat(),
                })
                break
    return findings


def detect_password_spray(evs: list[dict]) -> list[dict]:
    findings = []
    by_ip_password: dict[tuple[str, str], set[str]] = defaultdict(set)
    timespans: dict[tuple[str, str], list[datetime]] = defaultdict(list)

    for e in evs:
        if e.get("eventid") in ("cowrie.login.failed", "cowrie.login.success"):
            ip, pw, user = e.get("src_ip"), e.get("password"), e.get("username")
            if ip and pw and user:
                by_ip_password[(ip, pw)].add(user)
                timespans[(ip, pw)].append(_parse_ts(e))

    for (ip, pw), usernames in by_ip_password.items():
        if len(usernames) >= SPRAY_MIN_USERNAMES:
            ts = sorted(timespans[(ip, pw)])
            findings.append({
                "rule_id": "PASSWORD_SPRAY",
                "severity": "medium",
                "src_ip": ip,
                "evidence": f"password '{pw}' tried against {len(usernames)} distinct usernames",
                "attack_technique": "T1110.003",
                "first_seen": ts[0].isoformat(),
                "last_seen": ts[-1].isoformat(),
            })
    return findings


def detect_successful_logins(evs: list[dict]) -> list[dict]:
    findings = []
    for e in evs:
        if e.get("eventid") == "cowrie.login.success":
            ts = _parse_ts(e)
            findings.append({
                "rule_id": "SUCCESSFUL_LOGIN",
                "severity": "high",
                "src_ip": e.get("src_ip"),
                "evidence": f"login succeeded as {e.get('username')!r}/{e.get('password')!r}",
                "attack_technique": "T1078",
                "first_seen": ts.isoformat(),
                "last_seen": ts.isoformat(),
            })
    return findings


def detect_post_exploit(evs: list[dict]) -> list[dict]:
    """Command execution and payload staging within sessions that had a
    successful login."""
    by_session = defaultdict(list)
    for e in evs:
        sess = e.get("session")
        if sess:
            by_session[sess].append(e)

    findings = []
    for sess, sess_events in by_session.items():
        success_ts = next(
            (_parse_ts(e) for e in sess_events if e.get("eventid") == "cowrie.login.success"),
            None,
        )
        if not success_ts:
            continue

        for e in sess_events:
            ts = _parse_ts(e)
            if not ts or ts < success_ts:
                continue

            if e.get("eventid") == "cowrie.command.input":
                cmd = e.get("input", "")
                is_download = any(p in cmd for p in DOWNLOAD_COMMAND_PATTERNS)
                findings.append({
                    "rule_id": "PAYLOAD_STAGING" if is_download else "POST_EXPLOIT_EXEC",
                    "severity": "high",
                    "src_ip": e.get("src_ip"),
                    "evidence": f"session {sess}: {cmd!r}",
                    "attack_technique": "T1105" if is_download else "T1059.004",
                    "first_seen": ts.isoformat(),
                    "last_seen": ts.isoformat(),
                })
            elif e.get("eventid") == "cowrie.session.file_download":
                findings.append({
                    "rule_id": "PAYLOAD_STAGING",
                    "severity": "high",
                    "src_ip": e.get("src_ip"),
                    "evidence": f"session {sess}: downloaded {e.get('url', e.get('shasum', 'unknown'))}",
                    "attack_technique": "T1105",
                    "first_seen": ts.isoformat(),
                    "last_seen": ts.isoformat(),
                })
    return findings


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def analyze_botnet_clusters(evs: list[dict]) -> list[dict]:
    """Group source IPs by overlap in attempted (username,password) pairs
    and SSH client version string, to estimate distinct campaigns rather
    than just counting IPs."""
    creds_by_ip: dict[str, set[tuple[str, str]]] = defaultdict(set)
    version_by_ip: dict[str, str] = {}

    for e in evs:
        ip = e.get("src_ip")
        if not ip:
            continue
        if e.get("eventid") in ("cowrie.login.failed", "cowrie.login.success"):
            u, p = e.get("username"), e.get("password")
            if u and p:
                creds_by_ip[ip].add((u, p))
        if e.get("eventid") == "cowrie.client.version":
            version_by_ip[ip] = e.get("version", "")

    ips = list(creds_by_ip.keys())
    parent = {ip: ip for ip in ips}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for i, ip_a in enumerate(ips):
        for ip_b in ips[i + 1:]:
            sim = _jaccard(creds_by_ip[ip_a], creds_by_ip[ip_b])
            same_version = version_by_ip.get(ip_a) and version_by_ip.get(ip_a) == version_by_ip.get(ip_b)
            if sim >= CLUSTER_JACCARD_THRESHOLD or same_version:
                union(ip_a, ip_b)

    clusters = defaultdict(list)
    for ip in ips:
        clusters[find(ip)].append(ip)

    return [
        {
            "cluster_id": root,
            "member_ips": sorted(members),
            "size": len(members),
            "sample_client_version": version_by_ip.get(root, ""),
        }
        for root, members in sorted(clusters.items(), key=lambda kv: -len(kv[1]))
    ]


def analyze_mirai_provenance(evs: list[dict]) -> dict:
    """What fraction of observed (username,password) attempts match
    Mirai's publicly documented hardcoded credential table."""
    total = 0
    matches = 0
    for e in evs:
        if e.get("eventid") not in ("cowrie.login.failed", "cowrie.login.success"):
            continue
        u, p = e.get("username"), e.get("password")
        if u is None or p is None:
            continue
        total += 1
        if (u, p) in MIRAI_CREDENTIALS:
            matches += 1

    pct = (matches / total * 100) if total else 0.0
    return {"total_attempts": total, "mirai_matches": matches, "mirai_match_pct": round(pct, 1)}


def run_all() -> dict:
    evs = _load_events()
    findings = (
        detect_brute_force(evs)
        + detect_password_spray(evs)
        + detect_successful_logins(evs)
        + detect_post_exploit(evs)
    )
    result = {
        "findings": findings,
        "botnet_clusters": analyze_botnet_clusters(evs),
        "mirai_provenance": analyze_mirai_provenance(evs),
    }
    statefile.save("findings", result)
    log.info(
        "%d findings, %d clusters, mirai match %.1f%%",
        len(findings), len(result["botnet_clusters"]), result["mirai_provenance"]["mirai_match_pct"],
    )
    return result


def main() -> None:
    run_all()


if __name__ == "__main__":
    main()
