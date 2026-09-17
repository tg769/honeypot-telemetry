"""Threat-intel enrichment for observed source IPs.

Sources (see docs/decisions/0005-threat-intel-sources.md for why these two
and not GreyNoise):
  - Shodan InternetDB: no key, no rate limit, open ports/CVEs/tags.
  - AbuseIPDB: free key, budgeted at 1000 checks/day.

Disk-cached by IP with a TTL so a re-run never re-queries a known IP --
this is the "cleaning up findings / removing manual effort" piece.
"""
from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timedelta, timezone

import requests

from secu import events, statefile
from secu.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("enrich")

CACHE_TTL = timedelta(days=7)
ABUSEIPDB_DAILY_BUDGET = 900  # headroom under the 1000/day free-tier limit


def _cache_key() -> dict:
    return statefile.load("enrich_cache", {})


def _fresh(entry: dict | None) -> bool:
    if not entry or "fetched_at" not in entry:
        return False
    fetched = datetime.fromisoformat(entry["fetched_at"])
    return datetime.now(timezone.utc) - fetched < CACHE_TTL


def _query_internetdb(ip: str) -> dict | None:
    try:
        resp = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 404:
            return {}  # no data on this IP, not an error
        log.warning("internetdb %s -> HTTP %d", ip, resp.status_code)
    except requests.RequestException as e:
        log.warning("internetdb %s failed: %s", ip, e)
    return None


def _query_abuseipdb(ip: str) -> dict | None:
    if not settings.abuseipdb_api_key:
        return None
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json().get("data", {})
        log.warning("abuseipdb %s -> HTTP %d", ip, resp.status_code)
    except requests.RequestException as e:
        log.warning("abuseipdb %s failed: %s", ip, e)
    return None


def _today_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def enrich_all(limit: int | None = None) -> dict[str, dict]:
    """Enrich every distinct src_ip seen so far, most-frequent first.
    Returns the full cache (ip -> enrichment dict)."""
    counts = Counter(e.get("src_ip") for e in events.read_all() if e.get("src_ip"))
    ordered_ips = [ip for ip, _ in counts.most_common(limit)]

    cache = _cache_key()
    budget_state = statefile.load("abuseipdb_budget", {"date": _today_key(), "used": 0})
    if budget_state["date"] != _today_key():
        budget_state = {"date": _today_key(), "used": 0}

    for ip in ordered_ips:
        entry = cache.get(ip)
        if _fresh(entry):
            continue

        internetdb = _query_internetdb(ip)
        abuseipdb = None
        if budget_state["used"] < ABUSEIPDB_DAILY_BUDGET:
            abuseipdb = _query_abuseipdb(ip)
            if abuseipdb is not None:
                budget_state["used"] += 1

        cache[ip] = {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "internetdb": internetdb or {},
            "abuseipdb": abuseipdb or {},
            "event_count": counts[ip],
        }

    statefile.save("enrich_cache", cache)
    statefile.save("abuseipdb_budget", budget_state)
    log.info(
        "enriched %d/%d distinct IPs (abuseipdb calls today: %d/%d)",
        len(ordered_ips), len(counts), budget_state["used"], ABUSEIPDB_DAILY_BUDGET,
    )
    return cache


def main() -> None:
    enrich_all()


if __name__ == "__main__":
    main()
