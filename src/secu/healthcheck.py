"""Routine health checks: is the sensor reachable, is cowrie.json growing,
is HEC accepting data, is the AbuseIPDB quota still available. Maps to the
JD's "routine health checks" and "validate data sources" lines.

Exits non-zero if anything is unhealthy, so it can be cron'd with alerting
bolted on later.
"""
from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone

import requests

from secu import statefile
from secu.config import DATA_DIR, settings

RAW_LOG_PATH = DATA_DIR / "raw" / "cowrie.json"


def check_sensor_reachable() -> tuple[bool, str]:
    if not settings.sensor_host:
        return False, "SENSOR_HOST not configured"
    result = subprocess.run(
        [
            "ssh", "-i", settings.sensor_ssh_key, "-p", settings.sensor_admin_port,
            "-o", "ConnectTimeout=8", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            f"{settings.sensor_ssh_user}@{settings.sensor_host}", "echo ok",
        ],
        capture_output=True, text=True, timeout=15,
    )
    return result.returncode == 0, result.stderr.strip() or "reachable"


def check_local_log_growing() -> tuple[bool, str]:
    if not RAW_LOG_PATH.exists():
        return False, "no local mirror yet -- run collector.py first"
    state = statefile.load("healthcheck", {"last_size": 0, "last_check": None})
    size = RAW_LOG_PATH.stat().st_size
    grew = size > state["last_size"]
    statefile.save("healthcheck", {"last_size": size, "last_check": datetime.now(timezone.utc).isoformat()})
    if state["last_check"] is None:
        return True, f"baseline established at {size} bytes"
    return grew, f"{state['last_size']} -> {size} bytes since last check"


def check_hec_accepting() -> tuple[bool, str]:
    if not settings.splunk_hec_token:
        return False, "SPLUNK_HEC_TOKEN not configured"
    health_url = settings.splunk_hec_url.replace("/services/collector", "/services/collector/health")
    try:
        resp = requests.get(health_url, verify=settings.splunk_verify_tls, timeout=10)
        return resp.status_code == 200, f"HTTP {resp.status_code}"
    except requests.RequestException as e:
        return False, str(e)


def check_abuseipdb_quota() -> tuple[bool, str]:
    budget = statefile.load("abuseipdb_budget", {"date": "", "used": 0})
    from secu.enrich import ABUSEIPDB_DAILY_BUDGET
    remaining = ABUSEIPDB_DAILY_BUDGET - budget["used"]
    return remaining > 0, f"{remaining}/{ABUSEIPDB_DAILY_BUDGET} remaining today"


def main() -> None:
    checks = {
        "sensor_reachable": check_sensor_reachable,
        "local_log_growing": check_local_log_growing,
        "hec_accepting": check_hec_accepting,
        "abuseipdb_quota": check_abuseipdb_quota,
    }
    all_ok = True
    for name, check in checks.items():
        ok, detail = check()
        all_ok &= ok
        print(f"[{'OK' if ok else 'FAIL'}] {name}: {detail}")

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
