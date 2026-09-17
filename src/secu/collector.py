"""Pulls cowrie.json from the sensor and appends newly-arrived, complete
JSON lines into the local canonical event store (events.py).

Deliberately shells out to rsync/ssh via subprocess instead of using
paramiko: paramiko 5.0 doesn't declare Python 3.14 support, and rsync
is both simpler and does incremental transfer for free.

Idempotent: safe to run repeatedly (e.g. every 15 min via cron/launchd).
"""
from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path

from secu import events, statefile
from secu.config import DATA_DIR, settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("collector")

RAW_LOG_PATH = DATA_DIR / "raw" / "cowrie.json"


def pull_from_sensor() -> None:
    """rsync the remote cowrie.json down to RAW_LOG_PATH."""
    if not settings.sensor_host:
        raise SystemExit("SENSOR_HOST not set, copy .env.example to .env and fill it in")

    RAW_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    remote = f"{settings.sensor_ssh_user}@{settings.sensor_host}:{settings.sensor_cowrie_log_path}"
    ssh_cmd = f"ssh -i {settings.sensor_ssh_key} -p {settings.sensor_admin_port} -o StrictHostKeyChecking=accept-new"

    cmd = ["rsync", "-az", "-e", ssh_cmd, remote, str(RAW_LOG_PATH)]
    log.info("pulling: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        log.error("rsync failed: %s", result.stderr.strip())
        raise SystemExit(1)


def parse_new_lines() -> int:
    """Read RAW_LOG_PATH from the last committed byte offset, parse any
    complete (newline-terminated) JSON lines, append to the event store,
    and advance the offset. Leaves a trailing partial line for next run."""
    if not RAW_LOG_PATH.exists():
        log.warning("no local raw log yet at %s", RAW_LOG_PATH)
        return 0

    state = statefile.load("collector", {"offset": 0})
    offset = state.get("offset", 0)

    size = RAW_LOG_PATH.stat().st_size
    if size < offset:
        log.warning("raw log shrank (rotated?), resetting offset to 0")
        offset = 0

    new_events = []
    with RAW_LOG_PATH.open("rb") as f:
        f.seek(offset)
        chunk = f.read()

    text = chunk.decode("utf-8", errors="replace")
    lines = text.split("\n")
    # last element is either "" (file ended on a newline) or a partial line
    # we haven't fully received yet, so don't consume it.
    complete_lines, partial = lines[:-1], lines[-1]
    consumed_bytes = len(("\n".join(complete_lines) + "\n").encode("utf-8")) if complete_lines else 0

    import json
    for line in complete_lines:
        line = line.strip()
        if not line:
            continue
        try:
            new_events.append(json.loads(line))
        except json.JSONDecodeError:
            log.warning("skipping malformed line: %r", line[:120])

    events.append(new_events)
    statefile.save("collector", {"offset": offset + consumed_bytes})
    log.info("ingested %d new events (offset %d -> %d)", len(new_events), offset, offset + consumed_bytes)
    return len(new_events)


def main() -> None:
    pull_from_sensor()
    parse_new_lines()


if __name__ == "__main__":
    main()
