"""Ships new events from the canonical local store to Splunk over HEC.
Splunk is never internet-exposed (see docs/decisions/0001) -- this is a
pull-then-push: collector.py pulls from the sensor, this pushes to
Splunk running in local Docker.

Tracks a line-count cursor in state/ so re-runs only ship what's new.
"""
from __future__ import annotations

import logging
from datetime import datetime

import requests

from secu import events, statefile
from secu.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ship")

BATCH_SIZE = 500


def _epoch(e: dict) -> float | None:
    ts = e.get("timestamp")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _hec_batch(batch: list[dict]) -> None:
    body = "".join(
        __import__("json").dumps({
            "event": e,
            "sourcetype": "cowrie:json",
            "index": settings.splunk_index,
            **({"time": _epoch(e)} if _epoch(e) else {}),
        })
        for e in batch
    )
    resp = requests.post(
        settings.splunk_hec_url,
        headers={"Authorization": f"Splunk {settings.splunk_hec_token}"},
        data=body,
        verify=settings.splunk_verify_tls,
        timeout=30,
    )
    resp.raise_for_status()


def ship_new() -> int:
    if not settings.splunk_hec_token:
        raise SystemExit("SPLUNK_HEC_TOKEN not set -- copy .env.example to .env and fill it in")

    state = statefile.load("ship", {"line_count": 0})
    already_shipped = state["line_count"]

    all_events = list(events.read_all())
    new_events = all_events[already_shipped:]

    shipped = 0
    for i in range(0, len(new_events), BATCH_SIZE):
        batch = new_events[i:i + BATCH_SIZE]
        _hec_batch(batch)
        shipped += len(batch)

    statefile.save("ship", {"line_count": already_shipped + shipped})
    log.info("shipped %d new events (%d total shipped)", shipped, already_shipped + shipped)
    return shipped


def main() -> None:
    ship_new()


if __name__ == "__main__":
    main()
