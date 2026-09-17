"""Canonical local event store: data/events.ndjson. Every pipeline stage
(enrich/detect/ship/report) reads from here rather than touching the raw
sensor mirror directly."""
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from secu.config import DATA_DIR

EVENTS_PATH = DATA_DIR / "events.ndjson"


def append(events: list[dict]) -> None:
    if not events:
        return
    with EVENTS_PATH.open("a") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def read_all() -> Iterator[dict]:
    if not EVENTS_PATH.exists():
        return
    with EVENTS_PATH.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
