"""Tiny helper for the JSON state files under state/. Not a class hierarchy --
just load/save so every script agrees on the format and nobody hand-rolls
their own json.load/dump with different defaults."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from secu.config import STATE_DIR


def load(name: str, default: Any) -> Any:
    path = STATE_DIR / f"{name}.json"
    if not path.exists():
        return default
    return json.loads(path.read_text())


def save(name: str, value: Any) -> None:
    path = STATE_DIR / f"{name}.json"
    path.write_text(json.dumps(value, indent=2, default=str))
