"""Central config, loaded from .env. Every other module imports from here
instead of reading os.environ directly."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(REPO_ROOT / ".env")

DATA_DIR = REPO_ROOT / "data"
STATE_DIR = REPO_ROOT / "state"
FINDINGS_DIR = REPO_ROOT / "docs" / "findings"
for d in (DATA_DIR, STATE_DIR, FINDINGS_DIR):
    d.mkdir(parents=True, exist_ok=True)


def _bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _list(name: str) -> list[str]:
    val = os.environ.get(name, "")
    return [p.strip() for p in val.split(",") if p.strip()]


@dataclass(frozen=True)
class Settings:
    # sensor
    sensor_host: str = os.environ.get("SENSOR_HOST", "")
    sensor_admin_port: str = os.environ.get("SENSOR_ADMIN_PORT", "52222")
    sensor_ssh_user: str = os.environ.get("SENSOR_SSH_USER", "ubuntu")
    sensor_ssh_key: str = os.environ.get("SENSOR_SSH_KEY", "")
    sensor_cowrie_log_path: str = os.environ.get("SENSOR_COWRIE_LOG_PATH", "")

    # splunk
    splunk_hec_url: str = os.environ.get("SPLUNK_HEC_URL", "https://localhost:8088/services/collector")
    splunk_hec_token: str = os.environ.get("SPLUNK_HEC_TOKEN", "")
    splunk_index: str = os.environ.get("SPLUNK_INDEX", "honeypot")
    splunk_verify_tls: bool = field(default_factory=lambda: _bool("SPLUNK_VERIFY_TLS", False))

    # threat intel
    abuseipdb_api_key: str = os.environ.get("ABUSEIPDB_API_KEY", "")

    # responder
    aws_region: str = os.environ.get("AWS_REGION", "us-east-1")
    aws_profile: str = os.environ.get("AWS_PROFILE", "")
    responder_nacl_id: str = os.environ.get("RESPONDER_NACL_ID", "")
    responder_allowlist: list[str] = field(default_factory=lambda: _list("RESPONDER_ALLOWLIST"))
    responder_max_rules: int = int(os.environ.get("RESPONDER_MAX_RULES", "18"))
    responder_block_ttl_hours: int = int(os.environ.get("RESPONDER_BLOCK_TTL_HOURS", "24"))


settings = Settings()
