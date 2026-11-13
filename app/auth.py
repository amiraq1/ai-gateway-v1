from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Any

from .database import Database


def digest_key(raw_key: str, pepper: str) -> str:
    if len(pepper.encode("utf-8")) < 32:
        raise ValueError("GATEWAY_PEPPER must contain at least 32 bytes")
    return hmac.new(pepper.encode("utf-8"), raw_key.encode("utf-8"), hashlib.sha256).hexdigest()


def create_client_key(db: Database, pepper: str, name: str, rpm: int = 60, now: int | None = None) -> tuple[str, str]:
    client_id = secrets.token_hex(8)
    raw_key = f"gw_{client_id}.{secrets.token_urlsafe(32)}"
    db.add_client(client_id, digest_key(raw_key, pepper), name, rpm, now)
    return client_id, raw_key


def authenticate_key(db: Database, pepper: str, raw_key: str | None) -> dict[str, Any] | None:
    if not raw_key or len(raw_key) > 256 or not raw_key.startswith("gw_") or "." not in raw_key:
        return None
    client_id = raw_key[3:].split(".", 1)[0]
    if len(client_id) != 16 or any(ch not in "0123456789abcdef" for ch in client_id):
        return None
    try:
        expected = digest_key(raw_key, pepper)
    except ValueError:
        return None
    client = db.get_client(client_id)
    if not client or client["revoked_at"] is not None:
        return None
    if not hmac.compare_digest(expected, client["key_digest"]):
        return None
    return client


def make_request_log(client_id: str, model_alias: str, provider_name: str | None,
                     status_code: int, latency_ms: int, usage: dict[str, Any] | None,
                     error_category: str | None, retention_days: int) -> dict[str, Any]:
    usage = usage or {}
    return {
        "id": secrets.token_hex(16),
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "client_id": client_id,
        "model_alias": model_alias,
        "provider_name": provider_name,
        "status_code": int(status_code),
        "latency_ms": max(0, int(latency_ms)),
        "input_tokens": _valid_token_count(usage.get("prompt_tokens", usage.get("input_tokens"))),
        "output_tokens": _valid_token_count(usage.get("completion_tokens", usage.get("output_tokens"))),
        "total_tokens": _valid_token_count(usage.get("total_tokens")),
        "error_category": error_category,
        "retention_days": retention_days,
    }


def _valid_token_count(value: Any) -> int | None:
    return value if isinstance(value, int) and value >= 0 else None
