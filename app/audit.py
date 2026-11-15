from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping
from typing import Any

from .clock import now_epoch

_ACTION = re.compile(r"[a-z0-9_.]{1,96}")
_METADATA_KEY = re.compile(r"[a-z_]{1,40}")
_MAX_TARGET_LENGTH = 256
_MAX_USER_AGENT_LENGTH = 512
_MAX_IP_LENGTH = 64
_MAX_METADATA_VALUE_LENGTH = 128
# Metadata keys that could carry credentials or user content are refused even when a caller passes them.
_FORBIDDEN_KEY_PARTS = (
    "password", "passwd", "secret", "token", "pepper", "api_key", "apikey",
    "prompt", "content", "message",
)


def _encode_metadata(metadata: Mapping[str, Any] | None) -> str | None:
    if not metadata:
        return None
    clean: dict[str, Any] = {}
    for key, value in metadata.items():
        if not _METADATA_KEY.fullmatch(key) or any(part in key for part in _FORBIDDEN_KEY_PARTS):
            raise ValueError("audit metadata key is not allowed")
        if value is None or isinstance(value, (bool, int)):
            clean[key] = value
        elif isinstance(value, str) and len(value) <= _MAX_METADATA_VALUE_LENGTH:
            clean[key] = value
        else:
            raise ValueError("audit metadata value is not allowed")
    return json.dumps(clean, sort_keys=True, separators=(",", ":"))


def record_audit_event(
    conn: sqlite3.Connection,
    *,
    action: str,
    admin_user_id: int | None = None,
    target: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    metadata: Mapping[str, Any] | None = None,
    now: int | None = None,
) -> None:
    """Append one audit row. Callers pass identifiers and reasons only, never credentials or content."""
    if not _ACTION.fullmatch(action):
        raise ValueError("invalid audit action")
    if target is not None and len(target) > _MAX_TARGET_LENGTH:
        raise ValueError("audit target is too long")
    conn.execute(
        "INSERT INTO audit_logs(admin_user_id, action, target, ip_address, user_agent, created_at, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            admin_user_id,
            action,
            target,
            ip_address[:_MAX_IP_LENGTH] if ip_address else None,
            user_agent[:_MAX_USER_AGENT_LENGTH] if user_agent else None,
            now_epoch() if now is None else now,
            _encode_metadata(metadata),
        ),
    )
