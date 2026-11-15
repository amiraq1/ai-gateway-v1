"""Server-side admin sessions.

Only SHA-256 hashes of session and CSRF tokens are stored. Raw tokens leave the
server once, in the Set-Cookie header (session) or a JSON body (CSRF token).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Any

from .clock import now_epoch

SESSION_COOKIE_NAME = "amnabd_admin_session"
SESSION_COOKIE_PATH = "/api/admin"
TOKEN_BYTES = 32  # 256 bits of randomness per token
LAST_SEEN_WRITE_INTERVAL_SECONDS = 60
_MAX_PRESENTED_TOKEN_LENGTH = 128
_MAX_PRESENTED_CSRF_LENGTH = 128


@dataclass(frozen=True)
class IssuedSession:
    session_id: int
    token: str
    csrf_token: str
    expires_at: int

    def __repr__(self) -> str:  # never print raw tokens in logs or tracebacks
        return f"IssuedSession(session_id={self.session_id}, expires_at={self.expires_at})"


@dataclass(frozen=True)
class SessionRecord:
    session_id: int
    admin_user_id: int
    username: str
    expires_at: int
    last_seen_at: int
    csrf_token_hash: str


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def create_session(
    conn: sqlite3.Connection,
    *,
    admin_user_id: int,
    ttl_seconds: int,
    ip_address: str | None,
    user_agent: str | None,
    now: int | None = None,
) -> IssuedSession:
    if ttl_seconds < 1:
        raise ValueError("session ttl must be positive")
    issued_at = now_epoch() if now is None else now
    token = secrets.token_urlsafe(TOKEN_BYTES)
    csrf_token = secrets.token_urlsafe(TOKEN_BYTES)
    expires_at = issued_at + ttl_seconds
    cursor = conn.execute(
        "INSERT INTO user_sessions(admin_user_id, token_hash, csrf_token_hash, created_at, expires_at, "
        "last_seen_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            admin_user_id,
            hash_token(token),
            hash_token(csrf_token),
            issued_at,
            expires_at,
            issued_at,
            ip_address[:64] if ip_address else None,
            user_agent[:512] if user_agent else None,
        ),
    )
    # Expired rows can never authenticate again; removing them keeps the table bounded.
    conn.execute("DELETE FROM user_sessions WHERE expires_at <= ?", (issued_at,))
    return IssuedSession(int(cursor.lastrowid or 0), token, csrf_token, expires_at)


def resolve_session(
    conn: sqlite3.Connection,
    token: str | None,
    *,
    idle_seconds: int,
    now: int | None = None,
) -> SessionRecord | None:
    """Return the active session for a raw cookie value, or None if it is missing, expired, revoked, or idle."""
    if not token or len(token) > _MAX_PRESENTED_TOKEN_LENGTH:
        return None
    current = now_epoch() if now is None else now
    row = conn.execute(
        "SELECT s.id AS session_id, s.admin_user_id AS admin_user_id, u.username AS username, "
        "s.expires_at AS expires_at, s.last_seen_at AS last_seen_at, s.csrf_token_hash AS csrf_token_hash "
        "FROM user_sessions AS s JOIN admin_users AS u ON u.id = s.admin_user_id "
        "WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND u.is_active = 1",
        (hash_token(token), current),
    ).fetchone()
    if row is None:
        return None
    idle_for = current - int(row["last_seen_at"])
    if idle_for > idle_seconds:
        return None
    if idle_for >= LAST_SEEN_WRITE_INTERVAL_SECONDS:
        # Written at most once per interval, so ordinary requests do not cause a write each time.
        conn.execute("UPDATE user_sessions SET last_seen_at = ? WHERE id = ?", (current, row["session_id"]))
    return SessionRecord(
        session_id=int(row["session_id"]),
        admin_user_id=int(row["admin_user_id"]),
        username=str(row["username"]),
        expires_at=int(row["expires_at"]),
        last_seen_at=current if idle_for >= LAST_SEEN_WRITE_INTERVAL_SECONDS else int(row["last_seen_at"]),
        csrf_token_hash=str(row["csrf_token_hash"]),
    )


def rotate_csrf_token(conn: sqlite3.Connection, session_id: int) -> str:
    """Replace a session's CSRF token and return the new raw value.

    The raw value is returned to the authenticated caller only. Earlier CSRF
    tokens for this session stop working after rotation.
    """
    csrf_token = secrets.token_urlsafe(TOKEN_BYTES)
    conn.execute("UPDATE user_sessions SET csrf_token_hash = ? WHERE id = ? AND revoked_at IS NULL",
                 (hash_token(csrf_token), session_id))
    return csrf_token


def verify_csrf_token(record: SessionRecord, presented: str | None) -> bool:
    if not presented or len(presented) > _MAX_PRESENTED_CSRF_LENGTH:
        return False
    return hmac.compare_digest(hash_token(presented), record.csrf_token_hash)


def revoke_session(conn: sqlite3.Connection, token: str | None, now: int | None = None) -> bool:
    if not token or len(token) > _MAX_PRESENTED_TOKEN_LENGTH:
        return False
    revoked_at = now_epoch() if now is None else now
    cursor = conn.execute("UPDATE user_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
                          (revoked_at, hash_token(token)))
    return cursor.rowcount == 1


def revoke_user_sessions(conn: sqlite3.Connection, admin_user_id: int, now: int | None = None) -> int:
    revoked_at = now_epoch() if now is None else now
    cursor = conn.execute("UPDATE user_sessions SET revoked_at = ? WHERE admin_user_id = ? AND revoked_at IS NULL",
                          (revoked_at, admin_user_id))
    return int(cursor.rowcount)


SESSION_COOKIE_OPTIONS: dict[str, Any] = {
    "path": SESSION_COOKIE_PATH,
    "secure": True,
    "httponly": True,
    "samesite": "lax",
}
