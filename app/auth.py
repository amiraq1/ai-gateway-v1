from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .audit import record_audit_event
from .clock import now_epoch
from .database import Database
from .sessions import IssuedSession, create_session, revoke_user_sessions


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


# ---------------------------------------------------------------------------
# Administrator accounts: Argon2id passwords, bootstrap, and login.
# ---------------------------------------------------------------------------

ADMIN_PASSWORD_MIN_LENGTH = 12
ADMIN_PASSWORD_MAX_LENGTH = 1024
_USERNAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")
_PASSWORD_HASHER = PasswordHasher()  # Argon2id with the argon2-cffi default cost parameters
_dummy_hash_cache: str | None = None


class AdminBootstrapError(Exception):
    """Bootstrap was refused, for example because an administrator already exists."""


def normalize_admin_username(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid username")
    normalized = value.strip().lower()
    if not _USERNAME_PATTERN.fullmatch(normalized):
        raise ValueError("invalid username")
    return normalized


def validate_admin_password(password: str, username: str) -> None:
    if not isinstance(password, str):
        raise ValueError("password must be a string")
    if len(password) < ADMIN_PASSWORD_MIN_LENGTH:
        raise ValueError(f"password must be at least {ADMIN_PASSWORD_MIN_LENGTH} characters")
    if len(password) > ADMIN_PASSWORD_MAX_LENGTH:
        raise ValueError("password is too long")
    if password.strip() != password or password.lower() == username.lower():
        raise ValueError("password is not acceptable")


def hash_admin_password(password: str) -> str:
    return _PASSWORD_HASHER.hash(password)


def verify_admin_password(stored_hash: str, candidate: str) -> bool:
    try:
        return _PASSWORD_HASHER.verify(stored_hash, candidate)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _dummy_hash() -> str:
    """A valid hash that never matches, so unknown users cost the same as known ones."""
    global _dummy_hash_cache
    if _dummy_hash_cache is None:
        _dummy_hash_cache = _PASSWORD_HASHER.hash(secrets.token_urlsafe(24))
    return _dummy_hash_cache


def bootstrap_first_admin(db: Database, username: str, password: str, now: int | None = None) -> int:
    """Create the first administrator. Refused whenever any administrator row already exists."""
    name = normalize_admin_username(username)
    validate_admin_password(password, name)
    password_hash = hash_admin_password(password)
    current = now_epoch() if now is None else now
    with db.transaction() as conn:
        existing = conn.execute("SELECT count(*) FROM admin_users").fetchone()[0]
        if existing:
            raise AdminBootstrapError("an administrator already exists")
        cursor = conn.execute(
            "INSERT INTO admin_users(username, password_hash, is_active, created_at, updated_at) VALUES (?, ?, 1, ?, ?)",
            (name, password_hash, current, current),
        )
        admin_id = int(cursor.lastrowid or 0)
        record_audit_event(conn, action="admin.bootstrap", admin_user_id=admin_id,
                           target=f"admin_user:{admin_id}", user_agent="local-cli",
                           metadata={"source": "cli"}, now=current)
    return admin_id


def set_admin_user_active(db: Database, username: str, active: bool, now: int | None = None) -> bool:
    """Enable or disable an account. Disabling also revokes every session it owns."""
    name = normalize_admin_username(username)
    current = now_epoch() if now is None else now
    with db.transaction() as conn:
        row = conn.execute("SELECT id FROM admin_users WHERE username = ?", (name,)).fetchone()
        if row is None:
            return False
        admin_id = int(row["id"])
        conn.execute("UPDATE admin_users SET is_active = ?, updated_at = ? WHERE id = ?",
                     (1 if active else 0, current, admin_id))
        if not active:
            revoke_user_sessions(conn, admin_id, current)
        record_audit_event(conn, action="admin.user.enable" if active else "admin.user.disable",
                           admin_user_id=admin_id, target=f"admin_user:{admin_id}",
                           user_agent="local-cli", metadata={"source": "cli"}, now=current)
    return True


def revoke_admin_user_sessions(db: Database, username: str, now: int | None = None) -> int:
    name = normalize_admin_username(username)
    current = now_epoch() if now is None else now
    with db.transaction() as conn:
        row = conn.execute("SELECT id FROM admin_users WHERE username = ?", (name,)).fetchone()
        if row is None:
            return 0
        admin_id = int(row["id"])
        revoked = revoke_user_sessions(conn, admin_id, current)
        record_audit_event(conn, action="admin.sessions.revoke", admin_user_id=admin_id,
                           target=f"admin_user:{admin_id}", user_agent="local-cli",
                           metadata={"source": "cli", "revoked": revoked}, now=current)
    return revoked


@dataclass(frozen=True)
class LoginPolicy:
    max_failures: int = 5
    window_seconds: int = 900


@dataclass(frozen=True)
class LoginResult:
    outcome: str  # "success", "invalid_credentials", or "rate_limited"
    session: IssuedSession | None = None
    username: str | None = None
    retry_after: int = 0


def reserve_login_attempt(db: Database, ip_key: str, policy: LoginPolicy, now: int) -> tuple[int | None, int]:
    """Atomically check the per-IP window and reserve one attempt.

    The reservation is written before the password is checked, so concurrent
    requests from one IP cannot all pass the check at once. A successful login
    deletes its reservation; a failed login keeps it.
    Returns (attempt_id, 0) when allowed, or (None, retry_after_seconds) when blocked.
    """
    window_start = now - policy.window_seconds
    with db.transaction() as conn:
        conn.execute("DELETE FROM login_attempts WHERE attempted_at <= ?", (window_start,))
        row = conn.execute(
            "SELECT count(*) AS attempts, min(attempted_at) AS oldest FROM login_attempts WHERE ip_key = ?",
            (ip_key,),
        ).fetchone()
        if int(row["attempts"]) >= policy.max_failures:
            retry_after = max(1, int(row["oldest"]) + policy.window_seconds - now)
            return None, retry_after
        cursor = conn.execute("INSERT INTO login_attempts(ip_key, attempted_at) VALUES (?, ?)", (ip_key, now))
        return int(cursor.lastrowid or 0), 0


def _audit_login(db: Database, action: str, *, admin_user_id: int | None, ip_address: str | None,
                 user_agent: str | None, reason: str | None, now: int) -> None:
    metadata = {"reason": reason} if reason else None
    target = f"admin_user:{admin_user_id}" if admin_user_id is not None else None
    with db.transaction() as conn:
        record_audit_event(conn, action=action, admin_user_id=admin_user_id, target=target,
                           ip_address=ip_address, user_agent=user_agent, metadata=metadata, now=now)


def _find_admin_user(db: Database, username: str) -> dict[str, Any] | None:
    try:
        name = normalize_admin_username(username)
    except ValueError:
        return None
    with db.connect() as conn:
        row = conn.execute("SELECT id, username, password_hash, is_active FROM admin_users WHERE username = ?",
                           (name,)).fetchone()
    return dict(row) if row else None


def authenticate_admin(
    db: Database,
    *,
    username: str,
    password: str,
    ip_key: str,
    ip_address: str | None,
    user_agent: str | None,
    policy: LoginPolicy,
    session_ttl_seconds: int,
    now: int | None = None,
) -> LoginResult:
    """Check credentials, enforce the per-IP login limit, and create a session on success.

    Failures return the same outcome whether the user is unknown, disabled, or has a wrong password.
    The reason is written only to the audit log. Passwords are never logged.
    """
    current = now_epoch() if now is None else now
    attempt_id, retry_after = reserve_login_attempt(db, ip_key, policy, current)
    if attempt_id is None:
        _audit_login(db, "admin.login.rate_limited", admin_user_id=None, ip_address=ip_address,
                     user_agent=user_agent, reason="rate_limited", now=current)
        return LoginResult("rate_limited", retry_after=retry_after)

    user = _find_admin_user(db, username)
    if user is None:
        verify_admin_password(_dummy_hash(), password)
        _audit_login(db, "admin.login.failure", admin_user_id=None, ip_address=ip_address,
                     user_agent=user_agent, reason="unknown_user", now=current)
        return LoginResult("invalid_credentials")

    admin_id = int(user["id"])
    password_ok = verify_admin_password(user["password_hash"], password)
    if not user["is_active"]:
        _audit_login(db, "admin.login.failure", admin_user_id=admin_id, ip_address=ip_address,
                     user_agent=user_agent, reason="account_disabled", now=current)
        return LoginResult("invalid_credentials")
    if not password_ok:
        _audit_login(db, "admin.login.failure", admin_user_id=admin_id, ip_address=ip_address,
                     user_agent=user_agent, reason="bad_password", now=current)
        return LoginResult("invalid_credentials")

    # Upgrade the stored hash when library defaults change. Hashing runs outside the write transaction.
    upgraded_hash: str | None = None
    if _PASSWORD_HASHER.check_needs_rehash(user["password_hash"]):
        upgraded_hash = hash_admin_password(password)

    with db.transaction() as conn:
        conn.execute("DELETE FROM login_attempts WHERE id = ?", (attempt_id,))
        conn.execute("UPDATE admin_users SET last_login_at = ? WHERE id = ?", (current, admin_id))
        if upgraded_hash is not None:
            conn.execute("UPDATE admin_users SET password_hash = ?, updated_at = ? WHERE id = ?",
                         (upgraded_hash, current, admin_id))
        issued = create_session(conn, admin_user_id=admin_id, ttl_seconds=session_ttl_seconds,
                                ip_address=ip_address, user_agent=user_agent, now=current)
        record_audit_event(conn, action="admin.login.success", admin_user_id=admin_id,
                           target=f"admin_user:{admin_id}", ip_address=ip_address,
                           user_agent=user_agent, now=current)
    return LoginResult("success", session=issued, username=str(user["username"]))
