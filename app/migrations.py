"""Versioned SQLite schema migrations.

Version 1 is the schema shipped before this module existed. Its statements use
IF NOT EXISTS, so applying it to an existing database only records the version.
Each later version is applied once, inside an IMMEDIATE transaction, and the
version is stored in PRAGMA user_version.
"""

from __future__ import annotations

import sqlite3


class SchemaError(RuntimeError):
    """The database schema is missing required objects or is newer than this code."""


_V1_BASELINE: tuple[str, ...] = (
    """CREATE TABLE IF NOT EXISTS clients (
        client_id TEXT PRIMARY KEY,
        key_digest TEXT NOT NULL,
        name TEXT NOT NULL,
        rpm INTEGER NOT NULL CHECK (rpm > 0),
        created_at INTEGER NOT NULL,
        revoked_at INTEGER
    )""",
    "CREATE INDEX IF NOT EXISTS idx_clients_digest ON clients(key_digest)",
    """CREATE TABLE IF NOT EXISTS rate_limits (
        client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
        bucket INTEGER NOT NULL,
        count INTEGER NOT NULL CHECK (count >= 0),
        PRIMARY KEY(client_id, bucket)
    )""",
    """CREATE TABLE IF NOT EXISTS request_logs (
        id TEXT PRIMARY KEY,
        timestamp_utc TEXT NOT NULL,
        client_id TEXT NOT NULL,
        model_alias TEXT NOT NULL,
        provider_name TEXT,
        status_code INTEGER NOT NULL,
        latency_ms INTEGER NOT NULL,
        input_tokens INTEGER,
        output_tokens INTEGER,
        total_tokens INTEGER,
        error_category TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp_utc)",
    "CREATE INDEX IF NOT EXISTS idx_request_logs_client ON request_logs(client_id, timestamp_utc)",
)

_V2_ADMIN: tuple[str, ...] = (
    """CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE CHECK (length(username) BETWEEN 3 AND 64),
        password_hash TEXT NOT NULL CHECK (length(password_hash) BETWEEN 32 AND 512),
        is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        last_login_at INTEGER
    )""",
    """CREATE TABLE IF NOT EXISTS user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_user_id INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
        csrf_token_hash TEXT NOT NULL CHECK (length(csrf_token_hash) = 64),
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
        last_seen_at INTEGER NOT NULL,
        revoked_at INTEGER,
        ip_address TEXT CHECK (ip_address IS NULL OR length(ip_address) <= 64),
        user_agent TEXT CHECK (user_agent IS NULL OR length(user_agent) <= 512)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(admin_user_id, revoked_at)",
    "CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at)",
    """CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_user_id INTEGER REFERENCES admin_users(id),
        action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 96),
        target TEXT CHECK (target IS NULL OR length(target) <= 256),
        ip_address TEXT CHECK (ip_address IS NULL OR length(ip_address) <= 64),
        user_agent TEXT CHECK (user_agent IS NULL OR length(user_agent) <= 512),
        created_at INTEGER NOT NULL,
        metadata TEXT CHECK (metadata IS NULL OR json_valid(metadata))
    )""",
    "CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(admin_user_id, created_at)",
    "CREATE TRIGGER IF NOT EXISTS audit_logs_no_update BEFORE UPDATE ON audit_logs "
    "BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete BEFORE DELETE ON audit_logs "
    "BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END",
    """CREATE TABLE IF NOT EXISTS admin_ip_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_type TEXT NOT NULL CHECK (rule_type IN ('allow', 'deny')),
        ip_or_cidr TEXT NOT NULL CHECK (length(ip_or_cidr) BETWEEN 2 AND 64),
        description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 200),
        is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
        created_at INTEGER NOT NULL,
        UNIQUE (rule_type, ip_or_cidr)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_admin_ip_rules_active ON admin_ip_rules(is_active, rule_type)",
)

_V3_LOGIN_ATTEMPTS: tuple[str, ...] = (
    """CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_key TEXT NOT NULL CHECK (length(ip_key) BETWEEN 1 AND 64),
        attempted_at INTEGER NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip_key, attempted_at)",
)

_V4_PROVIDER_SECRETS: tuple[str, ...] = (
    """CREATE TABLE IF NOT EXISTS provider_secrets (
        provider_name TEXT PRIMARY KEY CHECK (length(provider_name) BETWEEN 1 AND 128),
        key_version INTEGER NOT NULL CHECK (key_version >= 1),
        algorithm TEXT NOT NULL CHECK (algorithm = 'AES-256-GCM'),
        nonce BLOB NOT NULL CHECK (length(nonce) = 12),
        ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 17 AND 8208),
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_provider_secrets_key_version ON provider_secrets(key_version)",
)

MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: _V1_BASELINE,
    2: _V2_ADMIN,
    3: _V3_LOGIN_ATTEMPTS,
    4: _V4_PROVIDER_SECRETS,
}
LATEST_SCHEMA_VERSION = max(MIGRATIONS)

REQUIRED_TABLES: frozenset[str] = frozenset({
    "clients",
    "rate_limits",
    "request_logs",
    "admin_users",
    "user_sessions",
    "audit_logs",
    "admin_ip_rules",
    "login_attempts",
    "provider_secrets",
})


def read_schema_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("PRAGMA user_version").fetchone()
    return int(row[0])


def missing_tables(conn: sqlite3.Connection) -> frozenset[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    present = {str(row[0]) for row in rows}
    return REQUIRED_TABLES - present


def apply_pending_migrations(conn: sqlite3.Connection) -> int:
    """Apply every migration newer than the stored version.

    The caller must already hold a write transaction (BEGIN IMMEDIATE), so two
    processes starting at the same time cannot apply the same migration twice.
    """
    current = read_schema_version(conn)
    if current < 0:
        raise SchemaError("Database schema version is invalid.")
    if current > LATEST_SCHEMA_VERSION:
        raise SchemaError("Database schema is newer than this application supports.")
    for version in range(current + 1, LATEST_SCHEMA_VERSION + 1):
        for statement in MIGRATIONS[version]:
            conn.execute(statement)
        # version is an integer from the static MIGRATIONS table, never user input.
        conn.execute(f"PRAGMA user_version = {int(version)}")
    absent = missing_tables(conn)
    if absent:
        raise SchemaError("Database schema is incomplete after migration.")
    return read_schema_version(conn)
