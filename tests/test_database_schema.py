from __future__ import annotations

import os
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.database import Database
from app.migrations import LATEST_SCHEMA_VERSION, SchemaError

# The schema exactly as shipped on main before versioned migrations existed.
LEGACY_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    key_digest TEXT NOT NULL,
    name TEXT NOT NULL,
    rpm INTEGER NOT NULL CHECK (rpm > 0),
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_clients_digest ON clients(key_digest);
CREATE TABLE IF NOT EXISTS rate_limits (
    client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    bucket INTEGER NOT NULL,
    count INTEGER NOT NULL CHECK (count >= 0),
    PRIMARY KEY(client_id, bucket)
);
CREATE TABLE IF NOT EXISTS request_logs (
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
);
CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_request_logs_client ON request_logs(client_id, timestamp_utc);
"""


def _pragma(conn: sqlite3.Connection, name: str):
    return conn.execute(f"PRAGMA {name}").fetchone()[0]


def test_fresh_database_uses_wal_normal_busy_timeout_and_foreign_keys(tmp_path):
    db = Database(str(tmp_path / "fresh.sqlite3"))
    db.init()
    with db.connect() as conn:
        assert _pragma(conn, "journal_mode") == "wal"
        assert _pragma(conn, "synchronous") == 1  # NORMAL
        assert _pragma(conn, "busy_timeout") == 5000
        assert _pragma(conn, "foreign_keys") == 1
    assert _pragma(sqlite3.connect(db.path), "user_version") == LATEST_SCHEMA_VERSION


def test_legacy_database_is_migrated_in_place_and_keeps_data(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    legacy = sqlite3.connect(path)
    legacy.executescript(LEGACY_SCHEMA)
    legacy.execute("INSERT INTO clients(client_id,key_digest,name,rpm,created_at) VALUES('abcdef0123456789','digest','legacy',60,1)")
    legacy.execute("INSERT INTO request_logs(id,timestamp_utc,client_id,model_alias,status_code,latency_ms) "
                   "VALUES('r1','2026-01-01T00:00:00Z','abcdef0123456789','fast',200,5)")
    legacy.commit()
    assert _pragma(legacy, "user_version") == 0
    legacy.close()

    db = Database(str(path))
    db.init()

    assert db.list_clients()[0]["name"] == "legacy"
    with db.connect() as conn:
        assert conn.execute("SELECT count(*) FROM request_logs").fetchone()[0] == 1
        assert _pragma(conn, "user_version") == LATEST_SCHEMA_VERSION
        assert _pragma(conn, "journal_mode") == "wal"
    backups = [name for name in os.listdir(tmp_path) if ".pre-schema-v0-" in name and name.endswith(".bak")]
    assert len(backups) == 1
    backup_mode = stat.S_IMODE(os.stat(tmp_path / backups[0]).st_mode)
    assert backup_mode == 0o600


def test_repeated_init_is_idempotent_and_does_not_back_up_again(tmp_path):
    path = tmp_path / "repeat.sqlite3"
    db = Database(str(path))
    db.init()
    db.init()
    db.init()
    assert not [name for name in os.listdir(tmp_path) if name.endswith(".bak")]
    with db.connect() as conn:
        assert _pragma(conn, "user_version") == LATEST_SCHEMA_VERSION


def test_newer_schema_version_is_refused(tmp_path):
    path = tmp_path / "future.sqlite3"
    raw = sqlite3.connect(path)
    raw.execute(f"PRAGMA user_version = {LATEST_SCHEMA_VERSION + 1}")
    raw.commit()
    raw.close()
    with pytest.raises(SchemaError, match="newer"):
        Database(str(path)).init()


def test_incomplete_schema_is_refused_instead_of_silently_running(tmp_path):
    path = tmp_path / "broken.sqlite3"
    db = Database(str(path))
    db.init()
    with db.connect() as conn:
        conn.execute("DROP TABLE provider_secrets")
    with pytest.raises(SchemaError, match="incomplete"):
        db.init()


def test_audit_logs_are_append_only(tmp_path):
    db = Database(str(tmp_path / "audit.sqlite3"))
    db.init()
    with db.connect() as conn:
        conn.execute("INSERT INTO audit_logs(action, created_at) VALUES('test.event', 1)")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("UPDATE audit_logs SET action = 'changed'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM audit_logs")


def test_foreign_keys_and_check_constraints_are_enforced(tmp_path):
    db = Database(str(tmp_path / "constraints.sqlite3"))
    db.init()
    with db.connect() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO user_sessions(admin_user_id, token_hash, csrf_token_hash, created_at, expires_at, last_seen_at) "
                         "VALUES(999, ?, ?, 1, 2, 1)", ("a" * 64, "b" * 64))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO admin_ip_rules(rule_type, ip_or_cidr, created_at) VALUES('block', '10.0.0.1/32', 1)")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO provider_secrets(provider_name, key_version, algorithm, nonce, ciphertext, created_at, updated_at) "
                         "VALUES('OPENAI_API_KEY', 1, 'AES-128-CBC', randomblob(12), randomblob(32), 1, 1)")


def test_concurrent_writers_do_not_fail_with_database_locked(tmp_path):
    db = Database(str(tmp_path / "concurrent.sqlite3"))
    db.init()

    def write(index: int) -> None:
        for step in range(25):
            db.log_request({
                "id": f"{index:04d}{step:04d}".ljust(32, "0"), "timestamp_utc": "2026-11-15T00:00:00Z",
                "client_id": "concurrent", "model_alias": "fast", "provider_name": None, "status_code": 200,
                "latency_ms": 1, "input_tokens": None, "output_tokens": None, "total_tokens": None,
                "error_category": None, "retention_days": 30,
            })

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write, range(8)))
    with db.connect() as conn:
        assert conn.execute("SELECT count(*) FROM request_logs").fetchone()[0] == 200
