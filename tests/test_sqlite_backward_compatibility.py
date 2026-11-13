from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from app.auth import authenticate_key, create_client_key
from app.database import Database as NewDatabase

OLD_SCHEMA = """
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


def test_sqlite_migration_and_rollback_compatibility():
    """Test full forward and backward compatibility of SQLite between baseline (70b4027) and candidate."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test_gateway.sqlite3")
        pepper = "test-synthetic-pepper-for-compat-test-0123456789"

        # 1. Initialize DB using exact OLD schema (commit 70b4027)
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.executescript(OLD_SCHEMA)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0

        # Insert a client under OLD schema
        client_id = "0123456789abcdef"
        from app.auth import digest_key
        raw_key = f"gw_{client_id}.secretkey12345678901234567890"
        key_digest = digest_key(raw_key, pepper)
        conn.execute(
            "INSERT INTO clients(client_id, key_digest, name, rpm, created_at) VALUES(?, ?, ?, ?, ?)",
            (client_id, key_digest, "old-app-client", 60, 1700000000)
        )
        conn.execute(
            "INSERT INTO request_logs(id, timestamp_utc, client_id, model_alias, provider_name, status_code, latency_ms, total_tokens) VALUES(?, datetime('now'), ?, ?, ?, ?, ?, ?)",
            ("log_001", client_id, "fast", "mock_provider", 200, 150, 25)
        )
        conn.commit()
        conn.close()

        # 2. Open DB with NEW codebase and run migrate()
        new_db = NewDatabase(db_path)
        new_db.init()

        # Verify integrity and version
        with new_db.connect() as c:
            integrity = c.execute("PRAGMA integrity_check").fetchone()[0]
            assert integrity == "ok"
            version = c.execute("PRAGMA user_version").fetchone()[0]
            assert version == 1

        # Verify existing client can be loaded and authenticated by NEW codebase
        client_record = new_db.get_client(client_id)
        assert client_record is not None
        assert client_record["name"] == "old-app-client"
        auth_client = authenticate_key(new_db, pepper, raw_key)
        assert auth_client is not None
        assert auth_client["client_id"] == client_id

        # Verify usage logs are intact
        usage = new_db.usage_for_client(client_id)
        assert len(usage) == 1
        assert usage[0]["id"] == "log_001"

        # Add a new client via NEW codebase
        client_id_2, raw_key_2 = create_client_key(new_db, pepper, "new-app-client", 120)
        allowed, retry_after = new_db.consume_rate_limit(client_id_2, 120)
        assert allowed is True

        # 3. Simulate ROLLBACK: Open DB using OLD codebase logic (commit 70b4027)
        old_conn = sqlite3.connect(db_path)
        old_conn.row_factory = sqlite3.Row
        old_conn.execute("PRAGMA journal_mode=WAL")
        old_conn.execute("PRAGMA foreign_keys=ON")
        # Old code ran conn.executescript(_SCHEMA) unconditionally on startup:
        old_conn.executescript(OLD_SCHEMA)

        # Verify integrity is still OK under old connection
        assert old_conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

        # Verify OLD codebase can read both the old client and the new client
        c1 = old_conn.execute("SELECT * FROM clients WHERE client_id=?", (client_id,)).fetchone()
        assert c1 is not None
        assert c1["name"] == "old-app-client"

        c2 = old_conn.execute("SELECT * FROM clients WHERE client_id=?", (client_id_2,)).fetchone()
        assert c2 is not None
        assert c2["name"] == "new-app-client"

        # Verify OLD codebase can write new logs and consume rate limits
        old_conn.execute(
            "INSERT INTO request_logs(id, timestamp_utc, client_id, model_alias, provider_name, status_code, latency_ms, total_tokens) VALUES(?, datetime('now'), ?, ?, ?, ?, ?, ?)",
            ("log_rollback_002", client_id_2, "fast", "mock_provider", 200, 120, 30)
        )
        old_conn.commit()

        total_logs = old_conn.execute("SELECT count(*) FROM request_logs").fetchone()[0]
        assert total_logs == 2
        total_clients = old_conn.execute("SELECT count(*) FROM clients").fetchone()[0]
        assert total_clients == 2
        old_conn.close()

        # 4. Final verification: Re-open with NEW codebase after simulated rollback
        final_db = NewDatabase(db_path)
        final_db.init()
        clients_count, logs_count = final_db.counts()
        assert clients_count == 2
        assert logs_count == 2
