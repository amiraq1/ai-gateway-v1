from __future__ import annotations

import os
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from app.auth import authenticate_key, create_client_key, digest_key
from app.database import Database as NewDatabase


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


_HISTORICAL_SCHEMA = """
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


class FallbackHistoricalDatabase:
    """Exact unedited Database class implementation from baseline commit 70b4027."""

    def __init__(self, path: str, timeout_seconds: float = 5.0) -> None:
        self.path = path
        self.timeout_seconds = timeout_seconds
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=self.timeout_seconds, isolation_level=None, factory=_ClosingConnection)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={int(self.timeout_seconds * 1000)}")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def init(self) -> None:
        if self.path != ":memory:":
            old = os.umask(0o077)
            try:
                Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with self.connect() as conn:
                    conn.executescript(_HISTORICAL_SCHEMA)
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    pass
            finally:
                os.umask(old)
        else:
            with self.connect() as conn:
                conn.executescript(_HISTORICAL_SCHEMA)

    def add_client(self, client_id: str, digest: str, name: str, rpm: int, now: int | None = None) -> None:
        if rpm < 1 or rpm > 1_000_000:
            raise ValueError("rpm must be between 1 and 1000000")
        created_at = int(time.time() if now is None else now)
        with self.connect() as conn:
            conn.execute("INSERT INTO clients(client_id,key_digest,name,rpm,created_at) VALUES(?,?,?,?,?)",
                         (client_id, digest, name[:128], rpm, created_at))

    def get_client(self, client_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT client_id,key_digest,name,rpm,created_at,revoked_at FROM clients WHERE client_id=?", (client_id,)).fetchone()
            return dict(row) if row else None

    def revoke_client(self, client_id: str, now: int | None = None) -> bool:
        revoked_at = int(time.time() if now is None else now)
        with self.connect() as conn:
            cur = conn.execute("UPDATE clients SET revoked_at=? WHERE client_id=? AND revoked_at IS NULL", (revoked_at, client_id))
            return cur.rowcount == 1

    def list_clients(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT client_id,name,rpm,created_at,revoked_at FROM clients ORDER BY created_at DESC").fetchall()
            return [dict(row) for row in rows]

    def consume_rate_limit(self, client_id: str, rpm: int, now: float | None = None) -> tuple[bool, int]:
        current = float(time.time() if now is None else now)
        bucket = int(current // 60)
        retry_after = max(1, 60 - int(current % 60))
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT count FROM rate_limits WHERE client_id=? AND bucket=?", (client_id, bucket)).fetchone()
            count = int(row["count"]) if row else 0
            if count >= rpm:
                conn.rollback()
                return False, retry_after
            conn.execute("INSERT INTO rate_limits(client_id,bucket,count) VALUES(?,?,1) ON CONFLICT(client_id,bucket) DO UPDATE SET count=count+1", (client_id, bucket))
            conn.execute("DELETE FROM rate_limits WHERE bucket < ?", (bucket - 2,))
            conn.commit()
            return True, 0
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def log_request(self, entry: dict[str, Any]) -> None:
        retention_days = min(max(int(entry.get("retention_days", 30)), 1), 365)
        with self.connect() as conn:
            conn.execute("""INSERT INTO request_logs
                (id,timestamp_utc,client_id,model_alias,provider_name,status_code,latency_ms,
                 input_tokens,output_tokens,total_tokens,error_category)
                VALUES(:id,:timestamp_utc,:client_id,:model_alias,:provider_name,:status_code,:latency_ms,
                       :input_tokens,:output_tokens,:total_tokens,:error_category)""", entry)
            conn.execute("DELETE FROM request_logs WHERE timestamp_utc < datetime('now', ?)", (f"-{retention_days} days",))

    def usage_for_client(self, client_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT id,timestamp_utc,model_alias,provider_name,status_code,latency_ms,input_tokens,output_tokens,total_tokens,error_category FROM request_logs WHERE client_id=? ORDER BY timestamp_utc DESC LIMIT ?", (client_id, min(max(limit, 1), 1000))).fetchall()
            return [dict(row) for row in rows]

    def counts(self) -> tuple[int, int]:
        with self.connect() as conn:
            clients = conn.execute("SELECT count(*) FROM clients").fetchone()[0]
            logs = conn.execute("SELECT count(*) FROM request_logs").fetchone()[0]
            return int(clients), int(logs)


def get_historical_database_class():
    """Dynamically load historical Database class from git commit 70b4027, or use exact embedded fallback."""
    try:
        cmd = ["git", "show", "70b40270829549c5631be0bb8250481f442a3b6f:app/database.py"]
        source = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        ns: dict = {}
        exec(source, ns)
        return ns["Database"]
    except Exception:
        return FallbackHistoricalDatabase


def test_sqlite_migration_and_rollback_with_actual_historical_code():
    """Test full forward and backward compatibility using the ACTUAL historical Database implementation."""
    HistoricalDatabase = get_historical_database_class()

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test_gateway.sqlite3")
        pepper = "test-synthetic-pepper-for-compat-test-0123456789"

        # ---------------------------------------------------------------------
        # 1. Initialize and populate DB using ACTUAL HISTORICAL code (70b4027)
        # ---------------------------------------------------------------------
        old_db = HistoricalDatabase(db_path)
        old_db.init()

        # Verify initial schema has user_version == 0
        with old_db.connect() as conn:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
            assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

        # Insert client using historical add_client
        client_id = "0123456789abcdef"
        raw_key = f"gw_{client_id}.secretkey12345678901234567890"
        key_digest = digest_key(raw_key, pepper)
        old_db.add_client(client_id, key_digest, "historical-client", 60)

        # Consume rate limit and log request using historical methods
        allowed, retry_after = old_db.consume_rate_limit(client_id, 60)
        assert allowed is True
        assert retry_after == 0

        old_db.log_request({
            "id": "req_historical_001",
            "timestamp_utc": "2026-11-13T12:00:00Z",
            "client_id": client_id,
            "model_alias": "fast",
            "provider_name": "mock_provider",
            "status_code": 200,
            "latency_ms": 120,
            "input_tokens": 10,
            "output_tokens": 5,
            "total_tokens": 15,
            "error_category": None,
            "retention_days": 30,
        })

        clients_count, logs_count = old_db.counts()
        assert clients_count == 1
        assert logs_count == 1

        # ---------------------------------------------------------------------
        # 2. Upgrade / Migrate using NEW candidate codebase (app.database)
        # ---------------------------------------------------------------------
        new_db = NewDatabase(db_path)
        new_db.init()  # calls migrate()

        with new_db.connect() as conn:
            assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 1

        # Authenticate historical client with candidate auth logic
        client_record = new_db.get_client(client_id)
        assert client_record is not None
        assert client_record["name"] == "historical-client"
        auth_client = authenticate_key(new_db, pepper, raw_key)
        assert auth_client is not None
        assert auth_client["client_id"] == client_id

        # Check historical request logs are intact
        usage = new_db.usage_for_client(client_id)
        assert len(usage) == 1
        assert usage[0]["id"] == "req_historical_001"

        # Create new client and consume rate limit under NEW codebase
        client_id_2, raw_key_2 = create_client_key(new_db, pepper, "candidate-client", 120)
        allowed2, _ = new_db.consume_rate_limit(client_id_2, 120)
        assert allowed2 is True

        clients_count, logs_count = new_db.counts()
        assert clients_count == 2
        assert logs_count == 1

        # ---------------------------------------------------------------------
        # 3. Simulate FULL ROLLBACK to actual historical Database class (70b4027)
        # ---------------------------------------------------------------------
        rollback_db = HistoricalDatabase(db_path)
        rollback_db.init()

        with rollback_db.connect() as conn:
            assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

        # Verify historical class can read both historical and new clients
        rec1 = rollback_db.get_client(client_id)
        assert rec1 is not None
        assert rec1["name"] == "historical-client"

        rec2 = rollback_db.get_client(client_id_2)
        assert rec2 is not None
        assert rec2["name"] == "candidate-client"

        # Verify historical class can consume rate limits and add logs on migrated DB
        allowed_rb, _ = rollback_db.consume_rate_limit(client_id_2, 120)
        assert allowed_rb is True

        rollback_db.log_request({
            "id": "req_rollback_002",
            "timestamp_utc": "2026-11-13T12:05:00Z",
            "client_id": client_id_2,
            "model_alias": "fast",
            "provider_name": "mock_provider",
            "status_code": 200,
            "latency_ms": 110,
            "input_tokens": 20,
            "output_tokens": 10,
            "total_tokens": 30,
            "error_category": None,
            "retention_days": 30,
        })

        rb_clients, rb_logs = rollback_db.counts()
        assert rb_clients == 2
        assert rb_logs == 2

        # ---------------------------------------------------------------------
        # 4. Final verification: Re-open with NEW codebase after rollback activity
        # ---------------------------------------------------------------------
        final_db = NewDatabase(db_path)
        final_db.init()
        f_clients, f_logs = final_db.counts()
        assert f_clients == 2
        assert f_logs == 2
        with final_db.connect() as conn:
            assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
