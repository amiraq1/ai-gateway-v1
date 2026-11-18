from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from typing import Any


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


SCHEMA_VERSION = 1

MIGRATIONS: dict[int, str] = {
    1: """
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
}


class Database:
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

    def get_version(self) -> int:
        with self.connect() as conn:
            return int(conn.execute("PRAGMA user_version").fetchone()[0])

    def migrate(self, conn: sqlite3.Connection) -> int:
        current_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        has_tables = conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='clients'").fetchone()[0] > 0
        if current_version == 0 and has_tables:
            current_version = 1
            conn.execute("PRAGMA user_version = 1")

        for target_version in range(current_version + 1, SCHEMA_VERSION + 1):
            if target_version in MIGRATIONS:
                conn.executescript(MIGRATIONS[target_version])
                conn.execute(f"PRAGMA user_version = {target_version}")
        return int(conn.execute("PRAGMA user_version").fetchone()[0])

    def init(self) -> None:
        if self.path != ":memory:":
            old = os.umask(0o077)
            try:
                Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with self.connect() as conn:
                    self.migrate(conn)
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    pass
            finally:
                os.umask(old)
        else:
            with self.connect() as conn:
                self.migrate(conn)

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

    def backup_to(self, destination: str) -> None:
        target = sqlite3.connect(destination)
        try:
            with self.connect() as source:
                source.backup(target)
            target.commit()
        finally:
            target.close()
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass
