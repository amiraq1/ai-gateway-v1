from __future__ import annotations

import os
import sqlite3
import subprocess
import tempfile
from pathlib import Path

from app.auth import authenticate_key, create_client_key, digest_key
from app.database import Database as NewDatabase


def get_historical_database_class():
    """Dynamically load the exact historical Database class from baseline commit 70b4027."""
    cmd = ["git", "show", "70b40270829549c5631be0bb8250481f442a3b6f:app/database.py"]
    source = subprocess.check_output(cmd, text=True)
    ns: dict = {}
    exec(source, ns)
    return ns["Database"]


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
        # Old Database.init() executed executescript(_SCHEMA) without checking user_version
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
