import sqlite3

import pytest

from app import database as db_module
from app.auth import create_client_key, make_request_log
from app.database import Database

PEPPER = "test-pepper-that-is-at-least-32-bytes-long"


def test_database_has_schema_version_1(tmp_path):
    db_path = str(tmp_path / "versioned.sqlite3")
    db = Database(db_path)
    db.init()
    assert hasattr(db, "get_version"), "Database must have get_version method"
    assert db.get_version() == 1, "Initial schema version must be 1"


def test_migration_preserves_existing_data(tmp_path):
    db_path = str(tmp_path / "preserve.sqlite3")
    db = Database(db_path)
    db.init()
    client_id, _ = create_client_key(db, PEPPER, "existing-client", 60)

    # Re-init / re-migrate should preserve client
    db.init()
    assert db.get_version() == 1
    clients = db.list_clients()
    assert len(clients) == 1
    assert clients[0]["client_id"] == client_id


def test_migration_is_atomic_on_mid_script_failure(tmp_path, monkeypatch):
    db_path = str(tmp_path / "atomic_migrate.sqlite3")
    db = Database(db_path)
    db.init()

    broken_migrations = dict(db_module.MIGRATIONS)
    broken_migrations[2] = "CREATE TABLE partial_migration_table(id INTEGER PRIMARY KEY); NOT VALID SQL;"
    monkeypatch.setattr(db_module, "MIGRATIONS", broken_migrations)
    monkeypatch.setattr(db_module, "SCHEMA_VERSION", 2)

    with db.connect() as conn:
        with pytest.raises(sqlite3.OperationalError):
            db.migrate(conn)
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='partial_migration_table'"
        ).fetchall()
    assert tables == []
    assert db.get_version() == 1


def test_log_request_cleanup_deletes_expired_iso_t_rows_on_cutoff_day(tmp_path):
    db_path = str(tmp_path / "retention.sqlite3")
    db = Database(db_path)
    db.init()
    client_id, _ = create_client_key(db, PEPPER, "retention-client", 60)

    expired = make_request_log(client_id, "fast", "primary", 200, 10, None, None, 30)
    with db.connect() as conn:
        cutoff_day_ts = conn.execute("SELECT date('now', '-30 days') || 'T00:00:00Z'").fetchone()[0]
    expired["id"] = "expired-cutoff-day"
    expired["timestamp_utc"] = cutoff_day_ts

    with db.connect() as conn:
        conn.execute(
            """INSERT INTO request_logs
            (id,timestamp_utc,client_id,model_alias,provider_name,status_code,latency_ms,
             input_tokens,output_tokens,total_tokens,error_category)
            VALUES(:id,:timestamp_utc,:client_id,:model_alias,:provider_name,:status_code,:latency_ms,
                   :input_tokens,:output_tokens,:total_tokens,:error_category)""",
            expired,
        )

    fresh = make_request_log(client_id, "fast", "primary", 200, 10, None, None, 30)
    db.log_request(fresh)

    rows = db.usage_for_client(client_id, limit=100)
    ids = [r["id"] for r in rows]
    assert "expired-cutoff-day" not in ids
    assert fresh["id"] in ids
