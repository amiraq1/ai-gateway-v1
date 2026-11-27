from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
import sqlite3

import pytest

from app.auth import create_client_key
from app.database import Database

PEPPER = "test-pepper-that-is-at-least-32-bytes-long"


def test_concurrent_rate_limit_never_exceeds_rpm(tmp_path):
    db = Database(str(tmp_path / "concurrent.sqlite3"), timeout_seconds=10)
    db.init()
    client_id, _ = create_client_key(db, PEPPER, "concurrent", 7, now=600)
    def hit(_):
        return db.consume_rate_limit(client_id, 7, now=601)[0]
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(hit, range(32)))
    assert sum(results) == 7


def test_client_metadata_never_lists_key_digest(tmp_path):
    db = Database(str(tmp_path / "metadata.sqlite3"))
    db.init()
    create_client_key(db, PEPPER, "metadata", 10)
    listing = db.list_clients()
    assert len(listing) == 1
    assert "key_digest" not in listing[0]


def test_backup_to_is_atomic_via_temp_file_and_os_replace(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "source.sqlite3"))
    db.init()
    client_id, _ = create_client_key(db, PEPPER, "backup-client", 10)

    backup_dir = tmp_path / "backups"
    backup_path = backup_dir / "gateway.sqlite3"
    replace_calls: list[tuple[str, str]] = []
    real_replace = os.replace

    def spy_replace(src, dst):
        replace_calls.append((str(src), str(dst)))
        return real_replace(src, dst)

    monkeypatch.setattr("app.database.os.replace", spy_replace)
    db.backup_to(str(backup_path))

    assert len(replace_calls) == 1
    src_path, dst_path = replace_calls[0]
    assert src_path != str(backup_path)
    assert dst_path == str(backup_path)
    restored = Database(str(backup_path))
    assert restored.list_clients()[0]["client_id"] == client_id

    # If a later backup fails mid-copy, the previous valid backup remains intact and no temp file leaks.
    prior_bytes = backup_path.read_bytes()

    def failing_connect():
        raise sqlite3.OperationalError("simulated backup failure")

    monkeypatch.setattr(db, "connect", failing_connect)
    with pytest.raises(sqlite3.OperationalError):
        db.backup_to(str(backup_path))

    assert backup_path.read_bytes() == prior_bytes
    assert [p.name for p in backup_dir.iterdir()] == ["gateway.sqlite3"]
