from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

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
