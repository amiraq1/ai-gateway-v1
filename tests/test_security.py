from __future__ import annotations

import hashlib
import hmac

from app.auth import authenticate_key, create_client_key, digest_key, make_request_log
from app.database import Database


PEPPER = "test-pepper-that-is-at-least-32-bytes-long"


def test_key_is_hmac_digest_only_and_revoke_is_immediate(tmp_path):
    path = str(tmp_path / "secure.sqlite3")
    db = Database(path)
    db.init()
    client_id, raw = create_client_key(db, PEPPER, "client", 7)
    stored = db.get_client(client_id)
    assert stored["key_digest"] == hmac.new(PEPPER.encode(), raw.encode(), hashlib.sha256).hexdigest()
    assert raw not in stored["key_digest"]
    assert authenticate_key(db, PEPPER, raw)["client_id"] == client_id
    forged = f"gw_{client_id}.forged-invalid-secret-key-material"
    assert authenticate_key(db, PEPPER, forged) is None
    assert db.revoke_client(client_id)
    assert authenticate_key(db, PEPPER, raw) is None
    assert db.list_clients()[0]["client_id"] == client_id


def test_request_logging_never_stores_prompt_key_or_provider_secret(tmp_path):
    path = tmp_path / "secure.sqlite3"
    db = Database(str(path))
    db.init()
    client_id, raw = create_client_key(db, PEPPER, "safe", 30)
    db.log_request(make_request_log(client_id, "fast", "primary", 200, 10, {"prompt_tokens": 1}, None, 30))
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM request_logs").fetchone()
        assert "PRIVATE-PROMPT-MARKER" not in repr(dict(row))
    for candidate in [path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")]:
        if candidate.exists():
            data = candidate.read_bytes()
            assert raw.encode() not in data
            assert b"PRIVATE-PROMPT-MARKER" not in data
            assert b"provider-secret-primary" not in data


def test_rate_limit_atomic_counter_and_retry_window(tmp_path):
    db = Database(str(tmp_path / "rate.sqlite3"))
    db.init()
    client_id, _ = create_client_key(db, PEPPER, "rate", 2, now=1200)
    assert db.consume_rate_limit(client_id, 2, now=1201) == (True, 0)
    assert db.consume_rate_limit(client_id, 2, now=1202) == (True, 0)
    allowed, retry_after = db.consume_rate_limit(client_id, 2, now=1203)
    assert not allowed
    assert retry_after == 57


def test_database_backup_is_readable_and_complete(tmp_path):
    db = Database(str(tmp_path / "source.sqlite3"))
    db.init()
    client_id, _ = create_client_key(db, PEPPER, "backup", 12)
    backup = tmp_path / "backup.sqlite3"
    db.backup_to(str(backup))
    restored = Database(str(backup))
    restored.init()
    assert restored.list_clients()[0]["client_id"] == client_id


def test_digest_requires_strong_pepper():
    try:
        digest_key("gw_test.secret", "short")
    except ValueError as exc:
        assert "32 bytes" in str(exc)
    else:
        raise AssertionError("weak pepper was accepted")
