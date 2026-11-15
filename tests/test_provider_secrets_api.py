from __future__ import annotations

import base64
import logging
import os
import secrets as stdlib_secrets

import pytest
from fastapi.testclient import TestClient

from app.admin_routes import ProviderSecretBody
from app.auth import bootstrap_first_admin
from app.crypto import load_keyring
from app.database import Database
from app.provider_secrets import (
    list_provider_secrets,
    provider_secret_names,
    resolve_provider_api_key,
    store_provider_secret,
)
from tests.support import build_gateway_app

ADMIN_USER = "admin"
ADMIN_PASSWORD = "synthetic-admin-password-123"  # test marker, not a credential
KEY_VALUE = "synthetic-provider-key-value-7731"  # test marker, not a credential
SECOND_VALUE = "synthetic-second-provider-key-42"
ADMIN_IP = "198.51.100.20"


def _master_key() -> str:
    return base64.b64encode(stdlib_secrets.token_bytes(32)).decode("ascii")


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_MASTER_KEY", _master_key())
    for name in ("GATEWAY_MASTER_KEY_VERSION", "GATEWAY_MASTER_KEY_PREVIOUS", "GATEWAY_MASTER_KEY_PREVIOUS_VERSION",
                 "GATEWAY_MASTER_KEY_FILE", "GATEWAY_MASTER_KEY_PREVIOUS_FILE", "OPENAI_API_KEY", "OPENAI_API_KEY_FILE",
                 "ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    app, db = build_gateway_app(tmp_path)
    bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
    return app, db, monkeypatch


def _client(app) -> TestClient:
    return TestClient(app, base_url="https://testserver", client=(ADMIN_IP, 50000))


def _login(client: TestClient) -> str:
    response = client.post("/api/admin/login", json={"username": ADMIN_USER, "password": ADMIN_PASSWORD})
    assert response.status_code == 200
    return response.json()["csrf_token"]


def _db_bytes(db: Database) -> bytes:
    data = b""
    for suffix in ("", "-wal", "-shm"):
        try:
            with open(db.path + suffix, "rb") as handle:
                data += handle.read()
        except FileNotFoundError:
            pass
    return data


def _audit(db: Database) -> list[dict]:
    with db.connect() as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM audit_logs ORDER BY id")]


def test_every_provider_secret_route_requires_an_admin_session(api):
    app, _db, _mp = api
    with _client(app) as client:
        assert client.get("/api/admin/provider-secrets").status_code == 401
        assert client.put("/api/admin/provider-secrets/OPENAI_API_KEY", json={"api_key": KEY_VALUE}).status_code == 401
        assert client.delete("/api/admin/provider-secrets/OPENAI_API_KEY").status_code == 401
        assert client.post("/api/admin/provider-secrets/rotate").status_code == 401


def test_state_changes_need_csrf_but_the_listing_does_not(api):
    app, _db, _mp = api
    with _client(app) as client:
        csrf = _login(client)
        assert client.get("/api/admin/provider-secrets").status_code == 200
        assert client.put("/api/admin/provider-secrets/OPENAI_API_KEY",
                          json={"api_key": KEY_VALUE}).status_code == 403
        assert client.delete("/api/admin/provider-secrets/OPENAI_API_KEY").status_code == 403
        assert client.post("/api/admin/provider-secrets/rotate").status_code == 403
        stored = client.put("/api/admin/provider-secrets/OPENAI_API_KEY", json={"api_key": KEY_VALUE},
                            headers={"X-CSRF-Token": csrf})
        assert stored.status_code == 200
        assert client.post("/api/admin/provider-secrets/rotate",
                           headers={"X-CSRF-Token": "forged-token-value"}).status_code == 403


def test_put_stores_and_the_response_and_listing_never_contain_the_key(api):
    app, db, _mp = api
    with _client(app) as client:
        csrf = _login(client)
        put = client.put("/api/admin/provider-secrets/OPENAI_API_KEY", json={"api_key": KEY_VALUE},
                         headers={"X-CSRF-Token": csrf})
        listing = client.get("/api/admin/provider-secrets")
    assert put.status_code == 200
    assert put.json() == {"status": "stored", "provider_name": "OPENAI_API_KEY", "key_version": 1}
    assert KEY_VALUE not in put.text and KEY_VALUE not in listing.text
    entry = listing.json()["secrets"][0]
    assert set(entry) == {"provider_name", "key_version", "created_at", "updated_at"}
    assert entry["provider_name"] == "OPENAI_API_KEY" and entry["key_version"] == 1
    assert provider_secret_names(db) == frozenset({"OPENAI_API_KEY"})


def test_secret_str_hides_the_key_in_repr_and_errors(api):
    body = ProviderSecretBody(api_key=KEY_VALUE)
    assert KEY_VALUE not in repr(body) and KEY_VALUE not in str(body)
    assert body.api_key.get_secret_value() == KEY_VALUE


def test_no_plaintext_key_reaches_sqlite_wal_or_shm_or_audit(api):
    app, db, mp = api
    master = os.environ["GATEWAY_MASTER_KEY"]
    with _client(app) as client:
        csrf = _login(client)
        client.put("/api/admin/provider-secrets/OPENAI_API_KEY", json={"api_key": KEY_VALUE},
                   headers={"X-CSRF-Token": csrf})
        client.put("/api/admin/provider-secrets/ANTHROPIC_API_KEY", json={"api_key": SECOND_VALUE},
                   headers={"X-CSRF-Token": csrf})
    raw = _db_bytes(db)
    for secret in (KEY_VALUE, SECOND_VALUE, master, base64.b64decode(master).hex()):
        assert secret.encode() not in raw
    assert not any(KEY_VALUE in str(row) or SECOND_VALUE in str(row) for row in _audit(db))


def test_store_audit_row_records_actor_and_key_version_only(api):
    app, db, _mp = api
    with _client(app) as client:
        csrf = _login(client)
        client.put("/api/admin/provider-secrets/OPENAI_API_KEY", json={"api_key": KEY_VALUE},
                   headers={"X-CSRF-Token": csrf})
    rows = [row for row in _audit(db) if row["action"] == "provider_secret.store"]
    assert len(rows) == 1
    row = rows[0]
    assert row["admin_user_id"] == 1
    assert row["target"] == "provider_secret:OPENAI_API_KEY"
    assert row["ip_address"] == ADMIN_IP
    assert row["user_agent"]
    assert '"key_version":1' in row["metadata"] and '"source":"api"' in row["metadata"]
    assert KEY_VALUE not in row["metadata"]


@pytest.mark.parametrize(("name", "status"), [
    ("GATEWAY_PEPPER", 400),
    ("openai_api_key", 400),
    ("ADMIN_API_KEY", 400),
])
def test_invalid_provider_names_are_refused(api, name, status):
    app, _db, _mp = api
    with _client(app) as client:
        csrf = _login(client)
        response = client.put(f"/api/admin/provider-secrets/{name}", json={"api_key": KEY_VALUE},
                              headers={"X-CSRF-Token": csrf})
    assert response.status_code == status
    assert response.json()["error"]["code"] == "invalid_provider_name"
    assert KEY_VALUE not in response.text


def test_invalid_values_are_refused_with_generic_messages(api):
    app, db, _mp = api
    with _client(app) as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf}
        spaced = client.put("/api/admin/provider-secrets/OPENAI_API_KEY", json={"api_key": "has space inside"},
                            headers=headers)
        oversized = client.put("/api/admin/provider-secrets/OPENAI_API_KEY", json={"api_key": "x" * 9000},
                               headers=headers)
        empty = client.put("/api/admin/provider-secrets/OPENAI_API_KEY", json={"api_key": ""}, headers=headers)
        extra = client.put("/api/admin/provider-secrets/OPENAI_API_KEY",
                           json={"api_key": KEY_VALUE, "owner_admin_user_id": 9}, headers=headers)
    assert spaced.status_code == 422 and spaced.json()["error"]["code"] == "invalid_provider_secret"
    assert oversized.status_code == 422 and "x" * 50 not in oversized.text
    assert empty.status_code == 422
    assert extra.status_code == 422
    assert provider_secret_names(db) == frozenset()


def test_delete_removes_the_key_and_reports_missing_names(api):
    app, db, _mp = api
    with _client(app) as client:
        csrf = _login(client)
        client.put("/api/admin/provider-secrets/OPENAI_API_KEY", json={"api_key": KEY_VALUE},
                   headers={"X-CSRF-Token": csrf})
        deleted = client.delete("/api/admin/provider-secrets/OPENAI_API_KEY", headers={"X-CSRF-Token": csrf})
        missing = client.delete("/api/admin/provider-secrets/OPENAI_API_KEY", headers={"X-CSRF-Token": csrf})
    assert deleted.status_code == 200 and deleted.json()["status"] == "deleted"
    assert missing.status_code == 404
    assert provider_secret_names(db) == frozenset()
    assert any(row["action"] == "provider_secret.delete" for row in _audit(db))


def test_missing_master_key_fails_safely_while_metadata_and_delete_still_work(api):
    app, db, mp = api
    master = os.environ["GATEWAY_MASTER_KEY"]
    with _client(app) as client:
        csrf = _login(client)
        client.put("/api/admin/provider-secrets/OPENAI_API_KEY", json={"api_key": KEY_VALUE},
                   headers={"X-CSRF-Token": csrf})
        mp.delenv("GATEWAY_MASTER_KEY")
        store = client.put("/api/admin/provider-secrets/ANTHROPIC_API_KEY", json={"api_key": SECOND_VALUE},
                           headers={"X-CSRF-Token": csrf})
        rotate = client.post("/api/admin/provider-secrets/rotate", headers={"X-CSRF-Token": csrf})
        listing = client.get("/api/admin/provider-secrets")
        deleted = client.delete("/api/admin/provider-secrets/OPENAI_API_KEY", headers={"X-CSRF-Token": csrf})
    assert store.status_code == 503 and store.json()["error"]["code"] == "provider_key_store_unavailable"
    assert rotate.status_code == 503
    assert master not in store.text and master not in rotate.text
    assert listing.status_code == 200 and len(listing.json()["secrets"]) == 1
    assert deleted.status_code == 200


def test_rotation_reencrypts_only_outdated_rows_and_reports_the_count(api):
    app, db, mp = api
    old_master = os.environ["GATEWAY_MASTER_KEY"]
    with _client(app) as client:
        csrf = _login(client)
        client.put("/api/admin/provider-secrets/OPENAI_API_KEY", json={"api_key": KEY_VALUE},
                   headers={"X-CSRF-Token": csrf})
        client.put("/api/admin/provider-secrets/ANTHROPIC_API_KEY", json={"api_key": SECOND_VALUE},
                   headers={"X-CSRF-Token": csrf})
        mp.setenv("GATEWAY_MASTER_KEY", _master_key())
        mp.setenv("GATEWAY_MASTER_KEY_VERSION", "2")
        mp.setenv("GATEWAY_MASTER_KEY_PREVIOUS", old_master)
        mp.setenv("GATEWAY_MASTER_KEY_PREVIOUS_VERSION", "1")
        first = client.post("/api/admin/provider-secrets/rotate", headers={"X-CSRF-Token": csrf})
        second = client.post("/api/admin/provider-secrets/rotate", headers={"X-CSRF-Token": csrf})
    assert first.status_code == 200
    assert first.json() == {"rotated": 2, "key_version": 2}
    assert second.json() == {"rotated": 0, "key_version": 2}
    assert KEY_VALUE not in first.text and SECOND_VALUE not in first.text
    assert {info.key_version for info in list_provider_secrets(db)} == {2}
    with db.connect() as conn:
        assert conn.execute("SELECT count(*) FROM audit_logs WHERE action = 'provider_secret.rotate'").fetchone()[0] == 2


def test_failed_rotation_changes_nothing_and_keeps_every_key_readable(api):
    app, db, mp = api
    old_master = os.environ["GATEWAY_MASTER_KEY"]
    with _client(app) as client:
        csrf = _login(client)
        client.put("/api/admin/provider-secrets/OPENAI_API_KEY", json={"api_key": KEY_VALUE},
                   headers={"X-CSRF-Token": csrf})
        client.put("/api/admin/provider-secrets/ANTHROPIC_API_KEY", json={"api_key": SECOND_VALUE},
                   headers={"X-CSRF-Token": csrf})
        with db.transaction() as conn:
            conn.execute("UPDATE provider_secrets SET key_version = 9 WHERE provider_name = 'ANTHROPIC_API_KEY'")
        mp.setenv("GATEWAY_MASTER_KEY", _master_key())
        mp.setenv("GATEWAY_MASTER_KEY_VERSION", "2")
        mp.setenv("GATEWAY_MASTER_KEY_PREVIOUS", old_master)
        mp.setenv("GATEWAY_MASTER_KEY_PREVIOUS_VERSION", "1")
        failed = client.post("/api/admin/provider-secrets/rotate", headers={"X-CSRF-Token": csrf})
    assert failed.status_code == 503
    assert failed.json()["error"]["code"] == "provider_key_rotation_failed"
    with db.connect() as conn:
        versions = {row["provider_name"]: row["key_version"] for row in
                    conn.execute("SELECT provider_name, key_version FROM provider_secrets")}
    assert versions == {"OPENAI_API_KEY": 1, "ANTHROPIC_API_KEY": 9}
    mp.delenv("GATEWAY_MASTER_KEY_PREVIOUS")
    mp.delenv("GATEWAY_MASTER_KEY_PREVIOUS_VERSION")
    mp.setenv("GATEWAY_MASTER_KEY", old_master)
    mp.setenv("GATEWAY_MASTER_KEY_VERSION", "1")
    assert resolve_provider_api_key(db, "OPENAI_API_KEY") == KEY_VALUE


def test_rotation_without_the_previous_key_is_refused_and_leaves_rows_alone(api):
    app, db, mp = api
    with _client(app) as client:
        csrf = _login(client)
        client.put("/api/admin/provider-secrets/OPENAI_API_KEY", json={"api_key": KEY_VALUE},
                   headers={"X-CSRF-Token": csrf})
        mp.setenv("GATEWAY_MASTER_KEY", _master_key())
        mp.setenv("GATEWAY_MASTER_KEY_VERSION", "2")
        response = client.post("/api/admin/provider-secrets/rotate", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 503
    assert [info.key_version for info in list_provider_secrets(db)] == [1]


def test_cli_default_actor_is_recorded_as_local_cli(api):
    app, db, _mp = api
    store_provider_secret(db, load_keyring(), "ANTHROPIC_API_KEY", SECOND_VALUE)
    rows = [row for row in _audit(db) if row["action"] == "provider_secret.store"]
    assert rows[-1]["user_agent"] == "local-cli"
    assert rows[-1]["admin_user_id"] is None
    assert '"source":"cli"' in rows[-1]["metadata"]
    assert SECOND_VALUE not in rows[-1]["metadata"]


def test_provider_secret_values_never_appear_in_logs(api, caplog):
    app, _db, _mp = api
    caplog.set_level(logging.DEBUG)
    with _client(app) as client:
        csrf = _login(client)
        client.put("/api/admin/provider-secrets/OPENAI_API_KEY", json={"api_key": KEY_VALUE},
                   headers={"X-CSRF-Token": csrf})
        client.put("/api/admin/provider-secrets/OPENAI_API_KEY", json={"api_key": "bad value"},
                   headers={"X-CSRF-Token": csrf})
    assert KEY_VALUE not in caplog.text
    assert "bad value" not in caplog.text
