from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app import admin
from app.auth import authenticate_key, create_client_key
from tests.test_api import success_handler


class EventStream(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield b'data: {"choices":[{"delta":{"content":"ok"}}]}\n\n'
        yield b"data: [DONE]\n\n"

    async def aclose(self):
        return None


def write_test_secret(path: Path, value: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(value.encode("utf-8"))
    path.chmod(0o400)
    return path


@pytest.mark.parametrize("streaming", [False, True])
def test_streaming_and_non_streaming_load_same_file_secret(streaming, gateway, monkeypatch, secret_directory):
    app, db = gateway
    upstream_secret = "synthetic-provider-secret-file-value"
    secret_file = write_test_secret(secret_directory / "provider-key", upstream_secret)
    monkeypatch.delenv("TEST_PRIMARY_API_KEY", raising=False)
    monkeypatch.setenv("TEST_PRIMARY_API_KEY_FILE", str(secret_file))
    seen_authorization = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_authorization.append(request.headers.get("authorization"))
        if streaming:
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=EventStream())
        return success_handler(request)

    app.state.http_transport = httpx.MockTransport(handler)
    token = create_client_key(db, "test-pepper-that-is-at-least-32-bytes-long", "file-secret", 20)[1]
    payload = {"model": "fast", "messages": [{"role": "user", "content": "safe prompt"}], "stream": streaming}
    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json=payload)

    assert response.status_code == 200
    assert seen_authorization == [f"Bearer {upstream_secret}"]
    assert upstream_secret not in response.text
    if streaming:
        assert "data: [DONE]" in response.text
    else:
        assert response.json()["model"] == "fast"


@pytest.mark.parametrize("streaming", [False, True])
def test_secret_load_failure_sends_no_upstream_request_or_secret_details(streaming, gateway, monkeypatch, secret_directory, caplog):
    app, db = gateway
    path_marker = "private-secret-path-marker"
    missing_file = secret_directory / path_marker
    monkeypatch.delenv("TEST_PRIMARY_API_KEY", raising=False)
    monkeypatch.setenv("TEST_PRIMARY_API_KEY_FILE", str(missing_file))
    seen = []
    app.state.http_transport = httpx.MockTransport(lambda request: seen.append(request) or httpx.Response(200, json={}))
    token = create_client_key(db, "test-pepper-that-is-at-least-32-bytes-long", "missing-secret", 20)[1]
    payload = {"model": "fast", "messages": [{"role": "user", "content": "safe prompt"}], "stream": streaming}

    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json=payload)

    assert seen == []
    assert response.status_code == (200 if streaming else 503)
    assert "provider_secret_unavailable" in response.text
    assert path_marker not in response.text
    assert str(missing_file) not in response.text
    assert "test-pepper-that-is-at-least-32-bytes-long" not in response.text
    assert str(missing_file) not in caplog.text
    assert "test-pepper-that-is-at-least-32-bytes-long" not in caplog.text
    assert db.usage_for_client(db.list_clients()[0]["client_id"])[0]["error_category"] == "provider_secret_unavailable"


def test_pepper_file_preserves_existing_client_key_compatibility(gateway, monkeypatch, secret_directory):
    app, db = gateway
    old_pepper = "synthetic-pepper-created-before-migration-with-trailing-space "
    monkeypatch.setenv("GATEWAY_PEPPER", old_pepper)
    monkeypatch.delenv("GATEWAY_PEPPER_FILE", raising=False)
    token = create_client_key(db, old_pepper, "pepper-migration", 20)[1]
    pepper_file = write_test_secret(secret_directory / "gateway-pepper", old_pepper)
    monkeypatch.delenv("GATEWAY_PEPPER", raising=False)
    monkeypatch.setenv("GATEWAY_PEPPER_FILE", str(pepper_file))

    with TestClient(app) as client:
        response = client.get("/v1/models", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert authenticate_key(db, old_pepper, token) is not None
    assert old_pepper not in response.text
    assert old_pepper not in response.headers.get("www-authenticate", "")


def test_pepper_load_failure_is_generic_and_does_not_authenticate(gateway, monkeypatch, secret_directory):
    app, db = gateway
    pepper = "synthetic-pepper-for-missing-file-api-test"
    token = create_client_key(db, pepper, "pepper-missing", 20)[1]
    missing_file = secret_directory / "private-pepper-path-marker"
    monkeypatch.delenv("GATEWAY_PEPPER", raising=False)
    monkeypatch.setenv("GATEWAY_PEPPER_FILE", str(missing_file))

    with TestClient(app) as client:
        response = client.get("/v1/models", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "secret_unavailable"
    assert str(missing_file) not in response.text
    assert "private-pepper-path-marker" not in response.text
    assert pepper not in response.text


def test_create_key_cli_reads_pepper_file_without_printing_pepper(gateway, monkeypatch, secret_directory, capsys):
    app, db = gateway
    pepper = "synthetic-cli-pepper-file-value-with-at-least-32-bytes"
    pepper_file = write_test_secret(secret_directory / "cli-pepper", pepper)
    monkeypatch.delenv("GATEWAY_PEPPER", raising=False)
    monkeypatch.setenv("GATEWAY_PEPPER_FILE", str(pepper_file))
    monkeypatch.setattr(admin, "load_config", lambda: app.state.gateway_config)
    monkeypatch.setattr(admin, "Database", lambda _path: db)
    monkeypatch.setattr(sys, "argv", ["ai-gateway-admin", "create-key", "--name", "test-client"])

    assert admin.main() == 0
    output = capsys.readouterr()
    token_line = next(line for line in output.out.splitlines() if line.startswith("api_key="))
    raw_key = token_line.partition("=")[2]
    assert authenticate_key(db, pepper, raw_key) is not None
    assert pepper not in output.out
    assert pepper not in output.err


def test_create_key_cli_fails_before_database_access_if_pepper_is_unavailable(gateway, monkeypatch, secret_directory, capsys):
    app, _db = gateway
    missing_file = secret_directory / "private-cli-pepper-path-marker"
    monkeypatch.delenv("GATEWAY_PEPPER", raising=False)
    monkeypatch.setenv("GATEWAY_PEPPER_FILE", str(missing_file))
    monkeypatch.setattr(admin, "load_config", lambda: app.state.gateway_config)
    monkeypatch.setattr(admin, "Database", lambda _path: pytest.fail("database must not be accessed"))
    monkeypatch.setattr(sys, "argv", ["ai-gateway-admin", "create-key", "--name", "test-client"])

    with pytest.raises(SystemExit) as captured:
        admin.main()
    output = capsys.readouterr()
    assert captured.value.code == 2
    assert "required secret is unavailable" in output.err
    assert str(missing_file) not in output.err
    assert "private-cli-pepper-path-marker" not in output.err


def test_provider_secret_and_pepper_are_absent_from_test_database(gateway, monkeypatch, secret_directory, caplog):
    app, db = gateway
    provider_secret = "synthetic-provider-secret-never-store"
    pepper = "synthetic-pepper-never-store-value-at-least-32-bytes"
    provider_file = write_test_secret(secret_directory / "provider-key", provider_secret)
    pepper_file = write_test_secret(secret_directory / "pepper", pepper)
    monkeypatch.delenv("TEST_PRIMARY_API_KEY", raising=False)
    monkeypatch.setenv("TEST_PRIMARY_API_KEY_FILE", str(provider_file))
    monkeypatch.delenv("GATEWAY_PEPPER", raising=False)
    monkeypatch.setenv("GATEWAY_PEPPER_FILE", str(pepper_file))
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("authorization"))
        return success_handler(request)

    app.state.http_transport = httpx.MockTransport(handler)
    token = create_client_key(db, pepper, "db-check", 20)[1]
    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json={
            "model": "fast", "messages": [{"role": "user", "content": "private prompt marker"}],
        })

    assert response.status_code == 200
    assert seen == [f"Bearer {provider_secret}"]
    assert provider_secret not in response.text
    assert pepper not in response.text
    assert provider_secret not in caplog.text
    assert pepper not in caplog.text
    config_repr = repr(app.state.gateway_config)
    assert provider_secret not in config_repr
    assert pepper not in config_repr
    files = [Path(db.path), Path(f"{db.path}-wal"), Path(f"{db.path}-shm")]
    for path in files:
        if path.exists():
            contents = path.read_bytes()
            assert provider_secret.encode() not in contents
            assert pepper.encode() not in contents
            assert token.encode() not in contents
            assert b"private prompt marker" not in contents
    with db.connect() as conn:
        stored = [json.dumps(dict(row), sort_keys=True) for row in conn.execute("SELECT * FROM clients")]
        stored += [json.dumps(dict(row), sort_keys=True) for row in conn.execute("SELECT * FROM request_logs")]
    serialized = "\n".join(stored)
    assert provider_secret not in serialized
    assert pepper not in serialized
