from __future__ import annotations

import json
import sqlite3
import sys
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from app.admin import main
from app.auth import create_client_key
from app.config import GatewayConfig, GatewaySettings
from tests.test_api import success_handler

PEPPER = "test-pepper-that-is-at-least-32-bytes-long"


def _token(db):
    return create_client_key(db, PEPPER, "audit-polish", 20)[1]


def test_sqlite_auth_failure_returns_openai_503(gateway, monkeypatch):
    app, db = gateway
    token = _token(db)

    def boom(*_args, **_kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr("app.main.authenticate_key", boom)
    with TestClient(app) as client:
        resp = client.get("/v1/models", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 503
    body = resp.json()
    assert body["error"]["code"] == "storage_unavailable"
    assert "message" in body["error"]


def test_sqlite_rate_limit_failure_returns_openai_503(gateway, monkeypatch):
    app, db = gateway
    token = _token(db)

    def boom(*_args, **_kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(db, "consume_rate_limit", boom)
    app.state.http_transport = httpx.MockTransport(success_handler)
    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={"model": "fast", "messages": [{"role": "user", "content": "hi"}]},
        )

    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "storage_unavailable"


def test_unknown_route_uses_openai_envelope(gateway):
    app, _ = gateway
    with TestClient(app) as client:
        resp = client.get("/nonexistent")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "http_error"
    assert "detail" not in resp.json()


def test_wrong_method_uses_openai_envelope(gateway):
    app, _ = gateway
    with TestClient(app) as client:
        resp = client.post("/v1/models")
    assert resp.status_code == 405
    assert resp.json()["error"]["code"] == "http_error"


def test_trailing_slash_is_not_redirected(gateway):
    app, db = gateway
    token = _token(db)
    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions/",
            headers={"Authorization": f"Bearer {token}"},
            json={"model": "fast", "messages": [{"role": "user", "content": "hi"}]},
        )
    assert resp.status_code == 404
    assert "error" in resp.json()


def test_malformed_body_uses_openai_envelope(gateway):
    app, db = gateway
    token = _token(db)
    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            content=b"[",
        )
    assert resp.status_code in (400, 422)
    assert resp.json()["error"]["code"] in ("http_error", "invalid_request")
    assert "detail" not in resp.json()


def test_logprobs_fields_are_accepted_and_forwarded(gateway):
    app, db = gateway
    token = _token(db)
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return success_handler(request)

    app.state.http_transport = httpx.MockTransport(handler)
    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "model": "fast",
                "messages": [{"role": "user", "content": "hi"}],
                "logprobs": True,
                "top_logprobs": 2,
            },
        )

    assert resp.status_code == 200
    assert seen["body"]["logprobs"] is True
    assert seen["body"]["top_logprobs"] == 2


@pytest.fixture
def admin_env(tmp_path, monkeypatch):
    db_path = str(tmp_path / "admin_audit.sqlite3")
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    monkeypatch.setenv("GATEWAY_DATABASE_PATH", db_path)
    cfg = GatewayConfig(GatewaySettings("127.0.0.1", 8000, db_path, 3.0, 1048576, 30), {})
    monkeypatch.setattr("app.admin.load_config", lambda: cfg)
    return db_path


@pytest.mark.parametrize("rpm", ["-1", "0", "1000001", "abc"])
def test_admin_rejects_invalid_rpm_without_traceback(admin_env, capsys, rpm):
    with pytest.raises(SystemExit) as exc:
        with patch.object(sys, "argv", ["admin", "create-key", "--name", "audit", "--rpm", rpm]):
            main()
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert "--rpm" in captured.err
