from __future__ import annotations

import json

import httpx
from fastapi.testclient import TestClient

from app.auth import create_client_key


def key(db, rpm=60):
    return create_client_key(db, "test-pepper-that-is-at-least-32-bytes-long", "unit-test", rpm)[1]


def success_handler(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    return httpx.Response(200, json={
        "id": "chatcmpl-test", "object": "chat.completion", "created": 1,
        "model": body["model"],
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "mock answer"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
    })


def test_health_is_minimal_and_unauthenticated(gateway):
    app, _ = gateway
    response = TestClient(app).get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_models_requires_valid_key_and_lists_active_aliases(gateway):
    app, db = gateway
    with TestClient(app) as client:
        assert client.get("/v1/models").status_code == 401
        token = key(db)
        response = client.get("/v1/models", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        assert [model["id"] for model in response.json()["data"]] == ["fast"]
        assert response.json()["object"] == "list"


def test_invalid_and_revoked_client_keys_return_401(gateway):
    app, db = gateway
    with TestClient(app) as client:
        invalid = client.get("/v1/models", headers={"Authorization": "Bearer gw_0000000000000000.not-a-real-key"})
        assert invalid.status_code == 401
        token = key(db)
        client_id = db.list_clients()[0]["client_id"]
        assert db.revoke_client(client_id)
        revoked = client.get("/v1/models", headers={"Authorization": f"Bearer {token}"})
        assert revoked.status_code == 401


def test_validation_error_does_not_echo_input_content(gateway):
    app, db = gateway
    token = key(db)
    marker = "PRIVATE-VALIDATION-MARKER"
    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json={
            "model": "fast", "messages": marker,
        })
    assert response.status_code == 422
    assert marker not in response.text
    assert response.json()["error"]["code"] == "invalid_request"


def test_standard_request_forwards_model_alias_and_records_usage(gateway):
    app, db = gateway
    app.state.http_transport = httpx.MockTransport(success_handler)
    token = key(db)
    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json={
            "model": "fast", "messages": [{"role": "user", "content": "PRIVATE-PROMPT-MARKER"}], "temperature": 0.2,
        })
    assert response.status_code == 200
    assert response.json()["model"] == "fast"
    assert response.json()["choices"][0]["message"]["content"] == "mock answer"
    usage = db.usage_for_client(db.list_clients()[0]["client_id"])[0]
    assert usage["provider_name"] == "primary"
    assert (usage["input_tokens"], usage["output_tokens"], usage["total_tokens"]) == (3, 2, 5)
    assert usage["error_category"] is None


def test_unknown_parameters_are_explicitly_rejected(gateway):
    app, db = gateway
    token = key(db)
    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json={
            "model": "fast", "messages": [{"role": "user", "content": "hi"}], "invented_flag": True,
        })
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "unsupported_parameter"


def test_rate_limit_is_persisted_and_returns_retry_after(gateway):
    app, db = gateway
    app.state.http_transport = httpx.MockTransport(success_handler)
    token = key(db, rpm=1)
    with TestClient(app) as client:
        payload = {"model": "fast", "messages": [{"role": "user", "content": "hi"}]}
        first = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json=payload)
        second = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json=payload)
    assert first.status_code == 200
    assert second.status_code == 429
    assert 1 <= int(second.headers["Retry-After"]) <= 60


def test_request_body_limit_returns_413(gateway):
    app, db = gateway
    token = key(db)
    # Set a small limit on the ASGI middleware for a deterministic test.
    app.user_middleware[0].kwargs["maximum"] = 1024
    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, content=b"x" * 2048)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_too_large"
