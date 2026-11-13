from __future__ import annotations

import json

import httpx
from fastapi.testclient import TestClient

from app.auth import create_client_key
from tests.test_api import success_handler


PEPPER = "test-pepper-that-is-at-least-32-bytes-long"


def test_fallback_uses_second_provider_and_records_actual_provider(gateway):
    app, db = gateway
    seen = []
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host, json.loads(request.content)["model"]))
        if request.url.host == "primary.example":
            return httpx.Response(503, json={"error": "internal detail must not be forwarded"})
        return success_handler(request)
    app.state.http_transport = httpx.MockTransport(handler)
    token = create_client_key(db, PEPPER, "fallback", 20)[1]
    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json={"model":"fast","messages":[{"role":"user","content":"hi"}]})
    assert response.status_code == 200
    assert response.json()["model"] == "fast"
    assert seen == [("primary.example", "test-primary-model"), ("secondary.example", "test-secondary-model")]
    usage = db.usage_for_client(db.list_clients()[0]["client_id"])[0]
    assert usage["provider_name"] == "secondary"


def test_provider_401_does_not_fallback(gateway):
    app, db = gateway
    seen = []
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        return httpx.Response(401, json={"error":"secret upstream message"})
    app.state.http_transport = httpx.MockTransport(handler)
    token = create_client_key(db, PEPPER, "no-fallback", 20)[1]
    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json={"model":"fast","messages":[{"role":"user","content":"hi"}]})
    assert response.status_code == 502
    assert seen == ["primary.example"]
    assert "secret upstream message" not in response.text


def test_retry_is_bounded_to_two_total_attempts(gateway):
    app, db = gateway
    seen = []
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        return httpx.Response(500, json={})
    app.state.http_transport = httpx.MockTransport(handler)
    token = create_client_key(db, PEPPER, "bounded", 20)[1]
    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json={"model":"fast","messages":[{"role":"user","content":"hi"}]})
    assert response.status_code == 502
    assert seen == ["primary.example", "secondary.example"]
