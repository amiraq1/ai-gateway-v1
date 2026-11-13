from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

from app.auth import create_client_key

PEPPER = "test-pepper-that-is-at-least-32-bytes-long"


class BytesStream(httpx.AsyncByteStream):
    def __init__(self, chunks, fail_after=None):
        self.chunks = chunks
        self.fail_after = fail_after

    async def __aiter__(self):
        for index, chunk in enumerate(self.chunks):
            yield chunk
            if self.fail_after is not None and index + 1 >= self.fail_after:
                raise httpx.ReadError("simulated connection break")

    async def aclose(self):
        return None


def test_stream_success_has_sse_headers_and_done(gateway):
    app, db = gateway
    stream = BytesStream([
        b'data: {"id":"c1","choices":[{"delta":{"content":"hello"}}]}\n\n',
        b'data: [DONE]\n\n',
    ])
    app.state.http_transport = httpx.MockTransport(lambda request: httpx.Response(200, headers={"content-type":"text/event-stream"}, stream=stream))
    token = create_client_key(db, PEPPER, "stream", 20)[1]
    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json={"model":"fast","stream":True,"messages":[{"role":"user","content":"hi"}]})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert "data: [DONE]" in response.text
    assert response.text.endswith("\n\n")


def test_stream_failure_after_first_event_does_not_fallback_or_send_done(gateway):
    app, db = gateway
    seen = []
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        stream = BytesStream([b'data: {"choices":[{"delta":{"content":"first"}}]}\n\n'], fail_after=1)
        return httpx.Response(200, headers={"content-type":"text/event-stream"}, stream=stream)
    app.state.http_transport = httpx.MockTransport(handler)
    token = create_client_key(db, PEPPER, "stream-failure", 20)[1]
    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json={"model":"fast","stream":True,"messages":[{"role":"user","content":"hi"}]})
    assert response.status_code == 200
    assert seen == ["primary.example"]
    assert 'event: error' in response.text
    assert "provider_stream_failure" in response.text
    assert "[DONE]" not in response.text


def test_stream_fallback_is_allowed_before_first_complete_event(gateway):
    app, db = gateway
    seen = []
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        if request.url.host == "primary.example":
            return httpx.Response(503, headers={"content-type":"application/json"}, json={})
        return httpx.Response(200, headers={"content-type":"text/event-stream"}, stream=BytesStream([b'data: {"choices":[]}\n\n', b'data: [DONE]\n\n']))
    app.state.http_transport = httpx.MockTransport(handler)
    token = create_client_key(db, PEPPER, "stream-fallback", 20)[1]
    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json={"model":"fast","stream":True,"messages":[{"role":"user","content":"hi"}]})
    assert response.status_code == 200
    assert seen == ["primary.example", "secondary.example"]
    assert "data: [DONE]" in response.text
