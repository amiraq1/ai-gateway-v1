from __future__ import annotations

import sqlite3

import httpx
from fastapi.testclient import TestClient

from app.auth import create_client_key
from tests.test_api import success_handler


PEPPER = "test-pepper-that-is-at-least-32-bytes-long"


class ProtocolErrorStream(httpx.AsyncByteStream):
    def __init__(self, emit_first: bool = True):
        self.emit_first = emit_first

    async def __aiter__(self):
        if self.emit_first:
            yield b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n'
        raise httpx.RemoteProtocolError("incomplete chunked read")

    async def aclose(self):
        return None


class NoDoneStream(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n'

    async def aclose(self):
        return None


class CommentOnlyThenFailStream(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield b": keep-alive\n\n"
        raise httpx.ReadError("dropped before payload")

    async def aclose(self):
        return None


class HugeErrorStream(httpx.AsyncByteStream):
    def __init__(self, total_bytes: int):
        self.total_bytes = total_bytes
        self.bytes_read = 0

    async def __aiter__(self):
        chunk = b"E" * 65536
        while self.bytes_read < self.total_bytes:
            self.bytes_read += len(chunk)
            yield chunk

    async def aclose(self):
        return None


def test_stream_catches_transport_error_and_logs_failure(gateway):
    app, db = gateway
    app.state.http_transport = httpx.MockTransport(
        lambda req: httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=ProtocolErrorStream(emit_first=True))
    )
    token = create_client_key(db, PEPPER, "transport-err", 20)[1]

    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={"model": "fast", "stream": True, "messages": [{"role": "user", "content": "hi"}]},
        )

    assert resp.status_code == 200
    assert "event: error" in resp.text
    assert "provider_stream_failure" in resp.text
    row = db.usage_for_client(db.list_clients()[0]["client_id"])[0]
    assert row["status_code"] != 200
    assert row["error_category"] == "provider_stream_failure"


def test_non_streaming_catches_transport_error_and_falls_back(gateway):
    app, db = gateway
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        if request.url.host == "primary.example":
            raise httpx.RemoteProtocolError("bad http framing", request=request)
        return success_handler(request)

    app.state.http_transport = httpx.MockTransport(handler)
    token = create_client_key(db, PEPPER, "nonstream-transport", 20)[1]

    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={"model": "fast", "messages": [{"role": "user", "content": "hi"}]},
        )

    assert resp.status_code == 200
    assert seen == ["primary.example", "secondary.example"]


def test_stream_does_not_fabricate_done_when_upstream_omits_done(gateway):
    app, db = gateway
    app.state.http_transport = httpx.MockTransport(
        lambda req: httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=NoDoneStream())
    )
    token = create_client_key(db, PEPPER, "no-done", 20)[1]

    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={"model": "fast", "stream": True, "messages": [{"role": "user", "content": "hi"}]},
        )

    assert "[DONE]" not in resp.text
    assert "event: error" in resp.text
    assert "provider_incomplete_stream" in resp.text
    row = db.usage_for_client(db.list_clients()[0]["client_id"])[0]
    assert row["status_code"] == 502
    assert row["error_category"] == "provider_incomplete_stream"


class SimpleAsyncStream(httpx.AsyncByteStream):
    def __init__(self, payload: bytes):
        self.payload = payload

    async def __aiter__(self):
        yield self.payload

    async def aclose(self):
        return None


def test_sse_comment_only_blocks_fallback_after_first_byte(gateway):
    app, db = gateway
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        if request.url.host == "primary.example":
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=CommentOnlyThenFailStream())
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=SimpleAsyncStream(b'data: {"choices":[{"delta":{"content":"ok"}}]}\n\ndata: [DONE]\n\n'),
        )

    app.state.http_transport = httpx.MockTransport(handler)
    token = create_client_key(db, PEPPER, "comment-fallback", 20)[1]

    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={"model": "fast", "stream": True, "messages": [{"role": "user", "content": "hi"}]},
        )

    # Once any upstream byte (including a comment) is forwarded, fallback is forbidden.
    assert seen == ["primary.example"]
    assert "event: error" in resp.text
    assert "data: [DONE]" not in resp.text


def test_log_request_failure_does_not_turn_200_into_502(gateway, monkeypatch):
    app, db = gateway
    app.state.http_transport = httpx.MockTransport(success_handler)
    token = create_client_key(db, PEPPER, "log-fail-200", 20)[1]

    def fail_log(_entry):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(db, "log_request", fail_log)

    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={"model": "fast", "messages": [{"role": "user", "content": "hi"}]},
        )

    assert resp.status_code == 200
    assert resp.json()["choices"][0]["message"]["content"] == "mock answer"


def test_retryable_503_error_drain_is_bounded(gateway):
    app, db = gateway
    error_stream = HugeErrorStream(total_bytes=2 * 1024 * 1024)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "primary.example":
            return httpx.Response(503, headers={"content-type": "application/json"}, stream=error_stream)
        return success_handler(request)

    app.state.http_transport = httpx.MockTransport(handler)
    token = create_client_key(db, PEPPER, "bounded-drain", 20)[1]

    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={"model": "fast", "messages": [{"role": "user", "content": "hi"}]},
        )

    assert resp.status_code == 200
    assert error_stream.bytes_read <= 128 * 1024


def test_streaming_retryable_503_error_drain_is_bounded(gateway):
    app, db = gateway
    error_stream = HugeErrorStream(total_bytes=2 * 1024 * 1024)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "primary.example":
            return httpx.Response(503, headers={"content-type": "application/json"}, stream=error_stream)
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=SimpleAsyncStream(b'data: {"choices":[{"delta":{"content":"ok"}}]}\n\ndata: [DONE]\n\n'),
        )

    app.state.http_transport = httpx.MockTransport(handler)
    token = create_client_key(db, PEPPER, "bounded-stream-drain", 20)[1]

    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={"model": "fast", "stream": True, "messages": [{"role": "user", "content": "hi"}]},
        )

    assert resp.status_code == 200
    assert "data: [DONE]" in resp.text
    assert error_stream.bytes_read <= 128 * 1024
