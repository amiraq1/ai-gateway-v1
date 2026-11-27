from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from app.auth import create_client_key
from app.config import GatewayConfig, GatewaySettings, ModelConfig, ProviderConfig
from app.database import Database
from app.main import create_app


PEPPER = "test-pepper-that-is-at-least-32-bytes-long"


def _build_app(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    monkeypatch.setenv("TEST_PRIMARY_API_KEY", "secret")
    settings = GatewaySettings("127.0.0.1", 8000, str(tmp_path / "cancel.sqlite3"), 5.0, 1_048_576, 30)
    provider = ProviderConfig("primary", "m", "https://primary.example/v1", "TEST_PRIMARY_API_KEY", True)
    cfg = GatewayConfig(settings, {"fast": ModelConfig("fast", True, (provider,))})
    db = Database(settings.database_path)
    app = create_app(cfg, db)
    token = create_client_key(db, PEPPER, "cancel-client", 60)[1]
    return app, db, token


def test_non_streaming_disconnect_cancels_upstream_and_logs_499(tmp_path, monkeypatch):
    app, db, token = _build_app(tmp_path, monkeypatch)
    upstream_entered = asyncio.Event()
    upstream_cancelled = asyncio.Event()

    class HangingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            upstream_entered.set()
            try:
                await asyncio.sleep(5.0)
            except asyncio.CancelledError:
                upstream_cancelled.set()
                raise
            return httpx.Response(200, json={"choices": []})

    app.state.http_transport = HangingTransport()

    async def scenario():
        async with app.router.lifespan_context(app):
            body_bytes = json.dumps(
                {"model": "fast", "stream": False, "messages": [{"role": "user", "content": "hi"}]}
            ).encode("utf-8")
            scope = {
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": "2.4"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": "/v1/chat/completions",
                "raw_path": b"/v1/chat/completions",
                "query_string": b"",
                "headers": [
                    (b"authorization", f"Bearer {token}".encode("ascii")),
                    (b"content-type", b"application/json"),
                ],
                "client": ("127.0.0.1", 12345),
                "server": ("127.0.0.1", 8000),
            }
            sent_body = False
            disconnect_event = asyncio.Event()

            async def receive():
                nonlocal sent_body
                if not sent_body:
                    sent_body = True
                    return {"type": "http.request", "body": body_bytes, "more_body": False}
                await disconnect_event.wait()
                return {"type": "http.disconnect"}

            async def send(_msg):
                return None

            task = asyncio.create_task(app(scope, receive, send))
            await asyncio.wait_for(upstream_entered.wait(), timeout=2.0)
            disconnect_event.set()
            await asyncio.wait_for(upstream_cancelled.wait(), timeout=0.5)
            await asyncio.wait_for(task, timeout=0.5)

        row = db.usage_for_client(db.list_clients()[0]["client_id"])[0]
        assert row["status_code"] == 499
        assert row["error_category"] == "client_disconnected"

    asyncio.run(scenario())


@pytest.mark.parametrize("spec_version", ["2.3", "2.4"])
def test_streaming_disconnect_cancels_upstream_across_asgi_versions(tmp_path, monkeypatch, spec_version):
    app, db, token = _build_app(tmp_path, monkeypatch)
    upstream_started = asyncio.Event()
    stream_closed = asyncio.Event()

    class HangingStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
            upstream_started.set()
            await asyncio.sleep(5.0)
            yield b"data: [DONE]\n\n"

        async def aclose(self):
            stream_closed.set()

    app.state.http_transport = httpx.MockTransport(
        lambda req: httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=HangingStream())
    )

    async def scenario():
        async with app.router.lifespan_context(app):
            body_bytes = json.dumps(
                {"model": "fast", "stream": True, "messages": [{"role": "user", "content": "hi"}]}
            ).encode("utf-8")
            scope = {
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": spec_version},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": "/v1/chat/completions",
                "raw_path": b"/v1/chat/completions",
                "query_string": b"",
                "headers": [
                    (b"authorization", f"Bearer {token}".encode("ascii")),
                    (b"content-type", b"application/json"),
                ],
                "client": ("127.0.0.1", 12345),
                "server": ("127.0.0.1", 8000),
            }
            sent_body = False
            disconnect_event = asyncio.Event()
            first_chunk = asyncio.Event()

            async def receive():
                nonlocal sent_body
                if not sent_body:
                    sent_body = True
                    return {"type": "http.request", "body": body_bytes, "more_body": False}
                await disconnect_event.wait()
                return {"type": "http.disconnect"}

            async def send(msg):
                if msg["type"] == "http.response.body" and msg.get("body"):
                    first_chunk.set()

            task = asyncio.create_task(app(scope, receive, send))
            await asyncio.wait_for(upstream_started.wait(), timeout=2.0)
            await asyncio.wait_for(first_chunk.wait(), timeout=2.0)
            disconnect_event.set()
            await asyncio.wait_for(stream_closed.wait(), timeout=0.5)
            await asyncio.wait_for(task, timeout=0.5)

        row = db.usage_for_client(db.list_clients()[0]["client_id"])[0]
        assert row["status_code"] == 499
        assert row["error_category"] == "client_disconnected"

    asyncio.run(scenario())
