from __future__ import annotations

import asyncio

import httpx
from fastapi.testclient import TestClient

from app.auth import create_client_key
from app.config import GatewayConfig, GatewaySettings, ModelConfig, ProviderConfig
from app.database import Database
from app.main import BoundedBodyMiddleware, create_app


PEPPER = "test-pepper-that-is-at-least-32-bytes-long"


class LargeSseStream(httpx.AsyncByteStream):
    def __init__(self, event_count: int, event_payload_bytes: int = 32768):
        self.event_count = event_count
        self.event_payload_bytes = event_payload_bytes

    async def __aiter__(self):
        chunk_text = "A" * self.event_payload_bytes
        payload = f'data: {{"choices":[{{"delta":{{"content":"{chunk_text}"}}}}]}}\n\n'.encode("utf-8")
        for _ in range(self.event_count):
            yield payload
        yield b"data: [DONE]\n\n"

    async def aclose(self):
        return None


class SlowBetweenChunksStream(httpx.AsyncByteStream):
    def __init__(self, pause_seconds: float):
        self.pause_seconds = pause_seconds

    async def __aiter__(self):
        yield b'data: {"choices":[{"delta":{"content":"first"}}]}\n\n'
        await asyncio.sleep(self.pause_seconds)
        yield b'data: {"choices":[{"delta":{"content":"late"}}]}\n\n'
        yield b"data: [DONE]\n\n"

    async def aclose(self):
        return None


def test_stream_enforces_max_stream_bytes(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    monkeypatch.setenv("TEST_PRIMARY_API_KEY", "secret")
    settings = GatewaySettings(
        "127.0.0.1",
        8000,
        str(tmp_path / "stream_limit.sqlite3"),
        5.0,
        1_048_576,
        30,
        max_stream_bytes=64 * 1024,
    )
    provider = ProviderConfig("primary", "m", "https://primary.example/v1", "TEST_PRIMARY_API_KEY", True)
    cfg = GatewayConfig(settings, {"fast": ModelConfig("fast", True, (provider,))})
    db = Database(settings.database_path)
    app = create_app(cfg, db)
    app.state.http_transport = httpx.MockTransport(
        lambda req: httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=LargeSseStream(event_count=6, event_payload_bytes=20000),
        )
    )
    token = create_client_key(db, PEPPER, "stream-cap", 20)[1]

    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={"model": "fast", "stream": True, "messages": [{"role": "user", "content": "hi"}]},
        )

    assert "provider_stream_too_large" in resp.text
    assert "[DONE]" not in resp.text


def test_stream_enforces_idle_timeout_between_chunks(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    monkeypatch.setenv("TEST_PRIMARY_API_KEY", "secret")
    settings = GatewaySettings(
        "127.0.0.1",
        8000,
        str(tmp_path / "idle.sqlite3"),
        5.0,
        1_048_576,
        30,
        stream_idle_timeout_seconds=0.1,
    )
    provider = ProviderConfig("primary", "m", "https://primary.example/v1", "TEST_PRIMARY_API_KEY", True)
    cfg = GatewayConfig(settings, {"fast": ModelConfig("fast", True, (provider,))})
    db = Database(settings.database_path)
    app = create_app(cfg, db)
    app.state.http_transport = httpx.MockTransport(
        lambda req: httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=SlowBetweenChunksStream(pause_seconds=0.4),
        )
    )
    token = create_client_key(db, PEPPER, "idle-timeout", 20)[1]

    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={"model": "fast", "stream": True, "messages": [{"role": "user", "content": "hi"}]},
        )

    assert "provider_stream_timeout" in resp.text
    assert "late" not in resp.text


def test_bounded_body_middleware_times_out_slow_body():
    async def scenario():
        async def inner(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok", "more_body": False})

        mw = BoundedBodyMiddleware(inner, maximum=1024, body_timeout=0.08)
        sent = []
        calls = 0

        async def slow_receive():
            nonlocal calls
            calls += 1
            if calls == 1:
                return {"type": "http.request", "body": b'{"a":', "more_body": True}
            await asyncio.sleep(0.3)
            return {"type": "http.request", "body": b"1}", "more_body": False}

        async def send(msg):
            sent.append(msg)

        await mw({"type": "http", "headers": []}, slow_receive, send)
        assert sent[0]["status"] == 408
        assert b"request_timeout" in sent[1]["body"]

    asyncio.run(scenario())


def test_concurrency_semaphore_rejects_excess_parallel_requests(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    monkeypatch.setenv("TEST_PRIMARY_API_KEY", "secret")
    settings = GatewaySettings(
        "127.0.0.1",
        8000,
        str(tmp_path / "conc.sqlite3"),
        5.0,
        1_048_576,
        30,
        max_concurrent_requests=1,
        max_client_concurrent_requests=1,
    )
    provider = ProviderConfig("primary", "m", "https://primary.example/v1", "TEST_PRIMARY_API_KEY", True)
    cfg = GatewayConfig(settings, {"fast": ModelConfig("fast", True, (provider,))})
    db = Database(settings.database_path)
    app = create_app(cfg, db)
    token = create_client_key(db, PEPPER, "conc-limit", 60)[1]

    entered = asyncio.Event()
    release = asyncio.Event()

    class SlowMockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            entered.set()
            await release.wait()
            return httpx.Response(
                200,
                json={
                    "id": "1",
                    "object": "chat.completion",
                    "created": 1,
                    "model": "m",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                },
            )

    app.state.http_transport = SlowMockTransport()

    async def scenario():
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://gateway.local") as client:
                headers = {"Authorization": f"Bearer {token}"}
                first_task = asyncio.create_task(
                    client.post(
                        "/v1/chat/completions",
                        headers=headers,
                        json={"model": "fast", "messages": [{"role": "user", "content": "1"}]},
                    )
                )
                await asyncio.wait_for(entered.wait(), timeout=2.0)
                second_resp = await client.post(
                    "/v1/chat/completions",
                    headers=headers,
                    json={"model": "fast", "messages": [{"role": "user", "content": "2"}]},
                )
                release.set()
                first_resp = await first_task
                assert first_resp.status_code == 200
                assert second_resp.status_code in {429, 503}

    asyncio.run(scenario())


def test_streaming_holds_concurrency_slot_until_stream_finishes(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    monkeypatch.setenv("TEST_PRIMARY_API_KEY", "secret")
    settings = GatewaySettings(
        "127.0.0.1",
        8000,
        str(tmp_path / "stream_conc.sqlite3"),
        5.0,
        1_048_576,
        30,
        max_concurrent_requests=1,
        max_client_concurrent_requests=1,
    )
    provider = ProviderConfig("primary", "m", "https://primary.example/v1", "TEST_PRIMARY_API_KEY", True)
    cfg = GatewayConfig(settings, {"fast": ModelConfig("fast", True, (provider,))})
    db = Database(settings.database_path)
    app = create_app(cfg, db)
    token = create_client_key(db, PEPPER, "stream-conc", 60)[1]

    started_stream = asyncio.Event()
    finish_stream = asyncio.Event()

    class ControlledStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'data: {"choices":[{"delta":{"content":"a"}}]}\n\n'
            started_stream.set()
            await finish_stream.wait()
            yield b"data: [DONE]\n\n"

        async def aclose(self):
            return None

    app.state.http_transport = httpx.MockTransport(
        lambda req: httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=ControlledStream())
    )

    async def scenario():
        async with app.router.lifespan_context(app):
            import json
            first_chunk_sent = asyncio.Event()
            body_bytes = json.dumps(
                {"model": "fast", "stream": True, "messages": [{"role": "user", "content": "1"}]}
            ).encode("utf-8")
            scope = {
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": "2.3"},
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
            req_sent = False
            done_event = asyncio.Event()

            async def receive():
                nonlocal req_sent
                if not req_sent:
                    req_sent = True
                    return {"type": "http.request", "body": body_bytes, "more_body": False}
                await done_event.wait()
                return {"type": "http.disconnect"}

            async def send(msg):
                if msg["type"] == "http.response.body" and msg.get("body"):
                    first_chunk_sent.set()
                if msg["type"] == "http.response.body" and not msg.get("more_body", True):
                    done_event.set()

            stream_task = asyncio.create_task(app(scope, receive, send))
            await asyncio.wait_for(first_chunk_sent.wait(), timeout=2.0)
            await asyncio.wait_for(started_stream.wait(), timeout=2.0)

            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://gateway.local") as client:
                second_resp = await client.post(
                    "/v1/chat/completions",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"model": "fast", "messages": [{"role": "user", "content": "2"}]},
                )
                assert second_resp.status_code in {429, 503}

            finish_stream.set()
            await asyncio.wait_for(stream_task, timeout=2.0)

    asyncio.run(scenario())
