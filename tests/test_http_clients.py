from __future__ import annotations

import asyncio

import httpx
from fastapi.testclient import TestClient

from app.auth import create_client_key
from app.config import GatewayConfig, GatewaySettings, ModelConfig, ProviderConfig
from app.database import Database
from app.main import create_app


PEPPER = "test-pepper-that-is-at-least-32-bytes-long"


def _make_local_app(tmp_path, port: int):
    settings = GatewaySettings("127.0.0.1", 8000, str(tmp_path / "gateway.sqlite3"), 3.0, 1_048_576, 30)
    provider = ProviderConfig(
        "local",
        "test-model",
        f"http://127.0.0.1:{port}/v1",
        "TEST_LOCAL_API_KEY",
        True,
        allow_private_hosts=True,
    )
    cfg = GatewayConfig(settings, {"fast": ModelConfig("fast", True, (provider,))})
    db = Database(settings.database_path)
    app = create_app(cfg, db)
    token = create_client_key(db, PEPPER, "concurrent-test", 60)[1]
    return app, token


def test_shared_http_clients_reused_and_closed_in_lifespan(gateway):
    app, _db = gateway
    assert hasattr(app.state, "http_clients")
    clients = app.state.http_clients

    with TestClient(app):
        c1 = clients.get_client(False)
        c2 = clients.get_client(False)
        assert c1 is c2
        assert not c1.is_closed

    assert c1.is_closed


def test_concurrent_requests_do_not_close_shared_transport(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    monkeypatch.setenv("TEST_LOCAL_API_KEY", "local-secret")

    async def scenario():
        async def handle_upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            header_bytes = await reader.readuntil(b"\r\n\r\n")
            content_length = 0
            for line in header_bytes.decode("latin-1").splitlines():
                if line.lower().startswith("content-length:"):
                    content_length = int(line.split(":", 1)[1].strip())
            req_body = await reader.readexactly(content_length)
            if b"slow" in req_body:
                await asyncio.sleep(0.25)
            body = (
                b'{"id":"1","object":"chat.completion","created":1,"model":"test-model",'
                b'"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},'
                b'"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}'
            )
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode("ascii")
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle_upstream, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            app, token = _make_local_app(tmp_path, port)
            async with app.router.lifespan_context(app):
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://gateway.local") as client:
                    headers = {"Authorization": f"Bearer {token}"}
                    slow_task = asyncio.create_task(
                        client.post(
                            "/v1/chat/completions",
                            headers=headers,
                            json={"model": "fast", "messages": [{"role": "user", "content": "slow"}]},
                        )
                    )
                    await asyncio.sleep(0.05)
                    fast_resp = await client.post(
                        "/v1/chat/completions",
                        headers=headers,
                        json={"model": "fast", "messages": [{"role": "user", "content": "fast"}]},
                    )
                    slow_resp = await slow_task
                    assert fast_resp.status_code == 200
                    assert slow_resp.status_code == 200
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())
