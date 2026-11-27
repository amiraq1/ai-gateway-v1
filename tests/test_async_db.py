from __future__ import annotations

import asyncio
import sqlite3
import threading
import time

import httpx

from app.auth import create_client_key
from app.config import GatewayConfig, GatewaySettings, ModelConfig, ProviderConfig
from app.database import Database, _ClosingConnection
from app.main import create_app


PEPPER = "test-pepper-that-is-at-least-32-bytes-long"


def test_wal_mode_is_set_in_init_not_on_every_connect(tmp_path, monkeypatch):
    db_path = str(tmp_path / "wal.sqlite3")
    db = Database(db_path)
    db.init()

    executed_during_connect: list[str] = []
    real_connect = sqlite3.connect

    class RecordingConnection(_ClosingConnection):
        def execute(self, sql, parameters=()):
            executed_during_connect.append(str(sql))
            return super().execute(sql, parameters)

    def wrapped_connect(*args, **kwargs):
        kwargs["factory"] = RecordingConnection
        return real_connect(*args, **kwargs)

    monkeypatch.setattr("app.database.sqlite3.connect", wrapped_connect)
    with db.connect() as conn:
        assert not any("journal_mode" in stmt.lower() for stmt in executed_during_connect)
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]

    assert mode.lower() == "wal"


def test_sqlite_operations_run_off_event_loop_and_do_not_freeze_heartbeat(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    monkeypatch.setenv("TEST_PRIMARY_API_KEY", "provider-secret")
    settings = GatewaySettings("127.0.0.1", 8000, str(tmp_path / "async_db.sqlite3"), 5.0, 1_048_576, 30)
    provider = ProviderConfig("primary", "m", "https://primary.example/v1", "TEST_PRIMARY_API_KEY", True)
    cfg = GatewayConfig(settings, {"fast": ModelConfig("fast", True, (provider,))})
    db = Database(settings.database_path, timeout_seconds=5.0)
    app = create_app(cfg, db)
    token = create_client_key(db, PEPPER, "async-test", 60)[1]

    def ok_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "1",
                "object": "chat.completion",
                "created": 1,
                "model": "m",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            },
        )

    app.state.http_transport = httpx.MockTransport(ok_handler)

    event_loop_thread = {"id": None}
    db_threads: dict[str, int] = {}

    orig_get_client = db.get_client
    orig_consume = db.consume_rate_limit
    orig_log = db.log_request
    orig_connect = db.connect

    def tracked_get_client(*args, **kwargs):
        db_threads["auth"] = threading.get_ident()
        return orig_get_client(*args, **kwargs)

    def tracked_consume(*args, **kwargs):
        db_threads["consume"] = threading.get_ident()
        return orig_consume(*args, **kwargs)

    def tracked_log(*args, **kwargs):
        db_threads["log"] = threading.get_ident()
        return orig_log(*args, **kwargs)

    monkeypatch.setattr(db, "get_client", tracked_get_client)
    monkeypatch.setattr(db, "consume_rate_limit", tracked_consume)
    monkeypatch.setattr(db, "log_request", tracked_log)

    async def scenario():
        event_loop_thread["id"] = threading.get_ident()
        lock_acquired = threading.Event()

        def hold_exclusive_lock():
            conn = sqlite3.connect(db.path, isolation_level=None)
            conn.execute("BEGIN EXCLUSIVE")
            lock_acquired.set()
            time.sleep(0.5)
            conn.commit()
            conn.close()

        blocker = threading.Thread(target=hold_exclusive_lock)
        blocker.start()
        lock_acquired.wait(timeout=2.0)

        max_tick_gap = 0.0
        stop_ticks = False

        async def heartbeat():
            nonlocal max_tick_gap
            last = time.monotonic()
            while not stop_ticks:
                await asyncio.sleep(0.02)
                now = time.monotonic()
                max_tick_gap = max(max_tick_gap, now - last)
                last = now

        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://gateway.local") as client:
                hb_task = asyncio.create_task(heartbeat())
                resp = await client.post(
                    "/v1/chat/completions",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"model": "fast", "messages": [{"role": "user", "content": "hi"}]},
                )
                stop_ticks = True
                await hb_task

                def tracked_connect(*args, **kwargs):
                    db_threads["healthz"] = threading.get_ident()
                    return orig_connect(*args, **kwargs)

                monkeypatch.setattr(db, "connect", tracked_connect)
                health = await client.get("/healthz")
                assert resp.status_code == 200
                assert health.status_code == 200
        blocker.join(timeout=2.0)
        assert db_threads["auth"] != event_loop_thread["id"]
        assert db_threads["consume"] != event_loop_thread["id"]
        assert db_threads["log"] != event_loop_thread["id"]
        assert db_threads["healthz"] != event_loop_thread["id"]
        assert max_tick_gap < 0.25

    asyncio.run(scenario())
