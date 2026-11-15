from __future__ import annotations

import asyncio
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

from app.auth import (
    Argon2Busy,
    Argon2Gate,
    _verify_login_secret,
    bootstrap_first_admin,
    create_client_key,
    hash_admin_password,
)
from app.config import ProviderConfig
from tests.support import build_gateway_app, serve_https, serve_slow_provider

PEPPER = "test-pepper-that-is-at-least-32-bytes-long"
ADMIN_USER = "admin"
ADMIN_PASSWORD = "synthetic-admin-password-123"  # test marker, not a credential
WRONG_PASSWORD = "wrong-synthetic-password-value"


def set_cookie_names(response: httpx.Response) -> set[str]:
    return {raw.split("=", 1)[0] for raw in response.headers.get_list("set-cookie")}


def test_gate_runs_at_most_concurrency_jobs_and_refuses_the_rest():
    gate = Argon2Gate(concurrency=2, queue=4)
    lock = threading.Lock()
    state = {"running": 0, "peak": 0}

    def job() -> bool:
        with lock:
            state["running"] += 1
            state["peak"] = max(state["peak"], state["running"])
        time.sleep(0.05)
        with lock:
            state["running"] -= 1
        return True

    async def scenario():
        return await asyncio.gather(*(gate.run(job) for _ in range(10)), return_exceptions=True)

    results = asyncio.run(scenario())
    accepted = [item for item in results if item is True]
    refused = [item for item in results if isinstance(item, Argon2Busy)]
    assert len(accepted) == 6  # two running plus four queued
    assert len(refused) == 4
    assert state["peak"] == 2


def test_real_argon2_checks_do_not_stall_the_event_loop():
    gate = Argon2Gate(concurrency=2, queue=8)
    stored = hash_admin_password("synthetic-password-for-loop-check")
    gaps: list[float] = []

    async def ticker(stop: asyncio.Event) -> None:
        last = time.perf_counter()
        while not stop.is_set():
            await asyncio.sleep(0.005)
            now = time.perf_counter()
            gaps.append(now - last)
            last = now

    async def scenario() -> None:
        stop = asyncio.Event()
        task = asyncio.create_task(ticker(stop))
        results = await asyncio.gather(*(gate.run(_verify_login_secret, stored, "synthetic-password-for-loop-check")
                                         for _ in range(4)))
        stop.set()
        await task
        assert all(ok for ok, _rehash in results)

    asyncio.run(scenario())
    # Four verifications take about 220 ms on this machine when run inline. The largest
    # gap seen by the loop must stay far below that.
    assert max(gaps) < 0.1


def test_login_beyond_capacity_is_refused_without_recording_a_failed_attempt(tmp_path, monkeypatch):
    original = _verify_login_secret

    def slow_verify(stored_hash, candidate):
        time.sleep(0.2)
        return original(stored_hash, candidate)

    monkeypatch.setattr("app.auth._verify_login_secret", slow_verify)
    app, db = build_gateway_app(tmp_path, admin_password_hash_concurrency=1,
                                admin_password_hash_queue=1, admin_login_max_failures=100)
    bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
    with serve_https(app, tmp_path / "tls") as (base, tls):
        with httpx.Client(base_url=base, verify=tls, trust_env=False, timeout=30) as client:
            def attempt(_index: int) -> tuple[int, str | None]:
                response = client.post("/api/admin/login", json={"username": ADMIN_USER, "password": WRONG_PASSWORD})
                return response.status_code, response.headers.get("retry-after")

            with ThreadPoolExecutor(max_workers=8) as pool:
                outcomes = list(pool.map(attempt, range(8)))
    statuses = [status for status, _ in outcomes]
    assert set(statuses) <= {401, 503}
    assert statuses.count(503) >= 5
    assert all(retry_after == "2" for status, retry_after in outcomes if status == 503)
    with db.connect() as conn:
        reserved = conn.execute("SELECT count(*) FROM login_attempts").fetchone()[0]
    assert reserved == statuses.count(401)


def test_login_pressure_keeps_sse_and_healthz_responsive(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    monkeypatch.setenv("SLOW_STUB_API_KEY", "synthetic-slow-stub-key")
    with serve_slow_provider() as provider_port:
        provider = ProviderConfig("slow", "stub-model", f"http://127.0.0.1:{provider_port}/v1",
                                  "SLOW_STUB_API_KEY", True,
                                  trusted_internal_networks=(ipaddress.ip_network("127.0.0.0/8"),))
        app, db = build_gateway_app(tmp_path, providers=[provider], admin_login_max_failures=100)
        bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
        bearer = create_client_key(db, PEPPER, "sse-under-pressure", 600)[1]
        body = {"model": "fast", "stream": True, "messages": [{"role": "user", "content": "hello"}]}
        with serve_https(app, tmp_path / "tls") as (base, tls):
            with httpx.Client(base_url=base, verify=tls, trust_env=False, timeout=60) as client:
                stream_result: dict[str, object] = {}

                def stream() -> None:
                    with client.stream("POST", "/v1/chat/completions",
                                       headers={"Authorization": f"Bearer {bearer}"}, json=body) as response:
                        stream_result["status"] = response.status_code
                        stream_result["text"] = response.read().decode("utf-8")

                def pressure(_index: int) -> int:
                    return client.post("/api/admin/login",
                                       json={"username": ADMIN_USER, "password": WRONG_PASSWORD}).status_code

                latencies: list[float] = []
                with ThreadPoolExecutor(max_workers=16) as pool:
                    stream_future = pool.submit(stream)
                    time.sleep(0.2)
                    login_futures = [pool.submit(pressure, index) for index in range(12)]
                    for _ in range(15):
                        started = time.perf_counter()
                        assert client.get("/healthz").status_code == 200
                        latencies.append(time.perf_counter() - started)
                        time.sleep(0.05)
                    statuses = [future.result() for future in login_futures]
                    stream_future.result()
    assert stream_result["status"] == 200
    text = str(stream_result["text"])
    assert text.count("part-") == 10 and "data: [DONE]" in text
    assert set(statuses) <= {401, 503}
    assert max(latencies) < 1.0


def test_concurrent_gets_and_posts_from_two_tabs_keep_one_csrf_token(tmp_path):
    app, db = build_gateway_app(tmp_path)
    bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
    with serve_https(app, tmp_path / "tls") as (base, tls):
        with httpx.Client(base_url=base, verify=tls, trust_env=False, timeout=30) as browser:
            login = browser.post("/api/admin/login", json={"username": ADMIN_USER, "password": ADMIN_PASSWORD})
            assert login.status_code == 200
            csrf = login.json()["csrf_token"]

            def read_session(_index: int) -> tuple[str, bool]:
                response = browser.get("/api/admin/session")
                return response.json()["csrf_token"], bool(set_cookie_names(response))

            def write_rule(index: int) -> int:
                # Deny rules for other addresses cannot lock out the loopback caller.
                return browser.post("/api/admin/ip-rules", headers={"X-CSRF-Token": csrf},
                                    json={"rule_type": "deny", "ip_or_cidr": f"203.0.113.{index}/32",
                                          "description": "concurrency check"}).status_code

            with ThreadPoolExecutor(max_workers=10) as pool:
                reads = list(pool.map(read_session, range(20)))
                writes = list(pool.map(write_rule, range(20)))
            assert all(token == csrf for token, _rewritten in reads)
            assert not any(rewritten for _token, rewritten in reads)
            assert writes == [201] * 20
            with httpx.Client(base_url=base, verify=tls, trust_env=False, cookies=browser.cookies) as reloaded:
                assert reloaded.get("/api/admin/session").json()["csrf_token"] == csrf
