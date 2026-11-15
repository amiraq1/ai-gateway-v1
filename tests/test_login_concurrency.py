from __future__ import annotations

import asyncio
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from argon2 import PasswordHasher

from app.auth import (
    Argon2Busy,
    Argon2Gate,
    LoginPolicy,
    _verify_login_secret,
    authenticate_admin,
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


async def _wait_until(predicate, timeout: float = 5.0) -> None:
    """Poll a condition on the event loop. Assertions depend on the final state, not on timing."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition was not reached in time")
        await asyncio.sleep(0.005)


def test_running_and_queued_jobs_share_one_limit():
    gate = Argon2Gate(concurrency=2, queue=4)
    release = threading.Event()
    lock = threading.Lock()
    counts = {"running": 0, "peak": 0, "started": 0}

    def job() -> str:
        with lock:
            counts["running"] += 1
            counts["started"] += 1
            counts["peak"] = max(counts["peak"], counts["running"])
        release.wait(10)
        with lock:
            counts["running"] -= 1
        return "ok"

    async def scenario() -> None:
        tasks = [asyncio.ensure_future(gate.run(job)) for _ in range(9)]
        await _wait_until(lambda: gate.admitted == 6)  # two running plus four queued
        await _wait_until(lambda: counts["started"] == 2)
        await asyncio.sleep(0.05)  # a third job would have started by now if the limit were wrong
        refused = [task for task in tasks if task.done()]
        assert len(refused) == 3
        assert all(isinstance(task.exception(), Argon2Busy) for task in refused)
        assert gate.admitted == 6 and counts["started"] == 2 and counts["peak"] == 2
        release.set()
        assert await asyncio.gather(*(task for task in tasks if not task.done())) == ["ok"] * 6
        await _wait_until(lambda: gate.admitted == 0)
        assert counts["started"] == 6 and counts["peak"] == 2
        assert await gate.run(lambda: "again") == "again"

    asyncio.run(scenario())


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
    with serve_slow_provider() as slow:
        provider = ProviderConfig("slow", "stub-model", f"http://127.0.0.1:{slow.port}/v1",
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


def test_cancelled_caller_keeps_its_slot_until_the_running_hash_finishes():
    gate = Argon2Gate(concurrency=1, queue=0)
    release = threading.Event()
    started = threading.Event()

    def job() -> str:
        started.set()
        release.wait(10)
        return "finished"

    async def scenario() -> None:
        task = asyncio.ensure_future(gate.run(job))
        await _wait_until(started.is_set)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert gate.admitted == 1  # the hash is still running, so its slot is still taken
        with pytest.raises(Argon2Busy):
            await gate.run(lambda: "second")
        release.set()
        await _wait_until(lambda: gate.admitted == 0)
        assert await gate.run(lambda: "third") == "third"

    asyncio.run(scenario())


def test_cancelled_queued_job_never_runs_and_frees_its_slot():
    gate = Argon2Gate(concurrency=1, queue=1)
    release = threading.Event()
    ran: list[str] = []

    def blocker() -> str:
        release.wait(10)
        return "first"

    def queued() -> str:
        ran.append("queued")
        return "queued"

    async def scenario() -> None:
        first = asyncio.ensure_future(gate.run(blocker))
        await _wait_until(lambda: gate.admitted == 1)
        second = asyncio.ensure_future(gate.run(queued))
        await _wait_until(lambda: gate.admitted == 2)
        second.cancel()
        with pytest.raises(asyncio.CancelledError):
            await second
        await _wait_until(lambda: gate.admitted == 1)  # freed as soon as the queued job is cancelled
        release.set()
        assert await first == "first"
        await _wait_until(lambda: gate.admitted == 0)

    asyncio.run(scenario())
    assert ran == []


def test_success_and_failure_both_free_the_slot():
    gate = Argon2Gate(concurrency=1, queue=0)

    def failing() -> None:
        raise ValueError("synthetic failure")

    async def scenario() -> None:
        assert await gate.run(lambda: 1) == 1
        assert gate.admitted == 0
        with pytest.raises(ValueError):
            await gate.run(failing)
        assert gate.admitted == 0
        assert await gate.run(lambda: 2) == 2

    asyncio.run(scenario())


def _login_attempt(db, gate, username: str):
    return authenticate_admin(db, gate, username=username, password=WRONG_PASSWORD, ip_key="198.51.100.9",
                              ip_address="198.51.100.9", user_agent=None, policy=LoginPolicy(100, 900),
                              session_ttl_seconds=600)


def _reservations(db) -> int:
    with db.connect() as conn:
        return int(conn.execute("SELECT count(*) FROM login_attempts").fetchone()[0])


def test_unknown_user_is_checked_through_the_same_gate(tmp_path, monkeypatch):
    _app, db = build_gateway_app(tmp_path)
    bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
    gate = Argon2Gate(concurrency=1, queue=0)
    entered = threading.Event()
    release = threading.Event()
    original = _verify_login_secret

    def blocking(stored_hash, candidate):
        entered.set()
        release.wait(10)
        return original(stored_hash, candidate)

    monkeypatch.setattr("app.auth._verify_login_secret", blocking)

    async def scenario() -> None:
        first = asyncio.ensure_future(_login_attempt(db, gate, "nobody-here"))
        await _wait_until(entered.is_set)
        assert gate.admitted == 1  # the dummy check holds the only slot
        with pytest.raises(Argon2Busy):
            await _login_attempt(db, gate, ADMIN_USER)
        release.set()
        result = await first
        assert result.outcome == "invalid_credentials"
        await _wait_until(lambda: gate.admitted == 0)

    asyncio.run(scenario())
    assert _reservations(db) == 1  # only the unknown-user attempt, which was checked


def test_only_an_admission_refusal_releases_the_attempt_reservation(tmp_path, monkeypatch):
    _app, db = build_gateway_app(tmp_path)
    bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
    gate = Argon2Gate(concurrency=1, queue=0)
    entered = threading.Event()
    release = threading.Event()
    original = _verify_login_secret

    def blocking(stored_hash, candidate):
        entered.set()
        release.wait(10)
        return original(stored_hash, candidate)

    monkeypatch.setattr("app.auth._verify_login_secret", blocking)

    async def scenario() -> None:
        holder = asyncio.ensure_future(_login_attempt(db, gate, ADMIN_USER))
        await _wait_until(entered.is_set)
        assert _reservations(db) == 1
        with pytest.raises(Argon2Busy):
            await _login_attempt(db, gate, ADMIN_USER)  # refused before any check started
        assert _reservations(db) == 1  # its own reservation was released
        holder.cancel()  # cancelled after admission, while the check is running
        with pytest.raises(asyncio.CancelledError):
            await holder
        assert _reservations(db) == 1  # cancellation keeps the reservation
        assert gate.admitted == 1  # and the slot, until the check finishes
        release.set()
        await _wait_until(lambda: gate.admitted == 0)
        assert _reservations(db) == 1

    asyncio.run(scenario())


def test_each_login_is_admitted_once_even_when_the_stored_hash_is_upgraded(tmp_path):
    app, db = build_gateway_app(tmp_path)
    weak_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(ADMIN_PASSWORD)
    now = int(time.time())
    with db.transaction() as conn:
        conn.execute("INSERT INTO admin_users(username, password_hash, is_active, created_at, updated_at) "
                     "VALUES (?, ?, 1, ?, ?)", (ADMIN_USER, weak_hash, now, now))
    gate = app.state.argon2_gate
    admissions: list[str] = []
    original_run = gate.run

    async def counting_run(func, *args):
        admissions.append(func.__name__)
        return await original_run(func, *args)

    gate.run = counting_run  # shadows the method on this gate instance only

    async def scenario():
        return await authenticate_admin(db, gate, username=ADMIN_USER, password=ADMIN_PASSWORD,
                                        ip_key="198.51.100.9", ip_address="198.51.100.9", user_agent=None,
                                        policy=LoginPolicy(100, 900), session_ttl_seconds=600)

    result = asyncio.run(scenario())
    assert result.outcome == "success"
    assert admissions == ["_verify_login_secret"]
    with db.connect() as conn:
        stored = str(conn.execute("SELECT password_hash FROM admin_users WHERE username = ?",
                                  (ADMIN_USER,)).fetchone()[0])
    assert stored != weak_hash
    assert PasswordHasher().check_needs_rehash(stored) is False
    assert PasswordHasher().verify(stored, ADMIN_PASSWORD)


def test_hard_limits_hold_under_live_login_load(tmp_path, monkeypatch):
    release = threading.Event()
    entered: list[int] = []
    lock = threading.Lock()
    original = _verify_login_secret

    def blocking(stored_hash, candidate):
        with lock:
            entered.append(1)
        release.wait(20)
        return original(stored_hash, candidate)

    monkeypatch.setattr("app.auth._verify_login_secret", blocking)
    app, db = build_gateway_app(tmp_path, admin_password_hash_concurrency=2, admin_password_hash_queue=4,
                                admin_login_max_failures=100)
    bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
    gate = app.state.argon2_gate
    with serve_https(app, tmp_path / "tls") as (base, tls):
        with httpx.Client(base_url=base, verify=tls, trust_env=False, timeout=60) as client:
            def attempt(_index: int) -> int:
                return client.post("/api/admin/login", json={"username": ADMIN_USER, "password": WRONG_PASSWORD}).status_code

            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(attempt, index) for index in range(8)]
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    answered = sum(1 for future in futures if future.done())
                    if len(entered) == 2 and gate.admitted == 6 and answered == 2:
                        break
                    time.sleep(0.02)
                # Two checks run, four wait, and two requests were refused at once.
                assert len(entered) == 2 and gate.admitted == 6
                assert sum(1 for future in futures if future.done()) == 2
                assert sorted(future.result() for future in futures if future.done()) == [503, 503]
                release.set()
                statuses = sorted(future.result() for future in futures)
    assert statuses == [401] * 6 + [503] * 2
    assert gate.admitted == 0
    assert _reservations(db) == 6  # the refused requests left no reservation behind


def test_healthz_models_and_chat_keep_working_during_login_load(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    monkeypatch.setenv("SLOW_STUB_API_KEY", "synthetic-slow-stub-key")
    original = _verify_login_secret

    def slow(stored_hash, candidate):
        time.sleep(0.4)  # each check holds a gate slot for a while, so the streams overlap real Argon2 work
        return original(stored_hash, candidate)

    monkeypatch.setattr("app.auth._verify_login_secret", slow)
    with serve_slow_provider() as stub:
        provider = ProviderConfig("slow", "stub-model", f"http://127.0.0.1:{stub.port}/v1", "SLOW_STUB_API_KEY", True,
                                  trusted_internal_networks=(ipaddress.ip_network("127.0.0.0/8"),))
        app, db = build_gateway_app(tmp_path, providers=[provider], admin_login_max_failures=100)
        bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
        bearer = create_client_key(db, PEPPER, "responsiveness-client", 600)[1]
        with serve_https(app, tmp_path / "tls") as (base, tls):
            with httpx.Client(base_url=base, verify=tls, trust_env=False, timeout=60) as browser:
                csrf = _admin_login_csrf(browser)
                cookies = browser.cookies

                def admin_chat() -> tuple[int, str]:
                    with httpx.Client(base_url=base, verify=tls, trust_env=False, timeout=60, cookies=cookies) as worker:
                        response = worker.post("/api/chat/completions", headers={"X-CSRF-Token": csrf},
                                               json={"model": "fast", "message": "chat during login load",
                                                     "stream": True})
                    return response.status_code, response.text

                def v1_stream() -> tuple[int, str]:
                    with httpx.Client(base_url=base, verify=tls, trust_env=False, timeout=60) as worker:
                        response = worker.post("/v1/chat/completions", headers={"Authorization": f"Bearer {bearer}"},
                                               json={"model": "fast", "stream": True,
                                                     "messages": [{"role": "user", "content": "hello"}]})
                    return response.status_code, response.text

                def wrong_login(_index: int) -> int:
                    with httpx.Client(base_url=base, verify=tls, trust_env=False, timeout=60) as worker:
                        return worker.post("/api/admin/login",
                                           json={"username": ADMIN_USER, "password": WRONG_PASSWORD}).status_code

                latencies: dict[str, list[float]] = {"healthz": [], "models": []}
                with ThreadPoolExecutor(max_workers=16) as pool:
                    chat_future = pool.submit(admin_chat)
                    v1_future = pool.submit(v1_stream)
                    time.sleep(0.1)
                    login_futures = [pool.submit(wrong_login, index) for index in range(12)]
                    with httpx.Client(base_url=base, verify=tls, trust_env=False, timeout=60) as probe:
                        for _ in range(15):
                            started = time.perf_counter()
                            assert probe.get("/healthz").status_code == 200
                            latencies["healthz"].append(time.perf_counter() - started)
                            started = time.perf_counter()
                            models = probe.get("/v1/models", headers={"Authorization": f"Bearer {bearer}"})
                            assert models.status_code == 200
                            assert "fast" in [item["id"] for item in models.json()["data"]]
                            latencies["models"].append(time.perf_counter() - started)
                            time.sleep(0.05)
                    statuses = [future.result() for future in login_futures]
                    chat_status, chat_text = chat_future.result()
                    v1_status, v1_text = v1_future.result()
    assert chat_status == 200 and chat_text.count("part-") == 10 and "data: [DONE]" in chat_text
    assert v1_status == 200 and v1_text.count("part-") == 10 and "data: [DONE]" in v1_text
    assert set(statuses) <= {401, 503}
    assert max(latencies["healthz"]) < 1.0 and max(latencies["models"]) < 1.0


def _admin_login_csrf(client: httpx.Client) -> str:
    response = client.post("/api/admin/login", json={"username": ADMIN_USER, "password": ADMIN_PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]
