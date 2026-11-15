"""Chat API tests: sessions, persistence, streaming, cancellation, idempotency, ownership, and limits.

Provider traffic is scripted with httpx.MockTransport unless a test needs a real
streaming socket. Live tests run uvicorn over TLS on 127.0.0.1 and use the slow
SSE stub from tests/support.py.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from fastapi.testclient import TestClient

from app.auth import bootstrap_first_admin, create_client_key, hash_admin_password
from app.config import ProviderConfig
from app.conversations import (
    CLAIM_STALE_SECONDS,
    MAX_ASSISTANT_BYTES,
    MAX_USER_MESSAGE_BYTES,
    ChatError,
    TurnResult,
    create_conversation,
    finish_turn,
    load_conversation,
    prepare_turn,
    trim_history,
)
from tests.support import build_gateway_app, serve_https, serve_slow_provider

PEPPER = "test-pepper-that-is-at-least-32-bytes-long"
ADMIN_USER = "admin"
ADMIN_PASSWORD = "synthetic-admin-password-123"  # test marker, not a credential
SECOND_USER = "second-admin"
SECOND_PASSWORD = "synthetic-second-admin-password-456"  # test marker, not a credential
ADMIN_IP = "198.51.100.30"
PRIMARY_KEY = "synthetic-primary-provider-key-001"  # test marker, not a credential
SECONDARY_KEY = "synthetic-secondary-provider-key-002"  # test marker, not a credential
PRIMARY = ProviderConfig("primary", "primary-model-v1", "https://primary.example/v1", "TEST_PRIMARY_API_KEY", True)
SECONDARY = ProviderConfig("secondary", "secondary-model-v1", "https://secondary.example/v1",
                           "TEST_SECONDARY_API_KEY", True)


@pytest.fixture
def chat(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    monkeypatch.setenv("TEST_PRIMARY_API_KEY", PRIMARY_KEY)
    monkeypatch.setenv("TEST_SECONDARY_API_KEY", SECONDARY_KEY)
    app, db = build_gateway_app(tmp_path, providers=[PRIMARY, SECONDARY])
    bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
    return app, db


def _admin_client(app) -> TestClient:
    return TestClient(app, base_url="https://testserver", client=(ADMIN_IP, 50000))


def _login(client: TestClient, username: str = ADMIN_USER, password: str = ADMIN_PASSWORD) -> str:
    response = client.post("/api/admin/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


def _create_conversation(client: TestClient, csrf: str, model: str = "fast") -> int:
    response = client.post("/api/chat/conversations", json={"model": model}, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def _turn(client: TestClient, csrf: str, message: str, **fields) -> httpx.Response:
    body = {"model": "fast", "message": message, **fields}
    return client.post("/api/chat/completions", json=body, headers={"X-CSRF-Token": csrf})


def _http_client(base: str, tls, cookies=None) -> httpx.Client:
    return httpx.Client(base_url=base, verify=tls, trust_env=False, timeout=60, cookies=cookies)


def _http_login(client: httpx.Client, username: str = ADMIN_USER, password: str = ADMIN_PASSWORD) -> str:
    response = client.post("/api/admin/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


def completion_json(text: str) -> dict:
    return {
        "id": "cmpl-test",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
    }


def sse_body(parts: tuple[str, ...] | list[str], done: bool = True) -> bytes:
    lines = []
    for part in parts:
        chunk = {"choices": [{"index": 0, "delta": {"content": part}}]}
        lines.append(f"data: {json.dumps(chunk)}\n\n")
    if done:
        lines.append("data: [DONE]\n\n")
    return "".join(lines).encode("utf-8")


class Upstream:
    """Scripted provider behind httpx.MockTransport. Records (host, request body) for every call."""

    def __init__(self, respond: Callable[[str, dict], httpx.Response]) -> None:
        self._respond = respond
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.calls.append((request.url.host, body))
        return self._respond(request.url.host, body)

    @property
    def hosts(self) -> list[str]:
        return [host for host, _ in self.calls]

    @property
    def bodies(self) -> list[dict]:
        return [body for _, body in self.calls]


def answering(*parts: str, done: bool = True, status: int = 200) -> Callable[[str, dict], httpx.Response]:
    """Stream requests get the parts as SSE. Other requests get one JSON completion of the joined text."""

    def respond(host: str, body: dict) -> httpx.Response:
        if status != 200:
            return httpx.Response(status, json={"error": {"message": "synthetic upstream failure"}})
        if body.get("stream"):
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=sse_body(parts, done))
        return httpx.Response(200, json=completion_json("".join(parts)))

    return respond


def primary_fails(*parts: str) -> Callable[[str, dict], httpx.Response]:
    """The primary provider returns 500, so the secondary answers as `answering` would."""
    secondary = answering(*parts)

    def respond(host: str, body: dict) -> httpx.Response:
        if host == "primary.example":
            return httpx.Response(500, json={"error": {"message": "synthetic upstream failure"}})
        return secondary(host, body)

    return respond


def _rows(db, sql: str, params: tuple = ()) -> list[dict]:
    with db.connect() as conn:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]


def _messages(db, conversation_id: int) -> list[dict]:
    return _rows(db, "SELECT * FROM messages WHERE conversation_id = ? ORDER BY id", (conversation_id,))


def _wait_for_status(db, request_id: str, wanted: set[str], timeout: float = 10.0) -> str:
    deadline = time.monotonic() + timeout
    status = None
    while time.monotonic() < deadline:
        rows = _rows(db, "SELECT status FROM messages WHERE request_id = ?", (request_id,))
        status = rows[0]["status"] if rows else None
        if status in wanted:
            return status
        time.sleep(0.02)
    raise AssertionError(f"request {request_id} stayed at {status!r}")


def _db_bytes(db) -> bytes:
    data = b""
    for suffix in ("", "-wal", "-shm"):
        try:
            with open(db.path + suffix, "rb") as handle:
                data += handle.read()
        except FileNotFoundError:
            pass
    return data


def _insert_turns(db, conversation_id: int, pairs: int) -> None:
    """Insert complete user/assistant pairs directly, so history can be set up without provider calls."""
    now = int(time.time())
    with db.transaction() as conn:
        for index in range(pairs):
            user_id = conn.execute(
                "INSERT INTO messages(conversation_id, role, content, status, created_at, completed_at) "
                "VALUES (?, 'user', ?, 'complete', ?, ?)",
                (conversation_id, f"turn-{index} question", now, now),
            ).lastrowid
            conn.execute(
                "INSERT INTO messages(conversation_id, role, content, status, reply_to_message_id, "
                "created_at, completed_at) VALUES (?, 'assistant', ?, 'complete', ?, ?, ?)",
                (conversation_id, f"turn-{index} reply", user_id, now, now),
            )


def sse_payloads(text: str) -> list[str]:
    """The data payload of each SSE event, in order."""
    payloads = []
    for block in text.split("\n\n"):
        data = [line[len("data: "):] for line in block.split("\n") if line.startswith("data: ")]
        if data:
            payloads.append("\n".join(data))
    return payloads


def deltas(payloads: list[str]) -> list[str]:
    """The content text of each chat chunk. The [DONE] marker and error events are skipped."""
    texts = []
    for payload in payloads:
        if payload == "[DONE]":
            continue
        data = json.loads(payload)
        if "choices" in data:
            texts.append(data["choices"][0]["delta"].get("content", ""))
    return texts


def _slow_app(tmp_path, monkeypatch, port: int):
    """An app whose only model is the slow SSE stub on 127.0.0.1, reached through the trusted loopback range."""
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    monkeypatch.setenv("SLOW_STUB_API_KEY", "synthetic-slow-stub-key")
    provider = ProviderConfig("slow", "stub-model", f"http://127.0.0.1:{port}/v1", "SLOW_STUB_API_KEY", True,
                              trusted_internal_networks=(ipaddress.ip_network("127.0.0.0/8"),))
    app, db = build_gateway_app(tmp_path, providers=[provider])
    bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
    return app, db


# ----------------------------------------------------------------- sessions and CSRF


def test_every_chat_route_requires_an_admin_session(chat):
    app, _db = chat
    with _admin_client(app) as anonymous:
        responses = [
            anonymous.get("/api/chat/conversations"),
            anonymous.post("/api/chat/conversations", json={"model": "fast"}),
            anonymous.get("/api/chat/conversations/1"),
            anonymous.delete("/api/chat/conversations/1"),
            anonymous.post("/api/chat/completions", json={"model": "fast", "message": "hi"}),
        ]
    assert [r.status_code for r in responses] == [401] * 5
    assert {r.json()["error"]["code"] for r in responses} == {"admin_session_required"}


def test_state_changes_need_csrf_and_an_allowed_origin(chat):
    app, db = chat
    upstream = Upstream(answering("unused"))
    app.state.http_transport = httpx.MockTransport(upstream)
    with _admin_client(app) as client:
        csrf = _login(client)
        conversation = _create_conversation(client, csrf)
        message = {"model": "fast", "message": "needs a token", "conversation_id": conversation}
        no_token = client.post("/api/chat/completions", json=message)
        forged = client.post("/api/chat/completions", json=message, headers={"X-CSRF-Token": "forged-token-value"})
        foreign = client.post("/api/chat/completions", json=message,
                              headers={"X-CSRF-Token": csrf, "Origin": "https://attacker.example"})
        no_delete = client.delete(f"/api/chat/conversations/{conversation}")
        no_create = client.post("/api/chat/conversations", json={"model": "fast"})
        listing = client.get("/api/chat/conversations")
    assert no_token.status_code == 403 and no_token.json()["error"]["code"] == "csrf_validation_failed"
    assert forged.status_code == 403
    assert foreign.status_code == 403 and foreign.json()["error"]["code"] == "origin_not_allowed"
    assert no_delete.status_code == 403 and no_create.status_code == 403
    assert listing.status_code == 200
    assert upstream.calls == []
    assert _messages(db, conversation) == []


def test_bearer_keys_cannot_use_chat_and_sessions_cannot_use_v1(chat):
    app, db = chat
    _client_id, bearer = create_client_key(db, PEPPER, "chat-tester", 600)
    app.state.http_transport = httpx.MockTransport(Upstream(answering("unused")))
    with _admin_client(app) as client:
        _login(client)
        v1_with_session = client.get("/v1/models")
    with _admin_client(app) as anonymous:
        chat_with_bearer = anonymous.get("/api/chat/conversations", headers={"Authorization": f"Bearer {bearer}"})
        v1_with_bearer = anonymous.get("/v1/models", headers={"Authorization": f"Bearer {bearer}"})
    assert v1_with_session.status_code == 401
    assert chat_with_bearer.status_code == 401
    assert v1_with_bearer.status_code == 200


def test_expired_or_idle_sessions_are_refused(chat):
    app, db = chat
    with _admin_client(app) as client:
        _login(client)
        assert client.get("/api/chat/conversations").status_code == 200
        now = int(time.time())
        with db.transaction() as conn:
            conn.execute("UPDATE user_sessions SET created_at = ?, expires_at = ?", (now - 100, now - 1))
        expired = client.get("/api/chat/conversations")
    with _admin_client(app) as client:
        _login(client)
        now = int(time.time())
        with db.transaction() as conn:
            conn.execute("UPDATE user_sessions SET created_at = ?, last_seen_at = ?, expires_at = ?",
                         (now - 5000, now - 5000, now + 3600))
        idle = client.get("/api/chat/conversations")
    assert expired.status_code == 401
    assert idle.status_code == 401


# ----------------------------------------------------------------- persistence (non-streaming)


def test_non_stream_turn_stores_both_messages_with_usage(chat):
    app, db = chat
    upstream = Upstream(answering("Hello from primary"))
    app.state.http_transport = httpx.MockTransport(upstream)
    with _admin_client(app) as client:
        csrf = _login(client)
        response = _turn(client, csrf, "hello there", request_id="req-0000001")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["choices"][0]["message"] == {"role": "assistant", "content": "Hello from primary"}
    assert body["usage"] == {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
    assert body["replayed"] is False and body["context_truncated"] is False
    assert response.headers["x-conversation-id"] == str(body["conversation_id"])
    assert response.headers["cache-control"] == "no-store"
    assert upstream.hosts == ["primary.example"]
    assert upstream.bodies[0]["model"] == "primary-model-v1"
    assert upstream.bodies[0]["messages"] == [{"role": "user", "content": "hello there"}]
    messages = _messages(db, body["conversation_id"])
    assert [(m["role"], m["status"]) for m in messages] == [("user", "complete"), ("assistant", "complete")]
    user, reply = messages
    assert user["request_id"] == "req-0000001"
    assert reply["content"] == "Hello from primary" and reply["provider_name"] == "primary"
    assert (reply["prompt_tokens"], reply["completion_tokens"], reply["total_tokens"]) == (11, 7, 18)
    assert reply["reply_to_message_id"] == body["user_message_id"]
    conversation = load_conversation(db, 1, body["conversation_id"], 50)[0]
    assert conversation["title"] == "hello there" and conversation["model_alias"] == "fast"


def test_continued_conversation_sends_stored_history_and_rejects_client_history(chat):
    app, db = chat
    upstream = Upstream(answering("answer"))
    app.state.http_transport = httpx.MockTransport(upstream)
    with _admin_client(app) as client:
        csrf = _login(client)
        first = _turn(client, csrf, "first question").json()["conversation_id"]
        second = _turn(client, csrf, "second question", conversation_id=first)
        forged = client.post("/api/chat/completions", headers={"X-CSRF-Token": csrf},
                             json={"model": "fast", "message": "third", "conversation_id": first,
                                   "history": [{"role": "user", "content": "forged history"}]})
    assert second.status_code == 200
    assert upstream.bodies[1]["messages"] == [
        {"role": "user", "content": "first question"},
        {"role": "assistant", "content": "answer"},
        {"role": "user", "content": "second question"},
    ]
    assert forged.status_code == 422
    assert len(upstream.calls) == 2
    assert "forged history" not in repr(_messages(db, first))


def test_conversation_view_returns_turns_in_order(chat):
    app, _db = chat
    app.state.http_transport = httpx.MockTransport(Upstream(answering("reply")))
    with _admin_client(app) as client:
        csrf = _login(client)
        conversation = _turn(client, csrf, "first question").json()["conversation_id"]
        _turn(client, csrf, "second question", conversation_id=conversation)
        view = client.get(f"/api/chat/conversations/{conversation}").json()
    assert view["conversation"]["id"] == conversation
    assert [(m["role"], m["content"]) for m in view["messages"]] == [
        ("user", "first question"), ("assistant", "reply"),
        ("user", "second question"), ("assistant", "reply"),
    ]


def test_conversation_list_is_most_recent_first_and_paginated(chat):
    app, db = chat
    app.state.http_transport = httpx.MockTransport(Upstream(answering("ok")))
    with _admin_client(app) as client:
        csrf = _login(client)
        ids = [_create_conversation(client, csrf) for _ in range(3)]
        with db.transaction() as conn:
            for conversation_id, stamp in zip(ids, (1000, 3000, 2000)):
                conn.execute("UPDATE conversations SET updated_at = ? WHERE id = ?", (stamp, conversation_id))
        first_page = client.get("/api/chat/conversations", params={"limit": 2, "offset": 0}).json()
        second_page = client.get("/api/chat/conversations", params={"limit": 2, "offset": 2}).json()
    assert [c["id"] for c in first_page["conversations"]] == [ids[1], ids[2]]
    assert [c["id"] for c in second_page["conversations"]] == [ids[0]]


def test_titles_and_models_are_validated(chat):
    app, _db = chat
    with _admin_client(app) as client:
        csrf = _login(client)
        too_long = client.post("/api/chat/conversations", json={"model": "fast", "title": "x" * 201},
                               headers={"X-CSRF-Token": csrf})
        unknown = client.post("/api/chat/conversations", json={"model": "no-such-model"},
                              headers={"X-CSRF-Token": csrf})
        named = client.post("/api/chat/conversations", json={"model": "fast", "title": "Project notes"},
                            headers={"X-CSRF-Token": csrf})
    assert too_long.status_code == 422
    assert unknown.status_code == 404 and unknown.json()["error"]["code"] == "model_not_found"
    assert named.status_code == 201 and named.json()["title"] == "Project notes"


# ----------------------------------------------------------------- streaming


def test_stream_forwards_chunks_in_order_and_stores_one_reply(chat):
    app, db = chat
    upstream = Upstream(answering("Hel", "lo ", "there"))
    app.state.http_transport = httpx.MockTransport(upstream)
    with _admin_client(app) as client:
        csrf = _login(client)
        response = _turn(client, csrf, "stream please", stream=True, request_id="req-stream-0001")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-cache, no-transform"
    payloads = sse_payloads(response.text)
    assert payloads[-1] == "[DONE]"
    assert deltas(payloads) == ["Hel", "lo ", "there"]
    assert upstream.bodies[0]["stream"] is True
    replies = [m for m in _messages(db, int(response.headers["x-conversation-id"])) if m["role"] == "assistant"]
    assert len(replies) == 1
    assert replies[0]["content"] == "Hello there" and replies[0]["status"] == "complete"


def test_stream_that_ends_without_done_stores_no_reply(chat):
    app, db = chat
    upstream = Upstream(answering("partial", done=False))
    app.state.http_transport = httpx.MockTransport(upstream)
    with _admin_client(app) as client:
        csrf = _login(client)
        response = _turn(client, csrf, "cut short", stream=True)
    assert response.status_code == 200
    assert '"code":"provider_stream_incomplete"' in response.text
    assert "[DONE]" not in response.text
    messages = _messages(db, int(response.headers["x-conversation-id"]))
    assert [(m["role"], m["status"]) for m in messages] == [("user", "failed")]
    assert messages[0]["error_category"] == "provider_stream_incomplete"
    assert upstream.hosts == ["primary.example"]


def test_stream_with_no_text_is_recorded_as_empty(chat):
    app, db = chat
    app.state.http_transport = httpx.MockTransport(Upstream(answering()))
    with _admin_client(app) as client:
        csrf = _login(client)
        response = _turn(client, csrf, "say nothing", stream=True)
    assert response.text.rstrip().endswith("data: [DONE]")
    messages = _messages(db, int(response.headers["x-conversation-id"]))
    assert [(m["role"], m["status"], m["error_category"]) for m in messages] == [
        ("user", "failed", "provider_empty_response")]


def test_stream_reply_over_the_limit_is_cut_and_not_stored(chat):
    app, db = chat
    part = "a" * 50_000
    app.state.http_transport = httpx.MockTransport(Upstream(answering(*([part] * 6))))
    with _admin_client(app) as client:
        csrf = _login(client)
        response = _turn(client, csrf, "very long", stream=True)
    forwarded = "".join(deltas(sse_payloads(response.text)))
    assert len(forwarded) == 5 * 50_000 <= MAX_ASSISTANT_BYTES
    assert '"code":"provider_response_too_large"' in response.text
    messages = _messages(db, int(response.headers["x-conversation-id"]))
    assert [(m["role"], m["status"]) for m in messages] == [("user", "failed")]
    assert messages[0]["error_category"] == "provider_response_too_large"


# ----------------------------------------------------------------- provider failure and fallback


def test_outage_on_both_providers_is_a_502_and_stores_no_reply(chat):
    app, db = chat
    upstream = Upstream(answering(status=500))
    app.state.http_transport = httpx.MockTransport(upstream)
    with _admin_client(app) as client:
        csrf = _login(client)
        conversation = _create_conversation(client, csrf)
        response = _turn(client, csrf, "anyone there?", conversation_id=conversation)
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "provider_unavailable"
    assert "synthetic upstream failure" not in response.text
    assert upstream.hosts == ["primary.example", "secondary.example"]
    assert [(m["role"], m["status"], m["error_category"]) for m in _messages(db, conversation)] == [
        ("user", "failed", "provider_unavailable")]


def test_fallback_answers_and_records_the_secondary_provider(chat):
    app, db = chat
    upstream = Upstream(primary_fails("from the secondary"))
    app.state.http_transport = httpx.MockTransport(upstream)
    with _admin_client(app) as client:
        csrf = _login(client)
        response = _turn(client, csrf, "fallback please")
    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "from the secondary"
    assert upstream.hosts == ["primary.example", "secondary.example"]
    assert upstream.bodies[1]["model"] == "secondary-model-v1"
    reply = [m for m in _messages(db, response.json()["conversation_id"]) if m["role"] == "assistant"][0]
    assert reply["provider_name"] == "secondary"


def test_stream_fallback_happens_before_the_first_event(chat):
    app, db = chat
    app.state.http_transport = httpx.MockTransport(Upstream(primary_fails("backup", " answer")))
    with _admin_client(app) as client:
        csrf = _login(client)
        response = _turn(client, csrf, "fallback stream", stream=True)
    assert deltas(sse_payloads(response.text)) == ["backup", " answer"]
    reply = [m for m in _messages(db, int(response.headers["x-conversation-id"])) if m["role"] == "assistant"]
    assert reply[0]["content"] == "backup answer" and reply[0]["provider_name"] == "secondary"


def test_empty_non_stream_reply_is_refused(chat):
    app, db = chat
    app.state.http_transport = httpx.MockTransport(Upstream(answering("")))
    with _admin_client(app) as client:
        csrf = _login(client)
        response = _turn(client, csrf, "empty answer please")
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "provider_empty_response"
    assert [(m["role"], m["status"]) for m in _messages(db, int(response.headers["x-conversation-id"]))] == [
        ("user", "failed")]


def test_non_stream_reply_over_the_limit_is_refused(chat):
    app, db = chat
    app.state.http_transport = httpx.MockTransport(Upstream(answering("x" * (MAX_ASSISTANT_BYTES + 1))))
    with _admin_client(app) as client:
        csrf = _login(client)
        response = _turn(client, csrf, "huge answer please")
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "provider_response_too_large"
    assert [m["role"] for m in _messages(db, int(response.headers["x-conversation-id"]))] == ["user"]


def test_reply_with_a_lone_surrogate_is_refused_without_a_server_error(chat):
    app, db = chat

    def respond(host: str, body: dict) -> httpx.Response:
        raw = (b'{"id":"x","object":"chat.completion","choices":[{"index":0,"message":'
               b'{"role":"assistant","content":"bad \\ud800 text"}}]}')
        return httpx.Response(200, headers={"content-type": "application/json"}, content=raw)

    app.state.http_transport = httpx.MockTransport(Upstream(respond))
    with _admin_client(app) as client:
        csrf = _login(client)
        response = _turn(client, csrf, "surrogate check")
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "provider_malformed_response"
    assert [(m["role"], m["status"]) for m in _messages(db, int(response.headers["x-conversation-id"]))] == [
        ("user", "failed")]


# ----------------------------------------------------------------- input limits and idempotency


@pytest.mark.parametrize(("message", "code"), [
    ("", "invalid_request"),
    ("   ", "invalid_message"),
    ("a" * (MAX_USER_MESSAGE_BYTES + 1), "message_too_large"),
    ("\u00e9" * 20_000, "message_too_large"),  # 20,000 characters but 40,000 UTF-8 bytes
])
def test_message_size_and_content_are_checked_before_anything_is_stored(chat, message, code):
    app, db = chat
    upstream = Upstream(answering("unused"))
    app.state.http_transport = httpx.MockTransport(upstream)
    with _admin_client(app) as client:
        csrf = _login(client)
        response = _turn(client, csrf, message)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == code
    assert upstream.calls == []
    assert _rows(db, "SELECT COUNT(*) AS n FROM conversations")[0]["n"] == 0


def test_a_message_at_the_byte_limit_is_accepted(chat):
    app, _db = chat
    app.state.http_transport = httpx.MockTransport(Upstream(answering("ok")))
    with _admin_client(app) as client:
        csrf = _login(client)
        response = _turn(client, csrf, "a" * MAX_USER_MESSAGE_BYTES)
    assert response.status_code == 200


def test_message_with_a_lone_surrogate_is_refused(chat):
    app, db = chat
    app.state.http_transport = httpx.MockTransport(Upstream(answering("unused")))
    with _admin_client(app) as client:
        csrf = _login(client)
        response = client.post("/api/chat/completions", content=b'{"model":"fast","message":"bad \\ud800 text"}',
                               headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"})
    # The JSON parser rejects the lone-surrogate escape before the route runs, so the generic
    # validation code is returned. The route's own check covers callers that bypass HTTP parsing.
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"
    assert _rows(db, "SELECT COUNT(*) AS n FROM messages")[0]["n"] == 0


@pytest.mark.parametrize("fields", [
    {"model": "no-such-model"},
    {"request_id": "abc"},
    {"request_id": "bad id with spaces"},
    {"conversation_id": "not-a-number"},
    {"user_id": 1},
])
def test_unknown_or_malformed_turn_fields_are_refused(chat, fields):
    app, _db = chat
    app.state.http_transport = httpx.MockTransport(Upstream(answering("unused")))
    with _admin_client(app) as client:
        csrf = _login(client)
        response = _turn(client, csrf, "fields check", **fields)
    assert response.status_code in {404, 422}
    if "model" in fields:
        assert response.json()["error"]["code"] == "model_not_found"


def test_repeated_request_id_replays_the_stored_reply_without_a_provider_call(chat):
    app, db = chat
    upstream = Upstream(answering("R1"))
    app.state.http_transport = httpx.MockTransport(upstream)
    with _admin_client(app) as client:
        csrf = _login(client)
        first = _turn(client, csrf, "same message", request_id="req-replay-01")
        again = _turn(client, csrf, "same message", request_id="req-replay-01")
        streamed = _turn(client, csrf, "same message", request_id="req-replay-01", stream=True)
    assert first.status_code == 200 and first.json()["replayed"] is False
    assert again.status_code == 200 and again.json()["replayed"] is True
    assert again.json()["message_id"] == first.json()["message_id"]
    assert again.json()["choices"][0]["message"]["content"] == "R1"
    assert streamed.headers["x-replayed"] == "1"
    assert deltas(sse_payloads(streamed.text)) == ["R1"]
    assert sse_payloads(streamed.text)[-1] == "[DONE]"
    assert len(upstream.calls) == 1
    assert len(_messages(db, first.json()["conversation_id"])) == 2


def test_request_id_cannot_be_reused_for_other_text_or_another_conversation(chat):
    app, _db = chat
    upstream = Upstream(answering("R"))
    app.state.http_transport = httpx.MockTransport(upstream)
    with _admin_client(app) as client:
        csrf = _login(client)
        first = _turn(client, csrf, "first text", request_id="req-conflict-01")
        other_text = _turn(client, csrf, "different text", request_id="req-conflict-01")
        other_conversation = _create_conversation(client, csrf)
        elsewhere = _turn(client, csrf, "first text", request_id="req-conflict-01",
                          conversation_id=other_conversation)
    assert first.status_code == 200
    assert other_text.status_code == 409 and other_text.json()["error"]["code"] == "request_id_conflict"
    assert elsewhere.status_code == 409 and elsewhere.json()["error"]["code"] == "request_id_conflict"
    assert len(upstream.calls) == 1


# ----------------------------------------------------------------- live server: duplicates, disconnects, parallel turns


def test_duplicate_request_while_processing_gets_409_and_one_provider_call(tmp_path, monkeypatch):
    with serve_slow_provider() as slow:
        app, db = _slow_app(tmp_path, monkeypatch, slow.port)
        with serve_https(app, tmp_path / "tls") as (base, tls):
            with _http_client(base, tls) as browser:
                csrf = _http_login(browser)
                headers = {"X-CSRF-Token": csrf}
                body = {"model": "fast", "message": "duplicate check", "stream": True,
                        "request_id": "req-dup-000001"}

                def original() -> httpx.Response:
                    with _http_client(base, tls, browser.cookies) as worker:
                        return worker.post("/api/chat/completions", json=body, headers=headers)

                with ThreadPoolExecutor(max_workers=1) as pool:
                    pending = pool.submit(original)
                    _wait_for_status(db, "req-dup-000001", {"processing"})
                    with _http_client(base, tls, browser.cookies) as second:
                        duplicate = second.post("/api/chat/completions", json=body, headers=headers)
                    first = pending.result(timeout=60)
                with _http_client(base, tls, browser.cookies) as third:
                    replay = third.post("/api/chat/completions", json=body, headers=headers)
    assert first.status_code == 200 and sse_payloads(first.text)[-1] == "[DONE]"
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "request_in_progress"
    assert duplicate.headers["retry-after"] == "2"
    assert replay.status_code == 200 and replay.headers["x-replayed"] == "1"
    assert deltas(sse_payloads(replay.text)) == ["".join(f"part-{i} " for i in range(10))]
    assert len(slow.hits) == 1


def test_client_disconnect_mid_stream_stores_no_reply(tmp_path, monkeypatch):
    with serve_slow_provider() as slow:
        app, db = _slow_app(tmp_path, monkeypatch, slow.port)
        with serve_https(app, tmp_path / "tls") as (base, tls):
            with _http_client(base, tls) as browser:
                csrf = _http_login(browser)
                body = {"model": "fast", "message": "disconnect me", "stream": True,
                        "request_id": "req-cancel-0001"}
                seen = ""
                with browser.stream("POST", "/api/chat/completions", json=body,
                                    headers={"X-CSRF-Token": csrf}) as response:
                    assert response.status_code == 200
                    for text in response.iter_text():
                        seen += text
                        if "part-0" in seen:
                            break
                status = _wait_for_status(db, "req-cancel-0001", {"complete", "failed", "cancelled"})
    assert status == "cancelled"
    user = _rows(db, "SELECT error_category FROM messages WHERE request_id = ?", ("req-cancel-0001",))[0]
    assert user["error_category"] == "client_disconnected"
    assert _rows(db, "SELECT COUNT(*) AS n FROM messages WHERE role = 'assistant'")[0]["n"] == 0
    assert len(slow.hits) == 1


def test_parallel_turns_in_new_conversations_all_persist(chat, tmp_path):
    app, db = chat
    app.state.http_transport = httpx.MockTransport(Upstream(answering("parallel reply")))
    with serve_https(app, tmp_path / "tls") as (base, tls):
        with _http_client(base, tls) as browser:
            csrf = _http_login(browser)

            def send(index: int) -> int:
                with _http_client(base, tls, browser.cookies) as worker:
                    response = worker.post("/api/chat/completions", headers={"X-CSRF-Token": csrf},
                                           json={"model": "fast", "message": f"parallel {index}",
                                                 "request_id": f"req-parallel-{index:04d}"})
                return response.status_code

            with ThreadPoolExecutor(max_workers=8) as pool:
                statuses = list(pool.map(send, range(8)))
    assert statuses == [200] * 8
    assert _rows(db, "SELECT COUNT(*) AS n FROM conversations")[0]["n"] == 8
    grouped: dict[int, list[tuple[str, str]]] = {}
    for row in _rows(db, "SELECT conversation_id, role, status FROM messages ORDER BY conversation_id, id"):
        grouped.setdefault(row["conversation_id"], []).append((row["role"], row["status"]))
    assert len(grouped) == 8
    assert all(pairs == [("user", "complete"), ("assistant", "complete")] for pairs in grouped.values())


# ----------------------------------------------------------------- ownership, delete, audit


def test_another_admin_cannot_read_continue_or_delete_a_conversation(chat):
    app, db = chat
    owner_upstream = Upstream(answering("owner reply"))
    app.state.http_transport = httpx.MockTransport(owner_upstream)
    now = int(time.time())
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO admin_users(username, password_hash, is_active, created_at, updated_at) VALUES (?, ?, 1, ?, ?)",
            (SECOND_USER, hash_admin_password(SECOND_PASSWORD), now, now),
        )
    with _admin_client(app) as owner:
        owner_csrf = _login(owner)
        conversation = _turn(owner, owner_csrf, "private text").json()["conversation_id"]
        calls_before = len(owner_upstream.calls)
    with _admin_client(app) as other:
        other_csrf = _login(other, SECOND_USER, SECOND_PASSWORD)
        read = other.get(f"/api/chat/conversations/{conversation}")
        missing = other.get("/api/chat/conversations/999999")
        intrude = _turn(other, other_csrf, "intrude", conversation_id=conversation)
        delete = other.delete(f"/api/chat/conversations/{conversation}", headers={"X-CSRF-Token": other_csrf})
        listing = other.get("/api/chat/conversations").json()["conversations"]
    assert read.status_code == 404 and read.json()["error"]["code"] == "conversation_not_found"
    assert read.json() == missing.json()  # not-owned and missing look the same
    assert intrude.status_code == 404 and intrude.json()["error"]["code"] == "conversation_not_found"
    assert delete.status_code == 404
    assert listing == []
    assert len(owner_upstream.calls) == calls_before  # the intruder never reached the provider
    assert [m["role"] for m in _messages(db, conversation)] == ["user", "assistant"]


def test_delete_removes_messages_and_audits_without_text(chat):
    app, db = chat
    marker = "MARKER-DELETE-4417-private"
    app.state.http_transport = httpx.MockTransport(Upstream(answering("reply")))
    with _admin_client(app) as client:
        csrf = _login(client)
        conversation = _turn(client, csrf, marker).json()["conversation_id"]
        deleted = client.delete(f"/api/chat/conversations/{conversation}", headers={"X-CSRF-Token": csrf})
        again = client.delete(f"/api/chat/conversations/{conversation}", headers={"X-CSRF-Token": csrf})
        gone = client.get(f"/api/chat/conversations/{conversation}")
    assert deleted.status_code == 200
    assert deleted.json() == {"status": "deleted", "id": conversation}
    assert again.status_code == 404 and gone.status_code == 404
    assert _rows(db, "SELECT COUNT(*) AS n FROM messages WHERE conversation_id = ?", (conversation,))[0]["n"] == 0
    audit = _rows(db, "SELECT * FROM audit_logs WHERE action = 'chat.conversation.delete'")
    assert len(audit) == 1
    assert audit[0]["target"] == f"conversation:{conversation}"
    assert audit[0]["admin_user_id"] == 1 and audit[0]["ip_address"] == ADMIN_IP
    assert audit[0]["metadata"] is None
    assert marker not in repr(_rows(db, "SELECT * FROM audit_logs"))


def test_admin_allowlist_blocks_admin_routes_but_not_chat(chat):
    app, db = chat
    app.state.http_transport = httpx.MockTransport(Upstream(answering("ok")))
    with _admin_client(app) as client:
        csrf = _login(client)
        conversation = _create_conversation(client, csrf)
        with db.transaction() as conn:
            conn.execute("INSERT INTO admin_ip_rules(rule_type, ip_or_cidr, description, is_active, created_at) "
                         "VALUES ('allow', '203.0.113.0/24', 'other office', 1, ?)", (int(time.time()),))
        admin_blocked = client.get("/api/admin/session")
        chat_listing = client.get("/api/chat/conversations")
        chat_turn = _turn(client, csrf, "still allowed", conversation_id=conversation)
    assert admin_blocked.status_code == 403
    assert chat_listing.status_code == 200
    assert chat_turn.status_code == 200


def test_history_sent_to_the_provider_is_capped_and_flagged(chat):
    app, db = chat
    upstream = Upstream(answering("ok"))
    app.state.http_transport = httpx.MockTransport(upstream)
    with _admin_client(app) as client:
        csrf = _login(client)
        conversation = _create_conversation(client, csrf)
        _insert_turns(db, conversation, pairs=25)
        response = _turn(client, csrf, "latest question", conversation_id=conversation)
    assert response.status_code == 200
    sent = upstream.bodies[0]["messages"]
    assert len(sent) == 41  # 40 stored messages plus the new question
    assert sent[0] == {"role": "user", "content": "turn-5 question"}
    assert sent[-2] == {"role": "assistant", "content": "turn-24 reply"}
    assert sent[-1] == {"role": "user", "content": "latest question"}
    assert response.json()["context_truncated"] is True
    assert response.headers["x-context-truncated"] == "1"


def test_message_text_and_provider_keys_stay_out_of_audit_request_logs_and_app_logs(chat, caplog):
    app, db = chat
    caplog.set_level(logging.DEBUG)
    marker = "MARKER-LEAK-SCAN-9913-plain"
    app.state.http_transport = httpx.MockTransport(Upstream(answering("reply text")))
    with _admin_client(app) as client:
        csrf = _login(client)
        conversation = _turn(client, csrf, marker).json()["conversation_id"]
        streamed = _turn(client, csrf, marker + " streamed", conversation_id=conversation, stream=True)
        assert streamed.status_code == 200
        client.delete(f"/api/chat/conversations/{conversation}", headers={"X-CSRF-Token": csrf})
    audit_text = repr(_rows(db, "SELECT * FROM audit_logs"))
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert marker not in audit_text and marker not in log_text
    assert PRIMARY_KEY not in audit_text and PRIMARY_KEY not in log_text
    assert PRIMARY_KEY.encode() not in _db_bytes(db)
    # Chat turns write no request_logs rows, so the table cannot hold chat content.
    assert _rows(db, "SELECT COUNT(*) AS n FROM request_logs")[0]["n"] == 0


# ----------------------------------------------------------------- storage rules (direct calls)


@pytest.mark.parametrize(("pairs", "max_messages", "max_chars", "expected", "truncated"), [
    ([], 40, 100, [], False),
    ([("user", "a"), ("assistant", "b")], 40, 100, [("user", "a"), ("assistant", "b")], False),
    ([("user", "a"), ("assistant", "b"), ("user", "c")], 2, 100, [("user", "c")], True),
    ([("user", "x" * 60), ("assistant", "y" * 60), ("user", "z" * 60)], 40, 120, [("user", "z" * 60)], True),
    ([("assistant", "orphan"), ("user", "q"), ("assistant", "a")], 40, 100,
     [("user", "q"), ("assistant", "a")], True),
])
def test_history_budget_keeps_recent_turns_and_starts_with_a_user_message(pairs, max_messages, max_chars,
                                                                          expected, truncated):
    assert trim_history(pairs, max_messages, max_chars) == (expected, truncated)


def test_only_the_request_that_claimed_a_turn_can_finish_it(chat):
    _app, db = chat
    conversation = create_conversation(db, 1, "claims", "fast", now=1000)["id"]
    first = prepare_turn(db, 1, conversation, "fast", "claim me", "req-claim-0001", now=1000)
    with pytest.raises(ChatError) as busy:
        prepare_turn(db, 1, conversation, "fast", "claim me", "req-claim-0001", now=1100)
    assert busy.value.code == "request_in_progress"
    second = prepare_turn(db, 1, conversation, "fast", "claim me", "req-claim-0001",
                          now=1000 + CLAIM_STALE_SECONDS + 1)
    assert second.claimed_at > first.claimed_at
    assert finish_turn(db, first, TurnResult(True, "stale reply", "primary")) is None
    assert _rows(db, "SELECT status FROM messages WHERE request_id = ?", ("req-claim-0001",))[0]["status"] == "processing"
    assert finish_turn(db, second, TurnResult(True, "fresh reply", "primary")) is not None
    assert finish_turn(db, second, TurnResult(True, "second finish", "primary")) is None
    replies = [m["content"] for m in _messages(db, conversation) if m["role"] == "assistant"]
    assert replies == ["fresh reply"]


def test_late_reply_stays_next_to_its_prompt(chat):
    _app, db = chat
    conversation = create_conversation(db, 1, "overlap", "fast", now=1000)["id"]
    first = prepare_turn(db, 1, conversation, "fast", "first", "req-overlap-01", now=1000)
    second = prepare_turn(db, 1, conversation, "fast", "second", "req-overlap-02", now=1001)
    finish_turn(db, second, TurnResult(True, "second reply", "primary"), now=1002)
    finish_turn(db, first, TurnResult(True, "first reply", "primary"), now=1003)
    _conversation, messages = load_conversation(db, 1, conversation, 50)
    assert [m["content"] for m in messages] == ["first", "first reply", "second", "second reply"]


def test_cancelled_turn_never_stores_a_reply_even_if_the_provider_finished(chat):
    _app, db = chat
    turn = prepare_turn(db, 1, None, "fast", "half done", None, now=2000)
    result = finish_turn(db, turn, TurnResult(True, "full reply", "primary", cancelled=True), now=2001)
    assert result is None
    rows = _rows(db, "SELECT role, status, error_category FROM messages WHERE id = ?", (turn.user_message_id,))
    assert rows == [{"role": "user", "status": "cancelled", "error_category": "client_disconnected"}]
    assert _rows(db, "SELECT COUNT(*) AS n FROM messages WHERE role = 'assistant'")[0]["n"] == 0
