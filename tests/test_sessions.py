from __future__ import annotations

import asyncio
import base64
import datetime
import hashlib
import io
import ipaddress
import json
import os
import secrets as stdlib_secrets
import ssl
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app import admin
from app.audit import record_audit_event
from app.auth import (
    LoginPolicy,
    authenticate_admin,
    bootstrap_first_admin,
    create_client_key,
    hash_admin_password,
    reserve_login_attempt,
    set_admin_user_active,
    validate_admin_password,
    verify_admin_password,
)
from app.config import GatewayConfig, GatewaySettings, ModelConfig, ProviderConfig
from app.crypto import CryptoError, load_keyring, parse_master_key
from app.database import Database
from app.ip_access import IpRule, is_request_allowed, parse_ip_or_cidr, parse_trusted_proxies, resolve_client_ip
from app.main import create_app
from app.provider_secrets import (
    delete_provider_secret,
    list_provider_secrets,
    provider_secret_names,
    resolve_provider_api_key,
    rotate_provider_secrets,
    store_provider_secret,
)
from app.sessions import (
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    create_session,
    resolve_session,
    revoke_user_sessions,
    verify_csrf_token,
)
from app.ssrf import DestinationBlockedError, EgressPolicy, PinnedDestinationTransport, classify_address, validate_provider_endpoint
from tests.test_api import success_handler

PEPPER = "test-pepper-that-is-at-least-32-bytes-long"
ADMIN_USER = "admin"
# Synthetic password used only inside these tests. It is not a credential.
ADMIN_PASSWORD = "synthetic-admin-password-123"
ADMIN_IP = "198.51.100.20"
OTHER_IP = "203.0.113.9"


def build_app(tmp_path, **overrides):
    settings = GatewaySettings("127.0.0.1", 8000, str(tmp_path / "admin.sqlite3"), 3.0, 1_048_576, 30, **overrides)
    providers = (
        ProviderConfig("primary", "test-primary-model", "https://primary.example/v1", "TEST_PRIMARY_API_KEY", True),
    )
    cfg = GatewayConfig(settings, {"fast": ModelConfig("fast", True, providers)})
    db = Database(settings.database_path)
    app = create_app(cfg, db)
    return app, db


@pytest.fixture
def admin_app(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    app, db = build_app(tmp_path)
    bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
    return app, db


def admin_client(app, ip: str = ADMIN_IP) -> TestClient:
    return TestClient(app, base_url="https://testserver", client=(ip, 50000))


def login(client: TestClient, password: str = ADMIN_PASSWORD, username: str = ADMIN_USER):
    return client.post("/api/admin/login", json={"username": username, "password": password})


def audit_rows(db: Database) -> list[dict]:
    with db.connect() as conn:
        return [dict(row) for row in conn.execute("SELECT action, target, metadata FROM audit_logs ORDER BY id")]


def set_rules(db: Database, rules: list[tuple[str, str]]) -> None:
    with db.connect() as conn:
        for rule_type, cidr in rules:
            conn.execute("INSERT INTO admin_ip_rules(rule_type, ip_or_cidr, description, is_active, created_at) "
                         "VALUES (?, ?, '', 1, 1)", (rule_type, cidr))


# 1. Session creation with 256-bit tokens, hash-only storage.
def test_session_creation_uses_256_bit_token_and_stores_only_hash(admin_app):
    app, db = admin_app
    with admin_client(app) as client:
        response = login(client)
        assert response.status_code == 200
        raw_token = client.cookies.get(SESSION_COOKIE_NAME)
    assert raw_token and len(raw_token) >= 43  # 32 random bytes encoded as base64url
    assert "csrf_token" in response.json()
    assert raw_token not in response.text
    with db.connect() as conn:
        stored = [row["token_hash"] for row in conn.execute("SELECT token_hash FROM user_sessions")]
    assert stored == [hashlib.sha256(raw_token.encode()).hexdigest()]
    assert raw_token.encode() not in db_bytes(db)


def db_bytes(db: Database) -> bytes:
    data = b""
    for suffix in ("", "-wal", "-shm"):
        try:
            with open(db.path + suffix, "rb") as handle:
                data += handle.read()
        except FileNotFoundError:
            pass
    return data


# 2. Invalid session tokens are rejected.
def test_invalid_session_token_is_rejected(admin_app):
    app, _db = admin_app
    with admin_client(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, "not-a-real-session-token-value-xxxxxxxxxxxxxxxxxxxx")
        assert client.get("/api/admin/session").status_code == 401


# 3. Expired sessions are rejected.
def test_expired_session_is_rejected(admin_app):
    app, db = admin_app
    with admin_client(app) as client:
        assert login(client).status_code == 200
        with db.connect() as conn:
            conn.execute("UPDATE user_sessions SET created_at = 0, expires_at = 1 WHERE 1=1")
        assert client.get("/api/admin/session").status_code == 401


def test_idle_timeout_rejects_session_without_activity(tmp_path):
    db = Database(str(tmp_path / "idle.sqlite3"))
    db.init()
    admin_id = bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD, now=1000)
    with db.transaction() as conn:
        at_limit = create_session(conn, admin_user_id=admin_id, ttl_seconds=86400, ip_address=None,
                                  user_agent=None, now=1000)
        past_limit = create_session(conn, admin_user_id=admin_id, ttl_seconds=86400, ip_address=None,
                                    user_agent=None, now=1000)
    with db.connect() as conn:
        assert resolve_session(conn, at_limit.token, idle_seconds=1800, now=1000 + 1800) is not None
    with db.connect() as conn:
        assert resolve_session(conn, past_limit.token, idle_seconds=1800, now=1000 + 1801) is None


# 4. Revoked sessions are rejected, and a revoked token cannot be reused.
def test_revoked_session_is_rejected_after_logout(admin_app):
    app, _db = admin_app
    with admin_client(app) as client:
        assert login(client).status_code == 200
        token = client.cookies.get(SESSION_COOKIE_NAME)
        csrf = client.get("/api/admin/session").json()["csrf_token"]
        assert client.post("/api/admin/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
        client.cookies.set(SESSION_COOKIE_NAME, token)
        assert client.get("/api/admin/session").status_code == 401


def test_revoke_all_sessions_for_a_user(tmp_path):
    db = Database(str(tmp_path / "revoke.sqlite3"))
    db.init()
    admin_id = bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
    with db.transaction() as conn:
        first = create_session(conn, admin_user_id=admin_id, ttl_seconds=3600, ip_address=None, user_agent=None)
        second = create_session(conn, admin_user_id=admin_id, ttl_seconds=3600, ip_address=None, user_agent=None)
    with db.transaction() as conn:
        assert revoke_user_sessions(conn, admin_id) == 2
    with db.connect() as conn:
        assert resolve_session(conn, first.token, idle_seconds=1800) is None
        assert resolve_session(conn, second.token, idle_seconds=1800) is None


def test_last_seen_is_written_only_after_the_write_interval(tmp_path):
    db = Database(str(tmp_path / "touch.sqlite3"))
    db.init()
    admin_id = bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD, now=1000)
    with db.transaction() as conn:
        issued = create_session(conn, admin_user_id=admin_id, ttl_seconds=3600, ip_address=None, user_agent=None, now=1000)
    with db.connect() as conn:
        record = resolve_session(conn, issued.token, idle_seconds=1800, now=1030)
        assert record.last_seen_at == 1000
        record = resolve_session(conn, issued.token, idle_seconds=1800, now=1061)
        assert record.last_seen_at == 1061
        assert conn.execute("SELECT last_seen_at FROM user_sessions").fetchone()[0] == 1061


# 5. Successful login: cookie attributes, last_login_at, and no token in JSON.
def test_successful_login_sets_hardened_cookie_and_records_last_login(admin_app):
    app, db = admin_app
    with admin_client(app) as client:
        response = login(client)
    assert response.status_code == 200
    body = response.json()
    assert body["username"] == ADMIN_USER
    assert body["csrf_token"]
    assert "token" not in body
    attrs = cookie_attributes(set_cookie_headers(response)[SESSION_COOKIE_NAME])
    assert attrs["httponly"] is True and attrs["secure"] is True
    assert attrs["samesite"].lower() == "lax" and attrs["path"] == "/api"
    assert response.headers["cache-control"] == "no-store"
    with db.connect() as conn:
        assert conn.execute("SELECT last_login_at FROM admin_users").fetchone()[0] is not None


# 6. Failed login is generic and never logs the password.
def test_failed_login_is_generic_and_does_not_log_password(admin_app):
    app, db = admin_app
    wrong = "wrong-synthetic-password-value"
    with admin_client(app) as client:
        wrong_password = login(client, password=wrong)
        unknown_user = login(client, username="nobody", password=wrong)
        assert SESSION_COOKIE_NAME not in client.cookies
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json()["error"]["code"] == unknown_user.json()["error"]["code"] == "invalid_credentials"
    assert wrong_password.json() == unknown_user.json()
    rows = audit_rows(db)
    failures = [row for row in rows if row["action"] == "admin.login.failure"]
    assert len(failures) == 2
    assert all(wrong not in (row["metadata"] or "") for row in failures)
    raw = db_bytes(db)
    assert wrong.encode() not in raw


# 7. Disabled accounts cannot log in and lose their sessions.
def test_disabled_account_cannot_login_and_loses_sessions(admin_app):
    app, db = admin_app
    with admin_client(app) as client:
        assert login(client).status_code == 200
        token = client.cookies.get(SESSION_COOKIE_NAME)
    assert set_admin_user_active(db, ADMIN_USER, active=False)
    with admin_client(app) as client:
        response = login(client)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "invalid_credentials"
    with db.connect() as conn:
        assert resolve_session(conn, token, idle_seconds=1800) is None
    reasons = [row["metadata"] for row in audit_rows(db) if row["action"] == "admin.login.failure"]
    assert any('"reason":"account_disabled"' in (reason or "") for reason in reasons)


# 8 and 9. CSRF: valid token accepted, missing or wrong token rejected.
def test_csrf_token_is_required_and_verified_on_state_changes(admin_app):
    app, db = admin_app
    with admin_client(app) as client:
        assert login(client).status_code == 200
        csrf = client.get("/api/admin/session").json()["csrf_token"]
        valid = client.post("/api/admin/ip-rules", headers={"X-CSRF-Token": csrf},
                            json={"rule_type": "allow", "ip_or_cidr": "198.51.100.0/24", "description": "office"})
        assert valid.status_code == 201
        missing = client.post("/api/admin/ip-rules", json={"rule_type": "allow", "ip_or_cidr": "192.0.2.11"})
        assert missing.status_code == 403
        assert missing.json()["error"]["code"] == "csrf_validation_failed"
        wrong = client.post("/api/admin/ip-rules", headers={"X-CSRF-Token": "forged-token-value"},
                            json={"rule_type": "allow", "ip_or_cidr": "192.0.2.12"})
        assert wrong.status_code == 403
        delete_wrong = client.delete("/api/admin/ip-rules/1", headers={"X-CSRF-Token": "forged-token-value"})
        assert delete_wrong.status_code == 403


def cookie_attributes(set_cookie_header: str) -> dict[str, object]:
    """Parse the attributes of one Set-Cookie header. Bare flags map to True."""
    attributes: dict[str, object] = {}
    for part in set_cookie_header.split(";")[1:]:
        name, _, value = part.strip().partition("=")
        attributes[name.lower()] = value if value else True
    return attributes


def set_cookie_headers(response) -> dict[str, str]:
    """Map each cookie name in a response to its full Set-Cookie header."""
    return {raw.split("=", 1)[0]: raw for raw in response.headers.get_list("set-cookie")}


def test_csrf_cookie_is_scoped_to_api_and_readable_by_the_ui(admin_app):
    app, _db = admin_app
    with admin_client(app) as client:
        response = login(client)
    cookies = set_cookie_headers(response)
    session_attrs = cookie_attributes(cookies[SESSION_COOKIE_NAME])
    csrf_attrs = cookie_attributes(cookies[CSRF_COOKIE_NAME])
    for attrs in (session_attrs, csrf_attrs):
        assert attrs["path"] == "/api" and attrs["secure"] is True
        assert attrs["samesite"].lower() == "lax"
    assert session_attrs["httponly"] is True
    assert csrf_attrs.get("httponly") is None


def test_session_cookie_is_sent_to_admin_and_chat_paths_but_not_v1(admin_app):
    app, _db = admin_app
    with admin_client(app) as client:
        response = login(client)
    jar = httpx.Cookies()
    jar.extract_cookies(response)
    for url, expected in (("https://testserver/api/admin/session", True),
                          ("https://testserver/api/chat/conversations", True),
                          ("https://testserver/v1/models", False)):
        request = httpx.Request("GET", url)
        jar.set_cookie_header(request)
        assert (SESSION_COOKIE_NAME in request.headers.get("cookie", "")) is expected, url


def test_csrf_token_is_stable_across_reads_and_reloads(admin_app):
    app, _db = admin_app
    with admin_client(app) as client:
        login_csrf = login(client).json()["csrf_token"]
        first = client.get("/api/admin/session")
        second = client.get("/api/admin/session")
        assert first.json()["csrf_token"] == second.json()["csrf_token"] == login_csrf
        assert CSRF_COOKIE_NAME not in set_cookie_headers(first)
        assert client.post("/api/admin/ip-rules", headers={"X-CSRF-Token": login_csrf},
                           json={"rule_type": "allow", "ip_or_cidr": "198.51.100.0/24"}).status_code == 201
        with admin_client(app) as reloaded:
            reloaded.cookies = client.cookies
            assert reloaded.get("/api/admin/session").json()["csrf_token"] == login_csrf


def test_two_tabs_share_one_csrf_token_and_neither_invalidates_the_other(admin_app):
    app, _db = admin_app
    with admin_client(app) as tab_a:
        csrf = login(tab_a).json()["csrf_token"]
        with admin_client(app) as tab_b:
            tab_b.cookies = tab_a.cookies
            assert tab_a.get("/api/admin/session").json()["csrf_token"] == csrf
            assert tab_b.get("/api/admin/session").json()["csrf_token"] == csrf
            first = tab_a.post("/api/admin/ip-rules", headers={"X-CSRF-Token": csrf},
                               json={"rule_type": "allow", "ip_or_cidr": "198.51.100.0/24"})
            second = tab_b.post("/api/admin/ip-rules", headers={"X-CSRF-Token": csrf},
                                json={"rule_type": "allow", "ip_or_cidr": "203.0.113.0/24"})
            assert first.status_code == 201 and second.status_code == 201
            assert tab_a.get("/api/admin/session").json()["csrf_token"] == csrf


def test_missing_csrf_cookie_issues_a_new_token_and_invalidates_the_old_one(admin_app):
    app, _db = admin_app
    with admin_client(app) as client:
        old_csrf = login(client).json()["csrf_token"]
        client.cookies.delete(CSRF_COOKIE_NAME)
        response = client.get("/api/admin/session")
        new_csrf = response.json()["csrf_token"]
        assert new_csrf != old_csrf
        assert CSRF_COOKIE_NAME in set_cookie_headers(response)
        stale = client.post("/api/admin/ip-rules", headers={"X-CSRF-Token": old_csrf},
                            json={"rule_type": "allow", "ip_or_cidr": "198.51.100.0/24"})
        assert stale.status_code == 403
        current = client.post("/api/admin/ip-rules", headers={"X-CSRF-Token": new_csrf},
                              json={"rule_type": "allow", "ip_or_cidr": "198.51.100.0/24"})
        assert current.status_code == 201


def test_csrf_helper_compares_hashes_and_rejects_empty_values(tmp_path):
    db = Database(str(tmp_path / "csrf.sqlite3"))
    db.init()
    admin_id = bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
    with db.transaction() as conn:
        issued = create_session(conn, admin_user_id=admin_id, ttl_seconds=3600, ip_address=None, user_agent=None)
    with db.connect() as conn:
        record = resolve_session(conn, issued.token, idle_seconds=1800)
    assert verify_csrf_token(record, issued.csrf_token)
    assert not verify_csrf_token(record, None)
    assert not verify_csrf_token(record, "")
    assert not verify_csrf_token(record, issued.token)  # session token is never a CSRF token


def test_foreign_origin_is_rejected_for_state_changes(admin_app):
    app, _db = admin_app
    with admin_client(app) as client:
        csrf = login(client).json()["csrf_token"]
        response = client.post("/api/admin/ip-rules", headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example"},
                               json={"rule_type": "allow", "ip_or_cidr": "192.0.2.30"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "origin_not_allowed"


# 10. Login rate limit: five failures per IP, then 429 even for the right password.
def test_login_rate_limit_blocks_after_five_failures_and_returns_retry_after(admin_app):
    app, _db = admin_app
    with admin_client(app) as client:
        for _ in range(5):
            assert login(client, password="wrong-synthetic-password-value").status_code == 401
        blocked = login(client)
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "login_rate_limited"
    assert 1 <= int(blocked.headers["Retry-After"]) <= 900


def test_login_rate_limit_window_expires_and_reservations_are_atomic(tmp_path):
    db = Database(str(tmp_path / "limit.sqlite3"))
    db.init()
    policy = LoginPolicy(max_failures=5, window_seconds=900)
    attempts = [reserve_login_attempt(db, "198.51.100.20", policy, now=1000)[0] for _ in range(7)]
    assert sum(item is not None for item in attempts) == 5
    allowed, retry_after = reserve_login_attempt(db, "198.51.100.20", policy, now=1500)
    assert allowed is None and retry_after == 400
    allowed, _ = reserve_login_attempt(db, "198.51.100.20", policy, now=1900)
    assert allowed is not None
    other_ip, _ = reserve_login_attempt(db, "203.0.113.9", policy, now=1500)
    assert other_ip is not None


def test_concurrent_login_reservations_never_exceed_limit(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    db = Database(str(tmp_path / "race.sqlite3"), timeout_seconds=10)
    db.init()
    policy = LoginPolicy(max_failures=5, window_seconds=900)
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: reserve_login_attempt(db, "198.51.100.77", policy, now=2000)[0], range(30)))
    assert sum(item is not None for item in results) == 5


# 11, 12. IP deny blocks admin access; allowlist admits matching addresses only.
def test_denied_ip_cannot_reach_admin_routes(admin_app):
    app, db = admin_app
    set_rules(db, [("deny", "198.51.100.0/24")])
    with admin_client(app, ADMIN_IP) as client:
        assert login(client).status_code == 403
        assert client.get("/api/admin/health").status_code == 403


def test_allowlist_admits_only_matching_addresses(admin_app):
    app, db = admin_app
    set_rules(db, [("allow", "198.51.100.20/32")])
    with admin_client(app, ADMIN_IP) as client:
        assert login(client).status_code == 200
    with admin_client(app, OTHER_IP) as client:
        assert login(client).status_code == 403


def test_deny_rule_takes_priority_over_matching_allow_rule(admin_app):
    app, db = admin_app
    set_rules(db, [("allow", "198.51.100.0/24"), ("deny", "198.51.100.20/32")])
    with admin_client(app, ADMIN_IP) as client:
        assert login(client).status_code == 403


def test_ip_rule_api_refuses_rules_that_would_lock_out_the_caller(admin_app):
    app, _db = admin_app
    with admin_client(app, ADMIN_IP) as client:
        csrf = login(client).json()["csrf_token"]
        blocked = client.post("/api/admin/ip-rules", headers={"X-CSRF-Token": csrf},
                              json={"rule_type": "deny", "ip_or_cidr": "198.51.100.0/24"})
        assert blocked.status_code == 409
        assert blocked.json()["error"]["code"] == "would_block_current_client"
        allow_others = client.post("/api/admin/ip-rules", headers={"X-CSRF-Token": csrf},
                                   json={"rule_type": "allow", "ip_or_cidr": "203.0.113.0/24"})
        assert allow_others.status_code == 409
        allow_self = client.post("/api/admin/ip-rules", headers={"X-CSRF-Token": csrf},
                                 json={"rule_type": "allow", "ip_or_cidr": "198.51.100.0/24"})
        assert allow_self.status_code == 201


# 13. IPv4, IPv6, and CIDR handling.
@pytest.mark.parametrize(("text", "canonical"), [
    ("192.0.2.1", "192.0.2.1/32"),
    ("192.0.2.0/24", "192.0.2.0/24"),
    ("2001:db8::1", "2001:db8::1/128"),
    ("2001:db8::/32", "2001:db8::/32"),
    ("::ffff:10.1.2.3", "10.1.2.3/32"),
])
def test_ip_rule_parsing_accepts_ipv4_ipv6_and_cidr(text, canonical):
    assert str(parse_ip_or_cidr(text)) == canonical


@pytest.mark.parametrize("text", ["192.0.2.1/24", "256.1.1.1", "2001:db8::/129", "", "example.com", "*"])
def test_ip_rule_parsing_rejects_invalid_values(text):
    with pytest.raises(ValueError):
        parse_ip_or_cidr(text)


def test_ip_matching_across_families_and_mapped_addresses():
    rules = [IpRule(1, "allow", parse_ip_or_cidr("2001:db8::/32"), True),
             IpRule(2, "allow", parse_ip_or_cidr("10.0.0.0/8"), True)]
    assert is_request_allowed(resolve_client_ip("2001:db8::5", [], ()), rules)
    assert is_request_allowed(resolve_client_ip("::ffff:10.9.8.7", [], ()), rules)
    assert not is_request_allowed(resolve_client_ip("198.51.100.1", [], ()), rules)


# 14. Trusted proxy handling: forwarded headers count only from explicitly trusted peers.
def test_forwarded_header_is_ignored_from_untrusted_peer():
    trusted = parse_trusted_proxies("10.0.0.5")
    assert resolve_client_ip("203.0.113.9", ["192.0.2.77"], trusted) == resolve_client_ip("203.0.113.9", [], trusted)


def test_forwarded_header_is_honored_from_trusted_peer_and_skips_trusted_hops():
    trusted = parse_trusted_proxies("10.0.0.0/8")
    assert str(resolve_client_ip("10.0.0.5", ["192.0.2.77, 10.0.0.9"], trusted)) == "192.0.2.77"
    assert str(resolve_client_ip("10.0.0.5", ["2001:db8::7"], trusted)) == "2001:db8::7"


def test_malformed_forwarded_chain_from_trusted_peer_fails_closed():
    trusted = parse_trusted_proxies("10.0.0.5")
    assert resolve_client_ip("10.0.0.5", ["not-an-address"], trusted) is None
    assert resolve_client_ip("10.0.0.5", ["192.0.2.1,,192.0.2.2"], trusted) is None
    assert resolve_client_ip(None, [], trusted) is None


def test_admin_allowlist_cannot_be_bypassed_with_spoofed_forwarded_header(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    app, db = build_app(tmp_path)
    bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
    set_rules(db, [("allow", "198.51.100.20/32")])
    with TestClient(app, base_url="https://testserver", client=(OTHER_IP, 50000),
                    headers={"X-Forwarded-For": ADMIN_IP}) as client:
        assert login(client).status_code == 403


def test_trusted_proxy_forwarded_address_is_used_for_admin_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    app, db = build_app(tmp_path, trusted_proxies=parse_trusted_proxies("10.0.0.5"))
    bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
    set_rules(db, [("allow", "198.51.100.20/32")])
    with TestClient(app, base_url="https://testserver", client=("10.0.0.5", 50000),
                    headers={"X-Forwarded-For": ADMIN_IP}) as client:
        assert login(client).status_code == 200
    with TestClient(app, base_url="https://testserver", client=("10.0.0.5", 50000),
                    headers={"X-Forwarded-For": OTHER_IP}) as client:
        assert login(client).status_code == 403


def test_authenticate_admin_rate_limit_is_keyed_by_resolved_ip(tmp_path):
    db = Database(str(tmp_path / "keyed.sqlite3"))
    db.init()
    bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
    policy = LoginPolicy(max_failures=1, window_seconds=900)
    first = authenticate_admin(db, username=ADMIN_USER, password="wrong-synthetic-password-value", ip_key="198.51.100.20",
                               ip_address="198.51.100.20", user_agent=None, policy=policy, session_ttl_seconds=3600, now=5000)
    assert first.outcome == "invalid_credentials"
    second = authenticate_admin(db, username=ADMIN_USER, password=ADMIN_PASSWORD, ip_key="198.51.100.20",
                                ip_address="198.51.100.20", user_agent=None, policy=policy, session_ttl_seconds=3600, now=5001)
    assert second.outcome == "rate_limited"
    other = authenticate_admin(db, username=ADMIN_USER, password=ADMIN_PASSWORD, ip_key="203.0.113.9",
                               ip_address="203.0.113.9", user_agent=None, policy=policy, session_ttl_seconds=3600, now=5001)
    assert other.outcome == "success"


def test_admin_password_hashes_use_argon2id_and_never_store_plaintext(tmp_path):
    db = Database(str(tmp_path / "argon.sqlite3"))
    db.init()
    bootstrap_first_admin(db, ADMIN_USER, ADMIN_PASSWORD)
    with db.connect() as conn:
        stored = conn.execute("SELECT password_hash FROM admin_users").fetchone()[0]
    assert stored.startswith("$argon2id$")
    assert ADMIN_PASSWORD not in stored
    assert verify_admin_password(stored, ADMIN_PASSWORD)
    assert not verify_admin_password(stored, "wrong-synthetic-password-value")
    assert not verify_admin_password("not-a-hash", ADMIN_PASSWORD)
    assert ADMIN_PASSWORD.encode() not in db_bytes(db)


# 19. Bearer API keys and admin sessions are separate credentials.
def test_admin_session_does_not_authorize_v1_and_bearer_key_does_not_authorize_admin(admin_app):
    app, db = admin_app
    _client_id, bearer = create_client_key(db, PEPPER, "compat", 60)
    app.state.http_transport = httpx.MockTransport(success_handler)
    with admin_client(app) as client:
        assert login(client).status_code == 200
        v1 = client.post("/v1/chat/completions", json={"model": "fast", "messages": [{"role": "user", "content": "hi"}]})
        assert v1.status_code == 401
    with TestClient(app, base_url="https://testserver", client=(ADMIN_IP, 50000)) as client:
        models = client.get("/v1/models", headers={"Authorization": f"Bearer {bearer}"})
        assert models.status_code == 200
        admin = client.get("/api/admin/session", headers={"Authorization": f"Bearer {bearer}"})
        assert admin.status_code == 401


def test_admin_health_reports_schema_version_for_authenticated_admins(admin_app):
    app, _db = admin_app
    with admin_client(app) as client:
        assert client.get("/api/admin/health").status_code == 401
        login(client)
        response = client.get("/api/admin/health")
    assert response.status_code == 200
    assert response.json()["database"] == "ok"
    assert response.json()["schema_version"] >= 2


def test_logout_clears_both_cookies_and_the_csrf_token_stops_working(admin_app):
    app, db = admin_app
    with admin_client(app) as client:
        csrf = login(client).json()["csrf_token"]
        token = client.cookies.get(SESSION_COOKIE_NAME)
        response = client.post("/api/admin/logout", headers={"X-CSRF-Token": csrf})
        assert response.status_code == 200
        cleared = set_cookie_headers(response)
        for name in (SESSION_COOKIE_NAME, CSRF_COOKIE_NAME):
            assert cookie_attributes(cleared[name]).get("max-age") == "0"
        assert client.cookies.get(CSRF_COOKIE_NAME) is None
        client.cookies.set(SESSION_COOKIE_NAME, token)
        client.cookies.set(CSRF_COOKIE_NAME, csrf)
        assert client.get("/api/admin/session").status_code == 401
        assert client.post("/api/admin/ip-rules", headers={"X-CSRF-Token": csrf},
                           json={"rule_type": "allow", "ip_or_cidr": "198.51.100.0/24"}).status_code == 401
    assert any(row["action"] == "admin.logout" for row in audit_rows(db))


def test_ip_rule_changes_are_audited_without_secrets(admin_app):
    app, db = admin_app
    with admin_client(app) as client:
        csrf = login(client).json()["csrf_token"]
        created = client.post("/api/admin/ip-rules", headers={"X-CSRF-Token": csrf},
                              json={"rule_type": "allow", "ip_or_cidr": "198.51.100.0/24", "description": "ops"})
        rule_id = created.json()["id"]
        deleted = client.delete(f"/api/admin/ip-rules/{rule_id}", headers={"X-CSRF-Token": csrf})
        assert deleted.status_code == 200
    actions = [row["action"] for row in audit_rows(db)]
    assert "admin.ip_rule.create" in actions and "admin.ip_rule.delete" in actions
    assert ADMIN_PASSWORD.encode() not in db_bytes(db)


def test_audit_metadata_refuses_credential_like_keys(tmp_path):
    db = Database(str(tmp_path / "audit-keys.sqlite3"))
    db.init()
    with db.transaction() as conn:
        with pytest.raises(ValueError):
            record_audit_event(conn, action="test.event", metadata={"password": "x"})
        with pytest.raises(ValueError):
            record_audit_event(conn, action="test.event", metadata={"prompt_text": "x"})
        with pytest.raises(ValueError):
            record_audit_event(conn, action="bad action!")


def test_password_policy_rejects_short_or_username_passwords():
    with pytest.raises(ValueError):
        validate_admin_password("short", ADMIN_USER)
    with pytest.raises(ValueError):
        validate_admin_password("Administrator1", "administrator1")
    validate_admin_password(ADMIN_PASSWORD, ADMIN_USER)
    assert hash_admin_password(ADMIN_PASSWORD).startswith("$argon2id$")


# 15. Bootstrap: the first administrator can only be created from the local CLI, and only once.
def _cli(monkeypatch, cfg, argv, stdin_text=None, capsys=None):
    monkeypatch.setattr(admin, "load_config", lambda: cfg)
    monkeypatch.setattr("sys.argv", ["ai-gateway-admin", *argv])
    if stdin_text is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text))
    try:
        code = admin.main()
    except SystemExit as exc:
        code = exc.code
    output = capsys.readouterr() if capsys is not None else None
    return code, output


def _cfg_for(app):
    return app.state.gateway_config


def test_bootstrap_cli_creates_first_admin_once_and_never_reads_password_from_argv(admin_app, monkeypatch, capsys, tmp_path):
    app, db = admin_app
    fresh = Database(str(tmp_path / "bootstrap.sqlite3"))
    fresh_cfg = replace(_cfg_for(app), settings=replace(_cfg_for(app).settings, database_path=fresh.path))

    code, output = _cli(monkeypatch, fresh_cfg, ["bootstrap-admin", "--username", "owner", "--password-stdin"],
                        stdin_text=ADMIN_PASSWORD + "\n", capsys=capsys)
    assert code == 0
    assert "admin_user_id=1" in output.out
    assert ADMIN_PASSWORD not in output.out + output.err

    code, output = _cli(monkeypatch, fresh_cfg, ["bootstrap-admin", "--username", "second", "--password-stdin"],
                        stdin_text=ADMIN_PASSWORD + "\n", capsys=capsys)
    assert code == 1
    assert "already exists" in output.out
    with fresh.connect() as conn:
        assert conn.execute("SELECT count(*) FROM admin_users").fetchone()[0] == 1
        assert conn.execute("SELECT action FROM audit_logs").fetchone()[0] == "admin.bootstrap"


def test_bootstrap_cli_refuses_non_interactive_use_without_stdin_flag(admin_app, monkeypatch, capsys, tmp_path):
    app, _db = admin_app
    fresh = Database(str(tmp_path / "no-tty.sqlite3"))
    cfg = replace(_cfg_for(app), settings=replace(_cfg_for(app).settings, database_path=fresh.path))
    code, output = _cli(monkeypatch, cfg, ["bootstrap-admin", "--username", "owner"], stdin_text="", capsys=capsys)
    assert code == 2
    assert "terminal" in output.out


def test_bootstrap_cli_rejects_weak_password_without_creating_account(admin_app, monkeypatch, capsys, tmp_path):
    app, _db = admin_app
    fresh = Database(str(tmp_path / "weak.sqlite3"))
    cfg = replace(_cfg_for(app), settings=replace(_cfg_for(app).settings, database_path=fresh.path))
    code, _output = _cli(monkeypatch, cfg, ["bootstrap-admin", "--username", "owner", "--password-stdin"],
                         stdin_text="short\n", capsys=capsys)
    assert code == 2
    with fresh.connect() as conn:
        assert conn.execute("SELECT count(*) FROM admin_users").fetchone()[0] == 0


def test_admin_has_no_http_break_glass_endpoint(admin_app):
    app, _db = admin_app
    paths = {getattr(route, "path", "") for route in app.routes}
    assert not any("break" in path.lower() or "glass" in path.lower() for path in paths)


# 16. Break-glass CLI: list, disable, delete, reopen after lockout, and confirmed clear, all audited.
def test_breakglass_reopens_access_after_allowlist_lockout(admin_app, monkeypatch, capsys):
    app, db = admin_app
    cfg = _cfg_for(app)
    set_rules(db, [("allow", "203.0.113.0/24")])
    with admin_client(app, ADMIN_IP) as client:
        assert login(client).status_code == 403

    code, output = _cli(monkeypatch, cfg, ["ip-rules", "list"], capsys=capsys)
    assert code == 0
    assert "rule_type=allow" in output.out and "203.0.113.0/24" in output.out

    code, output = _cli(monkeypatch, cfg, ["ip-rules", "reopen"], capsys=capsys)
    assert code == 0 and "allow_rules_disabled=1" in output.out

    with admin_client(app, ADMIN_IP) as client:
        assert login(client).status_code == 200

    actions = [row["action"] for row in audit_rows(db)]
    assert "breakglass.ip_rules.reopen" in actions
    reopen_meta = [row["metadata"] for row in audit_rows(db) if row["action"] == "breakglass.ip_rules.reopen"][0]
    assert '"source":"break-glass-cli"' in reopen_meta


def test_breakglass_disable_and_delete_single_rule(admin_app, monkeypatch, capsys):
    app, db = admin_app
    cfg = _cfg_for(app)
    set_rules(db, [("deny", "192.0.2.0/24"), ("deny", "192.0.3.0/24")])
    code, output = _cli(monkeypatch, cfg, ["ip-rules", "disable", "1"], capsys=capsys)
    assert code == 0 and "disabled" in output.out
    code, output = _cli(monkeypatch, cfg, ["ip-rules", "delete", "2"], capsys=capsys)
    assert code == 0 and "deleted" in output.out
    code, output = _cli(monkeypatch, cfg, ["ip-rules", "delete", "99"], capsys=capsys)
    assert code == 1 and "not_found" in output.out
    with db.connect() as conn:
        rows = conn.execute("SELECT id, is_active FROM admin_ip_rules").fetchall()
    assert [(row["id"], row["is_active"]) for row in rows] == [(1, 0)]


def test_breakglass_clear_requires_exact_confirmation(admin_app, monkeypatch, capsys):
    app, db = admin_app
    cfg = _cfg_for(app)
    set_rules(db, [("deny", "192.0.2.0/24"), ("deny", "192.0.3.0/24")])
    code, output = _cli(monkeypatch, cfg, ["ip-rules", "clear"], capsys=capsys)
    assert code == 2 and "refused" in output.out
    code, output = _cli(monkeypatch, cfg, ["ip-rules", "clear", "--confirm", "yes"], capsys=capsys)
    assert code == 2
    with db.connect() as conn:
        assert conn.execute("SELECT count(*) FROM admin_ip_rules").fetchone()[0] == 2
    code, output = _cli(monkeypatch, cfg, ["ip-rules", "clear", "--confirm", "DELETE-ALL-ADMIN-IP-RULES"], capsys=capsys)
    assert code == 0 and "deleted=2" in output.out
    with db.connect() as conn:
        assert conn.execute("SELECT count(*) FROM admin_ip_rules").fetchone()[0] == 0
    assert any(row["action"] == "breakglass.ip_rules.clear" for row in audit_rows(db))


def test_cli_disable_admin_revokes_sessions_and_blocks_login(admin_app, monkeypatch, capsys):
    app, db = admin_app
    cfg = _cfg_for(app)
    with admin_client(app) as client:
        assert login(client).status_code == 200
        token = client.cookies.get(SESSION_COOKIE_NAME)
    code, output = _cli(monkeypatch, cfg, ["disable-admin", ADMIN_USER], capsys=capsys)
    assert code == 0 and "disabled" in output.out
    with db.connect() as conn:
        assert resolve_session(conn, token, idle_seconds=1800) is None
    with admin_client(app) as client:
        assert login(client).status_code == 401
    code, output = _cli(monkeypatch, cfg, ["enable-admin", ADMIN_USER], capsys=capsys)
    assert code == 0 and "enabled" in output.out
    with admin_client(app) as client:
        assert login(client).status_code == 200
    code, output = _cli(monkeypatch, cfg, ["revoke-admin-sessions", ADMIN_USER], capsys=capsys)
    assert code == 0 and "revoked=1" in output.out


# 17. Provider key encryption: AES-256-GCM, fresh nonces, tamper and binding checks, rotation, and fail-closed behavior.
PROVIDER_KEY = "synthetic-provider-key-value-7731"  # test marker, not a credential


def _random_master_key() -> str:
    return base64.b64encode(stdlib_secrets.token_bytes(32)).decode("ascii")


@pytest.fixture
def master_env(monkeypatch):
    monkeypatch.setenv("GATEWAY_MASTER_KEY", _random_master_key())
    monkeypatch.delenv("GATEWAY_MASTER_KEY_VERSION", raising=False)
    monkeypatch.delenv("GATEWAY_MASTER_KEY_PREVIOUS", raising=False)
    monkeypatch.delenv("GATEWAY_MASTER_KEY_PREVIOUS_VERSION", raising=False)
    monkeypatch.delenv("GATEWAY_MASTER_KEY_FILE", raising=False)
    monkeypatch.delenv("GATEWAY_MASTER_KEY_PREVIOUS_FILE", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY_FILE", raising=False)
    return monkeypatch


def _fresh_db(tmp_path, name="secrets.sqlite3") -> Database:
    db = Database(str(tmp_path / name))
    db.init()
    return db


def test_provider_key_is_stored_encrypted_and_round_trips(tmp_path, master_env):
    db = _fresh_db(tmp_path)
    keyring = load_keyring()
    assert store_provider_secret(db, keyring, "OPENAI_API_KEY", PROVIDER_KEY) == 1
    assert PROVIDER_KEY.encode() not in db_bytes(db)
    with db.connect() as conn:
        row = conn.execute("SELECT algorithm, length(nonce) AS nonce_len, ciphertext FROM provider_secrets").fetchone()
    assert row["algorithm"] == "AES-256-GCM"
    assert row["nonce_len"] == 12
    assert PROVIDER_KEY.encode() not in bytes(row["ciphertext"])
    assert resolve_provider_api_key(db, "OPENAI_API_KEY") == PROVIDER_KEY


def test_every_seal_uses_a_fresh_nonce(tmp_path, master_env):
    db = _fresh_db(tmp_path)
    keyring = load_keyring()
    store_provider_secret(db, keyring, "OPENAI_API_KEY", PROVIDER_KEY)
    with db.connect() as conn:
        first = tuple(bytes(x) for x in conn.execute("SELECT nonce, ciphertext FROM provider_secrets").fetchone())
    store_provider_secret(db, keyring, "OPENAI_API_KEY", PROVIDER_KEY)
    with db.connect() as conn:
        second = tuple(bytes(x) for x in conn.execute("SELECT nonce, ciphertext FROM provider_secrets").fetchone())
    assert first[0] != second[0]
    assert first[1] != second[1]


def test_tampered_ciphertext_fails_closed(tmp_path, master_env):
    db = _fresh_db(tmp_path)
    store_provider_secret(db, load_keyring(), "OPENAI_API_KEY", PROVIDER_KEY)
    with db.connect() as conn:
        ciphertext = bytearray(conn.execute("SELECT ciphertext FROM provider_secrets").fetchone()[0])
        ciphertext[0] ^= 0x01
        conn.execute("UPDATE provider_secrets SET ciphertext = ?", (bytes(ciphertext),))
    with pytest.raises(CryptoError, match="integrity"):
        resolve_provider_api_key(db, "OPENAI_API_KEY")


def test_ciphertext_cannot_be_moved_to_another_provider_name(tmp_path, master_env):
    db = _fresh_db(tmp_path)
    store_provider_secret(db, load_keyring(), "OPENAI_API_KEY", PROVIDER_KEY)
    with db.connect() as conn:
        conn.execute("UPDATE provider_secrets SET provider_name = 'ANTHROPIC_API_KEY'")
    with pytest.raises(CryptoError):
        resolve_provider_api_key(db, "ANTHROPIC_API_KEY")


def test_master_key_is_never_written_to_the_database(tmp_path, master_env):
    db = _fresh_db(tmp_path)
    store_provider_secret(db, load_keyring(), "OPENAI_API_KEY", PROVIDER_KEY)
    key_text = os.environ["GATEWAY_MASTER_KEY"]
    assert key_text.encode() not in db_bytes(db)
    assert base64.b64decode(key_text) not in db_bytes(db)


@pytest.mark.parametrize("bad_key", ["", "c2hvcnQ=", "not base64 at all!!", "A" * 44])
def test_invalid_master_keys_are_refused(bad_key, master_env):
    master_env.setenv("GATEWAY_MASTER_KEY", bad_key)
    with pytest.raises(CryptoError):
        load_keyring()


def test_missing_master_key_and_bad_version_fail_closed(tmp_path, master_env):
    master_env.delenv("GATEWAY_MASTER_KEY")
    with pytest.raises(CryptoError, match="unavailable"):
        load_keyring()
    master_env.setenv("GATEWAY_MASTER_KEY", _random_master_key())
    master_env.setenv("GATEWAY_MASTER_KEY_VERSION", "zero")
    with pytest.raises(CryptoError, match="version"):
        load_keyring()


def test_wrong_master_key_cannot_open_stored_keys(tmp_path, master_env):
    db = _fresh_db(tmp_path)
    store_provider_secret(db, load_keyring(), "OPENAI_API_KEY", PROVIDER_KEY)
    master_env.setenv("GATEWAY_MASTER_KEY", _random_master_key())
    with pytest.raises(CryptoError):
        resolve_provider_api_key(db, "OPENAI_API_KEY")


def test_master_key_can_be_read_from_a_protected_file(tmp_path, master_env, secret_directory):
    key_text = _random_master_key()
    key_file = secret_directory / "master-key"
    key_file.write_bytes(key_text.encode("ascii"))
    key_file.chmod(0o400)
    master_env.delenv("GATEWAY_MASTER_KEY")
    master_env.setenv("GATEWAY_MASTER_KEY_FILE", str(key_file))
    keyring = load_keyring()
    assert keyring.current.version == 1
    db = _fresh_db(tmp_path)
    store_provider_secret(db, keyring, "OPENAI_API_KEY", PROVIDER_KEY)
    assert resolve_provider_api_key(db, "OPENAI_API_KEY") == PROVIDER_KEY


def test_rotation_reencrypts_to_new_version_then_old_key_can_be_removed(tmp_path, master_env):
    db = _fresh_db(tmp_path)
    old_key = os.environ["GATEWAY_MASTER_KEY"]
    store_provider_secret(db, load_keyring(), "OPENAI_API_KEY", PROVIDER_KEY)

    master_env.setenv("GATEWAY_MASTER_KEY", _random_master_key())
    master_env.setenv("GATEWAY_MASTER_KEY_VERSION", "2")
    master_env.setenv("GATEWAY_MASTER_KEY_PREVIOUS", old_key)
    master_env.setenv("GATEWAY_MASTER_KEY_PREVIOUS_VERSION", "1")
    keyring = load_keyring()
    assert resolve_provider_api_key(db, "OPENAI_API_KEY") == PROVIDER_KEY
    assert rotate_provider_secrets(db, keyring) == 1
    assert [info.key_version for info in list_provider_secrets(db)] == [2]

    master_env.delenv("GATEWAY_MASTER_KEY_PREVIOUS")
    master_env.delenv("GATEWAY_MASTER_KEY_PREVIOUS_VERSION")
    assert resolve_provider_api_key(db, "OPENAI_API_KEY") == PROVIDER_KEY


def test_rotation_is_all_or_nothing(tmp_path, master_env):
    db = _fresh_db(tmp_path)
    old_key = os.environ["GATEWAY_MASTER_KEY"]
    store_provider_secret(db, load_keyring(), "OPENAI_API_KEY", PROVIDER_KEY)
    store_provider_secret(db, load_keyring(), "ANTHROPIC_API_KEY", "synthetic-second-key-value")
    with db.transaction() as conn:
        # A row whose key version no longer exists makes the whole rotation fail.
        conn.execute("UPDATE provider_secrets SET key_version = 9 WHERE provider_name = 'ANTHROPIC_API_KEY'")
    master_env.setenv("GATEWAY_MASTER_KEY", _random_master_key())
    master_env.setenv("GATEWAY_MASTER_KEY_VERSION", "2")
    master_env.setenv("GATEWAY_MASTER_KEY_PREVIOUS", old_key)
    master_env.setenv("GATEWAY_MASTER_KEY_PREVIOUS_VERSION", "1")
    with pytest.raises(CryptoError):
        rotate_provider_secrets(db, load_keyring())
    versions = {info.provider_name: info.key_version for info in list_provider_secrets(db)}
    assert versions == {"ANTHROPIC_API_KEY": 9, "OPENAI_API_KEY": 1}
    assert resolve_provider_api_key(db, "OPENAI_API_KEY") == PROVIDER_KEY


def test_stored_key_and_env_source_together_are_refused(tmp_path, master_env):
    db = _fresh_db(tmp_path)
    store_provider_secret(db, load_keyring(), "OPENAI_API_KEY", PROVIDER_KEY)
    master_env.setenv("OPENAI_API_KEY", "synthetic-env-key-value")
    with pytest.raises(CryptoError, match="more than one"):
        resolve_provider_api_key(db, "OPENAI_API_KEY")


def test_store_rejects_bad_names_and_values_without_echoing_them(tmp_path, master_env):
    db = _fresh_db(tmp_path)
    keyring = load_keyring()
    with pytest.raises(ValueError) as captured:
        store_provider_secret(db, keyring, "GATEWAY_PEPPER", PROVIDER_KEY)
    assert PROVIDER_KEY not in str(captured.value)
    with pytest.raises(ValueError):
        store_provider_secret(db, keyring, "OPENAI_API_KEY", "has space inside")
    with pytest.raises(ValueError):
        store_provider_secret(db, keyring, "OPENAI_API_KEY", "")
    assert provider_secret_names(db) == frozenset()


def test_store_list_and_delete_never_expose_values(tmp_path, master_env):
    db = _fresh_db(tmp_path)
    store_provider_secret(db, load_keyring(), "OPENAI_API_KEY", PROVIDER_KEY)
    listing = list_provider_secrets(db)
    assert [info.provider_name for info in listing] == ["OPENAI_API_KEY"]
    assert PROVIDER_KEY not in repr(listing)
    assert delete_provider_secret(db, "OPENAI_API_KEY")
    assert not delete_provider_secret(db, "OPENAI_API_KEY")


@pytest.mark.parametrize(("text", "length"), [
    ("A" * 64, 32),
    (base64.b64encode(bytes(range(32))).decode(), 32),
    (base64.urlsafe_b64encode(bytes(range(32, 64))).decode().rstrip("="), 32),
])
def test_master_key_formats_hex_and_base64_are_accepted(text, length):
    assert len(parse_master_key(text)) == length


@pytest.mark.parametrize("text", ["A" * 62, base64.b64encode(bytes(31)).decode(), "@@@@"])
def test_master_key_wrong_length_or_garbage_is_refused(text):
    with pytest.raises(CryptoError):
        parse_master_key(text)


def test_provider_request_uses_stored_key_without_env_and_never_echoes_it(tmp_path, master_env, caplog):
    master_env.setenv("GATEWAY_PEPPER", PEPPER)
    db = _fresh_db(tmp_path)
    store_provider_secret(db, load_keyring(), "OPENAI_API_KEY", PROVIDER_KEY)
    seen = []
    app, db = _route_app(tmp_path, [ProviderConfig("stored", "m1", "https://stored.example/v1", "OPENAI_API_KEY", True)],
                         _static_resolver({"stored.example": ["93.184.216.34"]}), db=db)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["authorization"])
        return success_handler(request)

    app.state.http_transport = httpx.MockTransport(handler)
    token = create_client_key(db, PEPPER, "stored-key", 20)[1]
    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"},
                               json={"model": "fast", "messages": [{"role": "user", "content": "hi"}]})
    assert response.status_code == 200
    assert seen == [f"Bearer {PROVIDER_KEY}"]
    assert PROVIDER_KEY not in response.text
    assert PROVIDER_KEY not in caplog.text


def test_missing_master_key_returns_503_without_contacting_provider(tmp_path, master_env):
    master_env.setenv("GATEWAY_PEPPER", PEPPER)
    db = _fresh_db(tmp_path)
    store_provider_secret(db, load_keyring(), "OPENAI_API_KEY", PROVIDER_KEY)
    master_env.delenv("GATEWAY_MASTER_KEY")
    app, db = _route_app(tmp_path, [ProviderConfig("stored", "m1", "https://stored.example/v1", "OPENAI_API_KEY", True)],
                         _static_resolver({"stored.example": ["93.184.216.34"]}), db=db)
    calls = []
    app.state.http_transport = httpx.MockTransport(lambda request: calls.append(request) or success_handler(request))
    token = create_client_key(db, PEPPER, "missing-master", 20)[1]
    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"},
                               json={"model": "fast", "messages": [{"role": "user", "content": "hi"}]})
    assert calls == []
    assert response.status_code == 503
    assert "provider_secret_unavailable" in response.text
    assert PROVIDER_KEY not in response.text


def test_cli_stores_lists_and_deletes_keys_without_printing_values(tmp_path, master_env, monkeypatch, capsys):
    db = _fresh_db(tmp_path)
    cfg = replace(_cfg_like(tmp_path, db), settings=replace(_cfg_like(tmp_path, db).settings, database_path=db.path))
    code, output = _cli(monkeypatch, cfg, ["provider-secret", "set", "OPENAI_API_KEY"],
                        stdin_text=PROVIDER_KEY + "\n", capsys=capsys)
    assert code == 0 and "stored name=OPENAI_API_KEY key_version=1" in output.out
    assert PROVIDER_KEY not in output.out + output.err
    code, output = _cli(monkeypatch, cfg, ["provider-secret", "list"], capsys=capsys)
    assert code == 0 and "name=OPENAI_API_KEY key_version=1" in output.out
    assert PROVIDER_KEY not in output.out
    code, output = _cli(monkeypatch, cfg, ["provider-secret", "delete", "OPENAI_API_KEY"], capsys=capsys)
    assert code == 0 and "deleted" in output.out
    assert any(row["action"] == "provider_secret.store" for row in audit_rows(db))
    assert PROVIDER_KEY.encode() not in db_bytes(db)


def test_cli_rejects_oversized_key_and_missing_master_key(tmp_path, master_env, monkeypatch, capsys):
    db = _fresh_db(tmp_path)
    cfg = replace(_cfg_like(tmp_path, db), settings=replace(_cfg_like(tmp_path, db).settings, database_path=db.path))
    code, output = _cli(monkeypatch, cfg, ["provider-secret", "set", "OPENAI_API_KEY"],
                        stdin_text="x" * 9000 + "\n", capsys=capsys)
    assert code == 2 and "too large" in output.out
    assert provider_secret_names(db) == frozenset()
    master_env.delenv("GATEWAY_MASTER_KEY")
    code, output = _cli(monkeypatch, cfg, ["provider-secret", "set", "OPENAI_API_KEY"],
                        stdin_text=PROVIDER_KEY + "\n", capsys=capsys)
    assert code == 2
    assert PROVIDER_KEY not in output.out + output.err
    assert provider_secret_names(db) == frozenset()


def _cfg_like(tmp_path, db):
    settings = GatewaySettings("127.0.0.1", 8000, db.path, 3.0, 1_048_576, 30)
    return GatewayConfig(settings, {})


# 18. SSRF: configuration checks, address classification, and connection-time pinning.
@pytest.mark.parametrize(("address", "tier"), [
    ("8.8.8.8", "public"),
    ("2606:4700:4700::1111", "public"),
    ("10.0.0.1", "internal"),
    ("192.168.1.10", "internal"),
    ("172.16.5.5", "internal"),
    ("127.0.0.1", "internal"),
    ("::1", "internal"),
    ("::ffff:127.0.0.1", "internal"),
    ("100.64.0.1", "internal"),
    ("fc00::1", "internal"),
    ("64:ff9b::8.8.8.8", "public"),
    ("64:ff9b::7f00:1", "internal"),
    ("2002:7f00:1::1", "internal"),
    ("2002:a9fe:a9fe::1", "denied"),
    ("169.254.169.254", "denied"),
    ("169.254.170.2", "denied"),
    ("100.100.100.200", "denied"),
    ("fd00:ec2::254", "denied"),
    ("0.0.0.0", "denied"),
    ("224.0.0.1", "denied"),
    ("240.0.0.1", "denied"),
    ("255.255.255.255", "denied"),
    ("fe80::1", "denied"),
    ("::", "denied"),
    ("::127.0.0.1", "denied"),
])
def test_address_classification_blocks_metadata_and_internal_ranges(address, tier):
    assert classify_address(address) == tier


@pytest.mark.parametrize("api_base", [
    "http://provider.example/v1",
    "https://provider.example:8443/v1",
    "https://169.254.169.254/latest",
    "https://[fd00:ec2::254]/v1",
    "https://127.0.0.1/v1",
    "https://localhost/v1",
    "https://user:secret@provider.example/v1",
    "https://provider.example/v1?key=1",
    "ftp://provider.example/v1",
    "https://provider.example:notaport/v1",
])
def test_unsafe_provider_endpoints_are_rejected_at_config_time(api_base):
    with pytest.raises(ValueError):
        ProviderConfig("unsafe", "m", api_base, "OPENAI_API_KEY")


def test_explicit_internal_provider_is_the_only_way_to_reach_internal_addresses():
    trusted = (ipaddress.ip_network("127.0.0.1/32"),)
    assert validate_provider_endpoint("http://127.0.0.1:8080/v1", trusted) == "http://127.0.0.1:8080/v1"
    with pytest.raises(ValueError):
        ProviderConfig("internal", "m", "http://127.0.0.1:8080/v1", "OPENAI_API_KEY")
    with pytest.raises(ValueError):
        ProviderConfig("bad-trust", "m", "https://provider.example/v1", "OPENAI_API_KEY",
                       trusted_internal_networks=(ipaddress.ip_network("169.254.0.0/16"),))


def _resolve_with(table):
    calls = []

    async def resolver(host: str, port: int) -> list[str]:
        calls.append((host, port))
        return list(table[host])

    resolver.calls = calls
    return resolver


async def _post_through_transport(host: str, resolver, *, scheme: str = "https", port: int = 443,
                                  trusted=()):
    policy = EgressPolicy(tuple(trusted))
    transport = PinnedDestinationTransport(policy, resolver)
    async with httpx.AsyncClient(transport=transport, trust_env=False, follow_redirects=False) as client:
        return await client.post(f"{scheme}://{host}:{port}/v1/chat/completions", json={"model": "m"})


@pytest.mark.parametrize("addresses", [
    ["169.254.169.254"],
    ["127.0.0.1"],
    ["8.8.8.8", "10.0.0.5"],
    ["8.8.8.8", "fe80::1"],
    ["not-an-ip"],
])
def test_any_forbidden_address_blocks_the_whole_connection(addresses):
    resolver = _resolve_with({"provider.example": addresses})
    with pytest.raises(DestinationBlockedError):
        asyncio.run(_post_through_transport("provider.example", resolver))
    assert resolver.calls == [("provider.example", 443)]


def test_dns_failure_is_reported_as_connection_failure_not_as_allowed():
    async def failing(host: str, port: int) -> list[str]:
        raise OSError("name resolution failed")

    with pytest.raises(httpx.ConnectError):
        asyncio.run(_post_through_transport("provider.example", failing))


def test_plain_http_and_nonstandard_ports_are_blocked_for_public_providers():
    resolver = _resolve_with({"provider.example": ["8.8.8.8"]})
    with pytest.raises(DestinationBlockedError):
        asyncio.run(_post_through_transport("provider.example", resolver, scheme="http", port=80))
    with pytest.raises(DestinationBlockedError):
        asyncio.run(_post_through_transport("provider.example", resolver, port=8443))
    assert resolver.calls == []


class _ProviderHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - http.server naming
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        self.server.seen.append({"host": self.headers.get("Host"), "auth": self.headers.get("Authorization"),
                                 "path": self.path})
        if self.path.endswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
            return
        if body.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b'data: {"choices":[{"delta":{"content":"ok"}}]}\n\n')
            self.wfile.write(b"data: [DONE]\n\n")
            return
        data = json.dumps({"id": "local", "object": "chat.completion", "created": 1, "model": body.get("model"),
                           "choices": [{"index": 0, "message": {"role": "assistant", "content": "local answer"},
                                        "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:  # keep test output quiet
        return


@pytest.fixture
def provider_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderHandler)
    server.seen = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def test_pinned_connection_uses_only_the_validated_address_and_original_host(provider_server):
    port = provider_server.server_address[1]
    resolver = _resolve_with({"provider.internal.test": ["127.0.0.1"]})
    trusted = (ipaddress.ip_network("127.0.0.0/8"),)
    response = asyncio.run(_post_through_transport("provider.internal.test", resolver, scheme="http",
                                                   port=port, trusted=trusted))
    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "local answer"
    assert resolver.calls == [("provider.internal.test", port)]
    assert provider_server.seen[0]["host"] == f"provider.internal.test:{port}"


def test_each_connection_is_validated_and_a_rebound_answer_is_never_used(provider_server):
    port = provider_server.server_address[1]
    answers = iter([["127.0.0.1"], ["169.254.169.254"]])

    async def rebinding(host: str, port_: int) -> list[str]:
        return next(answers)

    trusted = (ipaddress.ip_network("127.0.0.0/8"),)
    first = asyncio.run(_post_through_transport("rebind.internal.test", rebinding, scheme="http", port=port, trusted=trusted))
    assert first.status_code == 200
    with pytest.raises(DestinationBlockedError):
        asyncio.run(_post_through_transport("rebind.internal.test", rebinding, scheme="http", port=port, trusted=trusted))
    assert len(provider_server.seen) == 1


def test_redirects_from_providers_are_returned_not_followed(provider_server):
    port = provider_server.server_address[1]
    resolver = _resolve_with({"redirect.internal.test": ["127.0.0.1"]})
    trusted = (ipaddress.ip_network("127.0.0.0/8"),)

    async def call() -> httpx.Response:
        transport = PinnedDestinationTransport(EgressPolicy(trusted), resolver)
        async with httpx.AsyncClient(transport=transport, trust_env=False, follow_redirects=False) as client:
            return await client.post(f"http://redirect.internal.test:{port}/v1/redirect", json={"model": "m"})

    response = asyncio.run(call())
    assert response.status_code == 302
    assert len(provider_server.seen) == 1


def _route_app(tmp_path, providers, resolver, db=None):
    settings = GatewaySettings("127.0.0.1", 8000, str(tmp_path / "routing.sqlite3"), 5.0, 1_048_576, 30)
    cfg = GatewayConfig(settings, {"fast": ModelConfig("fast", True, tuple(providers))})
    database = db or Database(settings.database_path)
    app = create_app(cfg, database)
    app.state.dns_resolver = resolver
    return app, database


def _static_resolver(table):
    async def resolver(host: str, port: int) -> list[str]:
        return list(table[host])

    return resolver


def test_blocked_provider_falls_back_to_explicit_internal_provider(tmp_path, monkeypatch, provider_server):
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    monkeypatch.setenv("ROUTE_PRIMARY_API_KEY", "synthetic-primary-route-key")
    monkeypatch.setenv("ROUTE_SECONDARY_API_KEY", "synthetic-secondary-route-key")
    port = provider_server.server_address[1]
    providers = [
        ProviderConfig("primary", "m1", "https://primary.example/v1", "ROUTE_PRIMARY_API_KEY", True),
        ProviderConfig("secondary", "m2", f"http://secondary.internal:{port}/v1", "ROUTE_SECONDARY_API_KEY", True,
                       trusted_internal_networks=(ipaddress.ip_network("127.0.0.0/8"),)),
    ]
    resolver = _static_resolver({"primary.example": ["169.254.169.254"], "secondary.internal": ["127.0.0.1"]})
    app, db = _route_app(tmp_path, providers, resolver)
    token = create_client_key(db, PEPPER, "fallback-ssrf", 20)[1]
    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"},
                               json={"model": "fast", "messages": [{"role": "user", "content": "hi"}]})
    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "local answer"
    assert db.usage_for_client(db.list_clients()[0]["client_id"])[0]["provider_name"] == "secondary"
    assert provider_server.seen[0]["auth"] == "Bearer synthetic-secondary-route-key"


def test_only_blocked_providers_return_destination_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    monkeypatch.setenv("ROUTE_PRIMARY_API_KEY", "synthetic-primary-route-key")
    providers = [ProviderConfig("primary", "m1", "https://primary.example/v1", "ROUTE_PRIMARY_API_KEY", True)]
    app, db = _route_app(tmp_path, providers, _static_resolver({"primary.example": ["127.0.0.1"]}))
    token = create_client_key(db, PEPPER, "blocked-only", 20)[1]
    with TestClient(app) as client:
        response = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"},
                               json={"model": "fast", "messages": [{"role": "user", "content": "hi"}]})
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "provider_destination_blocked"


def test_streaming_and_non_streaming_v1_work_through_the_pinned_transport(tmp_path, monkeypatch, provider_server):
    monkeypatch.setenv("GATEWAY_PEPPER", PEPPER)
    monkeypatch.setenv("ROUTE_SECONDARY_API_KEY", "synthetic-secondary-route-key")
    port = provider_server.server_address[1]
    providers = [ProviderConfig("secondary", "m2", f"http://secondary.internal:{port}/v1", "ROUTE_SECONDARY_API_KEY", True,
                                trusted_internal_networks=(ipaddress.ip_network("127.0.0.0/8"),))]
    app, db = _route_app(tmp_path, providers, _static_resolver({"secondary.internal": ["127.0.0.1"]}))
    token = create_client_key(db, PEPPER, "sse-pinned", 60)[1]
    with TestClient(app) as client:
        plain = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"},
                            json={"model": "fast", "messages": [{"role": "user", "content": "hi"}]})
        streamed = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {token}"},
                               json={"model": "fast", "stream": True, "messages": [{"role": "user", "content": "hi"}]})
    assert plain.status_code == 200 and plain.json()["model"] == "fast"
    assert streamed.status_code == 200
    assert streamed.headers["content-type"].startswith("text/event-stream")
    assert "data: [DONE]" in streamed.text


def _write_tls_material(directory, dns_name: str):
    """Create a throwaway CA and one leaf certificate for dns_name at test runtime. Nothing is committed."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic test ca")])
    ca_cert = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_name)]))
        .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = directory / "ca.pem"
    cert_path = directory / f"{dns_name}.crt"
    key_path = directory / f"{dns_name}.key"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
    return ca_path, cert_path, key_path


def test_tls_verifies_the_original_hostname_when_connecting_to_a_validated_ip(tmp_path, monkeypatch):
    ca_path, cert_path, key_path = _write_tls_material(tmp_path, "secure.test")
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_path))
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderHandler)
    server.seen = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        resolver = _resolve_with({"secure.test": ["127.0.0.1"]})
        trusted = (ipaddress.ip_network("127.0.0.0/8"),)
        response = asyncio.run(_post_through_transport("secure.test", resolver, scheme="https", port=port, trusted=trusted))
        assert response.status_code == 200
        assert server.seen[0]["host"] == f"secure.test:{port}"
    finally:
        server.shutdown()
        server.server_close()


def test_tls_handshake_fails_when_certificate_does_not_name_the_requested_host(tmp_path, monkeypatch):
    ca_path, cert_path, key_path = _write_tls_material(tmp_path, "other.test")
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_path))
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderHandler)
    server.seen = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        resolver = _resolve_with({"secure.test": ["127.0.0.1"]})
        trusted = (ipaddress.ip_network("127.0.0.0/8"),)
        with pytest.raises(httpx.ConnectError):
            asyncio.run(_post_through_transport("secure.test", resolver, scheme="https", port=port, trusted=trusted))
        assert server.seen == []
    finally:
        server.shutdown()
        server.server_close()
