from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from app.auth import (
    LoginPolicy,
    authenticate_admin,
    bootstrap_first_admin,
    create_client_key,
    hash_admin_password,
    reserve_login_attempt,
    set_admin_user_active,
    verify_admin_password,
)
from app.config import GatewayConfig, GatewaySettings, ModelConfig, ProviderConfig
from app.database import Database
from app.ip_access import IpRule, is_request_allowed, parse_ip_or_cidr, parse_trusted_proxies, resolve_client_ip
from app.main import create_app
from app.sessions import (
    SESSION_COOKIE_NAME,
    create_session,
    resolve_session,
    revoke_session,
    revoke_user_sessions,
    verify_csrf_token,
)
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
    cookie_header = response.headers["set-cookie"].lower()
    assert "httponly" in cookie_header
    assert "secure" in cookie_header
    assert "samesite=lax" in cookie_header
    assert "path=/api/admin" in cookie_header
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


def test_csrf_token_rotates_on_session_read_and_old_value_stops_working(admin_app):
    app, _db = admin_app
    with admin_client(app) as client:
        login_csrf = login(client).json()["csrf_token"]
        new_csrf = client.get("/api/admin/session").json()["csrf_token"]
        assert new_csrf != login_csrf
        old = client.post("/api/admin/ip-rules", headers={"X-CSRF-Token": login_csrf},
                          json={"rule_type": "allow", "ip_or_cidr": "198.51.100.0/24"})
        assert old.status_code == 403
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


def test_logout_clears_cookie_and_writes_audit(admin_app):
    app, db = admin_app
    with admin_client(app) as client:
        csrf = login(client).json()["csrf_token"]
        response = client.post("/api/admin/logout", headers={"X-CSRF-Token": csrf})
        assert response.status_code == 200
        assert "amnabd_admin_session=\"\"" in response.headers["set-cookie"] or "Max-Age=0" in response.headers["set-cookie"]
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
    from app.audit import record_audit_event

    db = Database(str(tmp_path / "audit-keys.sqlite3"))
    db.init()
    with db.transaction() as conn:
        with pytest.raises(ValueError):
            record_audit_event(conn, action="test.event", metadata={"password": "x"})
        with pytest.raises(ValueError):
            record_audit_event(conn, action="test.event", metadata={"prompt_text": "x"})
        with pytest.raises(ValueError):
            record_audit_event(conn, action="bad action!")


def test_password_policy_rejects_short_or_username_passwords(tmp_path):
    from app.auth import validate_admin_password

    with pytest.raises(ValueError):
        validate_admin_password("short", ADMIN_USER)
    with pytest.raises(ValueError):
        validate_admin_password("Administrator1", "administrator1")
    validate_admin_password(ADMIN_PASSWORD, ADMIN_USER)
    assert hash_admin_password(ADMIN_PASSWORD).startswith("$argon2id$")


# 15. Bootstrap: the first administrator can only be created from the local CLI, and only once.
def _cli(monkeypatch, cfg, argv, stdin_text=None, capsys=None):
    from app import admin

    monkeypatch.setattr(admin, "load_config", lambda: cfg)
    monkeypatch.setattr("sys.argv", ["ai-gateway-admin", *argv])
    if stdin_text is not None:
        import io

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
