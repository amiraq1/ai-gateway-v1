"""Administrative HTTP API under /api/admin.

Request checks, in order: the client address must pass the admin IP policy, the
session cookie must match an active session, and for POST/PUT/PATCH/DELETE the
Origin or Referer (when present) and the X-CSRF-Token header must match.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from .audit import record_audit_event
from .auth import Argon2Busy, LoginPolicy, authenticate_admin
from .clock import now_epoch
from .config import GatewayConfig, validate_provider_api_key_env
from .crypto import CryptoError, Keyring, load_keyring
from .provider_secrets import (
    AuditActor,
    delete_provider_secret,
    list_provider_secrets,
    rotate_provider_secrets,
    store_provider_secret,
)
from .database import Database
from .ip_access import IpRule, IPAddress, is_request_allowed, parse_ip_or_cidr, resolve_client_ip
from .migrations import read_schema_version
from .sessions import (
    CSRF_COOKIE_NAME,
    CSRF_COOKIE_OPTIONS,
    SESSION_COOKIE_NAME,
    SESSION_COOKIE_OPTIONS,
    SessionRecord,
    csrf_token_for_session,
    resolve_session,
    revoke_session,
    verify_csrf_token,
)

ADMIN_PREFIX = "/api/admin"
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_NO_STORE = {"Cache-Control": "no-store"}


class AdminApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str, *,
                 error_type: str = "admin_error", headers: dict[str, str] | None = None) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.error_type = error_type
        self.headers = headers


def admin_error_handler(request: Request, exc: AdminApiError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"message": exc.message, "type": exc.error_type, "code": exc.code}},
        headers=exc.headers,
    )


@dataclass(frozen=True)
class AdminContext:
    session: SessionRecord


def _database(request: Request) -> Database:
    return request.app.state.database


def _settings(request: Request):
    config: GatewayConfig = request.app.state.gateway_config
    return config.settings


def _client_address(request: Request) -> IPAddress | None:
    settings = _settings(request)
    peer = request.client.host if request.client else None
    return resolve_client_ip(peer, request.headers.getlist("x-forwarded-for"), settings.trusted_proxies)


def _load_rules(conn: sqlite3.Connection, exclude_id: int | None = None) -> list[IpRule]:
    rows = conn.execute("SELECT id, rule_type, ip_or_cidr, is_active FROM admin_ip_rules WHERE is_active = 1").fetchall()
    rules = []
    for row in rows:
        if exclude_id is not None and int(row["id"]) == exclude_id:
            continue
        rules.append(IpRule(int(row["id"]), str(row["rule_type"]), parse_ip_or_cidr(str(row["ip_or_cidr"])), True))
    return rules


def _check_origin(request: Request) -> None:
    """Enforce Origin, or Referer when Origin is absent. Non-browser clients send neither and still need the token."""
    origin = request.headers.get("origin")
    if origin is None:
        referer = request.headers.get("referer")
        if referer is None:
            return
        parts = urlsplit(referer)
        origin = f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else ""
    own_origin = f"{request.url.scheme}://{request.url.netloc}"
    allowed = {own_origin.lower(), *_settings(request).admin_allowed_origins}
    if origin.lower() not in allowed:
        raise AdminApiError(403, "origin_not_allowed", "Request origin is not allowed.", error_type="permission_error")


def enforce_admin_network_policy(request: Request) -> None:
    """Apply admin IP rules to every /api/admin route, including login."""
    address = _client_address(request)
    if address is None:
        raise AdminApiError(403, "forbidden", "Access is not allowed from this network.", error_type="permission_error")
    with _database(request).connect() as conn:
        rules = _load_rules(conn)
    if not is_request_allowed(address, rules):
        raise AdminApiError(403, "forbidden", "Access is not allowed from this network.", error_type="permission_error")
    request.state.client_address = address


def require_admin_session(request: Request) -> AdminContext:
    settings = _settings(request)
    with _database(request).connect() as conn:
        record = resolve_session(conn, request.cookies.get(SESSION_COOKIE_NAME),
                                 idle_seconds=settings.admin_session_idle_seconds)
    if record is None:
        raise AdminApiError(401, "admin_session_required", "An authenticated admin session is required.",
                            error_type="authentication_error")
    if request.method in _UNSAFE_METHODS:
        _check_origin(request)
        if not verify_csrf_token(record, request.headers.get("x-csrf-token")):
            raise AdminApiError(403, "csrf_validation_failed", "CSRF validation failed.", error_type="permission_error")
    return AdminContext(record)


def _audit_actor(request: Request) -> tuple[str | None, str | None]:
    address = getattr(request.state, "client_address", None)
    return (str(address) if address else None, request.headers.get("user-agent"))


router = APIRouter(prefix=ADMIN_PREFIX, dependencies=[Depends(enforce_admin_network_policy)])


class LoginBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class IpRuleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_type: Literal["allow", "deny"]
    ip_or_cidr: str = Field(min_length=2, max_length=64)
    description: str = Field(default="", max_length=200)


@router.post("/login")
async def admin_login(body: LoginBody, request: Request) -> JSONResponse:
    _check_origin(request)
    settings = _settings(request)
    address = getattr(request.state, "client_address", None)
    ip_text = str(address) if address else None
    user_agent = request.headers.get("user-agent")
    try:
        result = await authenticate_admin(
            _database(request),
            request.app.state.argon2_gate,
            username=body.username,
            password=body.password,
            ip_key=ip_text or "unknown",
            ip_address=ip_text,
            user_agent=user_agent,
            policy=LoginPolicy(settings.admin_login_max_failures, settings.admin_login_window_seconds),
            session_ttl_seconds=settings.admin_session_ttl_seconds,
        )
    except Argon2Busy:
        # Refused before any password was checked, so no failed attempt is recorded.
        raise AdminApiError(503, "login_busy", "Login capacity is temporarily full. Try again shortly.",
                            error_type="gateway_error", headers={"Retry-After": "2"}) from None
    if result.outcome == "rate_limited":
        raise AdminApiError(429, "login_rate_limited", "Too many failed login attempts. Try again later.",
                            error_type="rate_limit_error", headers={"Retry-After": str(result.retry_after)})
    if result.outcome != "success" or result.session is None:
        raise AdminApiError(401, "invalid_credentials", "Invalid username or password.",
                            error_type="authentication_error")
    issued = result.session
    response = JSONResponse(
        {"authenticated": True, "username": result.username, "csrf_token": issued.csrf_token,
         "expires_at": issued.expires_at},
        headers=_NO_STORE,
    )
    response.set_cookie(SESSION_COOKIE_NAME, issued.token, max_age=settings.admin_session_ttl_seconds,
                        **SESSION_COOKIE_OPTIONS)
    response.set_cookie(CSRF_COOKIE_NAME, issued.csrf_token, max_age=settings.admin_session_ttl_seconds,
                        **CSRF_COOKIE_OPTIONS)
    return response


@router.post("/logout")
def admin_logout(request: Request, context: AdminContext = Depends(require_admin_session)) -> JSONResponse:
    ip_text, user_agent = _audit_actor(request)
    with _database(request).transaction() as conn:
        revoke_session(conn, request.cookies.get(SESSION_COOKIE_NAME))
        record_audit_event(conn, action="admin.logout", admin_user_id=context.session.admin_user_id,
                           target=f"admin_user:{context.session.admin_user_id}",
                           ip_address=ip_text, user_agent=user_agent, now=now_epoch())
    response = JSONResponse({"status": "logged_out"}, headers=_NO_STORE)
    response.delete_cookie(SESSION_COOKIE_NAME, **SESSION_COOKIE_OPTIONS)
    response.delete_cookie(CSRF_COOKIE_NAME, **CSRF_COOKIE_OPTIONS)
    return response


@router.get("/session")
def admin_session(request: Request, context: AdminContext = Depends(require_admin_session)) -> JSONResponse:
    """Return session state and the CSRF token bound to this session.

    While the CSRF cookie matches the stored hash, the same token is returned, so
    several tabs of one browser keep working. A new token is issued only when the
    cookie is missing or does not match.
    """
    with _database(request).connect() as conn:
        csrf_token, issued_new = csrf_token_for_session(conn, context.session,
                                                        request.cookies.get(CSRF_COOKIE_NAME))
    response = JSONResponse(
        {
            "authenticated": True,
            "username": context.session.username,
            "csrf_token": csrf_token,
            "expires_at": context.session.expires_at,
            "idle_timeout_seconds": _settings(request).admin_session_idle_seconds,
        },
        headers=_NO_STORE,
    )
    if issued_new:
        remaining = max(1, context.session.expires_at - now_epoch())
        response.set_cookie(CSRF_COOKIE_NAME, csrf_token, max_age=remaining, **CSRF_COOKIE_OPTIONS)
    return response


@router.get("/health")
def admin_health(request: Request, context: AdminContext = Depends(require_admin_session)) -> dict[str, object]:
    try:
        with _database(request).connect() as conn:
            conn.execute("SELECT 1").fetchone()
            version = read_schema_version(conn)
    except sqlite3.Error:
        raise AdminApiError(503, "database_unavailable", "Database is unavailable.", error_type="gateway_error") from None
    return {"status": "ok", "database": "ok", "schema_version": version}


@router.get("/ip-rules")
def list_ip_rules(request: Request, context: AdminContext = Depends(require_admin_session)) -> dict[str, object]:
    with _database(request).connect() as conn:
        rows = conn.execute(
            "SELECT id, rule_type, ip_or_cidr, description, is_active, created_at FROM admin_ip_rules ORDER BY id"
        ).fetchall()
    return {"rules": [
        {"id": int(row["id"]), "rule_type": row["rule_type"], "ip_or_cidr": row["ip_or_cidr"],
         "description": row["description"], "is_active": bool(row["is_active"]),
         "created_at": int(row["created_at"])}
        for row in rows
    ]}


def _clean_description(text: str) -> str:
    return "".join(ch for ch in text.strip() if ch.isprintable())


@router.post("/ip-rules", status_code=201)
def create_ip_rule(body: IpRuleCreate, request: Request, context: AdminContext = Depends(require_admin_session)) -> JSONResponse:
    try:
        network = parse_ip_or_cidr(body.ip_or_cidr)
    except ValueError:
        raise AdminApiError(400, "invalid_ip_rule", "IP rule must be a valid IP address or CIDR.",
                            error_type="invalid_request_error") from None
    if body.rule_type == "deny" and network.prefixlen == 0:
        raise AdminApiError(400, "invalid_ip_rule", "A deny rule cannot cover every address.",
                            error_type="invalid_request_error")
    canonical = str(network)
    description = _clean_description(body.description)
    address = getattr(request.state, "client_address", None)
    ip_text, user_agent = _audit_actor(request)
    with _database(request).transaction() as conn:
        candidate = IpRule(-1, body.rule_type, network, True)
        if address is None or not is_request_allowed(address, [*_load_rules(conn), candidate]):
            raise AdminApiError(409, "would_block_current_client",
                                "This rule would block the address making this request.",
                                error_type="invalid_request_error")
        try:
            cursor = conn.execute(
                "INSERT INTO admin_ip_rules(rule_type, ip_or_cidr, description, is_active, created_at) VALUES (?, ?, ?, 1, ?)",
                (body.rule_type, canonical, description, now_epoch()),
            )
        except sqlite3.IntegrityError:
            raise AdminApiError(409, "ip_rule_exists", "An identical IP rule already exists.",
                                error_type="invalid_request_error") from None
        rule_id = int(cursor.lastrowid or 0)
        record_audit_event(conn, action="admin.ip_rule.create", admin_user_id=context.session.admin_user_id,
                           target=f"ip_rule:{rule_id}", ip_address=ip_text, user_agent=user_agent,
                           metadata={"rule_type": body.rule_type, "cidr": canonical})
    return JSONResponse(status_code=201, content={
        "id": rule_id, "rule_type": body.rule_type, "ip_or_cidr": canonical,
        "description": description, "is_active": True,
    }, headers=_NO_STORE)


@router.delete("/ip-rules/{rule_id}")
def delete_ip_rule(rule_id: int, request: Request, context: AdminContext = Depends(require_admin_session)) -> dict[str, object]:
    address = getattr(request.state, "client_address", None)
    ip_text, user_agent = _audit_actor(request)
    with _database(request).transaction() as conn:
        row = conn.execute("SELECT rule_type, ip_or_cidr FROM admin_ip_rules WHERE id = ?", (rule_id,)).fetchone()
        if row is None:
            raise AdminApiError(404, "ip_rule_not_found", "IP rule was not found.", error_type="invalid_request_error")
        if address is None or not is_request_allowed(address, _load_rules(conn, exclude_id=rule_id)):
            raise AdminApiError(409, "would_block_current_client",
                                "Deleting this rule would block the address making this request.",
                                error_type="invalid_request_error")
        conn.execute("DELETE FROM admin_ip_rules WHERE id = ?", (rule_id,))
        record_audit_event(conn, action="admin.ip_rule.delete", admin_user_id=context.session.admin_user_id,
                           target=f"ip_rule:{rule_id}", ip_address=ip_text, user_agent=user_agent,
                           metadata={"rule_type": str(row["rule_type"]), "cidr": str(row["ip_or_cidr"])})
    return {"status": "deleted", "id": rule_id}


# ---------------------------------------------------------------------------
# Provider key management. Responses carry metadata only, never key values.
# ---------------------------------------------------------------------------


class ProviderSecretBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # SecretStr keeps the value out of repr(), logs, and validation messages.
    api_key: SecretStr = Field(min_length=1, max_length=8192)


def _provider_name(raw: str) -> str:
    try:
        return validate_provider_api_key_env(raw)
    except ValueError:
        raise AdminApiError(400, "invalid_provider_name",
                            "Provider key name must end in _API_KEY and must not use a reserved prefix.",
                            error_type="invalid_request_error") from None


def _key_store_error() -> AdminApiError:
    return AdminApiError(503, "provider_key_store_unavailable", "The provider key store is not available.",
                         error_type="gateway_error")


def _actor(request: Request, context: AdminContext) -> AuditActor:
    ip_text, user_agent = _audit_actor(request)
    return AuditActor(admin_user_id=context.session.admin_user_id, ip_address=ip_text,
                      user_agent=user_agent, source="api")


@router.get("/provider-secrets")
def list_provider_secret_metadata(request: Request,
                                  context: AdminContext = Depends(require_admin_session)) -> dict[str, object]:
    return {"secrets": [
        {"provider_name": info.provider_name, "key_version": info.key_version,
         "created_at": info.created_at, "updated_at": info.updated_at}
        for info in list_provider_secrets(_database(request))
    ]}


@router.put("/provider-secrets/{name}")
def put_provider_secret(name: str, body: ProviderSecretBody, request: Request,
                        context: AdminContext = Depends(require_admin_session)) -> dict[str, object]:
    provider_name = _provider_name(name)
    try:
        keyring = load_keyring()
    except CryptoError:
        raise _key_store_error() from None
    try:
        version = store_provider_secret(_database(request), keyring, provider_name,
                                        body.api_key.get_secret_value(), actor=_actor(request, context))
    except ValueError:
        raise AdminApiError(422, "invalid_provider_secret",
                            "The provider key is empty, too large, or contains whitespace or control characters.",
                            error_type="invalid_request_error") from None
    except CryptoError:
        raise _key_store_error() from None
    return {"status": "stored", "provider_name": provider_name, "key_version": version}


@router.delete("/provider-secrets/{name}")
def delete_provider_secret_route(name: str, request: Request,
                                 context: AdminContext = Depends(require_admin_session)) -> dict[str, object]:
    provider_name = _provider_name(name)
    if not delete_provider_secret(_database(request), provider_name, actor=_actor(request, context)):
        raise AdminApiError(404, "provider_secret_not_found", "No stored key has that name.",
                            error_type="invalid_request_error")
    return {"status": "deleted", "provider_name": provider_name}


@router.post("/provider-secrets/rotate")
def rotate_provider_secret_keys(request: Request,
                                context: AdminContext = Depends(require_admin_session)) -> dict[str, object]:
    try:
        keyring: Keyring = load_keyring()
    except CryptoError:
        raise _key_store_error() from None
    try:
        rotated = rotate_provider_secrets(_database(request), keyring, actor=_actor(request, context))
    except CryptoError:
        raise AdminApiError(503, "provider_key_rotation_failed",
                            "Key rotation was not applied. Check the master key configuration.",
                            error_type="gateway_error") from None
    return {"rotated": rotated, "key_version": keyring.current.version}
