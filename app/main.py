from __future__ import annotations

import time
from typing import Any, Callable

import httpx
from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse

from .admin_routes import AdminApiError, admin_error_handler
from .admin_routes import router as admin_router
from .auth import Argon2Gate, authenticate_key, make_request_log
from .config import GatewayConfig, ProviderConfig, load_config
from .database import Database
from .models import ChatCompletionRequest, provider_payload
from .provider_secrets import provider_secret_names, resolve_provider_api_key
from .providers import ProviderFailure, SecretSource, StreamOutcome, complete, stream_completion
from .secret_loader import SecretLoadError, resolve_secret
from .ssrf import Resolver, system_resolver


def _secret_source(database: Database) -> SecretSource:
    def resolve(name: str) -> str:
        return resolve_provider_api_key(database, name)
    return resolve


class BoundedBodyMiddleware:
    """Buffer only a small, bounded request body before JSON parsing."""
    def __init__(self, app: Any, maximum: int) -> None:
        self.app = app
        self.maximum = maximum

    async def __call__(self, scope: dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        body = bytearray()
        disconnected = False
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                disconnected = True
                break
            if message["type"] != "http.request":
                continue
            body.extend(message.get("body", b""))
            if len(body) > self.maximum:
                response = JSONResponse(status_code=413, content={"error": {"message": "Request body is too large.", "type": "invalid_request_error", "code": "request_too_large"}})
                await response(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        if disconnected:
            return
        sent = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)


def _error(status: int, message: str, error_type: str = "gateway_error", code: str = "gateway_error", headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"message": message, "type": error_type, "code": code}}, headers=headers)


def create_app(config: GatewayConfig | None = None, db: Database | None = None) -> FastAPI:
    cfg = config or load_config()
    database = db or Database(cfg.settings.database_path)
    database.init()
    app = FastAPI(title="AI Gateway V1", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.gateway_config = cfg
    app.state.database = database
    app.state.http_transport = None
    app.state.dns_resolver = system_resolver
    app.state.argon2_gate = Argon2Gate(cfg.settings.admin_password_hash_concurrency,
                                       cfg.settings.admin_password_hash_queue)
    app.add_middleware(BoundedBodyMiddleware, maximum=cfg.settings.max_body_bytes)
    app.add_exception_handler(AdminApiError, admin_error_handler)
    app.include_router(admin_router)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _error(422, "Request validation failed.", "invalid_request_error", "invalid_request")

    async def get_client(authorization: str | None = Header(default=None)) -> dict[str, Any] | JSONResponse:
        if not authorization or not authorization.startswith("Bearer "):
            return _error(401, "A valid bearer API key is required.", "authentication_error", "invalid_api_key", {"WWW-Authenticate": "Bearer"})
        try:
            pepper = resolve_secret("GATEWAY_PEPPER")
        except SecretLoadError:
            return _error(503, "Gateway authentication is unavailable.", "gateway_error", "secret_unavailable")
        client = authenticate_key(database, pepper, authorization[7:])
        if not client:
            return _error(401, "A valid bearer API key is required.", "authentication_error", "invalid_api_key", {"WWW-Authenticate": "Bearer"})
        return client

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        try:
            with database.connect() as conn:
                conn.execute("SELECT 1").fetchone()
        except Exception:
            return JSONResponse(status_code=503, content={"status": "unavailable"})
        return {"status": "ok"}

    @app.get("/v1/models")
    async def models(client: dict[str, Any] | JSONResponse = Depends(get_client)) -> Any:
        if isinstance(client, JSONResponse):
            return client
        created = int(time.time())
        return {"object": "list", "data": [{"id": alias, "object": "model", "created": created, "owned_by": "ai-gateway"} for alias in cfg.public_aliases(provider_secret_names(database))]}

    @app.post("/v1/chat/completions")
    async def chat_completions(payload: ChatCompletionRequest, request: Request, client: dict[str, Any] | JSONResponse = Depends(get_client)) -> Any:
        if isinstance(client, JSONResponse):
            return client
        allowed, retry_after = database.consume_rate_limit(client["client_id"], int(client["rpm"]))
        if not allowed:
            return _error(429, "Rate limit exceeded.", "rate_limit_error", "rate_limit_exceeded", {"Retry-After": str(retry_after)})
        providers = cfg.providers_for(payload.model, provider_secret_names(database))
        if not providers:
            return _error(404, "The requested model is not available.", "invalid_request_error", "model_not_found")
        try:
            upstream_payload = provider_payload(payload, payload.model)
        except ValueError as exc:
            return _error(400, str(exc), "invalid_request_error", "unsupported_parameter")
        started = time.monotonic()
        secret_source = _secret_source(database)
        resolver: Resolver = request.app.state.dns_resolver
        if payload.stream:
            return StreamingResponse(
                _stream_chat(database, cfg, client, payload.model, providers, upstream_payload, request.app.state.http_transport, started, secret_source, resolver),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
            )
        try:
            data, provider_name, usage = await complete(providers, upstream_payload, cfg.settings.provider_timeout_seconds, request.app.state.http_transport, secret_source=secret_source, resolver=resolver)
            data["model"] = payload.model
            database.log_request(make_request_log(client["client_id"], payload.model, provider_name, 200, (time.monotonic() - started) * 1000, usage, None, cfg.settings.retention_days))
            return data
        except ProviderFailure as failure:
            status = failure.status_code
            try:
                database.log_request(make_request_log(client["client_id"], payload.model, None, status, (time.monotonic() - started) * 1000, None, failure.category, cfg.settings.retention_days))
            except Exception:
                return _error(503, "Gateway storage is unavailable.", "gateway_error", "storage_unavailable")
            return _error(status, "The upstream provider could not complete the request.", "gateway_error", failure.category)
        except Exception:
            try:
                database.log_request(make_request_log(client["client_id"], payload.model, None, 502, (time.monotonic() - started) * 1000, None, "gateway_internal", cfg.settings.retention_days))
            except Exception:
                pass
            return _error(502, "The gateway could not complete the request.", "gateway_error", "gateway_internal")

    return app


async def _stream_chat(database: Database, cfg: GatewayConfig, client: dict[str, Any], alias: str,
                       providers: list[ProviderConfig], base_payload: dict[str, Any],
                       transport: httpx.AsyncBaseTransport | None, started: float,
                       secret_source: SecretSource = resolve_secret, resolver: Resolver = system_resolver):
    """Forward the /v1 SSE stream and write one usage row when it ends, is cancelled, or fails."""
    outcome = StreamOutcome()
    events = stream_completion(
        providers, base_payload,
        timeout=cfg.settings.provider_timeout_seconds,
        deadline=started + min(600.0, cfg.settings.provider_timeout_seconds * 10),
        transport=transport, secret_source=secret_source, resolver=resolver, outcome=outcome,
    )
    try:
        async for event in events:
            yield event.data
    finally:
        try:
            await events.aclose()
        finally:
            try:
                database.log_request(make_request_log(client["client_id"], alias, outcome.provider_name,
                                                      outcome.final_status, (time.monotonic() - started) * 1000,
                                                      outcome.usage, outcome.error_category,
                                                      cfg.settings.retention_days))
            except Exception:
                # Never place prompts, provider bodies, or exception strings in logs.
                pass
