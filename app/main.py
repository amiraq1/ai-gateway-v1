from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Callable

import httpx
from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse

from .auth import authenticate_key, make_request_log
from .config import GatewayConfig, ProviderConfig, load_config
from .database import Database
from .models import ChatCompletionRequest, provider_payload
from .providers import MAX_ATTEMPTS, RETRYABLE_STATUS, ProviderFailure, _headers, complete
from .secret_loader import SecretLoadError, resolve_secret


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


def _provider_body(base_payload: dict[str, Any], provider: ProviderConfig) -> dict[str, Any]:
    body = dict(base_payload)
    body["model"] = provider.model
    return body


def _safe_error_event(code: str) -> bytes:
    data = json.dumps({"error": {"message": "The upstream stream failed.", "type": "gateway_error", "code": code}}, separators=(",", ":"))
    return f"event: error\ndata: {data}\n\n".encode("utf-8")


def _parse_sse_data(lines: list[str]) -> str | None:
    data_lines = [line[5:].lstrip(" ") for line in lines if line.startswith("data:")]
    return "\n".join(data_lines) if data_lines else None


def create_app(config: GatewayConfig | None = None, db: Database | None = None) -> FastAPI:
    cfg = config or load_config()
    database = db or Database(cfg.settings.database_path)
    database.init()
    app = FastAPI(title="AI Gateway V1", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.gateway_config = cfg
    app.state.database = database
    app.state.http_transport = None
    app.add_middleware(BoundedBodyMiddleware, maximum=cfg.settings.max_body_bytes)

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
        return {"object": "list", "data": [{"id": alias, "object": "model", "created": created, "owned_by": "ai-gateway"} for alias in cfg.public_aliases()]}

    @app.post("/v1/chat/completions")
    async def chat_completions(payload: ChatCompletionRequest, request: Request, client: dict[str, Any] | JSONResponse = Depends(get_client)) -> Any:
        if isinstance(client, JSONResponse):
            return client
        allowed, retry_after = database.consume_rate_limit(client["client_id"], int(client["rpm"]))
        if not allowed:
            return _error(429, "Rate limit exceeded.", "rate_limit_error", "rate_limit_exceeded", {"Retry-After": str(retry_after)})
        providers = cfg.providers_for(payload.model)
        if not providers:
            return _error(404, "The requested model is not available.", "invalid_request_error", "model_not_found")
        try:
            upstream_payload = provider_payload(payload, payload.model)
        except ValueError as exc:
            return _error(400, str(exc), "invalid_request_error", "unsupported_parameter")
        started = time.monotonic()
        if payload.stream:
            return StreamingResponse(
                _stream_chat(database, cfg, client, payload.model, providers, upstream_payload, request.app.state.http_transport, started),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
            )
        try:
            data, provider_name, usage = await complete(providers, upstream_payload, cfg.settings.provider_timeout_seconds, request.app.state.http_transport)
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
                       transport: httpx.AsyncBaseTransport | None, started: float):
    stream_deadline = started + min(600.0, cfg.settings.provider_timeout_seconds * 10)
    final_provider: str | None = None
    error_category: str | None = None
    final_status = 200
    usage: dict[str, Any] | None = None
    success = False
    attempt_providers = providers[:MAX_ATTEMPTS]
    try:
        for index, provider in enumerate(attempt_providers):
            emitted = False
            event_lines: list[str] = []
            event_size = 0
            saw_done = False
            try:
                async with httpx.AsyncClient(timeout=cfg.settings.provider_timeout_seconds, transport=transport, follow_redirects=False) as http:
                    async with http.stream("POST", f"{provider.api_base.rstrip('/')}/chat/completions", headers=_headers(provider), json=_provider_body(base_payload, provider)) as response:
                        if response.status_code in RETRYABLE_STATUS:
                            await response.aread()
                            if index + 1 < len(attempt_providers):
                                continue
                            error_category = "provider_unavailable"
                            final_status = 502
                            yield _safe_error_event(error_category)
                            return
                        if response.status_code in {401, 403}:
                            error_category = "provider_authentication"
                            final_status = 502
                            yield _safe_error_event(error_category)
                            return
                        if response.status_code < 200 or response.status_code >= 300:
                            error_category = "provider_rejected_request"
                            final_status = 502
                            yield _safe_error_event(error_category)
                            return
                        content_type = response.headers.get("content-type", "").lower()
                        if "text/event-stream" not in content_type:
                            error_category = "provider_malformed_stream"
                            final_status = 502
                            yield _safe_error_event(error_category)
                            return
                        async for line in response.aiter_lines():
                            if time.monotonic() > stream_deadline:
                                raise ProviderFailure("provider_stream_timeout", 504, retryable=not emitted)
                            if line == "":
                                if event_lines:
                                    data = _parse_sse_data(event_lines)
                                    if data is not None:
                                        if data == "[DONE]":
                                            yield ("\n".join(event_lines) + "\n\n").encode("utf-8")
                                            emitted = True
                                            saw_done = True
                                            break
                                        try:
                                            decoded = json.loads(data)
                                            if isinstance(decoded, dict) and isinstance(decoded.get("usage"), dict):
                                                usage = decoded["usage"]
                                        except (ValueError, TypeError):
                                            pass
                                    event = ("\n".join(event_lines) + "\n\n").encode("utf-8")
                                    event_lines = []
                                    event_size = 0
                                    if event:
                                        yield event
                                        emitted = True
                                continue
                            event_size += len(line.encode("utf-8"))
                            if event_size > 65536:
                                raise ProviderFailure("provider_event_too_large", 502, False)
                            event_lines.append(line)
                        if event_lines and not saw_done:
                            # An unterminated final SSE event is malformed; never forward a partial event.
                            raise ProviderFailure("provider_malformed_stream", 502, False)
                        if not saw_done:
                            yield b"data: [DONE]\n\n"
                        final_provider = provider.name
                        success = True
                        break
            except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError):
                if not emitted and index + 1 < len(attempt_providers):
                    continue
                error_category = "provider_stream_failure"
                final_status = 502
                yield _safe_error_event(error_category)
                return
            except ProviderFailure as failure:
                if failure.retryable and not emitted and index + 1 < len(attempt_providers):
                    continue
                error_category = failure.category
                final_status = failure.status_code
                yield _safe_error_event(error_category)
                return
        if not success and error_category is None:
            error_category = "provider_unavailable"
            final_status = 502
            yield _safe_error_event(error_category)
    except asyncio.CancelledError:
        error_category = "client_disconnected"
        final_status = 499
        raise
    finally:
        try:
            database.log_request(make_request_log(client["client_id"], alias, final_provider, final_status,
                                                  (time.monotonic() - started) * 1000, usage,
                                                  error_category, cfg.settings.retention_days))
        except Exception:
            # Never place prompts, provider bodies, or exception strings in logs.
            pass
