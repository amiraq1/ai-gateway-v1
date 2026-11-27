from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import logging
import time
from typing import Any, Callable

import anyio
import httpx
from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse

from .auth import authenticate_key, digest_key, make_request_log
from .config import GatewayConfig, ProviderConfig, load_config
from .database import Database
from .models import ChatCompletionRequest, provider_payload
from .providers import (
    MAX_ATTEMPTS,
    RETRYABLE_STATUS,
    ProviderFailure,
    SharedHttpClients,
    _headers,
    borrow_http_client,
    complete,
    drain_bounded_response,
)
from .secret_loader import SecretLoadError, resolve_secret
from .ssrf import create_safe_transport

logger = logging.getLogger("ai_gateway")


def _check_db_health(database: Database) -> None:
    with database.connect() as conn:
        conn.execute("SELECT 1").fetchone()


def _check_gateway_health(database: Database) -> None:
    _check_db_health(database)
    pepper = resolve_secret("GATEWAY_PEPPER")
    digest_key("healthz-check", pepper)


class BoundedBodyMiddleware:
    """Buffer only a small, bounded request body before JSON parsing."""
    def __init__(self, app: Any, maximum: int, body_timeout: float = 15.0) -> None:
        self.app = app
        self.maximum = maximum
        self.body_timeout = body_timeout

    async def __call__(self, scope: dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        body = bytearray()
        disconnected = False
        deadline = time.monotonic() + self.body_timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                response = JSONResponse(
                    status_code=408,
                    content={"error": {"message": "Request body read timed out.", "type": "invalid_request_error", "code": "request_timeout"}},
                )
                await response(scope, receive, send)
                return
            try:
                message = await asyncio.wait_for(receive(), timeout=remaining)
            except asyncio.TimeoutError:
                response = JSONResponse(
                    status_code=408,
                    content={"error": {"message": "Request body read timed out.", "type": "invalid_request_error", "code": "request_timeout"}},
                )
                await response(scope, receive, send)
                return
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


class DisconnectAwareStreamingResponse(StreamingResponse):
    """StreamingResponse that cancels upstream work on http.disconnect across all ASGI versions."""

    def __init__(self, *args: Any, on_cleanup: Callable[[], None] | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._on_cleanup = on_cleanup

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        try:
            if scope.get("type") != "http":
                await super().__call__(scope, receive, send)
                return
            async with anyio.create_task_group() as tg:
                async def run_stream() -> None:
                    try:
                        await self.stream_response(send)
                    except OSError:
                        pass
                    finally:
                        aclose = getattr(self.body_iterator, "aclose", None)
                        if callable(aclose):
                            with anyio.CancelScope(shield=True):
                                await aclose()
                        tg.cancel_scope.cancel()

                async def watch_disconnect() -> None:
                    while True:
                        message = await receive()
                        if message["type"] == "http.disconnect":
                            tg.cancel_scope.cancel()
                            break

                tg.start_soon(run_stream)
                await watch_disconnect()
            if self.background is not None:
                await self.background()
        finally:
            if self._on_cleanup is not None:
                self._on_cleanup()


class _ClientDisconnectedError(Exception):
    """Raised when an HTTP client disconnects while awaiting a non-streaming completion."""


async def _complete_with_disconnect(
    request: Request,
    providers: list[ProviderConfig],
    upstream_payload: dict[str, Any],
    timeout: float,
    transport: Any,
    clients: SharedHttpClients,
) -> tuple[dict[str, Any], str, dict[str, Any] | None]:
    result: tuple[dict[str, Any], str, dict[str, Any] | None] | None = None
    captured_exc: Exception | None = None
    disconnected = False

    async with anyio.create_task_group() as tg:
        async def run_complete() -> None:
            nonlocal result, captured_exc
            try:
                result = await complete(
                    providers,
                    upstream_payload,
                    timeout,
                    transport,
                    clients=clients,
                )
            except Exception as exc:
                captured_exc = exc
            finally:
                tg.cancel_scope.cancel()

        async def watch_disconnect() -> None:
            nonlocal disconnected
            while True:
                message = await request.receive()
                if message["type"] == "http.disconnect":
                    disconnected = True
                    tg.cancel_scope.cancel()
                    return

        tg.start_soon(watch_disconnect)
        await run_complete()

    if disconnected:
        raise _ClientDisconnectedError()
    if captured_exc is not None:
        raise captured_exc
    if result is None:
        raise _ClientDisconnectedError()
    return result


def create_app(config: GatewayConfig | None = None, db: Database | None = None) -> FastAPI:
    cfg = config or load_config()
    if config is None:
        pepper = resolve_secret("GATEWAY_PEPPER")
        digest_key("startup-check", pepper)
    database = db or Database(cfg.settings.database_path)
    database.init()

    @asynccontextmanager
    async def lifespan(fastapi_app: FastAPI):
        fastapi_app.state.http_clients.ensure_initialized()
        try:
            yield
        finally:
            await fastapi_app.state.http_clients.aclose()

    app = FastAPI(title="AI Gateway V1", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.gateway_config = cfg
    app.state.database = database
    app.state.http_transports = {
        False: create_safe_transport(allow_private_hosts=False),
        True: create_safe_transport(allow_private_hosts=True),
    }
    app.state.http_transport = app.state.http_transports
    app.state.http_clients = SharedHttpClients(app.state.http_transports, cfg.settings.provider_timeout_seconds)
    app.state.global_semaphore = asyncio.Semaphore(cfg.settings.max_concurrent_requests)
    app.state.client_semaphores = {}
    app.add_middleware(
        BoundedBodyMiddleware,
        maximum=cfg.settings.max_body_bytes,
        body_timeout=cfg.settings.body_read_timeout_seconds,
    )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _error(422, "Request validation failed.", "invalid_request_error", "invalid_request")

    async def get_client(authorization: str | None = Header(default=None)) -> dict[str, Any] | JSONResponse:
        if not authorization or not authorization.startswith("Bearer "):
            return _error(401, "A valid bearer API key is required.", "authentication_error", "invalid_api_key", {"WWW-Authenticate": "Bearer"})
        try:
            pepper = await asyncio.to_thread(resolve_secret, "GATEWAY_PEPPER")
            digest_key("auth-check", pepper)
        except (SecretLoadError, ValueError):
            return _error(503, "Gateway authentication is unavailable.", "gateway_error", "secret_unavailable")
        client = await asyncio.to_thread(authenticate_key, database, pepper, authorization[7:])
        if not client:
            return _error(401, "A valid bearer API key is required.", "authentication_error", "invalid_api_key", {"WWW-Authenticate": "Bearer"})
        return client

    @app.get("/healthz")
    async def healthz() -> Any:
        try:
            await asyncio.to_thread(_check_gateway_health, database)
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
        allowed, retry_after = await asyncio.to_thread(database.consume_rate_limit, client["client_id"], int(client["rpm"]))
        if not allowed:
            return _error(429, "Rate limit exceeded.", "rate_limit_error", "rate_limit_exceeded", {"Retry-After": str(retry_after)})
        providers = cfg.providers_for(payload.model)
        if not providers:
            return _error(404, "The requested model is not available.", "invalid_request_error", "model_not_found")
        requested_tokens = payload.max_tokens if payload.max_tokens is not None else payload.max_completion_tokens
        if requested_tokens is not None and requested_tokens > cfg.settings.max_request_output_tokens:
            return _error(400, "Requested output token limit exceeds gateway cap.", "invalid_request_error", "max_tokens_exceeded")
        if payload.n is not None and payload.n > cfg.settings.max_request_choices:
            return _error(400, "Requested choice count exceeds gateway cap.", "invalid_request_error", "n_exceeded")
        try:
            upstream_payload = provider_payload(payload, payload.model)
        except ValueError as exc:
            return _error(400, str(exc), "invalid_request_error", "unsupported_parameter")

        global_sem: asyncio.Semaphore = request.app.state.global_semaphore
        try:
            await asyncio.wait_for(global_sem.acquire(), timeout=0.01)
        except asyncio.TimeoutError:
            return _error(503, "Gateway concurrency limit exceeded.", "gateway_error", "server_busy", {"Retry-After": "1"})

        client_semaphores: dict[str, asyncio.Semaphore] = request.app.state.client_semaphores
        client_sem = client_semaphores.setdefault(
            client["client_id"],
            asyncio.Semaphore(cfg.settings.max_client_concurrent_requests),
        )
        try:
            await asyncio.wait_for(client_sem.acquire(), timeout=0.01)
        except asyncio.TimeoutError:
            global_sem.release()
            return _error(
                429,
                "Too many concurrent requests for this API key.",
                "rate_limit_error",
                "too_many_concurrent_requests",
                {"Retry-After": "1"},
            )

        released = False

        def release_slots() -> None:
            nonlocal released
            if not released:
                released = True
                client_sem.release()
                global_sem.release()

        started = time.monotonic()
        if payload.stream:
            try:
                return DisconnectAwareStreamingResponse(
                    _stream_chat(
                        database,
                        cfg,
                        client,
                        payload.model,
                        providers,
                        upstream_payload,
                        request.app.state.http_transport,
                        started,
                        clients=request.app.state.http_clients,
                        release_slots=release_slots,
                    ),
                    media_type="text/event-stream",
                    headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
                    on_cleanup=release_slots,
                )
            except BaseException:
                release_slots()
                raise
        try:
            data, provider_name, usage = await _complete_with_disconnect(
                request,
                providers,
                upstream_payload,
                cfg.settings.provider_timeout_seconds,
                request.app.state.http_transport,
                request.app.state.http_clients,
            )
            data["model"] = payload.model
        except _ClientDisconnectedError:
            with anyio.CancelScope(shield=True):
                try:
                    await asyncio.to_thread(
                        database.log_request,
                        make_request_log(
                            client["client_id"],
                            payload.model,
                            None,
                            499,
                            (time.monotonic() - started) * 1000,
                            None,
                            "client_disconnected",
                            cfg.settings.retention_days,
                        ),
                    )
                except Exception:
                    logger.warning("Failed to persist client_disconnected request log entry")
            return _error(499, "Client disconnected.", "invalid_request_error", "client_disconnected")
        except ProviderFailure as failure:
            status = failure.status_code
            try:
                await asyncio.to_thread(database.log_request, make_request_log(client["client_id"], payload.model, None, status, (time.monotonic() - started) * 1000, None, failure.category, cfg.settings.retention_days))
            except Exception:
                return _error(503, "Gateway storage is unavailable.", "gateway_error", "storage_unavailable")
            return _error(status, "The upstream provider could not complete the request.", "gateway_error", failure.category)
        except Exception:
            try:
                await asyncio.to_thread(database.log_request, make_request_log(client["client_id"], payload.model, None, 502, (time.monotonic() - started) * 1000, None, "gateway_internal", cfg.settings.retention_days))
            except Exception:
                logger.warning("Failed to persist error request log entry")
            return _error(502, "The gateway could not complete the request.", "gateway_error", "gateway_internal")
        finally:
            release_slots()
        try:
            await asyncio.to_thread(database.log_request, make_request_log(client["client_id"], payload.model, provider_name, 200, (time.monotonic() - started) * 1000, usage, None, cfg.settings.retention_days))
        except Exception:
            logger.warning("Failed to persist successful request log entry")
        return data

    return app


async def _stream_chat(database: Database, cfg: GatewayConfig, client: dict[str, Any], alias: str,
                       providers: list[ProviderConfig], base_payload: dict[str, Any],
                       transport: httpx.AsyncBaseTransport | None, started: float,
                       clients: SharedHttpClients | None = None,
                       release_slots: Callable[[], None] | None = None):
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
            total_stream_bytes = 0
            saw_done = False
            try:
                async with borrow_http_client(provider, cfg.settings.provider_timeout_seconds, transport=transport, clients=clients) as http:
                    async with http.stream("POST", f"{provider.api_base.rstrip('/')}/chat/completions", headers=_headers(provider), json=_provider_body(base_payload, provider), timeout=cfg.settings.provider_timeout_seconds) as response:
                        if response.status_code in RETRYABLE_STATUS:
                            await drain_bounded_response(response)
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
                        bytes_iter = response.aiter_bytes().__aiter__()
                        line_buf = bytearray()
                        pending_lines: list[str] = []
                        received_first_chunk = False
                        while True:
                            while not pending_lines:
                                remaining_deadline = stream_deadline - time.monotonic()
                                if remaining_deadline <= 0:
                                    raise ProviderFailure("provider_stream_timeout", 504, retryable=not emitted)
                                step_timeout = (
                                    cfg.settings.provider_timeout_seconds
                                    if not received_first_chunk
                                    else cfg.settings.stream_idle_timeout_seconds
                                )
                                try:
                                    chunk = await asyncio.wait_for(
                                        bytes_iter.__anext__(),
                                        timeout=min(remaining_deadline, step_timeout),
                                    )
                                except StopAsyncIteration:
                                    if line_buf:
                                        if len(line_buf) > 65536:
                                            raise ProviderFailure("provider_event_too_large", 502, False)
                                        pending_lines.append(line_buf.rstrip(b"\r").decode("utf-8", errors="replace"))
                                        line_buf.clear()
                                    break
                                except asyncio.TimeoutError:
                                    raise ProviderFailure("provider_stream_timeout", 504, retryable=not emitted) from None
                                received_first_chunk = True
                                total_stream_bytes += len(chunk)
                                if total_stream_bytes > cfg.settings.max_stream_bytes:
                                    raise ProviderFailure("provider_stream_too_large", 502, False)
                                line_buf.extend(chunk)
                                while b"\n" in line_buf:
                                    raw_line, _, rest = line_buf.partition(b"\n")
                                    line_buf = bytearray(rest)
                                    if len(raw_line) > 65536:
                                        raise ProviderFailure("provider_event_too_large", 502, False)
                                    pending_lines.append(raw_line.rstrip(b"\r").decode("utf-8", errors="replace"))
                                if len(line_buf) > 65536:
                                    raise ProviderFailure("provider_event_too_large", 502, False)
                            if not pending_lines:
                                break
                            line = pending_lines.pop(0)
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
                                        if data is not None:
                                            emitted = True
                                continue
                            event_size += len(line.encode("utf-8"))
                            if event_size > 65536:
                                raise ProviderFailure("provider_event_too_large", 502, False)
                            event_lines.append(line)
                        if event_lines and not saw_done:
                            # An unterminated final SSE event is malformed; never forward a partial event.
                            raise ProviderFailure("provider_malformed_stream", 502, retryable=not emitted)
                        if not saw_done:
                            raise ProviderFailure("provider_incomplete_stream", 502, retryable=not emitted)
                        final_provider = provider.name
                        success = True
                        break
            except (httpx.TransportError, httpx.DecodingError):
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
    except (asyncio.CancelledError, GeneratorExit):
        error_category = "client_disconnected"
        final_status = 499
        raise
    finally:
        if release_slots is not None:
            release_slots()
        with anyio.CancelScope(shield=True):
            try:
                await asyncio.to_thread(
                    database.log_request,
                    make_request_log(
                        client["client_id"],
                        alias,
                        final_provider,
                        final_status,
                        (time.monotonic() - started) * 1000,
                        usage,
                        error_category,
                        cfg.settings.retention_days,
                    ),
                )
            except Exception:
                # Never place prompts, provider bodies, or exception strings in logs.
                logger.warning("Failed to persist stream request log entry")
