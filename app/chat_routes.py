"""Chat routes under /api/chat. Every route needs an admin session.

The session cookie is scoped to /api, so the browser sends it here too. The
admin IP allowlist applies only to /api/admin, not to chat.

A chat completion is stored in three steps. The user message is written first,
with status processing. The provider is called. Then the outcome is recorded
once: the assistant reply is inserted only when the upstream stream reached
[DONE] with text. Failures and disconnects store no reply text.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from functools import partial
from typing import Any

from anyio import to_thread
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from .admin_routes import AdminApiError, AdminContext, _client_address, require_admin_session
from .clock import now_epoch
from .config import GatewayConfig
from .conversations import (
    MAX_ASSISTANT_BYTES,
    MAX_USER_MESSAGE_BYTES,
    ChatError,
    Turn,
    TurnResult,
    clean_title,
    create_conversation,
    delete_conversation,
    finish_turn,
    list_conversations,
    load_conversation,
    prepare_turn,
    replay_payload,
    utf8_size,
)
from .database import Database
from .models import ChatCompletionRequest, provider_payload
from .provider_secrets import provider_secret_names, resolve_provider_api_key
from .providers import ProviderFailure, StreamOutcome, complete, safe_error_event, stream_completion
from .ssrf import Resolver

chat_router = APIRouter(prefix="/api/chat")
_NO_STORE = {"Cache-Control": "no-store"}
_STREAM_HEADERS = {"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"}


class ConversationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str = Field(min_length=1, max_length=64)
    title: str | None = Field(default=None, max_length=200)


class ChatTurnBody(BaseModel):
    # The client sends only the new message. Stored history is read from SQLite, never from the request.
    model_config = ConfigDict(extra="forbid")
    conversation_id: int | None = Field(default=None, ge=1)
    model: str = Field(min_length=1, max_length=64)
    # The byte limit is checked in _check_message. A character limit here would not match it.
    message: str = Field(min_length=1)
    stream: bool = False
    request_id: str | None = Field(default=None, min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


def _state(request: Request) -> tuple[GatewayConfig, Database]:
    return request.app.state.gateway_config, request.app.state.database


def _model_available(cfg: GatewayConfig, db: Database, alias: str) -> bool:
    return bool(cfg.providers_for(alias, provider_secret_names(db)))


def _turn_headers(turn: Turn) -> dict[str, str]:
    return {
        "X-Conversation-Id": str(turn.conversation_id),
        "X-User-Message-Id": str(turn.user_message_id),
        "X-Context-Truncated": "1" if turn.context_truncated else "0",
    }


def _completion_body(turn: Turn, reply: dict[str, Any], replayed: bool) -> dict[str, Any]:
    usage = {key: value for key, value in (reply.get("usage") or {}).items() if value is not None}
    return {
        "id": f"chatcmpl-{reply['id']}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": reply["model_alias"],
        "choices": [{"index": 0, "message": {"role": "assistant", "content": reply["content"]},
                     "finish_reason": "stop"}],
        "usage": usage,
        "conversation_id": turn.conversation_id,
        "user_message_id": turn.user_message_id,
        "message_id": reply["id"],
        "replayed": replayed,
        "context_truncated": turn.context_truncated,
    }


def _upstream_error(status: int, code: str, headers: dict[str, str]) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"message": "The upstream provider could not complete the request.",
                           "type": "gateway_error", "code": code}},
        headers=headers,
    )


def _first_choice_content(data: dict[str, Any]) -> str:
    choices = data.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            return message["content"]
    return ""


def _check_message(message: str) -> None:
    """Reject empty, non-UTF-8, and oversized messages before any database work. Size counts UTF-8 bytes."""
    size = utf8_size(message)
    if size is None:
        raise AdminApiError(422, "invalid_message", "The message must be valid UTF-8 text.",
                            error_type="invalid_request_error")
    if not message.strip():
        raise AdminApiError(422, "invalid_message", "The message is empty.", error_type="invalid_request_error")
    if size > MAX_USER_MESSAGE_BYTES:
        raise AdminApiError(422, "message_too_large", f"The message is larger than {MAX_USER_MESSAGE_BYTES} bytes.",
                            error_type="invalid_request_error")


def _reply_problem(content: str) -> str | None:
    """Why a provider reply cannot be stored as the assistant message, or None when it can."""
    size = utf8_size(content)
    if size is None:
        return "provider_malformed_response"
    if size == 0:
        return "provider_empty_response"
    if size > MAX_ASSISTANT_BYTES:
        return "provider_response_too_large"
    return None


def _outcome_result(outcome: StreamOutcome, pieces: list[str], cancelled: bool) -> TurnResult:
    return TurnResult(completed=outcome.completed, content="".join(pieces), provider_name=outcome.provider_name,
                      usage=outcome.usage, error_category=outcome.error_category, cancelled=cancelled)


@chat_router.get("/conversations")
async def list_chat_conversations(request: Request,
                                  limit: int = Query(default=50, ge=1, le=100),
                                  offset: int = Query(default=0, ge=0, le=100_000),
                                  context: AdminContext = Depends(require_admin_session)) -> JSONResponse:
    _cfg, db = _state(request)
    rows = await to_thread.run_sync(partial(list_conversations, db, context.session.admin_user_id, limit, offset))
    return JSONResponse({"conversations": rows}, headers=_NO_STORE)


@chat_router.post("/conversations", status_code=201)
async def create_chat_conversation(body: ConversationCreate, request: Request,
                                   context: AdminContext = Depends(require_admin_session)) -> JSONResponse:
    cfg, db = _state(request)
    if not await to_thread.run_sync(partial(_model_available, cfg, db, body.model)):
        raise AdminApiError(404, "model_not_found", "The requested model is not available.",
                            error_type="invalid_request_error")
    conversation = await to_thread.run_sync(partial(create_conversation, db, context.session.admin_user_id,
                                                    clean_title(body.title), body.model))
    return JSONResponse(conversation, status_code=201, headers=_NO_STORE)


@chat_router.get("/conversations/{conversation_id}")
async def get_chat_conversation(conversation_id: int, request: Request,
                                limit: int = Query(default=200, ge=1, le=500),
                                context: AdminContext = Depends(require_admin_session)) -> JSONResponse:
    _cfg, db = _state(request)
    loaded = await to_thread.run_sync(partial(load_conversation, db, context.session.admin_user_id,
                                              conversation_id, limit))
    if loaded is None:
        raise AdminApiError(404, "conversation_not_found", "Conversation was not found.",
                            error_type="invalid_request_error")
    conversation, messages = loaded
    return JSONResponse({"conversation": conversation, "messages": messages}, headers=_NO_STORE)


@chat_router.delete("/conversations/{conversation_id}")
async def delete_chat_conversation(conversation_id: int, request: Request,
                                   context: AdminContext = Depends(require_admin_session)) -> dict[str, Any]:
    _cfg, db = _state(request)
    address = _client_address(request)
    deleted = await to_thread.run_sync(partial(
        delete_conversation, db, context.session.admin_user_id, conversation_id,
        ip_address=str(address) if address else None, user_agent=request.headers.get("user-agent")))
    if not deleted:
        raise AdminApiError(404, "conversation_not_found", "Conversation was not found.",
                            error_type="invalid_request_error")
    return {"status": "deleted", "id": conversation_id}


@chat_router.post("/completions")
async def chat_completion(body: ChatTurnBody, request: Request,
                          context: AdminContext = Depends(require_admin_session)) -> Any:
    cfg, db = _state(request)
    owner = context.session.admin_user_id
    message = body.message
    _check_message(message)
    if not await to_thread.run_sync(partial(_model_available, cfg, db, body.model)):
        raise AdminApiError(404, "model_not_found", "The requested model is not available.",
                            error_type="invalid_request_error")
    try:
        turn = await to_thread.run_sync(partial(prepare_turn, db, owner, body.conversation_id, body.model,
                                                message, body.request_id, now_epoch()))
    except ChatError as exc:
        raise AdminApiError(exc.status, exc.code, exc.message, error_type="invalid_request_error",
                            headers=exc.headers) from None

    if turn.replay is not None:
        return _replay_response(turn, body.stream)

    try:
        messages = [{"role": role, "content": content} for role, content in turn.history]
        messages.append({"role": "user", "content": message})
        upstream = provider_payload(ChatCompletionRequest(model=body.model, messages=messages, stream=body.stream),
                                    body.model)
        providers = cfg.providers_for(body.model, await to_thread.run_sync(partial(provider_secret_names, db)))
    except Exception:
        await to_thread.run_sync(partial(finish_turn, db, turn, TurnResult(False, error_category="gateway_internal")))
        raise
    if not providers:
        await to_thread.run_sync(partial(finish_turn, db, turn, TurnResult(False, error_category="model_not_found")))
        raise AdminApiError(404, "model_not_found", "The requested model is not available.",
                            error_type="invalid_request_error")

    secret_source = partial(resolve_provider_api_key, db)
    resolver: Resolver = request.app.state.dns_resolver
    transport = request.app.state.http_transport
    headers = _turn_headers(turn)
    if body.stream:
        return StreamingResponse(
            _stream_turn(cfg, db, turn, providers, upstream, transport, secret_source, resolver),
            media_type="text/event-stream",
            headers={**_STREAM_HEADERS, **headers},
        )
    return await _complete_turn(cfg, db, turn, body.model, providers, upstream, transport, secret_source, resolver)


async def _complete_turn(cfg: GatewayConfig, db: Database, turn: Turn, model: str, providers: list,
                         upstream: dict[str, Any], transport: Any, secret_source: Any,
                         resolver: Resolver) -> JSONResponse:
    headers = _turn_headers(turn)
    try:
        data, provider_name, usage = await complete(providers, upstream, cfg.settings.provider_timeout_seconds,
                                                    transport, secret_source=secret_source, resolver=resolver)
    except ProviderFailure as failure:
        await to_thread.run_sync(partial(finish_turn, db, turn, TurnResult(False, error_category=failure.category)))
        return _upstream_error(failure.status_code, failure.category, headers)
    except asyncio.CancelledError:
        finish_turn(db, turn, TurnResult(False, cancelled=True))
        raise
    except Exception:
        await to_thread.run_sync(partial(finish_turn, db, turn, TurnResult(False, error_category="gateway_internal")))
        return _upstream_error(502, "gateway_internal", headers)

    content = _first_choice_content(data)
    problem = _reply_problem(content)
    if problem is not None:
        await to_thread.run_sync(partial(finish_turn, db, turn, TurnResult(False, error_category=problem)))
        return _upstream_error(502, problem, headers)
    assistant_id = await to_thread.run_sync(partial(finish_turn, db, turn,
                                                    TurnResult(True, content, provider_name, usage)))
    if assistant_id is None:
        raise AdminApiError(409, "turn_state_changed", "The reply was not stored because the turn changed.",
                            error_type="invalid_request_error", headers=headers)
    reply = {"id": assistant_id, "content": content, "model_alias": model, "usage": usage or {}}
    return JSONResponse(_completion_body(turn, reply, replayed=False), headers={**_NO_STORE, **headers})


async def _stream_turn(cfg: GatewayConfig, db: Database, turn: Turn, providers: list,
                       upstream: dict[str, Any], transport: Any, secret_source: Any,
                       resolver: Resolver) -> AsyncIterator[bytes]:
    """Forward the provider stream and record one outcome, however the stream ends."""
    outcome = StreamOutcome()
    pieces: list[str] = []
    reply_bytes = 0
    settled = False
    cancelled = False
    events = stream_completion(
        providers, upstream,
        timeout=cfg.settings.provider_timeout_seconds,
        deadline=time.monotonic() + min(600.0, cfg.settings.provider_timeout_seconds * 10),
        transport=transport, secret_source=secret_source, resolver=resolver,
        outcome=outcome, require_done=True,
    )
    try:
        async for event in events:
            if event.text:
                size = utf8_size(event.text)
                if size is None or reply_bytes + size > MAX_ASSISTANT_BYTES:
                    # Stop before forwarding more text, so memory stays within the reply limit.
                    outcome.error_category = ("provider_malformed_response" if size is None
                                              else "provider_response_too_large")
                    yield safe_error_event(outcome.error_category)
                    break
                reply_bytes += size
                pieces.append(event.text)
            yield event.data
        await to_thread.run_sync(partial(finish_turn, db, turn, _outcome_result(outcome, pieces, cancelled=False)))
        settled = True
    except (asyncio.CancelledError, GeneratorExit):
        cancelled = True
        raise
    finally:
        try:
            await events.aclose()
        finally:
            if not settled:
                # Runs synchronously: the request task may already be cancelled, and a write is short.
                finish_turn(db, turn, _outcome_result(outcome, pieces, cancelled=cancelled))


def _replay_response(turn: Turn, stream: bool) -> Any:
    """Return the stored reply for a request id that already completed. No provider call is made."""
    reply = replay_payload(turn)
    headers = _turn_headers(turn)
    if not stream:
        return JSONResponse(_completion_body(turn, reply, replayed=True), headers={**_NO_STORE, **headers})

    async def events() -> AsyncIterator[bytes]:
        chunk = {
            "id": f"chatcmpl-{reply['id']}",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": reply["model_alias"],
            "choices": [{"index": 0, "delta": {"role": "assistant", "content": reply["content"]},
                         "finish_reason": "stop"}],
        }
        yield f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n".encode("utf-8")
        yield b"data: [DONE]\n\n"

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={**_STREAM_HEADERS, **headers, "X-Replayed": "1"})
