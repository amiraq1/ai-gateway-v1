from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from .config import ProviderConfig
from .crypto import CryptoError
from .secret_loader import SecretLoadError, resolve_secret
from .ssrf import DestinationBlockedError, EgressPolicy, PinnedDestinationTransport, Resolver, system_resolver

RETRYABLE_STATUS = {429, *range(500, 600)}
MAX_ATTEMPTS = 2
SecretSource = Callable[[str], str]


class ProviderFailure(Exception):
    def __init__(self, category: str, status_code: int = 502, retryable: bool = False) -> None:
        super().__init__(category)
        self.category = category
        self.status_code = status_code
        self.retryable = retryable


@dataclass
class StreamOutcome:
    """Filled in while a stream runs. Read it after the stream ends or is cancelled."""

    provider_name: str | None = None
    final_status: int = 200
    error_category: str | None = None
    usage: dict[str, Any] | None = None
    completed: bool = False


@dataclass(frozen=True)
class StreamEvent:
    """One SSE event to forward. `text` is the content delta it carries, if any."""

    data: bytes
    text: str | None = None


def _url(provider: ProviderConfig) -> str:
    return f"{provider.api_base.rstrip('/')}/chat/completions"


def _headers(provider: ProviderConfig, secret_source: SecretSource = resolve_secret) -> dict[str, str]:
    try:
        secret = secret_source(provider.api_key_env)
    except (SecretLoadError, CryptoError):
        raise ProviderFailure("provider_secret_unavailable", 503, False) from None
    return {"Authorization": f"Bearer {secret}", "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


def _client(provider: ProviderConfig, timeout: float, transport: httpx.AsyncBaseTransport | None,
            resolver: Resolver) -> httpx.AsyncClient:
    """Injected transports (tests) are used as-is. Production connections go through the pinned destination transport."""
    if transport is None:
        transport = PinnedDestinationTransport(EgressPolicy(provider.trusted_internal_networks), resolver)
    # trust_env=False keeps environment proxies from routing around the destination checks.
    return httpx.AsyncClient(timeout=timeout, transport=transport, follow_redirects=False, trust_env=False)


def _extract_usage(data: Any) -> dict[str, Any] | None:
    if isinstance(data, dict) and isinstance(data.get("usage"), dict):
        return data["usage"]
    return None


def _provider_body(base_payload: dict[str, Any], provider: ProviderConfig) -> dict[str, Any]:
    body = dict(base_payload)
    body["model"] = provider.model
    return body


def safe_error_event(code: str) -> bytes:
    """One SSE error event with a fixed message. The provider's own error text is never forwarded."""
    data = json.dumps({"error": {"message": "The upstream stream failed.", "type": "gateway_error", "code": code}}, separators=(",", ":"))
    return f"event: error\ndata: {data}\n\n".encode("utf-8")


def _parse_sse_data(lines: list[str]) -> str | None:
    data_lines = [line[5:].lstrip(" ") for line in lines if line.startswith("data:")]
    return "\n".join(data_lines) if data_lines else None


def _delta_text(decoded: Any) -> str | None:
    """The content text carried by one chat.completion.chunk, or None."""
    if not isinstance(decoded, dict):
        return None
    choices = decoded.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None
    delta = choices[0].get("delta")
    if not isinstance(delta, dict):
        return None
    content = delta.get("content")
    return content if isinstance(content, str) and content else None


async def complete(providers: list[ProviderConfig], payload: dict[str, Any], timeout: float,
                   transport: httpx.AsyncBaseTransport | None = None, *,
                   secret_source: SecretSource = resolve_secret,
                   resolver: Resolver = system_resolver) -> tuple[dict[str, Any], str, dict[str, Any] | None]:
    last: ProviderFailure | None = None
    for index, provider in enumerate(providers[:MAX_ATTEMPTS]):
        body = dict(payload)
        body["model"] = provider.model
        try:
            async with _client(provider, timeout, transport, resolver) as client:
                response = await client.post(_url(provider), headers=_headers(provider, secret_source), json=body)
            if response.status_code in RETRYABLE_STATUS:
                last = ProviderFailure("provider_unavailable", 502, True)
                if index + 1 < min(len(providers), MAX_ATTEMPTS):
                    continue
                raise last
            if response.status_code in {401, 403}:
                raise ProviderFailure("provider_authentication", 502, False)
            if response.status_code < 200 or response.status_code >= 300:
                raise ProviderFailure("provider_rejected_request", 502, False)
            try:
                data = response.json()
            except (ValueError, json.JSONDecodeError):
                raise ProviderFailure("provider_malformed_response", 502, False) from None
            if not isinstance(data, dict) or not isinstance(data.get("choices"), list):
                raise ProviderFailure("provider_malformed_response", 502, False)
            return data, provider.name, _extract_usage(data)
        except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError):
            last = ProviderFailure("provider_connection", 504, True)
            if index + 1 < min(len(providers), MAX_ATTEMPTS):
                continue
            raise last from None
        except DestinationBlockedError:
            last = ProviderFailure("provider_destination_blocked", 502, True)
            if index + 1 < min(len(providers), MAX_ATTEMPTS):
                continue
            raise last from None
    raise last or ProviderFailure("provider_unavailable", 502, True)


async def stream_completion(providers: list[ProviderConfig], base_payload: dict[str, Any], *,
                            timeout: float, deadline: float, transport: httpx.AsyncBaseTransport | None,
                            secret_source: SecretSource, resolver: Resolver,
                            outcome: StreamOutcome, require_done: bool = False) -> AsyncIterator[StreamEvent]:
    """Stream one completion from the first provider that can serve it.

    Fallback to the next provider happens only before any event has been sent.
    Events are yielded as they arrive. `outcome` records the provider, status,
    usage, and error category. With require_done, a stream that ends without
    [DONE] is treated as an error. Otherwise the gateway writes [DONE] itself,
    as the /v1 route always has.
    """
    attempt_providers = providers[:MAX_ATTEMPTS]
    try:
        for index, provider in enumerate(attempt_providers):
            emitted = False
            event_lines: list[str] = []
            event_size = 0
            saw_done = False
            try:
                async with _client(provider, timeout, transport, resolver) as http:
                    async with http.stream("POST", _url(provider), headers=_headers(provider, secret_source),
                                           json=_provider_body(base_payload, provider)) as response:
                        if response.status_code in RETRYABLE_STATUS:
                            await response.aread()
                            if index + 1 < len(attempt_providers):
                                continue
                            outcome.error_category = "provider_unavailable"
                            outcome.final_status = 502
                            yield StreamEvent(safe_error_event(outcome.error_category))
                            return
                        if response.status_code in {401, 403}:
                            outcome.error_category = "provider_authentication"
                            outcome.final_status = 502
                            yield StreamEvent(safe_error_event(outcome.error_category))
                            return
                        if response.status_code < 200 or response.status_code >= 300:
                            outcome.error_category = "provider_rejected_request"
                            outcome.final_status = 502
                            yield StreamEvent(safe_error_event(outcome.error_category))
                            return
                        content_type = response.headers.get("content-type", "").lower()
                        if "text/event-stream" not in content_type:
                            outcome.error_category = "provider_malformed_stream"
                            outcome.final_status = 502
                            yield StreamEvent(safe_error_event(outcome.error_category))
                            return
                        async for line in response.aiter_lines():
                            if time.monotonic() > deadline:
                                raise ProviderFailure("provider_stream_timeout", 504, retryable=not emitted)
                            if line == "":
                                if event_lines:
                                    data = _parse_sse_data(event_lines)
                                    text: str | None = None
                                    if data is not None:
                                        if data == "[DONE]":
                                            yield StreamEvent(("\n".join(event_lines) + "\n\n").encode("utf-8"))
                                            emitted = True
                                            saw_done = True
                                            break
                                        try:
                                            decoded = json.loads(data)
                                            if isinstance(decoded, dict) and isinstance(decoded.get("usage"), dict):
                                                outcome.usage = decoded["usage"]
                                            text = _delta_text(decoded)
                                        except (ValueError, TypeError):
                                            pass
                                    event = ("\n".join(event_lines) + "\n\n").encode("utf-8")
                                    event_lines = []
                                    event_size = 0
                                    if event:
                                        yield StreamEvent(event, text)
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
                            if require_done:
                                raise ProviderFailure("provider_stream_incomplete", 502, False)
                            yield StreamEvent(b"data: [DONE]\n\n")
                        outcome.provider_name = provider.name
                        outcome.completed = True
                        break
            except DestinationBlockedError:
                if not emitted and index + 1 < len(attempt_providers):
                    continue
                outcome.error_category = "provider_destination_blocked"
                outcome.final_status = 502
                yield StreamEvent(safe_error_event(outcome.error_category))
                return
            except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError):
                if not emitted and index + 1 < len(attempt_providers):
                    continue
                outcome.error_category = "provider_stream_failure"
                outcome.final_status = 502
                yield StreamEvent(safe_error_event(outcome.error_category))
                return
            except ProviderFailure as failure:
                if failure.retryable and not emitted and index + 1 < len(attempt_providers):
                    continue
                outcome.error_category = failure.category
                outcome.final_status = failure.status_code
                yield StreamEvent(safe_error_event(outcome.error_category))
                return
        if not outcome.completed and outcome.error_category is None:
            outcome.error_category = "provider_unavailable"
            outcome.final_status = 502
            yield StreamEvent(safe_error_event(outcome.error_category))
    except asyncio.CancelledError:
        outcome.error_category = "client_disconnected"
        outcome.final_status = 499
        raise
