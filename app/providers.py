from __future__ import annotations

from contextlib import asynccontextmanager
import json
from typing import Any, AsyncIterator

import httpx

from .config import ProviderConfig
from .secret_loader import SecretLoadError, resolve_secret
from .ssrf import create_safe_transport

RETRYABLE_STATUS = {429, *range(500, 600)}
MAX_ATTEMPTS = 2
MAX_PROVIDER_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_STREAM_BYTES = 10 * 1024 * 1024
MAX_ERROR_DRAIN_BYTES = 64 * 1024


async def drain_bounded_response(response: httpx.Response, max_bytes: int = MAX_ERROR_DRAIN_BYTES) -> None:
    """Drain at most max_bytes from an error response before closing it."""
    drained = 0
    try:
        async for chunk in response.aiter_bytes():
            drained += len(chunk)
            if drained >= max_bytes:
                break
    except (httpx.TransportError, httpx.DecodingError):
        return


def _resolve_transport(
    allow_private_hosts: bool,
    transport: httpx.AsyncBaseTransport | dict[bool, httpx.AsyncBaseTransport] | None,
) -> httpx.AsyncBaseTransport:
    if isinstance(transport, dict):
        resolved = transport.get(allow_private_hosts)
        if resolved is not None:
            return resolved
    elif transport is not None:
        return transport
    return create_safe_transport(allow_private_hosts=allow_private_hosts)


class SharedHttpClients:
    """Manage long-lived httpx.AsyncClient instances keyed by SSRF transport policy."""

    def __init__(self, transports: dict[bool, httpx.AsyncBaseTransport], timeout: float) -> None:
        self._transports = transports
        self._timeout = timeout
        self._clients: dict[bool, tuple[httpx.AsyncBaseTransport, httpx.AsyncClient]] = {}
        self._retired: list[httpx.AsyncClient] = []

    def ensure_initialized(self) -> None:
        for allow_private in (False, True):
            existing = self._clients.get(allow_private)
            if existing is not None and existing[1].is_closed:
                self._transports[allow_private] = create_safe_transport(allow_private_hosts=allow_private)
                self._clients.pop(allow_private, None)
            self.get_client(allow_private)

    def get_client(
        self,
        allow_private_hosts: bool,
        transport_override: httpx.AsyncBaseTransport | dict[bool, httpx.AsyncBaseTransport] | None = None,
    ) -> httpx.AsyncClient:
        transport = _resolve_transport(allow_private_hosts, transport_override or self._transports)
        entry = self._clients.get(allow_private_hosts)
        if entry is not None:
            cached_transport, cached_client = entry
            if cached_transport is transport and not cached_client.is_closed:
                return cached_client
            if not cached_client.is_closed:
                self._retired.append(cached_client)
        client = httpx.AsyncClient(
            timeout=self._timeout,
            transport=transport,
            follow_redirects=False,
        )
        self._clients[allow_private_hosts] = (transport, client)
        return client

    async def aclose(self) -> None:
        clients = [client for _transport, client in self._clients.values()]
        clients.extend(self._retired)
        self._clients.clear()
        self._retired.clear()
        for client in clients:
            if not client.is_closed:
                await client.aclose()


@asynccontextmanager
async def borrow_http_client(
    provider: ProviderConfig,
    timeout: float,
    transport: httpx.AsyncBaseTransport | dict[bool, httpx.AsyncBaseTransport] | None = None,
    clients: SharedHttpClients | None = None,
) -> AsyncIterator[httpx.AsyncClient]:
    """Borrow a shared long-lived client when available, or create a scoped one."""
    if clients is not None:
        yield clients.get_client(provider.allow_private_hosts, transport_override=transport)
        return
    provider_transport = _resolve_transport(provider.allow_private_hosts, transport)
    async with httpx.AsyncClient(
        timeout=timeout,
        transport=provider_transport,
        follow_redirects=False,
    ) as temp_client:
        yield temp_client


class ProviderFailure(Exception):
    def __init__(self, category: str, status_code: int = 502, retryable: bool = False) -> None:
        super().__init__(category)
        self.category = category
        self.status_code = status_code
        self.retryable = retryable


def _url(provider: ProviderConfig) -> str:
    return f"{provider.api_base.rstrip('/')}/chat/completions"


def _headers(provider: ProviderConfig) -> dict[str, str]:
    try:
        secret = resolve_secret(provider.api_key_env)
    except SecretLoadError:
        raise ProviderFailure("provider_secret_unavailable", 503, False) from None
    return {"Authorization": f"Bearer {secret}", "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


def _extract_usage(data: Any) -> dict[str, Any] | None:
    if isinstance(data, dict) and isinstance(data.get("usage"), dict):
        return data["usage"]
    return None


async def complete(providers: list[ProviderConfig], payload: dict[str, Any], timeout: float,
                   transport: httpx.AsyncBaseTransport | dict[bool, httpx.AsyncBaseTransport] | None = None,
                   clients: SharedHttpClients | None = None) -> tuple[dict[str, Any], str, dict[str, Any] | None]:
    last: ProviderFailure | None = None
    for index, provider in enumerate(providers[:MAX_ATTEMPTS]):
        body = dict(payload)
        body["model"] = provider.model
        try:
            body_bytes = bytearray()
            async with borrow_http_client(provider, timeout, transport=transport, clients=clients) as client:
                async with client.stream("POST", _url(provider), headers=_headers(provider), json=body, timeout=timeout) as response:
                    if response.status_code in RETRYABLE_STATUS:
                        await drain_bounded_response(response)
                        last = ProviderFailure("provider_unavailable", 502, True)
                        if index + 1 < min(len(providers), MAX_ATTEMPTS):
                            continue
                        raise last
                    if response.status_code in {401, 403}:
                        raise ProviderFailure("provider_authentication", 502, False)
                    if response.status_code < 200 or response.status_code >= 300:
                        raise ProviderFailure("provider_rejected_request", 502, False)

                    cl_hdr = response.headers.get("content-length")
                    if cl_hdr and cl_hdr.isdigit() and int(cl_hdr) > MAX_PROVIDER_RESPONSE_BYTES:
                        raise ProviderFailure("provider_response_too_large", 502, False)

                    async for chunk in response.aiter_bytes():
                        body_bytes.extend(chunk)
                        if len(body_bytes) > MAX_PROVIDER_RESPONSE_BYTES:
                            raise ProviderFailure("provider_response_too_large", 502, False)

            try:
                data = json.loads(body_bytes.decode("utf-8"))
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
                raise ProviderFailure("provider_malformed_response", 502, False) from None
            if not isinstance(data, dict) or not isinstance(data.get("choices"), list):
                raise ProviderFailure("provider_malformed_response", 502, False)
            return data, provider.name, _extract_usage(data)
        except (httpx.TransportError, httpx.DecodingError) as exc:
            status = 504 if isinstance(exc, (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError)) else 502
            last = ProviderFailure("provider_connection", status, True)
            if index + 1 < min(len(providers), MAX_ATTEMPTS):
                continue
            raise last from None
    raise last or ProviderFailure("provider_unavailable", 502, True)
