from __future__ import annotations

import json
from typing import Any

import httpx

from .config import ProviderConfig
from .secret_loader import SecretLoadError, resolve_secret

RETRYABLE_STATUS = {429, *range(500, 600)}
MAX_ATTEMPTS = 2


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
                   transport: httpx.AsyncBaseTransport | None = None) -> tuple[dict[str, Any], str, dict[str, Any] | None]:
    last: ProviderFailure | None = None
    for index, provider in enumerate(providers[:MAX_ATTEMPTS]):
        body = dict(payload)
        body["model"] = provider.model
        try:
            async with httpx.AsyncClient(timeout=timeout, transport=transport, follow_redirects=False) as client:
                response = await client.post(_url(provider), headers=_headers(provider), json=body)
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
    raise last or ProviderFailure("provider_unavailable", 502, True)
