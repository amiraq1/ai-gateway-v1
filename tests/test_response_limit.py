import asyncio
import os
import httpx
import pytest

from app.config import ProviderConfig
from app.providers import complete, ProviderFailure


def test_oversized_provider_response_is_rejected():
    provider = ProviderConfig("test", "model", "https://api.example/v1", "TEST_PROVIDER_API_KEY", True)
    large_body = b'{"data": "' + (b"A" * (11 * 1024 * 1024)) + b'"}'

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json", "Content-Length": str(len(large_body))},
            content=large_body,
        )

    transport = httpx.MockTransport(handler)
    os.environ["TEST_PROVIDER_API_KEY"] = "provider-key"

    with pytest.raises(ProviderFailure, match="provider_response_too_large"):
        asyncio.run(complete([provider], {"model": "test", "messages": []}, timeout=5.0, transport=transport))
