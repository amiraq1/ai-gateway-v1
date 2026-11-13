import asyncio
import os
import pytest
import httpcore
import httpx
from fastapi.testclient import TestClient

from app.auth import create_client_key
from app.config import GatewayConfig, GatewaySettings, ModelConfig, ProviderConfig
from app.database import Database
from app.main import create_app
from app.providers import complete, ProviderFailure
from app.ssrf import SafeSSRFNetworkBackend, SafeSSRFTransport, create_safe_transport


@pytest.mark.anyio
async def test_dns_mixed_public_and_private_fails_closed():
    # DNS returns both a public IP and an internal RFC1918 IP
    backend = SafeSSRFNetworkBackend(dns_resolver=lambda h, p: ["93.184.216.34", "10.0.0.1"])
    with pytest.raises(httpcore.ConnectError, match="SSRF protection blocked target.*10.0.0.1"):
        await backend.connect_tcp("mixed.example.com", 443)


@pytest.mark.anyio
async def test_dns_loopback_rejected():
    backend = SafeSSRFNetworkBackend(dns_resolver=lambda h, p: ["127.0.0.1"])
    with pytest.raises(httpcore.ConnectError, match="SSRF protection blocked target.*127.0.0.1"):
        await backend.connect_tcp("loopback.example.com", 443)


@pytest.mark.anyio
async def test_dns_ipv6_link_local_rejected():
    backend = SafeSSRFNetworkBackend(dns_resolver=lambda h, p: ["fe80::1"])
    with pytest.raises(httpcore.ConnectError, match="SSRF protection blocked target.*fe80::1"):
        await backend.connect_tcp("linklocal-v6.example.com", 443)


@pytest.mark.anyio
async def test_dns_metadata_ip_rejected():
    backend = SafeSSRFNetworkBackend(dns_resolver=lambda h, p: ["169.254.169.254"])
    with pytest.raises(httpcore.ConnectError, match="SSRF protection blocked target.*169.254.169.254"):
        await backend.connect_tcp("metadata.example.com", 443)


@pytest.mark.anyio
async def test_dns_rebinding_pins_ip_and_blocks_subsequent_rebinding():
    query_count = 0

    def rebinding_resolver(h, p):
        nonlocal query_count
        query_count += 1
        if query_count == 1:
            return ["93.184.216.34"]
        # On second query, simulated attacker DNS rebinds to loopback
        return ["127.0.0.1"]

    backend = SafeSSRFNetworkBackend(dns_resolver=rebinding_resolver)

    # 1. First resolution succeeds and pins to 93.184.216.34
    resolved = await backend._resolve("rebind.example.com", 443)
    assert resolved == ["93.184.216.34"]

    # 2. Second resolution detects rebinding to 127.0.0.1 and fails closed
    with pytest.raises(httpcore.ConnectError, match="SSRF protection blocked target.*127.0.0.1"):
        await backend.connect_tcp("rebind.example.com", 443)


def test_trust_env_false_ignores_proxy_environment_variables(monkeypatch):
    # Set proxy variables that point to a forbidden/dummy proxy
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8888")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8888")
    monkeypatch.setenv("ALL_PROXY", "socks5://127.0.0.1:8888")

    transport = create_safe_transport()
    assert isinstance(transport, SafeSSRFTransport)

    # Pool must NOT be configured with an AsyncHTTPProxy
    assert not isinstance(transport._pool, httpcore.AsyncHTTPProxy)


@pytest.mark.anyio
async def test_redirect_to_internal_target_is_not_followed(monkeypatch):
    # Verify that follow_redirects=False prevents following 302 redirect
    monkeypatch.setenv("TEST_KEY", "dummy-secret-value")
    redirect_target_called = False

    def redirect_handler(request: httpx.Request) -> httpx.Response:
        nonlocal redirect_target_called
        if request.url.path == "/redirected":
            redirect_target_called = True
            return httpx.Response(200, json={"choices": [{"message": {"content": "leaked"}}]})
        return httpx.Response(302, headers={"Location": "https://internal.example/redirected"})

    mock_transport = httpx.MockTransport(redirect_handler)
    provider = ProviderConfig("test", "model", "https://api.example/v1", "TEST_KEY", True)

    with pytest.raises(ProviderFailure) as exc_info:
        await complete([provider], {"messages": []}, timeout=5.0, transport=mock_transport)

    assert exc_info.value.category == "provider_rejected_request"
    assert exc_info.value.status_code == 502
    assert not redirect_target_called, "Redirect must never be followed!"
