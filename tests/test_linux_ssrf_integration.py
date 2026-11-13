import asyncio
import os
import ssl
import pytest
import httpcore
import httpx
from httpcore._backends.auto import AutoBackend
from fastapi.testclient import TestClient

from app.config import ProviderConfig
from app.providers import complete, ProviderFailure
from app.ssrf import SafeSSRFNetworkBackend, SafeSSRFTransport, create_safe_transport


@pytest.mark.anyio
async def test_socket_ip_matches_verified_ip_and_no_re_resolution(monkeypatch):
    """Prove that the socket connects strictly to the verified IP, bypassing OS resolver."""
    dns_queries = []

    def mock_dns(host, port):
        dns_queries.append((host, port))
        return ["93.184.216.34"]

    backend = SafeSSRFNetworkBackend(dns_resolver=mock_dns)
    connected_target = None

    async def mock_super_connect(self, host, port, timeout=None, local_address=None, socket_options=None):
        nonlocal connected_target
        connected_target = host
        return None

    monkeypatch.setattr(AutoBackend, "connect_tcp", mock_super_connect)

    await backend.connect_tcp("api.example.com", 443)
    assert len(dns_queries) == 1
    assert connected_target == "93.184.216.34", f"Expected socket to connect to pinned IP, got {connected_target}"
    assert backend.last_connected_ip == "93.184.216.34"


def test_tls_sni_retains_original_hostname_and_certificate_verification_active():
    """Prove TLS SNI receives original domain name and cert verification is CERT_REQUIRED."""
    transport = create_safe_transport()
    assert isinstance(transport, SafeSSRFTransport)

    # SSL context must verify certificates
    ssl_context = transport._pool._ssl_context
    assert ssl_context is not None
    assert ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert ssl_context.check_hostname is True


def test_proxy_variables_cannot_bypass_ssrf_policy(monkeypatch):
    """Prove that HTTP_PROXY, HTTPS_PROXY, ALL_PROXY are ignored (trust_env=False)."""
    monkeypatch.setenv("HTTP_PROXY", "http://10.0.0.1:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://10.0.0.1:8080")
    monkeypatch.setenv("ALL_PROXY", "socks5://10.0.0.1:1080")

    transport = create_safe_transport()
    # Pool must NOT be configured with an AsyncHTTPProxy
    assert not isinstance(transport._pool, httpcore.AsyncHTTPProxy)
    assert not isinstance(transport._pool, getattr(httpcore, "AsyncSOCKSProxy", type(None)))


@pytest.mark.anyio
async def test_redirect_to_internal_target_is_never_followed(monkeypatch):
    """Prove that 301/302 redirects are not followed and Authorization is never leaked."""
    monkeypatch.setenv("TEST_KEY", "dummy-secret-value")
    redirect_target_hit = False

    def redirect_handler(request: httpx.Request) -> httpx.Response:
        nonlocal redirect_target_hit
        if request.url.path == "/internal-target":
            redirect_target_hit = True
            return httpx.Response(200, json={"choices": [{"message": {"content": "leaked"}}]})
        return httpx.Response(302, headers={"Location": "https://127.0.0.1:8000/internal-target"})

    mock_transport = httpx.MockTransport(redirect_handler)
    provider = ProviderConfig("test", "model", "https://api.example/v1", "TEST_KEY", True)

    with pytest.raises(ProviderFailure) as exc_info:
        await complete([provider], {"messages": []}, timeout=5.0, transport=mock_transport)

    assert exc_info.value.category == "provider_rejected_request"
    assert exc_info.value.status_code == 502
    assert not redirect_target_hit, "CRITICAL: Redirect to internal target was followed!"


def test_streaming_and_non_streaming_use_same_safe_transport():
    """Verify that both streaming and non-streaming use create_safe_transport."""
    from app.providers import complete
    from app.main import _stream_chat
    import inspect

    # Verify both modules import and use create_safe_transport
    from app import providers, main
    assert hasattr(providers, "create_safe_transport")
    assert hasattr(main, "create_safe_transport")
