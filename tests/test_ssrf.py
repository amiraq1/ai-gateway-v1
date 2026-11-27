from __future__ import annotations

import pytest

from app.ssrf import is_ip_forbidden, validate_ssrf_url, SafeSSRFNetworkBackend
import httpcore


def test_validate_ssrf_url_accepts_valid_https():
    valid = "https://api.openai.com/v1"
    assert validate_ssrf_url(valid, "openai") == "https://api.openai.com/v1"


def test_validate_ssrf_url_rejects_http():
    with pytest.raises(ValueError, match="must use HTTPS"):
        validate_ssrf_url("http://api.openai.com/v1", "openai")


@pytest.mark.parametrize("forbidden_url", [
    "https://localhost/v1",
    "https://127.0.0.1/v1",
    "https://127.0.0.1:8000/v1",
    "https://[::1]/v1",
    "https://169.254.169.254/latest/meta-data/",
    "https://10.0.0.1/v1",
    "https://172.16.0.1/v1",
    "https://192.168.1.1/v1",
    "https://100.64.0.1/v1",
    "https://sub.localhost/v1",
    "https://internal.lan/v1",
    "https://2130706433/v1",  # 127.0.0.1 as decimal integer
    "https://0177.0.0.1/v1",   # octal leading zero
    "https://user:pass@api.openai.com/v1",
    "https://api.openai.com/v1?query=1",
    "https://api.openai.com/v1#fragment",
])
def test_validate_ssrf_url_rejects_forbidden_targets(forbidden_url):
    with pytest.raises(ValueError):
        validate_ssrf_url(forbidden_url, "test-provider")


@pytest.mark.parametrize("ip_str,expected_forbidden", [
    ("127.0.0.1", True),
    ("::1", True),
    ("169.254.169.254", True),
    ("10.10.10.10", True),
    ("172.20.0.1", True),
    ("192.168.0.100", True),
    ("100.64.1.1", True),
    ("8.8.8.8", False),
    ("1.1.1.1", False),
    ("2606:4700:4700::1111", False),
])
def test_is_ip_forbidden(ip_str, expected_forbidden):
    assert is_ip_forbidden(ip_str) is expected_forbidden


import asyncio

def test_safe_ssrf_network_backend_blocks_dns_rebinding_to_private():
    # Simulate a DNS resolver returning a private IP
    backend = SafeSSRFNetworkBackend(dns_resolver=lambda host, port: ["169.254.169.254"])
    with pytest.raises(httpcore.ConnectError, match="SSRF protection blocked target"):
        asyncio.run(backend.connect_tcp("evil-rebinding.example", 443))


def test_allow_private_hosts_permits_local_targets():
    assert validate_ssrf_url("http://127.0.0.1:11434/v1", "ollama", allow_private_hosts=True) == "http://127.0.0.1:11434/v1"
    assert validate_ssrf_url("http://localhost:8080/v1", "llama-cpp", allow_private_hosts=True) == "http://localhost:8080/v1"
    assert validate_ssrf_url("http://192.168.1.50:8000/v1", "lan-llm", allow_private_hosts=True) == "http://192.168.1.50:8000/v1"
    assert validate_ssrf_url("http://10.0.1.25:8000/v1", "internal-vllm", allow_private_hosts=True) == "http://10.0.1.25:8000/v1"


def test_allow_private_hosts_still_blocks_cloud_metadata_and_cgnat():
    with pytest.raises(ValueError):
        validate_ssrf_url("http://169.254.169.254/latest/meta-data/", "metadata", allow_private_hosts=True)
    with pytest.raises(ValueError):
        validate_ssrf_url("http://100.64.0.1/v1", "cgnat", allow_private_hosts=True)


def test_is_ip_forbidden_with_allow_private_hosts():
    assert is_ip_forbidden("127.0.0.1", allow_private_hosts=True) is False
    assert is_ip_forbidden("192.168.1.1", allow_private_hosts=True) is False
    assert is_ip_forbidden("10.0.0.1", allow_private_hosts=True) is False
    assert is_ip_forbidden("169.254.169.254", allow_private_hosts=True) is True
    assert is_ip_forbidden("100.64.1.1", allow_private_hosts=True) is True


def test_backend_with_allow_private_hosts_still_blocks_metadata():
    backend = SafeSSRFNetworkBackend(dns_resolver=lambda host, port: ["169.254.169.254"], allow_private_hosts=True)
    with pytest.raises(httpcore.ConnectError, match="SSRF protection blocked target"):
        asyncio.run(backend.connect_tcp("metadata.example", 80))


@pytest.mark.parametrize("ipv6_target", [
    "2002:a9fe:a9fe::1",                      # 6to4 embedding 169.254.169.254
    "2001:0:4136:e378:8000:63bf:5601:5601",   # Teredo client embedding 169.254.169.254
    "2001:0:a9fe:a9fe:8000:0000:f7f7:f7f7",   # Teredo server embedding 169.254.169.254
    "64:ff9b::169.254.169.254",               # NAT64 WKP embedding 169.254.169.254
    "64:ff9b:1::169.254.169.254",             # NAT64 local-use /96 embedding 169.254.169.254
    "64:ff9b:1:0:a9:fea9:fe00:0",             # NAT64 local-use /64 (RFC 6052) embedding 169.254.169.254
    "::169.254.169.254",                      # IPv4-compatible embedding 169.254.169.254
])
def test_transitional_ipv6_metadata_blocked_even_with_allow_private_hosts(ipv6_target):
    assert is_ip_forbidden(ipv6_target, allow_private_hosts=True) is True


@pytest.mark.parametrize("ipv6_private", [
    "64:ff9b::8.8.8.8",       # NAT64 well-known prefix blocked when private/tunneling disabled
    "64:ff9b::10.0.0.1",
    "2002:0a00:0001::1",      # 6to4 10.0.0.1
    "2001:0:4136:e378:8000:63bf:f5ff:fffe",  # Teredo client 10.0.0.1
])
def test_transitional_ipv6_blocked_by_default(ipv6_private):
    assert is_ip_forbidden(ipv6_private, allow_private_hosts=False) is True


@pytest.mark.parametrize("trailing_dot_url", [
    "https://localhost./v1",
    "https://api.internal./v1",
    "https://127.0.0.1./v1",
])
def test_validate_ssrf_url_normalizes_trailing_dot(trailing_dot_url):
    with pytest.raises(ValueError):
        validate_ssrf_url(trailing_dot_url, "test-provider", allow_private_hosts=False)

