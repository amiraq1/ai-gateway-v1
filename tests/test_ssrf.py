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
