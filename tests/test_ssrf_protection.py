import pytest
from app.config import _validate_api_base


def test_ssrf_rejects_link_local_and_cloud_metadata():
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://169.254.169.254/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://169.254.169.254/latest", "test-provider")


def test_ssrf_rejects_loopback_and_private_ips():
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://127.0.0.1:8000/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden local domain"):
        _validate_api_base("https://localhost:8000/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden local domain"):
        _validate_api_base("https://sub.localhost:8000/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://10.0.0.1/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://172.16.0.1/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://192.168.1.1/v1", "test-provider")


def test_ssrf_rejects_plain_http_by_default():
    with pytest.raises(ValueError, match="must use HTTPS"):
        _validate_api_base("http://external-provider.com/v1", "test-provider")


def test_ssrf_rejects_userinfo_query_and_fragment():
    with pytest.raises(ValueError, match="cannot contain userinfo"):
        _validate_api_base("https://user:password@api.example.com/v1", "test-provider")
    with pytest.raises(ValueError, match="cannot contain query or fragment"):
        _validate_api_base("https://api.example.com/v1?token=leak", "test-provider")
    with pytest.raises(ValueError, match="cannot contain query or fragment"):
        _validate_api_base("https://api.example.com/v1#section", "test-provider")


def test_ssrf_rejects_ipv6_loopback_and_ula():
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://[::1]/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://[fe80::1]/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://[fc00::1]/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://[fd00::1]/v1", "test-provider")


def test_ssrf_rejects_ipv4_mapped_ipv6():
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://[::ffff:127.0.0.1]/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://[::ffff:192.168.1.1]/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://[::ffff:169.254.169.254]/v1", "test-provider")


def test_ssrf_rejects_non_standard_ip_notations():
    # Decimal integer IP notation (2130706433 == 127.0.0.1)
    with pytest.raises(ValueError, match="non-standard integer IP notation"):
        _validate_api_base("https://2130706433/v1", "test-provider")

    # Octal notation (0177.0.0.1 == 127.0.0.1)
    with pytest.raises(ValueError, match="non-standard octal/hex IP notation"):
        _validate_api_base("https://0177.0.0.1/v1", "test-provider")

    # Hex notation (0x7f000001 == 127.0.0.1)
    with pytest.raises(ValueError, match="non-standard octal/hex IP notation"):
        _validate_api_base("https://0x7f000001/v1", "test-provider")

    # Shorthand notation (127.1 == 127.0.0.1)
    with pytest.raises(ValueError, match="non-standard shorthand IP notation"):
        _validate_api_base("https://127.1/v1", "test-provider")


def test_ssrf_rejects_zone_identifiers_and_local_domains():
    with pytest.raises(ValueError, match="forbidden zone identifier"):
        _validate_api_base("https://[fe80::1%25eth0]/v1", "test-provider")

    with pytest.raises(ValueError, match="forbidden local domain"):
        _validate_api_base("https://api.internal/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden local domain"):
        _validate_api_base("https://service.local/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden local domain"):
        _validate_api_base("https://gateway.lan/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden local domain"):
        _validate_api_base("https://host.home/v1", "test-provider")


def test_valid_https_provider_is_accepted():
    assert _validate_api_base("https://api.openai.com/v1", "openai") == "https://api.openai.com/v1"
    assert _validate_api_base("https://api.anthropic.com/v1", "anthropic") == "https://api.anthropic.com/v1"
    assert _validate_api_base("https://openrouter.ai/api/v1", "openrouter") == "https://openrouter.ai/api/v1"
    assert _validate_api_base("https://primary.example/v1", "test") == "https://primary.example/v1"


def test_ssrf_rejects_shared_address_space_and_non_global_ips():
    # RFC 6598 Carrier-Grade NAT (100.64.0.0/10)
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://100.64.0.1/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://100.127.255.254/v1", "test-provider")

    # RFC 2544 Benchmarking (198.18.0.0/15)
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://198.18.0.1/v1", "test-provider")

    # RFC 5737 Documentation TEST-NETs
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://192.0.2.1/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://198.51.100.1/v1", "test-provider")
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://203.0.113.1/v1", "test-provider")

    # RFC 1112 Reserved (240.0.0.0/4)
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://240.0.0.1/v1", "test-provider")

    # RFC 3849 IPv6 Documentation (2001:db8::/32)
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://[2001:db8::1]/v1", "test-provider")

    # RFC 6666 IPv6 Discard prefix (100::/64)
    with pytest.raises(ValueError, match="forbidden IP address"):
        _validate_api_base("https://[100::1]/v1", "test-provider")

