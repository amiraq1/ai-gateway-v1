import pytest
from app.config import _validate_api_base

def test_ssrf_rejects_link_local_and_cloud_metadata():
    with pytest.raises(ValueError, match="SSRF protection"):
        _validate_api_base("https://169.254.169.254/v1", "test-provider")
    with pytest.raises(ValueError, match="SSRF protection"):
        _validate_api_base("https://169.254.169.254/latest", "test-provider")

def test_ssrf_rejects_loopback_and_private_ips():
    with pytest.raises(ValueError, match="SSRF protection"):
        _validate_api_base("https://127.0.0.1:8000/v1", "test-provider")
    with pytest.raises(ValueError, match="SSRF protection"):
        _validate_api_base("https://localhost:8000/v1", "test-provider")
    with pytest.raises(ValueError, match="SSRF protection"):
        _validate_api_base("https://10.0.0.1/v1", "test-provider")
    with pytest.raises(ValueError, match="SSRF protection"):
        _validate_api_base("https://192.168.1.1/v1", "test-provider")

def test_ssrf_rejects_plain_http_by_default():
    with pytest.raises(ValueError, match="must use HTTPS"):
        _validate_api_base("http://external-provider.com/v1", "test-provider")

def test_valid_https_provider_is_accepted():
    assert _validate_api_base("https://api.openai.com/v1", "openai") == "https://api.openai.com/v1"
    assert _validate_api_base("https://primary.example/v1", "test") == "https://primary.example/v1"
