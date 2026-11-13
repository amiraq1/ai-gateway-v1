import os
import pytest
import httpx
from fastapi.testclient import TestClient
from pathlib import Path
from app.config import (
    GatewayConfig,
    GatewaySettings,
    ModelConfig,
    ProviderConfig,
    load_config,
    validate_provider_key_env,
)
from app.auth import digest_key
from app.database import Database
from app.main import create_app


def test_gateway_pepper_as_api_key_env_is_strictly_forbidden(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("""
settings:
  host: 127.0.0.1
models:
  test:
    enabled: true
    providers:
      - name: bad-provider
        model: test-model
        api_base: https://external.example/v1
        api_key_env: GATEWAY_PEPPER
        enabled: true
""", encoding="utf-8")
    with pytest.raises(ValueError, match="not an allowed provider key environment variable"):
        load_config(config_file)


def test_system_env_vars_forbidden_as_api_key_env(tmp_path):
    for bad_env in ["PATH", "USER", "GATEWAY_PEPPER_FILE", "HOME", "SYSTEMROOT", "WINDIR"]:
        config_file = tmp_path / f"config_{bad_env}.yaml"
        config_file.write_text(f"""
settings:
  host: 127.0.0.1
models:
  test:
    enabled: true
    providers:
      - name: bad-provider
        model: test-model
        api_base: https://external.example/v1
        api_key_env: {bad_env}
        enabled: true
""", encoding="utf-8")
        with pytest.raises(ValueError, match="not an allowed provider key environment variable"):
            load_config(config_file)


def test_unapproved_variable_with_valid_prefix_is_rejected():
    # Variables with approved prefixes but not explicitly allowlisted MUST be rejected
    unapproved_vars = [
        "OPENAI_RANDOM_UNAPPROVED_VAR",
        "OPENAI_INTERNAL_SECRET",
        "PROVIDER_CUSTOM_TOKEN",
        "ANTHROPIC_UNAPPROVED_KEY",
        "DEEPSEEK_SECRET_PEPPER",
    ]
    for var_name in unapproved_vars:
        with pytest.raises(ValueError, match="not in the approved provider key allowlist"):
            validate_provider_key_env(var_name)


def test_provider_name_to_key_binding():
    # Specific providers only allow their corresponding approved keys
    with pytest.raises(ValueError, match="not permitted for provider"):
        validate_provider_key_env("ANTHROPIC_API_KEY", provider_name="openai")

    with pytest.raises(ValueError, match="not permitted for provider"):
        validate_provider_key_env("OPENAI_API_KEY", provider_name="anthropic")

    # Correct binding passes
    assert validate_provider_key_env("OPENAI_API_KEY", provider_name="openai") == "OPENAI_API_KEY"
    assert validate_provider_key_env("ANTHROPIC_API_KEY", provider_name="anthropic") == "ANTHROPIC_API_KEY"
    assert validate_provider_key_env("OPENROUTER_API_KEY", provider_name="openrouter") == "OPENROUTER_API_KEY"


def test_file_suffix_supported_and_strictly_checked():
    # Approved key with _FILE suffix passes allowlist
    assert validate_provider_key_env("OPENAI_API_KEY_FILE", provider_name="openai") == "OPENAI_API_KEY_FILE"
    assert validate_provider_key_env("TEST_PRIMARY_KEY_FILE", provider_name="primary") == "TEST_PRIMARY_KEY_FILE"

    # Unapproved key with _FILE suffix is rejected
    with pytest.raises(ValueError, match="not in the approved provider key allowlist"):
        validate_provider_key_env("OPENAI_UNAPPROVED_FILE")

    with pytest.raises(ValueError, match="not an allowed provider key environment variable"):
        validate_provider_key_env("GATEWAY_PEPPER_FILE")


def test_mock_transport_never_called_on_unapproved_key_env(tmp_path):
    db = Database(str(tmp_path / "test.sqlite3"))
    db.init()
    pepper = "test-pepper-that-is-at-least-32-bytes-long"
    os.environ["GATEWAY_PEPPER"] = pepper
    from app.auth import create_client_key
    client_id, raw_key = create_client_key(db, pepper, "client", 100)

    transport_called = False

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal transport_called
        transport_called = True
        return httpx.Response(200, json={"choices": [{"message": {"content": "leak"}}]})

    # Set unapproved secret in environment so secret_source_configured is True
    os.environ["OPENAI_UNAPPROVED_SECRET"] = "some-secret-token"

    # Create provider with unapproved key
    provider = ProviderConfig("primary", "test-model", "https://api.example.com/v1", "OPENAI_UNAPPROVED_SECRET", True)
    settings = GatewaySettings("127.0.0.1", 8000, str(tmp_path / "test.sqlite3"), 2.0, 1048576, 30)
    cfg = GatewayConfig(settings, {"test": ModelConfig("test", True, (provider,))})
    app = create_app(cfg, db)
    app.state.http_transport = httpx.MockTransport(mock_handler)

    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {raw_key}"},
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert resp.status_code in {404, 503}
        assert not transport_called, "CRITICAL: MockTransport was called for unapproved key_env!"


def test_conflict_when_direct_and_file_sources_both_exist(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "test.sqlite3"))
    db.init()
    pepper = "test-pepper-that-is-at-least-32-bytes-long"
    os.environ["GATEWAY_PEPPER"] = pepper
    from app.auth import create_client_key
    client_id, raw_key = create_client_key(db, pepper, "client", 100)

    # Set both direct and file environment variables
    monkeypatch.setenv("TEST_PRIMARY_KEY", "direct-secret-value")
    monkeypatch.setenv("TEST_PRIMARY_KEY_FILE", "/path/to/secret")

    transport_called = False

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal transport_called
        transport_called = True
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    provider = ProviderConfig("primary", "test-model", "https://api.example.com/v1", "TEST_PRIMARY_KEY", True)
    settings = GatewaySettings("127.0.0.1", 8000, str(tmp_path / "test.sqlite3"), 2.0, 1048576, 30)
    cfg = GatewayConfig(settings, {"test": ModelConfig("test", True, (provider,))})
    app = create_app(cfg, db)
    app.state.http_transport = httpx.MockTransport(mock_handler)

    from app.secret_loader import resolve_secret, SecretLoadError
    with pytest.raises(SecretLoadError):
        resolve_secret("TEST_PRIMARY_KEY")

    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {raw_key}"},
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert resp.status_code in {404, 503}
        assert not transport_called, "MockTransport must not be called when secret sources conflict!"
