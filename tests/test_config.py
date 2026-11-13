from __future__ import annotations

import json

import pytest

from app.config import ProviderConfig, load_config


SAFE_PROVIDER_KEY_NAMES = [
    "OPENROUTER_API_KEY",
    "OPENAI_API_KEY",
    "PROVIDER_API_KEY",
    "ANTHROPIC_API_KEY",
]


FORBIDDEN_OR_MALFORMED_KEY_NAMES = [
    "GATEWAY_PEPPER",
    "GATEWAY_PEPPER_FILE",
    "GATEWAY_API_KEY",
    "GATEWAY_API_KEY_FILE",
    "ADMIN_API_KEY",
    "APP_API_KEY",
    "AUTH_API_KEY",
    "CLIENT_API_KEY",
    "DATABASE_API_KEY",
    "DB_API_KEY",
    "INTERNAL_API_KEY",
    "JWT_API_KEY",
    "SECRET_API_KEY",
    "SESSION_API_KEY",
    "AUTH_TOKEN",
    "JWT_SIGNING_KEY",
    "SECRET_KEY",
    "PROVIDER_API_KEY_FILE",
    "OPENAI_API_KEY_FILE",
    "TEST_PRIMARY_KEY",
    "PROVIDER_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SECRET_ACCESS_KEY_FILE",
    "provider_api_key",
    "PROVIDER-API-KEY",
]


def write_config(tmp_path, api_key_env: str):
    path = tmp_path / "synthetic-config.json"
    path.write_text(json.dumps({
        "models": {
            "fast": {
                "enabled": True,
                "providers": [{
                    "name": "synthetic-provider",
                    "model": "synthetic-model",
                    "api_base": "https://provider.example.invalid/v1",
                    "api_key_env": api_key_env,
                }],
            },
        },
    }), encoding="utf-8")
    return path


@pytest.mark.parametrize("key_env", SAFE_PROVIDER_KEY_NAMES)
def test_load_config_accepts_provider_key_name_convention(tmp_path, key_env):
    config = load_config(write_config(tmp_path, key_env))

    assert config.models["fast"].providers[0].api_key_env == key_env


@pytest.mark.parametrize("key_env", FORBIDDEN_OR_MALFORMED_KEY_NAMES)
def test_load_config_rejects_internal_or_unsafe_key_names(tmp_path, key_env):
    with pytest.raises(ValueError, match="Provider api_key_env must name a provider key") as captured:
        load_config(write_config(tmp_path, key_env))

    assert key_env not in str(captured.value)


@pytest.mark.parametrize("key_env", [
    "GATEWAY_PEPPER",
    "GATEWAY_PEPPER_FILE",
    "GATEWAY_API_KEY",
    "TEST_PRIMARY_KEY",
    "AWS_SECRET_ACCESS_KEY",
])
def test_provider_config_cannot_bypass_key_name_validation(key_env):
    with pytest.raises(ValueError, match="Provider api_key_env must name a provider key"):
        ProviderConfig(
            name="synthetic-provider",
            model="synthetic-model",
            api_base="https://provider.example.invalid/v1",
            api_key_env=key_env,
        )
