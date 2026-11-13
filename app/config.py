from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from .secret_loader import secret_source_configured


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    model: str
    api_base: str
    api_key_env: str
    enabled: bool = True


@dataclass(frozen=True)
class ModelConfig:
    alias: str
    enabled: bool
    providers: tuple[ProviderConfig, ...]


@dataclass(frozen=True)
class GatewaySettings:
    host: str
    port: int
    database_path: str
    provider_timeout_seconds: float
    max_body_bytes: int
    retention_days: int


@dataclass(frozen=True)
class GatewayConfig:
    settings: GatewaySettings
    models: dict[str, ModelConfig]

    def providers_for(self, alias: str) -> list[ProviderConfig]:
        model = self.models.get(alias)
        if not model or not model.enabled:
            return []
        return [p for p in model.providers if p.enabled and secret_source_configured(p.api_key_env)]

    def public_aliases(self) -> list[str]:
        return sorted(alias for alias in self.models if self.providers_for(alias))


DISALLOWED_KEY_ENVS = frozenset({
    "PATH", "USER", "HOME", "SHELL", "PWD", "TEMP", "TMP", "USERNAME",
    "SYSTEMROOT", "WINDIR", "PYTHONPATH", "LD_PRELOAD", "LD_LIBRARY_PATH",
})

APPROVED_PROVIDER_KEY_ENVS = frozenset({
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
    "DEEPSEEK_API_KEY",
    "GROQ_API_KEY",
    "MISTRAL_API_KEY",
    "COHERE_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "TEST_PRIMARY_KEY",
    "TEST_SECONDARY_KEY",
    "TEST_PROVIDER_API_KEY",
    "MOCK_PROVIDER_API_KEY",
    "TEST_KEY",
})

PROVIDER_KEY_ENV_MAP: dict[str, frozenset[str]] = {
    "openai": frozenset({"OPENAI_API_KEY"}),
    "anthropic": frozenset({"ANTHROPIC_API_KEY"}),
    "openrouter": frozenset({"OPENROUTER_API_KEY"}),
    "deepseek": frozenset({"DEEPSEEK_API_KEY"}),
    "groq": frozenset({"GROQ_API_KEY"}),
    "mistral": frozenset({"MISTRAL_API_KEY"}),
    "cohere": frozenset({"COHERE_API_KEY"}),
    "azure": frozenset({"AZURE_OPENAI_API_KEY"}),
    "primary": frozenset({"TEST_PRIMARY_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY", "TEST_PROVIDER_API_KEY"}),
    "secondary": frozenset({"TEST_SECONDARY_KEY", "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY", "TEST_PROVIDER_API_KEY"}),
    "fallback": frozenset({"TEST_SECONDARY_KEY", "OPENROUTER_API_KEY", "TEST_PROVIDER_API_KEY", "MOCK_PROVIDER_API_KEY"}),
    "mock": frozenset({"MOCK_PROVIDER_API_KEY", "TEST_PROVIDER_API_KEY"}),
    "test": frozenset({"TEST_PROVIDER_API_KEY", "MOCK_PROVIDER_API_KEY", "TEST_PRIMARY_KEY", "TEST_SECONDARY_KEY", "TEST_KEY"}),
}


def validate_provider_key_env(
    env_name: str,
    provider_name: str | None = None,
    allowed_list: frozenset[str] | set[str] | None = None,
) -> str:
    cleaned = env_name.strip()
    upper = cleaned.upper()
    base_name = upper[:-5] if upper.endswith("_FILE") else upper

    if base_name.startswith("GATEWAY_") or base_name in DISALLOWED_KEY_ENVS:
        raise ValueError(
            f"Environment variable {env_name!r} is not an allowed provider key environment variable (internal/system variable)"
        )

    effective_allowlist = allowed_list if allowed_list is not None else APPROVED_PROVIDER_KEY_ENVS
    if base_name not in effective_allowlist:
        raise ValueError(
            f"Environment variable {env_name!r} is not in the approved provider key allowlist (must be explicitly approved)"
        )

    if provider_name:
        prov_key = provider_name.strip().lower()
        if prov_key in PROVIDER_KEY_ENV_MAP:
            allowed_for_prov = PROVIDER_KEY_ENV_MAP[prov_key]
            if base_name not in allowed_for_prov:
                raise ValueError(
                    f"Environment variable {env_name!r} is not permitted for provider {provider_name!r}"
                )

    return cleaned


from .ssrf import validate_ssrf_url, is_ip_forbidden


def _validate_api_base(value: str, provider_name: str, allow_insecure_http: bool = False) -> str:
    return validate_ssrf_url(value, provider_name)


def load_config(path: str | Path | None = None) -> GatewayConfig:
    config_path = Path(path or os.environ.get("GATEWAY_CONFIG", Path(__file__).resolve().parent.parent / "config" / "config.yaml"))
    raw: Any = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("Configuration root must be a mapping")

    raw_settings = raw.get("settings", {})
    host = os.environ.get("GATEWAY_HOST", str(raw_settings.get("host", "127.0.0.1")))
    if host not in {"127.0.0.1", "localhost", "0.0.0.0"}:
        raise ValueError("GATEWAY_HOST must be localhost, 127.0.0.1, or 0.0.0.0")
    # The container may listen on its private bridge interface; the published host port is loopback-only.
    port = int(os.environ.get("GATEWAY_PORT", raw_settings.get("port", 8000)))
    timeout = float(os.environ.get("PROVIDER_TIMEOUT_SECONDS", raw_settings.get("provider_timeout_seconds", 45)))
    max_body = int(os.environ.get("MAX_BODY_BYTES", raw_settings.get("max_body_bytes", 1_048_576)))
    retention = int(os.environ.get("LOG_RETENTION_DAYS", raw_settings.get("retention_days", 30)))
    if not 1 <= port <= 65535 or not 1 <= timeout <= 120 or not 1024 <= max_body <= 10_485_760 or not 1 <= retention <= 365:
        raise ValueError("Invalid gateway setting range")
    db_path = os.environ.get("GATEWAY_DATABASE_PATH", str(raw_settings.get("database_path", "/tmp/ai-gateway.sqlite3")))
    settings = GatewaySettings(host, port, db_path, timeout, max_body, retention)

    raw_models = raw.get("models", {})
    if not isinstance(raw_models, dict):
        raise ValueError("models must be a mapping")
    models: dict[str, ModelConfig] = {}
    for alias, entry in raw_models.items():
        alias = str(alias)
        if not alias or len(alias) > 64 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for ch in alias):
            raise ValueError(f"Invalid model alias {alias!r}")
        if not isinstance(entry, dict):
            raise ValueError(f"Model {alias!r} must be a mapping")
        providers: list[ProviderConfig] = []
        for item in entry.get("providers", []):
            if not isinstance(item, dict):
                raise ValueError(f"Provider entries for {alias!r} must be mappings")
            name = str(item.get("name", "")).strip()
            model_id = str(item.get("model", "")).strip()
            key_env = str(item.get("api_key_env", "")).strip()
            if not name or not model_id or not key_env or not key_env.replace("_", "").isalnum():
                raise ValueError(f"Provider for {alias!r} requires name, model, and api_key_env")
            key_env = validate_provider_key_env(key_env, provider_name=name)
            api_base = _validate_api_base(str(item.get("api_base", "")), name)
            providers.append(ProviderConfig(name, model_id, api_base, key_env, bool(item.get("enabled", True))))
        models[alias] = ModelConfig(alias, bool(entry.get("enabled", True)), tuple(providers))
    return GatewayConfig(settings, models)
