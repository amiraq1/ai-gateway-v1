import pytest
from app.config import GatewayConfig, GatewaySettings, ModelConfig, ProviderConfig, load_config
import tempfile
from pathlib import Path

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
    for bad_env in ["PATH", "USER", "GATEWAY_PEPPER_FILE", "HOME"]:
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
