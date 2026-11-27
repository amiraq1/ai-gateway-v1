from __future__ import annotations

from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_compose_file_exists_and_binds_loopback():
    compose_path = REPO_ROOT / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml must exist"
    data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    assert "services" in data and "gateway" in data["services"]
    gw = data["services"]["gateway"]

    # Every port binding must start with 127.0.0.1:
    ports = gw.get("ports", [])
    assert len(ports) > 0, "Gateway must define ports"
    for port in ports:
        port_str = str(port)
        assert port_str.startswith("127.0.0.1:"), f"Port {port_str!r} violates loopback security requirement"

    assert "ai-gateway-v1-data" in str(gw.get("volumes", []))
    assert gw.get("read_only") is True
    assert "ALL" in gw.get("cap_drop", [])
    assert "no-new-privileges:true" in gw.get("security_opt", [])
    assert "gateway_internal" in gw.get("networks", [])


def test_operational_scripts_exist_and_have_lf_and_shebang():
    for name in ["init_env.sh", "health_check.sh", "backup.sh"]:
        p = REPO_ROOT / "scripts" / name
        assert p.exists(), f"scripts/{name} must exist"
        data = p.read_bytes()
        assert b"\r\n" not in data, f"scripts/{name} must have LF line endings, found CRLF"
        text = data.decode("utf-8")
        assert text.startswith("#!/bin/sh") or text.startswith("#!/usr/bin/env bash")


def test_compose_uses_docker_file_secrets_for_pepper():
    data = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    gw = data["services"]["gateway"]
    env_entries = [str(item) for item in gw.get("environment", [])]
    assert not any(entry.startswith("GATEWAY_PEPPER=") for entry in env_entries)
    assert "GATEWAY_PEPPER_FILE=/run/secrets/gateway_pepper" in env_entries

    service_secrets = gw.get("secrets", [])
    assert len(service_secrets) >= 1
    pepper_mount = next((s for s in service_secrets if isinstance(s, dict) and s.get("source") == "gateway_pepper"), None)
    assert pepper_mount is not None
    assert str(pepper_mount.get("uid")) == "10001"
    assert str(pepper_mount.get("gid")) == "10001"
    assert int(pepper_mount.get("mode")) == 0o400

    top_secrets = data.get("secrets", {})
    assert "gateway_pepper" in top_secrets
    assert top_secrets["gateway_pepper"].get("file") == "./secrets/gateway_pepper"


def test_dockerfile_declares_stopsignal_sigterm():
    dockerfile_text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "STOPSIGNAL SIGTERM" in dockerfile_text
