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
