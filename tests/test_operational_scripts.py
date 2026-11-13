from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

def test_compose_file_exists_and_binds_loopback():
    compose_path = REPO_ROOT / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml must exist"
    data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    assert "services" in data and "gateway" in data["services"]
    gw = data["services"]["gateway"]
    assert "127.0.0.1:8000:8000" in gw.get("ports", []), "Port must bind 127.0.0.1:8000:8000"
    assert "ai-gateway-v1-data" in str(gw.get("volumes", []))

def test_operational_scripts_exist():
    for name in ["init_env.sh", "health_check.sh", "backup.sh"]:
        p = REPO_ROOT / "scripts" / name
        assert p.exists(), f"scripts/{name} must exist"
        content = p.read_text(encoding="utf-8")
        assert content.startswith("#!/bin/sh") or content.startswith("#!/usr/bin/env bash")
