import json
import sys
from unittest.mock import patch

import pytest
from app.admin import main
from app.config import GatewayConfig, GatewaySettings


@pytest.fixture
def admin_env(tmp_path, monkeypatch):
    db_path = str(tmp_path / "admin_test.sqlite3")
    monkeypatch.setenv("GATEWAY_PEPPER", "test-pepper-that-is-at-least-32-bytes-long")
    monkeypatch.setenv("GATEWAY_DATABASE_PATH", db_path)
    settings = GatewaySettings("127.0.0.1", 8000, db_path, 3.0, 1048576, 30)
    cfg = GatewayConfig(settings, {})
    monkeypatch.setattr("app.admin.load_config", lambda: cfg)
    return db_path


def test_admin_create_key_and_list_json(admin_env, capsys):
    with patch.object(sys, "argv", ["admin", "create-key", "--name", "test-admin", "--rpm", "30"]):
        assert main() == 0
    captured = capsys.readouterr().out
    assert "client_id=" in captured
    assert "api_key=gw_" in captured
    client_id = captured.split("client_id=")[1].split("\n")[0].strip()

    # Test list-clients --json
    with patch.object(sys, "argv", ["admin", "list-clients", "--json"]):
        assert main() == 0
    json_out = capsys.readouterr().out
    data = json.loads(json_out)
    assert len(data) == 1
    assert data[0]["client_id"] == client_id
    assert data[0]["name"] == "test-admin"
    assert "key_digest" not in data[0]

    # Test revoke-key
    with patch.object(sys, "argv", ["admin", "revoke-key", client_id]):
        assert main() == 0
    revoke_out = capsys.readouterr().out
    assert "revoked" in revoke_out

    # Test usage --json
    with patch.object(sys, "argv", ["admin", "usage", client_id, "--json"]):
        assert main() == 0
    usage_out = capsys.readouterr().out
    assert json.loads(usage_out) == []
