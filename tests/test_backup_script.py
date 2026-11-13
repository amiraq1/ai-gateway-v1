from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from app.admin import main as admin_main
from app.database import Database


def test_admin_backup_creates_valid_sqlite_backup(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "gateway.sqlite3"
        backup_path = Path(tmpdir) / "backups" / "test_backup.sqlite3"

        # Initialize DB with some data
        db = Database(str(db_path))
        db.init()
        db.add_client("0123456789abcdef", "dummy_digest", "test_app", 60)

        # Setup valid config file
        config_path = Path(tmpdir) / "config.yaml"
        config_path.write_text("""
settings:
  database_path: /data/gateway.sqlite3
models:
  fast:
    enabled: true
    providers:
      - name: openrouter
        model: anthropic/claude-3.5-sonnet
        api_base: https://openrouter.ai/api/v1
        api_key_env: OPENROUTER_API_KEY
        enabled: true
""", encoding="utf-8")

        # Set environment for admin CLI
        monkeypatch.setenv("GATEWAY_CONFIG", str(config_path))
        monkeypatch.setenv("GATEWAY_DATABASE_PATH", str(db_path))
        monkeypatch.setattr("sys.argv", ["admin.py", "backup", str(backup_path)])

        # Run admin backup
        ret = admin_main()
        assert ret == 0

        # Verify backup exists and is non-empty
        assert backup_path.exists()
        assert backup_path.stat().st_size > 0

        # Verify integrity check on backup
        conn = sqlite3.connect(str(backup_path))
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            assert integrity == "ok"
            # Verify data is copied
            client = conn.execute("SELECT name FROM clients WHERE client_id='0123456789abcdef'").fetchone()
            assert client[0] == "test_app"
        finally:
            conn.close()
