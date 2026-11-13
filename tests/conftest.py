from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest

from app.config import GatewayConfig, GatewaySettings, ModelConfig, ProviderConfig
from app.database import Database
from app.main import create_app
from app import secret_loader


@pytest.fixture
def secret_directory(monkeypatch):
    """Create private test files while simulating the container's runtime identity."""
    root = Path(tempfile.mkdtemp(prefix=".secret-tests-", dir=Path(__file__).resolve().parent))
    os.chmod(root, 0o700)
    monkeypatch.setattr(secret_loader, "RUNTIME_UID", os.getuid())
    monkeypatch.setattr(secret_loader, "RUNTIME_GID", os.getgid())
    monkeypatch.setattr(secret_loader, "SAFE_DIRECTORY_UIDS", frozenset({0, os.getuid()}))
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_PEPPER", "test-pepper-that-is-at-least-32-bytes-long")
    monkeypatch.setenv("TEST_PRIMARY_API_KEY", "provider-secret-primary")
    monkeypatch.setenv("TEST_SECONDARY_API_KEY", "provider-secret-secondary")
    settings = GatewaySettings("127.0.0.1", 8000, str(tmp_path / "gateway.sqlite3"), 3.0, 1_048_576, 30)
    providers = (
        ProviderConfig("primary", "test-primary-model", "https://primary.example/v1", "TEST_PRIMARY_API_KEY", True),
        ProviderConfig("secondary", "test-secondary-model", "https://secondary.example/v1", "TEST_SECONDARY_API_KEY", True),
    )
    cfg = GatewayConfig(settings, {"fast": ModelConfig("fast", True, providers)})
    db = Database(settings.database_path)
    app = create_app(cfg, db)
    return app, db
