from __future__ import annotations

import os
from pathlib import Path

import pytest

from app import secret_loader
from app.secret_loader import MAX_SECRET_BYTES, SecretLoadError, resolve_secret, secret_source_configured


def configure_file(monkeypatch, env_name: str, path: Path) -> None:
    monkeypatch.delenv(env_name, raising=False)
    monkeypatch.setenv(f"{env_name}_FILE", str(path))


def write_secret(path: Path, content: bytes, mode: int = 0o400) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(content)
    path.chmod(mode)
    return path


def test_runtime_identity_and_size_limit_are_explicit():
    assert secret_loader.RUNTIME_UID == 10001
    assert secret_loader.RUNTIME_GID == 10001
    assert MAX_SECRET_BYTES == 8192


def test_direct_environment_source_preserves_value(monkeypatch):
    monkeypatch.setenv("UNIT_SECRET", "  synthetic-secret  ")
    monkeypatch.delenv("UNIT_SECRET_FILE", raising=False)
    assert secret_source_configured("UNIT_SECRET")
    assert resolve_secret("UNIT_SECRET") == "  synthetic-secret  "


def test_file_source_is_configured_without_reading_contents(monkeypatch, secret_directory):
    path = secret_directory / "not-yet-created"
    configure_file(monkeypatch, "UNIT_SECRET", path)
    assert secret_source_configured("UNIT_SECRET")
    with pytest.raises(SecretLoadError, match="^Secret source is unavailable\\.$"):
        resolve_secret("UNIT_SECRET")


def test_no_source_and_empty_sources_fail_closed(monkeypatch):
    monkeypatch.delenv("UNIT_SECRET", raising=False)
    monkeypatch.delenv("UNIT_SECRET_FILE", raising=False)
    assert not secret_source_configured("UNIT_SECRET")
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")
    monkeypatch.setenv("UNIT_SECRET", "")
    assert not secret_source_configured("UNIT_SECRET")
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")
    monkeypatch.delenv("UNIT_SECRET", raising=False)
    monkeypatch.setenv("UNIT_SECRET_FILE", "")
    assert not secret_source_configured("UNIT_SECRET")
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")


def test_both_sources_conflict_even_when_file_would_be_valid(monkeypatch, secret_directory):
    path = write_secret(secret_directory / "secret", b"synthetic-file-secret")
    monkeypatch.setenv("UNIT_SECRET", "synthetic-direct-secret")
    monkeypatch.setenv("UNIT_SECRET_FILE", str(path))
    assert not secret_source_configured("UNIT_SECRET")
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")


def test_no_fallback_from_bad_file_to_direct_source(monkeypatch, secret_directory):
    monkeypatch.setenv("UNIT_SECRET", "synthetic-direct-secret")
    monkeypatch.setenv("UNIT_SECRET_FILE", str(secret_directory / "missing"))
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")


def test_valid_file_without_final_newline(monkeypatch, secret_directory):
    path = write_secret(secret_directory / "secret", b"synthetic-file-secret")
    configure_file(monkeypatch, "UNIT_SECRET", path)
    assert resolve_secret("UNIT_SECRET") == "synthetic-file-secret"


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"synthetic-secret\n", "synthetic-secret"),
        (b"synthetic-secret\r\n", "synthetic-secret"),
    ],
)
def test_one_terminal_lf_or_crlf_is_removed_only(content, expected, monkeypatch, secret_directory):
    path = write_secret(secret_directory / "secret", content)
    configure_file(monkeypatch, "UNIT_SECRET", path)
    assert resolve_secret("UNIT_SECRET") == expected


@pytest.mark.parametrize(
    "content",
    [b"", b"\n", b"\r\n", b"synthetic-secret\n\n", b"synthetic-secret\r\n\r\n", b"synthetic\nsecret", b"synthetic\rsecret"],
)
def test_empty_or_repeated_or_internal_line_endings_are_rejected(content, monkeypatch, secret_directory):
    path = write_secret(secret_directory / "secret", content)
    configure_file(monkeypatch, "UNIT_SECRET", path)
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")


@pytest.mark.parametrize("content", [b"synthetic\xffsecret", b"synthetic\x00secret"])
def test_invalid_utf8_and_nul_are_rejected(content, monkeypatch, secret_directory):
    path = write_secret(secret_directory / "secret", content)
    configure_file(monkeypatch, "UNIT_SECRET", path)
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")


def test_file_larger_than_8kib_is_rejected(monkeypatch, secret_directory):
    path = write_secret(secret_directory / "secret", b"x" * (MAX_SECRET_BYTES + 1))
    configure_file(monkeypatch, "UNIT_SECRET", path)
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")


def test_file_at_exactly_8kib_is_accepted(monkeypatch, secret_directory):
    content = b"x" * MAX_SECRET_BYTES
    path = write_secret(secret_directory / "secret", content)
    configure_file(monkeypatch, "UNIT_SECRET", path)
    assert resolve_secret("UNIT_SECRET") == content.decode("ascii")


def test_missing_file_directory_and_fifo_are_rejected_without_blocking(monkeypatch, secret_directory):
    missing = secret_directory / "missing"
    configure_file(monkeypatch, "UNIT_SECRET", missing)
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")

    directory = secret_directory / "directory"
    directory.mkdir(mode=0o700)
    configure_file(monkeypatch, "UNIT_SECRET", directory)
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")

    fifo = secret_directory / "fifo"
    os.mkfifo(fifo, 0o400)
    configure_file(monkeypatch, "UNIT_SECRET", fifo)
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")


def test_file_symlink_is_rejected(monkeypatch, secret_directory):
    actual = write_secret(secret_directory / "actual", b"synthetic-secret")
    link = secret_directory / "link"
    link.symlink_to(actual)
    configure_file(monkeypatch, "UNIT_SECRET", link)
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")


def test_symlink_parent_is_rejected(monkeypatch, secret_directory):
    target_directory = secret_directory / "target"
    actual = write_secret(target_directory / "secret", b"synthetic-secret")
    link_directory = secret_directory / "linked-parent"
    link_directory.symlink_to(target_directory, target_is_directory=True)
    configure_file(monkeypatch, "UNIT_SECRET", link_directory / actual.name)
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")


def test_parent_directory_must_be_protected_from_group_and_other_writes(monkeypatch, secret_directory):
    unsafe_directory = secret_directory / "unsafe"
    path = write_secret(unsafe_directory / "secret", b"synthetic-secret")
    unsafe_directory.chmod(0o777)
    configure_file(monkeypatch, "UNIT_SECRET", path)
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")


def test_directory_owner_must_be_trusted(monkeypatch, secret_directory):
    path = write_secret(secret_directory / "secret", b"synthetic-secret")
    monkeypatch.setattr(secret_loader, "SAFE_DIRECTORY_UIDS", frozenset({os.getuid() + 1}))
    configure_file(monkeypatch, "UNIT_SECRET", path)
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")


@pytest.mark.parametrize("mode", [0o000, 0o444, 0o600, 0o640, 0o644])
def test_file_permissions_must_be_private_read_only(mode, monkeypatch, secret_directory):
    path = write_secret(secret_directory / "secret", b"synthetic-secret", mode=mode)
    configure_file(monkeypatch, "UNIT_SECRET", path)
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")


def test_group_read_only_mode_is_allowed_when_runtime_group_owns_file(monkeypatch, secret_directory):
    path = write_secret(secret_directory / "secret", b"synthetic-secret", mode=0o440)
    configure_file(monkeypatch, "UNIT_SECRET", path)
    assert resolve_secret("UNIT_SECRET") == "synthetic-secret"


def test_incorrect_file_uid_or_gid_is_rejected(monkeypatch, secret_directory):
    path = write_secret(secret_directory / "secret", b"synthetic-secret")
    configure_file(monkeypatch, "UNIT_SECRET", path)
    monkeypatch.setattr(secret_loader, "RUNTIME_UID", os.getuid() + 1)
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")

    monkeypatch.setattr(secret_loader, "RUNTIME_UID", os.getuid())
    monkeypatch.setattr(secret_loader, "RUNTIME_GID", os.getgid() + 1)
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")


def test_relative_path_and_invalid_environment_name_are_rejected(monkeypatch):
    monkeypatch.setenv("UNIT_SECRET_FILE", "relative-secret-file")
    with pytest.raises(SecretLoadError):
        resolve_secret("UNIT_SECRET")
    assert secret_source_configured("UNIT_SECRET")
    with pytest.raises(SecretLoadError):
        resolve_secret("BAD=NAME")
    assert not secret_source_configured("BAD=NAME")


def test_error_text_never_contains_path_or_secret(monkeypatch, secret_directory):
    path = secret_directory / "private-path-marker"
    monkeypatch.setenv("UNIT_SECRET_FILE", str(path))
    with pytest.raises(SecretLoadError) as captured:
        resolve_secret("UNIT_SECRET")
    assert str(path) not in str(captured.value)
    assert "synthetic" not in str(captured.value)
