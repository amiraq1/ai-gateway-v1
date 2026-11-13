from __future__ import annotations

import os
import re
import stat
from pathlib import Path

MAX_SECRET_BYTES = 8 * 1024
RUNTIME_UID = 10001
RUNTIME_GID = 10001
SAFE_DIRECTORY_UIDS = frozenset({0, RUNTIME_UID})
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
_SECRET_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


class SecretLoadError(Exception):
    """A sanitized failure to resolve a configured secret."""

    category = "secret_unavailable"

    def __init__(self) -> None:
        super().__init__("Secret source is unavailable.")


def _valid_env_name(env_name: str) -> bool:
    return isinstance(env_name, str) and bool(_ENV_NAME.fullmatch(env_name))


def secret_source_configured(env_name: str) -> bool:
    """Return whether exactly one non-empty source is configured, without reading it."""
    if not _valid_env_name(env_name):
        return False
    file_name = f"{env_name}_FILE"
    direct_present = env_name in os.environ
    file_present = file_name in os.environ
    if direct_present == file_present:
        return False
    if direct_present:
        return bool(os.environ[env_name])
    return bool(os.environ[file_name])


def _unavailable() -> SecretLoadError:
    return SecretLoadError()


def _check_directory(fd: int) -> None:
    metadata = os.fstat(fd)
    mode = stat.S_IMODE(metadata.st_mode)
    if not stat.S_ISDIR(metadata.st_mode):
        raise _unavailable()
    if metadata.st_uid not in SAFE_DIRECTORY_UIDS:
        raise _unavailable()
    if mode & 0o022:
        raise _unavailable()


def _read_secret_file(raw_path: str) -> str:
    try:
        path = Path(raw_path)
        parts = path.parts
        if not path.is_absolute() or len(parts) < 2 or any(part in {".", ".."} for part in parts[1:]):
            raise _unavailable()

        directory_fd = os.open("/", _DIRECTORY_FLAGS)
        secret_fd: int | None = None
        try:
            _check_directory(directory_fd)
            for component in parts[1:-1]:
                next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=directory_fd)
                try:
                    _check_directory(next_fd)
                except Exception:
                    os.close(next_fd)
                    raise
                os.close(directory_fd)
                directory_fd = next_fd

            filename = parts[-1]
            if not filename:
                raise _unavailable()
            secret_fd = os.open(filename, _SECRET_FLAGS, dir_fd=directory_fd)
            metadata = os.fstat(secret_fd)
            file_mode = stat.S_IMODE(metadata.st_mode)
            if not stat.S_ISREG(metadata.st_mode):
                raise _unavailable()
            if metadata.st_uid != RUNTIME_UID or metadata.st_gid != RUNTIME_GID:
                raise _unavailable()
            if file_mode not in {0o400, 0o440}:
                raise _unavailable()
            if metadata.st_size > MAX_SECRET_BYTES:
                raise _unavailable()

            content = bytearray()
            while len(content) <= MAX_SECRET_BYTES:
                chunk = os.read(secret_fd, min(4096, MAX_SECRET_BYTES + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            if len(content) > MAX_SECRET_BYTES or not content:
                raise _unavailable()
            data = bytes(content)
        finally:
            if secret_fd is not None:
                os.close(secret_fd)
            os.close(directory_fd)
    except SecretLoadError:
        raise
    except (OSError, ValueError, TypeError, OverflowError):
        raise _unavailable() from None

    if b"\x00" in data:
        raise _unavailable()
    if data.endswith(b"\r\n"):
        data = data[:-2]
    elif data.endswith(b"\n"):
        data = data[:-1]
    if not data or b"\r" in data or b"\n" in data:
        raise _unavailable()
    try:
        secret = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise _unavailable() from None
    if not secret:
        raise _unavailable()
    return secret


def resolve_secret(env_name: str) -> str:
    """Resolve one secret from N or N_FILE; never fall back between sources."""
    if not _valid_env_name(env_name):
        raise _unavailable()
    file_name = f"{env_name}_FILE"
    direct_present = env_name in os.environ
    file_present = file_name in os.environ
    if direct_present and file_present:
        raise _unavailable()
    if direct_present:
        direct_value = os.environ[env_name]
        if not direct_value:
            raise _unavailable()
        return direct_value
    if file_present:
        raw_path = os.environ[file_name]
        if not raw_path:
            raise _unavailable()
        return _read_secret_file(raw_path)
    raise _unavailable()
