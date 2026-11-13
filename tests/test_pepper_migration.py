from __future__ import annotations

import hashlib
import hmac
import tempfile
from pathlib import Path

import pytest

EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def validate_pepper_bytes(raw_bytes: bytes | None) -> bytes:
    """Validate raw bytes extracted from process environment."""
    if raw_bytes is None:
        raise ValueError("ABORT: GATEWAY_PEPPER environment variable is missing from container")
    if len(raw_bytes) < 32:
        raise ValueError(f"ABORT: GATEWAY_PEPPER length is {len(raw_bytes)} bytes; minimum required is 32 bytes")
    if b"\n" in raw_bytes or b"\r" in raw_bytes:
        raise ValueError("ABORT: GATEWAY_PEPPER contains line break characters (CR/LF); aborting to prevent key corruption")
    return raw_bytes


def verify_pepper_migration(src_bytes: bytes, dst_bytes: bytes) -> bool:
    """Verify byte-for-byte equivalence and non-emptiness without printing secrets."""
    if len(src_bytes) < 32 or len(dst_bytes) < 32:
        return False
    if len(src_bytes) != len(dst_bytes):
        return False

    src_sha = hashlib.sha256(src_bytes).hexdigest()
    dst_sha = hashlib.sha256(dst_bytes).hexdigest()

    if src_sha == EMPTY_SHA or dst_sha == EMPTY_SHA:
        return False
    if src_sha != dst_sha:
        return False

    # Functional HMAC check on canary token
    token = b"test_canary_token_12345"
    src_hmac = hmac.new(src_bytes, token, hashlib.sha256).hexdigest()
    dst_hmac = hmac.new(dst_bytes, token, hashlib.sha256).hexdigest()

    return hmac.compare_digest(src_hmac, dst_hmac)


def test_pepper_migration_rejects_missing():
    with pytest.raises(ValueError, match="is missing"):
        validate_pepper_bytes(None)


def test_pepper_migration_rejects_too_short():
    with pytest.raises(ValueError, match="minimum required is 32 bytes"):
        validate_pepper_bytes(b"short-pepper-12345")


def test_pepper_migration_rejects_newline_characters():
    # Trailing newline
    with pytest.raises(ValueError, match="contains line break characters"):
        validate_pepper_bytes(b"a" * 32 + b"\n")

    # Trailing CRLF
    with pytest.raises(ValueError, match="contains line break characters"):
        validate_pepper_bytes(b"a" * 32 + b"\r\n")

    # Internal newline
    with pytest.raises(ValueError, match="contains line break characters"):
        validate_pepper_bytes(b"a" * 16 + b"\n" + b"b" * 16)


def test_pepper_migration_rejects_empty_sha():
    assert verify_pepper_migration(b"", b"") is False


def test_pepper_migration_rejects_mismatch():
    src = b"valid_source_pepper_at_least_32_bytes_long"
    dst = b"valid_destination_different_32_bytes_long"
    assert verify_pepper_migration(src, dst) is False


def test_pepper_migration_accepts_valid_bytes():
    valid = b"valid_source_pepper_at_least_32_bytes_long_12345"
    assert validate_pepper_bytes(valid) == valid
    assert verify_pepper_migration(valid, valid) is True
