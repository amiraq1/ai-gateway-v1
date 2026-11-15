"""AES-256-GCM sealing for provider API keys stored in SQLite.

The master key comes from GATEWAY_MASTER_KEY or GATEWAY_MASTER_KEY_FILE through
the same loader as other secrets. It is never written to the database.

Each seal uses a fresh random 96-bit nonce. The authenticated data binds the
ciphertext to its provider name and key version, so a row copied to another
provider or relabeled with another version fails verification.
"""

from __future__ import annotations

import base64
import binascii
import os
import secrets
import string
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .secret_loader import SecretLoadError, resolve_secret

ALGORITHM = "AES-256-GCM"
KEY_BYTES = 32
NONCE_BYTES = 12
MAX_KEY_VERSION = 2**31 - 1


class CryptoError(Exception):
    """Encryption or decryption is unavailable. Messages never contain key or plaintext material."""


@dataclass(frozen=True)
class MasterKey:
    version: int
    key: bytes = field(repr=False, compare=False)


@dataclass(frozen=True)
class Keyring:
    current: MasterKey
    previous: MasterKey | None = None

    def get(self, version: int) -> MasterKey:
        if version == self.current.version:
            return self.current
        if self.previous is not None and version == self.previous.version:
            return self.previous
        raise CryptoError("no master key is available for this record")


@dataclass(frozen=True)
class Envelope:
    key_version: int
    nonce: bytes
    ciphertext: bytes


def parse_master_key(text: str) -> bytes:
    """Accept a 32-byte key as 64 hex characters or as base64 or base64url. Other forms are refused."""
    candidate = text.strip()
    if len(candidate) == 2 * KEY_BYTES and all(ch in string.hexdigits for ch in candidate):
        key = bytes.fromhex(candidate)
    else:
        key = _decode_base64(candidate)
    if len(key) != KEY_BYTES:
        raise CryptoError("master key is invalid")
    return key


def _decode_base64(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    for decoder in (lambda value: base64.b64decode(value, validate=True), base64.urlsafe_b64decode):
        try:
            return decoder(padded)
        except (ValueError, binascii.Error):
            continue
    raise CryptoError("master key is invalid")


def _key_version(env_name: str, default: int | None) -> int:
    raw = os.environ.get(env_name)
    if raw is None:
        if default is None:
            raise CryptoError("master key version is missing")
        return default
    if not raw.isdigit():
        raise CryptoError("master key version is invalid")
    value = int(raw)
    if not 1 <= value <= MAX_KEY_VERSION:
        raise CryptoError("master key version is invalid")
    return value


def _resolve_key_text(env_name: str) -> str:
    try:
        return resolve_secret(env_name)
    except SecretLoadError:
        raise CryptoError("master key is unavailable") from None


def load_keyring() -> Keyring:
    """Load the current master key and, during rotation, the previous one."""
    current_key = parse_master_key(_resolve_key_text("GATEWAY_MASTER_KEY"))
    current_version = _key_version("GATEWAY_MASTER_KEY_VERSION", default=1)
    previous: MasterKey | None = None
    if "GATEWAY_MASTER_KEY_PREVIOUS" in os.environ or "GATEWAY_MASTER_KEY_PREVIOUS_FILE" in os.environ:
        previous_key = parse_master_key(_resolve_key_text("GATEWAY_MASTER_KEY_PREVIOUS"))
        previous_version = _key_version("GATEWAY_MASTER_KEY_PREVIOUS_VERSION", default=None)
        if previous_version == current_version:
            raise CryptoError("previous and current master key versions must differ")
        previous = MasterKey(previous_version, previous_key)
    return Keyring(MasterKey(current_version, current_key), previous)


def _authenticated_data(context: bytes, key_version: int) -> bytes:
    return context + b"|v" + str(key_version).encode("ascii")


def seal(keyring: Keyring, plaintext: bytes, context: bytes) -> Envelope:
    master = keyring.current
    nonce = secrets.token_bytes(NONCE_BYTES)
    ciphertext = AESGCM(master.key).encrypt(nonce, plaintext, _authenticated_data(context, master.version))
    return Envelope(master.version, nonce, ciphertext)


def open_envelope(keyring: Keyring, envelope: Envelope, context: bytes) -> bytes:
    if len(envelope.nonce) != NONCE_BYTES:
        raise CryptoError("stored secret is malformed")
    master = keyring.get(envelope.key_version)
    try:
        return AESGCM(master.key).decrypt(envelope.nonce, envelope.ciphertext,
                                          _authenticated_data(context, envelope.key_version))
    except InvalidTag:
        raise CryptoError("stored secret failed integrity verification") from None
