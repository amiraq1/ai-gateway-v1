"""Encrypted storage for provider API keys.

Keys are stored under the same name used by api_key_env in the configuration.
A stored key replaces the env or file source for that name. A name with both
a stored key and an env or file source is refused, because the source would be ambiguous.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .audit import record_audit_event
from .clock import now_epoch
from .config import validate_provider_api_key_env
from .crypto import ALGORITHM, CryptoError, Envelope, Keyring, load_keyring, open_envelope, seal
from .database import Database
from .secret_loader import MAX_SECRET_BYTES, resolve_secret


@dataclass(frozen=True)
class ProviderSecretInfo:
    provider_name: str
    key_version: int
    created_at: int
    updated_at: int


def _context(provider_name: str) -> bytes:
    return f"amnabd.provider_secret.v1|{provider_name}".encode("utf-8")


def _encode_value(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("provider secret is empty")
    if value != value.strip() or any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in value):
        raise ValueError("provider secret contains whitespace or control characters")
    data = value.encode("utf-8")
    if len(data) > MAX_SECRET_BYTES:
        raise ValueError("provider secret is too large")
    return data


def store_provider_secret(db: Database, keyring: Keyring, provider_name: str, value: str,
                          now: int | None = None) -> int:
    """Encrypt and store one key, replacing any existing value. Returns the key version used."""
    name = validate_provider_api_key_env(provider_name)
    plaintext = _encode_value(value)
    current = now_epoch() if now is None else now
    envelope = seal(keyring, plaintext, _context(name))
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO provider_secrets(provider_name, key_version, algorithm, nonce, ciphertext, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(provider_name) DO UPDATE SET key_version = excluded.key_version, "
            "algorithm = excluded.algorithm, nonce = excluded.nonce, ciphertext = excluded.ciphertext, "
            "updated_at = excluded.updated_at",
            (name, envelope.key_version, ALGORITHM, envelope.nonce, envelope.ciphertext, current, current),
        )
        record_audit_event(conn, action="provider_secret.store", target=f"provider_secret:{name}",
                           user_agent="local-cli", metadata={"source": "cli", "key_version": envelope.key_version},
                           now=current)
    return envelope.key_version


def delete_provider_secret(db: Database, provider_name: str, now: int | None = None) -> bool:
    name = validate_provider_api_key_env(provider_name)
    current = now_epoch() if now is None else now
    with db.transaction() as conn:
        cursor = conn.execute("DELETE FROM provider_secrets WHERE provider_name = ?", (name,))
        deleted = cursor.rowcount == 1
        if deleted:
            record_audit_event(conn, action="provider_secret.delete", target=f"provider_secret:{name}",
                               user_agent="local-cli", metadata={"source": "cli"}, now=current)
    return deleted


def list_provider_secrets(db: Database) -> list[ProviderSecretInfo]:
    """Metadata only. Ciphertext and key values are never returned."""
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT provider_name, key_version, created_at, updated_at FROM provider_secrets ORDER BY provider_name"
        ).fetchall()
    return [ProviderSecretInfo(str(r["provider_name"]), int(r["key_version"]), int(r["created_at"]),
                               int(r["updated_at"])) for r in rows]


def provider_secret_names(db: Database) -> frozenset[str]:
    with db.connect() as conn:
        rows = conn.execute("SELECT provider_name FROM provider_secrets").fetchall()
    return frozenset(str(row["provider_name"]) for row in rows)


def rotate_provider_secrets(db: Database, keyring: Keyring, now: int | None = None) -> int:
    """Re-encrypt every key that is not on the current master key version. All-or-nothing."""
    current = now_epoch() if now is None else now
    rotated = 0
    with db.transaction() as conn:
        rows = conn.execute("SELECT provider_name, key_version, nonce, ciphertext FROM provider_secrets").fetchall()
        for row in rows:
            if int(row["key_version"]) == keyring.current.version:
                continue
            name = str(row["provider_name"])
            old = Envelope(int(row["key_version"]), bytes(row["nonce"]), bytes(row["ciphertext"]))
            plaintext = open_envelope(keyring, old, _context(name))
            new = seal(keyring, plaintext, _context(name))
            conn.execute(
                "UPDATE provider_secrets SET key_version = ?, nonce = ?, ciphertext = ?, updated_at = ? WHERE provider_name = ?",
                (new.key_version, new.nonce, new.ciphertext, current, name),
            )
            rotated += 1
        record_audit_event(conn, action="provider_secret.rotate", user_agent="local-cli",
                           metadata={"source": "cli", "rotated": rotated, "key_version": keyring.current.version},
                           now=current)
    return rotated


def resolve_provider_api_key(db: Database, provider_name: str) -> str:
    """Return the key for one provider at request time. Raises SecretLoadError or CryptoError if it is unavailable."""
    with db.connect() as conn:
        row = conn.execute(
            "SELECT key_version, nonce, ciphertext FROM provider_secrets WHERE provider_name = ?",
            (provider_name,),
        ).fetchone()
    if row is None:
        return resolve_secret(provider_name)
    if provider_name in os.environ or f"{provider_name}_FILE" in os.environ:
        raise CryptoError("provider key has more than one configured source")
    keyring = load_keyring()
    envelope = Envelope(int(row["key_version"]), bytes(row["nonce"]), bytes(row["ciphertext"]))
    plaintext = open_envelope(keyring, envelope, _context(provider_name))
    return plaintext.decode("utf-8")


