"""Authenticated encryption for downstream credentials.

Sealed values are stored as ``nonce || AES-256-GCM ciphertext`` alongside an explicit
``key_version``. Associated data binds each ciphertext to its purpose, organization,
server, and (for per-user material) principal, so a ciphertext copied to another row
fails authentication instead of decrypting.
"""

import base64
import binascii
import os
from dataclasses import dataclass
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from coyote_mcp.settings import Settings

_NONCE_BYTES = 12
_TAG_BYTES = 16
_KEY_BYTES = 32
_AAD_PREFIX = "coyote-mcp-credential-v1"


class CredentialVaultError(RuntimeError):
    """Raised when encryption keys are missing, malformed, or cannot authenticate data."""


@dataclass(frozen=True)
class SealedValue:
    key_version: str
    sealed: bytes


def associated_data(*parts: UUID | str) -> bytes:
    return "\x1f".join((_AAD_PREFIX, *(str(part) for part in parts))).encode("utf-8")


def _key(settings: Settings, key_version: str) -> bytes:
    secret = settings.credential_encryption_keys.get(key_version)
    if secret is None:
        raise CredentialVaultError("Credential encryption key version is not configured.")
    try:
        raw = base64.urlsafe_b64decode(secret.get_secret_value())
    except (binascii.Error, ValueError) as error:
        raise CredentialVaultError("Credential encryption key is malformed.") from error
    if len(raw) != _KEY_BYTES:
        raise CredentialVaultError("Credential encryption key must decode to 32 bytes.")
    return raw


def active_key_version(settings: Settings) -> str:
    version = settings.credential_active_key_version
    if not version:
        raise CredentialVaultError("No active credential encryption key version is configured.")
    return version


def seal(settings: Settings, plaintext: bytes, aad: bytes) -> SealedValue:
    key_version = active_key_version(settings)
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(_key(settings, key_version)).encrypt(nonce, plaintext, aad)
    return SealedValue(key_version=key_version, sealed=nonce + ciphertext)


def open_sealed(settings: Settings, value: SealedValue, aad: bytes) -> bytes:
    if len(value.sealed) < _NONCE_BYTES + _TAG_BYTES:
        raise CredentialVaultError("Stored credential is malformed.")
    nonce, ciphertext = value.sealed[:_NONCE_BYTES], value.sealed[_NONCE_BYTES:]
    try:
        return AESGCM(_key(settings, value.key_version)).decrypt(nonce, ciphertext, aad)
    except InvalidTag as error:
        raise CredentialVaultError("Stored credential could not be authenticated.") from error
