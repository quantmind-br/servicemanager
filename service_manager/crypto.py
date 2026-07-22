from __future__ import annotations

import base64
import functools
import binascii
import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app


class CryptoError(RuntimeError):
    """A safe error for failed secret encryption or authentication."""


@dataclass(frozen=True, slots=True)
class EncryptedValue:
    ciphertext: bytes
    nonce: bytes
    key_version: int


_PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


@functools.lru_cache(maxsize=4)
def _cipher_for(key_b64: str) -> AESGCM:
    try:
        key = base64.b64decode(key_b64, validate=True)
    except (ValueError, binascii.Error) as error:
        raise CryptoError("DATA_KEY_V1 is not configured correctly") from error
    if len(key) != 32:
        raise CryptoError("DATA_KEY_V1 is not configured correctly")
    return AESGCM(key)


def _cipher() -> AESGCM:
    configured_key = current_app.config.get("DATA_KEY_V1")
    if not isinstance(configured_key, str) or not configured_key:
        raise CryptoError("DATA_KEY_V1 is not configured correctly")
    return _cipher_for(configured_key)


def _require_aad(aad: bytes) -> bytes:
    if not isinstance(aad, bytes):
        raise TypeError("aad must be bytes")
    return aad


def encrypt_secret(plaintext: str, *, aad: bytes) -> EncryptedValue:
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be text")
    nonce = secrets.token_bytes(12)
    ciphertext = _cipher().encrypt(nonce, plaintext.encode("utf-8"), _require_aad(aad))
    return EncryptedValue(ciphertext=ciphertext, nonce=nonce, key_version=1)


def decrypt_secret(value: EncryptedValue, *, aad: bytes) -> str:
    try:
        if not isinstance(value, EncryptedValue) or value.key_version != 1 or len(value.nonce) != 12:
            raise ValueError("invalid encrypted value")
        plaintext = _cipher().decrypt(value.nonce, value.ciphertext, _require_aad(aad))
        return plaintext.decode("utf-8")
    except (CryptoError, InvalidTag, UnicodeDecodeError, TypeError, ValueError) as error:
        if isinstance(error, CryptoError) and str(error).startswith("DATA_KEY_V1"):
            raise
        raise CryptoError("unable to decrypt secret") from error


def account_password_aad(account_id: int) -> bytes:
    return f"account:{account_id}:password".encode("utf-8")


def account_field_aad(account_id: int, field_id: int) -> bytes:
    return f"account:{account_id}:field:{field_id}".encode("utf-8")




def hash_password(password: str) -> str:
    return _PASSWORD_HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _PASSWORD_HASHER.verify(password_hash, password)
    except (InvalidHashError, VerifyMismatchError, VerificationError):
        return False


def needs_password_rehash(password_hash: str) -> bool:
    try:
        return _PASSWORD_HASHER.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True
