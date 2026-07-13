from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
from service_manager.crypto import (
    CryptoError,
    account_field_aad,
    account_password_aad,
    bootstrap_token_hash,
    decrypt_secret,
    encrypt_secret,
    generate_bootstrap_token,
    hash_password,
    needs_password_rehash,
    user_totp_aad,
    verify_password,
)


@pytest.fixture()
def app(tmp_path: Path):
    key = base64.b64encode(b"k" * 32).decode("ascii")
    return create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "service-manager-test.db"),
            "DATA_KEY_V1": key,
            "SECRET_KEY": "test-session-key",
        }
    )


def test_aes_gcm_round_trip_uses_unique_nonce_and_exact_aad(app):
    with app.app_context():
        aad = account_password_aad(42)
        first = encrypt_secret("known secret", aad=aad)
        second = encrypt_secret("known secret", aad=aad)

        assert first.key_version == second.key_version == 1
        assert len(first.nonce) == len(second.nonce) == 12
        assert first.nonce != second.nonce
        assert decrypt_secret(first, aad=aad) == "known secret"
        assert decrypt_secret(second, aad=aad) == "known secret"


def test_aad_helpers_bind_to_the_exact_required_resource_identifiers():
    assert account_password_aad(7) == b"account:7:password"
    assert account_field_aad(7, 9) == b"account:7:field:9"
    assert user_totp_aad(3) == b"user:3:totp"


def test_crypto_authentication_failure_has_generic_error_and_no_partial_plaintext(app):
    with app.app_context():
        value = encrypt_secret("never return this", aad=account_password_aad(1))
        with pytest.raises(CryptoError, match="unable to decrypt secret"):
            decrypt_secret(value, aad=account_password_aad(2))
        with pytest.raises(CryptoError, match="unable to decrypt secret"):
            decrypt_secret(type(value)(value.ciphertext[:-1] + b"x", value.nonce, value.key_version), aad=account_password_aad(1))
        with pytest.raises(CryptoError, match="unable to decrypt secret"):
            decrypt_secret(type(value)(value.ciphertext, b"short", value.key_version), aad=account_password_aad(1))


@pytest.mark.parametrize("key", [None, "", "not base64", base64.b64encode(b"too short").decode("ascii")])
def test_malformed_data_key_is_rejected_at_use(tmp_path: Path, key: str | None):
    app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "service-manager-test.db"),
            "DATA_KEY_V1": key,
            "SECRET_KEY": "test-session-key",
        }
    )
    with app.app_context(), pytest.raises(CryptoError, match="DATA_KEY_V1"):
        encrypt_secret("value", aad=b"test")


def test_argon2_hash_verify_and_rehash_contract(app):
    password_hash = hash_password("correct horse battery staple")

    assert verify_password(password_hash, "correct horse battery staple") is True
    assert verify_password(password_hash, "incorrect") is False
    assert needs_password_rehash(password_hash) is False
    assert needs_password_rehash("$argon2id$v=19$m=8,t=1,p=1$MTIzNDU2Nzg$MTIzNDU2Nzg") is True


def test_bootstrap_token_is_random_urlsafe_32_bytes_and_only_hash_is_persistable():
    first = generate_bootstrap_token()
    second = generate_bootstrap_token()
    digest = bootstrap_token_hash(first)

    assert first != second
    assert len(base64.urlsafe_b64decode(first + "=" * (-len(first) % 4))) == 32
    assert len(digest) == 32
    assert digest != first.encode("utf-8")
    assert digest == bootstrap_token_hash(first)
