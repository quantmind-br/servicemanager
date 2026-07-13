from __future__ import annotations

import base64
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from contextlib import contextmanager

import pyotp
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest
import service_manager.auth as auth_module

from app import create_app
from service_manager.crypto import (
    EncryptedValue,
    account_field_aad,
    account_password_aad,
    decrypt_secret,
    encrypt_secret,
    hash_password,
    user_totp_aad,
)
from service_manager.db import get_db


KEY = base64.b64encode(b"k" * 32).decode("ascii")
BOOTSTRAP_TOKEN = "bootstrap-token-for-testing-only"
INITIAL_PASSWORD = "initial-password-for-bootstrap"
NEW_PASSWORD = "a-new-strong-password"


@pytest.fixture()
def app(tmp_path: Path):
    return create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "auth.db"),
            "DATA_KEY_V1": KEY,
            "SECRET_KEY": "s" * 32,
            "ADMIN_EMAIL": "admin@local.invalid",
            "ADMIN_INITIAL_PASSWORD": INITIAL_PASSWORD,
            "ADMIN_BOOTSTRAP_TOKEN": BOOTSTRAP_TOKEN,
        }
    )


def test_factory_seeds_bootstrap_from_environment_and_explicit_config_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ADMIN_EMAIL", "environment@local.invalid")
    monkeypatch.setenv("ADMIN_INITIAL_PASSWORD", "environment-password")
    monkeypatch.setenv("ADMIN_BOOTSTRAP_TOKEN", "environment-bootstrap-token")

    env_app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "environment.db"),
            "DATA_KEY_V1": KEY,
            "SECRET_KEY": "s" * 32,
        }
    )
    with env_app.app_context():
        user = get_db().execute("SELECT email FROM users").fetchone()
        assert user["email"] == "environment@local.invalid"

    configured_app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "configured.db"),
            "DATA_KEY_V1": KEY,
            "SECRET_KEY": "s" * 32,
            "ADMIN_EMAIL": "configured@local.invalid",
            "ADMIN_INITIAL_PASSWORD": "configured-password",
            "ADMIN_BOOTSTRAP_TOKEN": "configured-bootstrap-token",
        }
    )
    with configured_app.app_context():
        user = get_db().execute("SELECT email FROM users").fetchone()
        assert user["email"] == "configured@local.invalid"


def test_expired_inactive_bootstrap_rotates_but_activation_closes_it(tmp_path: Path):
    database = str(tmp_path / "rotation.db")
    initial = {
        "TESTING": True,
        "DATABASE_PATH": database,
        "DATA_KEY_V1": KEY,
        "SECRET_KEY": "s" * 32,
        "ADMIN_EMAIL": "initial@local.invalid",
        "ADMIN_INITIAL_PASSWORD": INITIAL_PASSWORD,
        "ADMIN_BOOTSTRAP_TOKEN": BOOTSTRAP_TOKEN,
    }
    first_app = create_app(initial)
    with first_app.app_context():
        conn = get_db()
        conn.execute("UPDATE bootstrap_tokens SET expires_at = ?", ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(),))
        conn.commit()

    replacement_token = "replacement-bootstrap-token"
    replacement_password = "replacement-bootstrap-password"
    replacement = {
        **initial,
        "ADMIN_EMAIL": "replacement@local.invalid",
        "ADMIN_INITIAL_PASSWORD": replacement_password,
        "ADMIN_BOOTSTRAP_TOKEN": replacement_token,
    }
    rotated_app = create_app(replacement)
    rotated_client = rotated_app.test_client()
    enrollment = rotated_client.post("/bootstrap/issue-totp", data={"token": replacement_token, "initial_password": replacement_password})
    assert enrollment.status_code == 200
    secret = enrollment.get_json()["totp_secret"]
    with rotated_app.app_context():
        conn = get_db()
        assert conn.execute("SELECT email FROM users").fetchone()["email"] == "replacement@local.invalid"
        assert conn.execute("SELECT COUNT(*) FROM bootstrap_tokens WHERE consumed_at IS NULL").fetchone()[0] == 1

    activated = rotated_client.post(
        "/bootstrap",
        data={"token": replacement_token, "initial_password": replacement_password, "new_password": NEW_PASSWORD, "totp_code": pyotp.TOTP(secret).now()},
    )
    assert activated.status_code == 200

    closed_app = create_app({**replacement, "ADMIN_EMAIL": "reopened@local.invalid", "ADMIN_INITIAL_PASSWORD": "reopened-password", "ADMIN_BOOTSTRAP_TOKEN": "reopened-token"})
    assert closed_app.test_client().get("/bootstrap").status_code == 404
    with closed_app.app_context():
        assert get_db().execute("SELECT email FROM users WHERE is_active = 1").fetchone()["email"] == "replacement@local.invalid"


@pytest.fixture()
def client(app):
    return app.test_client()


def active_user(app, *, email="operator@local.invalid", password=NEW_PASSWORD, role="operador", secret=None):
    secret = secret or pyotp.random_base32()
    with app.app_context():
        conn = get_db()
        now = datetime.now(UTC).isoformat()
        user_id = conn.execute(
            "INSERT INTO users (email, password_hash, role, is_active, must_change_password, created_at, updated_at, password_changed_at) VALUES (?, ?, ?, 1, 0, ?, ?, ?)",
            (email, hash_password(password), role, now, now, now),
        ).lastrowid
        from service_manager.crypto import encrypt_secret
        envelope = encrypt_secret(secret, aad=user_totp_aad(user_id))
        conn.execute("UPDATE users SET totp_secret_ciphertext=?, totp_nonce=?, totp_key_version=1, totp_confirmed_at=? WHERE id=?", (envelope.ciphertext, envelope.nonce, now, user_id))
        conn.commit()
    return user_id, secret


def onboarding_user(app, *, email="onboarding@local.invalid", password=NEW_PASSWORD):
    with app.app_context():
        conn = get_db()
        stamp = datetime.now(UTC).isoformat()
        user_id = conn.execute(
            "INSERT INTO users (email, password_hash, role, is_active, must_change_password, created_at, updated_at, password_changed_at) VALUES (?, ?, 'operador', 1, 1, ?, ?, ?)",
            (email, hash_password(password), stamp, stamp, stamp),
        ).lastrowid
        conn.commit()
    return user_id


def login(client, email, password, secret):
    return client.post("/login", data={"email": email, "password": password, "totp_code": pyotp.TOTP(secret).now()})


def bootstrap_secret(client):
    response = client.post(
        "/bootstrap/issue-totp",
        data={"token": BOOTSTRAP_TOKEN, "initial_password": INITIAL_PASSWORD},
    )
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store, private"
    return response.get_json()["totp_secret"]


def test_bootstrap_issues_totp_only_from_post_credentials_and_only_once(app, client):
    url_credentials = client.get(
        "/bootstrap",
        query_string={"token": BOOTSTRAP_TOKEN, "initial_password": INITIAL_PASSWORD},
    )
    assert url_credentials.status_code == 200
    assert not url_credentials.is_json
    with app.app_context():
        user = get_db().execute("SELECT * FROM users WHERE role='admin'").fetchone()
        assert user["pending_totp_secret_ciphertext"] is None
        assert user["totp_enrollment_shown_at"] is None

    for credentials in ({}, {"token": BOOTSTRAP_TOKEN}, {"token": BOOTSTRAP_TOKEN, "initial_password": "wrong"}):
        response = client.post("/bootstrap/issue-totp", data=credentials)
        assert response.status_code == 400
        with app.app_context():
            user = get_db().execute("SELECT * FROM users WHERE role='admin'").fetchone()
            assert user["pending_totp_secret_ciphertext"] is None
            assert user["totp_enrollment_shown_at"] is None
            assert get_db().execute("SELECT consumed_at FROM bootstrap_tokens").fetchone()[0] is None

    secret = bootstrap_secret(client)
    assert client.post("/bootstrap/issue-totp", data={"token": BOOTSTRAP_TOKEN, "initial_password": INITIAL_PASSWORD}).status_code == 404
    response = client.post(
        "/bootstrap",
        data={"token": BOOTSTRAP_TOKEN, "initial_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD, "totp_code": pyotp.TOTP(secret).now()},
    )
    assert response.status_code == 200
    assert len(response.get_json()["recovery_codes"]) == 10
    assert response.headers["Cache-Control"] == "no-store, private"
    assert client.get("/bootstrap").status_code == 404
    with app.app_context():
        conn = get_db()
        assert conn.execute("SELECT COUNT(*) FROM users WHERE is_active = 1").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM recovery_codes").fetchone()[0] == 10
        assert conn.execute("SELECT consumed_at FROM bootstrap_tokens").fetchone()[0] is not None


def test_bootstrap_totp_issuance_is_audited_without_recording_the_secret(app, client):
    secret = bootstrap_secret(client)

    with app.app_context():
        conn = get_db()
        user = conn.execute("SELECT id FROM users WHERE role='admin'").fetchone()
        event = conn.execute(
            "SELECT actor_user_id, action, target_type, target_id, metadata_json FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert event["actor_user_id"] == user["id"]
        assert (event["action"], event["target_type"], event["target_id"]) == ("bootstrap.totp_issued", "user", str(user["id"]))
        assert secret not in event["metadata_json"]


@pytest.mark.parametrize("endpoint,payload", (
    ("/bootstrap/issue-totp", lambda: {"token": "x" * 4097, "initial_password": INITIAL_PASSWORD}),
    ("/bootstrap/issue-totp", lambda: {"token": BOOTSTRAP_TOKEN, "initial_password": "x" * 4097}),
    ("/bootstrap", lambda: {"token": "x" * 4097, "initial_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD, "totp_code": "000000"}),
    ("/bootstrap", lambda: {"token": BOOTSTRAP_TOKEN, "initial_password": "x" * 4097, "new_password": NEW_PASSWORD, "totp_code": "000000"}),
    ("/bootstrap", lambda: {"token": BOOTSTRAP_TOKEN, "initial_password": INITIAL_PASSWORD, "new_password": "x" * 4097, "totp_code": "000000"}),
    ("/bootstrap", lambda: {"token": BOOTSTRAP_TOKEN, "initial_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD, "totp_code": "x" * 4097}),
))
def test_bootstrap_rejects_oversized_secrets_before_hashing_or_mutating_state(app, client, endpoint, payload, monkeypatch):
    def hash_attempt(_: str) -> bytes:
        raise AssertionError("oversized bootstrap input reached token hashing")

    monkeypatch.setattr(auth_module, "bootstrap_token_hash", hash_attempt)
    with app.app_context():
        conn = get_db()
        before_hash = conn.execute("SELECT password_hash FROM users WHERE role='admin'").fetchone()[0]
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1

    response = client.post(endpoint, data=payload())

    assert response.status_code == 400
    assert response.get_data(as_text=True) == "Bootstrap inválido"
    with app.app_context():
        conn = get_db()
        user = conn.execute("SELECT password_hash, pending_totp_secret_ciphertext, totp_enrollment_shown_at FROM users WHERE role='admin'").fetchone()
        assert user["password_hash"] == before_hash
        assert user["pending_totp_secret_ciphertext"] is None
        assert user["totp_enrollment_shown_at"] is None
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1


def test_expired_bootstrap_token_is_not_exposed(app, client):
    with app.app_context():
        get_db().execute("UPDATE bootstrap_tokens SET expires_at = ?", ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(),))
        get_db().commit()
    assert client.get("/bootstrap").status_code == 404


def test_login_requires_totp_and_refuses_replayed_code(app, client):
    _, secret = active_user(app)
    first = login(client, "operator@local.invalid", NEW_PASSWORD, secret)
    assert first.status_code == 302
    client.post("/logout")
    replay = login(client, "operator@local.invalid", NEW_PASSWORD, secret)
    assert replay.status_code == 401


def test_login_accepts_adjacent_totp_window_once(app, client):
    _, secret = active_user(app)
    previous_code = pyotp.TOTP(secret).at(time.time() - 30)
    response = client.post("/login", data={"email": "operator@local.invalid", "password": NEW_PASSWORD, "totp_code": previous_code})
    assert response.status_code == 302


def test_failed_login_limit_is_persisted_in_shared_database(app, client):
    for _ in range(5):
        assert client.post("/login", data={"email": "missing@local.invalid", "password": "wrong", "totp_code": "000000"}).status_code == 401
    assert client.post("/login", data={"email": "missing@local.invalid", "password": "wrong", "totp_code": "000000"}).status_code == 429
    another_client = app.test_client()
    assert another_client.post("/login", data={"email": "other@local.invalid", "password": "wrong", "totp_code": "000000"}).status_code == 429


def test_session_rejects_version_change_idle_and_absolute_expiry(app, client):
    user_id, secret = active_user(app)
    assert login(client, "operator@local.invalid", NEW_PASSWORD, secret).status_code == 302
    with client.session_transaction() as session:
        assert set(session) == {"user_id", "role", "session_version", "authenticated_at", "last_seen_at", "reauthenticated_at"}
        session["last_seen_at"] = time.time() - 16 * 60
    assert client.get("/").status_code == 302
    assert login(client, "operator@local.invalid", NEW_PASSWORD, secret).status_code == 401  # replay protected
    with app.app_context():
        get_db().execute("UPDATE users SET last_totp_step = NULL, session_version = session_version + 1 WHERE id = ?", (user_id,))
        get_db().commit()
    assert login(client, "operator@local.invalid", NEW_PASSWORD, secret).status_code == 302
    with client.session_transaction() as session:
        session["authenticated_at"] = time.time() - 8 * 60 * 60 - 1
    assert client.get("/").status_code == 302


def test_operator_cannot_access_admin_or_delete_and_last_admin_stays_active(app, client):
    _, operator_secret = active_user(app)
    admin_id, admin_secret = active_user(app, email="admin2@local.invalid", role="admin")
    recovery_code = "admin-recovery-code"
    with app.app_context():
        get_db().execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", (admin_id, hash_password(recovery_code)))
        get_db().commit()
    assert login(client, "operator@local.invalid", NEW_PASSWORD, operator_secret).status_code == 302
    assert client.get("/admin/users").status_code == 403
    assert client.post(f"/admin/users/{admin_id}/active", data={"is_active": "0"}).status_code == 403
    assert client.post("/delete/1").status_code == 403
    assert client.post("/import").status_code == 403
    client.post("/logout")
    assert login(client, "admin2@local.invalid", NEW_PASSWORD, admin_secret).status_code == 302
    assert client.post("/reauth", data={"password": NEW_PASSWORD, "recovery_code": recovery_code}).status_code == 204
    assert client.post(f"/admin/users/{admin_id}/active", data={"is_active": "0"}).status_code == 400
    assert client.post(f"/admin/users/{admin_id}/role", data={"role": "operador"}).status_code == 400


def test_reauth_accepts_recovery_code_only_once_and_reveal_window_is_enforced(app, client):
    user_id, secret = active_user(app)
    from service_manager.crypto import hash_password
    code = "recovery-code"
    with app.app_context():
        get_db().execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", (user_id, hash_password(code)))
        get_db().commit()
    assert login(client, "operator@local.invalid", NEW_PASSWORD, secret).status_code == 302
    response = client.post("/reauth", data={"password": NEW_PASSWORD, "recovery_code": code})
    assert response.status_code == 204
    with client.session_transaction() as session:
        assert session["reauthenticated_at"] is not None
    assert client.post("/reauth", data={"password": NEW_PASSWORD, "recovery_code": code}).status_code == 401
    with client.session_transaction() as session:
        session["reauthenticated_at"] = time.time() - 301
    assert client.get("/", follow_redirects=False).status_code == 200
    with app.app_context():
        assert get_db().execute("SELECT used_at FROM recovery_codes WHERE user_id=?", (user_id,)).fetchone()[0] is not None


def test_temporary_user_must_change_password_and_enroll_totp_before_listing(app, client):
    _, admin_secret = active_user(app, email="creator@local.invalid", role="admin")
    admin_recovery = "admin-create-recovery"
    with app.app_context():
        admin_id = get_db().execute("SELECT id FROM users WHERE email='creator@local.invalid'").fetchone()[0]
        get_db().execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", (admin_id, hash_password(admin_recovery)))
        get_db().commit()
    assert login(client, "creator@local.invalid", NEW_PASSWORD, admin_secret).status_code == 302
    assert client.post("/reauth", data={"password": NEW_PASSWORD, "recovery_code": admin_recovery}).status_code == 204
    created = client.post("/admin/users", data={"email": "new@local.invalid", "role": "operador"})
    temporary_password = created.get_json()["temporary_password"]
    client.post("/logout")
    assert client.post("/login", data={"email": "new@local.invalid", "password": temporary_password}).status_code == 302
    assert client.get("/").status_code == 403
    assert client.post("/change-password", data={"current_password": temporary_password, "new_password": temporary_password}).status_code == 400
    assert client.post("/change-password", data={"current_password": temporary_password, "new_password": NEW_PASSWORD}).status_code == 204
    enrollment = client.post("/enroll-totp/issue")
    assert enrollment.status_code == 200
    secret = enrollment.get_json()["totp_secret"]
    confirmed = client.post("/enroll-totp", data={"totp_code": pyotp.TOTP(secret).now()})
    assert confirmed.status_code == 200
    recovery_codes = confirmed.get_json()["recovery_codes"]
    assert len(recovery_codes) == 10
    assert confirmed.headers["Cache-Control"] == "no-store, private"
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM recovery_codes WHERE user_id=(SELECT id FROM users WHERE email='new@local.invalid')").fetchone()[0] == 10
    assert client.post("/login", data={"email": "new@local.invalid", "password": NEW_PASSWORD, "totp_code": pyotp.TOTP(secret).at(time.time() + 30)}).status_code == 302


def test_only_health_login_and_bootstrap_are_anonymous(app, client):
    assert client.get("/healthz").status_code == 200
    assert client.get("/login").status_code == 200
    assert client.get("/").status_code == 302
    assert client.post("/add", data={}).status_code == 302


def seed_reveal_data(app):
    with app.app_context():
        conn = get_db()
        first_service = conn.execute("INSERT INTO services (name) VALUES ('First')").lastrowid
        second_service = conn.execute("INSERT INTO services (name) VALUES ('Second')").lastrowid
        first_account = conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
            ("first@example.test", b"", b"0" * 12),
        ).lastrowid
        second_account = conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
            ("second@example.test", b"", b"0" * 12),
        ).lastrowid
        for account_id, password in ((first_account, "first-password"), (second_account, "second-password")):
            envelope = encrypt_secret(password, aad=account_password_aad(account_id))
            conn.execute(
                "UPDATE accounts SET password_ciphertext=?, password_nonce=?, password_key_version=? WHERE id=?",
                (envelope.ciphertext, envelope.nonce, envelope.key_version, account_id),
            )
        conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (first_account, first_service))
        conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (second_account, second_service))
        first_field = conn.execute("INSERT INTO custom_fields (service_id, name) VALUES (?, 'First token')", (first_service,)).lastrowid
        second_field = conn.execute("INSERT INTO custom_fields (service_id, name) VALUES (?, 'Second token')", (second_service,)).lastrowid
        for account_id, field_id, value in ((first_account, first_field, "first-token"), (second_account, second_field, "second-token")):
            envelope = encrypt_secret(value, aad=account_field_aad(account_id, field_id))
            conn.execute(
                "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, ?)",
                (field_id, account_id, envelope.ciphertext, envelope.nonce, envelope.key_version),
            )
        conn.commit()
    return first_service, second_service, first_account, second_account, first_field, second_field


def test_session_cookie_is_secure_lax_host_only_and_rejects_future_timestamps(app, client):
    _, secret = active_user(app)
    response = login(client, "operator@local.invalid", NEW_PASSWORD, secret)
    cookie = response.headers["Set-Cookie"]
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    assert "Domain=" not in cookie
    with client.session_transaction() as session:
        session["authenticated_at"] = time.time() + 61
        session["last_seen_at"] = time.time() + 61
    assert client.get("/").status_code == 302


def test_login_rate_limit_uses_configured_trusted_proxy_client_ip(tmp_path: Path):
    proxy_app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "proxy.db"),
            "DATA_KEY_V1": KEY,
            "SECRET_KEY": "s" * 32,
            "TRUSTED_PROXY_HOPS": 1,
        }
    )
    proxy_client = proxy_app.test_client()
    assert proxy_client.post(
        "/login",
        data={"email": "missing@local.invalid", "password": "wrong", "totp_code": "000000"},
        headers={"X-Forwarded-For": "198.51.100.20"},
    ).status_code == 401
    with proxy_app.app_context():
        assert get_db().execute("SELECT source_ip FROM security_events").fetchone()[0] == "198.51.100.20"


@pytest.mark.parametrize("value", ("-1", "invalid", "1.5", True))
def test_factory_rejects_invalid_trusted_proxy_hops_from_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value):
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", str(value))
    with pytest.raises(RuntimeError, match="TRUSTED_PROXY_HOPS"):
        create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "proxy-invalid.db"), "DATA_KEY_V1": KEY, "SECRET_KEY": "s" * 32})


def test_factory_loads_validated_trusted_proxy_hops_from_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "2")
    proxy_app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "proxy-env.db"), "DATA_KEY_V1": KEY, "SECRET_KEY": "s" * 32})
    assert proxy_app.config["TRUSTED_PROXY_HOPS"] == 2


def test_change_password_rechecks_the_current_hash_inside_its_write_transaction(app, client, monkeypatch: pytest.MonkeyPatch):
    user_id, secret = active_user(app)
    assert login(client, "operator@local.invalid", NEW_PASSWORD, secret).status_code == 302
    from service_manager import auth as auth_module

    real_transaction = auth_module.transaction

    def stale_before_lock(conn):
        with app.app_context():
            other = get_db()
            other.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password("concurrent-password"), user_id))
            other.commit()
        return real_transaction(conn)

    monkeypatch.setattr(auth_module, "transaction", stale_before_lock)
    assert client.post("/change-password", data={"current_password": NEW_PASSWORD, "new_password": "an-even-stronger-password"}).status_code == 400
    with app.app_context():
        assert auth_module.verify_password(get_db().execute("SELECT password_hash FROM users WHERE id=?", (user_id,)).fetchone()[0], "concurrent-password")


def test_enrollment_rejects_established_user_mfa_replacement(app, client):
    user_id, existing_secret = active_user(app)
    assert login(client, "operator@local.invalid", NEW_PASSWORD, existing_secret).status_code == 302
    attacker_secret = pyotp.random_base32()
    assert client.post("/enroll-totp", data={"totp_secret": attacker_secret, "totp_code": pyotp.TOTP(attacker_secret).now()}).status_code == 403
    with app.app_context():
        user = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        assert decrypt_secret(
            EncryptedValue(user["totp_secret_ciphertext"], user["totp_nonce"], user["totp_key_version"]),
            aad=user_totp_aad(user_id),
        ) == existing_secret


def test_pending_enrollment_secret_is_server_issued_and_can_only_be_shown_once(app, client):
    _, admin_secret = active_user(app, email="creator@local.invalid", role="admin")
    recovery_code = "create-user-recovery"
    with app.app_context():
        admin_id = get_db().execute("SELECT id FROM users WHERE email=?", ("creator@local.invalid",)).fetchone()[0]
        get_db().execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", (admin_id, hash_password(recovery_code)))
        get_db().commit()
    assert login(client, "creator@local.invalid", NEW_PASSWORD, admin_secret).status_code == 302
    assert client.post("/reauth", data={"password": NEW_PASSWORD, "recovery_code": recovery_code}).status_code == 204
    created = client.post("/admin/users", data={"email": "new@local.invalid", "role": "operador"})
    temporary_password = created.get_json()["temporary_password"]
    client.post("/logout")
    assert client.post("/login", data={"email": "new@local.invalid", "password": temporary_password}).status_code == 302
    assert client.post("/change-password", data={"current_password": temporary_password, "new_password": NEW_PASSWORD}).status_code == 204
    enrollment = client.post("/enroll-totp/issue")
    assert enrollment.status_code == 200
    issued_secret = enrollment.get_json()["totp_secret"]
    assert enrollment.headers["Cache-Control"] == "no-store, private"
    assert client.post("/enroll-totp/issue").status_code == 404
    attacker_secret = pyotp.random_base32()
    assert client.post("/enroll-totp", data={"totp_secret": attacker_secret, "totp_code": pyotp.TOTP(attacker_secret).now()}).status_code == 400
    confirmed = client.post("/enroll-totp", data={"totp_code": pyotp.TOTP(issued_secret).now()})
    assert confirmed.status_code == 200
    assert len(confirmed.get_json()["recovery_codes"]) == 10



def test_enrollment_get_is_read_only_and_issue_requires_post(app, client):
    onboarding_user(app)
    assert client.post("/login", data={"email": "onboarding@local.invalid", "password": NEW_PASSWORD}).status_code == 302
    assert client.get("/enroll-totp").status_code == 200
    with app.app_context():
        user = get_db().execute("SELECT pending_totp_secret_ciphertext, totp_enrollment_shown_at FROM users WHERE email='onboarding@local.invalid'").fetchone()
        assert user["pending_totp_secret_ciphertext"] is None
        assert user["totp_enrollment_shown_at"] is None
    issued = client.post("/enroll-totp/issue")
    assert issued.status_code == 200
    assert client.post("/enroll-totp/issue").status_code == 404

def test_enrollment_post_does_not_restore_mfa_reset_before_its_writer_lock(app, client, monkeypatch: pytest.MonkeyPatch):
    user_id = onboarding_user(app)
    assert client.post("/login", data={"email": "onboarding@local.invalid", "password": NEW_PASSWORD}).status_code == 302
    issued_secret = client.post("/enroll-totp/issue").get_json()["totp_secret"]
    from service_manager import auth as auth_module
    from service_manager.db import transaction as db_transaction

    real_transaction = auth_module.transaction

    def reset_runs_before_lock(conn):
        with app.app_context():
            other = get_db()
            with db_transaction(other):
                other.execute(
                    "UPDATE users SET totp_secret_ciphertext=NULL, totp_nonce=NULL, totp_key_version=NULL, totp_confirmed_at=NULL, last_totp_step=NULL, pending_totp_secret_ciphertext=NULL, pending_totp_nonce=NULL, pending_totp_key_version=NULL, totp_enrollment_shown_at=NULL, must_change_password=1, session_version=session_version+1, updated_at=? WHERE id=?",
                    (datetime.now(UTC).isoformat(), user_id),
                )
        return real_transaction(conn)

    monkeypatch.setattr(auth_module, "transaction", reset_runs_before_lock)

    assert client.post("/enroll-totp", data={"totp_code": pyotp.TOTP(issued_secret).now()}).status_code == 400
    with app.app_context():
        user = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        assert user["totp_secret_ciphertext"] is None
        assert user["pending_totp_secret_ciphertext"] is None
        assert user["must_change_password"] == 1

def test_bootstrap_stays_closed_after_any_admin_was_activated(app, client):
    secret = bootstrap_secret(client)
    assert client.post(
        "/bootstrap",
        data={"token": BOOTSTRAP_TOKEN, "initial_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD, "totp_code": pyotp.TOTP(secret).now()},
    ).status_code == 200
    with app.app_context():
        conn = get_db()
        conn.execute("UPDATE users SET is_active=0 WHERE role='admin'")
        conn.commit()
    assert client.get("/bootstrap").status_code == 404


def test_creating_users_requires_fresh_reauthentication(app, client):
    _, secret = active_user(app, email="admin2@local.invalid", role="admin")
    assert login(client, "admin2@local.invalid", NEW_PASSWORD, secret).status_code == 302
    assert client.post("/admin/users", data={"email": "new@local.invalid", "role": "operador"}).status_code == 403
    with client.session_transaction() as session:
        session["reauthenticated_at"] = time.time() - 301
    assert client.post("/admin/users", data={"email": "newer@local.invalid", "role": "operador"}).status_code == 403


def test_reveal_requires_reauth_and_complete_service_field_account_relationships(app, client):
    user_id, secret = active_user(app, role="admin")
    first_service, _, first_account, second_account, first_field, second_field = seed_reveal_data(app)
    recovery_code = "reveal-recovery"
    with app.app_context():
        get_db().execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", (user_id, hash_password(recovery_code)))
        get_db().commit()
    assert login(client, "operator@local.invalid", NEW_PASSWORD, secret).status_code == 302
    assert client.post(f"/api/accounts/{first_account}/secrets/password/reveal").status_code == 403
    assert client.post("/reauth", data={"password": NEW_PASSWORD, "recovery_code": recovery_code}).status_code == 204
    assert client.post(f"/api/accounts/{first_account}/secrets/password/reveal").get_json()["value"] == "first-password"
    assert client.post(f"/api/accounts/{first_account}/fields/{first_field}/reveal").get_json()["value"] == "first-token"
    assert client.post(f"/api/accounts/{first_account}/fields/{second_field}/reveal").status_code == 404
    assert client.get("/?service=999999").status_code == 404
    assert client.post(f"/update/{second_account}", data={"service": first_service, "email": "wrong@example.test"}).status_code == 404
    assert client.post(f"/field/update/{second_field}/{first_account}", data={"service": first_service, "value": "wrong"}).status_code == 404
    assert client.post(f"/field/delete/{second_field}/{first_account}", data={"service": first_service}).status_code == 404


def test_reveal_limit_is_shared_across_secret_endpoints(app, client):
    user_id, secret = active_user(app)
    _, _, account_id, _, field_id, _ = seed_reveal_data(app)
    recovery_code = "reveal-limit-recovery"
    with app.app_context():
        conn = get_db()
        conn.execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", (user_id, hash_password(recovery_code)))
        conn.commit()
    assert login(client, "operator@local.invalid", NEW_PASSWORD, secret).status_code == 302
    assert client.post("/reauth", data={"password": NEW_PASSWORD, "recovery_code": recovery_code}).status_code == 204

    for _ in range(10):
        assert client.post(f"/api/accounts/{account_id}/secrets/password/reveal").status_code == 200
        assert client.post(f"/api/accounts/{account_id}/fields/{field_id}/reveal").status_code == 200
    assert client.post(f"/api/accounts/{account_id}/secrets/password/reveal").status_code == 429
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM security_events WHERE kind='reveal' AND subject=?", (str(user_id),)).fetchone()[0] == 20



def test_future_reauthentication_timestamp_cannot_authorize_reveal(app, client):
    _, secret = active_user(app)
    _, _, account_id, _, _, _ = seed_reveal_data(app)
    assert login(client, "operator@local.invalid", NEW_PASSWORD, secret).status_code == 302
    with client.session_transaction() as session:
        session["reauthenticated_at"] = time.time() + 61
    assert client.post(f"/api/accounts/{account_id}/secrets/password/reveal").status_code == 403


def test_invalid_service_and_cross_service_account_deletion_return_404(app, client):
    user_id, secret = active_user(app, role="admin")
    first_service, _, _, second_account, _, _ = seed_reveal_data(app)
    recovery_code = "delete-recovery"
    with app.app_context():
        get_db().execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", (user_id, hash_password(recovery_code)))
        get_db().commit()
    assert login(client, "operator@local.invalid", NEW_PASSWORD, secret).status_code == 302
    assert client.post("/reauth", data={"password": NEW_PASSWORD, "recovery_code": recovery_code}).status_code == 204
    assert client.post("/service/delete/999999").status_code == 404
    assert client.post(f"/delete/{second_account}", data={"service": first_service}).status_code == 404
def test_bootstrap_confirms_only_the_server_issued_pending_totp_secret(app, client):
    issued_secret = bootstrap_secret(client)
    attacker_secret = pyotp.random_base32()

    rejected = client.post(
        "/bootstrap",
        data={
            "token": BOOTSTRAP_TOKEN,
            "initial_password": INITIAL_PASSWORD,
            "new_password": NEW_PASSWORD,
            "totp_secret": attacker_secret,
            "totp_code": pyotp.TOTP(attacker_secret).now(),
        },
    )

    assert rejected.status_code == 400
    accepted = client.post(
        "/bootstrap",
        data={
            "token": BOOTSTRAP_TOKEN,
            "initial_password": INITIAL_PASSWORD,
            "new_password": NEW_PASSWORD,
            "totp_code": pyotp.TOTP(issued_secret).now(),
        },
    )
    assert accepted.status_code == 200


def test_mfa_reset_revokes_obsolete_recovery_codes(app, client):
    admin_id, admin_secret = active_user(app, email="admin-recovery-reset@local.invalid", role="admin")
    target_id, _ = active_user(app, email="target-recovery-reset@local.invalid")
    admin_recovery = "admin-recovery-reset-code"
    with app.app_context():
        conn = get_db()
        conn.executemany(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
            ((admin_id, hash_password(admin_recovery)), (target_id, hash_password("obsolete-target-code"))),
        )
        conn.commit()
    assert login(client, "admin-recovery-reset@local.invalid", NEW_PASSWORD, admin_secret).status_code == 302
    assert client.post("/reauth", data={"password": NEW_PASSWORD, "recovery_code": admin_recovery}).status_code == 204
    assert client.post(f"/admin/users/{target_id}/reset-mfa").status_code == 204
    client.post("/logout")
    assert client.post("/login", data={"email": "target-recovery-reset@local.invalid", "password": NEW_PASSWORD}).status_code == 302
    assert client.post(
        "/change-password",
        data={"current_password": NEW_PASSWORD, "new_password": "target-reset-updated-password"},
    ).status_code == 204
    enrollment = client.post("/enroll-totp/issue")
    secret = enrollment.get_json()["totp_secret"]
    rotated = client.post("/enroll-totp", data={"totp_code": pyotp.TOTP(secret).now()})
    assert rotated.status_code == 200
    assert len(rotated.get_json()["recovery_codes"]) == 10
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM recovery_codes WHERE user_id=?", (target_id,)).fetchone()[0] == 10

def test_reset_mfa_clears_prior_pending_enrollment_state(app, client):
    admin_id, admin_secret = active_user(app, email="admin-reset@local.invalid", role="admin")
    target_id, _ = active_user(app, email="target-reset@local.invalid")
    recovery_code = "reset-mfa-recovery"
    with app.app_context():
        conn = get_db()
        envelope = encrypt_secret(pyotp.random_base32(), aad=user_totp_aad(target_id))
        conn.execute(
            "UPDATE users SET pending_totp_secret_ciphertext=?, pending_totp_nonce=?, pending_totp_key_version=?, totp_enrollment_shown_at=? WHERE id=?",
            (envelope.ciphertext, envelope.nonce, envelope.key_version, datetime.now(UTC).isoformat(), target_id),
        )
        conn.execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", (admin_id, hash_password(recovery_code)))
        conn.commit()

    assert login(client, "admin-reset@local.invalid", NEW_PASSWORD, admin_secret).status_code == 302
    assert client.post("/reauth", data={"password": NEW_PASSWORD, "recovery_code": recovery_code}).status_code == 204
    assert client.post(f"/admin/users/{target_id}/reset-mfa").status_code == 204
    client.post("/logout")
    target_password_login = client.post("/login", data={"email": "target-reset@local.invalid", "password": NEW_PASSWORD})
    assert target_password_login.status_code == 302
    enrollment = client.post("/enroll-totp/issue")
    assert enrollment.status_code == 200
    with app.app_context():
        target = get_db().execute("SELECT * FROM users WHERE id=?", (target_id,)).fetchone()
        assert target["totp_enrollment_shown_at"] is not None

def test_field_add_rejects_cross_service_account_without_mutation(app, client):
    _, admin_secret = active_user(app, role="admin")
    first_service, _, first_account, second_account, _, _ = seed_reveal_data(app)

    assert login(client, "operator@local.invalid", NEW_PASSWORD, admin_secret).status_code == 302
    response = client.post(
        "/field/add",
        data={"service": first_service, "name": "Cross service", "value": "not-written", "account_ids": [first_account, second_account]},
    )

    assert response.status_code == 404
    with app.app_context():
        conn = get_db()
        assert conn.execute("SELECT COUNT(*) FROM custom_fields WHERE service_id=? AND name=?", (first_service, "Cross service")).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM field_values WHERE account_id=?", (second_account,)).fetchone()[0] == 1

def test_confirmed_mfa_user_remains_usable_after_password_change(app, client):
    user_id, secret = active_user(app)

    assert login(client, "operator@local.invalid", NEW_PASSWORD, secret).status_code == 302
    assert client.post("/change-password", data={"current_password": NEW_PASSWORD, "new_password": "an-even-stronger-password"}).status_code == 204
    assert client.get("/").status_code == 200
    with app.app_context():
        user = get_db().execute("SELECT must_change_password FROM users WHERE id=?", (user_id,)).fetchone()
        assert user["must_change_password"] == 0
    client.post("/logout")
    assert client.post(
        "/login",
        data={"email": "operator@local.invalid", "password": "an-even-stronger-password", "totp_code": pyotp.TOTP(secret).at(time.time() + 30)},
    ).status_code == 302


def _tamper_audit_chain(app) -> None:
    from service_manager.audit import append_audit_event
    from service_manager.db import transaction

    with app.app_context():
        conn = get_db()
        with transaction(conn):
            append_audit_event(conn, action="test.created", target_type="test")
        conn.execute("DROP TRIGGER audit_events_no_update")
        conn.execute("UPDATE audit_events SET action='tampered' WHERE id=1")
        conn.commit()


def test_broken_audit_chain_blocks_authentication_and_bootstrap_mutations(app, client):
    _tamper_audit_chain(app)

    assert client.post(
        "/login",
        data={"email": "nobody@local.invalid", "password": "wrong", "totp_code": "000000"},
    ).status_code == 503
    assert client.post(
        "/bootstrap/issue-totp",
        data={"token": BOOTSTRAP_TOKEN, "initial_password": INITIAL_PASSWORD},
    ).status_code == 503


def test_bootstrap_activation_is_appended_to_the_audit_chain(app, client):
    secret = bootstrap_secret(client)
    assert client.post(
        "/bootstrap",
        data={
            "token": BOOTSTRAP_TOKEN,
            "initial_password": INITIAL_PASSWORD,
            "new_password": NEW_PASSWORD,
            "totp_code": pyotp.TOTP(secret).now(),
        },
    ).status_code == 200
    with app.app_context():
        event = get_db().execute("SELECT action FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        assert event["action"] == "bootstrap"


def test_successful_reauth_is_appended_to_the_audit_chain(app, client):
    admin_secret = pyotp.random_base32()
    admin_id, admin_secret = active_user(app, email="reauth-audit@local.invalid", role="admin", secret=admin_secret)
    assert login(client, "reauth-audit@local.invalid", NEW_PASSWORD, admin_secret).status_code == 302
    assert client.post(
        "/reauth",
        data={"password": NEW_PASSWORD, "totp_code": pyotp.TOTP(admin_secret).at(time.time() + 30)},
    ).status_code == 204
    with app.app_context():
        event = get_db().execute("SELECT action, actor_user_id FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        assert dict(event) == {"action": "reauth", "actor_user_id": admin_id}


def test_authorization_denial_and_oversized_login_are_audited_and_rate_limited(app, client):
    _, secret = active_user(app)
    assert client.post(
        "/login",
        data={"email": "operator@local.invalid", "password": NEW_PASSWORD, "totp_code": pyotp.TOTP(secret).at(time.time() + 30)},
    ).status_code == 302
    assert client.get("/admin/users").status_code == 403
    client.post("/logout")
    oversized = "x" * 4097
    for _ in range(5):
        assert client.post(
            "/login",
            data={"email": "missing@local.invalid", "password": oversized, "totp_code": "000000"},
        ).status_code == 401
    assert client.post(
        "/login",
        data={"email": "missing@local.invalid", "password": oversized, "totp_code": "000000"},
    ).status_code == 429
    with app.app_context():
        conn = get_db()
        assert conn.execute("SELECT COUNT(*) FROM security_events WHERE kind='login_failure'").fetchone()[0] == 5
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='authorization.failed'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='login_failure'").fetchone()[0] == 5


@pytest.mark.parametrize("email", ("a b@example.invalid", "a@@example.test", "plain-address.invalid"))
def test_reserved_domain_email_still_requires_valid_syntax(email):
    from service_manager.auth import normalize_email

    assert normalize_email(email) == ""


def test_bootstrap_initialization_is_audited_without_recording_credentials(app):
    with app.app_context():
        conn = get_db()
        user = conn.execute("SELECT id FROM users WHERE role='admin'").fetchone()
        event = conn.execute(
            "SELECT actor_user_id, action, target_type, target_id, metadata_json FROM audit_events"
        ).fetchone()

        assert dict(event) == {
            "actor_user_id": None,
            "action": "bootstrap.initialized",
            "target_type": "user",
            "target_id": str(user["id"]),
            "metadata_json": "{}",
        }


def test_expired_bootstrap_rotation_is_appended_to_the_audit_chain(tmp_path: Path):
    database = str(tmp_path / "bootstrap-rotation-audit.db")
    initial = {
        "TESTING": True,
        "DATABASE_PATH": database,
        "DATA_KEY_V1": KEY,
        "AUDIT_KEY_V1": KEY,
        "SECRET_KEY": "s" * 32,
        "ADMIN_EMAIL": "initial@local.invalid",
        "ADMIN_INITIAL_PASSWORD": INITIAL_PASSWORD,
        "ADMIN_BOOTSTRAP_TOKEN": BOOTSTRAP_TOKEN,
    }
    first = create_app(initial)
    with first.app_context():
        conn = get_db()
        conn.execute("UPDATE bootstrap_tokens SET expires_at=?", ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(),))
        conn.commit()

    rotated = create_app({
        **initial,
        "ADMIN_EMAIL": "rotated@local.invalid",
        "ADMIN_INITIAL_PASSWORD": "rotated-bootstrap-password",
        "ADMIN_BOOTSTRAP_TOKEN": "rotated-bootstrap-token",
    })
    with rotated.app_context():
        conn = get_db()
        events = conn.execute("SELECT action, metadata_json FROM audit_events ORDER BY id").fetchall()

        assert [event["action"] for event in events] == ["bootstrap.initialized", "bootstrap.rotated"]
        assert all(event["metadata_json"] == "{}" for event in events)
        from service_manager.audit import verify_audit_chain
        assert verify_audit_chain(conn)


def test_bootstrap_initialization_rolls_back_when_audit_append_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    bootstrap_app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "bootstrap-audit-rollback.db"),
            "DATA_KEY_V1": KEY,
            "AUDIT_KEY_V1": KEY,
            "SECRET_KEY": "s" * 32,
        }
    )
    bootstrap_app.config.update(
        ADMIN_EMAIL="admin@local.invalid",
        ADMIN_INITIAL_PASSWORD=INITIAL_PASSWORD,
        ADMIN_BOOTSTRAP_TOKEN=BOOTSTRAP_TOKEN,
    )

    def fail_audit(*args, **kwargs):
        raise RuntimeError("audit append unavailable")

    monkeypatch.setattr(auth_module, "_audit", fail_audit)
    with bootstrap_app.app_context(), pytest.raises(RuntimeError, match="audit append unavailable"):
        auth_module._bootstrap_initial_admin(bootstrap_app)

    with bootstrap_app.app_context():
        conn = get_db()
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM bootstrap_tokens").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0


def test_enrollment_rejects_oversized_totp_before_opening_a_transaction(app, client, monkeypatch: pytest.MonkeyPatch):
    user_id = onboarding_user(app)
    assert client.post("/login", data={"email": "onboarding@local.invalid", "password": NEW_PASSWORD}).status_code == 302
    assert client.post("/enroll-totp/issue").status_code == 200
    with app.app_context():
        before = get_db().execute(
            "SELECT pending_totp_secret_ciphertext, session_version FROM users WHERE id=?", (user_id,)
        ).fetchone()

    @contextmanager
    def transaction_must_not_open(_):
        raise AssertionError("oversized TOTP opened a transaction")
        yield

    monkeypatch.setattr(auth_module, "transaction", transaction_must_not_open)
    response = client.post("/enroll-totp", data={"totp_code": "x" * 4097})

    assert response.status_code == 400
    assert response.get_data(as_text=True) == "TOTP inválido"
    with app.app_context():
        after = get_db().execute(
            "SELECT pending_totp_secret_ciphertext, session_version FROM users WHERE id=?", (user_id,)
        ).fetchone()
        assert tuple(after) == tuple(before)


def test_bootstrap_rotation_rolls_back_when_audit_append_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database = str(tmp_path / "bootstrap-rotation-audit-rollback.db")
    initial = {
        "TESTING": True,
        "DATABASE_PATH": database,
        "DATA_KEY_V1": KEY,
        "AUDIT_KEY_V1": KEY,
        "SECRET_KEY": "s" * 32,
        "ADMIN_EMAIL": "initial@local.invalid",
        "ADMIN_INITIAL_PASSWORD": INITIAL_PASSWORD,
        "ADMIN_BOOTSTRAP_TOKEN": BOOTSTRAP_TOKEN,
    }
    first = create_app(initial)
    with first.app_context():
        conn = get_db()
        original = conn.execute("SELECT email, password_hash FROM users").fetchone()
        conn.execute("UPDATE bootstrap_tokens SET expires_at=?", ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(),))
        conn.commit()

    def fail_audit(*args, **kwargs):
        raise RuntimeError("audit append unavailable")

    monkeypatch.setattr(auth_module, "_audit", fail_audit)
    with pytest.raises(RuntimeError, match="audit append unavailable"):
        create_app({
            **initial,
            "ADMIN_EMAIL": "rotated@local.invalid",
            "ADMIN_INITIAL_PASSWORD": "rotated-bootstrap-password",
            "ADMIN_BOOTSTRAP_TOKEN": "rotated-bootstrap-token",
        })

    with first.app_context():
        conn = get_db()
        user = conn.execute("SELECT email, password_hash FROM users").fetchone()
        assert tuple(user) == tuple(original)
        assert conn.execute("SELECT COUNT(*) FROM bootstrap_tokens").fetchone()[0] == 1
