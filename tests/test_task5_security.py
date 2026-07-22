from __future__ import annotations

import sys
import re
import base64
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from itsdangerous import URLSafeTimedSerializer

from app import create_app
from service_manager.crypto import EncryptedValue, account_field_aad, decrypt_secret, hash_password
from service_manager.audit import append_audit_event, verify_audit_chain
from service_manager.db import get_db, transaction


KEY = base64.b64encode(b"a" * 32).decode("ascii")
PUBLIC_ORIGIN = "https://servicemanager.quantmind.com.br"


@pytest.fixture()
def app(tmp_path: Path):
    return create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "task5.db"),
            "DATA_KEY_V1": base64.b64encode(b"d" * 32).decode("ascii"),
            "AUDIT_KEY_V1": KEY,
            "SECRET_KEY": "task-five-session-secret",
            "PUBLIC_ORIGIN": PUBLIC_ORIGIN,
            "WTF_CSRF_ENABLED": True,
            "CSRF_ORIGIN_CHECK": True,
        }
    )


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf_headers(client, app, *, origin: str = PUBLIC_ORIGIN) -> dict[str, str]:
    with client.session_transaction() as session:
        session["csrf_token"] = "task-five-csrf-token"
    token = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="wtf-csrf-token").dumps("task-five-csrf-token")
    return {"X-CSRFToken": token, "Origin": origin}


def authenticated_operator(app, client, *, role: str = "operador") -> tuple[int, int]:
    with app.app_context():
        conn = get_db()
        service_id = conn.execute("INSERT INTO services (name) VALUES ('Mail')").lastrowid
        user_id = conn.execute(
            "INSERT INTO users (username, password_hash, role, is_active, must_change_password, created_at, updated_at) "
            "VALUES (?, ?, ?, 1, 0, ?, ?)",
            (f"fixture-{role}", hash_password("not-a-secret-in-audit"), role, datetime.now(UTC).isoformat(), datetime.now(UTC).isoformat()),
        ).lastrowid
        conn.commit()
    with client.session_transaction() as session:
        now = time.time()
        session.update(user_id=user_id, role=role, session_version=0, authenticated_at=now, last_seen_at=now, reauthenticated_at=now)
    return user_id, service_id


def test_mutation_requires_csrf_token_and_trusted_origin_without_creating_account(app, client):
    _, service_id = authenticated_operator(app, client)
    payload = {"service": service_id, "email": "person@example.test", "password": "account-secret", "status": "ativo"}

    missing = client.post("/add", data=payload, headers={"Origin": PUBLIC_ORIGIN})
    cross_origin = client.post("/add", data=payload, headers=csrf_headers(client, app, origin="https://evil.example"))

    assert missing.status_code == 403
    assert cross_origin.status_code == 403
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0


def test_valid_header_csrf_and_origin_allow_mutation_and_append_secret_free_audit_event(app, client):
    user_id, service_id = authenticated_operator(app, client)
    secret = "account-secret-that-must-not-be-audited"
    response = client.post(
        "/add",
        data={"service": service_id, "email": "person@example.com", "password": secret, "status": "ativo"},
        headers=csrf_headers(client, app),
    )

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/?service=")
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1
        event = get_db().execute("SELECT actor_user_id, action, target_type, metadata_json FROM audit_events WHERE action='account.created'").fetchone()
        assert event["actor_user_id"] == user_id
        assert event["action"] == "account.created"
        assert event["target_type"] == "account"
        assert secret not in event["metadata_json"]
        assert verify_audit_chain()


def test_login_with_valid_token_and_same_origin_referer_no_origin_succeeds(app):
    """Under Referrer-Policy: same-origin, a browser that omits Origin still
    sends a same-origin Referer. The CSRF token plus that Referer must reach
    authentication and succeed; neither header and cross-origin must fail."""
    def _login_token(c):
        match = re.search(r'<input type="hidden" name="csrf_token" value="([^"]+)">', c.get("/login").get_data(as_text=True))
        assert match is not None, "login form missing hidden csrf_token field"
        return match.group(1)

    valid_c = app.test_client()
    valid = valid_c.post(
        "/login",
        data={"username": "admin", "password": "12345678", "csrf_token": _login_token(valid_c)},
        headers={"Referer": PUBLIC_ORIGIN + "/login"},
    )

    neither_c = app.test_client()
    neither = neither_c.post(
        "/login",
        data={"username": "admin", "password": "12345678", "csrf_token": _login_token(neither_c)},
    )

    cross_c = app.test_client()
    cross = cross_c.post(
        "/login",
        data={"username": "admin", "password": "12345678", "csrf_token": _login_token(cross_c)},
        headers={"Referer": "https://evil.example/login"},
    )

    assert valid.status_code == 302
    assert valid.headers["Location"].endswith("/")
    assert neither.status_code == 403
    assert cross.status_code == 403


def test_https_mutation_with_origin_but_no_referer_is_allowed(app, client):
    """A browser under Referrer-Policy: same-origin sends Origin but may omit
    Referer on cross-document navigations. Flask-WTF SSL-strict must not demand
    a Referer on secure requests; the explicit Origin gate plus the CSRF token
    are the authoritative protection."""
    _, service_id = authenticated_operator(app, client)
    allowed = client.post(
        "/add",
        base_url="https://localhost",
        data={"service": service_id, "email": "person@example.com", "password": "https-secret", "status": "ativo"},
        headers=csrf_headers(client, app),
    )
    cross_origin = client.post(
        "/add",
        base_url="https://localhost",
        data={"service": service_id, "email": "evil@example.com", "password": "https-secret", "status": "ativo"},
        headers=csrf_headers(client, app, origin="https://evil.example"),
    )
    with client.session_transaction() as session:
        session["csrf_token"] = "task-five-csrf-token"
    token = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="wtf-csrf-token").dumps("task-five-csrf-token")
    missing_origin = client.post(
        "/add",
        base_url="https://localhost",
        data={"service": service_id, "email": "noorigin@example.com", "password": "https-secret", "status": "ativo"},
        headers={"X-CSRFToken": token},
    )
    assert allowed.status_code == 302
    assert cross_origin.status_code == 403
    assert missing_origin.status_code == 403
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1


def test_login_form_submits_csrf_token_with_trusted_origin(app, client):
    page = client.get("/login")
    match = re.search(r'<input type="hidden" name="csrf_token" value="([^"]+)">', page.get_data(as_text=True))

    assert page.status_code == 200
    assert match is not None
    response = client.post(
        "/login",
        data={"username": "admin", "password": "12345678", "csrf_token": match.group(1)},
        headers={"Origin": PUBLIC_ORIGIN},
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")

def test_header_only_csrf_is_accepted_and_stale_form_token_is_rejected(app, client):
    """The bootstrap JS sends the CSRF token only via the X-CSRFToken header (the
    meta tag). Flask-WTF prioritizes the hidden csrf_token form field over the
    header, so a stale/mismatched field value would override the valid header and
    fail closed ("tokens do not match"). The header-only path must be accepted;
    a mismatched form field must be rejected."""
    _, service_id = authenticated_operator(app, client)
    header_only = client.post(
        "/add",
        base_url="https://localhost",
        data={"service": service_id, "email": "header@example.com", "password": "s", "status": "ativo"},
        headers=csrf_headers(client, app),
    )
    stale_form_token = client.post(
        "/add",
        base_url="https://localhost",
        data={"service": service_id, "email": "stale@example.com", "password": "s", "status": "ativo", "csrf_token": "stale-mismatched-token"},
        headers=csrf_headers(client, app),
    )
    assert header_only.status_code == 302
    assert stale_form_token.status_code == 403
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1

def test_validation_rejects_duplicate_case_insensitive_email_and_invalid_status_without_mutating(app, client):
    _, service_id = authenticated_operator(app, client)
    first = client.post("/add", data={"service": service_id, "email": "Person@example.com", "password": "safe", "status": "ativo"}, headers=csrf_headers(client, app))
    duplicate = client.post("/add", data={"service": service_id, "email": "person@example.com", "password": "safe", "status": "ativo"}, headers=csrf_headers(client, app))
    invalid_status = client.post("/add", data={"service": service_id, "email": "other@example.com", "password": "safe", "status": "enabled"}, headers=csrf_headers(client, app))

    assert first.status_code == 302
    assert duplicate.status_code == 400
    assert invalid_status.status_code == 400
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 1


def test_audit_chain_rejects_tampering_and_health_degrades(app):
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            append_audit_event(conn, action="test.created", target_type="test", target_id="1", metadata={"count": 1})
        conn.execute("DROP TRIGGER audit_events_no_update")
        conn.execute("UPDATE audit_events SET metadata_json='{}' WHERE action='test.created'")
        conn.commit()
        assert not verify_audit_chain()

    response = app.test_client().get("/healthz")
    assert response.status_code == 503
    assert response.get_json() == {"status": "degraded"}


def test_expired_security_events_are_removed_during_audit_cleanup(app):
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            conn.execute(
                "INSERT INTO security_events (kind, subject, source_ip, occurred_at) VALUES ('login_failure', 'subject', '127.0.0.1', ?)",
                ((datetime.now(UTC) - timedelta(hours=25)).isoformat(),),
            )
            append_audit_event(conn, action="cleanup.test", target_type="test")
        assert conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 0


def test_factory_rejects_non_https_or_non_origin_public_origin(tmp_path: Path):
    base = {
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "origin.db"),
        "DATA_KEY_V1": base64.b64encode(b"d" * 32).decode("ascii"),
        "AUDIT_KEY_V1": KEY,
        "SECRET_KEY": "task-five-session-secret",
    }
    for origin in ("http://servicemanager.quantmind.com.br", "https://servicemanager.quantmind.com.br/path", "https://user@servicemanager.quantmind.com.br"):
        with pytest.raises(RuntimeError, match="PUBLIC_ORIGIN"):
            create_app({**base, "PUBLIC_ORIGIN": origin})


def test_audit_chain_rejects_a_gap_in_event_ids(app):
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            append_audit_event(conn, action="first", target_type="test")
            append_audit_event(conn, action="second", target_type="test")
        conn.execute("DROP TRIGGER audit_events_no_delete")
        conn.execute("DELETE FROM audit_events WHERE id = 1")
        conn.commit()
        assert not verify_audit_chain()


def test_tampering_behind_watermark_is_caught_by_scheduled_full_walk(app, monkeypatch):
    from service_manager import audit as audit_module
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            append_audit_event(conn, action="first", target_type="test")
            append_audit_event(conn, action="second", target_type="test")
        assert verify_audit_chain()          # advances watermark past both rows
        conn.execute("DROP TRIGGER audit_events_no_update")
        conn.execute("UPDATE audit_events SET action='tampered' WHERE action='first'")
        conn.commit()
        assert verify_audit_chain()          # inside the window: documents the bounded blind spot
        monkeypatch.setattr(audit_module, "_FULL_WALK_INTERVAL_SECONDS", 0.0)
        assert not verify_audit_chain()      # scheduled full walk catches it


def test_split_account_routes_preserve_blank_secret_and_isolate_status(app, client):
    _, service_id = authenticated_operator(app, client)
    created = client.post(
        "/add",
        data={"service": service_id, "email": "person@example.com", "password": "original-secret", "status": "ativo"},
        headers=csrf_headers(client, app),
    )
    assert created.status_code == 302
    with app.app_context():
        account_id = get_db().execute("SELECT id FROM accounts WHERE email='person@example.com'").fetchone()[0]
        before = get_db().execute("SELECT password_ciphertext FROM accounts WHERE id=?", (account_id,)).fetchone()[0]
    account_response = client.post(
        f"/accounts/{account_id}",
        data={"service_id": service_id, "email": "renamed@example.com", "password": ""},
        headers=csrf_headers(client, app),
    )
    status_response = client.post(
        f"/accounts/{account_id}/status",
        data={"service_id": service_id, "status": "inativo"},
        headers=csrf_headers(client, app),
    )
    assert account_response.status_code == 302
    assert status_response.status_code == 302
    with app.app_context():
        conn = get_db()
        assert conn.execute("SELECT password_ciphertext FROM accounts WHERE id=?", (account_id,)).fetchone()[0] == before
        assert conn.execute("SELECT status FROM account_service WHERE account_id=? AND service_id=?", (account_id, service_id)).fetchone()[0] == "inativo"


def test_broken_audit_chain_blocks_sensitive_mutation(app, client):
    _, service_id = authenticated_operator(app, client)
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            append_audit_event(conn, action="test.created", target_type="test")
        conn.execute("DROP TRIGGER audit_events_no_update")
        conn.execute("UPDATE audit_events SET action='tampered' WHERE action='test.created'")
        conn.commit()
    response = client.post(
        "/service/add",
        data={"name": "Blocked"},
        headers=csrf_headers(client, app),
    )
    assert response.status_code == 503
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM services WHERE name='Blocked'").fetchone()[0] == 0


def test_field_add_always_encrypts_the_value(app, client):
    _, service_id = authenticated_operator(app, client)
    with app.app_context():
        conn = get_db()
        account_id = conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
            ("public-field@example.test", b"ciphertext", b"0" * 12),
        ).lastrowid
        conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (account_id, service_id))
        conn.commit()

    created = client.post(
        "/field/add",
        data={"service": service_id, "name": "Public note", "value": "visible", "account_ids": [account_id]},
        headers=csrf_headers(client, app),
    )

    assert created.status_code == 302
    with app.app_context():
        conn = get_db()
        assert "is_secret" not in {row["name"] for row in conn.execute("PRAGMA table_info(custom_fields)")}
        field_id = conn.execute("SELECT id FROM custom_fields WHERE name='Public note'").fetchone()[0]
        row = conn.execute(
            "SELECT value_ciphertext, value_nonce, value_key_version FROM field_values WHERE field_id=? AND account_id=?", (field_id, account_id)
        ).fetchone()
        assert row["value_ciphertext"] is not None
        assert decrypt_secret(EncryptedValue(row["value_ciphertext"], row["value_nonce"], row["value_key_version"]), aad=account_field_aad(account_id, field_id)) == "visible"


def test_field_update_reencrypts_the_value(app, client):
    _, service_id = authenticated_operator(app, client, role="admin")
    with app.app_context():
        conn = get_db()
        account_id = conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
            ("update-field@example.test", b"ciphertext", b"0" * 12),
        ).lastrowid
        conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (account_id, service_id))
        conn.commit()
    client.post(
        "/field/add",
        data={"service": service_id, "name": "Note", "value": "first", "account_ids": [account_id]},
        headers=csrf_headers(client, app),
    )
    with app.app_context():
        field_id = get_db().execute("SELECT id FROM custom_fields WHERE name='Note'").fetchone()[0]
    updated = client.post(
        f"/field/update/{field_id}/{account_id}",
        data={"service_id": service_id, "value": "second"},
        headers=csrf_headers(client, app),
    )
    assert updated.status_code == 302
    with app.app_context():
        conn = get_db()
        row = conn.execute("SELECT value_ciphertext, value_nonce, value_key_version FROM field_values WHERE field_id=? AND account_id=?", (field_id, account_id)).fetchone()
        assert decrypt_secret(EncryptedValue(row["value_ciphertext"], row["value_nonce"], row["value_key_version"]), aad=account_field_aad(account_id, field_id)) == "second"


def test_removed_field_endpoints_return_404(app, client):
    _, service_id = authenticated_operator(app, client, role="admin")
    with app.app_context():
        conn = get_db()
        account_id = conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
            ("removed@example.test", b"ciphertext", b"0" * 12),
        ).lastrowid
        conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (account_id, service_id))
        conn.commit()
    client.post(
        "/field/add",
        data={"service": service_id, "name": "Note", "value": "first", "account_ids": [account_id]},
        headers=csrf_headers(client, app),
    )
    with app.app_context():
        field_id = get_db().execute("SELECT id FROM custom_fields WHERE name='Note'").fetchone()[0]
    reclassify = client.post(
        f"/field/{field_id}/classification",
        data={"service_id": service_id, "is_secret": "0"},
        headers=csrf_headers(client, app),
    )
    assert reclassify.status_code == 404
    reveal = client.post(
        f"/api/accounts/{account_id}/fields/{field_id}/reveal",
        headers=csrf_headers(client, app),
    )
    assert reveal.status_code == 404


def test_password_reveal_works_without_recent_reauth(app, client):
    _, service_id = authenticated_operator(app, client)
    with app.app_context():
        from service_manager.crypto import account_password_aad, encrypt_secret
        conn = get_db()
        envelope = encrypt_secret("account-password", aad=account_password_aad(1))
        account_id = conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, ?)",
            ("reveal@example.test", envelope.ciphertext, envelope.nonce, envelope.key_version),
        ).lastrowid
        conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (account_id, service_id))
        conn.commit()
        # Re-encrypt bound to the real account id now that it is known.
        envelope = encrypt_secret("account-password", aad=account_password_aad(account_id))
        conn.execute("UPDATE accounts SET password_ciphertext=?, password_nonce=?, password_key_version=? WHERE id=?", (envelope.ciphertext, envelope.nonce, envelope.key_version, account_id))
        conn.commit()
    with client.session_transaction() as session:
        session["reauthenticated_at"] = None
    reveal = client.post(
        f"/api/accounts/{account_id}/secrets/password/reveal",
        headers=csrf_headers(client, app),
    )
    assert reveal.status_code == 200
    payload = reveal.get_json()
    assert payload["value"] == "account-password"
    assert payload["expires_in"] == 30
    assert reveal.headers["Cache-Control"] == "no-store, private"


def test_unauthenticated_reveal_redirects_before_csrf_but_authenticated_bad_csrf_is_rejected(app, client):
    user_id, service_id = authenticated_operator(app, client)
    with app.app_context():
        account_id = get_db().execute("INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)", ("csrf-reveal@example.test", b"", b"0" * 12)).lastrowid
        get_db().execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (account_id, service_id))
        get_db().commit()
    with client.session_transaction() as session:
        session.clear()
    expired = client.post(f"/api/accounts/{account_id}/secrets/password/reveal")

    assert expired.status_code == 302
    assert expired.headers["Location"] == "/login"

    with client.session_transaction() as session:
        now = time.time()
        session.update(user_id=user_id, role="operador", session_version=0, authenticated_at=now, last_seen_at=now, reauthenticated_at=now)
    invalid_csrf = client.post(f"/api/accounts/{account_id}/secrets/password/reveal", headers={"Origin": PUBLIC_ORIGIN})

    assert invalid_csrf.status_code == 403
