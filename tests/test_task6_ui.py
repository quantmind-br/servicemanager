from __future__ import annotations

import base64
import time
from datetime import UTC, datetime
from pathlib import Path

import sys
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
from service_manager.crypto import account_field_aad, account_password_aad, encrypt_secret, hash_password, user_totp_aad
from service_manager.db import get_db


KEY = base64.b64encode(b"u" * 32).decode("ascii")
CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"


@pytest.fixture()
def app(tmp_path: Path):
    return create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "ui.db"),
            "DATA_KEY_V1": KEY,
            "AUDIT_KEY_V1": KEY,
            "SECRET_KEY": "task-six-session-secret",
            "WTF_CSRF_ENABLED": False,
        }
    )


@pytest.fixture()
def client(app):
    return app.test_client()


def seed_authenticated_secret(app, client) -> tuple[int, int, int]:
    with app.app_context():
        conn = get_db()
        stamp = datetime.now(UTC).isoformat()
        user_id = conn.execute(
            "INSERT INTO users (email, password_hash, role, is_active, must_change_password, created_at, updated_at) "
            "VALUES (?, ?, 'operador', 1, 0, ?, ?)",
            ("ui@local.invalid", hash_password("user-password"), stamp, stamp),
        ).lastrowid
        totp = encrypt_secret("JBSWY3DPEHPK3PXP", aad=user_totp_aad(user_id))
        conn.execute(
            "UPDATE users SET totp_secret_ciphertext=?, totp_nonce=?, totp_key_version=1, totp_confirmed_at=? WHERE id=?",
            (totp.ciphertext, totp.nonce, stamp, user_id),
        )
        service_id = conn.execute("INSERT INTO services (name) VALUES ('Email')").lastrowid
        account_id = conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
            ("person@example.test", b"", b"0" * 12),
        ).lastrowid
        password = encrypt_secret("known-secret", aad=account_password_aad(account_id))
        conn.execute(
            "UPDATE accounts SET password_ciphertext=?, password_nonce=?, password_key_version=1 WHERE id=?",
            (password.ciphertext, password.nonce, account_id),
        )
        conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (account_id, service_id))
        protected_field = conn.execute(
            "INSERT INTO custom_fields (service_id, name, is_secret) VALUES (?, 'Token', 1)", (service_id,)
        ).lastrowid
        protected = encrypt_secret("known-field-secret", aad=account_field_aad(account_id, protected_field))
        conn.execute(
            "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, 1)",
            (protected_field, account_id, protected.ciphertext, protected.nonce),
        )
        visible_field = conn.execute(
            "INSERT INTO custom_fields (service_id, name, is_secret) VALUES (?, 'Observação', 0)", (service_id,)
        ).lastrowid
        conn.execute("INSERT INTO field_values (field_id, account_id, value_plaintext) VALUES (?, ?, 'nota pública')", (visible_field, account_id))
        conn.commit()
    with client.session_transaction() as session:
        now = time.time()
        session.update(user_id=user_id, role="operador", session_version=0, authenticated_at=now, last_seen_at=now, reauthenticated_at=now)
    return service_id, account_id, protected_field


def test_authenticated_listing_uses_external_assets_and_excludes_secret_values(app, client):
    service_id, account_id, field_id = seed_authenticated_secret(app, client)

    response = client.get(f"/?service={service_id}")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Service Manager" in body
    assert 'href="/static/css/app.css?v=' in body
    assert 'src="/static/js/app.js?v=' in body
    assert "known-secret" not in body
    assert "known-field-secret" not in body
    assert "nota pública" in body
    assert "Protegido" in body
    assert f"/api/accounts/{account_id}/secrets/password/reveal" in body
    assert f"/api/accounts/{account_id}/fields/{field_id}/reveal" in body
    assert "<style" not in body
    assert "<script>" not in body
    assert "onclick=" not in body

def test_response_security_headers_are_strict_and_hsts_requires_production_https(app, client):
    service_id, _, _ = seed_authenticated_secret(app, client)
    app.config["IS_PRODUCTION"] = True

    insecure = client.get(f"/?service={service_id}")
    response = client.get(f"/?service={service_id}", base_url="https://servicemanager.quantmind.com.br")

    assert "Strict-Transport-Security" not in insecure.headers
    assert response.headers["Content-Security-Policy"] == CSP
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Permissions-Policy"] == "camera=(), microphone=(), geolocation=()"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
    assert insecure.headers["Cache-Control"] == "no-store, private"
    assert insecure.headers["Pragma"] == "no-cache"


def test_reveal_script_is_self_hosted_and_clears_exposed_values_on_timeout_and_tab_hide(client):
    response = client.get("/static/js/app.js")

    assert response.status_code == 200
    script = response.get_data(as_text=True)
    assert "localStorage" not in script
    assert "sessionStorage" not in script
    assert "visibilitychange" in script
    assert "30000" in script
    assert "navigator.clipboard.writeText" in script

def test_generic_error_pages_use_the_external_base_template(app, client):
    seed_authenticated_secret(app, client)
    response = client.get("/?service=invalid")
    body = response.get_data(as_text=True)

    assert response.status_code == 404
    assert "Não encontrado" in body
    assert 'href="/static/css/app.css?v=' in body
    assert 'src="/static/js/app.js?v=' in body

def test_bootstrap_page_can_issue_and_display_one_time_totp_enrollment(tmp_path: Path):
    app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "bootstrap-ui.db"),
            "DATA_KEY_V1": KEY,
            "AUDIT_KEY_V1": KEY,
            "SECRET_KEY": "bootstrap-ui-session-secret",
            "ADMIN_EMAIL": "admin@local.invalid",
            "ADMIN_INITIAL_PASSWORD": "bootstrap-initial-password",
            "ADMIN_BOOTSTRAP_TOKEN": "bootstrap-token-for-ui-testing",
            "WTF_CSRF_ENABLED": False,
        }
    )
    client = app.test_client()
    response = client.get("/bootstrap")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'data-bootstrap-enrollment' in body
    assert 'data-bootstrap-issue-url="/bootstrap/issue-totp"' in body
    assert 'id="totp-enrollment"' in body
    assert 'name="totp_secret"' not in body
    script = client.get("/static/js/app.js").get_data(as_text=True)
    assert "data-bootstrap-enrollment" in script
    assert "totp_secret" in script
    assert "qr_svg_base64" in script


def test_bootstrap_page_submits_required_totp_confirmation_code(tmp_path: Path):
    app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "bootstrap-totp-code-ui.db"),
            "DATA_KEY_V1": KEY,
            "AUDIT_KEY_V1": KEY,
            "SECRET_KEY": "bootstrap-totp-code-ui-session-secret",
            "ADMIN_EMAIL": "admin@local.invalid",
            "ADMIN_INITIAL_PASSWORD": "bootstrap-initial-password",
            "ADMIN_BOOTSTRAP_TOKEN": "bootstrap-token-for-totp-code-ui-testing",
            "WTF_CSRF_ENABLED": False,
        }
    )

    body = app.test_client().get("/bootstrap").get_data(as_text=True)

    assert 'name="totp_code"' in body
    assert 'autocomplete="one-time-code"' in body
    assert 'inputmode="numeric"' in body
    assert 'name="totp_code" type="text" autocomplete="one-time-code" inputmode="numeric" required' in body

def test_listing_excludes_accounts_without_a_link_to_the_selected_service(app, client):
    service_id, _, _ = seed_authenticated_secret(app, client)
    with app.app_context():
        conn = get_db()
        unlinked_account = conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
            ("unlinked@example.test", b"", b"1" * 12),
        ).lastrowid
        conn.commit()

    response = client.get(f"/?service={service_id}")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "unlinked@example.test" not in body
    assert f'action="/accounts/{unlinked_account}"' not in body


def test_bootstrap_totp_issue_returns_a_qr_image_for_the_server_issued_secret(tmp_path: Path):
    app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "bootstrap-qr.db"),
            "DATA_KEY_V1": KEY,
            "AUDIT_KEY_V1": KEY,
            "SECRET_KEY": "bootstrap-qr-session-secret",
            "ADMIN_EMAIL": "admin@local.invalid",
            "ADMIN_INITIAL_PASSWORD": "bootstrap-initial-password",
            "ADMIN_BOOTSTRAP_TOKEN": "bootstrap-token-for-qr-testing",
            "WTF_CSRF_ENABLED": False,
        }
    )

    response = app.test_client().post(
        "/bootstrap/issue-totp",
        data={"token": "bootstrap-token-for-qr-testing", "initial_password": "bootstrap-initial-password"},
    )

    assert response.status_code == 200
    assert base64.b64decode(response.get_json()["qr_svg_base64"]).lstrip().endswith(b"</svg>")



def test_bootstrap_confirmation_ui_preserves_enrollment_on_recoverable_error_and_shows_codes_once(tmp_path: Path):
    app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "bootstrap-confirm-ui.db"),
            "DATA_KEY_V1": KEY,
            "AUDIT_KEY_V1": KEY,
            "SECRET_KEY": "bootstrap-confirm-session-secret",
            "ADMIN_EMAIL": "admin@local.invalid",
            "ADMIN_INITIAL_PASSWORD": "bootstrap-initial-password",
            "ADMIN_BOOTSTRAP_TOKEN": "bootstrap-token-for-confirm-ui-testing",
            "WTF_CSRF_ENABLED": False,
        }
    )

    body = app.test_client().get("/bootstrap").get_data(as_text=True)
    script = app.test_client().get("/static/js/app.js").get_data(as_text=True)

    assert 'class="bootstrap-error"' in body
    assert 'id="recovery-codes"' in body
    assert 'form.addEventListener("submit"' in script
    assert "response.status === 400" in script
    assert "recovery_codes" in script
    assert "secretOutput.textContent = \"\"" in script

def test_bootstrap_fetches_send_csrf_only_via_header_not_restorable_form_field(client):
    """Chrome can restore the hidden csrf_token form field to a stale value, and
    Flask-WTF prefers the form field over the X-CSRFToken header, causing
    "tokens do not match". Both bootstrap fetches must strip csrf_token from the
    body so the header (from the non-restorable meta tag) is the single source."""
    script = client.get("/static/js/app.js").get_data(as_text=True)
    assert 'data.delete("csrf_token")' in script
    assert script.count("body: csrfBody(form)") == 2
    assert "body: new FormData(form)" not in script

def test_listing_restores_management_forms_without_prefilling_secrets(app, client):
    service_id, account_id, field_id = seed_authenticated_secret(app, client)
    with app.app_context():
        conn = get_db()
        conn.execute("UPDATE users SET role='admin' WHERE email='ui@local.invalid'")
        conn.commit()
    with client.session_transaction() as session:
        session["role"] = "admin"

    response = client.get(f"/?service={service_id}")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'action="/service/add"' in body
    assert f'action="/service/delete/{service_id}"' in body
    assert 'action="/add"' in body
    assert f'action="/accounts/{account_id}"' in body
    assert f'action="/accounts/{account_id}/status"' in body
    assert f'action="/delete/{account_id}"' in body
    assert 'action="/field/add"' in body
    assert f'action="/field/update/{field_id}/{account_id}"' in body
    assert f'action="/field/delete/{field_id}/{account_id}"' in body
    assert 'action="/import"' in body
    assert body.count('name="csrf_token"') >= 8
    assert 'value="known-secret"' not in body
    assert 'value="known-field-secret"' not in body


def test_proxy_fix_trusts_forwarded_https_for_production_hsts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLASK_ENV", "production")
    app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "proxy.db"),
            "DATA_KEY_V1": KEY,
            "AUDIT_KEY_V1": KEY,
            "SECRET_KEY": "proxy-session-secret",
            "TRUSTED_PROXY_HOPS": 1,
        }
    )

    response = app.test_client().get("/login", headers={"X-Forwarded-Proto": "https"})

    assert response.status_code == 200
    assert response.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"


def test_reveal_script_aborts_and_discards_hidden_inflight_responses(client):
    script = client.get("/static/js/app.js").get_data(as_text=True)

    assert "AbortController" in script
    assert ".abort()" in script
    assert "document.hidden" in script
    assert "revealGeneration" in script


def test_creating_service_backfills_existing_account_links_for_displayed_controls(app, client):
    _, account_id, _ = seed_authenticated_secret(app, client)

    created = client.post("/service/add", data={"name": "Novo serviço"})

    assert created.status_code == 302
    service_id = int(created.location.rsplit("=", 1)[1])
    with app.app_context():
        conn = get_db()
        assert conn.execute(
            "SELECT status FROM account_service WHERE account_id=? AND service_id=?", (account_id, service_id)
        ).fetchone()["status"] == "nunca"
        assert conn.execute(
            "SELECT 1 FROM audit_events WHERE action='service.created' AND target_id=?", (service_id,)
        ).fetchone() is not None

    updated = client.post(f"/accounts/{account_id}/status", data={"service_id": service_id, "status": "ativo"})

    assert updated.status_code == 302


def test_quiet_buttons_have_contrast_on_light_panels_and_dark_header(app, client):
    stylesheet = client.get("/static/css/app.css").get_data(as_text=True)

    assert ".button-quiet { background: transparent; border-color: #9ab1c2; color: var(--ink); }" in stylesheet
    assert ".site-header .button-quiet { color: #fff; }" in stylesheet
    assert ".button-quiet:hover, .button-quiet:focus-visible { background: var(--navy); border-color: var(--navy); color: #fff; }" in stylesheet
