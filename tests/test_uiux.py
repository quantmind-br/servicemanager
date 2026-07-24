from __future__ import annotations

import base64
import re
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
from service_manager.crypto import account_password_aad, encrypt_secret, hash_password
from service_manager.db import get_db, inserted_id


KEY = base64.b64encode(b"u" * 32).decode("ascii")


@pytest.fixture()
def app(tmp_path: Path):
    return create_app(
        {
            "TESTING": True,
            "PROPAGATE_EXCEPTIONS": False,
            "DATABASE_PATH": str(tmp_path / "uiux.db"),
            "DATA_KEY_V1": KEY,
            "AUDIT_KEY_V1": KEY,
            "SECRET_KEY": "uiux-session-secret",
            "WTF_CSRF_ENABLED": False,
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "admin-password-0123456789",
        }
    )


@pytest.fixture()
def client(app):
    return app.test_client()


def seed_authenticated_secret(app, client) -> tuple[int, int]:
    with app.app_context():
        conn = get_db()
        stamp = datetime.now(UTC).isoformat()
        user_id = inserted_id(conn.execute(
            "INSERT INTO users (username, password_hash, role, is_active, must_change_password, created_at, updated_at) "
            "VALUES (?, ?, 'operador', 1, 0, ?, ?)",
            ("ui-user", hash_password("user-password"), stamp, stamp),
        ))
        service_id = inserted_id(conn.execute("INSERT INTO services (name) VALUES ('Email')"))
        account_id = inserted_id(conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
            ("person@example.test", b"", b"0" * 12),
        ))
        password = encrypt_secret("known-secret", aad=account_password_aad(account_id))
        conn.execute(
            "UPDATE accounts SET password_ciphertext=?, password_nonce=?, password_key_version=1 WHERE id=?",
            (password.ciphertext, password.nonce, account_id),
        )
        conn.execute(
            "INSERT INTO account_service (account_id, service_id, status, registered) VALUES (?, ?, 'ativo', 1)",
            (account_id, service_id),
        )
        conn.execute(
            "INSERT INTO service_members (user_id, service_id, role, created_at) VALUES (?, ?, 'service_admin', ?)",
            (user_id, service_id, stamp),
        )
        conn.commit()
    with client.session_transaction() as session:
        now = time.time()
        session.update(
            user_id=user_id,
            role="operador",
            session_version=0,
            authenticated_at=now,
            last_seen_at=now,
            reauthenticated_at=now,
        )
    return service_id, account_id


# ---------- Step 1: styled auth failures ----------

def test_login_failure_renders_styled_page(app, client):
    response = client.post("/login", data={"username": "admin", "password": "wrong-password-123"})

    assert response.status_code == 401
    body = response.get_data(as_text=True)
    assert 'action="/login"' in body
    assert 'name="csrf_token"' in body
    assert "Credenciais inválidas." in body
    assert "feedback-error" in body


def test_login_rate_limit_renders_styled_page(app, client):
    for _ in range(5):
        client.post("/login", data={"username": "admin", "password": "wrong-password-123"})
    response = client.post("/login", data={"username": "admin", "password": "wrong-password-123"})

    assert response.status_code == 429
    body = response.get_data(as_text=True)
    assert "Muitas tentativas" in body
    assert "feedback-error" in body


def test_password_change_failure_rerenders_account(app, client):
    seed_authenticated_secret(app, client)
    response = client.post(
        "/account/password",
        data={"current_password": "definitely-wrong-pass", "new_password": "brand-new-password-1234"},
    )

    assert response.status_code == 400
    body = response.get_data(as_text=True)
    assert 'action="/account/password"' in body
    assert "Não foi possível alterar a senha" in body
    assert "feedback-error" in body


# ---------- Step 3: registered absence defaults to 0 ----------

def test_registered_absent_field_clears_flag(app, client):
    service_id, account_id = seed_authenticated_secret(app, client)

    def stored() -> int:
        with app.app_context():
            return get_db().execute(
                "SELECT registered FROM account_service WHERE account_id=? AND service_id=?",
                (account_id, service_id),
            ).fetchone()["registered"]

    assert stored() == 1
    response = client.post(f"/accounts/{account_id}/registered", data={"service_id": service_id})
    assert response.status_code == 302
    assert stored() == 0


# ---------- Step 2: success feedback via ?ok= whitelist ----------

def test_mutation_success_feedback(app, client):
    service_id, _ = seed_authenticated_secret(app, client)
    added = client.post(
        "/add",
        data={"service_id": service_id, "email": "new@example.test", "password": "pw", "status": "ativo"},
    )
    assert added.status_code == 302
    assert "ok=account_added" in added.headers["Location"]

    body = client.get(added.headers["Location"]).get_data(as_text=True)
    assert "Conta adicionada." in body
    assert "data-feedback" in body


def test_unknown_ok_code_is_ignored(app, client):
    service_id, _ = seed_authenticated_secret(app, client)
    response = client.get(f"/?service={service_id}&ok=bogus")

    assert response.status_code == 200
    assert "data-feedback" not in response.get_data(as_text=True)


# ---------- Step 4/6: template + asset contract for the frontend features ----------

def test_index_carries_frontend_hooks(app, client):
    service_id, account_id = seed_authenticated_secret(app, client)
    body = client.get(f"/?service={service_id}").get_data(as_text=True)

    # fetch-update opt-in on status + registered forms
    assert body.count("data-fetch-update") == 2
    # addressable summary counts
    assert 'data-count="total"' in body
    assert 'data-count="ativo"' in body
    # filter meta + clear
    assert 'id="filter-count"' in body
    assert 'id="filter-clear"' in body
    # column filters relocated into their table headers
    for name, control_id in (("email", "account-filter"), ("status", "filter-status"), ("registered", "filter-registered")):
        start = body.index(f'data-column-filter="{name}"')
        cell = body[start:body.index("</th>", start)]
        assert f'id="{control_id}"' in cell
    # shared confirm dialog + toast
    assert 'id="confirm-dialog"' in body
    assert 'id="toast"' in body
    # mobile card labels
    for label in ("Senha", "Status", "Cadastro", "Ações"):
        assert f'data-label="{label}"' in body
    # table caption
    assert '<caption class="sr-only">' in body
    # noscript save fallbacks (status + registered)
    assert body.count("<noscript>") == 2
    # no inline style/script/onclick (CSP)
    assert "<style" not in body
    assert "<script>" not in body
    assert "onclick=" not in body


def test_service_preferences_dialog_hooks_and_literals(app, client):
    seed_authenticated_secret(app, client)
    body = client.get("/").get_data(as_text=True)
    for literal in (
        'id="service-preferences-dialog"',
        "data-service-order-list",
        "data-move-service",
        "Serviço inicial",
        "Salvar preferências",
        "data-no-submit-lock",
        "data-service-chip",
        "Organizar serviços",
    ):
        assert literal in body


def test_service_preferences_script_and_touch_contract(client):
    script = client.get("/static/js/app.js").get_data(as_text=True)
    css = client.get("/static/css/app.css").get_data(as_text=True)
    assert "localStorage" not in script
    assert "sessionStorage" not in script
    build = script.index("const body = new URLSearchParams(new FormData(servicePreferencesForm))")
    disable = script.index("controls.forEach((control) => { control.disabled = true; })", build)
    assert build < disable
    for literal in (
        "Preferências de serviços salvas.",
        "Preferências de serviços inválidas.",
        "Não foi possível salvar as preferências.",
        "restoreServicePreferences",
        'servicePreferencesDialog.addEventListener("cancel"',
        'event.target === servicePreferencesDialog',
    ):
        assert literal in script
    coarse = css.index("@media (pointer: coarse)")
    assert ".service-order-button { width: 2.75rem; height: 2.75rem; }" in css[coarse:]
    assert "overflow-wrap: anywhere" in css


def test_admin_menu_groups_destinations_and_marks_current_page(app, client):
    login = client.post("/login", data={"username": "admin", "password": "admin-password-0123456789"})
    assert login.status_code == 302
    body = client.get("/admin/users").get_data(as_text=True)

    panel_start = body.index('<nav class="admin-menu-panel"')
    panel = body[panel_start:body.index("</nav>", panel_start)]

    for href in (
        "/admin/users",
        "/admin/service-access",
        "/admin/audit",
        "/admin/security-integrations",
        "/admin/settings",
    ):
        assert panel.count(f'href="{href}"') == 1
    for description in (
        "Contas e papéis",
        "Permissões por serviço",
        "Eventos e integridade",
        "Alertas de segurança",
        "Controles globais",
    ):
        assert panel.count(description) == 1

    # the current page's item carries both is-current and aria-current, attribute order aside
    users_anchor = re.search(r'<a\b[^>]*href="/admin/users"[^>]*>', panel)
    assert users_anchor is not None
    tag = users_anchor.group(0)
    assert "admin-menu-item is-current" in tag
    assert 'aria-current="page"' in tag

    # general actions stay outside the admin panel
    assert 'href="/coverage"' not in panel
    assert 'href="/account"' not in panel
    assert 'action="/logout"' not in panel


def test_service_delete_confirm_names_blast_radius_for_admin(app, client):
    # Log in as the bootstrapped admin so the delete form renders.
    login = client.post("/login", data={"username": "admin", "password": "admin-password-0123456789"})
    assert login.status_code == 302
    add = client.post("/service/add", data={"name": "Cofre"})
    service_id = parse_qs(urlsplit(add.headers["Location"]).query)["service"][0]

    body = client.get(f"/?service={service_id}").get_data(as_text=True)
    assert "conta(s)?" in body
    assert "«Cofre»" in body


def test_base_template_has_favicon_and_header_user(app, client):
    seed_authenticated_secret(app, client)
    body = client.get("/").get_data(as_text=True)

    assert 'rel="icon"' in body
    assert "favicon.svg" in body
    assert "header-user" in body

    favicon = client.get("/static/favicon.svg")
    assert favicon.status_code == 200
    assert b"<svg" in favicon.get_data()


def test_auth_templates_have_password_toggles_and_autofocus(app, client):
    login = client.get("/login").get_data(as_text=True)
    assert "data-password-toggle" in login
    assert "autofocus" in login
    assert "password-field" in login


def test_app_js_preserves_hard_invariants_and_new_hooks(client):
    script = client.get("/static/js/app.js").get_data(as_text=True)

    # forbidden storage
    assert "localStorage" not in script
    assert "sessionStorage" not in script
    # pinned invariants
    for literal in (
        "AbortController",
        ".abort()",
        "document.hidden",
        "secretState",
        "visibilitychange",
        "30000",
        "navigator.clipboard.writeText",
        "field.value = csrfToken",
        "syncCsrfFields(document)",
        '"pageshow"',
        "Math.min(expiresIn, 30) * 1000 || 30000",
    ):
        assert literal in script
    # new behaviors
    assert "data-password-toggle" in script
    assert "data-feedback" in script
    assert 'searchParams.has("ok")' in script
    assert "confirm-dialog" in script
    assert "Limite de revelações atingido" in script
    assert "is-expiring" in script


def test_fetch_update_builds_body_before_disabling_control(client):
    # Disabled controls are excluded from FormData; the payload MUST be
    # snapshotted before the control is disabled, or status/registered
    # updates POST an empty field and the server 400s.
    script = client.get("/static/js/app.js").get_data(as_text=True)
    fetch_updates = script.index('form.hasAttribute("data-fetch-update")')
    build = script.index("new URLSearchParams(new FormData(form))", fetch_updates)
    disable = script.index("control.disabled = true", build)
    assert build < disable


def test_mobile_cards_drop_table_min_width(client):
    # The card layout requires min-width:0 inside the ≤48rem media query,
    # otherwise table.accounts keeps its 48rem floor and pans horizontally.
    css = client.get("/static/css/app.css").get_data(as_text=True)
    media = css.index("@media (max-width: 48rem)")
    assert "table.accounts { min-width: 0; }" in css[media:]


def test_css_disclosure_uses_chevron_not_plus_minus(client):
    css = client.get("/static/css/app.css").get_data(as_text=True)

    assert 'content: "+ "' not in css
    assert "\\2212" not in css
    assert ".field-addition[open] > summary::before { transform: rotate(90deg); }" in css
    assert ".password-toggle" in css
    assert ".toast" in css
    assert "@media (pointer: coarse)" in css


def test_add_duplicate_email_json_for_fetch_and_styled_html_for_forms(app, client):
    service_id, _ = seed_authenticated_secret(app, client)
    data = {"service_id": service_id, "email": "dup@example.com", "password": "x", "status": "ativo"}

    assert client.post("/add", data=data).status_code == 302
    json_error = client.post("/add", data=data, headers={"Accept": "application/json"})
    html_error = client.post("/add", data=data)

    assert json_error.status_code == html_error.status_code == 400
    assert json_error.get_json() == {"error": "Email já cadastrado"}
    html = html_error.get_data(as_text=True)
    assert "Email já cadastrado" in html
    assert "error-card" in html


def test_field_mutations_redirect_with_row_anchor(app, client):
    service_id, account_id = seed_authenticated_secret(app, client)
    created = client.post(
        "/field/add",
        data={"service_id": service_id, "account_ids": account_id, "name": "Doc", "value": "v"},
    )

    assert created.status_code == 302
    assert created.headers["Location"].endswith(f"#row-{account_id}")
    with app.app_context():
        field_id = get_db().execute("SELECT id FROM custom_fields WHERE service_id=? AND name='Doc'", (service_id,)).fetchone()["id"]
    updated = client.post(f"/field/update/{field_id}/{account_id}", data={"service_id": service_id, "value": "next"})

    assert updated.status_code == 302
    assert updated.headers["Location"].endswith(f"#row-{account_id}")


def test_index_carries_a11y_and_async_hooks(app, client):
    service_id, _ = seed_authenticated_secret(app, client)
    body = client.get(f"/?service={service_id}").get_data(as_text=True)
    base = client.get("/").get_data(as_text=True)

    assert body.count("data-async-form") == 2
    for hook in (
        "data-form-error",
        'aria-current="page"',
        'aria-labelledby="edit-dialog-title"',
        'aria-labelledby="confirm-dialog-message"',
        'id="save-announcer"',
        'class="th-sort"',
        'aria-sort="none"',
        "data-password-toggle",
    ):
        assert hook in body
    assert 'class="skip-link"' in base
    assert 'id="main"' in base


def test_app_js_new_behaviors(client):
    script = client.get("/static/js/app.js").get_data(as_text=True)

    for literal in (
        "response.redirected",
        "is-loading",
        "toast toast-error",
        "is-copied",
        "#row-",
        "Status salvo.",
        "Cadastro salvo.",
        "data-async-form",
        "th-sort",
        '"added"',
        'searchParams.has("ok")',
        '[data-row-select], [data-autosubmit]',
    ):
        assert literal in script


def test_app_js_bulk_selection_persists_and_typed_delete(client):
    script = client.get("/static/js/app.js").get_data(as_text=True)

    # Selection must survive hidden rows: refreshBulkSelection only re-renders, never deletes.
    start = script.index("refreshBulkSelection = () => {")
    end = script.index("}", start)
    assert "selectedAccountIds.delete" not in script[start:end]
    for literal in (
        "visíveis",
        "confirmation_count",
        "delete-confirm-dialog",
        "delete-confirm-input",
        "/accounts/bulk/field",
        "bulk-apply-field",
        "bulk-add-field",
        "bulk-field-dialog",
        "selectedAccountIds",
        "new URLSearchParams",
        "Adicionando…",
        "Informe o nome do campo.",
        "Não foi possível adicionar o campo.",
        "bulkFieldForm.dataset.submitting",
    ):
        assert literal in script
    # No browser storage of selection/state.
    assert "localStorage" not in script
    assert "sessionStorage" not in script
    # The bulk-field body (with account_ids) MUST be built before controls are disabled,
    # otherwise disabled inputs drop from any FormData-derived payload and the ids are lost.
    build = script.index('body.append("field_name"')
    disable = script.index("control.disabled = true", build)
    assert build < disable
    # Success navigates to the followed redirect URL so the new empty fields render.
    assert "window.location.assign(response.url)" in script


def test_app_js_coverage_filter_navigates_server_side(client):
    script = client.get("/static/js/app.js").get_data(as_text=True)

    # The filter form drives a server-side query; showing the selected-service
    # fieldset for missing-registration is the only client-side behavior kept.
    for literal in ("coverage-form", "missing-registration", "coverage-service-filter", "requestSubmit"):
        assert literal in script
    # The full-table client-side row scan is gone.
    assert 'getAttribute("data-reg-svc-"' not in script
    assert "coverageRows" not in script


def test_app_js_rotation_filter_combines_with_url_state(client):
    script = client.get("/static/js/app.js").get_data(as_text=True)

    for literal in (
        "filter-rotation",
        "navigateAccounts",
        'set("rot"',
    ):
        assert literal in script

def test_css_new_rules(client):
    css = client.get("/static/css/app.css").get_data(as_text=True)

    for rule in (
        ".skip-link",
        ".toast-error",
        ".copy-button.is-copied",
        "@media (min-width: 34rem)",
        'th[aria-sort="ascending"]',
        ".coverage-service-label",
        ".rotation-badge",
        ".admin-menu-panel",
        ".column-filter",
    ):
        assert rule in css
    assert "bottom: calc(100% + .2rem)" not in css
    media = css.index("@media (max-width: 48rem)")
    assert "table.accounts thead tr { display: grid" in css[media:]
