from __future__ import annotations

import base64
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
from service_manager.db import get_db
from service_manager.crypto import account_field_aad, account_password_aad, encrypt_secret


KEY = base64.b64encode(b"f" * 32).decode("ascii")
ADMIN_PASSWORD = "admin-password-0123456789"


@pytest.fixture()
def app(tmp_path: Path):
    return create_app(
        {
            "TESTING": True,
            "PROPAGATE_EXCEPTIONS": False,
            "DATABASE_PATH": str(tmp_path / "feature-pack.db"),
            "DATA_KEY_V1": KEY,
            "AUDIT_KEY_V1": KEY,
            "SECRET_KEY": "feature-pack-session-secret",
            "WTF_CSRF_ENABLED": False,
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": ADMIN_PASSWORD,
        }
    )


@pytest.fixture()
def client(app):
    return app.test_client()


def login_admin(client) -> None:
    response = client.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD})
    assert response.status_code == 302

def login_operator(app, client) -> None:
    with app.app_context():
        conn = get_db()
        admin = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        stamp = conn.execute("SELECT created_at FROM users WHERE id=?", (admin["id"],)).fetchone()[0]
        from service_manager.crypto import hash_password

        conn.execute(
            "INSERT INTO users (username, password_hash, role, is_active, must_change_password, created_at, updated_at) VALUES (?, ?, 'operador', 1, 0, ?, ?)",
            ("operator", hash_password("operator-password-012345"), stamp, stamp),
        )
        conn.commit()
    response = client.post("/login", data={"username": "operator", "password": "operator-password-012345"})
    assert response.status_code == 302


def test_admin_users_renders_management_page(client):
    login_admin(client)

    response = client.get("/admin/users")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store, private"
    body = response.get_data(as_text=True)
    assert "data-admin-create" in body
    assert "data-admin-role" in body
    assert "data-admin-active" in body
    assert "admin" in body

    client.post("/logout")
    login_operator(client.application, client)
    assert client.get("/admin/users").status_code == 403


def test_admin_users_redirects_anonymous_user(client):
    response = client.get("/admin/users")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_index_renders_url_state_hooks(client):
    login_admin(client)
    with client.application.app_context():
        conn = get_db()
        service_id = conn.execute("INSERT INTO services (name) VALUES ('Email')").lastrowid
        account_id = conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES ('hook@example.test', ?, ?, 1)",
            (b"x", b"0" * 12),
        ).lastrowid
        conn.execute("INSERT INTO account_service (account_id, service_id, status, registered) VALUES (?, ?, 'ativo', 1)", (account_id, service_id))
        conn.commit()

    response = client.get("/")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'id="account-filter"' in body
    assert 'id="filter-status"' in body
    assert 'id="filter-registered"' in body
    assert 'id="share-view"' in body

    assert "data-row-select" in body

def seed_export_data(app) -> int:
    with app.app_context():
        conn = get_db()
        service_id = conn.execute("INSERT INTO services (name) VALUES ('Export')").lastrowid
        account_id = conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
            ("=formula@example.test", b"", b"0" * 12),
        ).lastrowid
        password = encrypt_secret("clear-password-must-not-export", aad=account_password_aad(account_id))
        conn.execute(
            "UPDATE accounts SET password_ciphertext=?, password_nonce=? WHERE id=?",
            (password.ciphertext, password.nonce, account_id),
        )
        conn.execute(
            "INSERT INTO account_service (account_id, service_id, status, registered) VALUES (?, ?, 'ativo', 1)",
            (account_id, service_id),
        )
        field_id = conn.execute("INSERT INTO custom_fields (service_id, name) VALUES (?, 'API key')", (service_id,)).lastrowid
        field = encrypt_secret("clear-field-must-not-export", aad=account_field_aad(account_id, field_id))
        conn.execute(
            "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, 1)",
            (field_id, account_id, field.ciphertext, field.nonce),
        )
        conn.commit()
        return service_id


def test_safe_csv_export_contains_no_secret_values(app, client):
    login_admin(client)
    service_id = seed_export_data(app)

    response = client.get(f"/export.csv?service={service_id}")

    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    body = response.get_data(as_text=True)
    assert "email,status,cadastrada,campos" in body
    assert "'=formula@example.test" in body
    assert "API key" in body
    assert "clear-password-must-not-export" not in body
    assert "clear-field-must-not-export" not in body


def test_safe_xlsx_export_uses_xlsx_mimetype(app, client):
    login_admin(client)
    service_id = seed_export_data(app)

    response = client.get(f"/export.xlsx?service={service_id}")

    assert response.status_code == 200
    assert response.mimetype == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def test_safe_exports_require_admin(app, client):
    service_id = seed_export_data(app)
    login_operator(app, client)

    assert client.get(f"/export.csv?service={service_id}").status_code == 403
    assert client.get(f"/export.xlsx?service={service_id}").status_code == 403


def seed_bulk_data(app) -> tuple[int, list[int], int]:
    with app.app_context():
        conn = get_db()
        service_id = conn.execute("INSERT INTO services (name) VALUES ('Bulk')").lastrowid
        other_service_id = conn.execute("INSERT INTO services (name) VALUES ('Other')").lastrowid
        account_ids = []
        for email in ("bulk-one@example.test", "bulk-two@example.test"):
            account_id = conn.execute(
                "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
                (email, b"x", b"0" * 12),
            ).lastrowid
            conn.execute("INSERT INTO account_service (account_id, service_id, status, registered) VALUES (?, ?, 'nunca', 0)", (account_id, service_id))
            account_ids.append(account_id)
        foreign_id = conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES ('foreign@example.test', ?, ?, 1)",
            (b"x", b"0" * 12),
        ).lastrowid
        conn.execute("INSERT INTO account_service (account_id, service_id, status, registered) VALUES (?, ?, 'nunca', 0)", (foreign_id, other_service_id))
        conn.commit()
        return service_id, account_ids, foreign_id


def test_bulk_status_updates_accounts_and_audits(app, client):
    login_admin(client)
    service_id, account_ids, _ = seed_bulk_data(app)

    response = client.post("/accounts/bulk/status", data={"service_id": service_id, "account_ids": account_ids, "status": "ativo"})

    assert response.status_code == 302
    assert "ok=bulk_updated" in response.headers["Location"]
    with app.app_context():
        conn = get_db()
        assert [row["status"] for row in conn.execute("SELECT status FROM account_service WHERE service_id=? ORDER BY account_id", (service_id,))] == ["ativo", "ativo"]
        event = conn.execute("SELECT metadata_json FROM audit_events WHERE action='accounts.bulk_status' ORDER BY id DESC LIMIT 1").fetchone()
        assert '"count":2' in event["metadata_json"]


def test_bulk_rejects_foreign_account_and_over_limit(app, client):
    login_admin(client)
    service_id, _, foreign_id = seed_bulk_data(app)

    assert client.post("/accounts/bulk/status", data={"service_id": service_id, "account_ids": [foreign_id], "status": "ativo"}).status_code == 404
    assert client.post("/accounts/bulk/status", data={"service_id": service_id, "account_ids": list(range(1, 202)), "status": "ativo"}).status_code == 400


def test_bulk_delete_requires_admin_and_removes_accounts(app, client):
    service_id, account_ids, _ = seed_bulk_data(app)
    login_operator(app, client)
    assert client.post("/accounts/bulk/delete", data={"service_id": service_id, "account_ids": account_ids}).status_code == 403
    client.post("/logout")
    login_admin(client)

    response = client.post("/accounts/bulk/delete", data={"service_id": service_id, "account_ids": account_ids})

    assert response.status_code == 302
    assert "ok=bulk_deleted" in response.headers["Location"]
    with app.app_context():
        conn = get_db()
        assert conn.execute("SELECT COUNT(*) FROM accounts WHERE id IN (?, ?)", account_ids).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='accounts.bulk_deleted'").fetchone()[0] == 1


def test_audit_view_filters_exports_and_requires_admin(app, client):
    login_admin(client)
    service_id, account_ids, _ = seed_bulk_data(app)
    client.post("/accounts/bulk/status", data={"service_id": service_id, "account_ids": account_ids, "status": "ativo"})

    response = client.get("/admin/audit")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "accounts.bulk_status" in body
    assert "Cadeia íntegra" in body

    filtered = client.get("/admin/audit?action=accounts.bulk_status").get_data(as_text=True)
    assert "login.succeeded" not in filtered
    assert "accounts.bulk_status" in filtered

    exported = client.get("/admin/audit.csv?action=accounts.bulk_status")
    assert exported.status_code == 200
    assert exported.get_data(as_text=True).startswith("\ufeffid,occurred_at,usuario,action,target_type,target_id,metadata_json,source_ip")

    client.post("/logout")
    login_operator(app, client)
    assert client.get("/admin/audit").status_code == 403
    assert client.get("/admin/audit.csv").status_code == 403


def test_coverage_matrix_renders_for_authenticated_user(app, client):
    service_id, account_ids, _ = seed_bulk_data(app)
    login_operator(app, client)

    response = client.get("/coverage")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Bulk" in body
    assert "bulk-one@example.test" in body
    assert f"/?service={service_id}#row-{account_ids[0]}" in body
    assert 'id="coverage-filter"' in body


def test_coverage_matrix_requires_authentication(client):
    response = client.get("/coverage")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")
