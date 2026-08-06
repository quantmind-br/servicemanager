from __future__ import annotations

import base64
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
from service_manager.audit import verify_audit_chain
from service_manager.crypto import hash_password
from service_manager.db import get_db, inserted_id, transaction
from service_manager.operations import create_api_key, principal_from_user, revoke_api_key

KEY = base64.b64encode(b"a" * 32).decode("ascii")
ADMIN_PASSWORD = "admin-password-0123456789"


@pytest.fixture()
def app(tmp_path: Path):
    return create_app(
        {
            "TESTING": True,
            "PROPAGATE_EXCEPTIONS": False,
            "DATABASE_PATH": str(tmp_path / "api.db"),
            "DATA_KEY_V1": KEY,
            "AUDIT_KEY_V1": KEY,
            "SECRET_KEY": "api-contract-session-secret",
            "WTF_CSRF_ENABLED": False,
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": ADMIN_PASSWORD,
        }
    )


@pytest.fixture()
def client(app):
    return app.test_client()


def _admin_row(app):
    with app.app_context():
        row = get_db().execute("SELECT id, username, role FROM users WHERE username='admin'").fetchone()
        assert row is not None
        return dict(row)


def _mint_api_key(app, name: str = "agent-smoke") -> tuple[int, str]:
    admin = _admin_row(app)
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            key_id, token = create_api_key(conn, principal_from_user(admin), name)
    return key_id, token


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _login_admin(client, *, reauthenticated: bool = True) -> None:
    assert client.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 302
    with client.session_transaction() as session:
        if reauthenticated:
            session["reauthenticated_at"] = time.time()
        else:
            session["reauthenticated_at"] = None


def _login_operator(app, client) -> int:
    with app.app_context():
        conn = get_db()
        stamp = conn.execute("SELECT created_at FROM users WHERE username='admin'").fetchone()[0]
        user_id = inserted_id(
            conn.execute(
                "INSERT INTO users (username, password_hash, role, is_active, must_change_password, created_at, updated_at) "
                "VALUES (?, ?, 'operador', 1, 0, ?, ?)",
                ("operator", hash_password("operator-password-012345"), stamp, stamp),
            )
        )
        conn.commit()
    assert client.post("/login", data={"username": "operator", "password": "operator-password-012345"}).status_code == 302
    with client.session_transaction() as session:
        session["reauthenticated_at"] = time.time()
    return int(user_id)


def _row_for(html: str, key_name: str) -> str:
    marker = f"<strong>{key_name}</strong>"
    name_at = html.index(marker)
    row_start = html.rfind("<tr>", 0, name_at)
    row_end = html.index("</tr>", name_at) + len("</tr>")
    return html[row_start:row_end]


def _subscribe_destructive_action(app) -> None:
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            cid = inserted_id(
                conn.execute(
                    "INSERT INTO webhook_configs (destination_host, url_ciphertext, url_nonce, url_key_version, "
                    "signing_secret_ciphertext, signing_secret_nonce, signing_secret_key_version, created_at, updated_at) "
                    "VALUES ('h.test', ?, ?, 1, ?, ?, 1, ?, ?)",
                    (b"u", b"0" * 12, b"s", b"1" * 12, datetime.now(UTC).isoformat(), datetime.now(UTC).isoformat()),
                )
            )
            conn.execute(
                "INSERT INTO webhook_subscriptions (config_id, event_type) VALUES (?, 'destructive_admin_action')",
                (cid,),
            )


def test_api_key_auth_write_self_revoke_and_audit_chain(app, client):
    key_id, token = _mint_api_key(app, "agent-smoke")
    suffix = "alpha"

    unauth = client.get("/api/v1/services")
    assert unauth.status_code == 401
    assert unauth.headers.get("WWW-Authenticate") == 'Bearer realm="service-manager"'
    assert "no-store" in (unauth.headers.get("Cache-Control") or "")
    assert unauth.get_json()["error"]["code"] == "unauthorized"

    listed = client.get("/api/v1/services", headers=_auth_headers(token))
    assert listed.status_code == 200
    assert listed.get_json() == {"items": []}
    assert "no-store" in (listed.headers.get("Cache-Control") or "")

    created = client.post(
        "/api/v1/services",
        headers=_auth_headers(token),
        json={"name": f"Skill smoke {suffix}"},
    )
    assert created.status_code == 201
    service_id = created.get_json()["id"]
    assert isinstance(service_id, int)

    fetched = client.get(f"/api/v1/services/{service_id}", headers=_auth_headers(token))
    assert fetched.status_code == 200
    body = fetched.get_json()
    assert body["id"] == service_id
    assert body["name"] == f"Skill smoke {suffix}"

    revoked = client.delete(f"/api/v1/api-keys/{key_id}", headers=_auth_headers(token))
    assert revoked.status_code == 204

    after = client.get("/api/v1/services", headers=_auth_headers(token))
    assert after.status_code == 401
    assert after.get_json()["error"]["code"] == "unauthorized"

    with app.app_context():
        conn = get_db()
        events = conn.execute(
            "SELECT action, target_type, target_id, metadata_json FROM audit_events WHERE action IN (?, ?, ?) ORDER BY id",
            ("api_key.created", "service.created", "api_key.revoked"),
        ).fetchall()
        actions = [row["action"] for row in events]
        assert actions == ["api_key.created", "service.created", "api_key.revoked"]

        by_action = {row["action"]: row for row in events}
        created_meta = json.loads(by_action["api_key.created"]["metadata_json"])
        assert created_meta["name"] == "agent-smoke"
        # Bootstrap mint uses human principal — no api_key_* on created event.
        assert "api_key_id" not in created_meta

        service_meta = json.loads(by_action["service.created"]["metadata_json"])
        assert service_meta["api_key_id"] == key_id
        assert service_meta["api_key_name"] == "agent-smoke"
        assert by_action["service.created"]["target_id"] == str(service_id)

        revoked_meta = json.loads(by_action["api_key.revoked"]["metadata_json"])
        assert revoked_meta["api_key_id"] == key_id
        assert revoked_meta["api_key_name"] == "agent-smoke"
        assert revoked_meta["name"] == "agent-smoke"
        assert by_action["api_key.revoked"]["target_id"] == str(key_id)

        assert verify_audit_chain(conn) is True


def test_malformed_bearer_token_is_unauthorized(app, client):
    key_id, token = _mint_api_key(app, "format-check")
    assert key_id > 0

    missing_scheme = client.get("/api/v1/services", headers={"Authorization": token})
    assert missing_scheme.status_code == 401
    assert missing_scheme.get_json()["error"]["code"] == "unauthorized"

    bad_prefix = client.get("/api/v1/services", headers={"Authorization": "Bearer not-a-key"})
    assert bad_prefix.status_code == 401
    assert bad_prefix.get_json()["error"]["code"] == "unauthorized"

    truncated = client.get("/api/v1/services", headers={"Authorization": f"Bearer {token[:-1]}"})
    assert truncated.status_code == 401


def test_invalid_json_body_returns_domain_error(app, client):
    _, token = _mint_api_key(app, "json-check")
    response = client.post(
        "/api/v1/services",
        headers={**_auth_headers(token), "Content-Type": "application/json"},
        data="[1,2,3]",
    )
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "invalid_json"


def test_api_key_name_conflict_and_secret_cache_control(app, client):
    _mint_api_key(app, "dup-name")
    _, token = _mint_api_key(app, "creator")

    conflict = client.post(
        "/api/v1/api-keys",
        headers=_auth_headers(token),
        json={"name": "dup-name"},
    )
    assert conflict.status_code == 409
    assert conflict.get_json()["error"]["code"] == "name_conflict"

    created = client.post(
        "/api/v1/api-keys",
        headers=_auth_headers(token),
        json={"name": "fresh-secret"},
    )
    assert created.status_code == 201
    payload = created.get_json()
    assert "api_key" in payload and payload["api_key"].startswith("smk_v1_")
    assert created.headers.get("Cache-Control") == "no-store, private"


def test_admin_api_key_list_exposes_delete_for_active_and_revoked(app, client):
    active_id, _ = _mint_api_key(app, "ui-active-key")
    revoked_id, _ = _mint_api_key(app, "ui-revoked-key")
    admin = _admin_row(app)
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            revoke_api_key(conn, principal_from_user(admin), revoked_id)

    _login_admin(client)
    html = client.get("/admin/api-keys").get_data(as_text=True)
    active_row = _row_for(html, "ui-active-key")
    revoked_row = _row_for(html, "ui-revoked-key")
    confirm = (
        "Excluir esta API key permanentemente? Integrações que a usam deixarão de autenticar. "
        "Esta ação não pode ser desfeita."
    )

    for row, key_id in ((active_row, active_id), (revoked_row, revoked_id)):
        assert f"/admin/api-keys/{key_id}/delete" in row
        assert "Excluir" in row
        assert confirm in row
        assert 'name="csrf_token"' in row

    assert f"/admin/api-keys/{active_id}/revoke" in active_row
    assert "Revogar" in active_row
    assert f"/admin/api-keys/{revoked_id}/revoke" not in revoked_row
    assert "Revogar" not in revoked_row


def test_admin_api_key_delete_active_removes_row_blocks_auth_and_audits(app, client):
    key_id, token = _mint_api_key(app, "delete-active-key")
    admin = _admin_row(app)
    _subscribe_destructive_action(app)

    ok = client.get("/api/v1/services", headers=_auth_headers(token))
    assert ok.status_code == 200

    _login_admin(client)
    response = client.post(f"/admin/api-keys/{key_id}/delete")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin/api-keys?ok=api_key_deleted")

    listing = client.get(response.headers["Location"])
    assert listing.status_code == 200
    body = listing.get_data(as_text=True)
    assert "API key excluída." in body
    assert "delete-active-key" not in body

    with app.app_context():
        conn = get_db()
        assert conn.execute("SELECT 1 FROM api_keys WHERE id=?", (key_id,)).fetchone() is None
        event = conn.execute(
            "SELECT actor_user_id, target_type, target_id, metadata_json FROM audit_events WHERE action='api_key.deleted'"
        ).fetchone()
        assert event is not None
        assert event["actor_user_id"] == admin["id"]
        assert event["target_type"] == "api_key"
        assert event["target_id"] == str(key_id)
        assert json.loads(event["metadata_json"]) == {"name": "delete-active-key"}
        assert verify_audit_chain(conn) is True
        deliveries = conn.execute(
            "SELECT payload_json FROM webhook_deliveries WHERE event_type='destructive_admin_action'"
        ).fetchall()
        assert len(deliveries) == 1
        details = json.loads(deliveries[0]["payload_json"])["details"]
        assert details == {
            "action": "api_key.deleted",
            "actor_user_id": admin["id"],
            "target_id": key_id,
            "target_type": "api_key",
        }

    denied = client.get("/api/v1/services", headers=_auth_headers(token))
    assert denied.status_code == 401
    assert denied.get_json()["error"]["code"] == "unauthorized"


def test_admin_api_key_delete_revoked_removes_row(app, client):
    key_id, _ = _mint_api_key(app, "delete-revoked-key")
    admin = _admin_row(app)
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            revoke_api_key(conn, principal_from_user(admin), key_id)

    _login_admin(client)
    response = client.post(f"/admin/api-keys/{key_id}/delete")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin/api-keys?ok=api_key_deleted")

    body = client.get("/admin/api-keys").get_data(as_text=True)
    assert "delete-revoked-key" not in body

    with app.app_context():
        conn = get_db()
        assert conn.execute("SELECT 1 FROM api_keys WHERE id=?", (key_id,)).fetchone() is None
        actions = [
            row["action"]
            for row in conn.execute(
                "SELECT action FROM audit_events WHERE target_type='api_key' AND target_id=? ORDER BY id",
                (str(key_id),),
            )
        ]
        assert "api_key.revoked" in actions
        assert "api_key.deleted" in actions
        assert actions.index("api_key.revoked") < actions.index("api_key.deleted")


def test_admin_api_key_delete_rejects_missing_unauthorized_and_stale_reauth(app, client):
    first_id, _ = _mint_api_key(app, "guard-first-key")
    second_id, _ = _mint_api_key(app, "guard-second-key")

    missing_client = app.test_client()
    _login_admin(missing_client)
    missing = missing_client.post("/admin/api-keys/999999/delete")
    assert missing.status_code == 404

    operator_client = app.test_client()
    _login_operator(app, operator_client)
    forbidden = operator_client.post(f"/admin/api-keys/{first_id}/delete")
    assert forbidden.status_code == 403

    stale_client = app.test_client()
    _login_admin(stale_client, reauthenticated=False)
    stale = stale_client.post(f"/admin/api-keys/{second_id}/delete")
    assert stale.status_code == 403

    with app.app_context():
        conn = get_db()
        assert conn.execute("SELECT 1 FROM api_keys WHERE id=?", (first_id,)).fetchone() is not None
        assert conn.execute("SELECT 1 FROM api_keys WHERE id=?", (second_id,)).fetchone() is not None
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='api_key.deleted'").fetchone()[0] == 0
