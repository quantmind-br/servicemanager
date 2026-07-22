from __future__ import annotations

import base64
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from flask import g

from app import create_app
from service_manager.authorization import (
    SERVICE_ROLE_RANK,
    accessible_services,
    get_user_service_role,
)
from service_manager.crypto import hash_password
from service_manager.db import get_db, inserted_id, transaction

KEY = base64.b64encode(b"k" * 32).decode("ascii")


def make_app(tmp_path: Path, **config: object):
    return create_app(
        {
            "TESTING": True,
            "PROPAGATE_EXCEPTIONS": False,
            "DATABASE_PATH": str(tmp_path / "authz.db"),
            "DATA_KEY_V1": KEY,
            "AUDIT_KEY_V1": KEY,
            "SECRET_KEY": "s" * 32,
            **config,
        }
    )


@pytest.fixture()
def app(tmp_path: Path):
    return make_app(tmp_path)


def _user(app, *, username: str, role: str = "operador", active: bool = True) -> int:
    with app.app_context():
        stamp = datetime.now(UTC).isoformat()
        uid = inserted_id(get_db().execute(
            "INSERT INTO users (username, password_hash, role, is_active, must_change_password, created_at, updated_at, password_changed_at) VALUES (?, ?, ?, ?, 0, ?, ?, ?)",
            (username, hash_password("x" * 16), role, int(active), stamp, stamp, stamp),
        ))
        get_db().commit()
        return uid


def _service(app, name: str) -> int:
    with app.app_context():
        sid = inserted_id(get_db().execute("INSERT INTO services (name) VALUES (?)", (name,)))
        get_db().commit()
        return sid


def _membership(app, user_id: int, service_id: int, role: str) -> None:
    with app.app_context():
        get_db().execute(
            "INSERT INTO service_members (user_id, service_id, role, created_at) VALUES (?, ?, ?, ?)",
            (user_id, service_id, role, datetime.now(UTC).isoformat()),
        )
        get_db().commit()


def _set_session(client, *, user_id: int, role: str, reauth: bool = False) -> None:
    with client.session_transaction() as session:
        now = time.time()
        session.update(user_id=user_id, role=role, session_version=0, authenticated_at=now, last_seen_at=now, reauthenticated_at=now if reauth else None)


def test_role_rank_ordering():
    assert SERVICE_ROLE_RANK["viewer"] < SERVICE_ROLE_RANK["editor"] < SERVICE_ROLE_RANK["service_admin"]


def test_get_user_service_role_admin_and_membership(app):
    admin = _user(app, username="glob", role="admin")
    op = _user(app, username="op")
    sid = _service(app, "Mail")
    _membership(app, op, sid, "editor")
    with app.app_context():
        conn = get_db()
        admin_row = conn.execute("SELECT * FROM users WHERE id=?", (admin,)).fetchone()
        op_row = conn.execute("SELECT * FROM users WHERE id=?", (op,)).fetchone()
        assert get_user_service_role(conn, admin_row, sid) == "admin"
        assert get_user_service_role(conn, op_row, sid) == "editor"
        assert get_user_service_role(conn, op_row, sid + 999) is None


def test_accessible_services_scopes_non_admin(app):
    admin = _user(app, username="glob", role="admin")
    op = _user(app, username="op")
    s1 = _service(app, "Alpha")
    s2 = _service(app, "Beta")
    _membership(app, op, s1, "viewer")
    with app.app_context():
        conn = get_db()
        admin_row = conn.execute("SELECT * FROM users WHERE id=?", (admin,)).fetchone()
        op_row = conn.execute("SELECT * FROM users WHERE id=?", (op,)).fetchone()
        assert {r["id"] for r in accessible_services(conn, admin_row)} == {s1, s2}
        assert {r["id"] for r in accessible_services(conn, op_row)} == {s1}


def test_index_returns_403_for_inaccessible_service_and_404_for_missing(app):
    client = app.test_client()
    op = _user(app, username="op")
    s1 = _service(app, "Alpha")
    s2 = _service(app, "Beta")
    _membership(app, op, s1, "viewer")
    _set_session(client, user_id=op, role="operador")
    assert client.get(f"/?service={s1}").status_code == 200
    assert client.get(f"/?service={s2}").status_code == 403
    assert client.get("/?service=99999").status_code == 404


def test_index_empty_state_for_member_less_operator(app):
    client = app.test_client()
    op = _user(app, username="lonely")
    _service(app, "Alpha")
    _set_session(client, user_id=op, role="operador")
    body = client.get("/").get_data(as_text=True)
    assert "Você não possui acesso a nenhum serviço" in body


def test_promotion_to_admin_clears_memberships(app):
    client = app.test_client()
    admin = _user(app, username="root", role="admin")
    op = _user(app, username="op")
    s1 = _service(app, "Alpha")
    _membership(app, op, s1, "editor")
    _set_session(client, user_id=admin, role="admin", reauth=True)
    resp = client.post(f"/admin/users/{op}/role", data={"role": "admin"})
    assert resp.status_code == 204
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM service_members WHERE user_id=?", (op,)).fetchone()[0] == 0


def test_demotion_to_operator_backfills_service_admin(app):
    client = app.test_client()
    root = _user(app, username="root", role="admin")
    other = _user(app, username="other", role="admin")
    s1 = _service(app, "Alpha")
    s2 = _service(app, "Beta")
    _set_session(client, user_id=root, role="admin", reauth=True)
    resp = client.post(f"/admin/users/{other}/role", data={"role": "operador"})
    assert resp.status_code == 204
    with app.app_context():
        rows = get_db().execute("SELECT service_id, role FROM service_members WHERE user_id=?", (other,)).fetchall()
        assert {(r["service_id"], r["role"]) for r in rows} == {(s1, "service_admin"), (s2, "service_admin")}


def test_role_change_audit_records_membership_count(app):
    client = app.test_client()
    root = _user(app, username="root", role="admin")
    other = _user(app, username="other", role="admin")
    _service(app, "Alpha")
    _service(app, "Beta")
    _set_session(client, user_id=root, role="admin", reauth=True)
    client.post(f"/admin/users/{other}/role", data={"role": "operador"})
    with app.app_context():
        meta = json.loads(get_db().execute("SELECT metadata_json FROM audit_events WHERE action='user.role_changed'").fetchone()[0])
        assert meta["membership_count"] == 2


def test_global_role_denial_commits_atomic_audit_and_webhook(app):
    client = app.test_client()
    _user(app, username="root", role="admin")
    op = _user(app, username="op")
    # Subscribe a webhook to authorization_failure so a delivery must be enqueued.
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            cid = inserted_id(conn.execute(
                "INSERT INTO webhook_configs (destination_host, url_ciphertext, url_nonce, url_key_version, signing_secret_ciphertext, signing_secret_nonce, signing_secret_key_version, created_at, updated_at) VALUES ('h.test', ?, ?, 1, ?, ?, 1, ?, ?)",
                (b"u", b"0" * 12, b"s", b"1" * 12, datetime.now(UTC).isoformat(), datetime.now(UTC).isoformat()),
            ))
            conn.execute("INSERT INTO webhook_subscriptions (config_id, event_type) VALUES (?, 'authorization_failure')", (cid,))
    _set_session(client, user_id=op, role="operador")
    # /admin/audit requires role admin -> operator denied.
    resp = client.get("/admin/audit")
    assert resp.status_code == 403
    with app.app_context():
        conn = get_db()
        audit = conn.execute("SELECT metadata_json FROM audit_events WHERE action='authorization.failed'").fetchone()
        assert audit is not None
        meta = json.loads(audit["metadata_json"])
        assert meta["method"] == "GET" and "endpoint" in meta
        delivery = conn.execute("SELECT payload_json FROM webhook_deliveries WHERE event_type='authorization_failure'").fetchone()
        assert delivery is not None
        payload = json.loads(delivery["payload_json"])
        assert payload["event"] == "authorization_failure"
        assert payload["details"]["actor_user_id"] == op
        assert payload["details"]["method"] == "GET"
        assert "endpoint" in payload["details"]


def test_require_service_role_rank_and_global_bypass(app):
    from service_manager.authorization import require_service_role
    from werkzeug.exceptions import Forbidden

    admin = _user(app, username="root", role="admin")
    op = _user(app, username="op")
    sid = _service(app, "Mail")
    _membership(app, op, sid, "editor")
    client = app.test_client()
    with app.test_request_context("/x", method="POST"):
        g.current_user = _row(app, admin)
        conn = get_db()
        assert require_service_role(conn, sid, "service_admin") == "admin"  # global bypass
        g.current_user = _row(app, op)
        assert require_service_role(conn, sid, "editor") == "editor"
        assert require_service_role(conn, sid, "viewer") == "editor"  # rank >= viewer
        with pytest.raises(Forbidden):
            require_service_role(conn, sid, "service_admin")
    # Denial committed an audit event.
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM audit_events WHERE action='authorization.failed'").fetchone()[0] == 1


def test_require_account_role_initiating_link_404_and_all_links_denial(app):
    from service_manager.authorization import require_account_role
    from werkzeug.exceptions import NotFound, Forbidden

    op = _user(app, username="op")
    s1 = _service(app, "Alpha")
    s2 = _service(app, "Beta")
    _membership(app, op, s1, "service_admin")
    _membership(app, op, s2, "viewer")
    with app.app_context():
        conn = get_db()
        aid = inserted_id(conn.execute("INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES ('a@e.test', ?, ?, 1)", (b"c", b"0" * 12)))
        conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (aid, s1))
        conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (aid, s2))
        conn.commit()
    with app.test_request_context("/x", method="POST"):
        g.current_user = _row(app, op)
        conn = get_db()
        # Not linked to initiating service -> 404.
        with pytest.raises(NotFound):
            require_account_role(conn, aid, s1 + 999, "viewer")
        # all_linked_services requires service_admin on EVERY link; op is only viewer on s2 -> denied.
        with pytest.raises(Forbidden):
            require_account_role(conn, aid, s1, "service_admin", all_linked_services=True)


def _row(app, user_id: int):
    return get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
