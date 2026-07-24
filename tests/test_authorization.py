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
from werkzeug.datastructures import MultiDict

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


def test_service_preferences_persist_order_initial_and_explicit_precedence(app):
    client = app.test_client()
    user_id = _user(app, username="ordered")
    alpha = _service(app, "Alpha")
    beta = _service(app, "Beta")
    zulu = _service(app, "Zulu")
    for service_id in (alpha, beta, zulu):
        _membership(app, user_id, service_id, "viewer")
    _set_session(client, user_id=user_id, role="operador")

    initial_body = client.get("/").get_data(as_text=True)
    assert initial_body.index("Alpha") < initial_body.index("Beta") < initial_body.index("Zulu")
    assert "Serviço selecionado: <strong class=\"ink-strong\">Alpha</strong>" in initial_body

    response = client.post(
        "/preferences/services",
        data=MultiDict([
            ("service_ids", str(zulu)),
            ("service_ids", str(alpha)),
            ("service_ids", str(beta)),
            ("initial_service_id", str(beta)),
        ]),
    )
    assert response.status_code == 204
    with app.app_context():
        conn = get_db()
        rows = conn.execute(
            "SELECT service_id, position, is_initial FROM user_service_preferences WHERE user_id=? ORDER BY position",
            (user_id,),
        ).fetchall()
        assert [tuple(row) for row in rows] == [(zulu, 0, 0), (alpha, 1, 0), (beta, 2, 1)]
        audit = conn.execute(
            "SELECT target_id, metadata_json FROM audit_events WHERE action='preferences.services_updated'"
        ).fetchone()
        assert audit["target_id"] == str(user_id)
        assert json.loads(audit["metadata_json"]) == {"initial_service_id": beta, "service_count": 3}

    body = client.get("/").get_data(as_text=True)
    assert "Serviço selecionado: <strong class=\"ink-strong\">Beta</strong>" in body
    assert body.index(">Zulu</a>") < body.index(">Alpha</a>") < body.index(">Beta</a>")
    explicit = client.get(f"/?service={alpha}").get_data(as_text=True)
    assert "Serviço selecionado: <strong class=\"ink-strong\">Alpha</strong>" in explicit
    with app.app_context():
        assert get_db().execute(
            "SELECT service_id FROM user_service_preferences WHERE user_id=? AND is_initial=1",
            (user_id,),
        ).fetchone()["service_id"] == beta


@pytest.mark.parametrize(
    "payload",
    [
        [("service_ids", "1")],
        [("service_ids", "1"), ("service_ids", "1"), ("initial_service_id", "1")],
        [("service_ids", "0"), ("initial_service_id", "1")],
        [("service_ids", "01"), ("initial_service_id", "1")],
        [("service_ids", "+1"), ("initial_service_id", "1")],
        [("service_ids", " 1"), ("initial_service_id", "1")],
        [("service_ids", "١"), ("initial_service_id", "1")],
        [("service_ids", "1"), ("initial_service_id", "1"), ("initial_service_id", "1")],
        [("service_ids", "1"), ("initial_service_id", "2")],
    ],
)
def test_invalid_service_preferences_roll_back(app, payload):
    client = app.test_client()
    user_id = _user(app, username="invalid")
    service_id = _service(app, "Alpha")
    _membership(app, user_id, service_id, "viewer")
    _set_session(client, user_id=user_id, role="operador")
    valid = client.post(
        "/preferences/services",
        data=MultiDict([("service_ids", str(service_id)), ("initial_service_id", str(service_id))]),
    )
    assert valid.status_code == 204
    response = client.post("/preferences/services", data=MultiDict(payload))
    assert response.status_code == 400
    with app.app_context():
        row = get_db().execute(
            "SELECT service_id, position, is_initial FROM user_service_preferences WHERE user_id=?",
            (user_id,),
        ).fetchone()
        assert tuple(row) == (service_id, 0, 1)


def test_service_preference_scope_new_access_and_revoke_cleanup(app):
    operator = app.test_client()
    admin_client = app.test_client()
    admin_id = _user(app, username="root", role="admin")
    user_id = _user(app, username="scoped")
    alpha = _service(app, "Alpha")
    zulu = _service(app, "Zulu")
    _membership(app, user_id, zulu, "viewer")
    _set_session(operator, user_id=user_id, role="operador")
    assert operator.post(
        "/preferences/services",
        data=MultiDict([("service_ids", str(zulu)), ("initial_service_id", str(zulu))]),
    ).status_code == 204
    _membership(app, user_id, alpha, "viewer")
    with app.app_context():
        user = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        assert [row["id"] for row in accessible_services(get_db(), user)] == [zulu, alpha]

    _set_session(admin_client, user_id=admin_id, role="admin", reauth=True)
    assert admin_client.post(f"/admin/service-access/{zulu}/{user_id}/delete").status_code == 204
    with app.app_context():
        assert get_db().execute(
            "SELECT COUNT(*) FROM user_service_preferences WHERE user_id=? AND service_id=?",
            (user_id, zulu),
        ).fetchone()[0] == 0
    body = operator.get("/").get_data(as_text=True)
    assert "Serviço selecionado: <strong class=\"ink-strong\">Alpha</strong>" in body


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


def _seed_account(app, email: str) -> int:
    with app.app_context():
        conn = get_db()
        aid = inserted_id(conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
            (email, b"c", b"0" * 12),
        ))
        conn.commit()
        return aid


def _seed_link(app, account_id: int, service_id: int) -> None:
    with app.app_context():
        conn = get_db()
        conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (account_id, service_id))
        conn.commit()


def _subscribe_authz_failure(app) -> None:
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            cid = inserted_id(conn.execute(
                "INSERT INTO webhook_configs (destination_host, url_ciphertext, url_nonce, url_key_version, signing_secret_ciphertext, signing_secret_nonce, signing_secret_key_version, created_at, updated_at) VALUES ('h.test', ?, ?, 1, ?, ?, 1, ?, ?)",
                (b"u", b"0" * 12, b"s", b"1" * 12, datetime.now(UTC).isoformat(), datetime.now(UTC).isoformat()),
            ))
            conn.execute("INSERT INTO webhook_subscriptions (config_id, event_type) VALUES (?, 'authorization_failure')", (cid,))


def _count_selects(conn, thunk):
    selects = 0

    def _trace(statement: str) -> None:
        nonlocal selects
        if statement.strip().upper().startswith("SELECT"):
            selects += 1

    conn.set_trace_callback(_trace)
    try:
        result = thunk()
    finally:
        conn.set_trace_callback(None)
    return result, selects


def test_require_accounts_role_ordinary_reads_are_constant_for_200_accounts(app):
    from service_manager.authorization import require_accounts_role

    op = _user(app, username="op")
    sid = _service(app, "Bulk")
    _membership(app, op, sid, "editor")
    with app.app_context():
        conn = get_db()
        ids = []
        for i in range(200):
            aid = inserted_id(conn.execute(
                "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
                (f"ord-{i}@e.test", b"c", b"0" * 12),
            ))
            conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (aid, sid))
            ids.append(aid)
        conn.commit()
    with app.test_request_context("/x", method="POST"):
        g.current_user = _row(app, op)
        conn = get_db()
        role1, n1 = _count_selects(conn, lambda: require_accounts_role(conn, ids[:1], sid, "editor"))
        role200, n200 = _count_selects(conn, lambda: require_accounts_role(conn, ids, sid, "editor"))
    assert role1 == "editor"
    assert role200 == "editor"
    assert n1 == 2
    assert n200 == 2


def test_require_accounts_role_all_linked_reads_are_constant_for_200_accounts(app):
    from service_manager.authorization import require_accounts_role

    op = _user(app, username="op")
    s1 = _service(app, "Init")
    s2 = _service(app, "Two")
    s3 = _service(app, "Three")
    for sid in (s1, s2, s3):
        _membership(app, op, sid, "service_admin")
    with app.app_context():
        conn = get_db()
        ids = []
        for i in range(200):
            aid = inserted_id(conn.execute(
                "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
                (f"all-{i}@e.test", b"c", b"0" * 12),
            ))
            conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (aid, s1))
            if i > 0:
                conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (aid, s2))
                conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (aid, s3))
            ids.append(aid)
        conn.commit()
    with app.test_request_context("/x", method="POST"):
        g.current_user = _row(app, op)
        conn = get_db()
        role1, n1 = _count_selects(conn, lambda: require_accounts_role(conn, ids[:1], s1, "service_admin", all_linked_services=True))
        role200, n200 = _count_selects(conn, lambda: require_accounts_role(conn, ids, s1, "service_admin", all_linked_services=True))
    assert role1 == "service_admin"
    assert role200 == "service_admin"
    assert n1 == 3
    assert n200 == 3


def test_require_accounts_role_preserves_mixed_failure_order(app):
    from service_manager.authorization import require_accounts_role
    from werkzeug.exceptions import Forbidden, NotFound

    op = _user(app, username="op")
    s1 = _service(app, "Init")
    _membership(app, op, s1, "viewer")  # below editor
    _subscribe_authz_failure(app)
    linked = _seed_account(app, "linked@e.test")
    missing = _seed_account(app, "missing@e.test")
    _seed_link(app, linked, s1)

    with app.test_request_context("/x", method="POST"):
        g.current_user = _row(app, op)
        conn = get_db()
        with pytest.raises(NotFound):
            require_accounts_role(conn, [missing, linked], s1, "editor")
    with app.app_context():
        conn = get_db()
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='authorization.failed'").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM webhook_deliveries WHERE event_type='authorization_failure'").fetchone()[0] == 0

    with app.test_request_context("/x", method="POST"):
        g.current_user = _row(app, op)
        conn = get_db()
        with pytest.raises(Forbidden):
            require_accounts_role(conn, [linked, missing], s1, "editor")
    with app.app_context():
        conn = get_db()
        rows = conn.execute("SELECT target_type, target_id FROM audit_events WHERE action='authorization.failed'").fetchall()
        assert len(rows) == 1
        assert rows[0]["target_type"] == "service"
        assert rows[0]["target_id"] == str(s1)
        assert conn.execute("SELECT COUNT(*) FROM webhook_deliveries WHERE event_type='authorization_failure'").fetchone()[0] == 1


def test_require_accounts_role_global_admin_checks_every_initiating_link(app):
    from service_manager.authorization import require_accounts_role
    from werkzeug.exceptions import NotFound

    admin = _user(app, username="root", role="admin")
    s1 = _service(app, "Init")
    _subscribe_authz_failure(app)
    linked = _seed_account(app, "l@e.test")
    linked2 = _seed_account(app, "l2@e.test")
    missing = _seed_account(app, "m@e.test")
    _seed_link(app, linked, s1)
    _seed_link(app, linked2, s1)

    with app.test_request_context("/x", method="POST"):
        g.current_user = _row(app, admin)
        conn = get_db()
        with pytest.raises(NotFound):
            require_accounts_role(conn, [linked, missing], s1, "service_admin", all_linked_services=True)
    with app.app_context():
        conn = get_db()
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='authorization.failed'").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM webhook_deliveries WHERE event_type='authorization_failure'").fetchone()[0] == 0

    with app.test_request_context("/x", method="POST"):
        g.current_user = _row(app, admin)
        conn = get_db()
        role, n = _count_selects(conn, lambda: require_accounts_role(conn, [linked, linked2], s1, "service_admin", all_linked_services=True))
    assert role == "admin"
    assert n == 1


def test_require_accounts_role_all_linked_denial_targets_first_failing_account(app):
    from service_manager.authorization import require_accounts_role
    from werkzeug.exceptions import Forbidden

    op = _user(app, username="op")
    s1 = _service(app, "Init")
    s2 = _service(app, "Extra")
    _membership(app, op, s1, "service_admin")  # no membership on s2
    _subscribe_authz_failure(app)
    first = _seed_account(app, "first@e.test")
    second = _seed_account(app, "second@e.test")
    _seed_link(app, first, s1)
    _seed_link(app, second, s1)
    _seed_link(app, second, s2)

    with app.test_request_context("/x", method="POST"):
        g.current_user = _row(app, op)
        conn = get_db()
        with pytest.raises(Forbidden):
            require_accounts_role(conn, [first, second], s1, "service_admin", all_linked_services=True)
    with app.app_context():
        conn = get_db()
        rows = conn.execute("SELECT target_type, target_id, metadata_json FROM audit_events WHERE action='authorization.failed'").fetchall()
        assert len(rows) == 1
        assert rows[0]["target_type"] == "account"
        assert rows[0]["target_id"] == str(second)
        meta = json.loads(rows[0]["metadata_json"])
        assert meta["service_id"] == s1
        assert meta["required_role"] == "service_admin"
        deliveries = conn.execute("SELECT payload_json FROM webhook_deliveries WHERE event_type='authorization_failure'").fetchall()
        assert len(deliveries) == 1
        payload = json.loads(deliveries[0]["payload_json"])
        assert payload["details"]["service_id"] == s1
        assert payload["details"]["required_role"] == "service_admin"


def test_require_accounts_role_denial_side_effects_rollback_together(app, monkeypatch):
    from service_manager.authorization import require_accounts_role

    op = _user(app, username="op")
    s1 = _service(app, "Init")
    _membership(app, op, s1, "viewer")  # below editor
    _subscribe_authz_failure(app)
    aid = _seed_account(app, "a@e.test")
    _seed_link(app, aid, s1)

    def _boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("service_manager.authorization.enqueue_webhook_event", _boom)
    with app.test_request_context("/x", method="POST"):
        g.current_user = _row(app, op)
        conn = get_db()
        with pytest.raises(RuntimeError):
            require_accounts_role(conn, [aid], s1, "editor")
    with app.app_context():
        conn = get_db()
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='authorization.failed'").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM webhook_deliveries WHERE event_type='authorization_failure'").fetchone()[0] == 0
