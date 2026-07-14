from __future__ import annotations

import base64
import json
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
from service_manager.crypto import hash_password, verify_password
from service_manager.db import SCHEMA, get_db

KEY = base64.b64encode(b"k" * 32).decode("ascii")
INITIAL_PASSWORD = "12345678"
NEW_PASSWORD = "a-new-password-with-at-least-sixteen-characters"


def make_app(tmp_path: Path, name: str = "auth.db", **config: object):
    return create_app(
        {
            "TESTING": True,
            "PROPAGATE_EXCEPTIONS": False,
            "DATABASE_PATH": str(tmp_path / name),
            "DATA_KEY_V1": KEY,
            "AUDIT_KEY_V1": KEY,
            "SECRET_KEY": "s" * 32,
            **config,
        }
    )


@pytest.fixture()
def app(tmp_path: Path):
    return make_app(tmp_path)


@pytest.fixture()
def client(app):
    return app.test_client()


def insert_user(
    app,
    *,
    username: str = "operator",
    password: str = NEW_PASSWORD,
    role: str = "operador",
    active: bool = True,
    must_change_password: bool = False,
) -> int:
    with app.app_context():
        stamp = datetime.now(UTC).isoformat()
        user_id = get_db().execute(
            "INSERT INTO users (username, password_hash, role, is_active, must_change_password, created_at, updated_at, password_changed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (username, hash_password(password), role, int(active), int(must_change_password), stamp, stamp, stamp),
        ).lastrowid
        get_db().commit()
    return user_id


def set_session(client, *, user_id: int, role: str, session_version: int = 0, reauthenticated: bool = False) -> None:
    with client.session_transaction() as session:
        now = time.time()
        session.update(
            user_id=user_id,
            role=role,
            session_version=session_version,
            authenticated_at=now,
            last_seen_at=now,
            reauthenticated_at=now if reauthenticated else None,
        )


def login(client, username: str, password: str):
    return client.post("/login", data={"username": username, "password": password})


def test_empty_database_seeds_default_admin_with_default_password(tmp_path: Path):
    app = make_app(tmp_path)

    with app.app_context():
        user = get_db().execute("SELECT * FROM users WHERE username='admin'").fetchone()
        assert user is not None
        assert user["role"] == "admin"
        assert user["is_active"] == 1
        assert user["must_change_password"] == 0
        assert verify_password(user["password_hash"], INITIAL_PASSWORD)
        assert get_db().execute("SELECT action FROM audit_events").fetchone()[0] == "bootstrap.initialized"


def test_empty_database_seed_honors_username_and_password_config_and_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ADMIN_USERNAME", "environment-admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "environment-password")
    env_app = make_app(tmp_path, "environment.db")
    with env_app.app_context():
        seeded = get_db().execute("SELECT username, password_hash FROM users").fetchone()
        assert seeded is not None
        assert seeded["username"] == "environment-admin"
        assert verify_password(seeded["password_hash"], "environment-password")

    configured_app = make_app(
        tmp_path,
        "configured.db",
        ADMIN_USERNAME="configured-admin",
        ADMIN_PASSWORD="configured-password",
    )
    with configured_app.app_context():
        seeded = get_db().execute("SELECT username, password_hash FROM users").fetchone()
        assert seeded is not None
        assert seeded["username"] == "configured-admin"
        assert verify_password(seeded["password_hash"], "configured-password")


def test_existing_database_ignores_changed_seed_environment_and_preserves_hash(tmp_path: Path):
    database = "persisted.db"
    first = make_app(tmp_path, database, ADMIN_USERNAME="original-admin", ADMIN_PASSWORD="original-password")
    with first.app_context():
        before = get_db().execute("SELECT username, password_hash FROM users").fetchone()

    restarted = make_app(tmp_path, database, ADMIN_USERNAME="replacement-admin", ADMIN_PASSWORD="replacement-password")
    with restarted.app_context():
        assert before is not None
        after = get_db().execute("SELECT username, password_hash FROM users").fetchone()
        assert after is not None
        assert dict(after) == dict(before)
        assert verify_password(after["password_hash"], "original-password")


def test_existing_invalid_audit_chain_is_degraded_without_seeding_or_mutation(tmp_path: Path):
    database = tmp_path / "tampered.db"
    connection = sqlite3.connect(database)
    connection.executescript(SCHEMA)
    stamp = datetime.now(UTC).isoformat()
    connection.execute(
        "INSERT INTO users (username, password_hash, role, is_active, must_change_password, created_at, updated_at) VALUES (?, ?, 'admin', 1, 0, ?, ?)",
        ("existing-admin", hash_password("existing-password"), stamp, stamp),
    )
    connection.execute(
        "INSERT INTO audit_events (occurred_at, action, target_type, previous_hash, event_hash) VALUES (?, 'tampered', 'database', ?, ?)",
        (stamp, b"x" * 32, b"y" * 32),
    )
    connection.commit()
    connection.close()

    app = make_app(tmp_path, "tampered.db", ADMIN_USERNAME="should-not-apply", ADMIN_PASSWORD="should-not-apply")
    with app.app_context():
        assert app.config["AUDIT_CHAIN_HEALTHY"] is False
        assert get_db().execute("SELECT username FROM users").fetchall()[0][0] == "existing-admin"
    assert app.test_client().get("/healthz").status_code == 503


def test_username_login_is_case_insensitive_password_only_rehashes_and_starts_a_session(app, client, monkeypatch: pytest.MonkeyPatch):
    user_id = insert_user(app, username="operator", password=INITIAL_PASSWORD)
    with app.app_context():
        old_hash = get_db().execute("SELECT password_hash FROM users WHERE id=?", (user_id,)).fetchone()[0]
    monkeypatch.setattr("service_manager.auth.needs_password_rehash", lambda _hash: True)

    response = login(client, "OpErAtOr", INITIAL_PASSWORD)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")
    with app.app_context():
        assert get_db().execute("SELECT password_hash FROM users WHERE id=?", (user_id,)).fetchone()[0] != old_hash
        event = get_db().execute("SELECT action FROM audit_events WHERE action='login.succeeded'").fetchone()
        assert event is not None
    with client.session_transaction() as session:
        assert session["user_id"] == user_id
        assert session["reauthenticated_at"] is None


def test_login_rate_limit_records_normalized_username_and_generic_metadata(app, client):
    for _ in range(5):
        assert login(client, "MiSsInG", "wrong").status_code == 401
    assert login(client, "missing", "wrong").status_code == 429
    with app.app_context():
        failure = get_db().execute("SELECT subject FROM security_events WHERE kind='login_failure' ORDER BY id LIMIT 1").fetchone()
        audit = get_db().execute("SELECT metadata_json FROM audit_events WHERE action='login_failure' ORDER BY id LIMIT 1").fetchone()
        assert failure["subject"] == "missing"
        assert json.loads(audit["metadata_json"]) == {"username_present": True}


def test_password_only_reauth_refreshes_five_minute_window(app, client):
    user_id = insert_user(app, password=INITIAL_PASSWORD)
    set_session(client, user_id=user_id, role="operador")

    response = client.post("/reauth", data={"password": INITIAL_PASSWORD})

    assert response.status_code == 204
    with client.session_transaction() as session:
        assert isinstance(session["reauthenticated_at"], float)
        assert time.time() - session["reauthenticated_at"] < 5


def test_temporary_user_is_redirected_to_account_and_can_only_change_password(app, client):
    insert_user(app, username="temporary", password=INITIAL_PASSWORD, must_change_password=True)

    response = login(client, "temporary", INITIAL_PASSWORD)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/account")
    assert client.get("/").status_code == 403
    account = client.get("/account")
    assert account.status_code == 200
    assert 'action="/account/username"' not in account.get_data(as_text=True)
    assert client.post("/account/password", data={"current_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD}).status_code == 303


def test_account_credentials_end_to_end_preserve_reauth_and_invalidate_prior_session(tmp_path: Path):
    app = make_app(tmp_path)
    owner = app.test_client()
    prior_session = app.test_client()

    assert login(owner, "admin", INITIAL_PASSWORD).status_code == 302
    assert login(prior_session, "admin", INITIAL_PASSWORD).status_code == 302
    changed_username = owner.post("/account/username", data={"current_password": INITIAL_PASSWORD, "username": "gestor"})
    assert changed_username.status_code == 303
    assert changed_username.headers["Location"].endswith("/account")
    with owner.session_transaction() as session:
        assert isinstance(session["reauthenticated_at"], float)
    assert prior_session.get("/", follow_redirects=False).status_code == 302
    owner.post("/logout")
    assert login(owner, "admin", INITIAL_PASSWORD).status_code == 401
    assert login(owner, "GESTOR", INITIAL_PASSWORD).status_code == 302
    changed_password = owner.post("/account/password", data={"current_password": INITIAL_PASSWORD, "new_password": NEW_PASSWORD})
    assert changed_password.status_code == 303
    with owner.session_transaction() as session:
        assert isinstance(session["reauthenticated_at"], float)
    assert prior_session.get("/", follow_redirects=False).status_code == 302
    owner.post("/logout")
    assert login(owner, "gestor", INITIAL_PASSWORD).status_code == 401
    assert login(owner, "gestor", NEW_PASSWORD).status_code == 302


def test_admin_creation_uses_username_rejects_casefold_collision_and_preserves_last_admin(app, client):
    with app.app_context():
        seeded_admin = get_db().execute("SELECT id FROM users WHERE username='admin'").fetchone()
    assert seeded_admin is not None
    admin_id = seeded_admin["id"]
    set_session(client, user_id=admin_id, role="admin", reauthenticated=True)

    created = client.post("/admin/users", data={"username": "operator", "role": "operador"})
    assert created.status_code == 201
    temporary_password = created.get_json()["temporary_password"]
    assert login(app.test_client(), "operator", temporary_password).status_code == 302
    assert client.post("/admin/users", data={"username": "OPERATOR", "role": "operador"}).status_code == 409
    assert client.post(f"/admin/users/{admin_id}/role", data={"role": "operador"}).status_code == 400
    assert client.post(f"/admin/users/{admin_id}/active", data={"is_active": "0"}).status_code == 400
    with app.app_context():
        event = get_db().execute("SELECT metadata_json FROM audit_events WHERE action='user.created'").fetchone()
        assert "operator" not in event["metadata_json"]


@pytest.mark.parametrize("path", ["/bootstrap", "/bootstrap/issue-totp", "/enroll-totp", "/enroll-totp/issue", "/admin/users/1/reset-mfa"])
def test_removed_totp_and_bootstrap_endpoints_are_not_found(app, client, path: str):
    if path.startswith("/enroll") or path.startswith("/admin/"):
        user_id = insert_user(app, username="endpoint-admin", role="admin")
        set_session(client, user_id=user_id, role="admin", reauthenticated=True)
    response = client.post(path) if path != "/bootstrap" and path != "/enroll-totp" else client.get(path)
    assert response.status_code == 404
