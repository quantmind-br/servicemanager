from __future__ import annotations

import base64
import json
import socket
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
from service_manager.crypto import (
    EncryptedValue,
    decrypt_secret_with_key,
    webhook_signing_secret_aad,
    webhook_url_aad,
)
from service_manager.db import get_db, transaction

KEY = base64.b64encode(b"w" * 32).decode("ascii")
ADMIN_PASSWORD = "admin-password-0123456789"
GLOBAL_IP = "93.184.216.34"


def _resolver(mapping):
    def resolve(host, port, *args, **kwargs):
        if host not in mapping:
            raise socket.gaierror(f"no such host: {host}")
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, port)) for addr in mapping[host]]

    return resolve


@pytest.fixture()
def app(tmp_path: Path):
    return create_app(
        {
            "TESTING": True,
            "PROPAGATE_EXCEPTIONS": False,
            "DATABASE_PATH": str(tmp_path / "webhooks.db"),
            "DATA_KEY_V1": KEY,
            "AUDIT_KEY_V1": KEY,
            "SECRET_KEY": "webhook-routes-session-secret",
            "WTF_CSRF_ENABLED": False,
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": ADMIN_PASSWORD,
            "WEBHOOK_RESOLVER": _resolver({"hooks.example.test": [GLOBAL_IP]}),
        }
    )


@pytest.fixture()
def client(app):
    return app.test_client()


def login_admin(client) -> None:
    assert client.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 302
    with client.session_transaction() as session:
        session["reauthenticated_at"] = time.time()


def login_operator(app, client) -> None:
    from service_manager.crypto import hash_password

    with app.app_context():
        conn = get_db()
        stamp = conn.execute("SELECT created_at FROM users WHERE username='admin'").fetchone()[0]
        conn.execute(
            "INSERT INTO users (username, password_hash, role, is_active, must_change_password, created_at, updated_at) "
            "VALUES (?, ?, 'operador', 1, 0, ?, ?)",
            ("operator", hash_password("operator-password-012345"), stamp, stamp),
        )
        conn.commit()
    assert client.post("/login", data={"username": "operator", "password": "operator-password-012345"}).status_code == 302
    with client.session_transaction() as session:
        session["reauthenticated_at"] = time.time()


def _create(client, **overrides):
    data = {
        "url": "https://hooks.example.test/hook",
        "description": "primary",
        "enabled": "1",
        "event_types": ["login_failures", "authorization_failure"],
    }
    data.update(overrides)
    return client.post("/admin/security-integrations", data=data)


# --------------------------------------------------------------------------
# Route access + create
# --------------------------------------------------------------------------


def test_operator_cannot_reach_security_integrations(app, client):
    login_operator(app, client)
    assert client.get("/admin/security-integrations").status_code == 403
    assert _create(client).status_code == 403


def test_create_returns_one_time_secret_and_persists_encrypted_url(app, client):
    login_admin(client)
    response = _create(client)
    assert response.status_code == 201
    assert response.headers["Cache-Control"] == "no-store, private"
    payload = json.loads(response.get_data(as_text=True))
    assert payload["signing_secret"]
    config_id = payload["id"]
    with app.app_context():
        row = get_db().execute("SELECT * FROM webhook_configs WHERE id=?", (config_id,)).fetchone()
        # Plaintext URL is never stored.
        assert b"hooks.example.test/hook" not in bytes(row["url_ciphertext"])
        assert row["destination_host"] == "hooks.example.test"
        # The secret round-trips under its config-id AAD.
        secret = decrypt_secret_with_key(
            KEY,
            EncryptedValue(row["signing_secret_ciphertext"], row["signing_secret_nonce"], row["signing_secret_key_version"]),
            aad=webhook_signing_secret_aad(config_id),
        )
        assert secret == payload["signing_secret"]
        url = decrypt_secret_with_key(
            KEY,
            EncryptedValue(row["url_ciphertext"], row["url_nonce"], row["url_key_version"]),
            aad=webhook_url_aad(config_id),
        )
        assert url == "https://hooks.example.test/hook"
        subs = {r["event_type"] for r in get_db().execute("SELECT event_type FROM webhook_subscriptions WHERE config_id=?", (config_id,))}
        assert subs == {"login_failures", "authorization_failure"}


def test_create_audit_only_lists_allowed_fields_and_no_secret(app, client):
    login_admin(client)
    payload = json.loads(_create(client).get_data(as_text=True))
    with app.app_context():
        event = get_db().execute("SELECT metadata_json FROM audit_events WHERE action='webhook.created'").fetchone()
        meta = json.loads(event["metadata_json"])
        assert set(meta) == {"destination_host", "enabled", "subscriptions"}
        assert meta["destination_host"] == "hooks.example.test"
        assert payload["signing_secret"] not in event["metadata_json"]


def test_create_rejects_invalid_url_and_missing_events(app, client):
    login_admin(client)
    assert _create(client, url="http://hooks.example.test/x").status_code == 400
    assert _create(client, url="https://hooks.example.test:8443/x").status_code == 400
    assert _create(client, url="https://hooks.example.test:abc/x").status_code == 400
    assert _create(client, event_types=[]).status_code == 400
    assert _create(client, event_types=["not_a_real_event"]).status_code == 400
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM webhook_configs").fetchone()[0] == 0


def test_config_cap_enforced_at_twenty(app, client):
    login_admin(client)
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            for i in range(20):
                conn.execute(
                    "INSERT INTO webhook_configs (destination_host, url_ciphertext, url_nonce, url_key_version, "
                    "signing_secret_ciphertext, signing_secret_nonce, signing_secret_key_version, created_at, updated_at) "
                    "VALUES ('h.test', ?, ?, 1, ?, ?, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                    (b"u", b"0" * 12, b"s", b"1" * 12),
                )
    assert _create(client).status_code == 400
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM webhook_configs").fetchone()[0] == 20


def test_security_integrations_capacity_uses_loaded_configs(app, client, monkeypatch):
    login_admin(client)
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            for i in range(20):
                conn.execute(
                    "INSERT INTO webhook_configs (destination_host, url_ciphertext, url_nonce, url_key_version, "
                    "signing_secret_ciphertext, signing_secret_nonce, signing_secret_key_version, created_at, updated_at) "
                    "VALUES ('h.test', ?, ?, 1, ?, ?, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                    (b"u", b"0" * 12, b"s", b"1" * 12),
                )

    def _fail(*args, **kwargs):
        raise AssertionError("count_active_configs must not run in the GET route")

    monkeypatch.setattr("service_manager.routes.count_active_configs", _fail, raising=False)
    response = client.get("/admin/security-integrations")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "20 de 20 configurados" in html
    assert "Limite de 20 integrações atingido" in html
    assert "data-webhook-create" not in html


def test_one_time_secret_never_in_listing_html(app, client):
    login_admin(client)
    secret = json.loads(_create(client).get_data(as_text=True))["signing_secret"]
    html = client.get("/admin/security-integrations").get_data(as_text=True)
    assert secret not in html
    assert "hooks.example.test/hook" not in html  # full URL never displayed
    assert "hooks.example.test" in html  # host is shown


# --------------------------------------------------------------------------
# Update / delete / test
# --------------------------------------------------------------------------


def _seed_config(app, client):
    return json.loads(_create(client).get_data(as_text=True))["id"]


def test_update_blank_url_preserves_stored_url_and_never_returns_secret(app, client):
    login_admin(client)
    config_id = _seed_config(app, client)
    with app.app_context():
        before = bytes(get_db().execute("SELECT url_ciphertext FROM webhook_configs WHERE id=?", (config_id,)).fetchone()["url_ciphertext"])
    response = client.post(
        f"/admin/security-integrations/{config_id}",
        data={"url": "", "description": "renamed", "enabled": "1", "event_types": ["login_failures"]},
    )
    assert response.status_code == 204
    assert "signing_secret" not in response.get_data(as_text=True)
    with app.app_context():
        row = get_db().execute("SELECT url_ciphertext, description FROM webhook_configs WHERE id=?", (config_id,)).fetchone()
        assert bytes(row["url_ciphertext"]) == before
        assert row["description"] == "renamed"


def test_disable_cancels_pending_and_retry_deliveries(app, client):
    login_admin(client)
    config_id = _seed_config(app, client)
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            for status in ("pending", "retry", "delivering", "succeeded"):
                conn.execute(
                    "INSERT INTO webhook_deliveries (config_id, event_type, payload_json, status, next_attempt_at, created_at) "
                    "VALUES (?, 'login_failures', '{}', ?, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                    (config_id, status),
                )
    resp = client.post(
        f"/admin/security-integrations/{config_id}",
        data={"url": "", "description": "primary", "enabled": "0", "event_types": ["login_failures"]},
    )
    assert resp.status_code == 204
    with app.app_context():
        # pending/retry become failed(disabled); delivering may still finish; succeeded untouched.
        counts = {}
        errors = set()
        for r in get_db().execute("SELECT status, last_error FROM webhook_deliveries WHERE config_id=?", (config_id,)):
            counts[r["status"]] = counts.get(r["status"], 0) + 1
            if r["status"] == "failed":
                errors.add(r["last_error"])
        assert counts.get("failed") == 2
        assert counts.get("delivering") == 1
        assert counts.get("succeeded") == 1
        assert errors == {"disabled"}


def test_delete_soft_disables_and_cancels(app, client):
    login_admin(client)
    config_id = _seed_config(app, client)
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            conn.execute(
                "INSERT INTO webhook_deliveries (config_id, event_type, payload_json, status, next_attempt_at, created_at) "
                "VALUES (?, 'login_failures', '{}', 'pending', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                (config_id,),
            )
    assert client.post(f"/admin/security-integrations/{config_id}/delete").status_code == 204
    with app.app_context():
        row = get_db().execute("SELECT enabled, deleted_at FROM webhook_configs WHERE id=?", (config_id,)).fetchone()
        assert row["enabled"] == 0 and row["deleted_at"] is not None
        # History remains referentially valid; the pending delivery is failed.
        status = get_db().execute("SELECT status, last_error FROM webhook_deliveries WHERE config_id=?", (config_id,)).fetchone()
        assert status["status"] == "failed" and status["last_error"] == "disabled"
        # Listing no longer includes the soft-deleted config.
    assert "hooks.example.test" not in client.get("/admin/security-integrations").get_data(as_text=True)


def test_test_route_queues_single_test_delivery(app, client):
    login_admin(client)
    config_id = _seed_config(app, client)
    assert client.post(f"/admin/security-integrations/{config_id}/test").status_code == 204
    with app.app_context():
        row = get_db().execute("SELECT event_type, status FROM webhook_deliveries WHERE config_id=? AND event_type='test'", (config_id,)).fetchone()
        assert row is not None and row["status"] == "pending"
        meta = json.loads(get_db().execute("SELECT metadata_json FROM audit_events WHERE action='webhook.test_enqueued'").fetchone()["metadata_json"])
        assert set(meta) == {"destination_host", "enabled"}


def test_update_and_delete_unknown_config_return_404(app, client):
    login_admin(client)
    assert client.post(
        "/admin/security-integrations/999",
        data={"url": "", "description": "x", "enabled": "1", "event_types": ["login_failures"]},
    ).status_code == 404
    assert client.post("/admin/security-integrations/999/delete").status_code == 404
    assert client.post("/admin/security-integrations/999/test").status_code == 404


def test_delivery_history_sanitizes_non_generic_last_error(app, client):
    login_admin(client)
    config_id = _seed_config(app, client)
    leak = "http://internal.svc/secret-path?token=abc123"
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            conn.execute(
                "INSERT INTO webhook_deliveries (config_id, event_type, payload_json, status, next_attempt_at, created_at, last_error) "
                "VALUES (?, 'login_failures', '{}', 'failed', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', ?)",
                (config_id, leak),
            )
    html = client.get("/admin/security-integrations").get_data(as_text=True)
    assert leak not in html
    assert "connection" in html


# --------------------------------------------------------------------------
# Event producers: thresholds and dedup
# --------------------------------------------------------------------------


def _subscribe(app, event_type):
    """Create an enabled config subscribed to one event; return its id."""
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            cid = conn.execute(
                "INSERT INTO webhook_configs (destination_host, url_ciphertext, url_nonce, url_key_version, "
                "signing_secret_ciphertext, signing_secret_nonce, signing_secret_key_version, created_at, updated_at) "
                "VALUES ('h.test', ?, ?, 1, ?, ?, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                (b"u", b"0" * 12, b"s", b"1" * 12),
            ).lastrowid
            conn.execute("INSERT INTO webhook_subscriptions (config_id, event_type) VALUES (?, ?)", (cid, event_type))
    return cid


def _login_failure_count(app):
    with app.app_context():
        return get_db().execute("SELECT COUNT(*) FROM webhook_deliveries WHERE event_type='login_failures'").fetchone()[0]


def test_login_failures_enqueues_once_at_fifth_attempt_and_sixth_is_rate_limited(app, client):
    _subscribe(app, "login_failures")
    # Four failures: below threshold, nothing enqueued.
    for _ in range(4):
        assert client.post("/login", data={"username": "admin", "password": "wrong-password-xx"}).status_code == 401
    assert _login_failure_count(app) == 0
    # Fifth failure crosses exactly 5 and enqueues one delivery.
    assert client.post("/login", data={"username": "admin", "password": "wrong-password-xx"}).status_code == 401
    assert _login_failure_count(app) == 1
    # Sixth attempt is rate-limited (429) and must not enqueue again.
    assert client.post("/login", data={"username": "admin", "password": "wrong-password-xx"}).status_code == 429
    assert _login_failure_count(app) == 1


def test_login_failures_payload_is_secret_free(app, client):
    _subscribe(app, "login_failures")
    for _ in range(5):
        client.post("/login", data={"username": "admin", "password": "the-actual-secret-attempt"})
    with app.app_context():
        payload = get_db().execute("SELECT payload_json FROM webhook_deliveries WHERE event_type='login_failures'").fetchone()["payload_json"]
    assert "the-actual-secret-attempt" not in payload
    body = json.loads(payload)
    assert body["event"] == "login_failures"
    assert set(body["details"]) == {"source_ip", "username_present", "ip_count", "username_count"}


def test_reveal_rate_limit_enqueues_once_per_user_ip_window(app, client):
    cid = _subscribe(app, "reveal_rate_limit")
    login_admin(client)
    with app.app_context():
        from service_manager.auth import consume_reveal_allowance

        conn = get_db()
        user_id = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()["id"]
        with transaction(conn):
            # First 20 consume the allowance; the 21st and 22nd are blocked.
            for _ in range(20):
                assert consume_reveal_allowance(conn, user_id=user_id, ip="203.0.113.7") is True
            assert consume_reveal_allowance(conn, user_id=user_id, ip="203.0.113.7") is False
            assert consume_reveal_allowance(conn, user_id=user_id, ip="203.0.113.7") is False
        count = conn.execute("SELECT COUNT(*) FROM webhook_deliveries WHERE event_type='reveal_rate_limit' AND config_id=?", (cid,)).fetchone()[0]
    # Dedup marker means only one enqueue per (user, ip) window despite two blocks.
    assert count == 1


def test_user_deactivated_enqueues_only_on_true_to_false_transition(app, client):
    cid = _subscribe(app, "user_deactivated")
    login_admin(client)
    with app.app_context():
        from service_manager.crypto import hash_password

        conn = get_db()
        stamp = conn.execute("SELECT created_at FROM users WHERE username='admin'").fetchone()[0]
        target = conn.execute(
            "INSERT INTO users (username, password_hash, role, is_active, must_change_password, created_at, updated_at) "
            "VALUES ('victim', ?, 'operador', 1, 0, ?, ?)",
            (hash_password("victim-password-01234"), stamp, stamp),
        ).lastrowid
        conn.commit()
    # Deactivate: one enqueue.
    assert client.post(f"/admin/users/{target}/active", data={"is_active": "0"}).status_code == 204
    # Re-post deactivation (already inactive): no additional enqueue.
    assert client.post(f"/admin/users/{target}/active", data={"is_active": "0"}).status_code == 204
    with app.app_context():
        count = get_db().execute("SELECT COUNT(*) FROM webhook_deliveries WHERE event_type='user_deactivated' AND config_id=?", (cid,)).fetchone()[0]
    assert count == 1


def test_audit_chain_degraded_dedup_across_connections(app):
    """A second worker/connection within five minutes must not double-enqueue."""
    cid = _subscribe(app, "audit_chain_degraded")
    from service_manager.webhooks import record_audit_degraded

    with app.app_context():
        assert record_audit_degraded(get_db()) is True
    # A distinct connection (simulating another process) inside the window is deduped.
    with app.app_context():
        assert record_audit_degraded(get_db()) is False
    with app.app_context():
        count = get_db().execute("SELECT COUNT(*) FROM webhook_deliveries WHERE event_type='audit_chain_degraded' AND config_id=?", (cid,)).fetchone()[0]
    assert count == 1
