from __future__ import annotations

import sqlite3
import stat
import time
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
from service_manager.db import LegacySchemaError, enforce_database_permissions, get_db, transaction


@pytest.fixture()
def app(tmp_path: Path):
    return create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "service-manager-test.db"),
            "DATA_KEY_V1": "A" * 43 + "=",
            "SECRET_KEY": "test-session-key",
        }
    )


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def test_new_database_has_the_exact_username_only_secure_schema(app):
    expected_tables = {
        "accounts",
        "services",
        "account_service",
        "custom_fields",
        "field_values",
        "users",
        "security_events",
        "audit_events",
        "service_members",
        "webhook_configs",
        "webhook_subscriptions",
        "webhook_deliveries",
    }
    expected_user_columns = {
        "id",
        "username",
        "password_hash",
        "role",
        "is_active",
        "must_change_password",
        "created_at",
        "updated_at",
        "password_changed_at",
        "session_version",
    }
    forbidden = {"recovery_codes", "bootstrap_tokens"}
    with app.app_context():
        conn = get_db()
        tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")}
        assert tables == expected_tables
        assert table_columns(conn, "users") == expected_user_columns
        assert not tables & forbidden
        assert conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'bootstrap_tokens_one_active'").fetchone() is None
        assert {"password_ciphertext", "password_nonce", "password_key_version"} <= table_columns(conn, "accounts")
        assert "password" not in table_columns(conn, "accounts")
        assert {"value_ciphertext", "value_nonce", "value_key_version"} <= table_columns(conn, "field_values")
        assert "value_plaintext" not in table_columns(conn, "field_values")
        assert "value" not in table_columns(conn, "field_values")
        assert "is_secret" not in table_columns(conn, "custom_fields")
        stamp = "2026-01-01T00:00:00Z"
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at, updated_at) VALUES (?, ?, 'admin', ?, ?)",
            ("tester", "hash", stamp, stamp),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at, updated_at) VALUES (?, ?, 'operador', ?, ?)",
                ("TESTER", "hash", stamp, stamp),
            )


def test_secure_schema_constraints_and_append_only_triggers(app):
    with app.app_context():
        conn = get_db()
        service_id = conn.execute("INSERT INTO services (name) VALUES ('Mail')").lastrowid
        account_id = conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
            ("account@example.test", b"ciphertext", b"0" * 12),
        ).lastrowid
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'other')", (account_id, service_id))
        field_id = conn.execute("INSERT INTO custom_fields (service_id, name) VALUES (?, 'Token')", (service_id,)).lastrowid
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce) VALUES (?, ?, ?, ?)",
                (field_id, account_id, b"cipher", b"0" * 12),
            )
        event_id = conn.execute(
            "INSERT INTO audit_events (occurred_at, action, target_type, previous_hash, event_hash) VALUES (?, ?, ?, ?, ?)",
            ("2026-01-01T00:00:00Z", "created", "account", b"0" * 32, b"1" * 32),
        ).lastrowid
        with pytest.raises(sqlite3.DatabaseError, match="audit_events is append-only"):
            conn.execute("UPDATE audit_events SET action = 'changed' WHERE id = ?", (event_id,))
        with pytest.raises(sqlite3.DatabaseError, match="audit_events is append-only"):
            conn.execute("DELETE FROM audit_events WHERE id = ?", (event_id,))


def test_feature_pack_schema_columns_constraints_indexes_and_delivery_mutability(app):
    with app.app_context():
        conn = get_db()
        assert "password_changed_at" in table_columns(conn, "accounts")
        assert "rotation_days" in table_columns(conn, "services")
        assert {"rotation_days", "rotation_due_at"} <= table_columns(conn, "account_service")
        assert table_columns(conn, "service_members") == {"user_id", "service_id", "role", "created_at"}
        indexes = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert {"service_members_service_id", "webhook_deliveries_status_next_attempt", "webhook_deliveries_config_created"} <= indexes
        # security_events kind CHECK accepts the new kinds.
        for kind in ("reveal_blocked", "audit_degraded"):
            conn.execute("INSERT INTO security_events (kind, subject, source_ip, occurred_at) VALUES (?, 's', '127.0.0.1', '2026-01-01T00:00:00Z')", (kind,))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO security_events (kind, subject, source_ip, occurred_at) VALUES ('bogus', 's', '127.0.0.1', '2026-01-01T00:00:00Z')")
        # rotation_days CHECK bounds.
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO services (name, rotation_days) VALUES ('Bad', 0)")
        service_id = conn.execute("INSERT INTO services (name, rotation_days) VALUES ('Mail', 30)").lastrowid
        user_id = conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at, updated_at) VALUES ('member', 'h', 'operador', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        ).lastrowid
        # service_members role CHECK.
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO service_members (user_id, service_id, role, created_at) VALUES (?, ?, 'bogus', '2026-01-01T00:00:00Z')", (user_id, service_id))
        conn.execute("INSERT INTO service_members (user_id, service_id, role, created_at) VALUES (?, ?, 'service_admin', '2026-01-01T00:00:00Z')", (user_id, service_id))
        # service_members FK cascades on service delete.
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("DELETE FROM services WHERE id = ?", (service_id,))
        assert conn.execute("SELECT COUNT(*) FROM service_members WHERE service_id = ?", (service_id,)).fetchone()[0] == 0
        # webhook config + subscription CHECK + delivery mutability.
        config_id = conn.execute(
            "INSERT INTO webhook_configs (destination_host, url_ciphertext, url_nonce, url_key_version, signing_secret_ciphertext, signing_secret_nonce, signing_secret_key_version, created_at, updated_at) VALUES ('h.test', ?, ?, 1, ?, ?, 1, ?, ?)",
            (b"u", b"0" * 12, b"s", b"1" * 12, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        ).lastrowid
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO webhook_subscriptions (config_id, event_type) VALUES (?, 'bogus')", (config_id,))
        conn.execute("INSERT INTO webhook_subscriptions (config_id, event_type) VALUES (?, 'login_failures')", (config_id,))
        delivery_id = conn.execute(
            "INSERT INTO webhook_deliveries (config_id, event_type, payload_json, status, next_attempt_at, created_at) VALUES (?, 'login_failures', '{}', 'pending', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            (config_id,),
        ).lastrowid
        conn.execute("UPDATE webhook_deliveries SET status = 'succeeded' WHERE id = ?", (delivery_id,))
        assert conn.execute("SELECT status FROM webhook_deliveries WHERE id = ?", (delivery_id,)).fetchone()["status"] == "succeeded"
        # webhook_deliveries.config_id FK must NOT cascade: a hard config delete cannot silently drop delivery history.
        delivery_fks = list(conn.execute("PRAGMA foreign_key_list(webhook_deliveries)"))
        assert len(delivery_fks) == 1 and delivery_fks[0]["table"] == "webhook_configs" and delivery_fks[0]["on_delete"] == "NO ACTION"
        # service_members FKs cascade to both parents.
        member_fks = {row["table"]: row["on_delete"] for row in conn.execute("PRAGMA foreign_key_list(service_members)")}
        assert member_fks == {"users": "CASCADE", "services": "CASCADE"}
        # webhook_subscriptions cascades to its config.
        sub_fks = {row["table"]: row["on_delete"] for row in conn.execute("PRAGMA foreign_key_list(webhook_subscriptions)")}
        assert sub_fks == {"webhook_configs": "CASCADE"}
        # Exact CHECK literals frozen in the canonical schema SQL.
        sql = {row["name"]: row["sql"] for row in conn.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")}
        assert "role IN ('viewer', 'editor', 'service_admin')" in sql["service_members"]
        assert "attempt_count BETWEEN 0 AND 5" in sql["webhook_deliveries"]
        assert "status IN ('pending', 'delivering', 'retry', 'succeeded', 'failed')" in sql["webhook_deliveries"]
        assert "kind IN ('login_failure', 'reveal', 'reveal_blocked', 'audit_degraded')" in sql["security_events"]


def test_custom_fields_have_no_classification_and_field_values_require_an_envelope(app):
    with app.app_context():
        conn = get_db()
        service_id = conn.execute("INSERT INTO services (name) VALUES ('Mail')").lastrowid
        account_id = conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
            ("account@example.test", b"ciphertext", b"0" * 12),
        ).lastrowid
        field_id = conn.execute("INSERT INTO custom_fields (service_id, name) VALUES (?, 'Token')", (service_id,)).lastrowid
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO field_values (field_id, account_id, value_nonce, value_key_version) VALUES (?, ?, ?, 1)", (field_id, account_id, b"1" * 12))
        conn.execute(
            "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, 1)",
            (field_id, account_id, b"ciphertext", b"1" * 12),
        )
        stored = conn.execute("SELECT value_ciphertext, value_nonce, value_key_version FROM field_values WHERE field_id=? AND account_id=?", (field_id, account_id)).fetchone()
        assert bytes(stored["value_ciphertext"]) == b"ciphertext"
        assert stored["value_key_version"] == 1


def test_new_schema_rejects_a_database_with_any_totp_or_bootstrap_residue(tmp_path: Path):
    database = tmp_path / "stale-secure.db"
    stale = sqlite3.connect(database)
    stale.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'operador')),
            is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
            must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1)),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            password_changed_at TEXT,
            session_version INTEGER NOT NULL DEFAULT 0 CHECK (session_version >= 0)
        );
        CREATE TABLE recovery_codes (user_id INTEGER NOT NULL, code_hash TEXT NOT NULL, used_at TEXT);
        """
    )
    stale.close()

    with pytest.raises(LegacySchemaError, match="incompatible"):
        create_app({"TESTING": True, "DATABASE_PATH": str(database), "DATA_KEY_V1": "A" * 43 + "=", "SECRET_KEY": "test-session-key"})

def test_get_db_configures_pragmas_and_transaction_rolls_back(app):
    with app.app_context():
        conn = get_db()
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
        with pytest.raises(RuntimeError, match="rollback"):
            with transaction(conn):
                conn.execute("INSERT INTO services (name) VALUES ('rolled back')")
                raise RuntimeError("rollback")
        assert conn.execute("SELECT COUNT(*) FROM services WHERE name = 'rolled back'").fetchone()[0] == 0


def test_production_database_permissions_cover_directory_and_wal_artifacts(monkeypatch, tmp_path: Path):
    database = tmp_path / "production" / "service-manager.db"
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("SECRET_KEY", "environment-session-key")

    production_app = create_app(
        {
            "DATABASE_PATH": str(database),
            "DATA_KEY_V1": "A" * 43 + "=",
        }
    )

    with production_app.app_context():
        conn = get_db()
        with transaction(conn):
            conn.execute("INSERT INTO services (name) VALUES ('Mail')")
        enforce_database_permissions()

    assert stat.S_IMODE(database.parent.stat().st_mode) == 0o700
    for artifact in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
        if artifact.exists():
            assert stat.S_IMODE(artifact.stat().st_mode) == 0o600


def test_legacy_database_is_rejected_without_in_place_upgrade(tmp_path: Path):
    database = tmp_path / "legacy.db"
    legacy = sqlite3.connect(database)
    legacy.execute("CREATE TABLE accounts (id INTEGER PRIMARY KEY, email TEXT, password TEXT)")
    legacy.commit()
    legacy.close()

    with pytest.raises(LegacySchemaError, match="legacy"):
        create_app(
            {
                "TESTING": True,
                "DATABASE_PATH": str(database),
                "DATA_KEY_V1": "A" * 43 + "=",
                "SECRET_KEY": "test-session-key",
            }
        )

    check = sqlite3.connect(database)
    assert {row[1] for row in check.execute("PRAGMA table_info(accounts)")} == {"id", "email", "password"}
    check.close()




def test_legacy_add_route_stores_an_encrypted_password(app):
    client = app.test_client()
    with app.app_context():
        conn = get_db()
        service_id = conn.execute("INSERT INTO services (name) VALUES ('Mail')").lastrowid
        user_id = conn.execute(
            "INSERT INTO users (username, password_hash, role, is_active, must_change_password, created_at, updated_at) VALUES (?, ?, 'operador', 1, 0, ?, ?)",
            ("operator", "unused", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
        ).lastrowid
        conn.execute(
            "INSERT INTO service_members (user_id, service_id, role, created_at) VALUES (?, ?, 'editor', '2026-01-01T00:00:00+00:00')",
            (user_id, service_id),
        )
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=user_id, role="operador", session_version=0, authenticated_at=time.time(), last_seen_at=time.time(), reauthenticated_at=None)
    response = client.post("/add", data={"service": service_id, "email": "person@example.test", "password": "known-secret", "status": "ativo"})

    assert response.status_code == 302
    with app.app_context():
        row = get_db().execute("SELECT password_ciphertext, password_nonce, password_key_version FROM accounts WHERE email = ?", ("person@example.test",)).fetchone()
        assert row is not None
        assert row["password_ciphertext"] != b"known-secret"
        assert row["password_nonce"] is not None
        assert row["password_key_version"] == 1
