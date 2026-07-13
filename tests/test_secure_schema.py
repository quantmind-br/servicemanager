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


def test_new_database_uses_only_secure_secret_columns(app):
    with app.app_context():
        conn = get_db()
        assert {"password_ciphertext", "password_nonce", "password_key_version"} <= table_columns(conn, "accounts")
        assert "password" not in table_columns(conn, "accounts")
        assert {"value_plaintext", "value_ciphertext", "value_nonce", "value_key_version"} <= table_columns(conn, "field_values")
        assert "value" not in table_columns(conn, "field_values")
        assert "credentials_backup" not in {
            row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }


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
        field_id = conn.execute("INSERT INTO custom_fields (service_id, name, is_secret) VALUES (?, 'Token', 1)", (service_id,)).lastrowid
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO field_values (field_id, account_id, value_plaintext, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, ?, ?)",
                (field_id, account_id, "plain", b"cipher", b"0" * 12, 1),
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO custom_fields (service_id, name, is_secret) VALUES (?, 'Invalid', 2)", (service_id,))
        event_id = conn.execute(
            "INSERT INTO audit_events (occurred_at, action, target_type, previous_hash, event_hash) VALUES (?, ?, ?, ?, ?)",
            ("2026-01-01T00:00:00Z", "created", "account", b"0" * 32, b"1" * 32),
        ).lastrowid
        with pytest.raises(sqlite3.DatabaseError, match="audit_events is append-only"):
            conn.execute("UPDATE audit_events SET action = 'changed' WHERE id = ?", (event_id,))
        with pytest.raises(sqlite3.DatabaseError, match="audit_events is append-only"):
            conn.execute("DELETE FROM audit_events WHERE id = ?", (event_id,))


def test_field_values_require_the_representation_matching_field_secrecy(app):
    with app.app_context():
        conn = get_db()
        service_id = conn.execute("INSERT INTO services (name) VALUES ('Mail')").lastrowid
        account_id = conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
            ("account@example.test", b"ciphertext", b"0" * 12),
        ).lastrowid
        secret_field = conn.execute("INSERT INTO custom_fields (service_id, name, is_secret) VALUES (?, 'Secret', 1)", (service_id,)).lastrowid
        public_field = conn.execute("INSERT INTO custom_fields (service_id, name, is_secret) VALUES (?, 'Public', 0)", (service_id,)).lastrowid
        with pytest.raises(sqlite3.IntegrityError, match="secret field"):
            conn.execute("INSERT INTO field_values (field_id, account_id, value_plaintext) VALUES (?, ?, ?)", (secret_field, account_id, "not allowed"))
        with pytest.raises(sqlite3.IntegrityError, match="non-secret field"):
            conn.execute(
                "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, ?)",
                (public_field, account_id, b"ciphertext", b"0" * 12, 1),
            )
        conn.execute(
            "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, ?)",
            (secret_field, account_id, b"ciphertext", b"1" * 12, 1),
        )
        conn.execute("INSERT INTO field_values (field_id, account_id, value_plaintext) VALUES (?, ?, ?)", (public_field, account_id, "displayable"))
        with pytest.raises(sqlite3.IntegrityError, match="secret field"):
            conn.execute("UPDATE field_values SET value_plaintext = ?, value_ciphertext = NULL, value_nonce = NULL, value_key_version = NULL WHERE field_id = ?", ("no", secret_field))


def test_reclassifying_a_field_cannot_break_its_existing_representation(app):
    with app.app_context():
        conn = get_db()
        service_id = conn.execute("INSERT INTO services (name) VALUES ('Mail')").lastrowid
        account_id = conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, 1)",
            ("account@example.test", b"ciphertext", b"0" * 12),
        ).lastrowid
        field_id = conn.execute("INSERT INTO custom_fields (service_id, name, is_secret) VALUES (?, 'Public', 0)", (service_id,)).lastrowid
        conn.execute("INSERT INTO field_values (field_id, account_id, value_plaintext) VALUES (?, ?, ?)", (field_id, account_id, "displayable"))
        with pytest.raises(sqlite3.IntegrityError, match="field secrecy classification"):
            conn.execute("UPDATE custom_fields SET is_secret = 1 WHERE id = ?", (field_id,))


def test_bootstrap_tokens_allow_only_one_active_token(app):
    with app.app_context():
        conn = get_db()
        stamp = "2026-01-01T00:00:00Z"
        first_user = conn.execute(
            "INSERT INTO users (email, password_hash, role, created_at, updated_at) VALUES (?, ?, 'admin', ?, ?)",
            ("first@local.invalid", "hash", stamp, stamp),
        ).lastrowid
        second_user = conn.execute(
            "INSERT INTO users (email, password_hash, role, created_at, updated_at) VALUES (?, ?, 'admin', ?, ?)",
            ("second@local.invalid", "hash", stamp, stamp),
        ).lastrowid
        conn.execute("INSERT INTO bootstrap_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)", (b"first", first_user, "2026-01-01T00:15:00Z"))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO bootstrap_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)", (b"second", second_user, "2026-01-01T00:15:00Z"))
        conn.execute("UPDATE bootstrap_tokens SET consumed_at = ?", ("2026-01-01T00:01:00Z",))
        conn.execute("INSERT INTO bootstrap_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)", (b"second", second_user, "2026-01-01T00:15:00Z"))


def test_bootstrap_token_is_bound_to_one_initial_admin(app):
    with app.app_context():
        columns = table_columns(get_db(), "bootstrap_tokens")
    assert "user_id" in columns

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


def test_startup_rejects_stale_secure_schema_missing_pending_enrollment_columns(tmp_path: Path):
    from service_manager.db import SCHEMA

    database = tmp_path / "stale-secure.db"
    stale_schema = SCHEMA.replace(
        "    pending_totp_secret_ciphertext BLOB,\n"
        "    pending_totp_nonce BLOB,\n"
        "    pending_totp_key_version INTEGER,\n"
        "    totp_enrollment_shown_at TEXT,\n"
        "    CHECK (\n"
        "        (totp_secret_ciphertext IS NULL AND totp_nonce IS NULL AND totp_key_version IS NULL)\n"
        "        OR\n"
        "        (totp_secret_ciphertext IS NOT NULL AND totp_nonce IS NOT NULL AND totp_key_version IS NOT NULL)\n"
        "    ),\n"
        "    CHECK (\n"
        "        (pending_totp_secret_ciphertext IS NULL AND pending_totp_nonce IS NULL AND pending_totp_key_version IS NULL)\n"
        "        OR\n"
        "        (pending_totp_secret_ciphertext IS NOT NULL AND pending_totp_nonce IS NOT NULL AND pending_totp_key_version IS NOT NULL)\n"
        "    )\n",
        "    CHECK (\n"
        "        (totp_secret_ciphertext IS NULL AND totp_nonce IS NULL AND totp_key_version IS NULL)\n"
        "        OR\n"
        "        (totp_secret_ciphertext IS NOT NULL AND totp_nonce IS NOT NULL AND totp_key_version IS NOT NULL)\n"
        "    )\n",
    )
    stale = sqlite3.connect(database)
    stale.executescript(stale_schema)
    stale.close()

    with pytest.raises(LegacySchemaError, match="incompatible"):
        create_app(
            {
                "TESTING": True,
                "DATABASE_PATH": str(database),
                "DATA_KEY_V1": "A" * 43 + "=",
                "SECRET_KEY": "test-session-key",
            }
        )

def test_legacy_add_route_stores_an_encrypted_password(app):
    client = app.test_client()
    with app.app_context():
        conn = get_db()
        service_id = conn.execute("INSERT INTO services (name) VALUES ('Mail')").lastrowid
        user_id = conn.execute(
            "INSERT INTO users (email, password_hash, role, is_active, must_change_password, created_at, updated_at) VALUES (?, ?, 'operador', 1, 0, ?, ?)",
            ("operator@local.invalid", "unused", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
        ).lastrowid
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
