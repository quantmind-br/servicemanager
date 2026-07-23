from __future__ import annotations

import argparse
import base64
import hashlib
import os
import sqlite3
import hmac
import json
import zlib
import inspect
import stat
import subprocess
import sys
from pathlib import Path

import pytest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from app import create_app
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from _pre_feature_schema import PRE_FEATURE_SCHEMA
MIGRATE = ROOT / "scripts" / "migrate_legacy_db.py"
VERIFY = ROOT / "scripts" / "verify_migrated_db.py"
BACKUP = ROOT / "scripts" / "backup.py"
RESTORE = ROOT / "scripts" / "restore_backup.py"
AUTH_MIGRATE = ROOT / "scripts" / "migrate_auth_schema.py"
SERVICE_PREFERENCES_MIGRATE = ROOT / "scripts" / "migrate_service_preferences.py"
DATA_KEY = base64.b64encode(b"d" * 32).decode("ascii")
BACKUP_KEY = base64.b64encode(b"b" * 32).decode("ascii")


def _run(script: Path, *args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=ROOT,
        env={**os.environ, **env},
        text=True,
        capture_output=True,
        check=False,
    )


def _legacy_source(path: Path, *, accounts: int = 116) -> list[str]:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE accounts (id INTEGER PRIMARY KEY, email TEXT NOT NULL, password TEXT NOT NULL);
        CREATE TABLE services (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
        CREATE TABLE account_service (account_id INTEGER NOT NULL, service_id INTEGER NOT NULL, status TEXT NOT NULL);
        CREATE TABLE custom_fields (id INTEGER PRIMARY KEY, service_id INTEGER NOT NULL, name TEXT NOT NULL);
        CREATE TABLE field_values (field_id INTEGER NOT NULL, account_id INTEGER NOT NULL, value TEXT NOT NULL);
        CREATE TABLE credentials_backup (id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL, snapshot TEXT NOT NULL);
        """
    )
    conn.execute("INSERT INTO services (id, name) VALUES (17, 'Synthetic mail')")
    conn.execute("INSERT INTO services (id, name) VALUES (18, 'Synthetic storage')")
    conn.execute("INSERT INTO custom_fields (id, service_id, name) VALUES (29, 17, 'Synthetic token')")
    conn.execute("INSERT INTO custom_fields (id, service_id, name) VALUES (30, 18, 'Synthetic key')")
    plaintexts: list[str] = []
    for index in range(1, accounts + 1):
        password = "" if index == 1 else f"migration-password-{index}-only"
        value = "" if index == 1 else f"migration-field-{index}-only"
        service_id, field_id = (17, 29) if index % 2 else (18, 30)
        plaintexts.extend((password, value))
        conn.execute("INSERT INTO accounts (id, email, password) VALUES (?, ?, ?)", (1000 + index, f"synthetic-{index}@example.test", password))
        conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (1000 + index, service_id))
        conn.execute("INSERT INTO field_values (field_id, account_id, value) VALUES (?, ?, ?)", (field_id, 1000 + index, value))
        conn.execute("INSERT INTO credentials_backup (id, account_id, snapshot) VALUES (?, ?, 'legacy')", (index, 1000 + index))
    conn.commit()
    conn.close()
    return plaintexts


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _artifact_bytes(path: Path) -> bytes:
    return b"".join(part.read_bytes() for part in (path, Path(f"{path}-wal"), Path(f"{path}-shm")) if part.exists())


PRE_FEATURE_SECURE_SCHEMA = PRE_FEATURE_SCHEMA


def _append_synthetic_audit_events(conn: sqlite3.Connection, count: int = 25) -> None:
    key = base64.b64decode(DATA_KEY)
    previous_hash = bytes(32)
    for event_id in range(1, count + 1):
        occurred_at = f"2026-01-01T00:00:{event_id:02d}Z"
        metadata_json = "{}"
        payload = {"occurred_at": occurred_at, "actor_user_id": 1, "action": "migration.synthetic", "target_type": "database", "target_id": str(event_id), "metadata_json": metadata_json, "source_ip": None, "user_agent": None}
        event_hash = hmac.new(key, json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8") + previous_hash, hashlib.sha256).digest()
        conn.execute("INSERT INTO audit_events (id, occurred_at, actor_user_id, action, target_type, target_id, metadata_json, source_ip, user_agent, previous_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (event_id, occurred_at, 1, "migration.synthetic", "database", str(event_id), metadata_json, None, None, previous_hash, event_hash))
        previous_hash = event_hash


def _old_secure_source(path: Path, *, users: int = 1, services: int = 1) -> None:
    """Build a pre-feature-schema secure database (users already carry username,
    no TOTP/recovery/bootstrap tables). Seeds services and users so the auth
    cutover's membership backfill can be exercised."""
    conn = sqlite3.connect(path)
    try:
        conn.executescript(PRE_FEATURE_SECURE_SCHEMA)
        for offset in range(services):
            conn.execute("INSERT INTO services (id, name) VALUES (?, ?)", (9 + offset, f"Synthetic service {offset}"))
        key = base64.b64decode(DATA_KEY)
        acct_nonce = b"p" * 12
        acct_cipher = AESGCM(key).encrypt(acct_nonce, b"account-secret", b"account:41:password")
        conn.execute("INSERT INTO accounts (id, email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, ?, ?)", (41, "service@example.test", acct_cipher, acct_nonce, 1))
        conn.execute("INSERT INTO custom_fields (id, service_id, name) VALUES (12, 9, 'Token')")
        conn.execute("INSERT INTO account_service (account_id, service_id, status, registered) VALUES (41, 9, 'ativo', 1)")
        field_nonce = b"f" * 12
        field_cipher = AESGCM(key).encrypt(field_nonce, b"field-secret", b"account:41:field:12")
        conn.execute("INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, ?)", (12, 41, field_cipher, field_nonce, 1))
        stamp = "2026-01-01T00:00:00Z"
        for user_id in range(1, users + 1):
            conn.execute("INSERT INTO users (id, username, password_hash, role, is_active, must_change_password, created_at, updated_at, password_changed_at, session_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (user_id, f"operator-{user_id}", f"argon2-hash-{user_id}", "admin" if user_id == 1 else "operador", 1, 0, stamp, stamp, stamp, 4))
        conn.execute("INSERT INTO security_events (id, kind, subject, source_ip, occurred_at) VALUES (7, 'login_failure', 'operator-1@example.test', '127.0.0.1', ?)", (stamp,))
        _append_synthetic_audit_events(conn)
        for table, sequence in {"accounts": 99, "services": 97, "custom_fields": 96, "users": 95, "security_events": 94, "audit_events": 93}.items():
            conn.execute("UPDATE sqlite_sequence SET seq = ? WHERE name = ?", (sequence, table))
        conn.commit()
    finally:
        conn.close()


def _table_rows(conn: sqlite3.Connection, table: str) -> list[tuple[object, ...]]:
    return [tuple(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]



def test_auth_schema_migration_exposes_the_approved_api():
    migration = _script_module("migrate_auth_schema")

    assert list(inspect.signature(migration.migrate).parameters) == ["source_path", "target_path", "audit_key_env", "data_key_env"]
    assert inspect.signature(migration.migrate).parameters["audit_key_env"].default == "AUDIT_KEY_V1"
    assert inspect.signature(migration.migrate).parameters["data_key_env"].default == "DATA_KEY_V1"


def _run_auth_migration(source: Path, target: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDIT_KEY_V1", DATA_KEY)
    pre_preferences = target.with_name(f".{target.name}.pre-preferences")
    auth_migration = _script_module("migrate_auth_schema")
    preferences_migration = _script_module("migrate_service_preferences")
    try:
        auth_migration.migrate(source, pre_preferences, "AUDIT_KEY_V1")
        preferences_migration.migrate(pre_preferences, target, "AUDIT_KEY_V1")
    finally:
        pre_preferences.unlink(missing_ok=True)


def _run_legacy_migration(source: Path, target: Path, *, key_env: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    pre_preferences = target.with_name(f".{target.name}.pre-preferences")
    first = _run(MIGRATE, "--source", str(source), "--target", str(pre_preferences), "--key-env", key_env, env=env)
    if first.returncode != 0:
        return first
    second = _run(
        SERVICE_PREFERENCES_MIGRATE,
        "--source", str(pre_preferences),
        "--target", str(target),
        env={**env, "AUDIT_KEY_V1": env[key_env]},
    )
    pre_preferences.unlink(missing_ok=True)
    return second

_PRE_PREFERENCES_TABLES = {
    "accounts", "services", "account_service", "custom_fields", "field_values", "users",
    "security_events", "audit_events", "service_members",
    "webhook_configs", "webhook_subscriptions", "webhook_deliveries", "app_settings",
}
_NEW_CANONICAL_TABLES = _PRE_PREFERENCES_TABLES | {"user_service_preferences"}


def _pre_service_preferences_source(path: Path) -> None:
    schema = _script_module("service_preferences_schema").PRE_SERVICE_PREFERENCES_SCHEMA
    conn = sqlite3.connect(path)
    try:
        conn.executescript(schema)
        stamp = "2026-01-01T00:00:00Z"
        conn.execute("INSERT INTO services (id, name) VALUES (9, 'Mail')")
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, created_at, updated_at) VALUES (1, 'admin', 'hash', 'admin', ?, ?)",
            (stamp, stamp),
        )
        conn.execute("INSERT INTO service_members (user_id, service_id, role, created_at) VALUES (1, 9, 'service_admin', ?)", (stamp,))
        conn.execute("UPDATE sqlite_sequence SET seq=17 WHERE name='services'")
        conn.execute("UPDATE sqlite_sequence SET seq=11 WHERE name='users'")
        conn.commit()
    finally:
        conn.close()


def test_service_preferences_migration_api_and_preservation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    migration = _script_module("migrate_service_preferences")
    assert list(inspect.signature(migration.migrate).parameters) == ["source_path", "target_path", "audit_key_env"]
    assert inspect.signature(migration.migrate).parameters["audit_key_env"].default == "AUDIT_KEY_V1"
    source = tmp_path / "pre-preferences.db"
    target = tmp_path / "current.db"
    _pre_service_preferences_source(source)
    source_conn = sqlite3.connect(source)
    old_tables = {
        row[0]
        for row in source_conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    }
    expected_rows = {table: _table_rows(source_conn, table) for table in old_tables}
    expected_sequences = _table_rows(source_conn, "sqlite_sequence")
    source_conn.close()
    monkeypatch.setenv("AUDIT_KEY_V1", DATA_KEY)
    migration.migrate(source, target)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    conn = sqlite3.connect(target)
    try:
        assert {table: _table_rows(conn, table) for table in old_tables} == expected_rows
        assert _table_rows(conn, "sqlite_sequence") == expected_sequences
        assert conn.execute("SELECT COUNT(*) FROM user_service_preferences").fetchone()[0] == 0
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert list(conn.execute("PRAGMA foreign_key_check")) == []
    finally:
        conn.close()

    result = _run(
        SERVICE_PREFERENCES_MIGRATE,
        "--source", str(source),
        "--target", str(tmp_path / "cli-current.db"),
        env={"AUDIT_KEY_V1": DATA_KEY},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "OK: service preferences schema migrated"


def test_service_preferences_migration_rejects_already_migrated_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "current.db"
    target = tmp_path / "other.db"
    conn = sqlite3.connect(source)
    conn.executescript(_script_module("migrate_service_preferences").TARGET_SCHEMA)
    conn.close()
    monkeypatch.setenv("AUDIT_KEY_V1", DATA_KEY)
    with pytest.raises(Exception, match="source schema is incompatible|target schema is incompatible"):
        _script_module("migrate_service_preferences").migrate(source, target)


def test_auth_schema_migration_snapshots_wal_and_preserves_every_value(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "old-secure.db"
    target = tmp_path / "new-secure.db"
    _old_secure_source(source, users=2)
    writer = sqlite3.connect(source)
    writer.execute("PRAGMA journal_mode = WAL")
    writer.execute("UPDATE services SET name = 'Confirmed WAL service' WHERE id = 9")
    writer.commit()
    source_conn = sqlite3.connect(source)
    expected_audit_events = _table_rows(source_conn, "audit_events")
    preserved_queries = {
        "services": "SELECT id, name FROM services ORDER BY id",
        "accounts": "SELECT id, email, password_ciphertext, password_nonce, password_key_version FROM accounts ORDER BY id",
        "security_events": "SELECT id, kind, subject, source_ip, occurred_at FROM security_events ORDER BY id",
        "account_service": "SELECT account_id, service_id, status, registered FROM account_service ORDER BY account_id, service_id",
    }
    expected_business_rows = {table: [tuple(row) for row in source_conn.execute(query)] for table, query in preserved_queries.items()}
    expected_custom_fields = [(row[0], row[1], row[2]) for row in source_conn.execute("SELECT id, service_id, name FROM custom_fields ORDER BY id")]
    expected_field_values = [tuple(row) for row in source_conn.execute("SELECT field_id, account_id, value_ciphertext, value_nonce, value_key_version FROM field_values ORDER BY field_id, account_id")]
    expected_sequences = dict(source_conn.execute("SELECT name, seq FROM sqlite_sequence WHERE name IN ('accounts', 'services', 'custom_fields', 'users', 'security_events', 'audit_events')"))
    expected_users = [tuple(row) for row in source_conn.execute("SELECT id, username, password_hash, role, is_active, must_change_password, created_at, updated_at, password_changed_at, session_version FROM users ORDER BY id")]
    source_conn.close()
    source_artifacts = _artifact_bytes(source)

    _run_auth_migration(source, target, monkeypatch)
    assert source_artifacts == _artifact_bytes(source)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert not any(path.exists() for path in _sidecars(target))
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    assert {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")} == _NEW_CANONICAL_TABLES
    assert all([tuple(row) for row in conn.execute(preserved_queries[table])] == rows for table, rows in expected_business_rows.items())
    assert [(row["id"], row["service_id"], row["name"]) for row in conn.execute("SELECT id, service_id, name FROM custom_fields ORDER BY id")] == expected_custom_fields
    assert [tuple(row) for row in conn.execute("SELECT field_id, account_id, value_ciphertext, value_nonce, value_key_version FROM field_values ORDER BY field_id, account_id")] == expected_field_values
    assert _table_rows(conn, "audit_events") == expected_audit_events
    assert [tuple(row) for row in conn.execute("SELECT id, username, password_hash, role, is_active, must_change_password, created_at, updated_at, password_changed_at, session_version FROM users ORDER BY id")] == expected_users
    assert dict(conn.execute("SELECT name, seq FROM sqlite_sequence WHERE name IN ('accounts', 'services', 'custom_fields', 'users', 'security_events', 'audit_events')")) == expected_sequences
    # New rotation metadata must be NULL.
    assert conn.execute("SELECT COUNT(*) FROM accounts WHERE password_changed_at IS NOT NULL").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM services WHERE rotation_days IS NOT NULL").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM account_service WHERE rotation_days IS NOT NULL OR rotation_due_at IS NOT NULL").fetchone()[0] == 0
    # New webhook tables must be empty.
    for table in ("webhook_configs", "webhook_subscriptions", "webhook_deliveries"):
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    # Membership backfill: one active non-admin user (id 2) x one service.
    members = {tuple(row) for row in conn.execute("SELECT user_id, service_id, role FROM service_members")}
    assert members == {(2, 9, "service_admin")}
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert list(conn.execute("PRAGMA foreign_key_check")) == []
    from service_manager.audit import verify_audit_chain_with_key

    assert verify_audit_chain_with_key(conn, base64.b64decode(DATA_KEY))
    conn.close()
    writer.close()


def test_auth_schema_migration_backfills_membership_for_active_non_admins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "old-secure.db"
    target = tmp_path / "new-secure.db"
    # 1 admin + 2 operators, one deactivated; 2 services.
    _old_secure_source(source, users=3, services=2)
    conn = sqlite3.connect(source)
    conn.execute("UPDATE users SET is_active = 0 WHERE id = 3")
    conn.commit()
    conn.close()

    _run_auth_migration(source, target, monkeypatch)

    migrated = sqlite3.connect(target)
    try:
        # Only user 2 (active operator) receives memberships, on both services.
        members = {tuple(row) for row in migrated.execute("SELECT user_id, service_id, role FROM service_members")}
        assert members == {(2, 9, "service_admin"), (2, 10, "service_admin")}
        assert migrated.execute("SELECT COUNT(*) FROM service_members").fetchone()[0] == 2
    finally:
        migrated.close()


def test_auth_schema_migration_rejects_incompatible_source_atomically(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "old-secure.db"
    target = tmp_path / "new-secure.db"
    _old_secure_source(source)
    # Add a table absent from the frozen pre-feature schema to break source validation.
    conn = sqlite3.connect(source)
    conn.execute("CREATE TABLE rogue_table (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()
    source_artifacts = _artifact_bytes(source)
    sentinel = b"preexisting-target-bytes"
    target.write_bytes(sentinel)

    migration = _script_module("migrate_auth_schema")
    with pytest.raises(migration.ScriptError, match="source schema"):
        _run_auth_migration(source, target, monkeypatch)

    assert source_artifacts == _artifact_bytes(source)
    assert target.read_bytes() == sentinel
    assert not any(tmp_path.glob(".new-secure.db.*.tmp*"))
    assert not any(path.exists() for path in _sidecars(target))


def test_auth_schema_migration_preserves_empty_surviving_table_sequence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "old-secure.db"
    target = tmp_path / "new-secure.db"
    _old_secure_source(source)
    conn = sqlite3.connect(source)
    conn.execute("DELETE FROM security_events")
    conn.commit()
    assert conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'security_events'").fetchone()[0] == 94
    conn.close()

    _run_auth_migration(source, target, monkeypatch)

    migrated = sqlite3.connect(target)
    assert migrated.execute("SELECT seq FROM sqlite_sequence WHERE name = 'security_events'").fetchone()[0] == 94
    migrated.close()


@pytest.mark.parametrize(
    ("object_type", "name", "before", "after"),
    (
        ("table", "users", "CHECK (role IN ('admin', 'operador'))", "CHECK (role IN ('admin'))"),
        ("trigger", "audit_events_no_update", "audit_events is append-only", "audit mutation accepted"),
        ("index", "security_events_occurred_at", "security_events(occurred_at)", "security_events(subject)"),
    ),
)
def test_auth_schema_migration_rejects_old_schema_object_semantic_weakening(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, object_type: str, name: str, before: str, after: str):
    source = tmp_path / "old-secure.db"
    target = tmp_path / "new-secure.db"
    _old_secure_source(source)
    _weaken_schema_sql(source, object_type, name, before, after)

    migration = _script_module("migrate_auth_schema")
    with pytest.raises(migration.ScriptError, match="source schema"):
        _run_auth_migration(source, target, monkeypatch)

def test_auth_schema_migration_restores_existing_target_when_rollback_cleanup_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "old-secure.db"
    target = tmp_path / "new-secure.db"
    _old_secure_source(source)
    sentinel = b"preexisting-target-bytes"
    target.write_bytes(sentinel)
    migration = _script_module("migrate_auth_schema")
    migration_io = _script_module("_migration_io")
    original_remove_artifacts = migration_io.remove_artifacts

    def fail_rollback_cleanup(*paths: Path | None) -> None:
        if any(path is not None and path.suffix == ".rollback" for path in paths):
            raise migration_io.ScriptError("temporary artifact cleanup failed")
        original_remove_artifacts(*paths)

    monkeypatch.setattr(migration_io, "remove_artifacts", fail_rollback_cleanup)
    with pytest.raises(migration.ScriptError, match="recovery"):
        _run_auth_migration(source, target, monkeypatch)
    assert target.read_bytes() == sentinel

def test_new_schema_backup_restore_round_trip_is_restorable_and_byte_for_byte_complete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "old-secure.db"
    migrated = tmp_path / "new-secure.db"
    encrypted = tmp_path / "new-secure.smbk"
    restored = tmp_path / "restored.db"
    _old_secure_source(source, users=2)
    _run_auth_migration(source, migrated, monkeypatch)
    backup = _script_module("backup")
    restore = _script_module("restore_backup")
    monkeypatch.setenv("TEST_BACKUP_KEY", BACKUP_KEY)
    monkeypatch.setenv("AUDIT_KEY_V1", DATA_KEY)

    backup.backup(migrated, encrypted, "TEST_BACKUP_KEY")
    restore.restore(encrypted, restored, "TEST_BACKUP_KEY")

    from service_manager.audit import verify_audit_chain_with_key
    from service_manager.db import schema_is_current

    assert stat.S_IMODE(restored.stat().st_mode) == 0o600
    source_conn = sqlite3.connect(migrated)
    restored_conn = sqlite3.connect(restored)
    restored_conn.row_factory = sqlite3.Row
    assert schema_is_current(restored_conn)
    assert restored_conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert list(restored_conn.execute("PRAGMA foreign_key_check")) == []
    assert verify_audit_chain_with_key(restored_conn, base64.b64decode(DATA_KEY))
    tables = ("services", "accounts", "users", "custom_fields", "account_service", "field_values", "security_events", "audit_events", "service_members")
    assert all(_table_rows(source_conn, table) == _table_rows(restored_conn, table) for table in tables)
    assert _table_rows(source_conn, "sqlite_sequence") == _table_rows(restored_conn, "sqlite_sequence")
    source_conn.close()
    restored_conn.close()

def test_auth_schema_migration_proof_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """End-to-end migration proof gate: exact preservation of old columns, NULL
    rotation metadata, membership backfill, valid AES-GCM secrets, preserved
    sequences, integrity/foreign-key health, canonical schema, and audit chain."""
    source = tmp_path / "old-secure.db"
    target = tmp_path / "new-secure.db"
    _old_secure_source(source, users=3, services=2)

    source_conn = sqlite3.connect(source)
    source_conn.row_factory = sqlite3.Row
    old_accounts = [tuple(row) for row in source_conn.execute("SELECT id, email, password_ciphertext, password_nonce, password_key_version FROM accounts ORDER BY id")]
    old_services = [tuple(row) for row in source_conn.execute("SELECT id, name FROM services ORDER BY id")]
    old_links = [tuple(row) for row in source_conn.execute("SELECT account_id, service_id, status, registered FROM account_service ORDER BY account_id, service_id")]
    old_field_values = [tuple(row) for row in source_conn.execute("SELECT field_id, account_id, value_ciphertext, value_nonce, value_key_version FROM field_values ORDER BY field_id, account_id")]
    old_users = [tuple(row) for row in source_conn.execute("SELECT id, username, password_hash, role, is_active, must_change_password, created_at, updated_at, password_changed_at, session_version FROM users ORDER BY id")]
    old_audit = [tuple(row) for row in source_conn.execute("SELECT id, occurred_at, action, previous_hash, event_hash FROM audit_events ORDER BY id")]
    old_sequences = dict(source_conn.execute("SELECT name, seq FROM sqlite_sequence WHERE name IN ('accounts', 'services', 'custom_fields', 'users', 'security_events', 'audit_events')"))
    source_conn.close()
    assert len(old_audit) == 25

    _run_auth_migration(source, target, monkeypatch)

    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    try:
        assert [tuple(row) for row in conn.execute("SELECT id, email, password_ciphertext, password_nonce, password_key_version FROM accounts ORDER BY id")] == old_accounts
        assert [tuple(row) for row in conn.execute("SELECT id, name FROM services ORDER BY id")] == old_services
        assert [tuple(row) for row in conn.execute("SELECT account_id, service_id, status, registered FROM account_service ORDER BY account_id, service_id")] == old_links
        assert [tuple(row) for row in conn.execute("SELECT field_id, account_id, value_ciphertext, value_nonce, value_key_version FROM field_values ORDER BY field_id, account_id")] == old_field_values
        assert [tuple(row) for row in conn.execute("SELECT id, username, password_hash, role, is_active, must_change_password, created_at, updated_at, password_changed_at, session_version FROM users ORDER BY id")] == old_users
        assert [tuple(row) for row in conn.execute("SELECT id, occurred_at, action, previous_hash, event_hash FROM audit_events ORDER BY id")] == old_audit
        # NULL rotation metadata everywhere.
        assert conn.execute("SELECT COUNT(*) FROM accounts WHERE password_changed_at IS NOT NULL").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM services WHERE rotation_days IS NOT NULL").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM account_service WHERE rotation_days IS NOT NULL OR rotation_due_at IS NOT NULL").fetchone()[0] == 0
        # service_admin membership for each active non-admin x service (users 2,3 active operators; 2 services).
        active_non_admin = [row[0] for row in conn.execute("SELECT id FROM users WHERE is_active = 1 AND role != 'admin' ORDER BY id")]
        services = [row[0] for row in conn.execute("SELECT id FROM services ORDER BY id")]
        expected_members = {(u, s, "service_admin") for u in active_non_admin for s in services}
        assert {tuple(row) for row in conn.execute("SELECT user_id, service_id, role FROM service_members")} == expected_members
        assert conn.execute("SELECT COUNT(*) FROM service_members").fetchone()[0] == len(active_non_admin) * len(services)
        # Valid AES-GCM secrets under the data key.
        key = base64.b64decode(DATA_KEY)
        for row in conn.execute("SELECT id, password_ciphertext, password_nonce FROM accounts ORDER BY id"):
            AESGCM(key).decrypt(bytes(row["password_nonce"]), bytes(row["password_ciphertext"]), f"account:{row['id']}:password".encode())
        # Preserved sequences.
        assert dict(conn.execute("SELECT name, seq FROM sqlite_sequence WHERE name IN ('accounts', 'services', 'custom_fields', 'users', 'security_events', 'audit_events')")) == old_sequences
        # Integrity, foreign keys, canonical schema, and audit chain.
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert list(conn.execute("PRAGMA foreign_key_check")) == []
        from service_manager.db import schema_is_current
        from service_manager.audit import verify_audit_chain_with_key
        assert schema_is_current(conn)
        assert verify_audit_chain_with_key(conn, key)
    finally:
        conn.close()

def test_auth_schema_migration_cli_reports_safe_validated_counts(tmp_path: Path):
    source = tmp_path / "old-secure.db"
    target = tmp_path / "new-secure.db"
    _old_secure_source(source, users=2)

    result = _run(
        AUTH_MIGRATE,
        "--source", str(source),
        "--target", str(target),
        env={"AUDIT_KEY_V1": DATA_KEY},
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "OK: users=2 accounts=1 audit_events=25 service_members=1"

def test_compare_business_data_reports_matching_secret_free_legacy_and_secure_digests(tmp_path: Path):
    source = tmp_path / "legacy.db"
    secure = tmp_path / "secure.db"
    _legacy_source(source)
    assert _run_legacy_migration(source, secure, key_env="TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0

    comparison = ROOT / "scripts" / "compare_business_data.py"
    legacy = _run(comparison, "legacy", "--database", str(source), env={})
    encrypted = _run(comparison, "secure", "--database", str(secure), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert legacy.returncode == 0, legacy.stderr
    assert encrypted.returncode == 0, encrypted.stderr
    legacy_result = json.loads(legacy.stdout)
    secure_result = json.loads(encrypted.stdout)
    assert legacy_result == secure_result
    assert set(legacy_result) == {"counts", "sha256"}
    assert legacy_result["counts"] == {"services": 2, "custom_fields": 2, "accounts": 116, "account_service": 116, "field_values": 116}
    assert all(secret not in legacy.stdout + legacy.stderr + encrypted.stdout + encrypted.stderr for secret in ("migration-password-2-only", "migration-field-2-only"))

def test_record_auth_migration_appends_one_idempotent_audit_event(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "old-secure.db"
    migrated = tmp_path / "new-secure.db"
    _old_secure_source(source)
    _run_auth_migration(source, migrated, monkeypatch)
    recorder = _script_module("record_auth_migration")
    monkeypatch.setenv("DATABASE_PATH", str(migrated))
    monkeypatch.setenv("DATA_KEY_V1", DATA_KEY)
    monkeypatch.setenv("AUDIT_KEY_V1", DATA_KEY)
    monkeypatch.setenv("SECRET_KEY", "record-migration-test")

    recorder.record()
    recorder.record()

    conn = sqlite3.connect(migrated)
    conn.row_factory = sqlite3.Row
    try:
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='auth.schema_migrated'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 26
        assert conn.execute("SELECT id FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()[0] == 26
        from _secure_db import load_key
        from service_manager.audit import verify_audit_chain_with_key
        assert verify_audit_chain_with_key(conn, load_key("AUDIT_KEY_V1"))
    finally:
        conn.close()

def test_audit_events_append_contiguous_ids_despite_high_preserved_sequence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "old-secure.db"
    migrated = tmp_path / "new-secure.db"
    _old_secure_source(source)
    _run_auth_migration(source, migrated, monkeypatch)

    app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(migrated),
            "DATA_KEY_V1": DATA_KEY,
            "AUDIT_KEY_V1": DATA_KEY,
            "SECRET_KEY": "contiguous-audit-test",
        }
    )
    with app.app_context():
        from _secure_db import load_key
        from service_manager.audit import append_audit_event, verify_audit_chain_with_key
        from service_manager.db import get_db, transaction as app_transaction
        conn = get_db()
        key = load_key("AUDIT_KEY_V1")
        with app_transaction(conn):
            append_audit_event(conn, action="test.first", target_type="test")
            append_audit_event(conn, action="test.second", target_type="test")
        ids = [row[0] for row in conn.execute("SELECT id FROM audit_events WHERE action LIKE 'test.%' ORDER BY id")]
        assert ids == [26, 27]
        assert verify_audit_chain_with_key(conn, key)
        assert conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'audit_events'").fetchone()[0] == 93

def test_migration_creates_secure_id_preserving_target_and_handles_empty_values(tmp_path: Path):
    source = tmp_path / "synthetic-legacy.db"
    target = tmp_path / "migrated.db"
    plaintexts = _legacy_source(source)
    source_digest = hashlib.sha256(source.read_bytes()).digest()

    result = _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert result.returncode == 0, result.stderr
    assert "accounts=116" in result.stdout
    assert "migration-password-2-only" not in result.stdout
    assert source_digest == hashlib.sha256(source.read_bytes()).digest()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    conn = sqlite3.connect(target)
    assert conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 116
    assert conn.execute("SELECT COUNT(*) FROM account_service").fetchone()[0] == 116
    assert conn.execute("SELECT COUNT(*) FROM field_values").fetchone()[0] == 116
    assert conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'credentials_backup'").fetchone() is None
    assert "password" not in _table_columns(conn, "accounts")
    assert "value" not in _table_columns(conn, "field_values")
    assert "is_secret" not in _table_columns(conn, "custom_fields")
    nonces = [row[0] for row in conn.execute("SELECT password_nonce FROM accounts")] + [row[0] for row in conn.execute("SELECT value_nonce FROM field_values")]
    assert len(nonces) == len(set(nonces)) == 232
    key = base64.b64decode(DATA_KEY)
    account = conn.execute("SELECT id, password_ciphertext, password_nonce FROM accounts WHERE id = 1001").fetchone()
    assert AESGCM(key).decrypt(account[2], account[1], b"account:1001:password") == b""
    field = conn.execute("SELECT value_ciphertext, value_nonce FROM field_values WHERE field_id = 29 AND account_id = 1001").fetchone()
    assert AESGCM(key).decrypt(field[1], field[0], b"account:1001:field:29") == b""
    conn.close()
    target_bytes = _artifact_bytes(target)
    assert all(not value or value.encode() not in target_bytes for value in plaintexts)


def test_migration_failure_keeps_existing_target_and_leaves_no_temporary_database(tmp_path: Path):
    source = tmp_path / "invalid-count.db"
    target = tmp_path / "target.db"
    _legacy_source(source, accounts=115)
    target.write_bytes(b"sentinel-target")

    result = _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert result.returncode != 0
    assert target.read_bytes() == b"sentinel-target"
    assert not list(tmp_path.glob(".target.db.*.tmp"))
    assert "migration-password" not in result.stdout + result.stderr


def test_migration_rejects_invalid_key_without_replacing_target(tmp_path: Path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    target.write_bytes(b"sentinel-target")

    result = _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": "not-base64"})

    assert result.returncode != 0
    assert target.read_bytes() == b"sentinel-target"


def test_migration_rejects_incompatible_source_schema_without_replacing_target(tmp_path: Path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    conn = sqlite3.connect(source)
    conn.execute("DROP TABLE credentials_backup")
    conn.commit()
    conn.close()
    target.write_bytes(b"sentinel-target")

    result = _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert result.returncode != 0
    assert target.read_bytes() == b"sentinel-target"
    assert not list(tmp_path.glob(".target.db.*.tmp"))


def test_independent_verifier_detects_corruption_nonce_and_permission_failures_without_secrets(tmp_path: Path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0

    clean = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})
    assert clean.returncode == 0, clean.stderr
    target_digest = hashlib.sha256(target.read_bytes()).digest()
    assert _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    assert hashlib.sha256(target.read_bytes()).digest() == target_digest
    os.chmod(target, 0o644)
    permission_failure = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})
    assert permission_failure.returncode != 0
    assert "migration-password-2-only" not in permission_failure.stdout + permission_failure.stderr
    os.chmod(target, 0o600)
    conn = sqlite3.connect(target)
    nonce = conn.execute("SELECT password_nonce FROM accounts WHERE id = 1001").fetchone()[0]
    conn.execute("UPDATE accounts SET password_nonce = ? WHERE id = 1002", (nonce,))
    conn.commit()
    conn.close()
    nonce_failure = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})
    assert nonce_failure.returncode != 0
    assert "migration-password-2-only" not in nonce_failure.stdout + nonce_failure.stderr


def test_independent_verifier_detects_plaintext_residue_without_printing_it(tmp_path: Path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    conn = sqlite3.connect(target)
    conn.execute("CREATE TABLE accidental_residue (contents TEXT NOT NULL)")
    conn.execute("INSERT INTO accidental_residue (contents) VALUES ('migration-password-2-only')")
    conn.commit()
    conn.close()

    result = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert result.returncode != 0
    assert "migration-password-2-only" not in result.stdout + result.stderr


def test_authenticated_backup_round_trip_rejects_wrong_key_tampering_and_invalid_header(tmp_path: Path):
    source = tmp_path / "source.db"
    secure = tmp_path / "secure.db"
    encrypted = tmp_path / "source.smbk"
    restored = tmp_path / "restored.db"
    _legacy_source(source)
    assert _run_legacy_migration(source, secure, key_env="TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    secure_digest = hashlib.sha256(secure.read_bytes()).digest()
    backup_env = {"TEST_BACKUP_KEY": BACKUP_KEY, "AUDIT_KEY_V1": DATA_KEY}

    backed_up = _run(BACKUP, "--source", str(secure), "--target", str(encrypted), "--key-env", "TEST_BACKUP_KEY", env=backup_env)
    assert backed_up.returncode == 0, backed_up.stderr
    assert encrypted.read_bytes()[:5] == b"SMBK\x01"
    assert stat.S_IMODE(encrypted.stat().st_mode) == 0o600
    assert secure_digest == hashlib.sha256(secure.read_bytes()).digest()
    restored_ok = _run(RESTORE, "--source", str(encrypted), "--target", str(restored), "--key-env", "TEST_BACKUP_KEY", env=backup_env)
    assert restored_ok.returncode == 0, restored_ok.stderr
    assert sqlite3.connect(restored).execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert stat.S_IMODE(restored.stat().st_mode) == 0o600

    wrong_key = _run(RESTORE, "--source", str(encrypted), "--target", str(tmp_path / "wrong.db"), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": DATA_KEY, "AUDIT_KEY_V1": DATA_KEY})
    assert wrong_key.returncode != 0
    corrupted = tmp_path / "corrupted.smbk"
    corrupted.write_bytes(encrypted.read_bytes()[:-1] + bytes([encrypted.read_bytes()[-1] ^ 0xFF]))
    assert _run(RESTORE, "--source", str(corrupted), "--target", str(tmp_path / "corrupted.db"), "--key-env", "TEST_BACKUP_KEY", env=backup_env).returncode != 0
    invalid_header = tmp_path / "invalid.smbk"
    invalid_header.write_bytes(b"NOPE\x02" + encrypted.read_bytes()[5:])
    assert _run(RESTORE, "--source", str(invalid_header), "--target", str(tmp_path / "invalid.db"), "--key-env", "TEST_BACKUP_KEY", env=backup_env).returncode != 0



def test_backup_refuses_a_secure_snapshot_with_a_broken_audit_chain(tmp_path: Path):
    source = tmp_path / "source.db"
    secure = tmp_path / "secure.db"
    valid_backup = tmp_path / "valid.smbk"
    rejected_backup = tmp_path / "rejected.smbk"
    _legacy_source(source)
    assert _run_legacy_migration(source, secure, key_env="TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0

    app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(secure),
            "DATA_KEY_V1": DATA_KEY,
            "AUDIT_KEY_V1": DATA_KEY,
            "SECRET_KEY": "backup-audit-test-key",
        }
    )
    from service_manager.audit import append_audit_event
    from service_manager.db import get_db as app_get_db, transaction as app_transaction
    with app.app_context():
        conn = app_get_db()
        with app_transaction(conn):
            append_audit_event(conn, action="backup.test", target_type="test")

    env = {"TEST_BACKUP_KEY": BACKUP_KEY, "AUDIT_KEY_V1": DATA_KEY}
    assert _run(BACKUP, "--source", str(secure), "--target", str(valid_backup), "--key-env", "TEST_BACKUP_KEY", env=env).returncode == 0
    with app.app_context():
        conn = app_get_db()
        conn.execute("DROP TRIGGER audit_events_no_update")
        conn.execute("UPDATE audit_events SET action='tampered' WHERE id=1")
        conn.commit()
    rejected = _run(BACKUP, "--source", str(secure), "--target", str(rejected_backup), "--key-env", "TEST_BACKUP_KEY", env=env)
    assert rejected.returncode != 0
    assert not rejected_backup.exists()

def _sidecars(path: Path) -> tuple[Path, Path]:
    return Path(f"{path}-wal"), Path(f"{path}-shm")


def test_migration_rejects_offline_target_sidecars_and_removes_all_temp_sidecars(tmp_path: Path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    target.write_bytes(b"sentinel-target")
    wal, shm = _sidecars(target)
    wal.write_bytes(b"stale-wal")
    result = _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})
    assert result.returncode != 0
    assert target.read_bytes() == b"sentinel-target"
    assert wal.exists()
    assert not shm.exists()
    assert "migration-password-2-only" not in result.stdout + result.stderr
    wal.unlink()
    shm.write_bytes(b"stale-shm")
    result = _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})
    assert result.returncode != 0
    assert target.read_bytes() == b"sentinel-target"
    assert shm.exists()
    shm.unlink()
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    assert not any(tmp_path.glob(".target.db.*.tmp*"))
    assert not any(path.exists() for path in _sidecars(target))


def test_verifier_rejects_complete_equivalence_and_exact_schema_tampering(tmp_path: Path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    conn = sqlite3.connect(target)
    conn.execute("UPDATE account_service SET status = 'inativo' WHERE account_id = 1001")
    conn.commit()
    conn.close()
    result = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})
    assert result.returncode != 0
    assert "migration-password-2-only" not in result.stdout + result.stderr
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    conn = sqlite3.connect(target)
    conn.execute("DROP TRIGGER audit_events_no_update")
    conn.commit()
    conn.close()
    assert _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode != 0


def test_restore_rejects_stale_sidecars_and_authenticated_wrong_schema_without_replacing_target(tmp_path: Path):
    source = tmp_path / "source.db"
    encrypted = tmp_path / "source.smbk"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(BACKUP, "--source", str(source), "--target", str(encrypted), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY}).returncode == 0
    target.write_bytes(b"sentinel-target")
    wal, shm = _sidecars(target)
    wal.write_bytes(b"stale-wal")
    result = _run(RESTORE, "--source", str(encrypted), "--target", str(target), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY})
    assert result.returncode != 0
    assert target.read_bytes() == b"sentinel-target"
    assert wal.exists()
    wal.unlink()
    empty = tmp_path / "empty.db"
    sqlite3.connect(empty).close()
    nonce = b"n" * 12
    invalid_backup = tmp_path / "empty.smbk"
    invalid_backup.write_bytes(b"SMBK\x01" + nonce + AESGCM(base64.b64decode(BACKUP_KEY)).encrypt(nonce, empty.read_bytes(), b"service-manager-backup:v1"))
    result = _run(RESTORE, "--source", str(invalid_backup), "--target", str(target), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY})
    assert result.returncode != 0
    assert target.read_bytes() == b"sentinel-target"
    assert not any(tmp_path.glob(".target.db.*.tmp*"))


def test_migration_schema_failure_is_atomic_and_cleans_main_and_sidecars(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    migration = _script_module("migrate_legacy_db")
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    target.write_bytes(b"sentinel-target")
    monkeypatch.setenv("TEST_DATA_KEY", DATA_KEY)
    monkeypatch.setattr(migration, "_after_schema_created", lambda: (_ for _ in ()).throw(migration.ScriptError("synthetic failure")))

    with pytest.raises(migration.ScriptError):
        migration.migrate(source, target, "TEST_DATA_KEY")

    assert target.read_bytes() == b"sentinel-target"
    assert not any(tmp_path.glob(".target.db.*.tmp*"))


def test_restore_post_placement_validation_failure_restores_existing_target_and_cleans_rollback_artifacts(tmp_path: Path):
    restore = _script_module("restore_backup")
    source = tmp_path / "source.db"
    encrypted = tmp_path / "source.smbk"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(BACKUP, "--source", str(source), "--target", str(encrypted), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY}).returncode == 0
    sentinel = b"old-target-sentinel"
    target.write_bytes(sentinel)

    with pytest.raises(restore.ScriptError):
        restore.restore(
            encrypted,
            target,
            "TEST_BACKUP_KEY",
            _after_post_placement_validation=lambda: (_ for _ in ()).throw(restore.ScriptError("synthetic failure")),
        )

    assert target.read_bytes() == sentinel
    assert not any(tmp_path.glob(".target.db.*.tmp*"))
    assert not any(tmp_path.glob(".target.db.*.rollback*"))
    assert not any(path.exists() for path in _sidecars(target))


def test_restore_success_removes_rollback_artifacts_after_replacing_existing_target(tmp_path: Path):
    source = tmp_path / "source.db"
    secure = tmp_path / "secure.db"
    encrypted = tmp_path / "source.smbk"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run_legacy_migration(source, secure, key_env="TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    backup_env = {"TEST_BACKUP_KEY": BACKUP_KEY, "AUDIT_KEY_V1": DATA_KEY}
    assert _run(BACKUP, "--source", str(secure), "--target", str(encrypted), "--key-env", "TEST_BACKUP_KEY", env=backup_env).returncode == 0
    target.write_bytes(b"old-target-sentinel")

    result = _run(RESTORE, "--source", str(encrypted), "--target", str(target), "--key-env", "TEST_BACKUP_KEY", env=backup_env)

    assert result.returncode == 0, result.stderr
    assert sqlite3.connect(target).execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert not any(tmp_path.glob(".target.db.*.tmp*"))
    assert not any(tmp_path.glob(".target.db.*.rollback*"))
    assert not any(path.exists() for path in _sidecars(target))


def test_migration_checkpoint_vacuums_then_revalidates_with_a_fresh_connection_before_replacement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import importlib

    scripts_dir = str(ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    migration = importlib.import_module("migrate_legacy_db")
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    statements: list[tuple[object, str]] = []
    real_connect = migration.sqlite3.connect

    class RecordingConnection:
        def __init__(self, connection: sqlite3.Connection):
            object.__setattr__(self, "connection", connection)

        def __getattr__(self, name: str):
            return getattr(self.connection, name)

        def __setattr__(self, name: str, value: object) -> None:
            setattr(self.connection, name, value)

        def execute(self, statement: str, *args: object, **kwargs: object):
            statements.append((self, statement))
            return self.connection.execute(statement, *args, **kwargs)

    def recording_connect(*args: object, **kwargs: object) -> RecordingConnection:
        return RecordingConnection(real_connect(*args, **kwargs))

    validations: list[object] = []
    real_validate = migration._validate_target

    def recording_validate(connection: object, key: bytes, snapshot: tuple[list[sqlite3.Row], ...]) -> None:
        validations.append(connection)
        real_validate(connection, key, snapshot)

    monkeypatch.setattr(migration.sqlite3, "connect", recording_connect)
    monkeypatch.setattr(migration, "_validate_target", recording_validate)
    monkeypatch.setenv("TEST_DATA_KEY", DATA_KEY)

    migration.migrate(source, target, "TEST_DATA_KEY")

    assert len(validations) == 2
    assert validations[0] is not validations[1]
    validation_indices = [index for index, (connection, statement) in enumerate(statements) if connection is validations[1] and statement == "PRAGMA integrity_check"]
    checkpoint_index = next(index for index, (_, statement) in enumerate(statements) if statement == "PRAGMA wal_checkpoint(TRUNCATE)")
    vacuum_index = next(index for index, (_, statement) in enumerate(statements) if statement == "VACUUM")
    assert checkpoint_index < vacuum_index < validation_indices[0]


def test_restore_rejects_stale_shm_without_replacing_sentinel(tmp_path: Path):
    source = tmp_path / "source.db"
    encrypted = tmp_path / "source.smbk"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(BACKUP, "--source", str(source), "--target", str(encrypted), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY}).returncode == 0
    sentinel = b"sentinel-target"
    target.write_bytes(sentinel)
    _, shm = _sidecars(target)
    shm.write_bytes(b"stale-shm")
    result = _run(RESTORE, "--source", str(encrypted), "--target", str(target), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY})
    assert result.returncode != 0
    assert target.read_bytes() == sentinel
    assert shm.exists()
    assert "migration-password-2-only" not in result.stdout + result.stderr


def test_backup_cleanup_failure_is_fatal_and_removes_snapshot_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import importlib

    scripts_dir = str(ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    backup_module = importlib.import_module("backup")
    source = tmp_path / "source.db"
    encrypted = tmp_path / "source.smbk"
    _legacy_source(source)
    monkeypatch.setenv("TEST_BACKUP_KEY", BACKUP_KEY)
    real_remove = backup_module.remove_artifacts

    def fail_after_cleanup(*paths: Path | None) -> None:
        real_remove(*paths)
        raise backup_module.ScriptError("temporary artifact cleanup failed")

    monkeypatch.setattr(backup_module, "remove_artifacts", fail_after_cleanup)
    with pytest.raises(backup_module.ScriptError, match="cleanup"):
        backup_module.backup(source, encrypted, "TEST_BACKUP_KEY")
    assert not any(tmp_path.glob(".backup-snapshot.*"))
    assert not any(tmp_path.glob(".source.smbk.*.tmp*"))


def test_migration_uses_one_source_wal_snapshot_when_writer_commits_after_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import importlib

    scripts_dir = str(ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    migration = importlib.import_module("migrate_legacy_db")
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    writer = sqlite3.connect(source)
    writer.execute("PRAGMA journal_mode = WAL")
    writer.close()
    monkeypatch.setenv("TEST_DATA_KEY", DATA_KEY)

    def concurrent_writer() -> None:
        conn = sqlite3.connect(source)
        conn.execute("UPDATE services SET name = 'writer-after-snapshot' WHERE id = 17")
        conn.commit()
        conn.close()

    monkeypatch.setattr(migration, "_after_source_snapshot", concurrent_writer)
    migration.migrate(source, target, "TEST_DATA_KEY")
    assert sqlite3.connect(target).execute("SELECT name FROM services WHERE id = 17").fetchone()[0] == "Synthetic mail"
    assert sqlite3.connect(source).execute("SELECT name FROM services WHERE id = 17").fetchone()[0] == "writer-after-snapshot"


def _script_module(name: str):
    import importlib

    scripts_dir = str(ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    return importlib.import_module(name)


def test_migration_mid_copy_failure_keeps_target_byte_identical_and_removes_all_temporary_artifacts(
    tmp_path: Path,
):
    migration = _script_module("migrate_legacy_db")
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    sentinel = b"preexisting-target-bytes"
    target.write_bytes(sentinel)

    with pytest.raises(migration.ScriptError):
        migration.migrate(
            source,
            target,
            "TEST_DATA_KEY",
            _after_account_copy=lambda: (_ for _ in ()).throw(migration.ScriptError("synthetic failure")),
        )

    assert target.read_bytes() == sentinel
    assert not any(tmp_path.glob(".target.db.*.tmp*"))
    assert not any(path.exists() for path in _sidecars(target))


def test_migration_and_verifier_pin_the_approved_wal_snapshot_before_a_concurrent_writer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    migration = _script_module("migrate_legacy_db")
    verifier = _script_module("verify_migrated_db")
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    writer = sqlite3.connect(source)
    writer.execute("PRAGMA journal_mode = WAL")
    writer.commit()
    monkeypatch.setenv("TEST_DATA_KEY", DATA_KEY)

    def change_source_after_snapshot() -> None:
        writer.execute("UPDATE services SET name = 'writer-mutation' WHERE id = 17")
        writer.commit()

    migration.migrate(source, target, "TEST_DATA_KEY", _after_snapshot_ready=change_source_after_snapshot)
    assert sqlite3.connect(target).execute("SELECT name FROM services WHERE id = 17").fetchone()[0] == "Synthetic mail"

    writer.execute("UPDATE services SET name = 'Synthetic mail' WHERE id = 17")
    writer.commit()
    verifier.verify(source, target, "TEST_DATA_KEY", _after_snapshot_ready=change_source_after_snapshot)
    writer.close()


@pytest.mark.parametrize(
    "mutation",
    (
        lambda conn: conn.execute("UPDATE services SET name = 'corrupt-service-name' WHERE id = 17"),
        lambda conn: conn.execute("UPDATE services SET id = 117 WHERE id = 17"),
        lambda conn: conn.execute("UPDATE custom_fields SET name = 'corrupt-field-name' WHERE id = 29"),
        lambda conn: conn.execute("UPDATE custom_fields SET service_id = 18 WHERE id = 29"),
        lambda conn: conn.execute("UPDATE accounts SET id = 9001 WHERE id = 1001"),
        lambda conn: conn.execute("UPDATE accounts SET email = 'corrupt@example.test' WHERE id = 1001"),
        lambda conn: conn.execute("UPDATE account_service SET service_id = 18 WHERE account_id = 1001"),
        lambda conn: conn.execute("UPDATE account_service SET status = 'inativo' WHERE account_id = 1001"),
        lambda conn: conn.execute("UPDATE field_values SET value_ciphertext = (SELECT value_ciphertext FROM field_values WHERE account_id = 1002) WHERE account_id = 1001"),
    ),
    ids=("service-name", "service-id", "field-name", "field-service", "account-id", "account-email", "link-service", "link-status", "encrypted-value-relationship"),
)
def test_verifier_independently_rejects_complete_relationship_equivalence_corruption(
    tmp_path: Path, mutation
):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    conn = sqlite3.connect(target)
    mutation(conn)
    conn.commit()
    conn.close()

    result = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert result.returncode != 0
    assert "migration-password-2-only" not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "mutation",
    (
        lambda conn: conn.execute("ALTER TABLE users ADD COLUMN email TEXT"),
        lambda conn: conn.execute("ALTER TABLE accounts ADD COLUMN password TEXT"),
        lambda conn: conn.execute("ALTER TABLE field_values ADD COLUMN value TEXT"),
        lambda conn: conn.execute("DROP TRIGGER audit_events_no_delete"),
        lambda conn: conn.execute("ALTER TABLE custom_fields ADD COLUMN is_secret INTEGER"),
        lambda conn: conn.execute("CREATE TABLE unexpected_user_table (id INTEGER)"),
    ),
    ids=("legacy-user-email-column", "legacy-password-column", "legacy-value-column", "audit-trigger", "field-classification-column", "unexpected-table"),
)
def test_verifier_requires_the_exact_secure_user_schema_and_excludes_sqlite_internal_tables(tmp_path: Path, mutation):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    clean = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})
    assert clean.returncode == 0, clean.stderr
    conn = sqlite3.connect(target)
    mutation(conn)
    conn.commit()
    conn.close()

    result = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert result.returncode != 0
    assert "migration-password-2-only" not in result.stdout + result.stderr


def test_backup_wal_snapshot_cleans_snapshot_artifacts_and_cleanup_failure_never_reports_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    backup = _script_module("backup")
    secure = _script_module("_secure_db")
    source = tmp_path / "source.db"
    target = tmp_path / "source.smbk"
    _legacy_source(source)
    writer = sqlite3.connect(source)
    writer.execute("PRAGMA journal_mode = WAL")
    writer.execute("UPDATE services SET name = 'WAL snapshot' WHERE id = 17")
    writer.commit()
    assert Path(f"{source}-wal").exists()
    monkeypatch.setenv("TEST_BACKUP_KEY", BACKUP_KEY)

    backup.backup(source, target, "TEST_BACKUP_KEY")
    assert target.exists()
    assert not any(tmp_path.glob(".backup-snapshot.*"))
    writer.close()

    def failed_cleanup(*_: Path | None) -> None:
        raise secure.ScriptError("temporary artifact cleanup failed")

    monkeypatch.setattr(backup, "remove_artifacts", failed_cleanup)
    monkeypatch.setattr(backup, "parse_args", lambda: argparse.Namespace(source=str(source), target=str(tmp_path / "failed.smbk"), key_env="TEST_BACKUP_KEY"))
    assert backup.main() == 1
    output = capsys.readouterr()
    assert "OK:" not in output.out
    assert "migration-password-2-only" not in output.out + output.err
    secure.remove_artifacts(*tmp_path.glob(".backup-snapshot.*"))


@pytest.mark.parametrize("artifact_suffix", ("", "-wal", "-shm"), ids=("main", "wal", "shm"))
def test_remove_artifacts_unlink_failure_is_fatal_for_each_database_artifact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, artifact_suffix: str):
    secure = _script_module("_secure_db")
    database = tmp_path / "temporary.db"
    artifact = Path(f"{database}{artifact_suffix}")
    artifact.write_bytes(b"synthetic-artifact")
    original_unlink = Path.unlink

    def fail_selected_unlink(path: Path, *args, **kwargs):
        if path == artifact:
            raise OSError("synthetic unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_selected_unlink)
    with pytest.raises(secure.ScriptError, match="cleanup"):
        secure.remove_artifacts(database)
    assert artifact.exists()


def test_restore_rejects_incompatible_payloads_and_rolls_back_no_prior_target_sidecar_failure(tmp_path: Path):
    import shutil

    restore = _script_module("restore_backup")
    source = tmp_path / "source.db"
    secure_target = tmp_path / "secure.db"
    _legacy_source(source)
    assert _run_legacy_migration(source, secure_target, key_env="TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0

    legacy_wrong = tmp_path / "legacy-wrong.db"
    _legacy_source(legacy_wrong, accounts=115)
    tampered = tmp_path / "tampered.db"
    shutil.copy(secure_target, tampered)
    conn = sqlite3.connect(tampered)
    conn.execute("CREATE TABLE rogue_table (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()

    def authenticated_payload(database: Path, path: Path) -> None:
        nonce = b"n" * 12
        path.write_bytes(b"SMBK\x01" + nonce + AESGCM(base64.b64decode(BACKUP_KEY)).encrypt(nonce, database.read_bytes(), b"service-manager-backup:v1"))

    for label, database in (("legacy", legacy_wrong), ("tampered", tampered)):
        backup_path = tmp_path / f"{label}.smbk"
        target = tmp_path / f"{label}-target.db"
        sentinel = b"target-sentinel"
        target.write_bytes(sentinel)
        authenticated_payload(database, backup_path)
        result = _run(RESTORE, "--source", str(backup_path), "--target", str(target), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY})
        assert result.returncode != 0
        assert target.read_bytes() == sentinel
        assert "migration-password-2-only" not in result.stdout + result.stderr

    valid_backup = tmp_path / "valid.smbk"
    assert _run(BACKUP, "--source", str(secure_target), "--target", str(valid_backup), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY, "AUDIT_KEY_V1": DATA_KEY}).returncode == 0
    new_target = tmp_path / "new-target.db"
    with pytest.raises(restore.ScriptError):
        restore.restore(valid_backup, new_target, "TEST_BACKUP_KEY", _after_post_placement_validation=lambda: Path(f"{new_target}-shm").write_bytes(b"synthetic-sidecar"))
    assert not new_target.exists()
    assert not any(path.exists() for path in _sidecars(new_target))


def test_backup_and_restore_roundtrip_after_legitimate_account_deletion(tmp_path: Path):
    source = tmp_path / "source.db"
    secure_target = tmp_path / "secure.db"
    _legacy_source(source)
    assert _run_legacy_migration(source, secure_target, key_env="TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0

    conn = sqlite3.connect(secure_target)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("DELETE FROM accounts WHERE id = 1001")
    conn.commit()
    conn.close()
    assert sqlite3.connect(secure_target).execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 115

    backup_path = tmp_path / "live.smbk"
    assert _run(BACKUP, "--source", str(secure_target), "--target", str(backup_path), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY, "AUDIT_KEY_V1": DATA_KEY}).returncode == 0

    restored = tmp_path / "restored.db"
    assert _run(RESTORE, "--source", str(backup_path), "--target", str(restored), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY, "AUDIT_KEY_V1": DATA_KEY}).returncode == 0
    conn = sqlite3.connect(restored)
    try:
        assert conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 115
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert list(conn.execute("PRAGMA foreign_key_check")) == []
    finally:
        conn.close()


def test_restore_rejects_authenticated_legacy_backup_and_preserves_target(tmp_path: Path):
    source = tmp_path / "legacy.db"
    encrypted = tmp_path / "legacy.smbk"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(BACKUP, "--source", str(source), "--target", str(encrypted), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY}).returncode == 0
    sentinel = b"secure-production-target"
    target.write_bytes(sentinel)

    result = _run(RESTORE, "--source", str(encrypted), "--target", str(target), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY, "AUDIT_KEY_V1": DATA_KEY})

    assert result.returncode != 0
    assert "incompatible" in result.stderr
    assert target.read_bytes() == sentinel
    assert "migration-password-2-only" not in result.stdout + result.stderr



def _authenticated_backup_payload(database: Path, destination: Path) -> None:
    nonce = b"n" * 12
    destination.write_bytes(
        b"SMBK\x01"
        + nonce
        + AESGCM(base64.b64decode(BACKUP_KEY)).encrypt(
            nonce, database.read_bytes(), b"service-manager-backup:v1"
        )
    )


def _weaken_schema_sql(path: Path, object_type: str, name: str, before: str, after: str) -> None:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA writable_schema = ON")
    result = conn.execute(
        "UPDATE sqlite_master SET sql = replace(sql, ?, ?) WHERE type = ? AND name = ?",
        (before, after, object_type, name),
    )
    assert result.rowcount == 1
    conn.execute("PRAGMA writable_schema = OFF")
    conn.execute("PRAGMA schema_version = 9001")
    conn.commit()
    conn.close()


def test_restore_keeps_rollback_artifact_when_rollback_replacement_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    restore = _script_module("restore_backup")
    source = tmp_path / "source.db"
    secure = tmp_path / "secure.db"
    encrypted = tmp_path / "source.smbk"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run_legacy_migration(source, secure, key_env="TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    assert _run(BACKUP, "--source", str(secure), "--target", str(encrypted), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY, "AUDIT_KEY_V1": DATA_KEY}).returncode == 0
    sentinel = b"original-target-bytes"
    target.write_bytes(sentinel)
    monkeypatch.setenv("TEST_BACKUP_KEY", BACKUP_KEY)
    monkeypatch.setenv("AUDIT_KEY_V1", DATA_KEY)
    real_replace = restore.os.replace

    def fail_rollback_replacement(source_path: Path | str, destination_path: Path | str) -> None:
        if str(source_path).endswith(".rollback") and Path(destination_path) == target:
            raise OSError("synthetic rollback replacement failure")
        real_replace(source_path, destination_path)

    monkeypatch.setattr(restore.os, "replace", fail_rollback_replacement)
    with pytest.raises(restore.ScriptError, match="recovery") as failure:
        restore.restore(
            encrypted,
            target,
            "TEST_BACKUP_KEY",
            _after_post_placement_validation=lambda: (_ for _ in ()).throw(restore.ScriptError("synthetic failure")),
        )

    rollback_files = list(tmp_path.glob(".target.db.*.rollback"))
    assert len(rollback_files) == 1
    assert rollback_files[0].read_bytes() == sentinel
    assert not target.exists()
    assert "migration-password-2-only" not in str(failure.value)


@pytest.mark.parametrize("failure_kind", ("permissions", "sidecar"))
def test_migration_final_placement_failures_restore_existing_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_kind: str):
    migration = _script_module("migrate_legacy_db")
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    sentinel = b"original-target-bytes"
    target.write_bytes(sentinel)
    monkeypatch.setenv("TEST_DATA_KEY", DATA_KEY)

    if failure_kind == "permissions":
        original_ensure_mode = migration.ensure_mode

        def fail_post_placement_permissions(path: Path, mode: int = 0o600) -> None:
            if path == target:
                raise migration.ScriptError("required file permissions could not be enforced")
            original_ensure_mode(path, mode)
        monkeypatch.setattr(migration, "ensure_mode", fail_post_placement_permissions)

        with pytest.raises(migration.ScriptError):
            migration.migrate(source, target, "TEST_DATA_KEY")
    else:
        with pytest.raises(migration.ScriptError):
            migration.migrate(
                source,
                target,
                "TEST_DATA_KEY",
                _after_placement=lambda: Path(f"{target}-shm").write_bytes(b"synthetic-sidecar"),
            )

    assert target.read_bytes() == sentinel
    assert not any(tmp_path.glob(".target.db.*.rollback*"))
    assert not any(path.exists() for path in _sidecars(target))


def test_migration_final_placement_failure_removes_new_target_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    migration = _script_module("migrate_legacy_db")
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    monkeypatch.setenv("TEST_DATA_KEY", DATA_KEY)
    original_ensure_mode = migration.ensure_mode

    def fail_post_placement_permissions(path: Path, mode: int = 0o600) -> None:
        if path == target:
            raise migration.ScriptError("required file permissions could not be enforced")
        original_ensure_mode(path, mode)

    monkeypatch.setattr(migration, "ensure_mode", fail_post_placement_permissions)
    with pytest.raises(migration.ScriptError):
        migration.migrate(source, target, "TEST_DATA_KEY")

    assert not target.exists()
    assert not any(path.exists() for path in _sidecars(target))






@pytest.mark.parametrize(
    ("object_type", "name", "before", "after"),
    (
        ("table", "account_service", "CHECK (status IN ('ativo', 'nunca', 'inativo'))", "CHECK (status IN ('ativo', 'nunca'))"),
        ("table", "users", "CHECK (role IN ('admin', 'operador'))", "CHECK (role IN ('admin'))"),
        ("table", "account_service", "CHECK (registered IN (0, 1))", "CHECK (registered IN (0, 1, 2))"),
        ("table", "account_service", "ON DELETE CASCADE", "ON DELETE RESTRICT"),
        ("trigger", "audit_events_no_update", "audit_events is append-only", "audit event mutation accepted"),
    ),
    ids=("status-check", "role-check", "registered-check", "foreign-key", "trigger-body"),
)
def test_verifier_rejects_every_canonical_secure_schema_weakening(tmp_path: Path, object_type: str, name: str, before: str, after: str):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    _weaken_schema_sql(target, object_type, name, before, after)

    result = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert result.returncode != 0
    assert "migration-password-2-only" not in result.stdout + result.stderr


def test_restore_shared_validator_rejects_canonical_schema_weakening_without_replacing_target(tmp_path: Path):
    source = tmp_path / "source.db"
    migrated = tmp_path / "migrated.db"
    encrypted = tmp_path / "weakened.smbk"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(migrated), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    _weaken_schema_sql(migrated, "table", "account_service", "CHECK (status IN ('ativo', 'nunca', 'inativo'))", "CHECK (status IN ('ativo', 'nunca'))")
    _authenticated_backup_payload(migrated, encrypted)
    sentinel = b"original-target-bytes"
    target.write_bytes(sentinel)

    result = _run(RESTORE, "--source", str(encrypted), "--target", str(target), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY})

    assert result.returncode != 0
    assert target.read_bytes() == sentinel
    assert "migration-password-2-only" not in result.stdout + result.stderr


def test_verifier_converts_corrupt_target_relationship_lookup_to_generic_script_error(tmp_path: Path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    conn = sqlite3.connect(target)
    conn.execute("UPDATE field_values SET account_id = 9999 WHERE field_id = 29 AND account_id = 1001")
    conn.commit()
    conn.close()

    result = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert result.returncode != 0
    assert "Traceback" not in result.stdout + result.stderr
    assert "migration-password-2-only" not in result.stdout + result.stderr


def _build_pre_registered_source(path: Path) -> None:
    """Build a source under the registered tool's frozen pre-registered schema."""
    migration = _script_module("migrate_registered_column")
    registered_line = "    registered INTEGER NOT NULL DEFAULT 0 CHECK (registered IN (0, 1)),\n"
    assert registered_line in migration.TARGET_SCHEMA
    old_schema = migration.TARGET_SCHEMA.replace(registered_line, "")
    conn = sqlite3.connect(path)
    try:
        conn.executescript(old_schema)
        stamp = "2026-01-01T00:00:00Z"
        conn.execute("INSERT INTO services (id, name) VALUES (9, 'Synthetic service')")
        conn.execute("INSERT INTO accounts (id, email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, ?, ?)", (41, "service@example.test", b"password-ciphertext", b"p" * 12, 1))
        conn.execute("INSERT INTO custom_fields (id, service_id, name) VALUES (12, 9, 'Token')")
        conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (41, 9, 'ativo')")
        conn.execute("INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, ?)", (12, 41, b"field-ciphertext", b"f" * 12, 1))
        conn.execute("INSERT INTO users (id, username, password_hash, role, is_active, must_change_password, created_at, updated_at, session_version) VALUES (1, 'admin', 'hash', 'admin', 1, 0, ?, ?, 0)", (stamp, stamp))
        _append_synthetic_audit_events(conn, count=3)
        for table, seq in {"accounts": 41, "services": 9, "custom_fields": 12, "users": 1, "audit_events": 3}.items():
            conn.execute("UPDATE sqlite_sequence SET seq = ? WHERE name = ?", (seq, table))
        conn.commit()
    finally:
        conn.close()
    os.chmod(path, 0o600)


def test_registered_column_migration_preserves_every_value_and_rejects_migrated_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "pre-registered.db"
    _build_pre_registered_source(source)
    source_bytes = source.read_bytes()
    target = tmp_path / "with-registered.db"

    migration = _script_module("migrate_registered_column")
    monkeypatch.setenv("AUDIT_KEY_V1", DATA_KEY)
    migration.migrate(source, target, "AUDIT_KEY_V1")

    assert source.read_bytes() == source_bytes
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    src_conn = sqlite3.connect(source)
    dst_conn = sqlite3.connect(target)
    dst_conn.row_factory = sqlite3.Row
    try:
        for table in ("services", "accounts", "users", "custom_fields", "field_values", "security_events", "audit_events"):
            assert _table_rows(dst_conn, table) == _table_rows(src_conn, table)
        assert _table_rows(dst_conn, "account_service") == [(*row, 0) for row in _table_rows(src_conn, "account_service")]
        assert dict(dst_conn.execute("SELECT name, seq FROM sqlite_sequence")) == dict(src_conn.execute("SELECT name, seq FROM sqlite_sequence"))
        from _secure_db import load_key
        from service_manager.audit import verify_audit_chain_with_key
        assert verify_audit_chain_with_key(dst_conn, load_key("AUDIT_KEY_V1"))
        assert {row[1] for row in dst_conn.execute("PRAGMA table_info(account_service)")} == {"account_id", "service_id", "status", "registered"}
    finally:
        src_conn.close()
        dst_conn.close()

    with pytest.raises(migration.ScriptError):
        migration.migrate(target, tmp_path / "again.db", "AUDIT_KEY_V1")


def test_service_index_migration_adds_index_preserves_data_and_rejects_migrated_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    migration = _script_module("migrate_service_index")
    index_line = "CREATE INDEX account_service_service_id ON account_service(service_id);"
    assert index_line in migration.TARGET_SCHEMA
    source = tmp_path / "pre-index.db"
    conn = sqlite3.connect(source)
    try:
        conn.executescript(migration.TARGET_SCHEMA.replace(index_line, ""))
        conn.execute("INSERT INTO services (id, name) VALUES (9, 'Synthetic service')")
        conn.execute("INSERT INTO accounts (id, email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, ?, ?)", (41, "service@example.test", b"password-ciphertext", b"p" * 12, 1))
        conn.execute("INSERT INTO account_service (account_id, service_id, status, registered) VALUES (41, 9, 'ativo', 1)")
        conn.execute("INSERT INTO users (id, username, password_hash, role, is_active, must_change_password, created_at, updated_at, session_version) VALUES (1, 'admin', 'hash', 'admin', 1, 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0)")
        _append_synthetic_audit_events(conn, count=3)
        for table, seq in {"accounts": 41, "services": 9, "users": 1, "audit_events": 3}.items():
            conn.execute("UPDATE sqlite_sequence SET seq = ? WHERE name = ?", (seq, table))
        conn.commit()
    finally:
        conn.close()
    os.chmod(source, 0o600)
    source_bytes = source.read_bytes()
    target = tmp_path / "with-index.db"

    monkeypatch.setenv("AUDIT_KEY_V1", DATA_KEY)
    migration.migrate(source, target, "AUDIT_KEY_V1")

    assert source.read_bytes() == source_bytes
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    src_conn = sqlite3.connect(source)
    dst_conn = sqlite3.connect(target)
    dst_conn.row_factory = sqlite3.Row
    try:
        assert dst_conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='account_service_service_id'").fetchone()[0] == 1
        migration.structural_schema_valid(dst_conn, migration._TARGET_OBJECTS, migration._TARGET_COLUMNS)
        for table in ("services", "accounts", "account_service", "custom_fields", "field_values", "users", "security_events", "audit_events"):
            assert _table_rows(dst_conn, table) == _table_rows(src_conn, table)
        from _secure_db import load_key
        from service_manager.audit import verify_audit_chain_with_key
        assert verify_audit_chain_with_key(dst_conn, load_key("AUDIT_KEY_V1"))
    finally:
        src_conn.close()
        dst_conn.close()

    with pytest.raises(migration.ScriptError, match="source schema is incompatible"):
        migration.migrate(target, tmp_path / "again.db", "AUDIT_KEY_V1")


def _pre_cutover_source(path: Path, data_key: bytes) -> None:
    """Build a pre-cutover database: registered + is_secret + mixed field representations + triggers."""
    migration = _script_module("migrate_unclassified_fields")
    expected = migration._expected_old_objects()
    statements: list[str] = []
    for kind in ("table", "index", "trigger"):
        statements.extend(f"{sql};" for sql in expected[kind].values())
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript("\n".join(statements))
        stamp = "2026-01-01T00:00:00Z"
        conn.execute("INSERT INTO users (id, username, password_hash, role, is_active, must_change_password, created_at, updated_at, password_changed_at, session_version) VALUES (1, 'admin', 'hash', 'admin', 1, 0, ?, ?, ?, 0)", (stamp, stamp, stamp))
        conn.execute("INSERT INTO services (id, name) VALUES (5, 'Mail')")
        conn.execute("INSERT INTO accounts (id, email, password_ciphertext, password_nonce, password_key_version) VALUES (10, 'a@example.test', ?, ?, 1)", (b"pw-cipher", b"p" * 12))
        conn.execute("INSERT INTO account_service (account_id, service_id, status, registered) VALUES (10, 5, 'ativo', 1)")
        plain_field = conn.execute("INSERT INTO custom_fields (id, service_id, name, is_secret) VALUES (20, 5, 'Nickname', 0)").lastrowid
        secret_field = conn.execute("INSERT INTO custom_fields (id, service_id, name, is_secret) VALUES (21, 5, 'Token', 1)").lastrowid
        conn.execute("INSERT INTO field_values (field_id, account_id, value_plaintext) VALUES (?, 10, 'apelido')", (plain_field,))
        nonce = os.urandom(12)
        ciphertext = AESGCM(data_key).encrypt(nonce, b"token-secret", b"account:10:field:21")
        conn.execute("INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, 10, ?, ?, 1)", (secret_field, ciphertext, nonce))
        _append_synthetic_audit_events(conn, count=3)
        for table, seq in {"accounts": 10, "services": 5, "custom_fields": 21, "users": 1, "audit_events": 3}.items():
            conn.execute("UPDATE sqlite_sequence SET seq = ? WHERE name = ?", (seq, table))
        conn.commit()
    finally:
        conn.close()
    os.chmod(path, 0o600)


def test_unclassified_fields_migration_encrypts_all_fields_and_rejects_migrated_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data_key = base64.b64decode(DATA_KEY)
    source = tmp_path / "pre-cutover.db"
    target = tmp_path / "encrypted-only.db"
    _pre_cutover_source(source, data_key)
    source_bytes = source.read_bytes()

    migration = _script_module("migrate_unclassified_fields")
    monkeypatch.setenv("DATA_KEY_V1", DATA_KEY)
    monkeypatch.setenv("AUDIT_KEY_V1", DATA_KEY)
    migration.migrate(source, target, "DATA_KEY_V1", "AUDIT_KEY_V1")

    assert source.read_bytes() == source_bytes
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    try:
        from service_manager.audit import verify_audit_chain_with_key
        migration.structural_schema_valid(conn, migration._TARGET_OBJECTS, migration._TARGET_COLUMNS)
        assert "is_secret" not in {row[1] for row in conn.execute("PRAGMA table_info(custom_fields)")}
        assert {row[1] for row in conn.execute("PRAGMA table_info(field_values)")} == {"field_id", "account_id", "value_ciphertext", "value_nonce", "value_key_version"}
        values = {}
        for row in conn.execute("SELECT field_id, account_id, value_ciphertext, value_nonce, value_key_version FROM field_values ORDER BY field_id"):
            assert row["value_key_version"] == 1 and len(bytes(row["value_nonce"])) == 12
            values[row["field_id"]] = AESGCM(data_key).decrypt(bytes(row["value_nonce"]), bytes(row["value_ciphertext"]), f"account:{row['account_id']}:field:{row['field_id']}".encode()).decode()
        assert values == {20: "apelido", 21: "token-secret"}
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert list(conn.execute("PRAGMA foreign_key_check")) == []
        assert verify_audit_chain_with_key(conn, data_key)
        assert dict(conn.execute("SELECT name, seq FROM sqlite_sequence")) == {"accounts": 10, "services": 5, "custom_fields": 21, "users": 1, "audit_events": 3}
        residue = _artifact_bytes(target)
        assert b"apelido" not in residue
    finally:
        conn.close()

    with pytest.raises(migration.ScriptError, match="source schema is incompatible"):
        migration.migrate(target, tmp_path / "again.db", "DATA_KEY_V1", "AUDIT_KEY_V1")


def test_unclassified_fields_migration_aborts_on_field_tampering_without_replacing_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data_key = base64.b64decode(DATA_KEY)
    source = tmp_path / "pre-cutover.db"
    _pre_cutover_source(source, data_key)
    tamper = sqlite3.connect(source)
    tamper.execute("UPDATE field_values SET value_nonce = ? WHERE field_id = 21", (b"z" * 12,))
    tamper.commit()
    tamper.close()
    target = tmp_path / "encrypted-only.db"
    sentinel = b"preexisting-target-bytes"
    target.write_bytes(sentinel)

    migration = _script_module("migrate_unclassified_fields")
    monkeypatch.setenv("DATA_KEY_V1", DATA_KEY)
    monkeypatch.setenv("AUDIT_KEY_V1", DATA_KEY)
    with pytest.raises(migration.ScriptError):
        migration.migrate(source, target, "DATA_KEY_V1", "AUDIT_KEY_V1")

    assert target.read_bytes() == sentinel
    assert not any(tmp_path.glob(".encrypted-only.db.*.tmp*"))
