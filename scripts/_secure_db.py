from __future__ import annotations

import base64
import binascii
import os
import sqlite3
import stat
from pathlib import Path

EXPECTED_COUNTS = {"accounts": 116, "account_service": 116, "field_values": 116, "credentials_backup": 116}
EXPECTED_SECURE_TABLES = {
    "accounts", "services", "account_service", "custom_fields", "field_values", "users",
    "security_events", "audit_events", "service_members",
    "webhook_configs", "webhook_subscriptions", "webhook_deliveries", "app_settings",
}
EXPECTED_SECURE_COLUMNS = {
    "accounts": {"id", "email", "password_ciphertext", "password_nonce", "password_key_version", "password_changed_at"},
    "services": {"id", "name", "rotation_days"},
    "account_service": {"account_id", "service_id", "status", "registered", "rotation_days", "rotation_due_at"},
    "custom_fields": {"id", "service_id", "name"},
    "field_values": {"field_id", "account_id", "value_ciphertext", "value_nonce", "value_key_version"},
    "users": {"id", "username", "password_hash", "role", "is_active", "must_change_password", "created_at", "updated_at", "password_changed_at", "session_version"},
    "security_events": {"id", "kind", "subject", "source_ip", "occurred_at"},
    "audit_events": {"id", "occurred_at", "actor_user_id", "action", "target_type", "target_id", "metadata_json", "source_ip", "user_agent", "previous_hash", "event_hash"},
    "service_members": {"user_id", "service_id", "role", "created_at"},
    "webhook_configs": {"id", "destination_host", "url_ciphertext", "url_nonce", "url_key_version", "description", "enabled", "signing_secret_ciphertext", "signing_secret_nonce", "signing_secret_key_version", "created_at", "updated_at", "deleted_at"},
    "webhook_subscriptions": {"config_id", "event_type"},
    "webhook_deliveries": {"id", "config_id", "event_type", "payload_json", "status", "attempt_count", "next_attempt_at", "lease_token", "leased_at", "last_status_code", "last_error", "created_at", "delivered_at"},
    "app_settings": {"key", "value"},
}
REQUIRED_TRIGGERS = {
    "audit_events_no_update", "audit_events_no_delete",
}


class ScriptError(RuntimeError):
    """An intentionally non-sensitive command failure."""


def fail(message: str) -> None:
    raise ScriptError(message)


def load_key(env_name: str) -> bytes:
    value = os.environ.get(env_name)
    if not value:
        fail("configured encryption key is unavailable")
    assert value is not None
    try:
        key = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ScriptError("configured encryption key is invalid") from error
    if len(key) != 32:
        fail("configured encryption key is invalid")
    return key


def open_source_read_only(path: Path) -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as error:
        raise ScriptError("source database cannot be opened read-only") from error


def begin_snapshot(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("BEGIN")
    except sqlite3.Error as error:
        raise ScriptError("source snapshot cannot be opened") from error


def columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def validate_legacy_source(conn: sqlite3.Connection) -> None:
    required = {
        "accounts": {"id", "email", "password"}, "services": {"id", "name"},
        "account_service": {"account_id", "service_id", "status"},
        "custom_fields": {"id", "service_id", "name"}, "field_values": {"field_id", "account_id", "value"},
        "credentials_backup": {"id"},
    }
    try:
        for table, required_columns in required.items():
            if not required_columns <= columns(conn, table):
                fail("source schema is incompatible")
        for table, count in EXPECTED_COUNTS.items():
            if conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] != count:
                fail("source counts do not match the controlled migration")
    except sqlite3.Error as error:
        raise ScriptError("source schema is incompatible") from error


def read_legacy_values(conn: sqlite3.Connection) -> tuple[list[sqlite3.Row], ...]:
    try:
        return (
            list(conn.execute("SELECT id, name FROM services ORDER BY id")),
            list(conn.execute("SELECT id, service_id, name FROM custom_fields ORDER BY id")),
            list(conn.execute("SELECT id, email, password FROM accounts ORDER BY id")),
            list(conn.execute("SELECT account_id, service_id, status FROM account_service ORDER BY account_id, service_id")),
            list(conn.execute("SELECT field_id, account_id, value FROM field_values ORDER BY field_id, account_id")),
        )
    except sqlite3.Error as error:
        raise ScriptError("source schema is incompatible") from error


def ensure_mode(path: Path, mode: int = 0o600) -> None:
    try:
        os.chmod(path, mode)
        if stat.S_IMODE(path.stat().st_mode) != mode:
            fail("required file permissions could not be enforced")
    except OSError as error:
        raise ScriptError("required file permissions could not be enforced") from error


def sidecars(path: Path) -> tuple[Path, Path]:
    return Path(f"{path}-wal"), Path(f"{path}-shm")


def require_offline_target(path: Path) -> None:
    if any(artifact.exists() for artifact in sidecars(path)):
        fail("target database has active sidecars")


def remove_sidecars(path: Path) -> None:
    failures = False
    for artifact in sidecars(path):
        try:
            if artifact.exists():
                artifact.unlink()
        except OSError:
            failures = True
    if failures or any(artifact.exists() for artifact in sidecars(path)):
        fail("temporary artifact cleanup failed")

def remove_artifacts(*paths: Path | None) -> None:
    failures = False
    for path in paths:
        if path is None:
            continue
        for artifact in (path, *sidecars(path)):
            try:
                if artifact.exists():
                    artifact.unlink()
            except OSError:
                failures = True
    if failures or any(artifact.exists() for path in paths if path is not None for artifact in (path, *sidecars(path))):
        fail("temporary artifact cleanup failed")


def _schema_sql(conn: sqlite3.Connection, type_: str) -> dict[str, str]:
    return {
        row[0]: row[1] or ""
        for row in conn.execute("SELECT name, sql FROM sqlite_master WHERE type = ?", (type_,))
        if not row[0].startswith("sqlite_")
    }



def _normalize_schema_sql(sql: str) -> str:
    return " ".join(sql.split())


def _canonical_secure_schema() -> dict[str, dict[str, str]]:
    from service_manager.db import SCHEMA

    reference = sqlite3.connect(":memory:")
    try:
        reference.executescript(SCHEMA)
        return {
            kind: {
                name: _normalize_schema_sql(sql)
                for name, sql in _schema_sql(reference, kind).items()
            }
            for kind in ("table", "index", "trigger")
        }
    finally:
        reference.close()


CANONICAL_SECURE_SCHEMA = _canonical_secure_schema()
def secure_schema_structure_valid(conn: sqlite3.Connection) -> None:
    """Validate only the secure schema shape, independent of runtime row counts."""
    try:
        for kind, expected in CANONICAL_SECURE_SCHEMA.items():
            actual = {
                name: _normalize_schema_sql(sql)
                for name, sql in _schema_sql(conn, kind).items()
            }
            if actual != expected:
                fail("target schema is incompatible")
        for table, expected in EXPECTED_SECURE_COLUMNS.items():
            if columns(conn, table) != expected:
                fail("target schema is incompatible")
    except sqlite3.Error as error:
        raise ScriptError("target schema is incompatible") from error


def secure_schema_valid(conn: sqlite3.Connection) -> None:
    """Validate the schema plus the one-time controlled-migration invariants (exact counts)."""
    secure_schema_structure_valid(conn)
    try:
        if any(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] != count for table, count in EXPECTED_COUNTS.items() if table != "credentials_backup"):
            fail("target counts do not match the controlled migration")
    except sqlite3.Error as error:
        raise ScriptError("target schema is incompatible") from error


def validate_restorable_database(conn: sqlite3.Connection, *, secure_only: bool = False) -> None:
    """Backup/restore gate. Backups may snapshot a legacy or secure database; restores accept only the canonical secure schema."""
    try:
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            fail("restored database integrity check failed")
        if list(conn.execute("PRAGMA foreign_key_check")):
            fail("restored database has foreign-key violations")
        tables = set(_schema_sql(conn, "table"))
        if tables == EXPECTED_SECURE_TABLES:
            secure_schema_structure_valid(conn)
        elif not secure_only and tables == {"accounts", "services", "account_service", "custom_fields", "field_values", "credentials_backup"}:
            validate_legacy_source(conn)
        else:
            fail("restored database schema is incompatible")
    except sqlite3.Error as error:
        raise ScriptError("restored database validation failed") from error
