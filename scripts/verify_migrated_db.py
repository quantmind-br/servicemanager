from __future__ import annotations

import argparse
import base64
import binascii
import os
import sqlite3
import stat
import sys
from pathlib import Path
from collections.abc import Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from _pre_feature_schema import PRE_FEATURE_SCHEMA
from service_manager.audit import verify_audit_chain_with_key
from service_manager.db import SCHEMA

EXPECTED_COUNTS = {"accounts": 116, "account_service": 116, "field_values": 116, "credentials_backup": 116}
EXPECTED_TABLES = {
    "accounts", "services", "account_service", "custom_fields", "field_values", "users",
    "security_events", "audit_events", "service_members",
    "webhook_configs", "webhook_subscriptions", "webhook_deliveries", "app_settings",
}
EXPECTED_COLUMNS = {
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
REQUIRED_TRIGGERS = {"audit_events_no_update", "audit_events_no_delete"}

# The frozen pre-feature source columns preserved by the cutover.
_PRE_FEATURE_USER_COLUMNS = (
    "id", "username", "password_hash", "role", "is_active", "must_change_password",
    "created_at", "updated_at", "password_changed_at", "session_version",
)
_SEQUENCE_TABLES = ("accounts", "services", "custom_fields", "users", "security_events", "audit_events")


class ScriptError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Independent migrated database verifier")
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--data-key-env")
    parser.add_argument("--audit-key-env")
    # Legacy single-key alias retained for the frozen legacy migration verifier path.
    parser.add_argument("--key-env")
    return parser.parse_args()


def _key(name: str) -> bytes:
    try:
        value = base64.b64decode(os.environ[name], validate=True)
    except (KeyError, ValueError, binascii.Error) as error:
        raise ScriptError("configured encryption key is invalid") from error
    if len(value) != 32:
        raise ScriptError("configured encryption key is invalid")
    return value


def _ro(path: Path) -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN")
        return conn
    except sqlite3.Error as error:
        raise ScriptError("database cannot be opened read-only") from error


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _objects(conn: sqlite3.Connection, kind: str) -> dict[str, str]:
    return {
        row[0]: row[1] or ""
        for row in conn.execute("SELECT name, sql FROM sqlite_master WHERE type = ?", (kind,))
        if not row[0].startswith("sqlite_")
    }


def _normalize_schema_sql(sql: str) -> str:
    return " ".join(sql.split())


def _schema_from(schema_sql: str) -> dict[str, dict[str, str]]:
    reference = sqlite3.connect(":memory:")
    try:
        reference.executescript(schema_sql)
        return {
            kind: {
                name: _normalize_schema_sql(sql)
                for name, sql in _objects(reference, kind).items()
            }
            for kind in ("table", "index", "trigger")
        }
    finally:
        reference.close()


CANONICAL_SECURE_SCHEMA = _schema_from(SCHEMA)
# Source validation compares against the frozen pre-feature schema, never the live SCHEMA.
PRE_FEATURE_SECURE_SCHEMA = _schema_from(PRE_FEATURE_SCHEMA)


def _table_names(conn: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
    }


def _validate_new_canonical_target(conn: sqlite3.Connection) -> None:
    for kind, expected in CANONICAL_SECURE_SCHEMA.items():
        actual = {
            name: _normalize_schema_sql(sql)
            for name, sql in _objects(conn, kind).items()
        }
        if actual != expected:
            raise ScriptError("target schema is incompatible")
    for table, expected in EXPECTED_COLUMNS.items():
        if _columns(conn, table) != expected:
            raise ScriptError("target schema is incompatible")
    if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise ScriptError("target integrity is invalid")
    if list(conn.execute("PRAGMA foreign_key_check")):
        raise ScriptError("target foreign-key validation failed")


# --------------------------------------------------------------------------- #
# Legacy plaintext -> secure verification (frozen historical migrate_legacy_db)
# --------------------------------------------------------------------------- #


def _legacy(conn: sqlite3.Connection) -> tuple[list[sqlite3.Row], ...]:
    required = {"accounts": {"id", "email", "password"}, "services": {"id", "name"}, "account_service": {"account_id", "service_id", "status"}, "custom_fields": {"id", "service_id", "name"}, "field_values": {"field_id", "account_id", "value"}, "credentials_backup": {"id"}}
    try:
        for table, expected in required.items():
            if not expected <= _columns(conn, table):
                raise ScriptError("source schema or counts are incompatible")
            if table in EXPECTED_COUNTS and conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] != EXPECTED_COUNTS[table]:
                raise ScriptError("source schema or counts are incompatible")
        return tuple(list(conn.execute(query)) for query in (
            "SELECT id, name FROM services ORDER BY id", "SELECT id, service_id, name FROM custom_fields ORDER BY id", "SELECT id, email, password FROM accounts ORDER BY id", "SELECT account_id, service_id, status FROM account_service ORDER BY account_id, service_id", "SELECT field_id, account_id, value FROM field_values ORDER BY field_id, account_id",
        ))
    except sqlite3.Error as error:
        raise ScriptError("source schema or counts are incompatible") from error


def _secure(conn: sqlite3.Connection) -> None:
    try:
        _validate_new_canonical_target(conn)
        if any(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] != count for table, count in EXPECTED_COUNTS.items() if table != "credentials_backup"):
            raise ScriptError("target counts are incompatible")
    except sqlite3.Error as error:
        raise ScriptError("target schema is incompatible") from error


def _compare(conn: sqlite3.Connection, source: tuple[list[sqlite3.Row], ...], key: bytes) -> None:
    services, fields, accounts, links, values = source
    exact = (
        ("SELECT id, name FROM services ORDER BY id", [tuple(row) for row in services]),
        ("SELECT id, service_id, name FROM custom_fields ORDER BY id", [tuple(row) for row in fields]),
        ("SELECT id, email FROM accounts ORDER BY id", [(row["id"], row["email"]) for row in accounts]),
        ("SELECT account_id, service_id, status FROM account_service ORDER BY account_id, service_id", [tuple(row) for row in links]),
    )
    for query, expected in exact:
        if [tuple(row) for row in conn.execute(query)] != expected:
            raise ScriptError("target relationships do not match source")
    passwords = {row["id"]: row["password"] for row in accounts}
    field_values = {(row["field_id"], row["account_id"]): row["value"] for row in values}
    nonces: set[bytes] = set()
    try:
        for row in conn.execute("SELECT id, password_ciphertext, password_nonce, password_key_version FROM accounts ORDER BY id"):
            nonce = bytes(row["password_nonce"])
            if len(nonce) != 12 or row["password_key_version"] != 1 or nonce in nonces or AESGCM(key).decrypt(nonce, bytes(row["password_ciphertext"]), f"account:{row['id']}:password".encode()).decode() != passwords[row["id"]]:
                raise ScriptError("target encryption is invalid")
            nonces.add(nonce)
        for row in conn.execute("SELECT field_id, account_id, value_ciphertext, value_nonce, value_key_version FROM field_values ORDER BY field_id, account_id"):
            nonce = bytes(row["value_nonce"])
            expected = field_values[(row["field_id"], row["account_id"])]
            if len(nonce) != 12 or row["value_key_version"] != 1 or nonce in nonces or AESGCM(key).decrypt(nonce, bytes(row["value_ciphertext"]), f"account:{row['account_id']}:field:{row['field_id']}".encode()).decode() != expected:
                raise ScriptError("target encryption is invalid")
            nonces.add(nonce)
    except (sqlite3.Error, InvalidTag, UnicodeDecodeError, ValueError, TypeError, KeyError) as error:
        raise ScriptError("target encryption is invalid") from error
    if len(nonces) != 232:
        raise ScriptError("target encryption is invalid")


def _scan(target: Path, source: tuple[list[sqlite3.Row], ...]) -> None:
    payload = b"".join(path.read_bytes() for path in (target, Path(f"{target}-wal"), Path(f"{target}-shm")) if path.exists())
    for row in (*source[2], *source[4]):
        secret = row["password"] if "password" in row.keys() else row["value"]
        if secret and secret.encode() in payload:
            raise ScriptError("target contains plaintext residue")


# --------------------------------------------------------------------------- #
# Pre-feature secure -> new-canonical verification (migrate_auth_schema cutover)
# --------------------------------------------------------------------------- #


def _validate_pre_feature_source(conn: sqlite3.Connection, audit_key: bytes) -> None:
    try:
        for kind, expected in PRE_FEATURE_SECURE_SCHEMA.items():
            actual = {
                name: _normalize_schema_sql(sql)
                for name, sql in _objects(conn, kind).items()
            }
            if actual != expected:
                raise ScriptError("source schema is incompatible")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ScriptError("source integrity validation failed")
        if list(conn.execute("PRAGMA foreign_key_check")):
            raise ScriptError("source foreign-key validation failed")
        if not verify_audit_chain_with_key(conn, audit_key):
            raise ScriptError("source audit chain validation failed")
    except sqlite3.Error as error:
        raise ScriptError("source schema is incompatible") from error


def _pre_feature_snapshot(conn: sqlite3.Connection) -> dict[str, list[tuple[object, ...]]]:
    snapshot: dict[str, list[tuple[object, ...]]] = {}
    snapshot["services"] = [tuple(row) for row in conn.execute("SELECT id, name FROM services ORDER BY id")]
    snapshot["accounts"] = [tuple(row) for row in conn.execute("SELECT id, email, password_ciphertext, password_nonce, password_key_version FROM accounts ORDER BY id")]
    snapshot["custom_fields"] = [tuple(row) for row in conn.execute("SELECT id, service_id, name FROM custom_fields ORDER BY id")]
    snapshot["account_service"] = [tuple(row) for row in conn.execute("SELECT account_id, service_id, status, registered FROM account_service ORDER BY account_id, service_id")]
    snapshot["field_values"] = [tuple(row) for row in conn.execute("SELECT field_id, account_id, value_ciphertext, value_nonce, value_key_version FROM field_values ORDER BY field_id, account_id")]
    snapshot["users"] = [tuple(row) for row in conn.execute(f"SELECT {', '.join(_PRE_FEATURE_USER_COLUMNS)} FROM users ORDER BY id")]
    snapshot["security_events"] = [tuple(row) for row in conn.execute("SELECT id, kind, subject, source_ip, occurred_at FROM security_events ORDER BY id")]
    snapshot["audit_events"] = [tuple(row) for row in conn.execute("SELECT id, occurred_at, actor_user_id, action, target_type, target_id, metadata_json, source_ip, user_agent, previous_hash, event_hash FROM audit_events ORDER BY id")]
    snapshot["_sequences"] = [tuple(row) for row in conn.execute("SELECT name, seq FROM sqlite_sequence WHERE name IN (?, ?, ?, ?, ?, ?) ORDER BY name", _SEQUENCE_TABLES)]
    return snapshot


def _compare_pre_feature(conn: sqlite3.Connection, snapshot: dict[str, list[tuple[object, ...]]], data_key: bytes, audit_key: bytes) -> None:
    try:
        preserved = {
            "services": "SELECT id, name FROM services ORDER BY id",
            "accounts": "SELECT id, email, password_ciphertext, password_nonce, password_key_version FROM accounts ORDER BY id",
            "custom_fields": "SELECT id, service_id, name FROM custom_fields ORDER BY id",
            "account_service": "SELECT account_id, service_id, status, registered FROM account_service ORDER BY account_id, service_id",
            "field_values": "SELECT field_id, account_id, value_ciphertext, value_nonce, value_key_version FROM field_values ORDER BY field_id, account_id",
            "users": f"SELECT {', '.join(_PRE_FEATURE_USER_COLUMNS)} FROM users ORDER BY id",
            "security_events": "SELECT id, kind, subject, source_ip, occurred_at FROM security_events ORDER BY id",
            "audit_events": "SELECT id, occurred_at, actor_user_id, action, target_type, target_id, metadata_json, source_ip, user_agent, previous_hash, event_hash FROM audit_events ORDER BY id",
        }
        for table, query in preserved.items():
            if [tuple(row) for row in conn.execute(query)] != snapshot[table]:
                raise ScriptError("target relationships do not match source")
        sequences = [tuple(row) for row in conn.execute("SELECT name, seq FROM sqlite_sequence WHERE name IN (?, ?, ?, ?, ?, ?) ORDER BY name", _SEQUENCE_TABLES)]
        if sequences != snapshot["_sequences"]:
            raise ScriptError("target sequence validation failed")
        # New rotation metadata must default to NULL.
        if conn.execute("SELECT COUNT(*) FROM accounts WHERE password_changed_at IS NOT NULL").fetchone()[0]:
            raise ScriptError("target rotation defaults are invalid")
        if conn.execute("SELECT COUNT(*) FROM services WHERE rotation_days IS NOT NULL").fetchone()[0]:
            raise ScriptError("target rotation defaults are invalid")
        if conn.execute("SELECT COUNT(*) FROM account_service WHERE rotation_days IS NOT NULL OR rotation_due_at IS NOT NULL").fetchone()[0]:
            raise ScriptError("target rotation defaults are invalid")
        # New webhook tables must be empty.
        for table in ("webhook_configs", "webhook_subscriptions", "webhook_deliveries"):
            if conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]:
                raise ScriptError("target webhook tables are not empty")
        # Membership backfill == active non-admin users * services, all service_admin.
        active_non_admin = conn.execute("SELECT COUNT(*) FROM users WHERE is_active = 1 AND role != 'admin'").fetchone()[0]
        services = conn.execute("SELECT COUNT(*) FROM services").fetchone()[0]
        members = conn.execute("SELECT COUNT(*) FROM service_members").fetchone()[0]
        if members != active_non_admin * services:
            raise ScriptError("target membership backfill is invalid")
        if conn.execute("SELECT COUNT(*) FROM service_members WHERE role != 'service_admin'").fetchone()[0]:
            raise ScriptError("target membership backfill is invalid")
        # AES envelopes must decrypt with the data key.
        for row in conn.execute("SELECT id, password_ciphertext, password_nonce, password_key_version FROM accounts ORDER BY id"):
            nonce = bytes(row["password_nonce"])
            if len(nonce) != 12 or row["password_key_version"] != 1:
                raise ScriptError("target encryption is invalid")
            AESGCM(data_key).decrypt(nonce, bytes(row["password_ciphertext"]), f"account:{row['id']}:password".encode())
        for row in conn.execute("SELECT field_id, account_id, value_ciphertext, value_nonce, value_key_version FROM field_values ORDER BY field_id, account_id"):
            nonce = bytes(row["value_nonce"])
            if len(nonce) != 12 or row["value_key_version"] != 1:
                raise ScriptError("target encryption is invalid")
            AESGCM(data_key).decrypt(nonce, bytes(row["value_ciphertext"]), f"account:{row['account_id']}:field:{row['field_id']}".encode())
        if not verify_audit_chain_with_key(conn, audit_key):
            raise ScriptError("target audit chain validation failed")
    except (sqlite3.Error, InvalidTag, ValueError, TypeError, KeyError) as error:
        raise ScriptError("target verification failed") from error


def _scan_pre_feature(target: Path, conn: sqlite3.Connection, data_key: bytes) -> None:
    payload = b"".join(path.read_bytes() for path in (target, Path(f"{target}-wal"), Path(f"{target}-shm")) if path.exists())
    for row in conn.execute("SELECT id, password_ciphertext, password_nonce FROM accounts ORDER BY id"):
        plaintext = AESGCM(data_key).decrypt(bytes(row["password_nonce"]), bytes(row["password_ciphertext"]), f"account:{row['id']}:password".encode())
        if plaintext and plaintext in payload:
            raise ScriptError("target contains plaintext residue")
    for row in conn.execute("SELECT field_id, account_id, value_ciphertext, value_nonce FROM field_values ORDER BY field_id, account_id"):
        plaintext = AESGCM(data_key).decrypt(bytes(row["value_nonce"]), bytes(row["value_ciphertext"]), f"account:{row['account_id']}:field:{row['field_id']}".encode())
        if plaintext and plaintext in payload:
            raise ScriptError("target contains plaintext residue")


def verify(
    source_path: Path,
    target_path: Path,
    data_key_env: str,
    audit_key_env: str | None = None,
    _after_snapshot_ready: Callable[[], None] | None = None,
) -> None:
    if not target_path.is_file() or stat.S_IMODE(target_path.stat().st_mode) != 0o600:
        raise ScriptError("target database permissions are invalid")
    data_key = _key(data_key_env)
    audit_key = _key(audit_key_env) if audit_key_env else data_key
    source = _ro(source_path)
    target = _ro(target_path)
    try:
        legacy = "credentials_backup" in _table_names(source)
        if legacy:
            source_data = _legacy(source)
            if _after_snapshot_ready is not None:
                _after_snapshot_ready()
            _secure(target)
            _compare(target, source_data, data_key)
            _scan(target_path, source_data)
        else:
            _validate_pre_feature_source(source, audit_key)
            snapshot = _pre_feature_snapshot(source)
            if _after_snapshot_ready is not None:
                _after_snapshot_ready()
            _validate_new_canonical_target(target)
            _compare_pre_feature(target, snapshot, data_key, audit_key)
            _scan_pre_feature(target_path, target, data_key)
    finally:
        target.close()
        source.close()


def main() -> int:
    args = parse_args()
    data_key_env = args.data_key_env or args.key_env
    audit_key_env = args.audit_key_env or args.key_env
    if data_key_env is None:
        print("ERROR: a data key environment variable is required", file=sys.stderr)
        return 1
    try:
        verify(Path(args.source), Path(args.target), data_key_env, audit_key_env)
    except ScriptError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("OK: verification succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
