from __future__ import annotations

import argparse
import sqlite3
import sys
import tempfile
import os
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _secure_db import (
    ScriptError,
    ensure_mode,
    load_key,
    remove_artifacts,
    require_offline_target,
    sidecars,
)
from _migration_io import (
    _copy_rows,
    _create_schema,
    _place,
    _snapshot,
    frozen_schema_objects,
    normalized_objects,
)
from _pre_feature_schema import PRE_FEATURE_SCHEMA
from service_manager.audit import verify_audit_chain_with_key
from service_manager.db import SCHEMA, schema_is_current

# The frozen source contract: the canonical schema exactly as it existed before
# the feature-pack cutover. Source validation compares against this constant and
# never against the live (post-cutover) service_manager.db.SCHEMA.
_PRE_FEATURE_OBJECTS, _PRE_FEATURE_COLUMNS = frozen_schema_objects(PRE_FEATURE_SCHEMA)

# Tables carried across verbatim, with the columns preserved for each.
_COPY_COLUMNS = {
    "services": ("id", "name"),
    "accounts": ("id", "email", "password_ciphertext", "password_nonce", "password_key_version"),
    "custom_fields": ("id", "service_id", "name"),
    "users": (
        "id", "username", "password_hash", "role", "is_active", "must_change_password",
        "created_at", "updated_at", "password_changed_at", "session_version",
    ),
    "security_events": ("id", "kind", "subject", "source_ip", "occurred_at"),
    "audit_events": (
        "id", "occurred_at", "actor_user_id", "action", "target_type", "target_id",
        "metadata_json", "source_ip", "user_agent", "previous_hash", "event_hash",
    ),
}
# account_service and field_values are keyed on composite primary keys, so they
# are copied with explicit ordering rather than the id-ordered _copy_rows helper.
_ACCOUNT_SERVICE_COLUMNS = ("account_id", "service_id", "status", "registered")
_FIELD_VALUE_COLUMNS = ("field_id", "account_id", "value_ciphertext", "value_nonce", "value_key_version")
# Only the pre-existing AUTOINCREMENT tables have source sequences worth preserving.
_SEQUENCE_TABLES = ("accounts", "services", "custom_fields", "users", "security_events", "audit_events")


def _validate_old_source(conn: sqlite3.Connection, audit_key: bytes) -> None:
    try:
        if any(normalized_objects(conn, kind) != expected for kind, expected in _PRE_FEATURE_OBJECTS.items()):
            raise ScriptError("source schema is incompatible")
        if any(
            {row[1] for row in conn.execute(f"PRAGMA table_info({table})")} != expected
            for table, expected in _PRE_FEATURE_COLUMNS.items()
        ):
            raise ScriptError("source schema is incompatible")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ScriptError("source integrity validation failed")
        if list(conn.execute("PRAGMA foreign_key_check")):
            raise ScriptError("source foreign-key validation failed")
        if not verify_audit_chain_with_key(conn, audit_key):
            raise ScriptError("source audit chain validation failed")
    except sqlite3.Error as error:
        raise ScriptError("source schema is incompatible") from error


def _copy(source: sqlite3.Connection, destination: sqlite3.Connection) -> tuple[dict[str, list[tuple[object, ...]]], dict[str, int], int]:
    copied: dict[str, list[tuple[object, ...]]] = {}
    for table in ("services", "accounts", "custom_fields", "users", "security_events", "audit_events"):
        copied[table] = _copy_rows(source, destination, table, _COPY_COLUMNS[table])
    copied["account_service"] = [
        tuple(row)
        for row in source.execute(
            f"SELECT {', '.join(_ACCOUNT_SERVICE_COLUMNS)} FROM account_service ORDER BY account_id, service_id"
        )
    ]
    destination.executemany(
        f"INSERT INTO account_service ({', '.join(_ACCOUNT_SERVICE_COLUMNS)}) VALUES (?, ?, ?, ?)",
        copied["account_service"],
    )
    copied["field_values"] = [
        tuple(row)
        for row in source.execute(
            f"SELECT {', '.join(_FIELD_VALUE_COLUMNS)} FROM field_values ORDER BY field_id, account_id"
        )
    ]
    destination.executemany(
        f"INSERT INTO field_values ({', '.join(_FIELD_VALUE_COLUMNS)}) VALUES (?, ?, ?, ?, ?)",
        copied["field_values"],
    )
    sequences = {
        row["name"]: row["seq"]
        for row in source.execute("SELECT name, seq FROM sqlite_sequence WHERE name IN (?, ?, ?, ?, ?, ?)", _SEQUENCE_TABLES)
    }
    for table, sequence in sequences.items():
        destination.execute("DELETE FROM sqlite_sequence WHERE name = ?", (table,))
        destination.execute("INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)", (table, sequence))
    membership_count = _backfill_memberships(source, destination)
    return copied, sequences, membership_count


def _backfill_memberships(source: sqlite3.Connection, destination: sqlite3.Connection) -> int:
    """Grant every active non-admin user service_admin on every service so that
    current all-access behaviour is preserved at cutover. Global admins bypass
    membership and receive no rows."""
    now = datetime.now(UTC).isoformat()
    service_ids = [row["id"] for row in source.execute("SELECT id FROM services ORDER BY id")]
    user_ids = [
        row["id"]
        for row in source.execute(
            "SELECT id FROM users WHERE is_active = 1 AND role != 'admin' ORDER BY id"
        )
    ]
    rows = [(user_id, service_id, "service_admin", now) for user_id in user_ids for service_id in service_ids]
    destination.executemany(
        "INSERT INTO service_members (user_id, service_id, role, created_at) VALUES (?, ?, ?, ?)",
        rows,
    )
    return len(rows)


def _validate_destination(
    conn: sqlite3.Connection,
    copied: dict[str, list[tuple[object, ...]]],
    sequences: dict[str, int],
    membership_count: int,
    audit_key: bytes,
) -> None:
    if not schema_is_current(conn):
        raise ScriptError("target schema is incompatible")
    try:
        if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise ScriptError("target foreign-key enforcement is disabled")
        for table, columns in _COPY_COLUMNS.items():
            actual = [tuple(row) for row in conn.execute(f"SELECT {', '.join(columns)} FROM {table} ORDER BY id")]
            if actual != copied[table]:
                raise ScriptError("target equivalence validation failed")
        links = [
            tuple(row)
            for row in conn.execute(
                f"SELECT {', '.join(_ACCOUNT_SERVICE_COLUMNS)} FROM account_service ORDER BY account_id, service_id"
            )
        ]
        if links != copied["account_service"]:
            raise ScriptError("target equivalence validation failed")
        values = [
            tuple(row)
            for row in conn.execute(
                f"SELECT {', '.join(_FIELD_VALUE_COLUMNS)} FROM field_values ORDER BY field_id, account_id"
            )
        ]
        if values != copied["field_values"]:
            raise ScriptError("target equivalence validation failed")
        # New rotation metadata must be initialized to NULL for every carried row.
        if conn.execute("SELECT COUNT(*) FROM accounts WHERE password_changed_at IS NOT NULL").fetchone()[0]:
            raise ScriptError("target rotation initialization failed")
        if conn.execute("SELECT COUNT(*) FROM services WHERE rotation_days IS NOT NULL").fetchone()[0]:
            raise ScriptError("target rotation initialization failed")
        if conn.execute("SELECT COUNT(*) FROM account_service WHERE rotation_days IS NOT NULL OR rotation_due_at IS NOT NULL").fetchone()[0]:
            raise ScriptError("target rotation initialization failed")
        # New webhook tables must start empty.
        for table in ("webhook_configs", "webhook_subscriptions", "webhook_deliveries"):
            if conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]:
                raise ScriptError("target webhook initialization failed")
        # Membership backfill == active non-admin users * services.
        active_non_admin = conn.execute("SELECT COUNT(*) FROM users WHERE is_active = 1 AND role != 'admin'").fetchone()[0]
        services = conn.execute("SELECT COUNT(*) FROM services").fetchone()[0]
        actual_members = conn.execute("SELECT COUNT(*) FROM service_members").fetchone()[0]
        if actual_members != membership_count or actual_members != active_non_admin * services:
            raise ScriptError("target membership backfill validation failed")
        if conn.execute("SELECT COUNT(*) FROM service_members WHERE role != 'service_admin'").fetchone()[0]:
            raise ScriptError("target membership backfill validation failed")
        actual_sequences = {row["name"]: row["seq"] for row in conn.execute("SELECT name, seq FROM sqlite_sequence WHERE name IN (?, ?, ?, ?, ?, ?)", _SEQUENCE_TABLES)}
        if actual_sequences != sequences:
            raise ScriptError("target sequence validation failed")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or list(conn.execute("PRAGMA foreign_key_check")):
            raise ScriptError("target integrity validation failed")
        if not verify_audit_chain_with_key(conn, audit_key):
            raise ScriptError("target audit chain validation failed")
    except sqlite3.Error as error:
        raise ScriptError("target validation failed") from error


def _validated_counts(path: Path) -> dict[str, int]:
    conn = sqlite3.connect(path)
    try:
        return {
            table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in ("users", "accounts", "audit_events", "service_members")
        }
    except sqlite3.Error as error:
        raise ScriptError("target validation failed") from error
    finally:
        conn.close()


def migrate(source_path: Path, target_path: Path, audit_key_env: str = "AUDIT_KEY_V1", data_key_env: str = "DATA_KEY_V1") -> None:
    if source_path.resolve() == target_path.resolve() or not source_path.is_file() or not target_path.parent.is_dir():
        raise ScriptError("migration paths are invalid")
    require_offline_target(target_path)
    audit_key = load_key(audit_key_env)
    snapshot: Path | None = None
    temporary: Path | None = None
    source: sqlite3.Connection | None = None
    destination: sqlite3.Connection | None = None
    try:
        snapshot = _snapshot(source_path, target_path.parent)
        source = sqlite3.connect(snapshot)
        source.row_factory = sqlite3.Row
        _validate_old_source(source, audit_key)
        fd, name = tempfile.mkstemp(prefix=f".{target_path.name}.", suffix=".tmp", dir=target_path.parent)
        os.close(fd)
        temporary = Path(name)
        ensure_mode(temporary)
        destination = sqlite3.connect(temporary)
        destination.row_factory = sqlite3.Row
        destination.execute("PRAGMA foreign_keys = ON")
        if destination.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise ScriptError("target foreign-key enforcement is disabled")
        destination.execute("BEGIN IMMEDIATE")
        _create_schema(destination, SCHEMA)
        copied, sequences, membership_count = _copy(source, destination)
        _validate_destination(destination, copied, sequences, membership_count, audit_key)
        destination.commit()
        destination.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        destination.execute("VACUUM")
        destination.close()
        destination = None
        if any(path.exists() for path in sidecars(temporary)):
            raise ScriptError("temporary database sidecars remain")
        destination = sqlite3.connect(temporary)
        destination.row_factory = sqlite3.Row
        destination.execute("PRAGMA foreign_keys = ON")
        _validate_destination(destination, copied, sequences, membership_count, audit_key)
        destination.close()
        destination = None
        ensure_mode(temporary)
        _place(temporary, target_path)
        temporary = None
    except sqlite3.Error as error:
        raise ScriptError("migration database operation failed") from error
    finally:
        if destination is not None:
            destination.close()
        if source is not None:
            source.close()
        remove_artifacts(snapshot, temporary)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline pre-feature to new-canonical schema migration")
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--audit-key-env", default="AUDIT_KEY_V1")
    parser.add_argument("--data-key-env", default="DATA_KEY_V1")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        migrate(Path(args.source), Path(args.target), args.audit_key_env, args.data_key_env)
    except ScriptError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    counts = _validated_counts(Path(args.target))
    print(f"OK: users={counts['users']} accounts={counts['accounts']} audit_events={counts['audit_events']} service_members={counts['service_members']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
