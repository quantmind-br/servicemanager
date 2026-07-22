from __future__ import annotations

import argparse
import copy
import sqlite3
import sys
import tempfile
import os
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
    _place,
    _snapshot,
    frozen_schema_objects,
    normalized_objects,
    structural_schema_valid,
)
from service_manager.audit import verify_audit_chain_with_key

# Frozen, independent copy of this tool's TARGET schema: the canonical schema as
# it existed when this historical migration shipped (before the feature pack).
# Deliberately not imported from _secure_db or _pre_feature_schema so this frozen
# utility keeps behaving identically regardless of later canonical schema changes.
TARGET_SCHEMA = """
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_ciphertext BLOB NOT NULL,
    password_nonce BLOB NOT NULL,
    password_key_version INTEGER NOT NULL
);
CREATE TABLE services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);
CREATE TABLE account_service (
    account_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'nunca' CHECK (status IN ('ativo', 'nunca', 'inativo')),
    registered INTEGER NOT NULL DEFAULT 0 CHECK (registered IN (0, 1)),
    PRIMARY KEY (account_id, service_id),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);
CREATE TABLE custom_fields (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    UNIQUE (service_id, name),
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);
CREATE TABLE field_values (
    field_id INTEGER NOT NULL,
    account_id INTEGER NOT NULL,
    value_ciphertext BLOB NOT NULL,
    value_nonce BLOB NOT NULL,
    value_key_version INTEGER NOT NULL,
    PRIMARY KEY (field_id, account_id),
    FOREIGN KEY (field_id) REFERENCES custom_fields(id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
CREATE INDEX account_service_service_id ON account_service(service_id);
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
CREATE TABLE security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('login_failure', 'reveal')),
    subject TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX security_events_kind_subject_occurred_at
    ON security_events(kind, subject, occurred_at);
CREATE INDEX security_events_kind_source_ip_occurred_at
    ON security_events(kind, source_ip, occurred_at);
CREATE INDEX security_events_occurred_at ON security_events(occurred_at);
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    actor_user_id INTEGER,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    metadata_json TEXT,
    source_ip TEXT,
    user_agent TEXT,
    previous_hash BLOB NOT NULL,
    event_hash BLOB NOT NULL,
    FOREIGN KEY (actor_user_id) REFERENCES users(id)
);
CREATE TRIGGER audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
CREATE TRIGGER audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
"""

_TARGET_OBJECTS, _TARGET_COLUMNS = frozen_schema_objects(TARGET_SCHEMA)

# Tables whose row contents must be preserved byte-for-byte by the migration.
_ROW_TABLES = (
    "accounts", "services", "account_service", "custom_fields", "field_values",
    "users", "security_events", "audit_events",
)


def _expected_old_objects() -> dict[str, dict[str, str]]:
    expected = {kind: dict(objects) for kind, objects in copy.deepcopy(_TARGET_OBJECTS).items()}
    del expected["index"]["account_service_service_id"]
    return expected


def _validate_old_source(conn: sqlite3.Connection, audit_key: bytes) -> None:
    try:
        if any(normalized_objects(conn, kind) != objects for kind, objects in _expected_old_objects().items()):
            raise ScriptError("source schema is incompatible")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ScriptError("source integrity validation failed")
        if list(conn.execute("PRAGMA foreign_key_check")):
            raise ScriptError("source foreign-key validation failed")
        if not verify_audit_chain_with_key(conn, audit_key):
            raise ScriptError("source audit chain validation failed")
    except sqlite3.Error as error:
        raise ScriptError("source schema is incompatible") from error


def _row_counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in _ROW_TABLES}


def _validate_destination(conn: sqlite3.Connection, expected_counts: dict[str, int], audit_key: bytes) -> None:
    structural_schema_valid(conn, _TARGET_OBJECTS, _TARGET_COLUMNS)
    try:
        if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise ScriptError("target foreign-key enforcement is disabled")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ScriptError("target integrity validation failed")
        if list(conn.execute("PRAGMA foreign_key_check")):
            raise ScriptError("target foreign-key validation failed")
        if not verify_audit_chain_with_key(conn, audit_key):
            raise ScriptError("target audit chain validation failed")
        if _row_counts(conn) != expected_counts:
            raise ScriptError("target counts do not match the source")
    except sqlite3.Error as error:
        raise ScriptError("target validation failed") from error


def migrate(source_path: Path, target_path: Path, audit_key_env: str = "AUDIT_KEY_V1") -> None:
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
        expected_counts = _row_counts(source)
        source.close()
        source = None
        fd, name = tempfile.mkstemp(prefix=f".{target_path.name}.", suffix=".tmp", dir=target_path.parent)
        os.close(fd)
        temporary = Path(name)
        ensure_mode(temporary)
        temporary.write_bytes(snapshot.read_bytes())
        destination = sqlite3.connect(temporary)
        destination.row_factory = sqlite3.Row
        destination.execute("PRAGMA foreign_keys = ON")
        if destination.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise ScriptError("target foreign-key enforcement is disabled")
        destination.execute("BEGIN IMMEDIATE")
        destination.execute("CREATE INDEX account_service_service_id ON account_service(service_id)")
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
        _validate_destination(destination, expected_counts, audit_key)
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
    parser = argparse.ArgumentParser(description="Offline account_service(service_id) index migration")
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--audit-key-env", default="AUDIT_KEY_V1")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        migrate(Path(args.source), Path(args.target), audit_key_env=args.audit_key_env)
    except ScriptError as error:
        print(f"erro: {error}", file=sys.stderr)
        return 1
    print("migração concluída")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
