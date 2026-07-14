from __future__ import annotations

import argparse
import sqlite3
import sys
import tempfile
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from _secure_db import (
    CANONICAL_SECURE_SCHEMA,
    ScriptError,
    _normalize_schema_sql,
    ensure_mode,
    load_key,
    remove_artifacts,
    require_offline_target,
    secure_schema_structure_valid,
    sidecars,
)
from migrate_auth_schema import _copy_rows, _create_schema, _place, _snapshot
from service_manager.audit import verify_audit_chain_with_key

# The pre-cutover custom_fields/field_values definitions, frozen independently of
# service_manager.db.SCHEMA (which is now the encrypted-only post-cutover schema).
_OLD_CUSTOM_FIELDS_SQL = _normalize_schema_sql(
    """CREATE TABLE custom_fields (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    is_secret INTEGER NOT NULL DEFAULT 1 CHECK (is_secret IN (0, 1)),
    UNIQUE (service_id, name),
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
)"""
)
_OLD_FIELD_VALUES_SQL = _normalize_schema_sql(
    """CREATE TABLE field_values (
    field_id INTEGER NOT NULL,
    account_id INTEGER NOT NULL,
    value_plaintext TEXT,
    value_ciphertext BLOB,
    value_nonce BLOB,
    value_key_version INTEGER,
    PRIMARY KEY (field_id, account_id),
    FOREIGN KEY (field_id) REFERENCES custom_fields(id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    CHECK (
        (value_plaintext IS NOT NULL AND value_ciphertext IS NULL AND value_nonce IS NULL AND value_key_version IS NULL)
        OR
        (value_plaintext IS NULL AND value_ciphertext IS NOT NULL AND value_nonce IS NOT NULL AND value_key_version IS NOT NULL)
    )
)"""
)
_OLD_REPRESENTATION_TRIGGERS = {
    "field_values_require_secret_representation_insert": _normalize_schema_sql(
        """CREATE TRIGGER field_values_require_secret_representation_insert
BEFORE INSERT ON field_values
BEGIN
    SELECT CASE
        WHEN (SELECT is_secret FROM custom_fields WHERE id = NEW.field_id) = 1
             AND NEW.value_plaintext IS NOT NULL
        THEN RAISE(ABORT, 'secret field requires encrypted representation')
        WHEN (SELECT is_secret FROM custom_fields WHERE id = NEW.field_id) = 0
             AND NEW.value_ciphertext IS NOT NULL
        THEN RAISE(ABORT, 'non-secret field requires plaintext representation')
    END;
END"""
    ),
    "custom_fields_preserve_value_representation": _normalize_schema_sql(
        """CREATE TRIGGER custom_fields_preserve_value_representation
BEFORE UPDATE OF is_secret ON custom_fields
WHEN NEW.is_secret != OLD.is_secret
  AND EXISTS (
      SELECT 1 FROM field_values
      WHERE field_id = OLD.id
        AND ((NEW.is_secret = 1 AND value_plaintext IS NOT NULL)
          OR (NEW.is_secret = 0 AND value_ciphertext IS NOT NULL))
  )
BEGIN
    SELECT RAISE(ABORT, 'field secrecy classification conflicts with stored values');
END"""
    ),
    "field_values_require_secret_representation_update": _normalize_schema_sql(
        """CREATE TRIGGER field_values_require_secret_representation_update
BEFORE UPDATE ON field_values
BEGIN
    SELECT CASE
        WHEN (SELECT is_secret FROM custom_fields WHERE id = NEW.field_id) = 1
             AND NEW.value_plaintext IS NOT NULL
        THEN RAISE(ABORT, 'secret field requires encrypted representation')
        WHEN (SELECT is_secret FROM custom_fields WHERE id = NEW.field_id) = 0
             AND NEW.value_ciphertext IS NOT NULL
        THEN RAISE(ABORT, 'non-secret field requires plaintext representation')
    END;
END"""
    ),
}

_COPY_COLUMNS = {
    "services": ("id", "name"),
    "accounts": ("id", "email", "password_ciphertext", "password_nonce", "password_key_version"),
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
_SEQUENCE_TABLES = ("accounts", "services", "custom_fields", "users", "security_events", "audit_events")


def _normalized_objects(conn: sqlite3.Connection, kind: str) -> dict[str, str]:
    return {
        row[0]: _normalize_schema_sql(row[1])
        for row in conn.execute("SELECT name, sql FROM sqlite_master WHERE type = ? AND name NOT LIKE 'sqlite_%'", (kind,))
        if row[1]
    }


def _expected_old_objects() -> dict[str, dict[str, str]]:
    expected = {kind: dict(objects) for kind, objects in CANONICAL_SECURE_SCHEMA.items()}
    expected["table"]["custom_fields"] = _OLD_CUSTOM_FIELDS_SQL
    expected["table"]["field_values"] = _OLD_FIELD_VALUES_SQL
    expected["trigger"].update(_OLD_REPRESENTATION_TRIGGERS)
    return expected


def _validate_old_source(conn: sqlite3.Connection, audit_key: bytes) -> None:
    try:
        if any(_normalized_objects(conn, kind) != objects for kind, objects in _expected_old_objects().items()):
            raise ScriptError("source schema is incompatible")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ScriptError("source integrity validation failed")
        if list(conn.execute("PRAGMA foreign_key_check")):
            raise ScriptError("source foreign-key validation failed")
        if not verify_audit_chain_with_key(conn, audit_key):
            raise ScriptError("source audit chain validation failed")
    except sqlite3.Error as error:
        raise ScriptError("source schema is incompatible") from error


def _source_field_plaintext(row: sqlite3.Row, data_key: bytes) -> str:
    plaintext = row["value_plaintext"]
    ciphertext = row["value_ciphertext"]
    nonce = row["value_nonce"]
    key_version = row["value_key_version"]
    has_plaintext = plaintext is not None
    has_envelope = ciphertext is not None or nonce is not None or key_version is not None
    if has_plaintext and has_envelope:
        raise ScriptError("source field representation is ambiguous")
    if not has_plaintext and not has_envelope:
        raise ScriptError("source field representation is empty")
    if has_plaintext:
        return str(plaintext)
    if ciphertext is None or nonce is None or key_version != 1 or len(bytes(nonce)) != 12:
        raise ScriptError("source field envelope is invalid")
    try:
        return AESGCM(data_key).decrypt(bytes(nonce), bytes(ciphertext), f"account:{row['account_id']}:field:{row['field_id']}".encode()).decode("utf-8")
    except Exception as error:
        raise ScriptError("source field authentication failed") from error


def _copy(source: sqlite3.Connection, destination: sqlite3.Connection, data_key: bytes) -> tuple[dict[str, list[tuple[object, ...]]], dict[str, int]]:
    copied: dict[str, list[tuple[object, ...]]] = {}
    for table in ("services", "accounts", "users", "security_events", "audit_events"):
        copied[table] = _copy_rows(source, destination, table, _COPY_COLUMNS[table])
    copied["custom_fields"] = [tuple(row) for row in source.execute("SELECT id, service_id, name FROM custom_fields ORDER BY id")]
    destination.executemany("INSERT INTO custom_fields (id, service_id, name) VALUES (?, ?, ?)", copied["custom_fields"])
    copied["account_service"] = [
        tuple(row) for row in source.execute("SELECT account_id, service_id, status, registered FROM account_service ORDER BY account_id, service_id")
    ]
    destination.executemany(
        "INSERT INTO account_service (account_id, service_id, status, registered) VALUES (?, ?, ?, ?)",
        copied["account_service"],
    )
    field_values: list[tuple[int, int, str]] = []
    for row in source.execute("SELECT field_id, account_id, value_plaintext, value_ciphertext, value_nonce, value_key_version FROM field_values ORDER BY field_id, account_id"):
        if row["value_plaintext"] is None:
            if row["value_key_version"] != 1 or row["value_nonce"] is None or len(bytes(row["value_nonce"])) != 12:
                raise ScriptError("source field envelope is invalid")
            plaintext = _source_field_plaintext(row, data_key)
            destination.execute(
                "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, ?)",
                (row["field_id"], row["account_id"], bytes(row["value_ciphertext"]), bytes(row["value_nonce"]), row["value_key_version"]),
            )
        else:
            plaintext = _source_field_plaintext(row, data_key)
            nonce = os.urandom(12)
            destination.execute(
                "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, 1)",
                (row["field_id"], row["account_id"], AESGCM(data_key).encrypt(nonce, plaintext.encode("utf-8"), f"account:{row['account_id']}:field:{row['field_id']}".encode()), nonce),
            )
        field_values.append((row["field_id"], row["account_id"], plaintext))
    copied["field_values"] = field_values
    sequences = {
        row["name"]: row["seq"]
        for row in source.execute("SELECT name, seq FROM sqlite_sequence WHERE name IN (?, ?, ?, ?, ?, ?)", _SEQUENCE_TABLES)
    }
    for table, sequence in sequences.items():
        destination.execute("DELETE FROM sqlite_sequence WHERE name = ?", (table,))
        destination.execute("INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)", (table, sequence))
    return copied, sequences


def _validate_destination(conn: sqlite3.Connection, copied: dict[str, list[tuple[object, ...]]], sequences: dict[str, int], audit_key: bytes, data_key: bytes) -> None:
    secure_schema_structure_valid(conn)
    try:
        if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise ScriptError("target foreign-key enforcement is disabled")
        for table, columns in _COPY_COLUMNS.items():
            actual = [tuple(row) for row in conn.execute(f"SELECT {', '.join(columns)} FROM {table} ORDER BY id")]
            if actual != copied[table]:
                raise ScriptError("target equivalence validation failed")
        custom_fields = [tuple(row) for row in conn.execute("SELECT id, service_id, name FROM custom_fields ORDER BY id")]
        if custom_fields != copied["custom_fields"]:
            raise ScriptError("target equivalence validation failed")
        links = [tuple(row) for row in conn.execute("SELECT account_id, service_id, status, registered FROM account_service ORDER BY account_id, service_id")]
        if links != copied["account_service"]:
            raise ScriptError("target equivalence validation failed")
        decrypted: list[tuple[int, int, str]] = []
        for row in conn.execute("SELECT field_id, account_id, value_ciphertext, value_nonce, value_key_version FROM field_values ORDER BY field_id, account_id"):
            nonce = row["value_nonce"]
            if row["value_ciphertext"] is None or nonce is None or row["value_key_version"] != 1 or len(bytes(nonce)) != 12:
                raise ScriptError("target field envelope is invalid")
            plaintext = AESGCM(data_key).decrypt(bytes(nonce), bytes(row["value_ciphertext"]), f"account:{row['account_id']}:field:{row['field_id']}".encode()).decode("utf-8")
            decrypted.append((row["field_id"], row["account_id"], plaintext))
        if decrypted != copied["field_values"]:
            raise ScriptError("target equivalence validation failed")
        actual_sequences = {row["name"]: row["seq"] for row in conn.execute("SELECT name, seq FROM sqlite_sequence WHERE name IN (?, ?, ?, ?, ?, ?)", _SEQUENCE_TABLES)}
        if actual_sequences != sequences:
            raise ScriptError("target sequence validation failed")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or list(conn.execute("PRAGMA foreign_key_check")):
            raise ScriptError("target integrity validation failed")
        if not verify_audit_chain_with_key(conn, audit_key):
            raise ScriptError("target audit chain validation failed")
    except sqlite3.Error as error:
        raise ScriptError("target validation failed") from error


def migrate(source_path: Path, target_path: Path, data_key_env: str = "DATA_KEY_V1", audit_key_env: str = "AUDIT_KEY_V1") -> None:
    if source_path.resolve() == target_path.resolve() or not source_path.is_file() or not target_path.parent.is_dir():
        raise ScriptError("migration paths are invalid")
    require_offline_target(target_path)
    audit_key = load_key(audit_key_env)
    data_key = load_key(data_key_env)
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
        _create_schema(destination)
        copied, sequences = _copy(source, destination, data_key)
        _validate_destination(destination, copied, sequences, audit_key, data_key)
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
        _validate_destination(destination, copied, sequences, audit_key, data_key)
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
    parser = argparse.ArgumentParser(description="Offline unclassified custom-field encryption migration")
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--data-key-env", default="DATA_KEY_V1")
    parser.add_argument("--audit-key-env", default="AUDIT_KEY_V1")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        migrate(Path(args.source), Path(args.target), data_key_env=args.data_key_env, audit_key_env=args.audit_key_env)
    except ScriptError as error:
        print(f"erro: {error}", file=sys.stderr)
        return 1
    print("migração concluída")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
