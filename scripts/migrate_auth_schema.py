from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from _secure_db import (
    ScriptError,
    ensure_mode,
    load_key,
    remove_artifacts,
    require_offline_target,
    secure_schema_structure_valid,
    sidecars,
)
from service_manager.audit import verify_audit_chain_with_key
from _old_secure_schema import OLD_SECURE_OBJECTS
from service_manager.db import SCHEMA

_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")

# This contract intentionally describes the pre-cutover database independently
# from service_manager.db.SCHEMA, which is the post-cutover schema.
_OLD_TABLE_COLUMNS = {
    "accounts": {"id", "email", "password_ciphertext", "password_nonce", "password_key_version"},
    "services": {"id", "name"},
    "account_service": {"account_id", "service_id", "status"},
    "custom_fields": {"id", "service_id", "name", "is_secret"},
    "field_values": {"field_id", "account_id", "value_plaintext", "value_ciphertext", "value_nonce", "value_key_version"},
    "users": {
        "id", "email", "password_hash", "role", "is_active", "must_change_password",
        "totp_secret_ciphertext", "totp_nonce", "totp_key_version", "totp_confirmed_at",
        "last_totp_step", "created_at", "updated_at", "password_changed_at", "session_version",
        "pending_totp_secret_ciphertext", "pending_totp_nonce", "pending_totp_key_version",
        "totp_enrollment_shown_at",
    },
    "recovery_codes": {"user_id", "code_hash", "used_at"},
    "security_events": {"id", "kind", "subject", "source_ip", "occurred_at"},
    "audit_events": {
        "id", "occurred_at", "actor_user_id", "action", "target_type", "target_id",
        "metadata_json", "source_ip", "user_agent", "previous_hash", "event_hash",
    },
    "bootstrap_tokens": {"token_hash", "user_id", "expires_at", "consumed_at"},
}
_OLD_TABLES = set(_OLD_TABLE_COLUMNS)
_OLD_INDEXES = {
    "security_events_kind_subject_occurred_at",
    "security_events_kind_source_ip_occurred_at",
    "security_events_occurred_at",
    "bootstrap_tokens_one_active",
}
_OLD_TRIGGERS = {
    "audit_events_no_update",
    "audit_events_no_delete",
    "field_values_require_secret_representation_insert",
    "field_values_require_secret_representation_update",
    "custom_fields_preserve_value_representation",
}
_COPY_COLUMNS = {
    "services": ("id", "name"),
    "accounts": ("id", "email", "password_ciphertext", "password_nonce", "password_key_version"),
    "security_events": ("id", "kind", "subject", "source_ip", "occurred_at"),
    "audit_events": ("id", "occurred_at", "actor_user_id", "action", "target_type", "target_id", "metadata_json", "source_ip", "user_agent", "previous_hash", "event_hash"),
}
_USER_COLUMNS = ("id", "password_hash", "role", "is_active", "must_change_password", "created_at", "updated_at", "password_changed_at", "session_version")
_SEQUENCE_TABLES = ("accounts", "services", "custom_fields", "users", "security_events", "audit_events")


def _object_names(conn: sqlite3.Connection, kind: str) -> set[str]:
    return {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = ? AND name NOT LIKE 'sqlite_%'", (kind,))
    }


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}



def _normalized_objects(conn: sqlite3.Connection, kind: str) -> dict[str, str]:
    return {
        row[0]: " ".join((row[1] or "").split())
        for row in conn.execute("SELECT name, sql FROM sqlite_master WHERE type = ?", (kind,))
        if not row[0].startswith("sqlite_")
    }
def _normalize_username(value: object) -> str:
    candidate = value.strip().lower() if isinstance(value, str) else ""
    return candidate if _USERNAME_RE.fullmatch(candidate) else ""


def _validate_old_source(conn: sqlite3.Connection, audit_key: bytes) -> None:
    try:
        if any(_normalized_objects(conn, kind) != expected for kind, expected in OLD_SECURE_OBJECTS.items()):
            raise ScriptError("source schema is incompatible")
        if any(_columns(conn, table) != expected for table, expected in _OLD_TABLE_COLUMNS.items()):
            raise ScriptError("source schema is incompatible")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ScriptError("source integrity validation failed")
        if list(conn.execute("PRAGMA foreign_key_check")):
            raise ScriptError("source foreign-key validation failed")
        if not verify_audit_chain_with_key(conn, audit_key):
            raise ScriptError("source audit chain validation failed")
    except sqlite3.Error as error:
        raise ScriptError("source schema is incompatible") from error


def _load_username_map(path: Path, user_ids: set[int]) -> dict[int, str]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ScriptError("username map is invalid") from error
    if not isinstance(loaded, dict) or set(loaded) != {str(user_id) for user_id in user_ids}:
        raise ScriptError("username map is incomplete or contains unknown users")
    mapped: dict[int, str] = {}
    seen: set[str] = set()
    for key, value in loaded.items():
        username = _normalize_username(value)
        if not username or username.casefold() in seen:
            raise ScriptError("username map contains invalid or duplicate usernames")
        seen.add(username.casefold())
        mapped[int(key)] = username
    return mapped


def _create_schema(conn: sqlite3.Connection) -> None:
    statement = ""
    for line in SCHEMA.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            conn.execute(statement)
            statement = ""
    if statement.strip():
        raise ScriptError("migration schema setup failed")


def _copy_rows(source: sqlite3.Connection, destination: sqlite3.Connection, table: str, columns: tuple[str, ...]) -> list[tuple[object, ...]]:
    quoted = ", ".join(columns)
    rows = [tuple(row) for row in source.execute(f"SELECT {quoted} FROM {table} ORDER BY id")]
    placeholders = ", ".join("?" for _ in columns)
    destination.executemany(f"INSERT INTO {table} ({quoted}) VALUES ({placeholders})", rows)
    return rows


def _copy(source: sqlite3.Connection, destination: sqlite3.Connection, usernames: dict[int, str], data_key_env: str) -> tuple[dict[str, list[tuple[object, ...]]], list[tuple[object, ...]], dict[str, int]]:
    copied: dict[str, list[tuple[object, ...]]] = {}
    copied["services"] = _copy_rows(source, destination, "services", _COPY_COLUMNS["services"])
    copied["accounts"] = _copy_rows(source, destination, "accounts", _COPY_COLUMNS["accounts"])
    old_users = [tuple(row) for row in source.execute(f"SELECT {', '.join(_USER_COLUMNS)} FROM users ORDER BY id")]
    destination.executemany(
        "INSERT INTO users (id, username, password_hash, role, is_active, must_change_password, created_at, updated_at, password_changed_at, session_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ((row[0], usernames[row[0]], *row[1:]) for row in old_users),
    )
    copied["custom_fields"] = [tuple(row) for row in source.execute("SELECT id, service_id, name FROM custom_fields ORDER BY id")]
    destination.executemany("INSERT INTO custom_fields (id, service_id, name) VALUES (?, ?, ?)", copied["custom_fields"])
    copied["account_service"] = [tuple(row) for row in source.execute("SELECT account_id, service_id, status FROM account_service ORDER BY account_id, service_id")]
    destination.executemany("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, ?)", copied["account_service"])
    field_values: list[tuple[object, ...]] = []
    for row in source.execute("SELECT field_id, account_id, value_plaintext, value_ciphertext, value_nonce, value_key_version FROM field_values ORDER BY field_id, account_id"):
        has_plaintext = row["value_plaintext"] is not None
        has_envelope = row["value_ciphertext"] is not None or row["value_nonce"] is not None or row["value_key_version"] is not None
        if has_plaintext and has_envelope:
            raise ScriptError("source field representation is ambiguous")
        if has_plaintext:
            nonce = os.urandom(12)
            ciphertext = AESGCM(load_key(data_key_env)).encrypt(nonce, str(row["value_plaintext"]).encode("utf-8"), f"account:{row['account_id']}:field:{row['field_id']}".encode())
            key_version = 1
        else:
            if row["value_ciphertext"] is None or row["value_nonce"] is None or row["value_key_version"] != 1 or len(bytes(row["value_nonce"])) != 12:
                raise ScriptError("source field envelope is invalid")
            ciphertext = bytes(row["value_ciphertext"])
            nonce = bytes(row["value_nonce"])
            key_version = row["value_key_version"]
        destination.execute(
            "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, ?)",
            (row["field_id"], row["account_id"], ciphertext, nonce, key_version),
        )
        field_values.append((row["field_id"], row["account_id"], ciphertext, nonce, key_version))
    copied["field_values"] = field_values
    copied["security_events"] = _copy_rows(source, destination, "security_events", _COPY_COLUMNS["security_events"])
    copied["audit_events"] = _copy_rows(source, destination, "audit_events", _COPY_COLUMNS["audit_events"])
    sequences = {
        row["name"]: row["seq"]
        for row in source.execute("SELECT name, seq FROM sqlite_sequence WHERE name IN (?, ?, ?, ?, ?, ?)", _SEQUENCE_TABLES)
    }
    for table, sequence in sequences.items():
        destination.execute("DELETE FROM sqlite_sequence WHERE name = ?", (table,))
        destination.execute("INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)", (table, sequence))
    return copied, old_users, sequences


def _validate_destination(conn: sqlite3.Connection, copied: dict[str, list[tuple[object, ...]]], old_users: list[tuple[object, ...]], usernames: dict[int, str], sequences: dict[str, int], audit_key: bytes) -> None:
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
        links = [tuple(row) for row in conn.execute("SELECT account_id, service_id, status FROM account_service ORDER BY account_id, service_id")]
        if links != copied["account_service"]:
            raise ScriptError("target equivalence validation failed")
        values = [
            (row["field_id"], row["account_id"], bytes(row["value_ciphertext"]), bytes(row["value_nonce"]), row["value_key_version"])
            for row in conn.execute("SELECT field_id, account_id, value_ciphertext, value_nonce, value_key_version FROM field_values ORDER BY field_id, account_id")
        ]
        if values != copied["field_values"]:
            raise ScriptError("target equivalence validation failed")
        users = [tuple(row) for row in conn.execute("SELECT id, username, password_hash, role, is_active, must_change_password, created_at, updated_at, password_changed_at, session_version FROM users ORDER BY id")]
        expected_users = [(row[0], usernames[row[0]], *row[1:]) for row in old_users]
        if users != expected_users:
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



def _snapshot(source_path: Path, target_dir: Path) -> Path:
    fd, name = tempfile.mkstemp(prefix=f".{source_path.name}.", suffix=".snapshot", dir=target_dir)
    os.close(fd)
    snapshot = Path(name)
    ensure_mode(snapshot)
    source: sqlite3.Connection | None = None
    destination: sqlite3.Connection | None = None
    try:
        source = sqlite3.connect(source_path.resolve().as_uri() + "?mode=ro&cache=private", uri=True)
        destination = sqlite3.connect(snapshot)
        source.backup(destination)
        return snapshot
    except sqlite3.Error as error:
        remove_artifacts(snapshot)
        raise ScriptError("source snapshot cannot be created") from error
    finally:
        if destination is not None:
            destination.close()
        if source is not None:
            source.close()


def _place(temporary: Path, target_path: Path) -> None:
    rollback: Path | None = None
    placed = False
    try:
        if target_path.exists():
            fd, name = tempfile.mkstemp(prefix=f".{target_path.name}.", suffix=".rollback", dir=target_path.parent)
            os.close(fd)
            rollback = Path(name)
            os.replace(target_path, rollback)
        os.replace(temporary, target_path)
        placed = True
        ensure_mode(target_path)
        if any(path.exists() for path in sidecars(target_path)):
            raise ScriptError("target database sidecars remain")
    except (OSError, ScriptError) as error:
        try:
            if rollback is not None:
                os.replace(rollback, target_path)
                rollback = None
            elif placed:
                remove_artifacts(target_path)
        except (OSError, ScriptError) as recovery_error:
            raise ScriptError("migration recovery required") from recovery_error
        raise error
    else:
        if rollback is not None:
            try:
                remove_artifacts(rollback)
            except ScriptError as error:
                try:
                    os.replace(rollback, target_path)
                except OSError as recovery_error:
                    raise ScriptError("migration recovery required") from recovery_error
                raise ScriptError("migration recovery required") from error



def _validated_counts(path: Path) -> dict[str, int]:
    conn = sqlite3.connect(path)
    try:
        return {
            table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in ("users", "accounts", "audit_events")
        }
    except sqlite3.Error as error:
        raise ScriptError("target validation failed") from error
    finally:
        conn.close()

def migrate(source_path: Path, target_path: Path, username_map_path: Path, audit_key_env: str = "AUDIT_KEY_V1", data_key_env: str = "DATA_KEY_V1") -> None:
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
        user_ids = {row["id"] for row in source.execute("SELECT id FROM users ORDER BY id")}
        usernames = _load_username_map(username_map_path, user_ids)
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
        copied, old_users, sequences = _copy(source, destination, usernames, data_key_env)
        _validate_destination(destination, copied, old_users, usernames, sequences, audit_key)
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
        _validate_destination(destination, copied, old_users, usernames, sequences, audit_key)
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
    parser = argparse.ArgumentParser(description="Offline secure authentication schema migration")
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--username-map", required=True)
    parser.add_argument("--audit-key-env", default="AUDIT_KEY_V1")
    parser.add_argument("--data-key-env", default="DATA_KEY_V1")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        migrate(Path(args.source), Path(args.target), Path(args.username_map), args.audit_key_env, args.data_key_env)
    except ScriptError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    counts = _validated_counts(Path(args.target))
    print(f"OK: users={counts['users']} accounts={counts['accounts']} audit_events={counts['audit_events']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
