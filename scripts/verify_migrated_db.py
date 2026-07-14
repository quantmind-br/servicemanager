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
from service_manager.db import SCHEMA

EXPECTED_COUNTS = {"accounts": 116, "account_service": 116, "field_values": 116, "credentials_backup": 116}
EXPECTED_TABLES = {"accounts", "services", "account_service", "custom_fields", "field_values", "users", "security_events", "audit_events"}
EXPECTED_COLUMNS = {
    "accounts": {"id", "email", "password_ciphertext", "password_nonce", "password_key_version"}, "services": {"id", "name"},
    "account_service": {"account_id", "service_id", "status", "registered"}, "custom_fields": {"id", "service_id", "name"},
    "field_values": {"field_id", "account_id", "value_ciphertext", "value_nonce", "value_key_version"},
    "users": {"id", "username", "password_hash", "role", "is_active", "must_change_password", "created_at", "updated_at", "password_changed_at", "session_version"},
    "security_events": {"id", "kind", "subject", "source_ip", "occurred_at"},
    "audit_events": {"id", "occurred_at", "actor_user_id", "action", "target_type", "target_id", "metadata_json", "source_ip", "user_agent", "previous_hash", "event_hash"},
}
REQUIRED_TRIGGERS = {"audit_events_no_update", "audit_events_no_delete"}


class ScriptError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Independent migrated database verifier")
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--key-env", required=True)
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


def _canonical_secure_schema() -> dict[str, dict[str, str]]:
    reference = sqlite3.connect(":memory:")
    try:
        reference.executescript(SCHEMA)
        return {
            kind: {
                name: _normalize_schema_sql(sql)
                for name, sql in _objects(reference, kind).items()
            }
            for kind in ("table", "index", "trigger")
        }
    finally:
        reference.close()


CANONICAL_SECURE_SCHEMA = _canonical_secure_schema()


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
        if any(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] != count for table, count in EXPECTED_COUNTS.items() if table != "credentials_backup"):
            raise ScriptError("target counts are incompatible")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ScriptError("target integrity is invalid")
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


def verify(
    source_path: Path,
    target_path: Path,
    key_env: str,
    _after_snapshot_ready: Callable[[], None] | None = None,
) -> None:
    if not target_path.is_file() or stat.S_IMODE(target_path.stat().st_mode) != 0o600:
        raise ScriptError("target database permissions are invalid")
    key = _key(key_env)
    source = _ro(source_path)
    target = _ro(target_path)
    try:
        source_data = _legacy(source)
        if _after_snapshot_ready is not None:
            _after_snapshot_ready()
        _secure(target)
        _compare(target, source_data, key)
        _scan(target_path, source_data)
    finally:
        target.close()
        source.close()


def main() -> int:
    args = parse_args()
    try:
        verify(Path(args.source), Path(args.target), args.key_env)
    except ScriptError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("OK: accounts=116 account_service=116 field_values=116")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
