from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from _secure_db import ScriptError, load_key, open_source_read_only


def _canonical_digest(rows: dict[str, list[tuple[object, ...]]]) -> tuple[dict[str, int], str]:
    counts = {name: len(value) for name, value in rows.items()}
    canonical = json.dumps(rows, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=_json_value).encode("utf-8")
    return counts, hashlib.sha256(canonical).hexdigest()


def _json_value(value: object) -> object:
    if isinstance(value, bytes):
        return value.hex()
    raise TypeError(f"unsupported canonical value: {type(value)!r}")


def _legacy_rows(conn: sqlite3.Connection) -> dict[str, list[tuple[object, ...]]]:
    try:
        return {
            "services": [tuple(row) for row in conn.execute("SELECT id, name FROM services ORDER BY id")],
            "custom_fields": [tuple(row) for row in conn.execute("SELECT id, service_id, name FROM custom_fields ORDER BY id")],
            "accounts": [tuple(row) for row in conn.execute("SELECT id, email, password FROM accounts ORDER BY id")],
            "account_service": [tuple(row) for row in conn.execute("SELECT account_id, service_id, status FROM account_service ORDER BY account_id, service_id")],
            "field_values": [tuple(row) for row in conn.execute("SELECT field_id, account_id, value FROM field_values ORDER BY field_id, account_id")],
        }
    except sqlite3.Error as error:
        raise ScriptError("database schema is incompatible") from error


def _secure_rows(conn: sqlite3.Connection, key: bytes) -> dict[str, list[tuple[object, ...]]]:
    try:
        accounts = []
        for row in conn.execute("SELECT id, email, password_ciphertext, password_nonce, password_key_version FROM accounts ORDER BY id"):
            if row["password_key_version"] != 1 or len(bytes(row["password_nonce"])) != 12:
                raise ScriptError("encrypted account data is invalid")
            password = AESGCM(key).decrypt(bytes(row["password_nonce"]), bytes(row["password_ciphertext"]), f"account:{row['id']}:password".encode()).decode("utf-8")
            accounts.append((row["id"], row["email"], password))
        fields = []
        for row in conn.execute("SELECT field_id, account_id, value_ciphertext, value_nonce, value_key_version FROM field_values ORDER BY field_id, account_id"):
            if row["value_key_version"] != 1 or row["value_nonce"] is None or len(bytes(row["value_nonce"])) != 12:
                raise ScriptError("encrypted field data is invalid")
            value = AESGCM(key).decrypt(bytes(row["value_nonce"]), bytes(row["value_ciphertext"]), f"account:{row['account_id']}:field:{row['field_id']}".encode()).decode("utf-8")
            fields.append((row["field_id"], row["account_id"], value))
        return {
            "services": [tuple(row) for row in conn.execute("SELECT id, name FROM services ORDER BY id")],
            "custom_fields": [tuple(row) for row in conn.execute("SELECT id, service_id, name FROM custom_fields ORDER BY id")],
            "accounts": accounts,
            "account_service": [tuple(row) for row in conn.execute("SELECT account_id, service_id, status FROM account_service ORDER BY account_id, service_id")],
            "field_values": fields,
        }
    except (sqlite3.Error, InvalidTag, UnicodeDecodeError, TypeError, ValueError) as error:
        if isinstance(error, ScriptError):
            raise
        raise ScriptError("encrypted business data is invalid") from error


def _result(rows: dict[str, list[tuple[object, ...]]]) -> str:
    counts, digest = _canonical_digest(rows)
    return json.dumps({"counts": counts, "sha256": digest}, sort_keys=True, separators=(",", ":"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare business data without exposing secrets")
    subparsers = parser.add_subparsers(dest="command", required=True)
    legacy = subparsers.add_parser("legacy")
    legacy.add_argument("--database", required=True)
    secure = subparsers.add_parser("secure")
    secure.add_argument("--database", required=True)
    secure.add_argument("--key-env", default="DATA_KEY_V1")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    conn: sqlite3.Connection | None = None
    try:
        conn = open_source_read_only(Path(args.database))
        conn.row_factory = sqlite3.Row
        if args.command == "legacy":
            print(_result(_legacy_rows(conn)))
        else:
            print(_result(_secure_rows(conn, load_key(args.key_env))))
    except ScriptError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    finally:
        if conn is not None:
            conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
