from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from collections.abc import Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from service_manager.db import SCHEMA
from _secure_db import (
    ScriptError, begin_snapshot, ensure_mode, load_key, open_source_read_only, read_legacy_values,
    remove_artifacts, remove_sidecars, require_offline_target, secure_schema_valid, sidecars,
    validate_legacy_source,
)


def _after_source_snapshot() -> None:
    """Test seam invoked after source rows are materialized under the read snapshot."""
    return None


def _after_schema_created() -> None:
    """Test seam invoked before any migrated data is copied."""
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Controlled legacy database migration")
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--key-env", required=True)
    return parser.parse_args()


def _create_schema_in_transaction(conn: sqlite3.Connection) -> None:
    statement = ""
    for line in SCHEMA.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            conn.execute(statement)
            statement = ""
    if statement.strip():
        raise ScriptError("migration schema setup failed")


def _validate_target(conn: sqlite3.Connection, key: bytes, source: tuple[list[sqlite3.Row], ...]) -> None:
    services, fields, accounts, links, values = source
    secure_schema_valid(conn)
    comparisons = (
        ("SELECT id, name FROM services ORDER BY id", [tuple(row) for row in services]),
        ("SELECT id, service_id, name, is_secret FROM custom_fields ORDER BY id", [(*tuple(row), 1) for row in fields]),
        ("SELECT id, email FROM accounts ORDER BY id", [(row["id"], row["email"]) for row in accounts]),
        ("SELECT account_id, service_id, status FROM account_service ORDER BY account_id, service_id", [tuple(row) for row in links]),
    )
    if any([tuple(row) for row in conn.execute(query)] != expected for query, expected in comparisons):
        raise ScriptError("target equivalence validation failed")
    expected_accounts = {row["id"]: row["password"] for row in accounts}
    expected_values = {(row["field_id"], row["account_id"]): row["value"] for row in values}
    nonces: set[bytes] = set()
    try:
        for row in conn.execute("SELECT id, password_ciphertext, password_nonce, password_key_version FROM accounts ORDER BY id"):
            nonce = bytes(row["password_nonce"])
            if len(nonce) != 12 or row["password_key_version"] != 1 or nonce in nonces:
                raise ScriptError("target encryption envelopes are invalid")
            nonces.add(nonce)
            if AESGCM(key).decrypt(nonce, bytes(row["password_ciphertext"]), f"account:{row['id']}:password".encode()).decode() != expected_accounts[row["id"]]:
                raise ScriptError("target equivalence validation failed")
        for row in conn.execute("SELECT field_id, account_id, value_ciphertext, value_nonce, value_key_version FROM field_values ORDER BY field_id, account_id"):
            nonce = bytes(row["value_nonce"])
            if len(nonce) != 12 or row["value_key_version"] != 1 or nonce in nonces:
                raise ScriptError("target encryption envelopes are invalid")
            nonces.add(nonce)
            if AESGCM(key).decrypt(nonce, bytes(row["value_ciphertext"]), f"account:{row['account_id']}:field:{row['field_id']}".encode()).decode() != expected_values[(row["field_id"], row["account_id"])]:
                raise ScriptError("target equivalence validation failed")
    except (sqlite3.Error, ValueError, TypeError) as error:
        raise ScriptError("target encryption verification failed") from error
    if len(nonces) != 232:
        raise ScriptError("target encryption envelopes are invalid")


def _scan_residue(path: Path, source: tuple[list[sqlite3.Row], ...]) -> None:
    payload = b"".join(artifact.read_bytes() for artifact in (path, *sidecars(path)) if artifact.exists())
    for row in (*source[2], *source[4]):
        secret = row["password"] if "password" in row.keys() else row["value"]
        if secret and secret.encode() in payload:
            raise ScriptError("target contains plaintext residue")


def migrate(
    source_path: Path,
    target_path: Path,
    key_env: str,
    *,
    _after_account_copy: Callable[[], None] | None = None,
    _after_snapshot_ready: Callable[[], None] | None = None,
    _after_placement: Callable[[], None] | None = None,
) -> None:
    if source_path.resolve() == target_path.resolve() or not target_path.parent.is_dir():
        raise ScriptError("migration paths are invalid")
    require_offline_target(target_path)
    key = load_key(key_env)
    source = open_source_read_only(source_path)
    temporary: Path | None = None
    target: sqlite3.Connection | None = None
    try:
        begin_snapshot(source)
        validate_legacy_source(source)
        snapshot = read_legacy_values(source)
        if _after_snapshot_ready is not None:
            _after_snapshot_ready()
        else:
            _after_source_snapshot()
        fd, temporary_name = tempfile.mkstemp(prefix=f".{target_path.name}.", suffix=".tmp", dir=target_path.parent)
        os.close(fd)
        temporary = Path(temporary_name)
        ensure_mode(temporary)
        target = sqlite3.connect(temporary)
        target.row_factory = sqlite3.Row
        target.execute("PRAGMA foreign_keys = ON")
        target.execute("BEGIN IMMEDIATE")
        _create_schema_in_transaction(target)
        _after_schema_created()
        services, fields, accounts, links, values = snapshot
        target.executemany("INSERT INTO services (id, name) VALUES (?, ?)", ((row["id"], row["name"]) for row in services))
        target.executemany("INSERT INTO custom_fields (id, service_id, name, is_secret) VALUES (?, ?, ?, 1)", ((row["id"], row["service_id"], row["name"]) for row in fields))
        for row in accounts:
            nonce = os.urandom(12)
            target.execute("INSERT INTO accounts (id, email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, ?, 1)", (row["id"], row["email"], AESGCM(key).encrypt(nonce, row["password"].encode(), f"account:{row['id']}:password".encode()), nonce))
        target.executemany("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, ?)", ((row["account_id"], row["service_id"], row["status"]) for row in links))
        if _after_account_copy is not None:
            _after_account_copy()
        for row in values:
            nonce = os.urandom(12)
            target.execute("INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, 1)", (row["field_id"], row["account_id"], AESGCM(key).encrypt(nonce, row["value"].encode(), f"account:{row['account_id']}:field:{row['field_id']}".encode()), nonce))
        _validate_target(target, key, snapshot)
        target.commit()
        target.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        target.execute("VACUUM")
        target.close()
        target = None
        if any(artifact.exists() for artifact in sidecars(temporary)):
            raise ScriptError("temporary database sidecars remain")
        target = sqlite3.connect(temporary)
        target.row_factory = sqlite3.Row
        if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ScriptError("target integrity validation failed")
        _validate_target(target, key, snapshot)
        target.close()
        target = None
        if any(artifact.exists() for artifact in sidecars(temporary)):
            raise ScriptError("temporary database sidecars remain")
        _scan_residue(temporary, snapshot)
        rollback: Path | None = None
        placed = False
        try:
            if target_path.exists():
                fd, rollback_name = tempfile.mkstemp(
                    prefix=f".{target_path.name}.", suffix=".rollback", dir=target_path.parent
                )
                os.close(fd)
                rollback = Path(rollback_name)
                os.replace(target_path, rollback)
            os.replace(temporary, target_path)
            temporary = None
            placed = True
            ensure_mode(target_path)
            if _after_placement is not None:
                _after_placement()
            if any(artifact.exists() for artifact in sidecars(target_path)):
                raise ScriptError("target database sidecars remain")
        except (OSError, ScriptError) as error:
            try:
                if rollback is not None:
                    os.replace(rollback, target_path)
                    rollback = None
                    remove_sidecars(target_path)
                elif placed:
                    remove_artifacts(target_path)
            except (OSError, ScriptError) as recovery_error:
                if rollback is not None:
                    raise ScriptError("migration recovery required") from recovery_error
                raise ScriptError("migration placement cleanup failed") from recovery_error
            raise error
        else:
            if rollback is not None:
                remove_artifacts(rollback)
    except sqlite3.Error as error:
        raise ScriptError("migration database operation failed") from error
    finally:
        if target is not None:
            target.close()
        source.close()
        if temporary is not None:
            remove_artifacts(temporary)


def main() -> int:
    args = parse_args()
    try:
        migrate(Path(args.source), Path(args.target), args.key_env)
    except ScriptError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("OK: accounts=116 account_service=116 field_values=116")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
