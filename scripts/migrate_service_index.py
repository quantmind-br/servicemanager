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
from migrate_auth_schema import _place, _snapshot
from service_manager.audit import verify_audit_chain_with_key

# Tables whose row contents must be preserved byte-for-byte by the migration.
_ROW_TABLES = (
    "accounts", "services", "account_service", "custom_fields", "field_values",
    "users", "security_events", "audit_events",
)


def _normalized_objects(conn: sqlite3.Connection, kind: str) -> dict[str, str]:
    return {
        row[0]: _normalize_schema_sql(row[1])
        for row in conn.execute("SELECT name, sql FROM sqlite_master WHERE type = ? AND name NOT LIKE 'sqlite_%'", (kind,))
        if row[1]
    }


def _expected_old_objects() -> dict[str, dict[str, str]]:
    expected = {kind: dict(objects) for kind, objects in copy.deepcopy(CANONICAL_SECURE_SCHEMA).items()}
    del expected["index"]["account_service_service_id"]
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


def _row_counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in _ROW_TABLES}


def _validate_destination(conn: sqlite3.Connection, expected_counts: dict[str, int], audit_key: bytes) -> None:
    secure_schema_structure_valid(conn)
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
