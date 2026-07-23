from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _migration_io import (
    _place,
    _snapshot,
    frozen_schema_objects,
    structural_schema_valid,
)
from _secure_db import (
    ScriptError,
    ensure_mode,
    load_key,
    remove_artifacts,
    require_offline_target,
    sidecars,
)
from service_manager.audit import verify_audit_chain_with_key
from service_manager.db import SCHEMA as TARGET_SCHEMA
from service_preferences_schema import PRE_SERVICE_PREFERENCES_SCHEMA

_SOURCE_OBJECTS, _SOURCE_COLUMNS = frozen_schema_objects(PRE_SERVICE_PREFERENCES_SCHEMA)
_TARGET_OBJECTS, _TARGET_COLUMNS = frozen_schema_objects(TARGET_SCHEMA)
_ROW_TABLES = tuple(sorted(_SOURCE_COLUMNS))


def _validate_source(conn: sqlite3.Connection, audit_key: bytes) -> None:
    try:
        structural_schema_valid(conn, _SOURCE_OBJECTS, _SOURCE_COLUMNS)
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ScriptError("source integrity validation failed")
        if list(conn.execute("PRAGMA foreign_key_check")):
            raise ScriptError("source foreign-key validation failed")
        if not verify_audit_chain_with_key(conn, audit_key):
            raise ScriptError("source audit chain validation failed")
    except sqlite3.Error as error:
        raise ScriptError("source schema is incompatible") from error


def _table_rows(conn: sqlite3.Connection) -> dict[str, list[tuple[object, ...]]]:
    return {
        table: [tuple(row) for row in conn.execute(f'SELECT * FROM "{table}" ORDER BY rowid')]
        for table in _ROW_TABLES
    }


def _sequences(conn: sqlite3.Connection) -> list[tuple[object, ...]]:
    return [tuple(row) for row in conn.execute("SELECT name, seq FROM sqlite_sequence ORDER BY name")]


def _validate_destination(
    conn: sqlite3.Connection,
    expected_rows: dict[str, list[tuple[object, ...]]],
    expected_sequences: list[tuple[object, ...]],
    audit_key: bytes,
) -> None:
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
        if _table_rows(conn) != expected_rows:
            raise ScriptError("target rows do not match the source")
        if _sequences(conn) != expected_sequences:
            raise ScriptError("target sequences do not match the source")
        if conn.execute("SELECT COUNT(*) FROM user_service_preferences").fetchone()[0]:
            raise ScriptError("target service preferences initialization failed")
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
        source.execute("PRAGMA foreign_keys = ON")
        _validate_source(source, audit_key)
        expected_rows = _table_rows(source)
        expected_sequences = _sequences(source)
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
        destination.execute(
            "CREATE TABLE user_service_preferences (\n"
            "    user_id INTEGER NOT NULL,\n"
            "    service_id INTEGER NOT NULL,\n"
            "    position INTEGER NOT NULL CHECK (position >= 0),\n"
            "    is_initial INTEGER NOT NULL DEFAULT 0 CHECK (is_initial IN (0, 1)),\n"
            "    PRIMARY KEY (user_id, service_id),\n"
            "    UNIQUE (user_id, position),\n"
            "    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,\n"
            "    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE\n"
            ")"
        )
        destination.execute(
            "CREATE UNIQUE INDEX user_service_preferences_one_initial "
            "ON user_service_preferences(user_id) WHERE is_initial = 1"
        )
        _validate_destination(destination, expected_rows, expected_sequences, audit_key)
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
        _validate_destination(destination, expected_rows, expected_sequences, audit_key)
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
    parser = argparse.ArgumentParser(description="Offline service preferences schema migration")
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--audit-key-env", default="AUDIT_KEY_V1")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        migrate(Path(args.source), Path(args.target), audit_key_env=args.audit_key_env)
    except ScriptError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("OK: service preferences schema migrated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
