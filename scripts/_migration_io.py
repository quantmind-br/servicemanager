"""Schema-neutral atomic snapshot/copy/place helpers shared by the offline
migration tools.

These helpers intentionally know nothing about any specific schema: callers
pass the schema SQL and column tuples they need. This lets the one-time
pre-feature -> new-canonical cutover and the frozen historical migration
utilities share the same audited atomic mechanics without importing each other.
"""
from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path

from _secure_db import (
    ScriptError,
    ensure_mode,
    remove_artifacts,
    sidecars,
)


def _normalize_schema_sql(sql: str) -> str:
    return " ".join(sql.split())


def frozen_schema_objects(schema_sql: str) -> tuple[dict[str, dict[str, str]], dict[str, set[str]]]:
    """Return normalized objects and columns for an arbitrary schema string."""
    reference = sqlite3.connect(":memory:")
    try:
        reference.executescript(schema_sql)
        objects = {
            kind: {
                row[0]: _normalize_schema_sql(row[1])
                for row in reference.execute("SELECT name, sql FROM sqlite_master WHERE type = ?", (kind,))
                if row[1] and not row[0].startswith("sqlite_")
            }
            for kind in ("table", "index", "trigger")
        }
        columns = {
            table: {row[1] for row in reference.execute(f"PRAGMA table_info({table})")}
            for table in objects["table"]
        }
        return objects, columns
    finally:
        reference.close()


def normalized_objects(conn: sqlite3.Connection, kind: str) -> dict[str, str]:
    return {
        row[0]: _normalize_schema_sql(row[1])
        for row in conn.execute("SELECT name, sql FROM sqlite_master WHERE type = ? AND name NOT LIKE 'sqlite_%'", (kind,))
        if row[1]
    }


def structural_schema_valid(
    conn: sqlite3.Connection,
    expected_objects: dict[str, dict[str, str]],
    expected_columns: dict[str, set[str]],
) -> None:
    """Validate that a connection matches an explicitly supplied schema shape."""
    try:
        for kind, expected in expected_objects.items():
            if normalized_objects(conn, kind) != expected:
                raise ScriptError("target schema is incompatible")
        for table, expected in expected_columns.items():
            if {row[1] for row in conn.execute(f"PRAGMA table_info({table})")} != expected:
                raise ScriptError("target schema is incompatible")
    except sqlite3.Error as error:
        raise ScriptError("target schema is incompatible") from error


def _create_schema(conn: sqlite3.Connection, schema_sql: str) -> None:
    statement = ""
    for line in schema_sql.splitlines(keepends=True):
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
