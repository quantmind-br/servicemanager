from __future__ import annotations

import os
import stat
import sqlite3
from collections.abc import Iterator
from typing import Protocol
from contextlib import contextmanager
from pathlib import Path
import time

from flask import Flask, current_app, g


class LegacySchemaError(RuntimeError):
    """Raised when a database requires the controlled legacy migration."""


SCHEMA = """
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_ciphertext BLOB NOT NULL,
    password_nonce BLOB NOT NULL,
    password_key_version INTEGER NOT NULL,
    password_changed_at TEXT
);
CREATE TABLE services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    rotation_days INTEGER CHECK (rotation_days IS NULL OR rotation_days BETWEEN 1 AND 3650)
);
CREATE TABLE account_service (
    account_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'nunca' CHECK (status IN ('ativo', 'nunca', 'inativo')),
    registered INTEGER NOT NULL DEFAULT 0 CHECK (registered IN (0, 1)),
    rotation_days INTEGER CHECK (rotation_days IS NULL OR rotation_days BETWEEN 1 AND 3650),
    rotation_due_at TEXT,
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
    kind TEXT NOT NULL CHECK (kind IN ('login_failure', 'reveal', 'reveal_blocked', 'audit_degraded')),
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
CREATE TABLE service_members (
    user_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('viewer', 'editor', 'service_admin')),
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, service_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);
CREATE INDEX service_members_service_id ON service_members(service_id, user_id);
CREATE TABLE webhook_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    destination_host TEXT NOT NULL,
    url_ciphertext BLOB NOT NULL,
    url_nonce BLOB NOT NULL,
    url_key_version INTEGER NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    signing_secret_ciphertext BLOB NOT NULL,
    signing_secret_nonce BLOB NOT NULL,
    signing_secret_key_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT
);
CREATE TABLE webhook_subscriptions (
    config_id INTEGER NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('login_failures', 'reveal_rate_limit', 'authorization_failure', 'audit_chain_degraded', 'user_deactivated', 'destructive_admin_action')),
    PRIMARY KEY (config_id, event_type),
    FOREIGN KEY (config_id) REFERENCES webhook_configs(id) ON DELETE CASCADE
);
CREATE TABLE webhook_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    config_id INTEGER NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('login_failures', 'reveal_rate_limit', 'authorization_failure', 'audit_chain_degraded', 'user_deactivated', 'destructive_admin_action', 'test')),
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'delivering', 'retry', 'succeeded', 'failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 5),
    next_attempt_at TEXT NOT NULL,
    lease_token TEXT,
    leased_at TEXT,
    last_status_code INTEGER,
    last_error TEXT,
    created_at TEXT NOT NULL,
    delivered_at TEXT,
    FOREIGN KEY (config_id) REFERENCES webhook_configs(id)
);
CREATE INDEX webhook_deliveries_status_next_attempt ON webhook_deliveries(status, next_attempt_at, id);
CREATE INDEX webhook_deliveries_config_created ON webhook_deliveries(config_id, created_at);
CREATE TABLE app_settings (
    key TEXT PRIMARY KEY CHECK (key IN ('rotation_enabled')),
    value TEXT NOT NULL CHECK (value IN ('0', '1'))
);
"""

def _schema_objects(conn: sqlite3.Connection, type_: str) -> dict[str, str]:
    return {
        row[0]: " ".join((row[1] or "").split())
        for row in conn.execute("SELECT name, sql FROM sqlite_master WHERE type = ?", (type_,))
        if not row[0].startswith("sqlite_")
    }


def _canonical_schema() -> tuple[dict[str, dict[str, str]], dict[str, set[str]]]:
    reference = sqlite3.connect(":memory:")
    try:
        reference.executescript(SCHEMA)
        objects = {type_: _schema_objects(reference, type_) for type_ in ("table", "index", "trigger")}
        columns = {
            table: {row[1] for row in reference.execute(f"PRAGMA table_info({table})")}
            for table in objects["table"]
        }
        return objects, columns
    finally:
        reference.close()


_CANONICAL_SCHEMA, _CANONICAL_COLUMNS = _canonical_schema()


def _user_tables(conn: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
    }


def _validate_schema_state(conn: sqlite3.Connection) -> None:
    if not _user_tables(conn):
        return
    actual_schema = {type_: _schema_objects(conn, type_) for type_ in ("table", "index", "trigger")}
    actual_columns = {
        table: {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        for table in actual_schema["table"]
    }
    if actual_schema != _CANONICAL_SCHEMA or actual_columns != _CANONICAL_COLUMNS:
        raise LegacySchemaError("legacy or incompatible database schema requires controlled migration")



def schema_is_current(conn: sqlite3.Connection) -> bool:
    """Return whether a non-empty database exactly matches the current schema."""
    try:
        _validate_schema_state(conn)
        return bool(_user_tables(conn))
    except (LegacySchemaError, sqlite3.Error):
        return False


def _enforce_mode(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
        if stat.S_IMODE(path.stat().st_mode) != mode:
            raise RuntimeError(f"could not enforce permissions for {path}")
    except OSError as error:
        raise RuntimeError(f"could not enforce permissions for {path}") from error


def enforce_database_permissions() -> None:
    """Apply required production modes to the configured SQLite database artifacts."""
    if not current_app.config["IS_PRODUCTION"]:
        return
    path = Path(current_app.config["DATABASE_PATH"])
    _enforce_mode(path.parent, 0o700)
    for artifact in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        if artifact.exists():
            _enforce_mode(artifact, 0o600)


_SQLITE_BUSY = 5
_SQLITE_LOCKED = 6


class _SqlExecutor(Protocol):
    def execute(self, statement: str, /) -> object: ...


def _enable_wal(conn: _SqlExecutor, *, attempts: int = 50, delay: float = 0.1) -> None:
    """Switch to WAL, retrying only on a peer's transient write lock during concurrent cold boot."""
    for remaining in range(attempts, 0, -1):
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            return
        except sqlite3.OperationalError as error:
            if getattr(error, "sqlite_errorcode", None) not in (_SQLITE_BUSY, _SQLITE_LOCKED) or remaining == 1:
                raise
            time.sleep(delay)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        path = Path(current_app.config["DATABASE_PATH"])
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db

def inserted_id(cursor: sqlite3.Cursor) -> int:
    """Return SQLite's generated row id, failing if no row was inserted."""
    value = cursor.lastrowid
    if value is None:
        raise RuntimeError("database insert did not produce a row id")
    return value


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Execute a write transaction that acquires SQLite's writer lock upfront."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.rollback()
        raise
    else:
        conn.commit()


def close_db(_: BaseException | None = None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def _create_schema(conn: sqlite3.Connection) -> None:
    statement = ""
    for line in SCHEMA.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            conn.execute(statement)
            statement = ""
    if statement.strip():
        raise RuntimeError("incomplete schema statement")


def init_db() -> None:
    Path(current_app.config["DATABASE_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    enforce_database_permissions()
    conn = get_db()
    _enable_wal(conn)
    with transaction(conn):
        if not _user_tables(conn):
            _create_schema(conn)
    _validate_schema_state(conn)
    enforce_database_permissions()


def init_app(app: Flask) -> None:
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
