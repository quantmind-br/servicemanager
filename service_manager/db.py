from __future__ import annotations

import os
import stat
import sqlite3
from collections.abc import Iterator
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
    PRIMARY KEY (account_id, service_id),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);
CREATE TABLE custom_fields (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    is_secret INTEGER NOT NULL DEFAULT 1 CHECK (is_secret IN (0, 1)),
    UNIQUE (service_id, name),
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);
CREATE TABLE field_values (
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
);
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'operador')),
    is_active INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0, 1)),
    must_change_password INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0, 1)),
    totp_secret_ciphertext BLOB,
    totp_nonce BLOB,
    totp_key_version INTEGER,
    totp_confirmed_at TEXT,
    last_totp_step INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    password_changed_at TEXT,
    session_version INTEGER NOT NULL DEFAULT 0 CHECK (session_version >= 0),
    pending_totp_secret_ciphertext BLOB,
    pending_totp_nonce BLOB,
    pending_totp_key_version INTEGER,
    totp_enrollment_shown_at TEXT,
    CHECK (
        (totp_secret_ciphertext IS NULL AND totp_nonce IS NULL AND totp_key_version IS NULL)
        OR
        (totp_secret_ciphertext IS NOT NULL AND totp_nonce IS NOT NULL AND totp_key_version IS NOT NULL)
    ),
    CHECK (
        (pending_totp_secret_ciphertext IS NULL AND pending_totp_nonce IS NULL AND pending_totp_key_version IS NULL)
        OR
        (pending_totp_secret_ciphertext IS NOT NULL AND pending_totp_nonce IS NOT NULL AND pending_totp_key_version IS NOT NULL)
    )
);
CREATE TABLE recovery_codes (
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    used_at TEXT,
    PRIMARY KEY (user_id, code_hash),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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
CREATE TABLE bootstrap_tokens (
    token_hash BLOB NOT NULL UNIQUE,
    user_id INTEGER NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX bootstrap_tokens_one_active
    ON bootstrap_tokens((1)) WHERE consumed_at IS NULL;
CREATE TRIGGER field_values_require_secret_representation_insert
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
END;
CREATE TRIGGER custom_fields_preserve_value_representation
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
END;
CREATE TRIGGER field_values_require_secret_representation_update
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
END;
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


def _enable_wal(conn: sqlite3.Connection, *, attempts: int = 50, delay: float = 0.1) -> None:
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
        path.parent.mkdir(parents=True, exist_ok=True)
        enforce_database_permissions()
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        _enable_wal(conn)
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
        enforce_database_permissions()
    return g.db


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
    conn = get_db()
    with transaction(conn):
        if not _user_tables(conn):
            _create_schema(conn)
    _validate_schema_state(conn)
    enforce_database_permissions()


def init_app(app: Flask) -> None:
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
