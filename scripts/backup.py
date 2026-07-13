from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from datetime import UTC, datetime
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from _secure_db import ScriptError, ensure_mode, load_key, open_source_read_only, remove_artifacts, sidecars, validate_restorable_database
from service_manager.audit import verify_audit_chain_with_key

MAGIC = b"SMBK"
VERSION = b"\x01"
AAD = b"service-manager-backup:v1"
SCHEDULED_BACKUP_RE = re.compile(r"^service-manager-(\d{8}T\d{6}Z)\.smbk$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Authenticated encrypted SQLite backup")
    parser.add_argument("--source", default=os.environ.get("DATABASE_PATH", "/data/service-manager.db"))
    parser.add_argument("--target")
    parser.add_argument("--backups-dir", default="/backups")
    parser.add_argument("--key-env", default="BACKUP_KEY_V1")
    return parser.parse_args()


def _checkpoint_source(source_path: Path) -> None:
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(source_path)
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.Error as error:
        raise ScriptError("source database checkpoint failed") from error
    finally:
        if connection is not None:
            connection.close()


def _snapshot(source_path: Path, destination_path: Path) -> None:
    _checkpoint_source(source_path)
    source = open_source_read_only(source_path)
    destination: sqlite3.Connection | None = None
    try:
        destination = sqlite3.connect(destination_path)
        destination.row_factory = sqlite3.Row
        source.backup(destination)
        if destination.execute("PRAGMA journal_mode = DELETE").fetchone()[0].lower() != "delete":
            raise ScriptError("backup snapshot journal normalization failed")
        validate_restorable_database(destination)
        tables = {row["name"] for row in destination.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "audit_events" in tables and not verify_audit_chain_with_key(destination, load_key("AUDIT_KEY_V1")):
            raise ScriptError("backup snapshot audit chain verification failed")
    except ScriptError:
        raise
    except sqlite3.Error as error:
        raise ScriptError("backup snapshot failed") from error
    finally:
        if destination is not None:
            destination.close()
        source.close()



def scheduled_backup_path(backups_directory: Path, now: datetime | None = None) -> Path:
    timestamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    return backups_directory / f"service-manager-{timestamp}.smbk"


def retain_daily_backups(backups_directory: Path, keep: int = 7) -> None:
    """Keep only the seven newest scheduler-created backups, preserving unrelated files."""
    dated_backups = sorted(
        (path for path in backups_directory.iterdir() if path.is_file() and SCHEDULED_BACKUP_RE.fullmatch(path.name)),
        key=lambda path: path.name,
        reverse=True,
    )
    for obsolete in dated_backups[keep:]:
        obsolete.unlink()


def backup_scheduled(source_path: Path, backups_directory: Path, key_env: str) -> Path:
    if not backups_directory.is_dir():
        raise ScriptError("backup directory is unavailable")
    target_path = scheduled_backup_path(backups_directory)
    backup(source_path, target_path, key_env)
    retain_daily_backups(backups_directory)
    return target_path

def backup(source_path: Path, target_path: Path, key_env: str) -> None:
    if source_path.resolve() == target_path.resolve() or target_path.suffix != ".smbk" or not target_path.parent.is_dir():
        raise ScriptError("backup paths are invalid")
    key = load_key(key_env)
    snapshot: Path | None = None
    output: Path | None = None
    try:
        fd, name = tempfile.mkstemp(prefix=".backup-snapshot.", suffix=".db", dir=target_path.parent)
        os.close(fd)
        snapshot = Path(name)
        ensure_mode(snapshot)
        _snapshot(source_path, snapshot)
        nonce = os.urandom(12)
        encrypted = AESGCM(key).encrypt(nonce, snapshot.read_bytes(), AAD)
        fd, name = tempfile.mkstemp(prefix=f".{target_path.name}.", suffix=".tmp", dir=target_path.parent)
        os.close(fd)
        output = Path(name)
        output.write_bytes(MAGIC + VERSION + nonce + encrypted)
        ensure_mode(output)
        os.replace(output, target_path)
        output = None
        ensure_mode(target_path)
    finally:
        remove_artifacts(snapshot, output)


def main() -> int:
    args = parse_args()
    try:
        if args.target:
            backup(Path(args.source), Path(args.target), args.key_env)
        else:
            backup_scheduled(Path(args.source), Path(args.backups_dir), args.key_env)
    except ScriptError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("OK: encrypted backup created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
