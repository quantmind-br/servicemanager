from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from collections.abc import Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from _secure_db import ScriptError, ensure_mode, load_key, remove_artifacts, require_offline_target, sidecars, validate_restorable_database
from backup import AAD, MAGIC, VERSION
from service_manager.audit import verify_audit_chain_with_key


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Authenticated encrypted SQLite restore")
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--key-env", required=True)
    return parser.parse_args()


def _validate(path: Path) -> None:
    try:
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            validate_restorable_database(conn, secure_only=True)
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "audit_events" in tables and not verify_audit_chain_with_key(conn, load_key("AUDIT_KEY_V1")):
                raise ScriptError("restored database audit chain verification failed")
        finally:
            conn.close()
    except sqlite3.Error as error:
        raise ScriptError("restored database validation failed") from error


def _post_placement_validate(path: Path, after_validation: Callable[[], None] | None = None) -> None:
    _validate(path)
    if after_validation is not None:
        after_validation()


def restore(
    source_path: Path,
    target_path: Path,
    key_env: str,
    _after_post_placement_validation: Callable[[], None] | None = None,
) -> None:
    if target_path.suffix != ".db" or not source_path.is_file() or not target_path.parent.is_dir():
        raise ScriptError("restore paths are invalid")
    require_offline_target(target_path)
    key = load_key(key_env)
    temporary: Path | None = None
    rollback: Path | None = None
    placed = False
    recovery_required = False
    try:
        payload = source_path.read_bytes()
        if len(payload) < 33 or payload[:4] != MAGIC or payload[4:5] != VERSION:
            raise ScriptError("backup format is invalid")
        try:
            plaintext = AESGCM(key).decrypt(payload[5:17], payload[17:], AAD)
        except InvalidTag as error:
            raise ScriptError("backup authentication failed") from error
        fd, name = tempfile.mkstemp(prefix=f".{target_path.name}.", suffix=".tmp", dir=target_path.parent)
        os.close(fd)
        temporary = Path(name)
        temporary.write_bytes(plaintext)
        ensure_mode(temporary)
        _validate(temporary)
        if any(artifact.exists() for artifact in sidecars(temporary)):
            raise ScriptError("temporary database sidecars remain")
        if target_path.exists():
            fd, name = tempfile.mkstemp(prefix=f".{target_path.name}.", suffix=".rollback", dir=target_path.parent)
            os.close(fd)
            rollback = Path(name)
            os.replace(target_path, rollback)
        os.replace(temporary, target_path)
        temporary = None
        placed = True
        ensure_mode(target_path)
        _post_placement_validate(target_path, _after_post_placement_validation)
        if any(artifact.exists() for artifact in sidecars(target_path)):
            raise ScriptError("target database sidecars remain")
        if rollback is not None:
            remove_artifacts(rollback)
            rollback = None
    except (OSError, ScriptError) as error:
        try:
            if placed:
                remove_artifacts(target_path)
            if rollback is not None:
                os.replace(rollback, target_path)
                rollback = None
        except (OSError, ScriptError) as cleanup_error:
            if rollback is not None:
                recovery_required = True
                raise ScriptError("restore recovery required") from cleanup_error
            raise ScriptError("restore rollback cleanup failed") from cleanup_error
        raise error
    finally:
        if temporary is not None:
            remove_artifacts(temporary)
        if rollback is not None and not recovery_required:
            remove_artifacts(rollback)


def main() -> int:
    args = parse_args()
    try:
        restore(Path(args.source), Path(args.target), args.key_env)
    except ScriptError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("OK: encrypted backup restored")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
