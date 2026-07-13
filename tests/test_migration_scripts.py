from __future__ import annotations

import argparse
import base64
import hashlib
import os
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from app import create_app
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
MIGRATE = ROOT / "scripts" / "migrate_legacy_db.py"
VERIFY = ROOT / "scripts" / "verify_migrated_db.py"
BACKUP = ROOT / "scripts" / "backup.py"
RESTORE = ROOT / "scripts" / "restore_backup.py"
DATA_KEY = base64.b64encode(b"d" * 32).decode("ascii")
BACKUP_KEY = base64.b64encode(b"b" * 32).decode("ascii")


def _run(script: Path, *args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=ROOT,
        env={**os.environ, **env},
        text=True,
        capture_output=True,
        check=False,
    )


def _legacy_source(path: Path, *, accounts: int = 116) -> list[str]:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE accounts (id INTEGER PRIMARY KEY, email TEXT NOT NULL, password TEXT NOT NULL);
        CREATE TABLE services (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
        CREATE TABLE account_service (account_id INTEGER NOT NULL, service_id INTEGER NOT NULL, status TEXT NOT NULL);
        CREATE TABLE custom_fields (id INTEGER PRIMARY KEY, service_id INTEGER NOT NULL, name TEXT NOT NULL);
        CREATE TABLE field_values (field_id INTEGER NOT NULL, account_id INTEGER NOT NULL, value TEXT NOT NULL);
        CREATE TABLE credentials_backup (id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL, snapshot TEXT NOT NULL);
        """
    )
    conn.execute("INSERT INTO services (id, name) VALUES (17, 'Synthetic mail')")
    conn.execute("INSERT INTO services (id, name) VALUES (18, 'Synthetic storage')")
    conn.execute("INSERT INTO custom_fields (id, service_id, name) VALUES (29, 17, 'Synthetic token')")
    conn.execute("INSERT INTO custom_fields (id, service_id, name) VALUES (30, 18, 'Synthetic key')")
    plaintexts: list[str] = []
    for index in range(1, accounts + 1):
        password = "" if index == 1 else f"migration-password-{index}-only"
        value = "" if index == 1 else f"migration-field-{index}-only"
        service_id, field_id = (17, 29) if index % 2 else (18, 30)
        plaintexts.extend((password, value))
        conn.execute("INSERT INTO accounts (id, email, password) VALUES (?, ?, ?)", (1000 + index, f"synthetic-{index}@example.test", password))
        conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')", (1000 + index, service_id))
        conn.execute("INSERT INTO field_values (field_id, account_id, value) VALUES (?, ?, ?)", (field_id, 1000 + index, value))
        conn.execute("INSERT INTO credentials_backup (id, account_id, snapshot) VALUES (?, ?, 'legacy')", (index, 1000 + index))
    conn.commit()
    conn.close()
    return plaintexts


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _artifact_bytes(path: Path) -> bytes:
    return b"".join(part.read_bytes() for part in (path, Path(f"{path}-wal"), Path(f"{path}-shm")) if part.exists())


def test_migration_creates_secure_id_preserving_target_and_handles_empty_values(tmp_path: Path):
    source = tmp_path / "synthetic-legacy.db"
    target = tmp_path / "migrated.db"
    plaintexts = _legacy_source(source)
    source_digest = hashlib.sha256(source.read_bytes()).digest()

    result = _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert result.returncode == 0, result.stderr
    assert "accounts=116" in result.stdout
    assert "migration-password-2-only" not in result.stdout
    assert source_digest == hashlib.sha256(source.read_bytes()).digest()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    conn = sqlite3.connect(target)
    assert conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 116
    assert conn.execute("SELECT COUNT(*) FROM account_service").fetchone()[0] == 116
    assert conn.execute("SELECT COUNT(*) FROM field_values").fetchone()[0] == 116
    assert conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'credentials_backup'").fetchone() is None
    assert "password" not in _table_columns(conn, "accounts")
    assert "value" not in _table_columns(conn, "field_values")
    assert conn.execute("SELECT DISTINCT is_secret FROM custom_fields").fetchall() == [(1,)]
    nonces = [row[0] for row in conn.execute("SELECT password_nonce FROM accounts")] + [row[0] for row in conn.execute("SELECT value_nonce FROM field_values")]
    assert len(nonces) == len(set(nonces)) == 232
    key = base64.b64decode(DATA_KEY)
    account = conn.execute("SELECT id, password_ciphertext, password_nonce FROM accounts WHERE id = 1001").fetchone()
    assert AESGCM(key).decrypt(account[2], account[1], b"account:1001:password") == b""
    field = conn.execute("SELECT value_ciphertext, value_nonce FROM field_values WHERE field_id = 29 AND account_id = 1001").fetchone()
    assert AESGCM(key).decrypt(field[1], field[0], b"account:1001:field:29") == b""
    conn.close()
    target_bytes = _artifact_bytes(target)
    assert all(not value or value.encode() not in target_bytes for value in plaintexts)


def test_migration_failure_keeps_existing_target_and_leaves_no_temporary_database(tmp_path: Path):
    source = tmp_path / "invalid-count.db"
    target = tmp_path / "target.db"
    _legacy_source(source, accounts=115)
    target.write_bytes(b"sentinel-target")

    result = _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert result.returncode != 0
    assert target.read_bytes() == b"sentinel-target"
    assert not list(tmp_path.glob(".target.db.*.tmp"))
    assert "migration-password" not in result.stdout + result.stderr


def test_migration_rejects_invalid_key_without_replacing_target(tmp_path: Path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    target.write_bytes(b"sentinel-target")

    result = _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": "not-base64"})

    assert result.returncode != 0
    assert target.read_bytes() == b"sentinel-target"


def test_migration_rejects_incompatible_source_schema_without_replacing_target(tmp_path: Path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    conn = sqlite3.connect(source)
    conn.execute("DROP TABLE credentials_backup")
    conn.commit()
    conn.close()
    target.write_bytes(b"sentinel-target")

    result = _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert result.returncode != 0
    assert target.read_bytes() == b"sentinel-target"
    assert not list(tmp_path.glob(".target.db.*.tmp"))


def test_independent_verifier_detects_corruption_nonce_and_permission_failures_without_secrets(tmp_path: Path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0

    clean = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})
    assert clean.returncode == 0, clean.stderr
    target_digest = hashlib.sha256(target.read_bytes()).digest()
    assert _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    assert hashlib.sha256(target.read_bytes()).digest() == target_digest
    os.chmod(target, 0o644)
    permission_failure = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})
    assert permission_failure.returncode != 0
    assert "migration-password-2-only" not in permission_failure.stdout + permission_failure.stderr
    os.chmod(target, 0o600)
    conn = sqlite3.connect(target)
    nonce = conn.execute("SELECT password_nonce FROM accounts WHERE id = 1001").fetchone()[0]
    conn.execute("UPDATE accounts SET password_nonce = ? WHERE id = 1002", (nonce,))
    conn.commit()
    conn.close()
    nonce_failure = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})
    assert nonce_failure.returncode != 0
    assert "migration-password-2-only" not in nonce_failure.stdout + nonce_failure.stderr


def test_independent_verifier_detects_plaintext_residue_without_printing_it(tmp_path: Path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    conn = sqlite3.connect(target)
    conn.execute("CREATE TABLE accidental_residue (contents TEXT NOT NULL)")
    conn.execute("INSERT INTO accidental_residue (contents) VALUES ('migration-password-2-only')")
    conn.commit()
    conn.close()

    result = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert result.returncode != 0
    assert "migration-password-2-only" not in result.stdout + result.stderr


def test_authenticated_backup_round_trip_rejects_wrong_key_tampering_and_invalid_header(tmp_path: Path):
    source = tmp_path / "source.db"
    secure = tmp_path / "secure.db"
    encrypted = tmp_path / "source.smbk"
    restored = tmp_path / "restored.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(secure), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    secure_digest = hashlib.sha256(secure.read_bytes()).digest()
    backup_env = {"TEST_BACKUP_KEY": BACKUP_KEY, "AUDIT_KEY_V1": DATA_KEY}

    backed_up = _run(BACKUP, "--source", str(secure), "--target", str(encrypted), "--key-env", "TEST_BACKUP_KEY", env=backup_env)
    assert backed_up.returncode == 0, backed_up.stderr
    assert encrypted.read_bytes()[:5] == b"SMBK\x01"
    assert stat.S_IMODE(encrypted.stat().st_mode) == 0o600
    assert secure_digest == hashlib.sha256(secure.read_bytes()).digest()
    restored_ok = _run(RESTORE, "--source", str(encrypted), "--target", str(restored), "--key-env", "TEST_BACKUP_KEY", env=backup_env)
    assert restored_ok.returncode == 0, restored_ok.stderr
    assert sqlite3.connect(restored).execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert stat.S_IMODE(restored.stat().st_mode) == 0o600

    wrong_key = _run(RESTORE, "--source", str(encrypted), "--target", str(tmp_path / "wrong.db"), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": DATA_KEY, "AUDIT_KEY_V1": DATA_KEY})
    assert wrong_key.returncode != 0
    corrupted = tmp_path / "corrupted.smbk"
    corrupted.write_bytes(encrypted.read_bytes()[:-1] + bytes([encrypted.read_bytes()[-1] ^ 0xFF]))
    assert _run(RESTORE, "--source", str(corrupted), "--target", str(tmp_path / "corrupted.db"), "--key-env", "TEST_BACKUP_KEY", env=backup_env).returncode != 0
    invalid_header = tmp_path / "invalid.smbk"
    invalid_header.write_bytes(b"NOPE\x02" + encrypted.read_bytes()[5:])
    assert _run(RESTORE, "--source", str(invalid_header), "--target", str(tmp_path / "invalid.db"), "--key-env", "TEST_BACKUP_KEY", env=backup_env).returncode != 0



def test_backup_refuses_a_secure_snapshot_with_a_broken_audit_chain(tmp_path: Path):
    source = tmp_path / "source.db"
    secure = tmp_path / "secure.db"
    valid_backup = tmp_path / "valid.smbk"
    rejected_backup = tmp_path / "rejected.smbk"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(secure), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0

    app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(secure),
            "DATA_KEY_V1": DATA_KEY,
            "AUDIT_KEY_V1": DATA_KEY,
            "SECRET_KEY": "backup-audit-test-key",
        }
    )
    from service_manager.audit import append_audit_event
    from service_manager.db import get_db as app_get_db, transaction as app_transaction
    with app.app_context():
        conn = app_get_db()
        with app_transaction(conn):
            append_audit_event(conn, action="backup.test", target_type="test")

    env = {"TEST_BACKUP_KEY": BACKUP_KEY, "AUDIT_KEY_V1": DATA_KEY}
    assert _run(BACKUP, "--source", str(secure), "--target", str(valid_backup), "--key-env", "TEST_BACKUP_KEY", env=env).returncode == 0
    with app.app_context():
        conn = app_get_db()
        conn.execute("DROP TRIGGER audit_events_no_update")
        conn.execute("UPDATE audit_events SET action='tampered' WHERE id=1")
        conn.commit()
    rejected = _run(BACKUP, "--source", str(secure), "--target", str(rejected_backup), "--key-env", "TEST_BACKUP_KEY", env=env)
    assert rejected.returncode != 0
    assert not rejected_backup.exists()

def _sidecars(path: Path) -> tuple[Path, Path]:
    return Path(f"{path}-wal"), Path(f"{path}-shm")


def test_migration_rejects_offline_target_sidecars_and_removes_all_temp_sidecars(tmp_path: Path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    target.write_bytes(b"sentinel-target")
    wal, shm = _sidecars(target)
    wal.write_bytes(b"stale-wal")
    result = _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})
    assert result.returncode != 0
    assert target.read_bytes() == b"sentinel-target"
    assert wal.exists()
    assert not shm.exists()
    assert "migration-password-2-only" not in result.stdout + result.stderr
    wal.unlink()
    shm.write_bytes(b"stale-shm")
    result = _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})
    assert result.returncode != 0
    assert target.read_bytes() == b"sentinel-target"
    assert shm.exists()
    shm.unlink()
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    assert not any(tmp_path.glob(".target.db.*.tmp*"))
    assert not any(path.exists() for path in _sidecars(target))


def test_verifier_rejects_complete_equivalence_and_exact_schema_tampering(tmp_path: Path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    conn = sqlite3.connect(target)
    conn.execute("UPDATE account_service SET status = 'inativo' WHERE account_id = 1001")
    conn.commit()
    conn.close()
    result = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})
    assert result.returncode != 0
    assert "migration-password-2-only" not in result.stdout + result.stderr
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    conn = sqlite3.connect(target)
    conn.execute("DROP TRIGGER audit_events_no_update")
    conn.commit()
    conn.close()
    assert _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode != 0


def test_restore_rejects_stale_sidecars_and_authenticated_wrong_schema_without_replacing_target(tmp_path: Path):
    source = tmp_path / "source.db"
    encrypted = tmp_path / "source.smbk"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(BACKUP, "--source", str(source), "--target", str(encrypted), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY}).returncode == 0
    target.write_bytes(b"sentinel-target")
    wal, shm = _sidecars(target)
    wal.write_bytes(b"stale-wal")
    result = _run(RESTORE, "--source", str(encrypted), "--target", str(target), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY})
    assert result.returncode != 0
    assert target.read_bytes() == b"sentinel-target"
    assert wal.exists()
    wal.unlink()
    empty = tmp_path / "empty.db"
    sqlite3.connect(empty).close()
    nonce = b"n" * 12
    invalid_backup = tmp_path / "empty.smbk"
    invalid_backup.write_bytes(b"SMBK\x01" + nonce + AESGCM(base64.b64decode(BACKUP_KEY)).encrypt(nonce, empty.read_bytes(), b"service-manager-backup:v1"))
    result = _run(RESTORE, "--source", str(invalid_backup), "--target", str(target), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY})
    assert result.returncode != 0
    assert target.read_bytes() == b"sentinel-target"
    assert not any(tmp_path.glob(".target.db.*.tmp*"))


def test_migration_schema_failure_is_atomic_and_cleans_main_and_sidecars(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    migration = _script_module("migrate_legacy_db")
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    target.write_bytes(b"sentinel-target")
    monkeypatch.setenv("TEST_DATA_KEY", DATA_KEY)
    monkeypatch.setattr(migration, "_after_schema_created", lambda: (_ for _ in ()).throw(migration.ScriptError("synthetic failure")))

    with pytest.raises(migration.ScriptError):
        migration.migrate(source, target, "TEST_DATA_KEY")

    assert target.read_bytes() == b"sentinel-target"
    assert not any(tmp_path.glob(".target.db.*.tmp*"))


def test_restore_post_placement_validation_failure_restores_existing_target_and_cleans_rollback_artifacts(tmp_path: Path):
    restore = _script_module("restore_backup")
    source = tmp_path / "source.db"
    encrypted = tmp_path / "source.smbk"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(BACKUP, "--source", str(source), "--target", str(encrypted), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY}).returncode == 0
    sentinel = b"old-target-sentinel"
    target.write_bytes(sentinel)

    with pytest.raises(restore.ScriptError):
        restore.restore(
            encrypted,
            target,
            "TEST_BACKUP_KEY",
            _after_post_placement_validation=lambda: (_ for _ in ()).throw(restore.ScriptError("synthetic failure")),
        )

    assert target.read_bytes() == sentinel
    assert not any(tmp_path.glob(".target.db.*.tmp*"))
    assert not any(tmp_path.glob(".target.db.*.rollback*"))
    assert not any(path.exists() for path in _sidecars(target))


def test_restore_success_removes_rollback_artifacts_after_replacing_existing_target(tmp_path: Path):
    source = tmp_path / "source.db"
    secure = tmp_path / "secure.db"
    encrypted = tmp_path / "source.smbk"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(secure), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    backup_env = {"TEST_BACKUP_KEY": BACKUP_KEY, "AUDIT_KEY_V1": DATA_KEY}
    assert _run(BACKUP, "--source", str(secure), "--target", str(encrypted), "--key-env", "TEST_BACKUP_KEY", env=backup_env).returncode == 0
    target.write_bytes(b"old-target-sentinel")

    result = _run(RESTORE, "--source", str(encrypted), "--target", str(target), "--key-env", "TEST_BACKUP_KEY", env=backup_env)

    assert result.returncode == 0, result.stderr
    assert sqlite3.connect(target).execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert not any(tmp_path.glob(".target.db.*.tmp*"))
    assert not any(tmp_path.glob(".target.db.*.rollback*"))
    assert not any(path.exists() for path in _sidecars(target))


def test_migration_checkpoint_vacuums_then_revalidates_with_a_fresh_connection_before_replacement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import importlib

    scripts_dir = str(ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    migration = importlib.import_module("migrate_legacy_db")
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    statements: list[tuple[object, str]] = []
    real_connect = migration.sqlite3.connect

    class RecordingConnection:
        def __init__(self, connection: sqlite3.Connection):
            object.__setattr__(self, "connection", connection)

        def __getattr__(self, name: str):
            return getattr(self.connection, name)

        def __setattr__(self, name: str, value: object) -> None:
            setattr(self.connection, name, value)

        def execute(self, statement: str, *args: object, **kwargs: object):
            statements.append((self, statement))
            return self.connection.execute(statement, *args, **kwargs)

    def recording_connect(*args: object, **kwargs: object) -> RecordingConnection:
        return RecordingConnection(real_connect(*args, **kwargs))

    validations: list[object] = []
    real_validate = migration._validate_target

    def recording_validate(connection: object, key: bytes, snapshot: tuple[list[sqlite3.Row], ...]) -> None:
        validations.append(connection)
        real_validate(connection, key, snapshot)

    monkeypatch.setattr(migration.sqlite3, "connect", recording_connect)
    monkeypatch.setattr(migration, "_validate_target", recording_validate)
    monkeypatch.setenv("TEST_DATA_KEY", DATA_KEY)

    migration.migrate(source, target, "TEST_DATA_KEY")

    assert len(validations) == 2
    assert validations[0] is not validations[1]
    validation_indices = [index for index, (connection, statement) in enumerate(statements) if connection is validations[1] and statement == "PRAGMA integrity_check"]
    checkpoint_index = next(index for index, (_, statement) in enumerate(statements) if statement == "PRAGMA wal_checkpoint(TRUNCATE)")
    vacuum_index = next(index for index, (_, statement) in enumerate(statements) if statement == "VACUUM")
    assert checkpoint_index < vacuum_index < validation_indices[0]


def test_restore_rejects_stale_shm_without_replacing_sentinel(tmp_path: Path):
    source = tmp_path / "source.db"
    encrypted = tmp_path / "source.smbk"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(BACKUP, "--source", str(source), "--target", str(encrypted), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY}).returncode == 0
    sentinel = b"sentinel-target"
    target.write_bytes(sentinel)
    _, shm = _sidecars(target)
    shm.write_bytes(b"stale-shm")
    result = _run(RESTORE, "--source", str(encrypted), "--target", str(target), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY})
    assert result.returncode != 0
    assert target.read_bytes() == sentinel
    assert shm.exists()
    assert "migration-password-2-only" not in result.stdout + result.stderr


def test_backup_cleanup_failure_is_fatal_and_removes_snapshot_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import importlib

    scripts_dir = str(ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    backup_module = importlib.import_module("backup")
    source = tmp_path / "source.db"
    encrypted = tmp_path / "source.smbk"
    _legacy_source(source)
    monkeypatch.setenv("TEST_BACKUP_KEY", BACKUP_KEY)
    real_remove = backup_module.remove_artifacts

    def fail_after_cleanup(*paths: Path | None) -> None:
        real_remove(*paths)
        raise backup_module.ScriptError("temporary artifact cleanup failed")

    monkeypatch.setattr(backup_module, "remove_artifacts", fail_after_cleanup)
    with pytest.raises(backup_module.ScriptError, match="cleanup"):
        backup_module.backup(source, encrypted, "TEST_BACKUP_KEY")
    assert not any(tmp_path.glob(".backup-snapshot.*"))
    assert not any(tmp_path.glob(".source.smbk.*.tmp*"))


def test_migration_uses_one_source_wal_snapshot_when_writer_commits_after_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import importlib

    scripts_dir = str(ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    migration = importlib.import_module("migrate_legacy_db")
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    writer = sqlite3.connect(source)
    writer.execute("PRAGMA journal_mode = WAL")
    writer.close()
    monkeypatch.setenv("TEST_DATA_KEY", DATA_KEY)

    def concurrent_writer() -> None:
        conn = sqlite3.connect(source)
        conn.execute("UPDATE services SET name = 'writer-after-snapshot' WHERE id = 17")
        conn.commit()
        conn.close()

    monkeypatch.setattr(migration, "_after_source_snapshot", concurrent_writer)
    migration.migrate(source, target, "TEST_DATA_KEY")
    assert sqlite3.connect(target).execute("SELECT name FROM services WHERE id = 17").fetchone()[0] == "Synthetic mail"
    assert sqlite3.connect(source).execute("SELECT name FROM services WHERE id = 17").fetchone()[0] == "writer-after-snapshot"


def _script_module(name: str):
    import importlib

    scripts_dir = str(ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    return importlib.import_module(name)


def test_migration_mid_copy_failure_keeps_target_byte_identical_and_removes_all_temporary_artifacts(
    tmp_path: Path,
):
    migration = _script_module("migrate_legacy_db")
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    sentinel = b"preexisting-target-bytes"
    target.write_bytes(sentinel)

    with pytest.raises(migration.ScriptError):
        migration.migrate(
            source,
            target,
            "TEST_DATA_KEY",
            _after_account_copy=lambda: (_ for _ in ()).throw(migration.ScriptError("synthetic failure")),
        )

    assert target.read_bytes() == sentinel
    assert not any(tmp_path.glob(".target.db.*.tmp*"))
    assert not any(path.exists() for path in _sidecars(target))


def test_migration_and_verifier_pin_the_approved_wal_snapshot_before_a_concurrent_writer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    migration = _script_module("migrate_legacy_db")
    verifier = _script_module("verify_migrated_db")
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    writer = sqlite3.connect(source)
    writer.execute("PRAGMA journal_mode = WAL")
    writer.commit()
    monkeypatch.setenv("TEST_DATA_KEY", DATA_KEY)

    def change_source_after_snapshot() -> None:
        writer.execute("UPDATE services SET name = 'writer-mutation' WHERE id = 17")
        writer.commit()

    migration.migrate(source, target, "TEST_DATA_KEY", _after_snapshot_ready=change_source_after_snapshot)
    assert sqlite3.connect(target).execute("SELECT name FROM services WHERE id = 17").fetchone()[0] == "Synthetic mail"

    writer.execute("UPDATE services SET name = 'Synthetic mail' WHERE id = 17")
    writer.commit()
    verifier.verify(source, target, "TEST_DATA_KEY", _after_snapshot_ready=change_source_after_snapshot)
    writer.close()


@pytest.mark.parametrize(
    "mutation",
    (
        lambda conn: conn.execute("UPDATE services SET name = 'corrupt-service-name' WHERE id = 17"),
        lambda conn: conn.execute("UPDATE services SET id = 117 WHERE id = 17"),
        lambda conn: conn.execute("UPDATE custom_fields SET name = 'corrupt-field-name' WHERE id = 29"),
        lambda conn: conn.execute("UPDATE custom_fields SET service_id = 18 WHERE id = 29"),
        lambda conn: conn.execute("UPDATE accounts SET id = 9001 WHERE id = 1001"),
        lambda conn: conn.execute("UPDATE accounts SET email = 'corrupt@example.test' WHERE id = 1001"),
        lambda conn: conn.execute("UPDATE account_service SET service_id = 18 WHERE account_id = 1001"),
        lambda conn: conn.execute("UPDATE account_service SET status = 'inativo' WHERE account_id = 1001"),
        lambda conn: conn.execute("UPDATE field_values SET value_ciphertext = (SELECT value_ciphertext FROM field_values WHERE account_id = 1002) WHERE account_id = 1001"),
    ),
    ids=("service-name", "service-id", "field-name", "field-service", "account-id", "account-email", "link-service", "link-status", "encrypted-value-relationship"),
)
def test_verifier_independently_rejects_complete_relationship_equivalence_corruption(
    tmp_path: Path, mutation
):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    conn = sqlite3.connect(target)
    mutation(conn)
    conn.commit()
    conn.close()

    result = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert result.returncode != 0
    assert "migration-password-2-only" not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "mutation",
    (
        lambda conn: conn.execute("DROP TABLE recovery_codes"),
        lambda conn: conn.execute("ALTER TABLE accounts ADD COLUMN password TEXT"),
        lambda conn: conn.execute("ALTER TABLE field_values ADD COLUMN value TEXT"),
        lambda conn: conn.execute("DROP TRIGGER audit_events_no_delete"),
        lambda conn: conn.execute("DROP TRIGGER field_values_require_secret_representation_insert"),
        lambda conn: (conn.execute("DROP INDEX bootstrap_tokens_one_active"), conn.execute("CREATE UNIQUE INDEX bootstrap_tokens_one_active ON bootstrap_tokens(token_hash)")),
        lambda conn: conn.execute("CREATE TABLE unexpected_user_table (id INTEGER)"),
    ),
    ids=("required-table", "legacy-password-column", "legacy-value-column", "audit-trigger", "field-trigger", "partial-bootstrap-index", "unexpected-table"),
)
def test_verifier_requires_the_exact_secure_user_schema_and_excludes_sqlite_internal_tables(tmp_path: Path, mutation):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    clean = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})
    assert clean.returncode == 0, clean.stderr
    conn = sqlite3.connect(target)
    mutation(conn)
    conn.commit()
    conn.close()

    result = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert result.returncode != 0
    assert "migration-password-2-only" not in result.stdout + result.stderr


def test_backup_wal_snapshot_cleans_snapshot_artifacts_and_cleanup_failure_never_reports_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    backup = _script_module("backup")
    secure = _script_module("_secure_db")
    source = tmp_path / "source.db"
    target = tmp_path / "source.smbk"
    _legacy_source(source)
    writer = sqlite3.connect(source)
    writer.execute("PRAGMA journal_mode = WAL")
    writer.execute("UPDATE services SET name = 'WAL snapshot' WHERE id = 17")
    writer.commit()
    assert Path(f"{source}-wal").exists()
    monkeypatch.setenv("TEST_BACKUP_KEY", BACKUP_KEY)

    backup.backup(source, target, "TEST_BACKUP_KEY")
    assert target.exists()
    assert not any(tmp_path.glob(".backup-snapshot.*"))
    writer.close()

    def failed_cleanup(*_: Path | None) -> None:
        raise secure.ScriptError("temporary artifact cleanup failed")

    monkeypatch.setattr(backup, "remove_artifacts", failed_cleanup)
    monkeypatch.setattr(backup, "parse_args", lambda: argparse.Namespace(source=str(source), target=str(tmp_path / "failed.smbk"), key_env="TEST_BACKUP_KEY"))
    assert backup.main() == 1
    output = capsys.readouterr()
    assert "OK:" not in output.out
    assert "migration-password-2-only" not in output.out + output.err
    secure.remove_artifacts(*tmp_path.glob(".backup-snapshot.*"))


@pytest.mark.parametrize("artifact_suffix", ("", "-wal", "-shm"), ids=("main", "wal", "shm"))
def test_remove_artifacts_unlink_failure_is_fatal_for_each_database_artifact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, artifact_suffix: str):
    secure = _script_module("_secure_db")
    database = tmp_path / "temporary.db"
    artifact = Path(f"{database}{artifact_suffix}")
    artifact.write_bytes(b"synthetic-artifact")
    original_unlink = Path.unlink

    def fail_selected_unlink(path: Path, *args, **kwargs):
        if path == artifact:
            raise OSError("synthetic unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_selected_unlink)
    with pytest.raises(secure.ScriptError, match="cleanup"):
        secure.remove_artifacts(database)
    assert artifact.exists()


def test_restore_rejects_incompatible_payloads_and_rolls_back_no_prior_target_sidecar_failure(tmp_path: Path):
    import shutil

    restore = _script_module("restore_backup")
    source = tmp_path / "source.db"
    secure_target = tmp_path / "secure.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(secure_target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0

    legacy_wrong = tmp_path / "legacy-wrong.db"
    _legacy_source(legacy_wrong, accounts=115)
    tampered = tmp_path / "tampered.db"
    shutil.copy(secure_target, tampered)
    conn = sqlite3.connect(tampered)
    conn.execute("CREATE TABLE rogue_table (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()

    def authenticated_payload(database: Path, path: Path) -> None:
        nonce = b"n" * 12
        path.write_bytes(b"SMBK\x01" + nonce + AESGCM(base64.b64decode(BACKUP_KEY)).encrypt(nonce, database.read_bytes(), b"service-manager-backup:v1"))

    for label, database in (("legacy", legacy_wrong), ("tampered", tampered)):
        backup_path = tmp_path / f"{label}.smbk"
        target = tmp_path / f"{label}-target.db"
        sentinel = b"target-sentinel"
        target.write_bytes(sentinel)
        authenticated_payload(database, backup_path)
        result = _run(RESTORE, "--source", str(backup_path), "--target", str(target), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY})
        assert result.returncode != 0
        assert target.read_bytes() == sentinel
        assert "migration-password-2-only" not in result.stdout + result.stderr

    valid_backup = tmp_path / "valid.smbk"
    assert _run(BACKUP, "--source", str(secure_target), "--target", str(valid_backup), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY, "AUDIT_KEY_V1": DATA_KEY}).returncode == 0
    new_target = tmp_path / "new-target.db"
    with pytest.raises(restore.ScriptError):
        restore.restore(valid_backup, new_target, "TEST_BACKUP_KEY", _after_post_placement_validation=lambda: Path(f"{new_target}-shm").write_bytes(b"synthetic-sidecar"))
    assert not new_target.exists()
    assert not any(path.exists() for path in _sidecars(new_target))


def test_backup_and_restore_roundtrip_after_legitimate_account_deletion(tmp_path: Path):
    source = tmp_path / "source.db"
    secure_target = tmp_path / "secure.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(secure_target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0

    conn = sqlite3.connect(secure_target)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("DELETE FROM accounts WHERE id = 1001")
    conn.commit()
    conn.close()
    assert sqlite3.connect(secure_target).execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 115

    backup_path = tmp_path / "live.smbk"
    assert _run(BACKUP, "--source", str(secure_target), "--target", str(backup_path), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY, "AUDIT_KEY_V1": DATA_KEY}).returncode == 0

    restored = tmp_path / "restored.db"
    assert _run(RESTORE, "--source", str(backup_path), "--target", str(restored), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY, "AUDIT_KEY_V1": DATA_KEY}).returncode == 0
    conn = sqlite3.connect(restored)
    try:
        assert conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 115
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert list(conn.execute("PRAGMA foreign_key_check")) == []
    finally:
        conn.close()


def test_restore_rejects_authenticated_legacy_backup_and_preserves_target(tmp_path: Path):
    source = tmp_path / "legacy.db"
    encrypted = tmp_path / "legacy.smbk"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(BACKUP, "--source", str(source), "--target", str(encrypted), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY}).returncode == 0
    sentinel = b"secure-production-target"
    target.write_bytes(sentinel)

    result = _run(RESTORE, "--source", str(encrypted), "--target", str(target), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY, "AUDIT_KEY_V1": DATA_KEY})

    assert result.returncode != 0
    assert "incompatible" in result.stderr
    assert target.read_bytes() == sentinel
    assert "migration-password-2-only" not in result.stdout + result.stderr



def _authenticated_backup_payload(database: Path, destination: Path) -> None:
    nonce = b"n" * 12
    destination.write_bytes(
        b"SMBK\x01"
        + nonce
        + AESGCM(base64.b64decode(BACKUP_KEY)).encrypt(
            nonce, database.read_bytes(), b"service-manager-backup:v1"
        )
    )


def _weaken_schema_sql(path: Path, object_type: str, name: str, before: str, after: str) -> None:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA writable_schema = ON")
    result = conn.execute(
        "UPDATE sqlite_master SET sql = replace(sql, ?, ?) WHERE type = ? AND name = ?",
        (before, after, object_type, name),
    )
    assert result.rowcount == 1
    conn.execute("PRAGMA writable_schema = OFF")
    conn.execute("PRAGMA schema_version = 9001")
    conn.commit()
    conn.close()


def test_restore_keeps_rollback_artifact_when_rollback_replacement_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    restore = _script_module("restore_backup")
    source = tmp_path / "source.db"
    secure = tmp_path / "secure.db"
    encrypted = tmp_path / "source.smbk"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(secure), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    assert _run(BACKUP, "--source", str(secure), "--target", str(encrypted), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY, "AUDIT_KEY_V1": DATA_KEY}).returncode == 0
    sentinel = b"original-target-bytes"
    target.write_bytes(sentinel)
    monkeypatch.setenv("TEST_BACKUP_KEY", BACKUP_KEY)
    monkeypatch.setenv("AUDIT_KEY_V1", DATA_KEY)
    real_replace = restore.os.replace

    def fail_rollback_replacement(source_path: Path | str, destination_path: Path | str) -> None:
        if str(source_path).endswith(".rollback") and Path(destination_path) == target:
            raise OSError("synthetic rollback replacement failure")
        real_replace(source_path, destination_path)

    monkeypatch.setattr(restore.os, "replace", fail_rollback_replacement)
    with pytest.raises(restore.ScriptError, match="recovery") as failure:
        restore.restore(
            encrypted,
            target,
            "TEST_BACKUP_KEY",
            _after_post_placement_validation=lambda: (_ for _ in ()).throw(restore.ScriptError("synthetic failure")),
        )

    rollback_files = list(tmp_path.glob(".target.db.*.rollback"))
    assert len(rollback_files) == 1
    assert rollback_files[0].read_bytes() == sentinel
    assert not target.exists()
    assert "migration-password-2-only" not in str(failure.value)


@pytest.mark.parametrize("failure_kind", ("permissions", "sidecar"))
def test_migration_final_placement_failures_restore_existing_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_kind: str):
    migration = _script_module("migrate_legacy_db")
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    sentinel = b"original-target-bytes"
    target.write_bytes(sentinel)
    monkeypatch.setenv("TEST_DATA_KEY", DATA_KEY)

    if failure_kind == "permissions":
        original_ensure_mode = migration.ensure_mode

        def fail_post_placement_permissions(path: Path, mode: int = 0o600) -> None:
            if path == target:
                raise migration.ScriptError("required file permissions could not be enforced")
            original_ensure_mode(path, mode)
        monkeypatch.setattr(migration, "ensure_mode", fail_post_placement_permissions)

        with pytest.raises(migration.ScriptError):
            migration.migrate(source, target, "TEST_DATA_KEY")
    else:
        with pytest.raises(migration.ScriptError):
            migration.migrate(
                source,
                target,
                "TEST_DATA_KEY",
                _after_placement=lambda: Path(f"{target}-shm").write_bytes(b"synthetic-sidecar"),
            )

    assert target.read_bytes() == sentinel
    assert not any(tmp_path.glob(".target.db.*.rollback*"))
    assert not any(path.exists() for path in _sidecars(target))


def test_migration_final_placement_failure_removes_new_target_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    migration = _script_module("migrate_legacy_db")
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    monkeypatch.setenv("TEST_DATA_KEY", DATA_KEY)
    original_ensure_mode = migration.ensure_mode

    def fail_post_placement_permissions(path: Path, mode: int = 0o600) -> None:
        if path == target:
            raise migration.ScriptError("required file permissions could not be enforced")
        original_ensure_mode(path, mode)

    monkeypatch.setattr(migration, "ensure_mode", fail_post_placement_permissions)
    with pytest.raises(migration.ScriptError):
        migration.migrate(source, target, "TEST_DATA_KEY")

    assert not target.exists()
    assert not any(path.exists() for path in _sidecars(target))






@pytest.mark.parametrize(
    ("object_type", "name", "before", "after"),
    (
        ("table", "account_service", "CHECK (status IN ('ativo', 'nunca', 'inativo'))", "CHECK (status IN ('ativo', 'nunca'))"),
        ("table", "users", "CHECK (role IN ('admin', 'operador'))", "CHECK (role IN ('admin'))"),
        ("table", "field_values", "value_key_version IS NOT NULL)", "value_key_version IS NOT NULL OR 1)"),
        ("table", "account_service", "ON DELETE CASCADE", "ON DELETE RESTRICT"),
        ("trigger", "audit_events_no_update", "audit_events is append-only", "audit event mutation accepted"),
        ("index", "bootstrap_tokens_one_active", "WHERE consumed_at IS NULL", "WHERE consumed_at IS NOT NULL"),
    ),
    ids=("status-check", "role-check", "representation-check", "foreign-key", "trigger-body", "partial-index"),
)
def test_verifier_rejects_every_canonical_secure_schema_weakening(tmp_path: Path, object_type: str, name: str, before: str, after: str):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    _weaken_schema_sql(target, object_type, name, before, after)

    result = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert result.returncode != 0
    assert "migration-password-2-only" not in result.stdout + result.stderr


def test_restore_shared_validator_rejects_canonical_schema_weakening_without_replacing_target(tmp_path: Path):
    source = tmp_path / "source.db"
    migrated = tmp_path / "migrated.db"
    encrypted = tmp_path / "weakened.smbk"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(migrated), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    _weaken_schema_sql(migrated, "table", "account_service", "CHECK (status IN ('ativo', 'nunca', 'inativo'))", "CHECK (status IN ('ativo', 'nunca'))")
    _authenticated_backup_payload(migrated, encrypted)
    sentinel = b"original-target-bytes"
    target.write_bytes(sentinel)

    result = _run(RESTORE, "--source", str(encrypted), "--target", str(target), "--key-env", "TEST_BACKUP_KEY", env={"TEST_BACKUP_KEY": BACKUP_KEY})

    assert result.returncode != 0
    assert target.read_bytes() == sentinel
    assert "migration-password-2-only" not in result.stdout + result.stderr


def test_verifier_converts_corrupt_target_relationship_lookup_to_generic_script_error(tmp_path: Path):
    source = tmp_path / "source.db"
    target = tmp_path / "target.db"
    _legacy_source(source)
    assert _run(MIGRATE, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY}).returncode == 0
    conn = sqlite3.connect(target)
    conn.execute("UPDATE field_values SET account_id = 9999 WHERE field_id = 29 AND account_id = 1001")
    conn.commit()
    conn.close()

    result = _run(VERIFY, "--source", str(source), "--target", str(target), "--key-env", "TEST_DATA_KEY", env={"TEST_DATA_KEY": DATA_KEY})

    assert result.returncode != 0
    assert "Traceback" not in result.stdout + result.stderr
    assert "migration-password-2-only" not in result.stdout + result.stderr
