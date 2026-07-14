from __future__ import annotations

import base64
import importlib
import os
import sqlite3
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
from service_manager.audit import append_audit_event
from service_manager.db import get_db, transaction

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
NGINX = ROOT / "docker" / "nginx.conf"
ENTRYPOINT = ROOT / "docker" / "entrypoint.sh"
SUPERVISOR = ROOT / "docker" / "supervisor.py"


def _backup_module():
    scripts_directory = str(ROOT / "scripts")
    if scripts_directory not in sys.path:
        sys.path.insert(0, scripts_directory)
    return importlib.import_module("backup")


def _script_module(name: str):
    scripts_directory = str(ROOT / "scripts")
    if scripts_directory not in sys.path:
        sys.path.insert(0, scripts_directory)
    return importlib.import_module(name)


def _build_secure_database(path: Path, *, accounts: int, disable_fk: bool = False) -> None:
    from service_manager.db import SCHEMA

    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA)
        if disable_fk:
            conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("INSERT INTO services (id, name) VALUES (1, 'Email')")
        conn.execute("INSERT INTO custom_fields (id, service_id, name, is_secret) VALUES (1, 1, 'Recovery', 1)")
        conn.execute("INSERT INTO custom_fields (id, service_id, name, is_secret) VALUES (2, 1, 'Nickname', 0)")
        for account_id in range(1, accounts + 1):
            conn.execute(
                "INSERT INTO accounts (id, email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, ?, 1)",
                (account_id, f"person{account_id}@example.test", b"cipher", b"0" * 12),
            )
            conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (?, 1, 'ativo')", (account_id,))
            conn.execute(
                "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (1, ?, ?, ?, 1)",
                (account_id, b"cipher", b"1" * 12),
            )
            conn.execute("INSERT INTO field_values (field_id, account_id, value_plaintext) VALUES (2, ?, 'apelido')", (account_id,))
        if disable_fk:
            conn.execute("INSERT INTO account_service (account_id, service_id, status) VALUES (9999, 1, 'ativo')")
        conn.commit()
    finally:
        conn.close()


def _app(tmp_path: Path):
    key = base64.b64encode(b"a" * 32).decode("ascii")
    return create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "service-manager.db"),
            "DATA_KEY_V1": key,
            "AUDIT_KEY_V1": key,
            "SECRET_KEY": "task-eight-test-secret",
        }
    )


def test_secure_backup_restore_roundtrip_preserves_mixed_secret_fields(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    backup = _backup_module()
    restore = _script_module("restore_backup")
    source = tmp_path / "live-secure.db"
    _build_secure_database(source, accounts=2)
    key = base64.b64encode(b"a" * 32).decode("ascii")
    monkeypatch.setenv("BACKUP_KEY_V1", key)
    monkeypatch.setenv("AUDIT_KEY_V1", key)
    encrypted = tmp_path / "live.smbk"
    backup.backup(source, encrypted, "BACKUP_KEY_V1")
    restored = tmp_path / "restored.db"
    restore.restore(encrypted, restored, "BACKUP_KEY_V1")

    conn = sqlite3.connect(restored)
    try:
        assert conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM custom_fields WHERE is_secret = 0").fetchone()[0] == 1
        assert conn.execute("SELECT value_plaintext FROM field_values WHERE field_id = 2 AND account_id = 1").fetchone()[0] == "apelido"
        assert list(conn.execute("PRAGMA foreign_key_check")) == []
    finally:
        conn.close()


def test_validate_restorable_database_rejects_authenticated_orphan_foreign_key(tmp_path: Path):
    secure = _script_module("_secure_db")
    corrupt = tmp_path / "orphan-fk.db"
    _build_secure_database(corrupt, accounts=1, disable_fk=True)
    conn = sqlite3.connect(corrupt)
    try:
        with pytest.raises(secure.ScriptError, match="foreign-key"):
            secure.validate_restorable_database(conn)
    finally:
        conn.close()


def test_authenticated_orphan_foreign_key_restore_is_rejected_and_preserves_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    backup = _backup_module()
    restore = _script_module("restore_backup")
    corrupt = tmp_path / "orphan-fk.db"
    _build_secure_database(corrupt, accounts=1, disable_fk=True)
    key = base64.b64encode(b"a" * 32).decode("ascii")
    monkeypatch.setenv("BACKUP_KEY_V1", key)
    payload = tmp_path / "orphan.smbk"
    nonce = b"n" * 12
    payload.write_bytes(backup.MAGIC + backup.VERSION + nonce + AESGCM(base64.b64decode(key)).encrypt(nonce, corrupt.read_bytes(), backup.AAD))
    monkeypatch.setenv("AUDIT_KEY_V1", key)
    target = tmp_path / "target.db"
    sentinel = b"existing-target"
    target.write_bytes(sentinel)

    rejected_backup = tmp_path / "rejected.smbk"
    with pytest.raises(backup.ScriptError):
        backup.backup(corrupt, rejected_backup, "BACKUP_KEY_V1")
    assert not rejected_backup.exists()

    with pytest.raises(restore.ScriptError):
        restore.restore(payload, target, "BACKUP_KEY_V1")
    assert target.read_bytes() == sentinel



def _secure_database_with_audit_event(path: Path, key: str) -> None:
    from service_manager.audit import append_audit_event_in_transaction
    from service_manager.db import get_db as _get_db

    app = create_app({"TESTING": True, "DATABASE_PATH": str(path), "DATA_KEY_V1": key, "AUDIT_KEY_V1": key, "SECRET_KEY": key})
    with app.app_context():
        append_audit_event_in_transaction(action="task8.audit", target_type="test")
        _get_db().close()


def test_restore_verifies_non_empty_audit_chain_and_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    backup = _backup_module()
    restore = _script_module("restore_backup")
    key = base64.b64encode(b"a" * 32).decode("ascii")
    source = tmp_path / "audited.db"
    _secure_database_with_audit_event(source, key)
    monkeypatch.setenv("BACKUP_KEY_V1", key)
    monkeypatch.setenv("AUDIT_KEY_V1", key)
    encrypted = tmp_path / "audited.smbk"
    backup.backup(source, encrypted, "BACKUP_KEY_V1")
    restored = tmp_path / "restored.db"
    restore.restore(encrypted, restored, "BACKUP_KEY_V1")

    conn = sqlite3.connect(restored)
    try:
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 2
    finally:
        conn.close()


def test_restore_rejects_tampered_audit_chain_and_preserves_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    backup = _backup_module()
    restore = _script_module("restore_backup")
    key = base64.b64encode(b"a" * 32).decode("ascii")
    source = tmp_path / "audited.db"
    _secure_database_with_audit_event(source, key)
    conn = sqlite3.connect(source)
    conn.execute(
        "INSERT INTO audit_events (occurred_at, action, target_type, previous_hash, event_hash) VALUES (?, ?, ?, ?, ?)",
        ("2026-07-13T00:00:00+00:00", "tampered", "test", b"\x00" * 32, b"\xff" * 32),
    )
    conn.commit()
    conn.close()
    monkeypatch.setenv("BACKUP_KEY_V1", key)
    monkeypatch.setenv("AUDIT_KEY_V1", key)
    payload = tmp_path / "tampered.smbk"
    nonce = b"n" * 12
    payload.write_bytes(backup.MAGIC + backup.VERSION + nonce + AESGCM(base64.b64decode(key)).encrypt(nonce, source.read_bytes(), backup.AAD))
    target = tmp_path / "target.db"
    sentinel = b"existing-target"
    target.write_bytes(sentinel)

    with pytest.raises(restore.ScriptError, match="audit chain"):
        restore.restore(payload, target, "BACKUP_KEY_V1")
    assert target.read_bytes() == sentinel

def test_healthz_degrades_when_current_schema_is_no_longer_present(tmp_path: Path):
    app = _app(tmp_path)
    with app.app_context():
        conn = get_db()
        with transaction(conn):
            append_audit_event(conn, action="task8.schema", target_type="test")
        conn.execute("CREATE TABLE unexpected_schema_drift (id INTEGER)")
        conn.commit()

    response = app.test_client().get("/healthz")

    assert response.status_code == 503
    assert response.get_json() == {"status": "degraded"}


def test_healthz_handles_database_query_failure_without_leaking_details(tmp_path: Path):
    app = _app(tmp_path)
    database = tmp_path / "service-manager.db"
    with app.app_context():
        get_db().close()
    database.unlink()
    database.mkdir()

    response = app.test_client().get("/healthz")

    assert response.status_code == 503
    assert response.get_json() == {"status": "degraded"}




def test_gunicorn_configuration_emits_secret_free_json_logs():
    configuration = (ROOT / "docker" / "gunicorn.conf.py").read_text()

    assert '"event": "request"' in configuration
    assert '"method": "%(m)s"' in configuration
    assert '"status": %(s)s' in configuration
    assert "headers" not in configuration.lower()
    supervisor = (ROOT / "docker" / "supervisor.py").read_text()
    assert '"gunicorn", "--config", "/app/gunicorn.conf.py"' in supervisor


def test_container_files_enforce_locked_dependencies_non_root_runtime_and_healthcheck():
    dockerfile = DOCKERFILE.read_text()

    assert dockerfile.count("FROM python:3.12-slim") == 2
    assert "COPY pyproject.toml uv.lock ./" in dockerfile
    assert "uv sync --frozen --no-dev --no-install-project" in dockerfile
    assert "COPY --from=build /opt/venv /opt/venv" in dockerfile
    assert "useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin servicemanager" in dockerfile
    assert "chmod 0700 /data /backups /tmp/nginx /var/cache/nginx" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert 'VOLUME ["/data", "/backups"]' in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "http://127.0.0.1:8000/healthz" in dockerfile
    assert "credentials.db" not in dockerfile
    for copied_path in ("service_manager", "templates", "static", "scripts", "app.py wsgi.py", "docker/nginx.conf", "docker/entrypoint.sh", "docker/supervisor.py"):
        assert copied_path in dockerfile
    assert "TRUSTED_PROXY_HOPS=1" in dockerfile
    assert "COPY ." not in dockerfile


def test_nginx_enforces_upload_limits_proxy_timeouts_rate_limiting_and_defensive_headers():
    nginx = NGINX.read_text()

    for directive in (
        "listen 8000;",
        "proxy_pass http://127.0.0.1:8001;",
        "client_max_body_size 5m;",
        "client_body_timeout 30s;",
        "proxy_connect_timeout 10s;",
        "proxy_send_timeout 30s;",
        "proxy_read_timeout 30s;",
        "limit_req_zone $binary_remote_addr zone=uploads:10m rate=6r/m;",
        "location = /import",
        "limit_req zone=uploads burst=2 nodelay;",
        "pid /tmp/nginx/nginx.pid;",
        "access_log /dev/stdout;",
        "include /tmp/nginx/trusted_proxy.conf;",
        "map $trusted_forwarded_peer:$http_x_forwarded_proto $forwarded_proto_to_flask",
        "default $scheme;",
        "\"1:https\" https;",
        "\"1:http\" http;",
        "proxy_set_header X-Forwarded-For $remote_addr;",
        "proxy_set_header X-Forwarded-Proto $forwarded_proto_to_flask;",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options nosniff always;",
        "X-Frame-Options DENY always;",
        "Referrer-Policy no-referrer always;",
        "Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
    ):
        assert directive in nginx
    assert "$proxy_add_x_forwarded_for" not in nginx
    assert "set_real_ip_from 172.16.0.0/12" not in nginx
    assert "set_real_ip_from 10.0.0.0/8" not in nginx
    assert "set_real_ip_from 192.168.0.0/16" not in nginx
    assert "$http_x_forwarded_proto" in nginx



def test_container_proxy_topology_preserves_client_ip_and_https_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    key = base64.b64encode(b"p" * 32).decode("ascii")
    monkeypatch.setenv("FLASK_ENV", "production")
    proxy_app = create_app(
        {
            "DATABASE_PATH": str(tmp_path / "proxy-topology.db"),
            "DATA_KEY_V1": key,
            "AUDIT_KEY_V1": key,
            "SECRET_KEY": key,
            "TRUSTED_PROXY_HOPS": 1,
            "TESTING": True,
        }
    )
    response = proxy_app.test_client().get(
        "/login",
        headers={"X-Forwarded-For": "198.51.100.20", "X-Forwarded-Proto": "https"},
    )

    assert response.status_code == 200
    assert response.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
    response = proxy_app.test_client().post(
        "/login",
        data={"username": "missing", "password": "wrong"},
        headers={"X-Forwarded-For": "198.51.100.20", "X-Forwarded-Proto": "https"},
    )
    assert response.status_code == 401
    with proxy_app.app_context():
        assert get_db().execute("SELECT source_ip FROM security_events").fetchone()[0] == "198.51.100.20"

def test_proxy_topology_does_not_trust_direct_forwarded_proto_spoof(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    key = base64.b64encode(b"d" * 32).decode("ascii")
    monkeypatch.setenv("FLASK_ENV", "production")
    direct_app = create_app(
        {
            "DATABASE_PATH": str(tmp_path / "direct-proxy-spoof.db"),
            "DATA_KEY_V1": key,
            "AUDIT_KEY_V1": key,
            "SECRET_KEY": key,
            "TRUSTED_PROXY_HOPS": 0,
            "TESTING": True,
        }
    )
    response = direct_app.test_client().get("/login", headers={"X-Forwarded-Proto": "https"})

    assert response.status_code == 200
    assert "Strict-Transport-Security" not in response.headers

def _base_entrypoint_env(key: str) -> dict[str, str]:
    return {
        "PATH": os.environ["PATH"],
        "SECRET_KEY": base64.b64encode(b"s" * 32).decode("ascii"),
        "DATA_KEY_V1": key,
        "BACKUP_KEY_V1": key,
        "AUDIT_KEY_V1": key,
        "TRAEFIK_TRUSTED_CIDR": "127.0.0.1/32",
    }



def test_entrypoint_rejects_missing_secrets_before_starting_processes():
    result = subprocess.run([str(ENTRYPOINT)], env={"PATH": os.environ["PATH"]}, text=True, capture_output=True, check=False)

    assert result.returncode != 0
    assert "SECRET_KEY" in result.stderr


def test_entrypoint_rejects_malformed_data_key_before_starting_processes():
    result = subprocess.run(
        [str(ENTRYPOINT)],
        env={**_base_entrypoint_env(base64.b64encode(b"b" * 32).decode("ascii")), "DATA_KEY_V1": "not-a-base64-key"},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "DATA_KEY_V1" in result.stderr


def test_entrypoint_requires_preexisting_database_when_enabled(tmp_path: Path):
    key = base64.b64encode(b"k" * 32).decode("ascii")
    result = subprocess.run(
        [str(ENTRYPOINT)],
        env={
            **_base_entrypoint_env(key),
            "REQUIRE_EXISTING_DATABASE": "true",
            "DATABASE_PATH": str(tmp_path / "missing.db"),
        },
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "DATABASE_PATH" in result.stderr


def _host_entrypoint(tmp_path: Path, marker: Path) -> Path:
    supervisor = tmp_path / "fake_supervisor.py"
    supervisor.write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('started')\n")
    temporary_entrypoint = tmp_path / "entrypoint.sh"
    text = ENTRYPOINT.read_text().replace("exec python /app/docker-supervisor.py", f"exec {sys.executable} {supervisor}")
    temporary_entrypoint.write_text(text)
    temporary_entrypoint.chmod(0o755)
    return temporary_entrypoint


def test_entrypoint_rejects_existing_empty_database_when_required(tmp_path: Path):
    key = base64.b64encode(b"k" * 32).decode("ascii")
    database = tmp_path / "service-manager.db"
    sqlite3.connect(database).close()
    marker = tmp_path / "supervisor.marker"
    proxy_config = tmp_path / "trusted_proxy.conf"
    result = subprocess.run(
        [str(_host_entrypoint(tmp_path, marker))],
        env={
            **_base_entrypoint_env(key),
            "REQUIRE_EXISTING_DATABASE": "true",
            "DATABASE_PATH": str(database),
            "SERVICE_MANAGER_TEST_HOOKS": "1",
            "TRUSTED_PROXY_CONFIG_PATH": str(proxy_config),
        },
        text=True,
        capture_output=True,
        check=False,
        cwd=str(ROOT),
    )

    assert result.returncode != 0
    assert "secure schema" in result.stderr
    assert not marker.exists()


def test_entrypoint_rejects_corrupt_existing_database_without_leaking_traceback(tmp_path: Path):
    key = base64.b64encode(b"k" * 32).decode("ascii")
    database = tmp_path / "service-manager.db"
    database.write_bytes(b"this is not a sqlite database")
    marker = tmp_path / "supervisor.marker"
    proxy_config = tmp_path / "trusted_proxy.conf"
    result = subprocess.run(
        [str(_host_entrypoint(tmp_path, marker))],
        env={
            **_base_entrypoint_env(key),
            "REQUIRE_EXISTING_DATABASE": "true",
            "DATABASE_PATH": str(database),
            "SERVICE_MANAGER_TEST_HOOKS": "1",
            "TRUSTED_PROXY_CONFIG_PATH": str(proxy_config),
        },
        text=True,
        capture_output=True,
        check=False,
        cwd=str(ROOT),
    )

    assert result.returncode != 0
    assert "secure schema" in result.stderr
    assert "Traceback" not in result.stderr
    assert not marker.exists()


def test_entrypoint_accepts_existing_secure_database_when_required(tmp_path: Path):
    key = base64.b64encode(b"k" * 32).decode("ascii")
    database = tmp_path / "service-manager.db"
    _build_secure_database(database, accounts=2)
    marker = tmp_path / "supervisor.marker"
    proxy_config = tmp_path / "trusted_proxy.conf"
    result = subprocess.run(
        [str(_host_entrypoint(tmp_path, marker))],
        env={
            **_base_entrypoint_env(key),
            "REQUIRE_EXISTING_DATABASE": "true",
            "DATABASE_PATH": str(database),
            "SERVICE_MANAGER_TEST_HOOKS": "1",
            "TRUSTED_PROXY_CONFIG_PATH": str(proxy_config),
        },
        text=True,
        capture_output=True,
        check=False,
        cwd=str(ROOT),
    )

    assert result.returncode == 0, result.stderr
    assert marker.read_text() == "started"

def test_entrypoint_requires_valid_trusted_traefik_cidr_before_starting_processes():
    key = base64.b64encode(b"k" * 32).decode("ascii")
    result = subprocess.run(
        [str(ENTRYPOINT)],
        env={
            "PATH": os.environ["PATH"],
            "SECRET_KEY": base64.b64encode(b"s" * 32).decode("ascii"),
            "DATA_KEY_V1": key,
            "BACKUP_KEY_V1": key,
            "AUDIT_KEY_V1": key,
            "TRAEFIK_TRUSTED_CIDR": "not-a-cidr",
        },
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "TRAEFIK_TRUSTED_CIDR" in result.stderr

def test_entrypoint_writes_exact_trusted_proxy_config_before_supervisor(tmp_path: Path):
    key = base64.b64encode(b"k" * 32).decode("ascii")
    proxy_config = tmp_path / "trusted_proxy.conf"
    supervisor = tmp_path / "fake_supervisor.py"
    supervisor.write_text(f"from pathlib import Path\nprint(Path({str(proxy_config)!r}).read_text())\n")
    temporary_entrypoint = tmp_path / "entrypoint.sh"
    temporary_entrypoint.write_text(ENTRYPOINT.read_text().replace("exec python /app/docker-supervisor.py", f"exec {sys.executable} {supervisor}"))
    temporary_entrypoint.chmod(0o755)

    result = subprocess.run(
        [str(temporary_entrypoint)],
        env={**_base_entrypoint_env(key), "TRAEFIK_TRUSTED_CIDR": "127.0.0.1/32", "TRUSTED_PROXY_CONFIG_PATH": str(proxy_config), "SERVICE_MANAGER_TEST_HOOKS": "1"},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.strip().splitlines() == [
        "set_real_ip_from 127.0.0.1/32;",
        "real_ip_header X-Forwarded-For;",
        "real_ip_recursive on;",
        "geo $realip_remote_addr $trusted_forwarded_peer {",
        "    default 0;",
        "    127.0.0.1/32 1;",
        "}",
    ]


def test_entrypoint_ignores_config_path_override_without_test_hooks(tmp_path: Path):
    key = base64.b64encode(b"k" * 32).decode("ascii")
    default_path = tmp_path / "default.conf"
    override = tmp_path / "attacker.conf"
    supervisor = tmp_path / "fake_supervisor.py"
    supervisor.write_text("import sys; sys.exit(0)\n")
    temporary_entrypoint = tmp_path / "entrypoint.sh"
    entrypoint_text = (
        ENTRYPOINT.read_text()
        .replace("exec python /app/docker-supervisor.py", f"exec {sys.executable} {supervisor}")
        .replace('output_path="/tmp/nginx/trusted_proxy.conf"', f'output_path="{default_path}"')
    )
    temporary_entrypoint.write_text(entrypoint_text)
    temporary_entrypoint.chmod(0o755)

    result = subprocess.run(
        [str(temporary_entrypoint)],
        env={**_base_entrypoint_env(key), "TRAEFIK_TRUSTED_CIDR": "127.0.0.1/32", "TRUSTED_PROXY_CONFIG_PATH": str(override)},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert not override.exists()
    assert default_path.exists()
    assert "set_real_ip_from 127.0.0.1/32;" in default_path.read_text()


def _free_port() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return str(sock.getsockname()[1])


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _wait_for(path: Path, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise AssertionError(f"process exited early with {process.returncode}")
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {path}")


def test_supervisor_reports_failure_when_gunicorn_binary_is_missing(tmp_path: Path):
    process = subprocess.Popen(
        [sys.executable, str(SUPERVISOR)],
        env={
            **os.environ,
            "SERVICE_MANAGER_TEST_HOOKS": "1",
            "SERVICE_MANAGER_GUNICORN_CMD": str(tmp_path / "does-not-exist-binary"),
            "SERVICE_MANAGER_HEALTH_URL": "http://127.0.0.1:1/healthz",
        },
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _, stderr = process.communicate(timeout=5)
    assert process.returncode == 1
    assert "ERROR" in stderr
    assert "does-not-exist-binary" not in stderr


def _write_supervisor_fakes(tmp_path: Path, *, nginx_exits: bool = False) -> tuple[Path, Path, Path, Path]:
    gunicorn_term = tmp_path / "gunicorn.term"
    nginx_started = tmp_path / "nginx.started"
    nginx_term = tmp_path / "nginx.term"
    gunicorn = tmp_path / "fake_gunicorn.py"
    nginx = tmp_path / "fake_nginx.py"
    gunicorn.write_text(
        "import signal, sys\n"
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        "term = sys.argv[2]\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        self.send_response(200 if self.path == '/healthz' else 404); self.end_headers(); self.wfile.write(b'ok')\n"
        "    def log_message(self, *args): pass\n"
        "def stop(signum, frame):\n"
        "    open(term, 'w').write('term'); sys.exit(0)\n"
        "signal.signal(signal.SIGTERM, stop)\n"
        "HTTPServer(('127.0.0.1', int(sys.argv[1])), Handler).serve_forever()\n"
    )
    nginx.write_text(
        "import signal, sys, time\n"
        "term, started = sys.argv[1], sys.argv[2]\n"
        "open(started, 'w').write('started')\n"
        + (
            "time.sleep(0.2); sys.exit(17)\n"
            if nginx_exits
            else "def stop(signum, frame):\n    open(term, 'w').write('term'); sys.exit(0)\nsignal.signal(signal.SIGTERM, stop)\nwhile True: time.sleep(0.1)\n"
        )
    )
    return gunicorn, nginx, gunicorn_term, nginx_started if nginx_exits else nginx_term


def test_entrypoint_delegates_process_lifecycle_to_supervisor():
    entrypoint = ENTRYPOINT.read_text()
    dockerfile = DOCKERFILE.read_text()

    assert "exec python /app/docker-supervisor.py" in entrypoint
    assert "exec nginx" not in entrypoint
    assert "COPY --chown=10001:10001 docker/supervisor.py /app/docker-supervisor.py" in dockerfile


def test_supervisor_forwards_sigterm_to_gunicorn_and_nginx(tmp_path: Path):
    gunicorn, nginx, gunicorn_term, nginx_term = _write_supervisor_fakes(tmp_path)
    port = _free_port()
    nginx_started = tmp_path / "nginx.started"
    process = subprocess.Popen(
        [sys.executable, str(SUPERVISOR)],
        env={
            **os.environ,
            "SERVICE_MANAGER_TEST_HOOKS": "1",
            "SERVICE_MANAGER_GUNICORN_CMD": f"{sys.executable} {gunicorn} {port} {gunicorn_term}",
            "SERVICE_MANAGER_NGINX_CMD": f"{sys.executable} {nginx} {nginx_term} {nginx_started}",
            "SERVICE_MANAGER_HEALTH_URL": f"http://127.0.0.1:{port}/healthz",
            "SERVICE_MANAGER_NGINX_TEST_CMD": f"{sys.executable} -c ''",
        },
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for(nginx_started, process)
        process.terminate()
        assert process.wait(timeout=5) == 0
    finally:
        _stop_process(process)

    assert gunicorn_term.read_text() == "term"
    assert nginx_term.read_text() == "term"

def test_supervisor_stops_gunicorn_when_sigterm_arrives_before_readiness(tmp_path: Path):
    terminated = tmp_path / "slow-gunicorn.term"
    started = tmp_path / "slow-gunicorn.started"
    gunicorn = tmp_path / "slow_gunicorn.py"
    gunicorn.write_text(
        "import signal, sys, time\n"
        "terminated, started = sys.argv[1], sys.argv[2]\n"
        "open(started, 'w').write('started')\n"
        "def stop(signum, frame):\n    open(terminated, 'w').write('term'); sys.exit(0)\n"
        "signal.signal(signal.SIGTERM, stop)\n"
        "while True: time.sleep(0.1)\n"
    )
    process = subprocess.Popen(
        [sys.executable, str(SUPERVISOR)],
        env={
            **os.environ,
            "SERVICE_MANAGER_TEST_HOOKS": "1",
            "SERVICE_MANAGER_GUNICORN_CMD": f"{sys.executable} {gunicorn} {terminated} {started}",
            "SERVICE_MANAGER_HEALTH_URL": "http://127.0.0.1:1/healthz",
        },
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for(started, process)
        process.terminate()
        assert process.wait(timeout=5) == 0
    finally:
        _stop_process(process)

    assert terminated.read_text() == "term"


def test_supervisor_stops_gunicorn_when_nginx_child_dies(tmp_path: Path):
    gunicorn, nginx, gunicorn_term, nginx_started = _write_supervisor_fakes(tmp_path, nginx_exits=True)
    port = _free_port()
    process = subprocess.Popen(
        [sys.executable, str(SUPERVISOR)],
        env={
            **os.environ,
            "SERVICE_MANAGER_TEST_HOOKS": "1",
            "SERVICE_MANAGER_GUNICORN_CMD": f"{sys.executable} {gunicorn} {port} {gunicorn_term}",
            "SERVICE_MANAGER_NGINX_CMD": f"{sys.executable} {nginx} unused {nginx_started}",
            "SERVICE_MANAGER_HEALTH_URL": f"http://127.0.0.1:{port}/healthz",
            "SERVICE_MANAGER_NGINX_TEST_CMD": f"{sys.executable} -c ''",
        },
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert process.wait(timeout=5) == 17
    finally:
        _stop_process(process)

    assert gunicorn_term.read_text() == "term"


def test_supervisor_reports_failure_when_child_exits_cleanly_but_unexpectedly(tmp_path: Path):
    gunicorn_term = tmp_path / "gunicorn.term"
    nginx_started = tmp_path / "nginx.started"
    gunicorn = tmp_path / "fake_gunicorn.py"
    nginx = tmp_path / "fake_nginx.py"
    gunicorn.write_text(
        "import signal, sys\n"
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        "term = sys.argv[2]\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        self.send_response(200 if self.path == '/healthz' else 404); self.end_headers(); self.wfile.write(b'ok')\n"
        "    def log_message(self, *args): pass\n"
        "def stop(signum, frame):\n    open(term, 'w').write('term'); sys.exit(0)\n"
        "signal.signal(signal.SIGTERM, stop)\n"
        "HTTPServer(('127.0.0.1', int(sys.argv[1])), Handler).serve_forever()\n"
    )
    nginx.write_text(
        "import sys, time\n"
        "open(sys.argv[1], 'w').write('started')\n"
        "time.sleep(0.2); sys.exit(0)\n"
    )
    port = _free_port()
    process = subprocess.Popen(
        [sys.executable, str(SUPERVISOR)],
        env={
            **os.environ,
            "SERVICE_MANAGER_TEST_HOOKS": "1",
            "SERVICE_MANAGER_GUNICORN_CMD": f"{sys.executable} {gunicorn} {port} {gunicorn_term}",
            "SERVICE_MANAGER_NGINX_CMD": f"{sys.executable} {nginx} {nginx_started}",
            "SERVICE_MANAGER_HEALTH_URL": f"http://127.0.0.1:{port}/healthz",
            "SERVICE_MANAGER_NGINX_TEST_CMD": f"{sys.executable} -c ''",
        },
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert process.wait(timeout=5) == 1
    finally:
        _stop_process(process)

    assert gunicorn_term.read_text() == "term"


def test_supervisor_aborts_when_nginx_config_test_fails(tmp_path: Path):
    gunicorn_term = tmp_path / "gunicorn.term"
    nginx_started = tmp_path / "nginx.started"
    gunicorn = tmp_path / "fake_gunicorn.py"
    nginx = tmp_path / "fake_nginx.py"
    gunicorn.write_text(
        "import signal, sys\n"
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        "term = sys.argv[2]\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        self.send_response(200 if self.path == '/healthz' else 404); self.end_headers(); self.wfile.write(b'ok')\n"
        "    def log_message(self, *args): pass\n"
        "def stop(signum, frame):\n    open(term, 'w').write('term'); sys.exit(0)\n"
        "signal.signal(signal.SIGTERM, stop)\n"
        "HTTPServer(('127.0.0.1', int(sys.argv[1])), Handler).serve_forever()\n"
    )
    nginx.write_text("import sys, time\nopen(sys.argv[1], 'w').write('started')\ntime.sleep(1)\n")
    port = _free_port()
    process = subprocess.Popen(
        [sys.executable, str(SUPERVISOR)],
        env={
            **os.environ,
            "SERVICE_MANAGER_TEST_HOOKS": "1",
            "SERVICE_MANAGER_GUNICORN_CMD": f"{sys.executable} {gunicorn} {port} {gunicorn_term}",
            "SERVICE_MANAGER_NGINX_CMD": f"{sys.executable} {nginx} {nginx_started}",
            "SERVICE_MANAGER_NGINX_TEST_CMD": f"{sys.executable} -c 'raise SystemExit(1)'",
            "SERVICE_MANAGER_HEALTH_URL": f"http://127.0.0.1:{port}/healthz",
        },
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert process.wait(timeout=5) == 1
    finally:
        _stop_process(process)

    assert not nginx_started.exists()
    assert gunicorn_term.read_text() == "term"


def test_backup_retention_keeps_seven_newest_dated_service_manager_backups_only(tmp_path: Path):
    backup = _backup_module()
    base = datetime(2026, 7, 13, tzinfo=UTC)
    dated = []
    for offset in range(9):
        timestamp = base - timedelta(days=offset)
        path = tmp_path / f"service-manager-{timestamp.strftime('%Y%m%dT%H%M%SZ')}.smbk"
        path.write_bytes(b"encrypted")
        dated.append(path)
    unrelated = tmp_path / "operator-supplied.smbk"
    unrelated.write_bytes(b"keep")
    backup.retain_daily_backups(tmp_path)

    assert [path.exists() for path in dated] == [True] * 7 + [False, False]
    assert unrelated.read_bytes() == b"keep"

def test_concurrent_first_boot_initializes_schema_without_partial_state(tmp_path: Path):
    import threading

    from service_manager.db import schema_is_current

    key = base64.b64encode(b"a" * 32).decode("ascii")
    database_path = str(tmp_path / "concurrent-boot.db")
    workers = 2
    start = threading.Barrier(workers)
    lock = threading.Lock()
    errors: list[BaseException] = []
    completed: list[int] = []

    def boot(index: int) -> None:
        start.wait()
        try:
            worker = create_app(
                {"TESTING": True, "DATABASE_PATH": database_path, "DATA_KEY_V1": key, "AUDIT_KEY_V1": key, "SECRET_KEY": key}
            )
            with worker.app_context():
                assert schema_is_current(get_db())
            with lock:
                completed.append(index)
        except BaseException as error:  # noqa: BLE001 - surfaced to the parent thread
            with lock:
                errors.append(error)

    threads = [threading.Thread(target=boot, args=(index,)) for index in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not any(thread.is_alive() for thread in threads)
    assert errors == []
    assert sorted(completed) == list(range(workers))

def test_enable_wal_retries_only_on_transient_lock(monkeypatch: pytest.MonkeyPatch):
    from service_manager import db as db_module

    class FakeConn:
        def __init__(self, errors: list[BaseException]):
            self._errors = errors
            self.calls = 0

        def execute(self, _statement: str):
            self.calls += 1
            if self._errors:
                raise self._errors.pop(0)
            return None

    monkeypatch.setattr(db_module.time, "sleep", lambda _seconds: None)

    busy = sqlite3.OperationalError("database is locked")
    busy.sqlite_errorcode = db_module._SQLITE_BUSY
    transient = FakeConn([busy, busy])
    db_module._enable_wal(transient)
    assert transient.calls == 3


def test_enable_wal_fails_fast_on_non_lock_error(monkeypatch: pytest.MonkeyPatch):
    from service_manager import db as db_module

    class FakeConn:
        def __init__(self, error: BaseException):
            self._error = error
            self.calls = 0

        def execute(self, _statement: str):
            self.calls += 1
            raise self._error

    monkeypatch.setattr(db_module.time, "sleep", lambda _seconds: None)

    disk_full = sqlite3.OperationalError("disk I/O error")
    disk_full.sqlite_errorcode = 10
    conn = FakeConn(disk_full)
    with pytest.raises(sqlite3.OperationalError):
        db_module._enable_wal(conn)
    assert conn.calls == 1


def test_snapshot_checkpoints_source_wal_before_opening_read_only_backup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    backup = _backup_module()
    source = tmp_path / "source.db"
    destination = tmp_path / "snapshot.db"
    sqlite3.connect(source).close()
    statements: list[str] = []
    real_connect = backup.sqlite3.connect

    class RecordingConnection:
        def __init__(self, connection: sqlite3.Connection):
            self.connection = connection

        def execute(self, statement: str, *args: object, **kwargs: object):
            statements.append(statement)
            return self.connection.execute(statement, *args, **kwargs)

        def __getattr__(self, name: str):
            return getattr(self.connection, name)

        def close(self) -> None:
            self.connection.close()

    def recording_connect(path: object, *args: object, **kwargs: object):
        connection = real_connect(path, *args, **kwargs)
        return RecordingConnection(connection) if Path(path) == source else connection

    monkeypatch.setattr(backup.sqlite3, "connect", recording_connect)

    with pytest.raises(backup.ScriptError):
        backup._snapshot(source, destination)

    assert statements == ["PRAGMA wal_checkpoint(TRUNCATE)"]


def test_scheduled_backup_uses_environment_paths_key_and_retention(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    backup = _backup_module()
    source = tmp_path / "service-manager.db"
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    connection = sqlite3.connect(source)
    connection.executescript(
        """
        CREATE TABLE accounts (id INTEGER PRIMARY KEY, email TEXT, password TEXT);
        CREATE TABLE services (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE account_service (account_id INTEGER, service_id INTEGER, status TEXT);
        CREATE TABLE custom_fields (id INTEGER PRIMARY KEY, service_id INTEGER, name TEXT);
        CREATE TABLE field_values (field_id INTEGER, account_id INTEGER, value TEXT);
        CREATE TABLE credentials_backup (id INTEGER PRIMARY KEY);
        """
    )
    connection.execute("INSERT INTO services VALUES (1, 'Service')")
    connection.execute("INSERT INTO custom_fields VALUES (1, 1, 'Field')")
    for account_id in range(1, 117):
        connection.execute("INSERT INTO accounts VALUES (?, 'user@example.test', '')", (account_id,))
        connection.execute("INSERT INTO account_service VALUES (?, 1, 'ativo')", (account_id,))
        connection.execute("INSERT INTO field_values VALUES (1, ?, '')", (account_id,))
        connection.execute("INSERT INTO credentials_backup VALUES (?)", (account_id,))
    connection.commit()
    connection.close()
    for day in range(1, 9):
        (backup_dir / f"service-manager-202607{day:02d}T030000Z.smbk").write_bytes(b"old")
    key = base64.b64encode(b"a" * 32).decode("ascii")
    monkeypatch.setenv("DATABASE_PATH", str(source))
    monkeypatch.setenv("BACKUP_KEY_V1", key)
    monkeypatch.setattr(sys, "argv", ["backup.py", "--backups-dir", str(backup_dir)])

    assert backup.main() == 0

    generated = list(backup_dir.glob("service-manager-*.smbk"))
    assert len(generated) == 7
    assert any(path.read_bytes().startswith(b"SMBK\x01") for path in generated)
    assert [path.stat().st_mode & 0o777 for path in generated if path.read_bytes().startswith(b"SMBK\x01")] == [0o600]