from __future__ import annotations

import importlib.util
import io
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".agents" / "skills" / "service-manager-api-management" / "scripts" / "service_manager_api.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("service_manager_api_skill", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


sm = _load_module()


def test_normalize_api_path_accepts_relative_and_absolute_namespace():
    assert sm.normalize_api_path("services") == "/api/v1/services"
    assert sm.normalize_api_path("/api/v1/services") == "/api/v1/services"
    assert sm.normalize_api_path("/api/v1/services/1/accounts") == "/api/v1/services/1/accounts"


def test_normalize_api_path_rejects_escape_and_absolute_urls():
    with pytest.raises(sm.ClientError):
        sm.normalize_api_path("https://evil.example/api/v1/services")
    with pytest.raises(sm.ClientError):
        sm.normalize_api_path("//evil.example/api/v1/services")
    with pytest.raises(sm.ClientError):
        sm.normalize_api_path("/api/v2/services")
    with pytest.raises(sm.ClientError):
        sm.normalize_api_path("/api/v1/../v2/secrets")
    with pytest.raises(sm.ClientError):
        sm.normalize_api_path("/admin")
    with pytest.raises(sm.ClientError):
        sm.normalize_api_path("/api/v1/services?x=1")


def test_redact_masks_full_api_tokens():
    token = "smk_v1_" + ("A" * 43)
    text = f"Authorization: Bearer {token} boom"
    assert token not in sm.redact(text)
    assert "smk_v1_[REDACTED]" in sm.redact(text)


def test_exit_for_status_mapping():
    assert sm.exit_for_status(200) == 0
    assert sm.exit_for_status(201) == 0
    assert sm.exit_for_status(204) == 0
    assert sm.exit_for_status(401) == 3
    assert sm.exit_for_status(404) == 4
    assert sm.exit_for_status(409) == 4
    assert sm.exit_for_status(500) == 5


def test_normalize_method_accepts_any_http_token_not_allowlist():
    assert sm.normalize_method("options") == "options"
    assert sm.normalize_method("GET") == "GET"
    assert sm.normalize_method("ProPFind") == "ProPFind"
    with pytest.raises(sm.ClientError):
        sm.normalize_method("")
    with pytest.raises(sm.ClientError):
        sm.normalize_method("GET /evil")
    with pytest.raises(sm.ClientError):
        sm.normalize_method("GET\nPOST")


def test_build_multipart_contains_field_file_and_bytes(tmp_path: Path):
    upload = tmp_path / "contas.csv"
    payload = b"email,password,status\na@b.c,secret,nunca\n"
    upload.write_bytes(payload)
    body, content_type = sm.build_multipart("file", upload)
    assert content_type.startswith("multipart/form-data; boundary=")
    assert b'name="file"' in body
    assert b'filename="contas.csv"' in body
    assert payload in body
    # Exactly one form-data part disposition for the file field.
    assert body.count(b'Content-Disposition: form-data; name="file"') == 1


def test_load_config_requires_env_and_normalizes_url():
    with pytest.raises(sm.ClientError):
        sm.load_config({})
    with pytest.raises(sm.ClientError):
        sm.load_config({"SERVICE_MANAGER_URL": "https://example.com"})
    with pytest.raises(sm.ClientError):
        sm.load_config({"SERVICE_MANAGER_API_KEY": "smk_v1_x"})
    with pytest.raises(sm.ClientError):
        sm.load_config({"SERVICE_MANAGER_URL": "ftp://example.com", "SERVICE_MANAGER_API_KEY": "k"})

    cfg = sm.load_config(
        {
            "SERVICE_MANAGER_URL": "https://servicemanager.example.com/extra/",
            "SERVICE_MANAGER_API_KEY": "smk_v1_test",
        }
    )
    assert cfg.base_url == "https://servicemanager.example.com"
    assert cfg.api_key == "smk_v1_test"


def test_reserved_headers_cannot_be_overridden_via_cli(http_server):
    address = http_server.server_address
    host = address[0]
    port = int(address[1])
    env = {
        "SERVICE_MANAGER_URL": f"http://{host}:{port}",
        "SERVICE_MANAGER_API_KEY": "smk_v1_" + ("F" * 43),
    }
    requests_before = list(http_server.requests)

    for reserved in ("Authorization", "authorization", "Accept", "user-agent", "Content-Type", "Host"):
        err = io.StringIO()
        code = sm.main(
            ["request", "GET", "/api/v1/services", "--header", f"{reserved}=evil"],
            environ=env,
            stdout=io.StringIO(),
            stderr=err,
        )
        assert code == sm.EXIT_USAGE, reserved
        assert "reserved" in err.getvalue().lower()
    # Nothing was ever sent: no network side effects for the rejected calls.
    assert http_server.requests == requests_before


def test_non_reserved_header_is_applied(http_server):
    address = http_server.server_address
    host = address[0]
    port = int(address[1])
    env = {
        "SERVICE_MANAGER_URL": f"http://{host}:{port}",
        "SERVICE_MANAGER_API_KEY": "smk_v1_" + ("G" * 43),
    }
    code = sm.main(
        ["request", "GET", "/api/v1/services", "--header", "X-Custom-Header=1"],
        environ=env,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert code == 0
    get = [r for r in http_server.requests if r[0] == "GET"][-1]
    assert get[2].get("X-Custom-Header") == "1"
    # Required contract headers still present unchanged.
    assert get[2].get("Accept") == "application/json"
    assert get[2].get("User-Agent") == "service-manager-api-management/1.0"
    assert get[2].get("Authorization", "").startswith("Bearer smk_v1_")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        return

    def _read(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _record(self, method: str, body: bytes = b"") -> None:
        requests = getattr(self.server, "requests")
        requests.append((method, self.path, dict(self.headers), body))

    def do_GET(self) -> None:
        self._record("GET")
        if self.path.startswith("/api/v1/services"):
            body = json.dumps({"items": [{"id": 1, "name": "Demo", "rotation_days": None}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/api/v1/bin":
            body = b"\x00\x01binary"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        raw = self._read()
        self._record("POST", raw)
        if self.path == "/api/v1/services":
            body = json.dumps({"id": 99}).encode()
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.endswith("/imports"):
            body = json.dumps({"added": 1, "skipped": 0}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_DELETE(self) -> None:
        self._record("DELETE")
        self.send_response(204)
        self.end_headers()

    def do_OPTIONS(self) -> None:
        self._record("OPTIONS")
        self.send_response(204)
        self.send_header("Allow", "GET,POST,OPTIONS")
        self.end_headers()


@pytest.fixture()
def http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.requests = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_doctor_and_shortcuts_against_ephemeral_server(http_server, tmp_path: Path):
    address = http_server.server_address
    host = address[0]
    port = int(address[1])
    env = {
        "SERVICE_MANAGER_URL": f"http://{host}:{port}",
        "SERVICE_MANAGER_API_KEY": "smk_v1_" + ("B" * 43),
    }
    out = io.StringIO()
    err = io.StringIO()
    code = sm.main(["doctor"], environ=env, stdout=out, stderr=err)
    assert code == 0
    payload = json.loads(out.getvalue())
    assert payload["authenticated"] is True
    assert payload["status"] == 200
    assert "Authorization" not in out.getvalue()

    out = io.StringIO()
    code = sm.main(["services", "create", "From CLI"], environ=env, stdout=out, stderr=err)
    assert code == 0
    assert json.loads(out.getvalue()) == {"id": 99}
    post = [r for r in http_server.requests if r[0] == "POST"][-1]
    assert post[1] == "/api/v1/services"
    assert post[2].get("User-Agent") == "service-manager-api-management/1.0"
    assert post[2].get("Authorization", "").startswith("Bearer smk_v1_")
    assert json.loads(post[3].decode()) == {"name": "From CLI"}

    # delete without --yes → usage exit
    code = sm.main(["services", "delete", "1"], environ=env, stdout=io.StringIO(), stderr=io.StringIO())
    assert code == 2

    code = sm.main(["services", "delete", "1", "--yes"], environ=env, stdout=io.StringIO(), stderr=io.StringIO())
    assert code == 0
    assert any(r[0] == "DELETE" and r[1] == "/api/v1/services/1" for r in http_server.requests)

    upload = tmp_path / "file.csv"
    upload.write_bytes(b"email,password,status\n")
    out = io.StringIO()
    code = sm.main(
        ["request", "POST", "/api/v1/services/1/imports", "--form-file", f"file={upload}"],
        environ=env,
        stdout=out,
        stderr=err,
    )
    assert code == 0
    import_req = [r for r in http_server.requests if r[0] == "POST" and r[1].endswith("/imports")][-1]
    assert b'name="file"' in import_req[3]
    assert upload.read_bytes() in import_req[3]
    assert "multipart/form-data" in import_req[2].get("Content-Type", "")

    target = tmp_path / "out.bin"
    # Pre-create with wide perms; client must tighten to 0600 on write.
    target.write_bytes(b"stale")
    target.chmod(0o644)
    out = io.StringIO()
    code = sm.main(
        ["request", "GET", "/api/v1/bin", "--output", str(target)],
        environ=env,
        stdout=out,
        stderr=err,
    )
    assert code == 0
    assert target.read_bytes() == b"\x00\x01binary"
    assert out.getvalue().startswith("saved:")
    assert target.stat().st_mode & 0o777 == 0o600

    fresh = tmp_path / "fresh.bin"
    code = sm.main(
        ["request", "GET", "/api/v1/bin", "--output", str(fresh)],
        environ=env,
        stdout=io.StringIO(),
        stderr=err,
    )
    assert code == 0
    assert fresh.read_bytes() == b"\x00\x01binary"
    assert fresh.stat().st_mode & 0o777 == 0o600

    # Methods outside GET/POST/PUT/PATCH/DELETE/HEAD must still be sent.
    code = sm.main(
        ["request", "OPTIONS", "/api/v1/services"],
        environ=env,
        stdout=io.StringIO(),
        stderr=err,
    )
    assert code == 0
    assert any(r[0] == "OPTIONS" and r[1] == "/api/v1/services" for r in http_server.requests)


def test_request_preserves_mixed_case_method_on_the_wire(http_server):
    address = http_server.server_address
    host = address[0]
    port = int(address[1])
    env = {
        "SERVICE_MANAGER_URL": f"http://{host}:{port}",
        "SERVICE_MANAGER_API_KEY": "smk_v1_" + ("E" * 43),
    }
    captured: dict[str, str] = {}

    class CapturingOpener:
        def open(self, request, timeout=None):  # noqa: ANN001
            captured["method"] = request.get_method()
            # Delegate to real no-redirect opener so the server still sees the call.
            return sm.build_opener().open(request, timeout=timeout)

    # BaseHTTPRequestHandler only dispatches do_<exact>; register dynamic handler.
    def do_mixed(self) -> None:  # noqa: ANN001
        self._record("ProPFind")
        self.send_response(204)
        self.end_headers()

    _Handler.do_ProPFind = do_mixed  # type: ignore[attr-defined]
    try:
        code = sm.main(
            ["request", "ProPFind", "/api/v1/services"],
            environ=env,
            opener=CapturingOpener(),
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        assert code == 0
        assert captured["method"] == "ProPFind"
        assert any(r[0] == "ProPFind" and r[1] == "/api/v1/services" for r in http_server.requests)
    finally:
        delattr(_Handler, "do_ProPFind")


def test_redirect_does_not_forward_authorization_to_other_host():
    """Cross-host 30x must not carry Bearer to the second server."""

    sink_requests: list[tuple[str, dict[str, str]]] = []

    class Sink(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:
            return

        def do_GET(self) -> None:
            sink_requests.append((self.path, dict(self.headers)))
            body = b'{"leaked":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    sink_thread = threading.Thread(target=sink.serve_forever, daemon=True)
    sink_thread.start()

    class Redirector(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:
            return

        def do_GET(self) -> None:
            sink_host = sink.server_address[0]
            sink_port = int(sink.server_address[1])
            self.send_response(302)
            self.send_header("Location", f"http://{sink_host}:{sink_port}/api/v1/services")
            self.end_headers()

    origin = ThreadingHTTPServer(("127.0.0.1", 0), Redirector)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()
    try:
        host = origin.server_address[0]
        port = int(origin.server_address[1])
        token = "smk_v1_" + ("D" * 43)
        env = {
            "SERVICE_MANAGER_URL": f"http://{host}:{port}",
            "SERVICE_MANAGER_API_KEY": token,
        }
        err = io.StringIO()
        code = sm.main(["doctor"], environ=env, stdout=io.StringIO(), stderr=err)
        assert code == sm.EXIT_TRANSPORT
        assert "redirect" in err.getvalue().lower()
        assert token not in err.getvalue()
        assert sink_requests == []
    finally:
        origin.shutdown()
        sink.shutdown()
        origin_thread.join(timeout=5)
        sink_thread.join(timeout=5)
        origin.server_close()
        sink.server_close()


def test_main_maps_401_to_exit_3():
    class Unauthorized(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:
            return

        def do_GET(self) -> None:
            body = json.dumps({"error": {"code": "unauthorized", "message": "nope"}}).encode()
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Unauthorized)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        address = server.server_address
        host = address[0]
        port = int(address[1])
        env = {
            "SERVICE_MANAGER_URL": f"http://{host}:{port}",
            "SERVICE_MANAGER_API_KEY": "smk_v1_" + ("C" * 43),
        }
        out = io.StringIO()
        err = io.StringIO()
        code = sm.main(["doctor"], environ=env, stdout=out, stderr=err)
        assert code == sm.EXIT_AUTH
        payload = json.loads(out.getvalue())
        assert payload["status"] == 401
        assert payload["authenticated"] is False
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_skill_packaging_paths_exist():
    base = ROOT / ".agents" / "skills" / "service-manager-api-management"
    assert (base / "SKILL.md").is_file()
    assert (base / "scripts" / "service_manager_api.py").is_file()
    assert (base / "references" / "ENDPOINTS.md").is_file()
