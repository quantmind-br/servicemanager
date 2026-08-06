#!/usr/bin/env python3
"""Service Manager /api/v1 unrestricted admin client (stdlib only)."""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlparse

USER_AGENT = "service-manager-api-management/1.0"
API_PREFIX = "/api/v1"
TOKEN_RE = re.compile(r"smk_v1_[A-Za-z0-9_-]{43}")
# RFC 7230 token (tchar+); no CR/LF/space — any method, no local allowlist.
METHOD_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
# Headers the client must own — callers can never override these.
RESERVED_HEADERS = frozenset({"authorization", "accept", "user-agent", "content-type", "host"})
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_AUTH = 3
EXIT_CLIENT = 4
EXIT_SERVER = 5
EXIT_TRANSPORT = 6


class ClientError(Exception):
    """Config/usage error → exit 2."""

    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class Config:
    base_url: str
    api_key: str


@dataclass(frozen=True)
class HttpResult:
    method: str
    path: str
    status: int
    headers: Mapping[str, str]
    body: bytes


def redact(text: str) -> str:
    return TOKEN_RE.sub("smk_v1_[REDACTED]", text)


def load_config(environ: Mapping[str, str] | None = None) -> Config:
    env = environ if environ is not None else os.environ
    raw_url = (env.get("SERVICE_MANAGER_URL") or "").strip()
    api_key = (env.get("SERVICE_MANAGER_API_KEY") or "").strip()
    if not raw_url:
        raise ClientError("Missing SERVICE_MANAGER_URL environment variable")
    if not api_key:
        raise ClientError("Missing SERVICE_MANAGER_API_KEY environment variable")
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ClientError("SERVICE_MANAGER_URL must be an absolute http(s) URL with a host")
    if parsed.username or parsed.password:
        raise ClientError("SERVICE_MANAGER_URL must not embed credentials")
    # Drop path/query/fragment: base is scheme://host[:port] only.
    base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    return Config(base_url=base, api_key=api_key)


def normalize_api_path(path: str) -> str:
    candidate = (path or "").strip()
    if not candidate:
        raise ClientError("PATH is required")
    if "://" in candidate or candidate.startswith("//"):
        raise ClientError("Absolute URLs are not allowed; pass a path under /api/v1")
    if "\\" in candidate:
        raise ClientError("Invalid path")
    if not candidate.startswith("/"):
        candidate = f"{API_PREFIX}/{candidate.lstrip('/')}"
    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc:
        raise ClientError("Absolute URLs are not allowed; pass a path under /api/v1")
    # Normalize . / .. without resolving outside the namespace.
    parts: list[str] = []
    for segment in parsed.path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if not parts:
                raise ClientError("PATH escapes /api/v1")
            parts.pop()
            continue
        if any(ch in segment for ch in "\r\n\0"):
            raise ClientError("PATH must not contain control characters")
        parts.append(segment)
    normalized = "/" + "/".join(urllib.parse.quote(p, safe="~@$&()*!+=:;,.?'") for p in parts)
    if normalized != API_PREFIX and not normalized.startswith(API_PREFIX + "/"):
        raise ClientError("PATH must stay under /api/v1")
    if parsed.query or parsed.fragment:
        raise ClientError("Query/fragment belong in --query, not PATH")
    return normalized


def mask_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    if len(host) <= 4:
        masked_host = "***"
    else:
        masked_host = host[:2] + "***" + host[-2:]
    netloc = masked_host
    if parsed.port:
        netloc = f"{masked_host}:{parsed.port}"
    return f"{parsed.scheme}://{netloc}"


def exit_for_status(status: int) -> int:
    if 200 <= status < 300:
        return EXIT_OK
    if status == 401:
        return EXIT_AUTH
    if 400 <= status < 500:
        return EXIT_CLIENT
    if status >= 500:
        return EXIT_SERVER
    return EXIT_TRANSPORT


def parse_kv_pairs(values: Sequence[str] | None, *, flag: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for raw in values or ():
        if "=" not in raw:
            raise ClientError(f"{flag} expects KEY=VALUE, got {raw!r}")
        key, value = raw.split("=", 1)
        if not key:
            raise ClientError(f"{flag} key must be non-empty")
        pairs.append((key, value))
    return pairs


def build_multipart(field: str, file_path: Path) -> tuple[bytes, str]:
    if not file_path.is_file():
        raise ClientError(f"Upload file not found: {file_path}")
    data = file_path.read_bytes()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", field):
        raise ClientError(f"Invalid multipart field name: {field!r}")
    filename = file_path.name or "upload.bin"
    content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    boundary = f"----smapi{secrets.token_hex(16)}"
    safe_filename = filename.replace('"', "").replace("\r", "").replace("\n", "")
    disposition = f'Content-Disposition: form-data; name="{field}"; filename="{safe_filename}"'
    chunks = [
        f"--{boundary}\r\n".encode("ascii"),
        f"{disposition}\r\n".encode(),
        f"Content-Type: {content_type}\r\n\r\n".encode("ascii"),
        data,
        b"\r\n",
        f"--{boundary}--\r\n".encode("ascii"),
    ]
    body = b"".join(chunks)
    return body, f"multipart/form-data; boundary={boundary}"


def default_headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never follow redirects — urllib would re-send Authorization to Location."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        location = headers.get("Location") if headers is not None else None
        target = location or newurl
        raise ClientError(
            f"Refusing HTTP {code} redirect to {redact(str(target))} "
            "(Authorization is not forwarded off the configured host)",
            exit_code=EXIT_TRANSPORT,
        )


def build_opener(custom: Any = None) -> Any:
    if custom is not None:
        return custom
    return urllib.request.build_opener(_RejectRedirectHandler)


def perform_request(
    config: Config,
    method: str,
    path: str,
    *,
    query: Sequence[tuple[str, str]] | None = None,
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 60.0,
    opener: Any = None,
) -> HttpResult:
    api_path = normalize_api_path(path)
    query_string = urllib.parse.urlencode(list(query or ()), doseq=True)
    url = config.base_url + api_path
    if query_string:
        url = f"{url}?{query_string}"
    req_headers = default_headers(config.api_key)
    if headers:
        for name, value in headers.items():
            req_headers[name] = value
    request = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    active = build_opener(opener)
    try:
        with active.open(request, timeout=timeout) as response:
            raw = response.read()
            status = getattr(response, "status", None) or response.getcode()
            header_map = {k: v for k, v in response.headers.items()}
            return HttpResult(method=method, path=api_path, status=int(status), headers=header_map, body=raw)
    except urllib.error.HTTPError as error:
        raw = error.read() if hasattr(error, "read") else b""
        try:
            raw = raw if isinstance(raw, (bytes, bytearray)) else bytes(raw)
        except (TypeError, ValueError):
            raw = b""
        header_map = {k: v for k, v in getattr(error, "headers", {}).items()} if error.headers else {}
        return HttpResult(method=method, path=api_path, status=int(error.code), headers=header_map, body=bytes(raw))
    except urllib.error.URLError as error:
        raise ClientError(f"Transport error: {redact(str(error.reason))}", exit_code=EXIT_TRANSPORT) from error
    except TimeoutError as error:
        raise ClientError("Transport error: request timed out", exit_code=EXIT_TRANSPORT) from error
    except OSError as error:
        raise ClientError(f"Transport error: {redact(str(error))}", exit_code=EXIT_TRANSPORT) from error


def format_body_for_error(body: bytes, limit: int = 800) -> str:
    if not body:
        return ""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = body[:limit].decode("utf-8", errors="replace")
    else:
        try:
            parsed = json.loads(text)
            text = json.dumps(parsed, ensure_ascii=False, indent=2)
        except json.JSONDecodeError:
            pass
    text = redact(text)
    if len(text) > limit:
        return text[:limit] + "…"
    return text


def write_private_file(path: Path, data: bytes) -> None:
    """Write bytes to path with mode 0600 (create or tighten existing)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except OSError:
        os.close(fd)
        raise
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def emit_success(result: HttpResult, output: Path | None, stdout=None, stderr=None) -> int:
    out = stdout or sys.stdout
    _ = stderr
    content_type = (result.headers.get("Content-Type") or result.headers.get("content-type") or "").lower()
    is_json = "application/json" in content_type or (
        result.body[:1] in (b"{", b"[") and b"\0" not in result.body[:64]
    )
    if output is not None:
        write_private_file(output, result.body)
        print(f"saved: {output} ({len(result.body)} bytes)", file=out)
        return exit_for_status(result.status)

    if not result.body:
        if result.status != 204:
            print(f"(empty body, HTTP {result.status})", file=out)
        return exit_for_status(result.status)

    if is_json:
        try:
            parsed = json.loads(result.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            # Fall through to raw bytes on stdout buffer.
            pass
        else:
            print(json.dumps(parsed, ensure_ascii=False, indent=2), file=out)
            return exit_for_status(result.status)

    # Non-JSON without --output: write bytes to stdout buffer without destructive decode.
    buffer = getattr(out, "buffer", None)
    if buffer is not None:
        buffer.write(result.body)
        if not result.body.endswith(b"\n"):
            buffer.write(b"\n")
        buffer.flush()
    else:
        print(result.body.decode("utf-8", errors="replace"), file=out)
    return exit_for_status(result.status)


def emit_failure(result: HttpResult, stderr=None) -> int:
    err = stderr or sys.stderr
    detail = format_body_for_error(result.body)
    lines = [f"HTTP {result.status} {result.method} {result.path}"]
    if detail:
        lines.append(detail)
    print(redact("\n".join(lines)), file=err)
    return exit_for_status(result.status)


def handle_result(result: HttpResult, output: Path | None = None, stdout=None, stderr=None) -> int:
    if 200 <= result.status < 300:
        return emit_success(result, output, stdout=stdout, stderr=stderr)
    return emit_failure(result, stderr=stderr)


def cmd_doctor(config: Config, *, opener: Any = None, stdout=None, stderr=None) -> int:
    out = stdout or sys.stdout
    result = perform_request(config, "GET", "/api/v1/services", opener=opener)
    authenticated = 200 <= result.status < 300
    payload = {
        "url": mask_url(config.base_url),
        "status": result.status,
        "authenticated": authenticated,
    }
    if result.status == 401:
        payload["hint"] = "API key missing, invalid, or revoked"
    print(json.dumps(payload, ensure_ascii=False, indent=2), file=out)
    if authenticated:
        return EXIT_OK
    if result.status == 401:
        return EXIT_AUTH
    return exit_for_status(result.status)


def resolve_request_body(args: argparse.Namespace) -> tuple[bytes | None, dict[str, str]]:
    modes = [
        bool(args.json is not None),
        bool(args.json_file is not None),
        bool(args.data_file is not None),
        bool(args.form_file is not None),
    ]
    if sum(1 for flag in modes if flag) > 1:
        raise ClientError("Use only one of --json, --json-file, --data-file, --form-file")
    if args.content_type and args.data_file is None:
        raise ClientError("--content-type requires --data-file")

    extra_headers: dict[str, str] = {}
    if args.json is not None:
        try:
            parsed = json.loads(args.json)
        except json.JSONDecodeError as error:
            raise ClientError(f"Invalid --json: {error}") from error
        body = json.dumps(parsed, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        extra_headers["Content-Type"] = "application/json"
        return body, extra_headers

    if args.json_file is not None:
        path = Path(args.json_file)
        if not path.is_file():
            raise ClientError(f"--json-file not found: {path}")
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ClientError(f"Invalid JSON in {path}: {error}") from error
        body = json.dumps(parsed, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        extra_headers["Content-Type"] = "application/json"
        return body, extra_headers

    if args.form_file is not None:
        if "=" not in args.form_file:
            raise ClientError("--form-file expects FIELD=PATH")
        field, raw_path = args.form_file.split("=", 1)
        if not field or not raw_path:
            raise ClientError("--form-file expects FIELD=PATH")
        body, content_type = build_multipart(field, Path(raw_path))
        extra_headers["Content-Type"] = content_type
        return body, extra_headers

    if args.data_file is not None:
        path = Path(args.data_file)
        if not path.is_file():
            raise ClientError(f"--data-file not found: {path}")
        body = path.read_bytes()
        content_type = args.content_type or mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        extra_headers["Content-Type"] = content_type
        return body, extra_headers

    return None, extra_headers


def normalize_method(method: str) -> str:
    candidate = (method or "").strip()
    if not candidate or any(ch in candidate for ch in " \t\r\n"):
        raise ClientError(f"Invalid METHOD: {method!r}")
    if not METHOD_RE.fullmatch(candidate):
        raise ClientError(f"Invalid METHOD: {method!r}")
    return candidate


def cmd_request(config: Config, args: argparse.Namespace, *, opener: Any = None, stdout=None, stderr=None) -> int:
    method = normalize_method(args.method)
    query = parse_kv_pairs(args.query, flag="--query")
    header_pairs = parse_kv_pairs(args.header, flag="--header")
    for name, value in header_pairs:
        if name.lower() in RESERVED_HEADERS:
            raise ClientError(f"--header cannot override reserved header {name!r}")
        if not METHOD_RE.fullmatch(name):
            raise ClientError(f"Invalid header name: {name!r}")
        if any(ch in value for ch in "\r\n\0"):
            raise ClientError(f"Header value for {name!r} must not contain CR/LF")
    body, body_headers = resolve_request_body(args)
    headers = {**body_headers, **dict(header_pairs)}
    result = perform_request(
        config,
        method,
        args.path,
        query=query,
        headers=headers,
        body=body,
        opener=opener,
    )
    output = Path(args.output) if args.output else None
    return handle_result(result, output=output, stdout=stdout, stderr=stderr)


def cmd_services(config: Config, args: argparse.Namespace, *, opener: Any = None, stdout=None, stderr=None) -> int:
    action = args.services_action
    if action == "list":
        result = perform_request(config, "GET", "/api/v1/services", opener=opener)
        return handle_result(result, stdout=stdout, stderr=stderr)
    if action == "create":
        body = json.dumps({"name": args.name}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        result = perform_request(
            config,
            "POST",
            "/api/v1/services",
            headers={"Content-Type": "application/json"},
            body=body,
            opener=opener,
        )
        return handle_result(result, stdout=stdout, stderr=stderr)
    if action == "delete":
        if not args.yes:
            raise ClientError("Refusing to delete service without --yes")
        result = perform_request(config, "DELETE", f"/api/v1/services/{int(args.id)}", opener=opener)
        return handle_result(result, stdout=stdout, stderr=stderr)
    raise ClientError(f"Unknown services action: {action}")


def cmd_api_keys(config: Config, args: argparse.Namespace, *, opener: Any = None, stdout=None, stderr=None) -> int:
    action = args.api_keys_action
    if action == "list":
        result = perform_request(config, "GET", "/api/v1/api-keys", opener=opener)
        return handle_result(result, stdout=stdout, stderr=stderr)
    if action == "create":
        body = json.dumps({"name": args.name}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        result = perform_request(
            config,
            "POST",
            "/api/v1/api-keys",
            headers={"Content-Type": "application/json"},
            body=body,
            opener=opener,
        )
        return handle_result(result, stdout=stdout, stderr=stderr)
    if action == "revoke":
        if not args.yes:
            raise ClientError("Refusing to revoke API key without --yes")
        result = perform_request(config, "DELETE", f"/api/v1/api-keys/{int(args.id)}", opener=opener)
        return handle_result(result, stdout=stdout, stderr=stderr)
    raise ClientError(f"Unknown api-keys action: {action}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Service Manager /api/v1 admin client")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("doctor", help="Check URL + API key against GET /api/v1/services")

    request_parser = sub.add_parser("request", help="Generic METHOD + PATH under /api/v1")
    request_parser.add_argument("method", help="HTTP method")
    request_parser.add_argument("path", help="Path relative to /api/v1 or absolute under it")
    request_parser.add_argument("--query", action="append", default=[], help="Query KEY=VALUE (repeatable)")
    request_parser.add_argument("--json", dest="json", default=None, help="Inline JSON object/array body")
    request_parser.add_argument("--json-file", dest="json_file", default=None, help="JSON body from file")
    request_parser.add_argument("--data-file", dest="data_file", default=None, help="Raw body from file")
    request_parser.add_argument("--content-type", dest="content_type", default=None, help="Content-Type for --data-file")
    request_parser.add_argument("--form-file", dest="form_file", default=None, help="Multipart FIELD=PATH (one file)")
    request_parser.add_argument("--header", action="append", default=[], help="Extra header NAME=VALUE")
    request_parser.add_argument("--output", dest="output", default=None, help="Write response body to path")

    services = sub.add_parser("services", help="Service shortcuts")
    services_sub = services.add_subparsers(dest="services_action")
    services_sub.add_parser("list")
    create_service = services_sub.add_parser("create")
    create_service.add_argument("name")
    delete_service = services_sub.add_parser("delete")
    delete_service.add_argument("id", type=int)
    delete_service.add_argument("--yes", action="store_true")

    api_keys = sub.add_parser("api-keys", help="API key shortcuts")
    api_keys_sub = api_keys.add_subparsers(dest="api_keys_action")
    api_keys_sub.add_parser("list")
    create_key = api_keys_sub.add_parser("create")
    create_key.add_argument("name")
    revoke_key = api_keys_sub.add_parser("revoke")
    revoke_key.add_argument("id", type=int)
    revoke_key.add_argument("--yes", action="store_true")

    return parser


def main(argv: Sequence[str] | None = None, *, environ: Mapping[str, str] | None = None, opener: Any = None, stdout=None, stderr=None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not args.command:
        parser.print_help(file=stderr or sys.stderr)
        return EXIT_USAGE
    if args.command == "services" and not getattr(args, "services_action", None):
        print("usage: service_manager_api.py services {list,create,delete} ...", file=stderr or sys.stderr)
        return EXIT_USAGE
    if args.command == "api-keys" and not getattr(args, "api_keys_action", None):
        print("usage: service_manager_api.py api-keys {list,create,revoke} ...", file=stderr or sys.stderr)
        return EXIT_USAGE

    try:
        config = load_config(environ)
        if args.command == "doctor":
            return cmd_doctor(config, opener=opener, stdout=stdout, stderr=stderr)
        if args.command == "request":
            return cmd_request(config, args, opener=opener, stdout=stdout, stderr=stderr)
        if args.command == "services":
            return cmd_services(config, args, opener=opener, stdout=stdout, stderr=stderr)
        if args.command == "api-keys":
            return cmd_api_keys(config, args, opener=opener, stdout=stdout, stderr=stderr)
        raise ClientError(f"Unknown command: {args.command}")
    except ClientError as error:
        print(redact(str(error)), file=stderr or sys.stderr)
        return error.exit_code
    except BrokenPipeError:
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
