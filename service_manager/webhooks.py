"""Durable, signed security webhook delivery engine.

This module is intentionally decoupled from Flask so it can run inside a
standalone supervised worker process. Enqueueing runs inside a caller's
transaction and performs no network I/O; delivery pins the resolved global IP
while preserving the hostname for SNI/certificate/Host, never follows
redirects, and never logs URLs, bodies, headers, or secrets.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import secrets
import socket
import sqlite3
import ssl
import threading
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from service_manager.crypto import (
    EncryptedValue,
    decrypt_secret_with_key,
    encrypt_secret_with_key,
    webhook_signing_secret_aad,
    webhook_url_aad,
)
from service_manager.db import schema_is_current, transaction

_MAX_URL_LENGTH = 2048
_SECRET_MARKERS = ("password", "secret", "token", "cipher", "nonce", "value")
_RETRY_SCHEDULE_SECONDS = (30, 60, 300, 900)
_MAX_ATTEMPTS = 5
_DELIVERY_TIMEOUT_SECONDS = 10
_STALE_LEASE_SECONDS = 60
_MAX_RESPONSE_BODY_BYTES = 64 * 1024
_IDLE_SLEEP_SECONDS = 5
_PURGE_RETENTION_DAYS = 90
_PURGE_BATCH = 500
_MAX_CONFIGS = 20
_MAX_DESCRIPTION_LENGTH = 200

_EVENT_TYPES = (
    "login_failures",
    "reveal_rate_limit",
    "authorization_failure",
    "audit_chain_degraded",
    "user_deactivated",
    "destructive_admin_action",
)

_GENERIC_ERRORS = frozenset(
    {"dns", "tls", "timeout", "connection", "redirect", "http", "disabled", "configuration_changed"}
)


class WebhookError(ValueError):
    """Raised when a webhook destination or payload is rejected."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _instance_host() -> str:
    """Best-effort PUBLIC_ORIGIN host from Flask without a hard dependency."""
    try:
        from flask import current_app

        origin = current_app.config.get("PUBLIC_ORIGIN")
    except Exception:
        return ""
    return _origin_host(origin)


def _origin_host(origin: str | None) -> str:
    if not origin:
        return ""
    try:
        return urlsplit(origin).hostname or ""
    except ValueError:
        return ""


# --------------------------------------------------------------------------
# URL validation and SSRF defenses
# --------------------------------------------------------------------------


def _resolved_addresses(hostname: str, resolver: Callable) -> list[str]:
    try:
        results = resolver(hostname, 443, proto=socket.IPPROTO_TCP)
    except Exception as error:  # noqa: BLE001 - any resolution failure rejects
        raise WebhookError("dns") from error
    addresses: list[str] = []
    for entry in results:
        sockaddr = entry[4]
        if sockaddr:
            addresses.append(sockaddr[0])
    if not addresses:
        raise WebhookError("dns")
    return addresses


def _global_addresses(hostname: str, resolver: Callable) -> list[str]:
    addresses = _resolved_addresses(hostname, resolver)
    globals_: list[str] = []
    for addr in addresses:
        try:
            parsed = ipaddress.ip_address(addr)
        except ValueError as error:
            raise WebhookError("dns") from error
        if not parsed.is_global:
            raise WebhookError("resolved address is not globally routable")
        globals_.append(addr)
    return sorted(globals_)


def validate_webhook_url(url: str, *, resolver: Callable = socket.getaddrinfo) -> str:
    """Validate an HTTPS webhook URL and return its destination hostname.

    Rejects non-HTTPS, missing/raw-IP hosts, userinfo, fragments, non-443
    ports, oversized URLs, and any hostname that resolves to a non-global or
    unresolvable address.
    """
    if not isinstance(url, str) or len(url) > _MAX_URL_LENGTH:
        raise WebhookError("invalid webhook url")
    try:
        parts = urlsplit(url)
        # Accessing .port parses the authority and may raise on a non-numeric port.
        port = parts.port
        username = parts.username
        password = parts.password
        hostname = parts.hostname
    except ValueError as error:
        # Malformed authority/port (e.g. non-numeric port) is a client error, not a 500.
        raise WebhookError("invalid webhook url") from error
    if parts.scheme != "https":
        raise WebhookError("webhook url must use https")
    if username or password:
        raise WebhookError("webhook url must not contain credentials")
    if parts.fragment:
        raise WebhookError("webhook url must not contain a fragment")
    if not hostname:
        raise WebhookError("webhook url must have a hostname")
    if port not in (None, 443):
        raise WebhookError("webhook url must use port 443")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise WebhookError("webhook url must not use a raw ip host")
    # Resolution failures / non-global addresses raise WebhookError.
    _global_addresses(hostname, resolver)
    return hostname


# --------------------------------------------------------------------------
# Enqueue
# --------------------------------------------------------------------------


def _validate_details(details: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(details, Mapping):
        raise WebhookError("webhook details must be a mapping")
    normalized: dict[str, Any] = {}
    for key, value in details.items():
        if not isinstance(key, str) or any(marker in key.lower() for marker in _SECRET_MARKERS):
            raise WebhookError("webhook details must not contain secrets")
        if isinstance(value, (str, int, float, bool)) or value is None:
            normalized[key] = value
        else:
            raise WebhookError("webhook details must contain scalar values")
    return normalized


def _canonical_payload(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def enqueue_webhook_event(
    conn: sqlite3.Connection,
    event_type: str,
    details: Mapping[str, Any],
    *,
    occurred_at: str | None = None,
    config_id: int | None = None,
) -> int:
    """Enqueue durable delivery rows inside the caller's active transaction.

    Performs no network I/O. Returns the number of delivery rows inserted.
    """
    safe_details = _validate_details(details)
    event_id = secrets.token_hex(16)
    when = occurred_at or _now()
    created = _now()
    payload = {
        "id": event_id,
        "event": event_type,
        "occurred_at": when,
        "instance": _instance_host(),
        "details": safe_details,
    }
    canonical = _canonical_payload(payload)

    if event_type == "test":
        rows = conn.execute(
            "SELECT id FROM webhook_configs WHERE id = ? AND deleted_at IS NULL",
            (config_id,),
        ).fetchall()
        config_ids = [row["id"] for row in rows]
    else:
        rows = conn.execute(
            """
            SELECT c.id AS id
            FROM webhook_configs AS c
            JOIN webhook_subscriptions AS s ON s.config_id = c.id
            WHERE c.enabled = 1 AND c.deleted_at IS NULL AND s.event_type = ?
            ORDER BY c.id
            """,
            (event_type,),
        ).fetchall()
        config_ids = [row["id"] for row in rows]

    for cid in config_ids:
        conn.execute(
            """
            INSERT INTO webhook_deliveries (
                config_id, event_type, payload_json, status, attempt_count,
                next_attempt_at, created_at
            ) VALUES (?, ?, ?, 'pending', 0, ?, ?)
            """,
            (cid, event_type, canonical, when, created),
        )
    return len(config_ids)


def record_audit_degraded(conn: sqlite3.Connection) -> bool:
    """Record an audit-chain degradation and enqueue alerts without touching the audit chain.

    Uses a direct BEGIN IMMEDIATE write transaction and a security_events marker; skips
    when a marker exists in the preceding five minutes. Returns True when it enqueued.
    """
    now = datetime.now(UTC)
    cutoff = (now - timedelta(minutes=5)).isoformat()
    conn.execute("BEGIN IMMEDIATE")
    try:
        recent = conn.execute(
            "SELECT COUNT(*) AS n FROM security_events WHERE kind='audit_degraded' AND subject='chain' AND occurred_at>=?",
            (cutoff,),
        ).fetchone()
        if (recent["n"] if isinstance(recent, sqlite3.Row) else recent[0]) > 0:
            conn.execute("COMMIT")
            return False
        conn.execute(
            "INSERT INTO security_events (kind, subject, source_ip, occurred_at) VALUES ('audit_degraded', 'chain', 'system', ?)",
            (now.isoformat(),),
        )
        enqueue_webhook_event(conn, "audit_chain_degraded", {"subject": "chain"}, occurred_at=now.isoformat())
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return True


# --------------------------------------------------------------------------
# Config management (called from the admin request path)
# --------------------------------------------------------------------------


def webhook_event_types() -> tuple[str, ...]:
    """The six selectable subscription event categories (``test`` excluded)."""
    return _EVENT_TYPES


def validate_event_types(raw: list[str]) -> list[str]:
    """Return the unique, ordered valid subscriptions, or raise on any invalid one."""
    selected = [value for value in dict.fromkeys(raw) if value]
    if not selected:
        raise WebhookError("select at least one event type")
    for value in selected:
        if value not in _EVENT_TYPES:
            raise WebhookError("invalid event type")
    return [value for value in _EVENT_TYPES if value in selected]


def _public_delivery(row: sqlite3.Row) -> dict[str, Any]:
    """Project a delivery row for display, forcing last_error to a generic literal."""
    data = dict(row)
    error = data.get("last_error")
    if error is not None and error not in _GENERIC_ERRORS:
        error = "connection"
    data["last_error"] = error
    return data


def list_webhook_configs(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Return non-deleted configs with subscriptions and delivery status counts."""
    rows = conn.execute(
        """
        SELECT id, destination_host, description, enabled, created_at, updated_at
        FROM webhook_configs
        WHERE deleted_at IS NULL
        ORDER BY id
        """
    ).fetchall()
    configs: list[dict[str, Any]] = []
    for row in rows:
        cid = row["id"]
        subs = [
            r["event_type"]
            for r in conn.execute(
                "SELECT event_type FROM webhook_subscriptions WHERE config_id = ? ORDER BY event_type",
                (cid,),
            ).fetchall()
        ]
        recent = conn.execute(
            """
            SELECT id, event_type, status, attempt_count, last_status_code, last_error,
                   created_at, delivered_at
            FROM webhook_deliveries
            WHERE config_id = ?
            ORDER BY id DESC
            LIMIT 10
            """,
            (cid,),
        ).fetchall()
        configs.append(
            {
                "id": cid,
                "destination_host": row["destination_host"],
                "description": row["description"],
                "enabled": bool(row["enabled"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "subscriptions": subs,
                "recent_deliveries": [_public_delivery(r) for r in recent],
            }
        )
    return configs


def count_active_configs(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM webhook_configs WHERE deleted_at IS NULL").fetchone()[0]


def _cancel_open_deliveries(conn: sqlite3.Connection, config_id: int, reason: str) -> None:
    """Terminal-fail every pending/retry delivery; a leased row may still finish."""
    conn.execute(
        """
        UPDATE webhook_deliveries
        SET status = 'failed', last_error = ?, next_attempt_at = next_attempt_at
        WHERE config_id = ? AND status IN ('pending', 'retry')
        """,
        (reason, config_id),
    )


def create_webhook_config(
    conn: sqlite3.Connection,
    *,
    url: str,
    description: str,
    enabled: bool,
    event_types: list[str],
    data_key_b64: str,
    resolver: Callable = socket.getaddrinfo,
) -> tuple[int, str, str, list[str]]:
    """Create a config and return ``(config_id, host, signing_secret_b64, subscriptions)``.

    The signing secret is returned exactly once; it is never persisted in plaintext
    nor re-derivable from the row. ``subscriptions`` is the normalized list actually
    stored. Caller owns the surrounding transaction.
    """
    if len(description) > _MAX_DESCRIPTION_LENGTH:
        raise WebhookError("description too long")
    subscriptions = validate_event_types(event_types)
    host = validate_webhook_url(url, resolver=resolver)
    if count_active_configs(conn) >= _MAX_CONFIGS:
        raise WebhookError("configuration limit reached")
    now = _now()
    # Insert placeholder envelopes to obtain the id used as encryption AAD.
    cur = conn.execute(
        """
        INSERT INTO webhook_configs (
            destination_host, url_ciphertext, url_nonce, url_key_version,
            description, enabled,
            signing_secret_ciphertext, signing_secret_nonce, signing_secret_key_version,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (host, b"", b"", 1, description, int(enabled), b"", b"", 1, now, now),
    )
    config_id = cur.lastrowid
    if config_id is None:
        raise RuntimeError("webhook insert did not return an id")
    secret_bytes = secrets.token_bytes(32)
    secret_b64 = _url_safe_b64_encode(secret_bytes)
    url_env = encrypt_secret_with_key(data_key_b64, url, aad=webhook_url_aad(config_id))
    sec_env = encrypt_secret_with_key(data_key_b64, secret_b64, aad=webhook_signing_secret_aad(config_id))
    conn.execute(
        """
        UPDATE webhook_configs
        SET url_ciphertext = ?, url_nonce = ?, url_key_version = ?,
            signing_secret_ciphertext = ?, signing_secret_nonce = ?, signing_secret_key_version = ?
        WHERE id = ?
        """,
        (
            url_env.ciphertext, url_env.nonce, url_env.key_version,
            sec_env.ciphertext, sec_env.nonce, sec_env.key_version,
            config_id,
        ),
    )
    for event_type in subscriptions:
        conn.execute(
            "INSERT INTO webhook_subscriptions (config_id, event_type) VALUES (?, ?)",
            (config_id, event_type),
        )
    return config_id, host, secret_b64, subscriptions


def update_webhook_config(
    conn: sqlite3.Connection,
    config_id: int,
    *,
    url: str,
    description: str,
    enabled: bool,
    event_types: list[str],
    data_key_b64: str,
    resolver: Callable = socket.getaddrinfo,
) -> tuple[str, list[str]]:
    """Update a config in place; return ``(host, subscriptions)``. Never rotates the secret.

    A blank ``url`` preserves the stored URL. Any URL replacement or a disable
    transition cancels every pending/retry delivery. Caller owns the transaction.
    """
    if len(description) > _MAX_DESCRIPTION_LENGTH:
        raise WebhookError("description too long")
    subscriptions = validate_event_types(event_types)
    row = conn.execute(
        "SELECT destination_host, enabled, url_ciphertext, url_nonce, url_key_version FROM webhook_configs WHERE id = ? AND deleted_at IS NULL",
        (config_id,),
    ).fetchone()
    if row is None:
        raise WebhookError("unknown config")
    host = row["destination_host"]
    was_enabled = bool(row["enabled"])
    now = _now()
    url_replaced = bool(url.strip())
    if url_replaced:
        host = validate_webhook_url(url, resolver=resolver)
        url_env = encrypt_secret_with_key(data_key_b64, url, aad=webhook_url_aad(config_id))
        conn.execute(
            "UPDATE webhook_configs SET destination_host = ?, url_ciphertext = ?, url_nonce = ?, url_key_version = ? WHERE id = ?",
            (host, url_env.ciphertext, url_env.nonce, url_env.key_version, config_id),
        )
    conn.execute(
        "UPDATE webhook_configs SET description = ?, enabled = ?, updated_at = ? WHERE id = ?",
        (description, int(enabled), now, config_id),
    )
    conn.execute("DELETE FROM webhook_subscriptions WHERE config_id = ?", (config_id,))
    for event_type in subscriptions:
        conn.execute(
            "INSERT INTO webhook_subscriptions (config_id, event_type) VALUES (?, ?)",
            (config_id, event_type),
        )
    if url_replaced:
        _cancel_open_deliveries(conn, config_id, "configuration_changed")
    if was_enabled and not enabled:
        _cancel_open_deliveries(conn, config_id, "disabled")
    return host, subscriptions


def delete_webhook_config(conn: sqlite3.Connection, config_id: int) -> str:
    """Soft-disable a config and cancel open deliveries; return the destination host."""
    row = conn.execute(
        "SELECT destination_host FROM webhook_configs WHERE id = ? AND deleted_at IS NULL",
        (config_id,),
    ).fetchone()
    if row is None:
        raise WebhookError("unknown config")
    now = _now()
    conn.execute(
        "UPDATE webhook_configs SET enabled = 0, deleted_at = ?, updated_at = ? WHERE id = ?",
        (now, now, config_id),
    )
    conn.execute("DELETE FROM webhook_subscriptions WHERE config_id = ?", (config_id,))
    _cancel_open_deliveries(conn, config_id, "disabled")
    return row["destination_host"]


def _url_safe_b64_encode(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


# --------------------------------------------------------------------------
# Pinned HTTPS connection
# --------------------------------------------------------------------------


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that dials a fixed IP while keeping the hostname.

    The socket is connected to ``resolved_ip`` (defeating DNS rebinding between
    validation and delivery) but SNI, certificate verification, and the Host
    header all use the original hostname. System proxies are ignored.
    """

    def __init__(self, hostname: str, resolved_ip: str, timeout: float):
        context = ssl.create_default_context()
        super().__init__(hostname, port=443, timeout=timeout, context=context)
        self._resolved_ip = resolved_ip
        self._ssl_context = context

    def connect(self) -> None:  # noqa: D401 - override
        sock = socket.create_connection((self._resolved_ip, 443), timeout=self.timeout)
        self.sock = self._ssl_context.wrap_socket(sock, server_hostname=self.host)


# --------------------------------------------------------------------------
# Delivery
# --------------------------------------------------------------------------


def _encrypted(ciphertext: bytes, nonce: bytes, key_version: int) -> EncryptedValue:
    return EncryptedValue(ciphertext=ciphertext, nonce=nonce, key_version=key_version)


def _signature(secret_bytes: bytes, payload_bytes: bytes) -> str:
    return "v1=" + hmac.new(secret_bytes, payload_bytes, hashlib.sha256).hexdigest()


def _terminal_error_for(exc: Exception) -> str:
    if isinstance(exc, WebhookError):
        return "dns"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    return "connection"


def _finalize_failure(
    conn: sqlite3.Connection,
    delivery_id: int,
    lease_token: str,
    attempt_count: int,
    error: str,
    status_code: int | None,
) -> None:
    if attempt_count >= _MAX_ATTEMPTS:
        conn.execute(
            """
            UPDATE webhook_deliveries
            SET status = 'failed', attempt_count = ?, last_error = ?,
                last_status_code = ?, lease_token = NULL, leased_at = NULL
            WHERE id = ? AND status = 'delivering' AND lease_token = ?
            """,
            (attempt_count, error, status_code, delivery_id, lease_token),
        )
    else:
        delay = _RETRY_SCHEDULE_SECONDS[attempt_count - 1]
        next_at = (datetime.now(UTC) + timedelta(seconds=delay)).isoformat()
        conn.execute(
            """
            UPDATE webhook_deliveries
            SET status = 'retry', attempt_count = ?, next_attempt_at = ?,
                last_error = ?, last_status_code = ?, lease_token = NULL, leased_at = NULL
            WHERE id = ? AND status = 'delivering' AND lease_token = ?
            """,
            (attempt_count, next_at, error, status_code, delivery_id, lease_token),
        )


def deliver_once(
    conn: sqlite3.Connection,
    delivery_id: int,
    *,
    data_key_b64: str,
    public_origin: str,
    resolver: Callable = socket.getaddrinfo,
    connection_factory: Callable = _PinnedHTTPSConnection,
) -> bool:
    """Attempt a single delivery for a leased row. Returns True on success."""
    row = conn.execute(
        """
        SELECT d.id, d.config_id, d.payload_json, d.attempt_count, d.lease_token,
               c.enabled, c.deleted_at,
               c.url_ciphertext, c.url_nonce, c.url_key_version,
               c.signing_secret_ciphertext, c.signing_secret_nonce, c.signing_secret_key_version
        FROM webhook_deliveries AS d
        JOIN webhook_configs AS c ON c.id = d.config_id
        WHERE d.id = ?
        """,
        (delivery_id,),
    ).fetchone()
    if row is None:
        return False
    lease_token = row["lease_token"]
    attempt_count = row["attempt_count"] + 1

    if not row["enabled"] or row["deleted_at"] is not None:
        with transaction(conn):
            conn.execute(
                """
                UPDATE webhook_deliveries
                SET status = 'failed', attempt_count = ?, last_error = 'disabled',
                    lease_token = NULL, leased_at = NULL
                WHERE id = ? AND status = 'delivering' AND lease_token = ?
                """,
                (attempt_count, delivery_id, lease_token),
            )
        return False

    status_code: int | None = None
    try:
        url = decrypt_secret_with_key(
            data_key_b64,
            _encrypted(row["url_ciphertext"], row["url_nonce"], row["url_key_version"]),
            aad=webhook_url_aad(row["config_id"]),
        )
        secret_b64 = decrypt_secret_with_key(
            data_key_b64,
            _encrypted(
                row["signing_secret_ciphertext"],
                row["signing_secret_nonce"],
                row["signing_secret_key_version"],
            ),
            aad=webhook_signing_secret_aad(row["config_id"]),
        )
        secret_bytes = _url_safe_b64_decode(secret_b64)

        hostname = validate_webhook_url(url, resolver=resolver)
        resolved_ip = _global_addresses(hostname, resolver)[0]
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"

        payload_bytes = row["payload_json"].encode("utf-8")
        signature = _signature(secret_bytes, payload_bytes)

        conn_out = connection_factory(hostname, resolved_ip, _DELIVERY_TIMEOUT_SECONDS)
        try:
            conn_out.request(
                "POST",
                path,
                body=payload_bytes,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "ServiceManager-Webhook/1",
                    "X-ServiceManager-Signature": signature,
                    "Host": hostname,
                },
            )
            response = conn_out.getresponse()
            status_code = int(response.status)
            # Only the status matters; cap the drain so a hostile endpoint cannot
            # balloon worker memory with an unbounded body before the timeout.
            response.read(_MAX_RESPONSE_BODY_BYTES)
        finally:
            conn_out.close()

        if 300 <= status_code < 400:
            raise WebhookError("redirect")
    except WebhookError as exc:
        error = "redirect" if str(exc) == "redirect" else "dns"
        with transaction(conn):
            _finalize_failure(conn, delivery_id, lease_token, attempt_count, error, status_code)
        return False
    except Exception as exc:  # noqa: BLE001 - any delivery error retries generically
        error = _terminal_error_for(exc)
        with transaction(conn):
            _finalize_failure(conn, delivery_id, lease_token, attempt_count, error, status_code)
        return False

    if 200 <= status_code < 300:
        with transaction(conn):
            conn.execute(
                """
                UPDATE webhook_deliveries
                SET status = 'succeeded', attempt_count = ?, last_status_code = ?,
                    last_error = NULL, delivered_at = ?, lease_token = NULL, leased_at = NULL
                WHERE id = ? AND status = 'delivering' AND lease_token = ?
                """,
                (attempt_count, status_code, _now(), delivery_id, lease_token),
            )
        return True

    with transaction(conn):
        _finalize_failure(conn, delivery_id, lease_token, attempt_count, "http", status_code)
    return False


def _url_safe_b64_decode(value: str) -> bytes:
    import base64

    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded)


# --------------------------------------------------------------------------
# Purge
# --------------------------------------------------------------------------


def purge_webhook_deliveries(conn: sqlite3.Connection, *, now: datetime) -> int:
    """Delete terminal rows older than the retention window, in batches."""
    cutoff = (now - timedelta(days=_PURGE_RETENTION_DAYS)).isoformat()
    total = 0
    while True:
        with transaction(conn):
            cursor = conn.execute(
                """
                DELETE FROM webhook_deliveries
                WHERE id IN (
                    SELECT id FROM webhook_deliveries
                    WHERE status IN ('succeeded', 'failed') AND created_at < ?
                    LIMIT ?
                )
                """,
                (cutoff, _PURGE_BATCH),
            )
            deleted = cursor.rowcount
        total += deleted
        if deleted < _PURGE_BATCH:
            break
    return total


# --------------------------------------------------------------------------
# Worker loop
# --------------------------------------------------------------------------


def _claim_one(conn: sqlite3.Connection) -> tuple[int, str] | None:
    now = datetime.now(UTC)
    now_iso = now.isoformat()
    stale_before = (now - timedelta(seconds=_STALE_LEASE_SECONDS)).isoformat()
    lease_token = secrets.token_hex(16)
    claimed: tuple[int, str] | None = None
    with transaction(conn):
        row = conn.execute(
            """
            SELECT id FROM webhook_deliveries
            WHERE (status IN ('pending', 'retry') AND next_attempt_at <= ?)
               OR (status = 'delivering' AND (leased_at IS NULL OR leased_at < ?))
            ORDER BY next_attempt_at, id
            LIMIT 1
            """,
            (now_iso, stale_before),
        ).fetchone()
        if row is not None:
            conn.execute(
                """
                UPDATE webhook_deliveries
                SET status = 'delivering', lease_token = ?, leased_at = ?
                WHERE id = ?
                """,
                (lease_token, now_iso, row["id"]),
            )
            claimed = (row["id"], lease_token)
    return claimed


def run_worker(
    database_path: str,
    data_key_b64: str,
    public_origin: str,
    stop_event: threading.Event,
    *,
    resolver: Callable = socket.getaddrinfo,
    connection_factory: Callable = _PinnedHTTPSConnection,
) -> None:
    """Poll the delivery queue until ``stop_event`` is set.

    Fatally exits if the database schema is not the current canonical schema.
    """
    conn = sqlite3.connect(database_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        if not schema_is_current(conn):
            raise RuntimeError("webhook worker requires the current database schema")

        last_purge_day: str | None = None
        while not stop_event.is_set():
            today = datetime.now(UTC).date().isoformat()
            if today != last_purge_day:
                purge_webhook_deliveries(conn, now=datetime.now(UTC))
                last_purge_day = today

            claimed = _claim_one(conn)
            if claimed is None:
                stop_event.wait(_IDLE_SLEEP_SECONDS)
                continue
            delivery_id, _lease_token = claimed
            deliver_once(
                conn,
                delivery_id,
                data_key_b64=data_key_b64,
                public_origin=public_origin,
                resolver=resolver,
                connection_factory=connection_factory,
            )
    finally:
        conn.close()
