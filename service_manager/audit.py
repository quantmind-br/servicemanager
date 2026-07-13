from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
import sqlite3
from typing import Any
from flask import current_app, has_request_context, request

from service_manager.db import get_db, transaction

_ZERO_HASH = bytes(32)
_SECRET_MARKERS = ("password", "secret", "token", "cipher", "nonce", "totp", "recovery", "value")


class AuditIntegrityError(RuntimeError):
    """Raised when the cryptographically chained audit log cannot be trusted."""


def _audit_key() -> bytes:
    configured = current_app.config.get("AUDIT_KEY_V1")
    if not isinstance(configured, str) or not configured:
        raise AuditIntegrityError("AUDIT_KEY_V1 is not configured correctly")
    try:
        key = base64.b64decode(configured, validate=True)
    except (ValueError, binascii.Error) as error:
        raise AuditIntegrityError("AUDIT_KEY_V1 is not configured correctly") from error
    if len(key) != 32:
        raise AuditIntegrityError("AUDIT_KEY_V1 is not configured correctly")
    return key


def verify_audit_chain_with_key(conn: Any, key: bytes) -> bool:
    """Verify a chain using an explicit key for offline snapshot validation."""
    if not isinstance(key, bytes) or len(key) != 32:
        return False
    try:
        previous_hash = _ZERO_HASH
        expected_id = 1
        for row in conn.execute(
            "SELECT id, occurred_at, actor_user_id, action, target_type, target_id, metadata_json, source_ip, user_agent, previous_hash, event_hash FROM audit_events ORDER BY id"
        ):
            if row["id"] != expected_id or not hmac.compare_digest(bytes(row["previous_hash"]), previous_hash):
                return False
            payload = _event_payload(
                occurred_at=row["occurred_at"], actor_user_id=row["actor_user_id"], action=row["action"],
                target_type=row["target_type"], target_id=row["target_id"], metadata_json=row["metadata_json"],
                source_ip=row["source_ip"], user_agent=row["user_agent"],
            )
            expected = hmac.new(key, _canonical_bytes(payload) + previous_hash, hashlib.sha256).digest()
            if not hmac.compare_digest(bytes(row["event_hash"]), expected):
                return False
            previous_hash = bytes(row["event_hash"])
            expected_id += 1
        return True
    except (TypeError, ValueError, sqlite3.Error):
        return False


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _canonical_bytes(event: Mapping[str, Any]) -> bytes:
    return json.dumps(event, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _safe_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    if metadata is None:
        return {}
    if not isinstance(metadata, Mapping):
        raise TypeError("audit metadata must be a mapping")
    normalized: dict[str, Any] = {}
    for key, value in metadata.items():
        if not isinstance(key, str) or any(marker in key.lower() for marker in _SECRET_MARKERS):
            raise ValueError("audit metadata must not contain secrets")
        if isinstance(value, (str, int, float, bool)) or value is None:
            normalized[key] = value
        else:
            raise ValueError("audit metadata must contain scalar values")
    return normalized


def _event_payload(
    *, occurred_at: str,
    actor_user_id: int | None,
    action: str,
    target_type: str,
    target_id: str | None,
    metadata_json: str,
    source_ip: str | None,
    user_agent: str | None,
) -> dict[str, Any]:
    return {
        "occurred_at": occurred_at,
        "actor_user_id": actor_user_id,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "metadata_json": metadata_json,
        "source_ip": source_ip,
        "user_agent": user_agent,
    }


def append_audit_event(
    conn: Any,
    *,
    action: str,
    target_type: str,
    target_id: int | str | None = None,
    actor_user_id: int | None = None,
    metadata: Mapping[str, Any] | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> int:
    """Append an auditable event inside the caller's active write transaction."""
    if not isinstance(action, str) or not action or not isinstance(target_type, str) or not target_type:
        raise ValueError("audit action and target type are required")
    metadata_json = _canonical_bytes(_safe_metadata(metadata)).decode("ascii")
    _cleanup_security_events(conn)
    occurred_at = _now()
    if source_ip is None and has_request_context():
        source_ip = request.remote_addr
    if user_agent is None and has_request_context():
        user_agent = request.user_agent.string
    previous = conn.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    previous_hash = _ZERO_HASH if previous is None else bytes(previous["event_hash"])
    payload = _event_payload(
        occurred_at=occurred_at,
        actor_user_id=actor_user_id,
        action=action,
        target_type=target_type,
        target_id=None if target_id is None else str(target_id),
        metadata_json=metadata_json,
        source_ip=source_ip,
        user_agent=user_agent,
    )
    event_hash = hmac.new(_audit_key(), _canonical_bytes(payload) + previous_hash, hashlib.sha256).digest()
    return conn.execute(
        """
        INSERT INTO audit_events (
            occurred_at, actor_user_id, action, target_type, target_id, metadata_json,
            source_ip, user_agent, previous_hash, event_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (*payload.values(), previous_hash, event_hash),
    ).lastrowid


def append_audit_event_in_transaction(**event: Any) -> int:
    """Create a standalone, serialized audit transaction for non-business events."""
    conn = get_db()
    with transaction(conn):
        _cleanup_security_events(conn)
        return append_audit_event(conn, **event)


def _cleanup_security_events(conn: Any) -> None:
    conn.execute("DELETE FROM security_events WHERE occurred_at < ?", ((datetime.now(UTC) - timedelta(hours=24)).isoformat(),))


def verify_audit_chain(conn: Any | None = None) -> bool:
    """Verify every predecessor link and HMAC without exposing audit contents."""
    try:
        return verify_audit_chain_with_key(conn or get_db(), _audit_key())
    except AuditIntegrityError:
        return False


def audit_chain_healthy() -> bool:
    return verify_audit_chain()
