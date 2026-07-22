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
import threading
import time
from dataclasses import dataclass
from flask import current_app, has_request_context, request

from service_manager.db import get_db, transaction

_ZERO_HASH = bytes(32)
_SECRET_MARKERS = ("password", "secret", "token", "cipher", "nonce", "totp", "recovery", "value")

_FULL_WALK_INTERVAL_SECONDS = 300.0
_FULL_WALK_ROW_BUDGET = 1000


@dataclass
class _ChainMark:
    verified_id: int = 0
    verified_hash: bytes = _ZERO_HASH
    last_full_walk: float = 0.0
    rows_since_full: int = 0


_MARKS: dict[str, _ChainMark] = {}
_MARKS_LOCK = threading.Lock()


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


def _walk_chain(conn: Any, key: bytes, start_id: int, previous_hash: bytes) -> tuple[bool, int, bytes]:
    """Verify rows with id > start_id. Returns (ok, last_verified_id, last_verified_hash)."""
    try:
        expected_id = start_id + 1
        last_id = start_id
        for row in conn.execute(
            "SELECT id, occurred_at, actor_user_id, action, target_type, target_id, metadata_json, source_ip, user_agent, previous_hash, event_hash FROM audit_events WHERE id > ? ORDER BY id",
            (start_id,),
        ):
            if row["id"] != expected_id or not hmac.compare_digest(bytes(row["previous_hash"]), previous_hash):
                return (False, start_id, previous_hash)
            payload = _event_payload(
                occurred_at=row["occurred_at"], actor_user_id=row["actor_user_id"], action=row["action"],
                target_type=row["target_type"], target_id=row["target_id"], metadata_json=row["metadata_json"],
                source_ip=row["source_ip"], user_agent=row["user_agent"],
            )
            expected = hmac.new(key, _canonical_bytes(payload) + previous_hash, hashlib.sha256).digest()
            if not hmac.compare_digest(bytes(row["event_hash"]), expected):
                return (False, start_id, previous_hash)
            previous_hash = bytes(row["event_hash"])
            last_id = row["id"]
            expected_id += 1
        return (True, last_id, previous_hash)
    except (TypeError, ValueError, sqlite3.Error):
        return (False, start_id, previous_hash)


def verify_audit_chain_with_key(conn: Any, key: bytes) -> bool:
    """Verify a chain using an explicit key for offline snapshot validation."""
    if not isinstance(key, bytes) or len(key) != 32:
        return False
    return _walk_chain(conn, key, 0, _ZERO_HASH)[0]


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
    last = conn.execute("SELECT id, event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    next_id = 1 if last is None else last["id"] + 1
    previous_hash = _ZERO_HASH if last is None else bytes(last["event_hash"])
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
    conn.execute(
        """
        INSERT INTO audit_events (
            id, occurred_at, actor_user_id, action, target_type, target_id, metadata_json,
            source_ip, user_agent, previous_hash, event_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (next_id, *payload.values(), previous_hash, event_hash),
    )
    return next_id


def append_audit_event_in_transaction(**event: Any) -> int:
    """Create a standalone, serialized audit transaction for non-business events."""
    conn = get_db()
    with transaction(conn):
        return append_audit_event(conn, **event)


def _cleanup_security_events(conn: Any) -> None:
    conn.execute("DELETE FROM security_events WHERE occurred_at < ?", ((datetime.now(UTC) - timedelta(hours=24)).isoformat(),))


def verify_audit_chain(conn: Any | None = None) -> bool:
    """Verify every predecessor link and HMAC without exposing audit contents."""
    try:
        key = _audit_key()
    except AuditIntegrityError:
        return False
    conn = conn or get_db()
    path = str(current_app.config["DATABASE_PATH"])
    with _MARKS_LOCK:
        mark = _MARKS.setdefault(path, _ChainMark())
        now = time.monotonic()
        needs_full = (
            mark.verified_id == 0
            or now - mark.last_full_walk > _FULL_WALK_INTERVAL_SECONDS
            or mark.rows_since_full >= _FULL_WALK_ROW_BUDGET
        )
        if not needs_full:
            try:
                anchor = conn.execute(
                    "SELECT event_hash FROM audit_events WHERE id = ?", (mark.verified_id,)
                ).fetchone()
                if anchor is None or not hmac.compare_digest(bytes(anchor[0]), mark.verified_hash):
                    needs_full = True  # truncation/rewrite of the anchor: fail closed into a full walk
            except (TypeError, ValueError, sqlite3.Error):
                return False
        if needs_full:
            ok, last_id, last_hash = _walk_chain(conn, key, 0, _ZERO_HASH)
            if ok:
                _MARKS[path] = _ChainMark(last_id, last_hash, now, 0)
            else:
                _MARKS.pop(path, None)  # next call re-walks from scratch
            return ok
        ok, last_id, last_hash = _walk_chain(conn, key, mark.verified_id, mark.verified_hash)
        if not ok:
            _MARKS.pop(path, None)
            return False
        mark.rows_since_full += last_id - mark.verified_id
        mark.verified_id, mark.verified_hash = last_id, last_hash
        return True


def audit_chain_healthy() -> bool:
    return verify_audit_chain()
