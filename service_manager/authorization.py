from __future__ import annotations

import sqlite3
from collections.abc import Mapping

from flask import abort, g, request

from service_manager.audit import append_audit_event
from service_manager.auth import require_recent_reauth, require_role
from service_manager.db import transaction
from service_manager.webhooks import enqueue_webhook_event

__all__ = [
    "require_recent_reauth",
    "require_role",
    "SERVICE_ROLE_RANK",
    "get_user_service_role",
    "accessible_services",
    "require_service_role",
    "require_account_role",
]

SERVICE_ROLE_RANK = {"viewer": 1, "editor": 2, "service_admin": 3}


def _is_global_admin(user: Mapping[str, object]) -> bool:
    return user is not None and user["role"] == "admin"


def get_user_service_role(conn: sqlite3.Connection, user: Mapping[str, object], service_id: int) -> str | None:
    """Return the caller's effective role on a service, or None with no access."""
    if _is_global_admin(user):
        return "admin"
    row = conn.execute(
        "SELECT role FROM service_members WHERE user_id = ? AND service_id = ?",
        (user["id"], service_id),
    ).fetchone()
    return row["role"] if row is not None else None


def accessible_services(conn: sqlite3.Connection, user: Mapping[str, object]) -> list[sqlite3.Row]:
    """Return the ordered services the caller may see."""
    if _is_global_admin(user):
        return conn.execute("SELECT id, name FROM services ORDER BY name").fetchall()
    return conn.execute(
        """
        SELECT s.id, s.name
        FROM services AS s
        JOIN service_members AS m ON m.service_id = s.id
        WHERE m.user_id = ?
        ORDER BY s.name
        """,
        (user["id"],),
    ).fetchall()


def _record_authorization_denial(
    conn: sqlite3.Connection,
    *,
    user_id: int,
    target_type: str,
    target_id: int | str | None,
    service_id: int | None,
    required_role: str,
) -> None:
    """Append the authorization-failure audit event and enqueue the alert atomically.

    The caller MUST already be inside ``transaction(conn)``.
    """
    append_audit_event(
        conn,
        action="authorization.failed",
        target_type=target_type,
        target_id=target_id,
        actor_user_id=user_id,
        metadata={
            "endpoint": request.endpoint or request.path,
            "method": request.method,
            "service_id": service_id,
            "required_role": required_role,
        },
    )
    enqueue_webhook_event(
        conn,
        "authorization_failure",
        {
            "actor_user_id": user_id,
            "service_id": service_id,
            "required_role": required_role,
            "endpoint": request.endpoint or request.path,
            "method": request.method,
        },
    )


def require_service_role(conn: sqlite3.Connection, service_id: int, minimum_role: str) -> str:
    """Authorize the caller on a service or abort 403; returns the granted role."""
    user = g.current_user
    role = get_user_service_role(conn, user, service_id)
    if role == "admin":
        return "admin"
    if role is not None and SERVICE_ROLE_RANK[role] >= SERVICE_ROLE_RANK[minimum_role]:
        return role
    with transaction(conn):
        _record_authorization_denial(
            conn,
            user_id=user["id"],
            target_type="service",
            target_id=service_id,
            service_id=service_id,
            required_role=minimum_role,
        )
    abort(403)


def require_account_role(
    conn: sqlite3.Connection,
    account_id: int,
    service_id: int,
    minimum_role: str,
    *,
    all_linked_services: bool = False,
) -> str:
    """Authorize an account operation initiated through ``service_id``.

    Requires the account to be linked to the initiating service, then authorizes.
    With ``all_linked_services`` the minimum rank is required on every linked
    service; global admins bypass.
    """
    user = g.current_user
    linked = conn.execute(
        "SELECT 1 FROM account_service WHERE account_id = ? AND service_id = ?",
        (account_id, service_id),
    ).fetchone()
    if linked is None:
        abort(404)
    if _is_global_admin(user):
        return "admin"
    if not all_linked_services:
        return require_service_role(conn, service_id, minimum_role)
    links = conn.execute(
        "SELECT service_id FROM account_service WHERE account_id = ?",
        (account_id,),
    ).fetchall()
    minimum_rank = SERVICE_ROLE_RANK[minimum_role]
    for link in links:
        role = get_user_service_role(conn, user, link["service_id"])
        if role != "admin" and (role is None or SERVICE_ROLE_RANK[role] < minimum_rank):
            with transaction(conn):
                _record_authorization_denial(
                    conn,
                    user_id=user["id"],
                    target_type="account",
                    target_id=account_id,
                    service_id=service_id,
                    required_role=minimum_role,
                )
            abort(403)
    return minimum_role
