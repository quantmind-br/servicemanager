from __future__ import annotations

import base64
import hashlib
import secrets
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from service_manager.crypto import EncryptedValue, account_field_aad, account_password_aad, decrypt_secret, encrypt_secret
from service_manager.db import inserted_id, transaction
from service_manager.webhooks import enqueue_webhook_event


def _now_text() -> str:
    from service_manager.auth import now_text
    return now_text()


def _normalize_email(value: str | None) -> str:
    from service_manager.auth import normalize_email
    return normalize_email(value)


def _normalize_username(value: str | None) -> str:
    from service_manager.auth import normalize_username
    return normalize_username(value)


def _hash_password(password: str) -> str:
    from service_manager.auth import hash_password
    return hash_password(password)



class DomainError(Exception):
    """Domain validation or conflict error with an HTTP-ish code and Portuguese message."""

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


class NotFoundError(DomainError):
    def __init__(self, message: str = "Recurso não encontrado") -> None:
        super().__init__("not_found", message, 404)


class ConflictError(DomainError):
    def __init__(self, message: str, code: str = "conflict") -> None:
        super().__init__(code, message, 409)


@dataclass(frozen=True, slots=True)
class AuditPrincipal:
    actor_user_id: int | None = None
    api_key_id: int | None = None
    api_key_name: str | None = None


API_KEY_PREFIX = "smk_v1_"
_API_KEY_RAW_BYTES = 32
_API_KEY_TOKEN_RE_LEN = 43  # base64url without padding for 32 bytes
_MAX_SECRET_LENGTH = 4096
STATUS_ORDER = frozenset({"ativo", "nunca", "inativo"})


def _metadata_for(principal: AuditPrincipal, metadata: Mapping[str, Any] | None = None) -> dict[str, Any]:
    payload = dict(metadata or {})
    if principal.api_key_id is not None:
        payload["api_key_id"] = principal.api_key_id
    if principal.api_key_name is not None:
        payload["api_key_name"] = principal.api_key_name
    return payload


def audit(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    action: str,
    target_type: str,
    target_id: int | str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> int:
    from service_manager.audit import append_audit_event

    return append_audit_event(
        conn,
        action=action,
        target_type=target_type,
        target_id=target_id,
        actor_user_id=principal.actor_user_id,
        metadata=_metadata_for(principal, metadata),
    )


def destructive_webhook(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    payload: Mapping[str, Any],
) -> None:
    event = dict(payload)
    if principal.api_key_id is not None:
        event["api_key_id"] = principal.api_key_id
    elif principal.actor_user_id is not None:
        event["actor_user_id"] = principal.actor_user_id
    enqueue_webhook_event(conn, "destructive_admin_action", event)


def valid_name(value: str | None) -> str | None:
    candidate = (value or "").strip()
    return candidate if 1 <= len(candidate) <= 100 else None


def valid_secret(value: object) -> str | None:
    return value if isinstance(value, str) and len(value) <= _MAX_SECRET_LENGTH else None


def normalize_status(value: str | None) -> str | None:
    status = (value or "").strip().lower()
    return status if status in STATUS_ORDER else None


def valid_email(value: str | None) -> str | None:
    return _normalize_email(value) or None


def encrypted_account_password(account_id: int, password: str) -> tuple[bytes, bytes, int]:
    value = encrypt_secret(password, aad=account_password_aad(account_id))
    return value.ciphertext, value.nonce, value.key_version


def encrypted_field_value(account_id: int, field_id: int, value: str) -> tuple[bytes, bytes, int]:
    encrypted = encrypt_secret(value, aad=account_field_aad(account_id, field_id))
    return encrypted.ciphertext, encrypted.nonce, encrypted.key_version


def link_all_services(
    conn: sqlite3.Connection,
    account_id: int,
    active_service_id: int,
    status: str,
    registered: int = 0,
) -> None:
    conn.execute(
        """
        INSERT INTO account_service (account_id, service_id, status, registered)
        SELECT ?, id,
               CASE WHEN id = ? THEN ? ELSE 'nunca' END,
               CASE WHEN id = ? THEN ? ELSE 0 END
        FROM services
        """,
        (account_id, active_service_id, status, active_service_id, registered),
    )


def generate_api_key_material() -> tuple[str, bytes]:
    raw = secrets.token_bytes(_API_KEY_RAW_BYTES)
    token = API_KEY_PREFIX + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    digest = hashlib.sha256(raw).digest()
    return token, digest


def parse_api_key_token(token: str) -> bytes | None:
    if not token.startswith(API_KEY_PREFIX):
        return None
    body = token[len(API_KEY_PREFIX) :]
    if len(body) != _API_KEY_TOKEN_RE_LEN or any(ch in "+/=" for ch in body):
        return None
    padding = "=" * (-len(body) % 4)
    try:
        raw = base64.urlsafe_b64decode(body + padding)
    except (ValueError, TypeError):
        return None
    if len(raw) != _API_KEY_RAW_BYTES:
        return None
    return raw


def hash_api_key_raw(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


def create_api_key(conn: sqlite3.Connection, principal: AuditPrincipal, name: str) -> tuple[int, str]:
    normalized = valid_name(name)
    if normalized is None:
        raise DomainError("invalid_name", "Nome inválido")
    token, digest = generate_api_key_material()
    stamp = _now_text()
    try:
        key_id = inserted_id(
            conn.execute(
                "INSERT INTO api_keys (name, secret_hash, created_at) VALUES (?, ?, ?)",
                (normalized, digest, stamp),
            )
        )
    except sqlite3.IntegrityError as error:
        raise ConflictError("Nome de API key indisponível", "name_conflict") from error
    audit(
        conn,
        principal,
        action="api_key.created",
        target_type="api_key",
        target_id=key_id,
        metadata={"name": normalized},
    )
    return key_id, token


def revoke_api_key(conn: sqlite3.Connection, principal: AuditPrincipal, key_id: int) -> bool:
    """Revoke an API key. Returns True if newly revoked, False if already revoked. Raises NotFoundError."""
    row = conn.execute("SELECT id, name, revoked_at FROM api_keys WHERE id=?", (key_id,)).fetchone()
    if row is None:
        raise NotFoundError("API key não encontrada")
    if row["revoked_at"] is not None:
        return False
    stamp = _now_text()
    conn.execute("UPDATE api_keys SET revoked_at=? WHERE id=?", (stamp, key_id))
    audit(
        conn,
        principal,
        action="api_key.revoked",
        target_type="api_key",
        target_id=key_id,
        metadata={"name": row["name"]},
    )
    return True


def list_api_keys(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, name, created_at, last_used_at, revoked_at FROM api_keys ORDER BY id DESC"
    ).fetchall()


def touch_api_key_last_used(conn: sqlite3.Connection, key_id: int, *, now: str | None = None) -> None:
    stamp = now or _now_text()
    conn.execute(
        """
        UPDATE api_keys
        SET last_used_at = ?
        WHERE id = ?
          AND (last_used_at IS NULL OR last_used_at < ?)
        """,
        (stamp, key_id, (datetime.now(UTC) - timedelta(hours=1)).isoformat()),
    )


def create_service(conn: sqlite3.Connection, principal: AuditPrincipal, name: str) -> int:
    normalized = valid_name(name)
    if normalized is None:
        raise DomainError("invalid_service", "Serviço inválido")
    existing = conn.execute("SELECT id FROM services WHERE name=?", (normalized,)).fetchone()
    if existing is not None:
        return int(existing["id"])
    service_id = inserted_id(conn.execute("INSERT INTO services (name) VALUES (?)", (normalized,)))
    conn.execute(
        "INSERT INTO account_service (account_id, service_id, status) SELECT id, ?, 'nunca' FROM accounts",
        (service_id,),
    )
    audit(conn, principal, action="service.created", target_type="service", target_id=service_id)
    return service_id


def delete_service(conn: sqlite3.Connection, principal: AuditPrincipal, service_id: int) -> None:
    if conn.execute("SELECT 1 FROM services WHERE id=?", (service_id,)).fetchone() is None:
        raise NotFoundError()
    conn.execute("DELETE FROM services WHERE id = ?", (service_id,))
    audit(conn, principal, action="service.deleted", target_type="service", target_id=service_id)
    destructive_webhook(
        conn,
        principal,
        {"action": "service.deleted", "target_type": "service", "target_id": service_id, "service_id": service_id},
    )


def create_account(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    service_id: int,
    email: str,
    password: str,
    status: str,
    registered: int = 0,
) -> int:
    normalized_email = valid_email(email)
    normalized_status = normalize_status(status)
    secret = valid_secret(password)
    if normalized_email is None or secret is None or not secret or normalized_status is None:
        raise DomainError("invalid_account", "Conta inválida")
    if registered not in (0, 1):
        raise DomainError("invalid_registered", "Cadastro inválido")
    try:
        now = _now_text()
        account_id = inserted_id(
            conn.execute(
                "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version, password_changed_at) VALUES (?, ?, ?, ?, ?)",
                (normalized_email, b"", b"0" * 12, 1, now),
            )
        )
        conn.execute(
            "UPDATE accounts SET password_ciphertext = ?, password_nonce = ?, password_key_version = ? WHERE id = ?",
            (*encrypted_account_password(account_id, secret), account_id),
        )
        link_all_services(conn, account_id, service_id, normalized_status, registered)
        audit(
            conn,
            principal,
            action="account.created",
            target_type="account",
            target_id=account_id,
            metadata={"service_id": service_id},
        )
    except sqlite3.IntegrityError as error:
        if "UNIQUE" in str(error).upper():
            raise ConflictError("Email já cadastrado", "email_conflict") from error
        raise
    return account_id


def update_account(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    account_id: int,
    service_id: int,
    email: str,
    password: str | None,
) -> None:
    normalized_email = valid_email(email)
    secret = valid_secret(password if password is not None else "")
    if normalized_email is None or secret is None:
        raise DomainError("invalid_account", "Conta inválida")
    try:
        if secret:
            conn.execute(
                "UPDATE accounts SET email=?, password_ciphertext=?, password_nonce=?, password_key_version=?, password_changed_at=? WHERE id=?",
                (normalized_email, *encrypted_account_password(account_id, secret), _now_text(), account_id),
            )
            conn.execute("UPDATE account_service SET rotation_due_at=NULL WHERE account_id=?", (account_id,))
            audit(
                conn,
                principal,
                action="account.updated",
                target_type="account",
                target_id=account_id,
                metadata={"service_id": service_id, "password_changed": True},
            )
        else:
            conn.execute("UPDATE accounts SET email=? WHERE id=?", (normalized_email, account_id))
            audit(
                conn,
                principal,
                action="account.updated",
                target_type="account",
                target_id=account_id,
                metadata={"service_id": service_id, "password_changed": False},
            )
    except sqlite3.IntegrityError as error:
        if "UNIQUE" in str(error).upper():
            raise ConflictError("Email já cadastrado", "email_conflict") from error
        raise


def update_account_status(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    account_id: int,
    service_id: int,
    status: str,
) -> None:
    normalized = normalize_status(status)
    if normalized is None:
        raise DomainError("invalid_status", "Status inválido")
    conn.execute(
        "UPDATE account_service SET status=? WHERE account_id=? AND service_id=?",
        (normalized, account_id, service_id),
    )
    audit(
        conn,
        principal,
        action="account.status_updated",
        target_type="account",
        target_id=account_id,
        metadata={"service_id": service_id},
    )


def update_account_registered(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    account_id: int,
    service_id: int,
    registered: int,
) -> None:
    if registered not in (0, 1):
        raise DomainError("invalid_registered", "Cadastro inválido")
    conn.execute(
        "UPDATE account_service SET registered=? WHERE account_id=? AND service_id=?",
        (registered, account_id, service_id),
    )
    audit(
        conn,
        principal,
        action="account.registered_updated",
        target_type="account",
        target_id=account_id,
        metadata={"service_id": service_id, "registered": registered},
    )


def delete_account(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    account_id: int,
    service_id: int,
) -> None:
    conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
    audit(
        conn,
        principal,
        action="account.deleted",
        target_type="account",
        target_id=account_id,
        metadata={"service_id": service_id},
    )
    destructive_webhook(
        conn,
        principal,
        {
            "action": "account.deleted",
            "target_type": "account",
            "target_id": account_id,
            "service_id": service_id,
        },
    )


def set_service_rotation_policy(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    service_id: int,
    rotation_days: int | None,
) -> None:
    if rotation_days is not None and not (1 <= rotation_days <= 3650):
        raise DomainError("invalid_rotation", "Intervalo inválido")
    conn.execute("UPDATE services SET rotation_days=? WHERE id=?", (rotation_days, service_id))
    audit(
        conn,
        principal,
        action="rotation.policy_updated",
        target_type="service",
        target_id=service_id,
        metadata={"service_id": service_id, "rotation_days": rotation_days, "rotation_due_at": None},
    )


def set_account_rotation_policy(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    account_id: int,
    service_id: int,
    rotation_days: int | None,
    rotation_due_at: str | None,
) -> None:
    if rotation_days is not None and not (1 <= rotation_days <= 3650):
        raise DomainError("invalid_rotation", "Política de rotação inválida")
    conn.execute(
        "UPDATE account_service SET rotation_days=?, rotation_due_at=? WHERE account_id=? AND service_id=?",
        (rotation_days, rotation_due_at, account_id, service_id),
    )
    audit(
        conn,
        principal,
        action="rotation.policy_updated",
        target_type="account",
        target_id=account_id,
        metadata={"service_id": service_id, "rotation_days": rotation_days, "rotation_due_at": rotation_due_at},
    )


def complete_rotation(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    account_id: int,
    service_id: int,
    outcome: str,
    new_password: str | None = None,
) -> None:
    if outcome not in ("completed", "incomplete"):
        raise DomainError("invalid_outcome", "Resultado inválido")
    if outcome == "incomplete":
        audit(
            conn,
            principal,
            action="rotation.incomplete_marked",
            target_type="account",
            target_id=account_id,
            metadata={"service_id": service_id},
        )
        return
    secret = valid_secret(new_password or "")
    if not secret:
        raise DomainError("invalid_password", "Nova senha obrigatória")
    now = _now_text()
    conn.execute(
        "UPDATE accounts SET password_ciphertext=?, password_nonce=?, password_key_version=?, password_changed_at=? WHERE id=?",
        (*encrypted_account_password(account_id, secret), now, account_id),
    )
    conn.execute("UPDATE account_service SET rotation_due_at=NULL WHERE account_id=?", (account_id,))
    audit(
        conn,
        principal,
        action="rotation.completed",
        target_type="account",
        target_id=account_id,
        metadata={"service_id": service_id},
    )


def bulk_update_status(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    service_id: int,
    account_ids: list[int],
    status: str,
) -> None:
    normalized = normalize_status(status)
    if normalized is None:
        raise DomainError("invalid_status", "Status inválido")
    placeholders = ",".join("?" for _ in account_ids)
    conn.execute(
        f"UPDATE account_service SET status=? WHERE service_id=? AND account_id IN ({placeholders})",
        (normalized, service_id, *account_ids),
    )
    audit(
        conn,
        principal,
        action="accounts.bulk_status",
        target_type="service",
        target_id=service_id,
        metadata={"count": len(account_ids), "status": normalized},
    )


def bulk_update_registered(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    service_id: int,
    account_ids: list[int],
    registered: int,
) -> None:
    if registered not in (0, 1):
        raise DomainError("invalid_registered", "Cadastro inválido")
    placeholders = ",".join("?" for _ in account_ids)
    conn.execute(
        f"UPDATE account_service SET registered=? WHERE service_id=? AND account_id IN ({placeholders})",
        (registered, service_id, *account_ids),
    )
    audit(
        conn,
        principal,
        action="accounts.bulk_registered",
        target_type="service",
        target_id=service_id,
        metadata={"count": len(account_ids), "registered": registered},
    )


def bulk_set_field(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    service_id: int,
    account_ids: list[int],
    field_id: int,
    value: str,
) -> None:
    secret = valid_secret(value)
    if field_id <= 0 or secret is None or not secret:
        raise DomainError("invalid_field", "Campo inválido")
    if conn.execute("SELECT 1 FROM custom_fields WHERE id=? AND service_id=?", (field_id, service_id)).fetchone() is None:
        raise NotFoundError()
    for account_id in account_ids:
        encrypted = encrypted_field_value(account_id, field_id, secret)
        conn.execute(
            "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(field_id, account_id) DO UPDATE SET value_ciphertext=excluded.value_ciphertext, value_nonce=excluded.value_nonce, value_key_version=excluded.value_key_version",
            (field_id, account_id, *encrypted),
        )
    audit(
        conn,
        principal,
        action="accounts.bulk_field",
        target_type="service",
        target_id=service_id,
        metadata={"count": len(account_ids), "field_id": field_id},
    )


def bulk_create_field(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    service_id: int,
    account_ids: list[int],
    name: str,
) -> tuple[int, int]:
    normalized = valid_name(name)
    if normalized is None:
        raise DomainError("invalid_field", "Campo inválido")
    placeholders = ",".join("?" for _ in account_ids)
    field = conn.execute("SELECT id FROM custom_fields WHERE service_id=? AND name=?", (service_id, normalized)).fetchone()
    field_id = field["id"] if field else inserted_id(
        conn.execute("INSERT INTO custom_fields (service_id, name) VALUES (?, ?)", (service_id, normalized))
    )
    existing = {
        row["account_id"]
        for row in conn.execute(
            f"SELECT account_id FROM field_values WHERE field_id=? AND account_id IN ({placeholders})",
            (field_id, *account_ids),
        )
    }
    missing_account_ids = [account_id for account_id in account_ids if account_id not in existing]
    for account_id in missing_account_ids:
        encrypted = encrypted_field_value(account_id, field_id, "")
        conn.execute(
            "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(field_id, account_id) DO NOTHING",
            (field_id, account_id, *encrypted),
        )
    created_count = len(missing_account_ids)
    audit(
        conn,
        principal,
        action="accounts.bulk_field_created",
        target_type="service",
        target_id=service_id,
        metadata={"count": len(account_ids), "created_count": created_count, "field_id": field_id},
    )
    return int(field_id), created_count


def bulk_delete_accounts(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    service_id: int,
    account_ids: list[int],
) -> None:
    placeholders = ",".join("?" for _ in account_ids)
    conn.execute(f"DELETE FROM accounts WHERE id IN ({placeholders})", account_ids)
    audit(
        conn,
        principal,
        action="accounts.bulk_deleted",
        target_type="service",
        target_id=service_id,
        metadata={"count": len(account_ids), "service_id": service_id},
    )
    destructive_webhook(
        conn,
        principal,
        {
            "action": "accounts.bulk_deleted",
            "target_type": "service",
            "target_id": service_id,
            "service_id": service_id,
            "count": len(account_ids),
        },
    )


def upsert_field_values(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    service_id: int,
    name: str,
    account_ids: list[int],
    value: str,
) -> int:
    normalized = valid_name(name)
    secret = valid_secret(value)
    if normalized is None or secret is None or not account_ids or any(account_id <= 0 for account_id in account_ids):
        raise DomainError("invalid_field", "Campo inválido")
    field = conn.execute("SELECT id FROM custom_fields WHERE service_id=? AND name=?", (service_id, normalized)).fetchone()
    field_id = field["id"] if field else inserted_id(
        conn.execute("INSERT INTO custom_fields (service_id, name) VALUES (?, ?)", (service_id, normalized))
    )
    for account_id in account_ids:
        encrypted = encrypted_field_value(account_id, field_id, secret)
        conn.execute(
            "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(field_id, account_id) DO UPDATE SET value_ciphertext=excluded.value_ciphertext, value_nonce=excluded.value_nonce, value_key_version=excluded.value_key_version",
            (field_id, account_id, *encrypted),
        )
    audit(
        conn,
        principal,
        action="field.created",
        target_type="field",
        target_id=field_id,
        metadata={"service_id": service_id, "accounts": len(account_ids)},
    )
    return int(field_id)


def update_field_value(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    service_id: int,
    field_id: int,
    account_id: int,
    value: str,
) -> None:
    secret = valid_secret(value)
    if secret is None:
        raise DomainError("invalid_field", "Campo inválido")
    field = conn.execute("SELECT id FROM custom_fields WHERE id=? AND service_id=?", (field_id, service_id)).fetchone()
    if field is None:
        raise NotFoundError()
    encrypted = encrypted_field_value(account_id, field_id, secret)
    conn.execute(
        "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(field_id, account_id) DO UPDATE SET value_ciphertext=excluded.value_ciphertext, value_nonce=excluded.value_nonce, value_key_version=excluded.value_key_version",
        (field_id, account_id, *encrypted),
    )
    audit(
        conn,
        principal,
        action="field.updated",
        target_type="field_value",
        target_id=f"{field_id}:{account_id}",
        metadata={"service_id": service_id},
    )


def delete_field_value(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    service_id: int,
    field_id: int,
    account_id: int,
) -> None:
    conn.execute("DELETE FROM field_values WHERE field_id=? AND account_id=?", (field_id, account_id))
    if not conn.execute("SELECT 1 FROM field_values WHERE field_id=?", (field_id,)).fetchone():
        conn.execute("DELETE FROM custom_fields WHERE id=?", (field_id,))
    audit(
        conn,
        principal,
        action="field.deleted",
        target_type="field_value",
        target_id=f"{field_id}:{account_id}",
        metadata={"service_id": service_id},
    )
    destructive_webhook(
        conn,
        principal,
        {
            "action": "field.deleted",
            "target_type": "field_value",
            "target_id": f"{field_id}:{account_id}",
            "service_id": service_id,
        },
    )


def last_admin_change_would_break(
    conn: sqlite3.Connection,
    target: Mapping[str, Any],
    *,
    role: str | None = None,
    is_active: bool | None = None,
) -> bool:
    resulting_admin = target["role"] if role is None else role
    resulting_active = bool(target["is_active"]) if is_active is None else is_active
    if target["role"] != "admin" or not target["is_active"] or (resulting_admin == "admin" and resulting_active):
        return False
    return conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1").fetchone()[0] <= 1


def create_user(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    username: str,
    role: str,
) -> tuple[int, str]:
    normalized = _normalize_username(username)
    if not normalized or role not in {"admin", "operador"}:
        raise DomainError("invalid_user", "Usuário inválido")
    temporary_password = secrets.token_urlsafe(24)
    stamp = _now_text()
    try:
        user_id = inserted_id(
            conn.execute(
                "INSERT INTO users (username,password_hash,role,is_active,must_change_password,created_at,updated_at,password_changed_at) "
                "VALUES (?, ?, ?, 1, 1, ?, ?, ?)",
                (normalized, _hash_password(temporary_password), role, stamp, stamp, stamp),
            )
        )
        audit(
            conn,
            principal,
            action="user.created",
            target_type="user",
            target_id=user_id,
            metadata={"role": role},
        )
    except sqlite3.IntegrityError as error:
        raise ConflictError("Login indisponível", "username_conflict") from error
    return user_id, temporary_password


def change_user_role(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    user_id: int,
    role: str,
) -> None:
    if role not in {"admin", "operador"}:
        raise DomainError("invalid_role", "Papel inválido")
    target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if target is None:
        raise NotFoundError()
    if last_admin_change_would_break(conn, target, role=role):
        raise DomainError("last_admin", "Último administrador ativo", 409)
    if target["role"] == role:
        return
    if role == "admin":
        conn.execute("DELETE FROM service_members WHERE user_id=?", (user_id,))
        membership_count = 0
    else:
        conn.execute(
            "INSERT INTO service_members (user_id, service_id, role, created_at) "
            "SELECT ?, id, 'service_admin', ? FROM services",
            (user_id, _now_text()),
        )
        membership_count = conn.execute("SELECT COUNT(*) FROM service_members WHERE user_id=?", (user_id,)).fetchone()[0]
    conn.execute(
        "UPDATE users SET role=?, session_version=session_version+1, updated_at=? WHERE id=?",
        (role, _now_text(), user_id),
    )
    audit(
        conn,
        principal,
        action="user.role_changed",
        target_type="user",
        target_id=user_id,
        metadata={"role": role, "membership_count": membership_count},
    )


def change_user_active(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    user_id: int,
    is_active: bool,
) -> None:
    target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if target is None:
        raise NotFoundError()
    if last_admin_change_would_break(conn, target, is_active=is_active):
        raise DomainError("last_admin", "Último administrador ativo", 409)
    conn.execute(
        "UPDATE users SET is_active=?, session_version=session_version+1, updated_at=? WHERE id=?",
        (int(is_active), _now_text(), user_id),
    )
    audit(
        conn,
        principal,
        action="user.active_changed",
        target_type="user",
        target_id=user_id,
        metadata={"active": is_active},
    )
    if target["is_active"] and not is_active:
        payload: dict[str, Any] = {"target_user_id": user_id}
        if principal.api_key_id is not None:
            payload["api_key_id"] = principal.api_key_id
        elif principal.actor_user_id is not None:
            payload["actor_user_id"] = principal.actor_user_id
        enqueue_webhook_event(conn, "user_deactivated", payload)


def grant_membership(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    service_id: int,
    user_id: int,
    role: str,
) -> None:
    from service_manager.authorization import SERVICE_ROLE_RANK

    if role not in SERVICE_ROLE_RANK:
        raise DomainError("invalid_role", "Papel inválido")
    service = conn.execute("SELECT 1 FROM services WHERE id=?", (service_id,)).fetchone()
    target = conn.execute("SELECT role, is_active FROM users WHERE id=?", (user_id,)).fetchone()
    if service is None or target is None:
        raise NotFoundError()
    if target["role"] == "admin" or not target["is_active"]:
        raise DomainError("invalid_user", "Usuário inválido")
    existing = conn.execute(
        "SELECT role FROM service_members WHERE user_id=? AND service_id=?",
        (user_id, service_id),
    ).fetchone()
    if existing is None:
        conn.execute(
            "INSERT INTO service_members (user_id, service_id, role, created_at) VALUES (?, ?, ?, ?)",
            (user_id, service_id, role, _now_text()),
        )
        audit(
            conn,
            principal,
            action="membership.granted",
            target_type="service",
            target_id=service_id,
            metadata={"user_id": user_id, "role": role},
        )
    else:
        conn.execute(
            "UPDATE service_members SET role=? WHERE user_id=? AND service_id=?",
            (role, user_id, service_id),
        )
        audit(
            conn,
            principal,
            action="membership.role_changed",
            target_type="service",
            target_id=service_id,
            metadata={"user_id": user_id, "role": role},
        )


def revoke_membership(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    service_id: int,
    user_id: int,
) -> None:
    existing = conn.execute(
        "SELECT 1 FROM service_members WHERE user_id=? AND service_id=?",
        (user_id, service_id),
    ).fetchone()
    if existing is None:
        raise NotFoundError()
    conn.execute("DELETE FROM service_members WHERE user_id=? AND service_id=?", (user_id, service_id))
    conn.execute("DELETE FROM user_service_preferences WHERE user_id=? AND service_id=?", (user_id, service_id))
    audit(
        conn,
        principal,
        action="membership.revoked",
        target_type="service",
        target_id=service_id,
        metadata={"user_id": user_id},
    )
    destructive_webhook(
        conn,
        principal,
        {
            "action": "membership.revoked",
            "target_type": "service",
            "target_id": service_id,
            "service_id": service_id,
            "user_id": user_id,
        },
    )


def set_rotation_enabled_setting(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    enabled: bool,
) -> None:
    conn.execute(
        "INSERT INTO app_settings (key, value) VALUES ('rotation_enabled', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        ("1" if enabled else "0",),
    )
    audit(
        conn,
        principal,
        action="settings.rotation_enabled_updated",
        target_type="setting",
        target_id="rotation_enabled",
        metadata={"enabled": enabled},
    )


def update_service_preferences(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    user_id: int,
    service_ids: list[int],
    initial_service_id: int | None,
) -> None:
    from service_manager.authorization import replace_service_preferences

    replace_service_preferences(conn, user_id, service_ids, initial_service_id)
    audit(
        conn,
        principal,
        action="preferences.services_updated",
        target_type="user",
        target_id=user_id,
        metadata={"service_count": len(service_ids), "initial_service_id": initial_service_id},
    )


def _resolve_import_field_ids(conn: sqlite3.Connection, service_id: int, field_names: tuple[str, ...]) -> list[int]:
    """Create missing custom fields for the service and return ordered field ids."""
    existing = {
        row["name"]: int(row["id"])
        for row in conn.execute("SELECT id, name FROM custom_fields WHERE service_id=?", (service_id,))
    }
    field_ids: list[int] = []
    for name in field_names:
        if name in existing:
            field_ids.append(existing[name])
            continue
        field_id = inserted_id(conn.execute("INSERT INTO custom_fields (service_id, name) VALUES (?, ?)", (service_id, name)))
        existing[name] = field_id
        field_ids.append(field_id)
    return field_ids


def import_accounts(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    service_id: int,
    records: list[tuple[str, str, str, tuple[str, ...]]],
    field_names: tuple[str, ...],
) -> tuple[int, int]:
    added = skipped = 0
    changed_at = _now_text()
    emails = {row["email"].casefold() for row in conn.execute("SELECT email FROM accounts")}
    field_ids: list[int] | None = None
    for email, password, status, field_values in records:
        if email.casefold() in emails:
            skipped += 1
            continue
        emails.add(email.casefold())
        if field_ids is None:
            field_ids = _resolve_import_field_ids(conn, service_id, field_names)
        resolved_field_ids = field_ids
        account_id = inserted_id(
            conn.execute(
                "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version, password_changed_at) VALUES (?, ?, ?, ?, ?)",
                (email, b"", b"0" * 12, 1, changed_at),
            )
        )
        conn.execute(
            "UPDATE accounts SET password_ciphertext=?, password_nonce=?, password_key_version=? WHERE id=?",
            (*encrypted_account_password(account_id, password), account_id),
        )
        link_all_services(conn, account_id, service_id, status)
        for field_id, value in zip(resolved_field_ids, field_values, strict=True):
            conn.execute(
                "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, ?)",
                (field_id, account_id, *encrypted_field_value(account_id, field_id, value)),
            )
        added += 1
    audit(
        conn,
        principal,
        action="accounts.imported",
        target_type="service",
        target_id=service_id,
        metadata={"added": added, "skipped": skipped},
    )
    return added, skipped


def reveal_account_password(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    account_id: int,
    subject: str,
    source_ip: str,
    actor_user_id_for_webhook: int | None = None,
) -> str:
    """Consume reveal allowance under subject and return decrypted password."""
    cutoff = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()
    count = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE kind='reveal' AND subject=? AND occurred_at>=?",
        (subject, cutoff),
    ).fetchone()[0]
    if count >= 20:
        blocked = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE kind='reveal_blocked' AND subject=? AND source_ip=? AND occurred_at>=?",
            (subject, source_ip, cutoff),
        ).fetchone()[0]
        if blocked == 0:
            conn.execute(
                "INSERT INTO security_events (kind, subject, source_ip, occurred_at) VALUES ('reveal_blocked', ?, ?, ?)",
                (subject, source_ip, _now_text()),
            )
            payload: dict[str, Any] = {"source_ip": source_ip}
            if principal.api_key_id is not None:
                payload["api_key_id"] = principal.api_key_id
            elif actor_user_id_for_webhook is not None:
                payload["actor_user_id"] = actor_user_id_for_webhook
            enqueue_webhook_event(conn, "reveal_rate_limit", payload)
        raise DomainError("reveal_rate_limit", "Muitas tentativas", 429)
    conn.execute(
        "INSERT INTO security_events (kind, subject, source_ip, occurred_at) VALUES ('reveal', ?, ?, ?)",
        (subject, source_ip, _now_text()),
    )
    row = conn.execute(
        "SELECT password_ciphertext, password_nonce, password_key_version FROM accounts WHERE id=?",
        (account_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError()
    value = decrypt_secret(
        EncryptedValue(row["password_ciphertext"], row["password_nonce"], row["password_key_version"]),
        aad=account_password_aad(account_id),
    )
    audit(conn, principal, action="secret.revealed", target_type="account_password", target_id=account_id)
    return value



def create_webhook(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    url: str,
    description: str,
    enabled: bool,
    event_types: list[str],
    data_key_b64: str,
    resolver=None,
) -> tuple[int, str, str, list[str]]:
    from service_manager.webhooks import WebhookError, create_webhook_config
    import socket

    try:
        config_id, host, secret, subscriptions = create_webhook_config(
            conn,
            url=url,
            description=description,
            enabled=enabled,
            event_types=event_types,
            data_key_b64=data_key_b64,
            resolver=resolver if resolver is not None else socket.getaddrinfo,
        )
    except WebhookError as error:
        raise DomainError("invalid_webhook", "Integração inválida") from error
    audit(
        conn,
        principal,
        action="webhook.created",
        target_type="webhook",
        target_id=config_id,
        metadata={"destination_host": host, "enabled": enabled, "subscriptions": ",".join(subscriptions)},
    )
    return config_id, host, secret, subscriptions


def update_webhook(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    config_id: int,
    url: str,
    description: str,
    enabled: bool,
    event_types: list[str],
    data_key_b64: str,
    resolver=None,
) -> tuple[str, list[str]]:
    from service_manager.webhooks import WebhookError, update_webhook_config
    import socket

    try:
        host, subscriptions = update_webhook_config(
            conn,
            config_id,
            url=url,
            description=description,
            enabled=enabled,
            event_types=event_types,
            data_key_b64=data_key_b64,
            resolver=resolver if resolver is not None else socket.getaddrinfo,
        )
    except WebhookError as error:
        if str(error) == "unknown config":
            raise NotFoundError() from error
        raise DomainError("invalid_webhook", "Integração inválida") from error
    audit(
        conn,
        principal,
        action="webhook.updated",
        target_type="webhook",
        target_id=config_id,
        metadata={"destination_host": host, "enabled": enabled, "subscriptions": ",".join(subscriptions)},
    )
    return host, subscriptions


def delete_webhook(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    config_id: int,
) -> str:
    from service_manager.webhooks import WebhookError, delete_webhook_config

    try:
        host = delete_webhook_config(conn, config_id)
    except WebhookError as error:
        raise NotFoundError() from error
    audit(
        conn,
        principal,
        action="webhook.deleted",
        target_type="webhook",
        target_id=config_id,
        metadata={"destination_host": host, "enabled": False},
    )
    return host


def test_webhook(
    conn: sqlite3.Connection,
    principal: AuditPrincipal,
    *,
    config_id: int,
) -> None:
    config = conn.execute(
        "SELECT destination_host, enabled FROM webhook_configs WHERE id=? AND deleted_at IS NULL",
        (config_id,),
    ).fetchone()
    if config is None:
        raise NotFoundError()
    enqueue_webhook_event(conn, "test", {"config_id": config_id}, config_id=config_id)
    audit(
        conn,
        principal,
        action="webhook.test_enqueued",
        target_type="webhook",
        target_id=config_id,
        metadata={"destination_host": config["destination_host"], "enabled": bool(config["enabled"])},
    )

def principal_from_user(user: Mapping[str, Any]) -> AuditPrincipal:
    return AuditPrincipal(actor_user_id=int(user["id"]))


def principal_from_api_key(api_key: Mapping[str, Any]) -> AuditPrincipal:
    return AuditPrincipal(api_key_id=int(api_key["id"]), api_key_name=str(api_key["name"]))


def with_transaction(conn: sqlite3.Connection):
    return transaction(conn)
