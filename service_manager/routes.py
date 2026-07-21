from __future__ import annotations

import csv
import io
from collections import defaultdict
import sqlite3

from collections.abc import Mapping

from service_manager.auth import consume_reveal_allowance, normalize_email, source_ip
from flask import Blueprint, Response, abort, current_app, g, jsonify, redirect, render_template, request, url_for
from service_manager.audit import append_audit_event, verify_audit_chain

from service_manager.crypto import EncryptedValue, account_field_aad, account_password_aad, decrypt_secret, encrypt_secret
from service_manager.db import get_db, schema_is_current, transaction
from service_manager.imports import ImportFormatError, has_allowed_upload_mimetype, parse_import_file
from service_manager.authorization import require_role

routes = Blueprint("routes", __name__)


@routes.before_request
def guard_sensitive_route_mutations() -> None:
    if request.method != "GET":
        _require_audit_chain()

STATUS_ORDER = {"ativo": 0, "nunca": 1, "inativo": 2}
STATUS_LABELS = {"ativo": "Ativo", "nunca": "Nunca teve", "inativo": "Teve, mas inativo"}
OK_MESSAGES = {
    "account_added": "Conta adicionada.",
    "account_updated": "Conta atualizada.",
    "account_deleted": "Conta excluída.",
    "status_updated": "Status atualizado.",
    "registered_updated": "Cadastro atualizado.",
    "field_added": "Campo adicionado.",
    "field_saved": "Campo salvo.",
    "field_deleted": "Campo excluído.",
    "service_added": "Serviço criado.",
    "service_deleted": "Serviço excluído.",
}
TEMPLATE_ROWS = [
    ("email", "password", "status"),
    ("exemplo1@gmail.com", "SenhaSegura1", "nunca"),
    ("exemplo2@gmail.com", "SenhaSegura2", "ativo"),
]


def normalize_status(value: str | None) -> str | None:
    status = (value or "").strip().lower()
    return status if status in STATUS_ORDER else None


def _valid_email(value: str | None) -> str | None:
    return normalize_email(value) or None


def _valid_name(value: str | None) -> str | None:
    candidate = (value or "").strip()
    return candidate if 1 <= len(candidate) <= 100 else None


def _valid_secret(value: str | None) -> str | None:
    return value if isinstance(value, str) and len(value) <= 4096 else None


def _audit_actor() -> int | None:
    user = getattr(g, "current_user", None)
    return user["id"] if user is not None else None


def _audit(conn, *, action: str, target_type: str, target_id: int | str | None = None, metadata: Mapping[str, object] | None = None) -> int:
    return append_audit_event(conn, action=action, target_type=target_type, target_id=target_id, actor_user_id=_audit_actor(), metadata=metadata)


def _require_audit_chain() -> None:
    healthy = verify_audit_chain()
    current_app.config["AUDIT_CHAIN_HEALTHY"] = healthy
    if not healthy:
        abort(503)


def selected_service_id() -> int | None:
    conn = get_db()
    services = conn.execute("SELECT id FROM services ORDER BY name").fetchall()
    raw_candidate = request.values.get("service") or request.values.get("service_id")
    if raw_candidate is None:
        return services[0]["id"] if services else None
    try:
        candidate = int(raw_candidate)
    except (TypeError, ValueError):
        abort(404)
    if candidate <= 0 or candidate not in {service["id"] for service in services}:
        abort(404)
    return candidate


def required_service_id() -> int:
    raw_candidate = request.form.get("service_id") or request.form.get("service")
    if raw_candidate is None:
        abort(400)
    try:
        service_id = int(raw_candidate)
    except (TypeError, ValueError):
        abort(400)
    if service_id <= 0 or get_db().execute("SELECT 1 FROM services WHERE id=?", (service_id,)).fetchone() is None:
        abort(404)
    return service_id


def encrypted_account_password(account_id: int, password: str) -> tuple[bytes, bytes, int]:
    value = encrypt_secret(password, aad=account_password_aad(account_id))
    return value.ciphertext, value.nonce, value.key_version


def encrypted_field_value(account_id: int, field_id: int, value: str) -> tuple[bytes, bytes, int]:
    encrypted = encrypt_secret(value, aad=account_field_aad(account_id, field_id))
    return encrypted.ciphertext, encrypted.nonce, encrypted.key_version


def _related_account(conn, service_id: int | None, account_id: int) -> None:
    if service_id is None or conn.execute(
        "SELECT 1 FROM account_service WHERE account_id=? AND service_id=?", (account_id, service_id)
    ).fetchone() is None:
        abort(404)


def _related_field_account(conn, service_id: int | None, field_id: int, account_id: int) -> None:
    _related_account(conn, service_id, account_id)
    if conn.execute("SELECT 1 FROM custom_fields WHERE id=? AND service_id=?", (field_id, service_id)).fetchone() is None:
        abort(404)


def link_all_services(conn, account_id: int, active_service_id: int, status: str, registered: int = 0) -> None:
    for service in conn.execute("SELECT id FROM services"):
        conn.execute(
            """
            INSERT INTO account_service (account_id, service_id, status, registered)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(account_id, service_id) DO UPDATE SET status = excluded.status, registered = excluded.registered
            """,
            (account_id, service["id"], status if service["id"] == active_service_id else "nunca", registered if service["id"] == active_service_id else 0),
        )

@routes.get("/healthz")
def healthz() -> Response:
    try:
        conn = get_db()
        healthy = conn.execute("SELECT 1").fetchone() is not None and schema_is_current(conn) and verify_audit_chain(conn)
    except (sqlite3.Error, OSError, RuntimeError):
        healthy = False
    if not healthy:
        return jsonify(status="degraded"), 503
    return jsonify(status="ok")


@routes.get("/")
def index() -> str:
    conn = get_db()
    services = conn.execute("SELECT id, name FROM services ORDER BY name").fetchall()
    service_id = selected_service_id()
    rows: list[dict[str, object]] = []
    fields: list[object] = []
    counts = {status: 0 for status in STATUS_ORDER}

    if service_id is not None:
        account_rows = conn.execute(
            """
            SELECT a.id, a.email, link.status, link.registered
            FROM account_service AS link
            JOIN accounts AS a ON a.id = link.account_id
            WHERE link.service_id = ?
            """,
            (service_id,),
        ).fetchall()
        fields = conn.execute("SELECT id, name FROM custom_fields WHERE service_id = ? ORDER BY name", (service_id,)).fetchall()
        field_names = defaultdict(list)
        for row in conn.execute(
            """
            SELECT value.account_id, value.field_id, field.name,
                   value.value_ciphertext, value.value_nonce, value.value_key_version
            FROM field_values AS value
            JOIN custom_fields AS field ON field.id = value.field_id
            WHERE field.service_id = ?
            ORDER BY field.name
            """,
            (service_id,),
        ):
            value = decrypt_secret(
                EncryptedValue(row["value_ciphertext"], row["value_nonce"], row["value_key_version"]),
                aad=account_field_aad(row["account_id"], row["field_id"]),
            )
            field_names[row["account_id"]].append(
                {
                    "field_id": row["field_id"],
                    "name": row["name"],
                    "value": value,
                }
            )
        for row in sorted(account_rows, key=lambda account: (STATUS_ORDER.get(account["status"], 1), account["email"].lower())):
            counts[row["status"]] += 1
            rows.append({"id": row["id"], "email": row["email"], "status": row["status"], "registered": bool(row["registered"]), "fields": field_names[row["id"]]})
    counts["total"] = len(rows)
    current_name = next((service["name"] for service in services if service["id"] == service_id), None)
    feedback = None
    error_kind = request.args.get("error")
    error_messages = {
        "format": "formato inválido",
        "limits": "limites excedidos",
        "validation": "dados inválidos",
    }
    if error_kind in error_messages:
        feedback = f"Importação rejeitada: {error_messages[error_kind]}. 0 adicionadas; 0 ignoradas."
    elif request.args.get("added") is not None or request.args.get("skipped") is not None:
        try:
            added = max(0, int(request.args.get("added", "0")))
            skipped = max(0, int(request.args.get("skipped", "0")))
        except ValueError:
            abort(400)
        feedback = f"Importação concluída: {added} adicionadas; {skipped} ignoradas."
    elif (ok := request.args.get("ok")) in OK_MESSAGES:
        feedback = OK_MESSAGES[ok]
    return render_template("index.html", rows=rows, labels=STATUS_LABELS, counts=counts, services=services, current=service_id, current_name=current_name, service_fields=fields, feedback=feedback)


@routes.post("/add")
def add() -> Response:
    _require_audit_chain()
    conn = get_db()
    service_id = required_service_id()
    email = _valid_email(request.form.get("email"))
    password = _valid_secret(request.form.get("password", ""))
    status = normalize_status(request.form.get("status"))
    registered = 1 if request.form.get("registered") == "1" else 0
    if email is None or password is None or status is None:
        return Response("Conta inválida", status=400)
    try:
        with transaction(conn):
            account_id = conn.execute(
                "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, ?)",
                (email, b"", b"0" * 12, 1),
            ).lastrowid
            conn.execute(
                "UPDATE accounts SET password_ciphertext = ?, password_nonce = ?, password_key_version = ? WHERE id = ?",
                (*encrypted_account_password(account_id, password), account_id),
            )
            link_all_services(conn, account_id, service_id, status, registered)
            _audit(conn, action="account.created", target_type="account", target_id=account_id, metadata={"service_id": service_id})
    except Exception as error:
        if "UNIQUE" in str(error).upper():
            return Response("Email já cadastrado", status=400)
        raise
    return redirect(url_for("routes.index", service=service_id, ok="account_added"))


@routes.get("/template.csv")
@require_role("admin")
def template_csv() -> Response:
    stream = io.StringIO()
    csv.writer(stream).writerows(TEMPLATE_ROWS)
    return Response(stream.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=modelo_credenciais.csv"})


@routes.get("/template.xlsx")
@require_role("admin")
def template_xlsx() -> Response:
    from openpyxl import Workbook

    workbook = Workbook()
    worksheet = workbook.active
    for row in TEMPLATE_ROWS:
        worksheet.append(row)
    stream = io.BytesIO()
    workbook.save(stream)
    return Response(stream.getvalue(), mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": "attachment; filename=modelo_credenciais.xlsx"})


@routes.post("/import")
@require_role("admin")
def import_bulk() -> Response:
    conn = get_db()
    service_id = required_service_id()
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return redirect(url_for("routes.index", service=service_id, error="format"))
    if not has_allowed_upload_mimetype(upload.filename, upload.mimetype):
        return redirect(url_for("routes.index", service=service_id, error="format"))
    try:
        records = parse_import_file(upload.filename, upload.stream)
    except ImportFormatError as error:
        return redirect(url_for("routes.index", service=service_id, error=error.kind))

    normalized_records: list[tuple[str, str, str]] = []
    for email, password, status in records:
        normalized_email = _valid_email(email)
        normalized_status = normalize_status(status)
        if normalized_email is None or normalized_status is None or _valid_secret(password) is None:
            return redirect(url_for("routes.index", service=service_id, error="validation"))
        normalized_records.append((normalized_email, password, normalized_status))

    added = skipped = 0
    try:
        with transaction(conn):
            emails = {row["email"].casefold() for row in conn.execute("SELECT email FROM accounts")}
            for email, password, status in normalized_records:
                if email.casefold() in emails:
                    skipped += 1
                    continue
                emails.add(email.casefold())
                account_id = conn.execute(
                    "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, ?)",
                    (email, b"", b"0" * 12, 1),
                ).lastrowid
                conn.execute(
                    "UPDATE accounts SET password_ciphertext=?, password_nonce=?, password_key_version=? WHERE id=?",
                    (*encrypted_account_password(account_id, password), account_id),
                )
                link_all_services(conn, account_id, service_id, status)
                added += 1
            _audit(conn, action="accounts.imported", target_type="service", target_id=service_id, metadata={"added": added, "skipped": skipped})
    except Exception:
        current_app.logger.exception("import transaction failed")
        return redirect(url_for("routes.index", service=service_id, error="validation"))
    return redirect(url_for("routes.index", service=service_id, added=added, skipped=skipped))


@routes.post("/update/<int:item_id>")
@routes.post("/accounts/<int:item_id>")
def update(item_id: int) -> Response:
    conn = get_db()
    service_id = required_service_id()
    _related_account(conn, service_id, item_id)
    email = _valid_email(request.form.get("email"))
    password = _valid_secret(request.form.get("password", ""))
    if email is None or password is None:
        return Response("Conta inválida", status=400)
    try:
        with transaction(conn):
            if password:
                conn.execute(
                    "UPDATE accounts SET email=?, password_ciphertext=?, password_nonce=?, password_key_version=? WHERE id=?",
                    (email, *encrypted_account_password(item_id, password), item_id),
                )
            else:
                conn.execute("UPDATE accounts SET email=? WHERE id=?", (email, item_id))
            _audit(conn, action="account.updated", target_type="account", target_id=item_id, metadata={"service_id": service_id})
    except Exception as error:
        if "UNIQUE" in str(error).upper():
            return Response("Email já cadastrado", status=400)
        raise
    return redirect(url_for("routes.index", service=service_id, ok="account_updated"))


@routes.post("/accounts/<int:item_id>/status")
def update_status(item_id: int) -> Response:
    conn = get_db()
    service_id = required_service_id()
    _related_account(conn, service_id, item_id)
    status = normalize_status(request.form.get("status"))
    if status is None:
        return Response("Status inválido", status=400)
    with transaction(conn):
        conn.execute("UPDATE account_service SET status=? WHERE account_id=? AND service_id=?", (status, item_id, service_id))
        _audit(conn, action="account.status_updated", target_type="account", target_id=item_id, metadata={"service_id": service_id})
    return redirect(url_for("routes.index", service=service_id, ok="status_updated"))


@routes.post("/accounts/<int:item_id>/registered")
def update_registered(item_id: int) -> Response:
    conn = get_db()
    service_id = required_service_id()
    _related_account(conn, service_id, item_id)
    raw = request.form.get("registered", "0")
    if raw not in {"0", "1"}:
        return Response("Cadastro inválido", status=400)
    registered = int(raw)
    with transaction(conn):
        conn.execute("UPDATE account_service SET registered=? WHERE account_id=? AND service_id=?", (registered, item_id, service_id))
        _audit(conn, action="account.registered_updated", target_type="account", target_id=item_id, metadata={"service_id": service_id, "registered": registered})
    return redirect(url_for("routes.index", service=service_id, ok="registered_updated"))

@routes.post("/delete/<int:item_id>")
@require_role("admin")
def delete(item_id: int) -> Response:
    conn = get_db()
    service_id = required_service_id()
    _related_account(conn, service_id, item_id)
    with transaction(conn):
        conn.execute("DELETE FROM accounts WHERE id = ?", (item_id,))
        _audit(conn, action="account.deleted", target_type="account", target_id=item_id, metadata={"service_id": service_id})
    return redirect(url_for("routes.index", service=service_id, ok="account_deleted"))


@routes.post("/service/add")
def service_add() -> Response:
    name = _valid_name(request.form.get("name"))
    if name is None:
        return Response("Serviço inválido", status=400)
    conn = get_db()
    with transaction(conn):
        existing = conn.execute("SELECT id FROM services WHERE name=?", (name,)).fetchone()
        if existing is None:
            service_id = conn.execute("INSERT INTO services (name) VALUES (?)", (name,)).lastrowid
            conn.execute(
                "INSERT INTO account_service (account_id, service_id, status) SELECT id, ?, 'nunca' FROM accounts",
                (service_id,),
            )
            _audit(conn, action="service.created", target_type="service", target_id=service_id)
        else:
            service_id = existing["id"]
    return redirect(url_for("routes.index", ok="service_added", service=service_id))


@routes.post("/service/delete/<int:service_id>")
@require_role("admin")
def service_delete(service_id: int) -> Response:
    conn = get_db()
    with transaction(conn):
        if conn.execute("SELECT 1 FROM services WHERE id=?", (service_id,)).fetchone() is None:
            abort(404)
        conn.execute("DELETE FROM services WHERE id = ?", (service_id,))
        _audit(conn, action="service.deleted", target_type="service", target_id=service_id)
    return redirect(url_for("routes.index", ok="service_deleted"))


@routes.post("/field/add")
def field_add() -> Response:
    conn = get_db()
    service_id = required_service_id()
    name = _valid_name(request.form.get("name"))
    value = _valid_secret(request.form.get("value", ""))
    raw_ids = request.form.getlist("account_ids")
    try:
        account_ids = [int(raw) for raw in raw_ids]
    except (TypeError, ValueError):
        return Response("Campo inválido", status=400)
    if name is None or value is None or not account_ids or any(account_id <= 0 for account_id in account_ids):
        return Response("Campo inválido", status=400)
    with transaction(conn):
        for account_id in account_ids:
            _related_account(conn, service_id, account_id)
        field = conn.execute("SELECT id FROM custom_fields WHERE service_id=? AND name=?", (service_id, name)).fetchone()
        field_id = field["id"] if field else conn.execute(
            "INSERT INTO custom_fields (service_id, name) VALUES (?, ?)", (service_id, name)
        ).lastrowid
        for account_id in account_ids:
            encrypted = encrypted_field_value(account_id, field_id, value)
            conn.execute(
                "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, ?) ON CONFLICT(field_id, account_id) DO UPDATE SET value_ciphertext=excluded.value_ciphertext, value_nonce=excluded.value_nonce, value_key_version=excluded.value_key_version",
                (field_id, account_id, *encrypted),
            )
        _audit(conn, action="field.created", target_type="field", target_id=field_id, metadata={"service_id": service_id, "accounts": len(account_ids)})
    return redirect(url_for("routes.index", service=service_id, ok="field_added"))


@routes.post("/field/update/<int:field_id>/<int:account_id>")
def field_update(field_id: int, account_id: int) -> Response:
    conn = get_db()
    service_id = required_service_id()
    _related_field_account(conn, service_id, field_id, account_id)
    value = _valid_secret(request.form.get("value", ""))
    if value is None:
        return Response("Campo inválido", status=400)
    with transaction(conn):
        field = conn.execute("SELECT id FROM custom_fields WHERE id=? AND service_id=?", (field_id, service_id)).fetchone()
        if field is None:
            abort(404)
        encrypted = encrypted_field_value(account_id, field_id, value)
        conn.execute(
            "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, ?) ON CONFLICT(field_id, account_id) DO UPDATE SET value_ciphertext=excluded.value_ciphertext, value_nonce=excluded.value_nonce, value_key_version=excluded.value_key_version",
            (field_id, account_id, *encrypted),
        )
        _audit(conn, action="field.updated", target_type="field_value", target_id=f"{field_id}:{account_id}", metadata={"service_id": service_id})
    return redirect(url_for("routes.index", service=service_id, ok="field_saved"))


@routes.post("/field/delete/<int:field_id>/<int:account_id>")
@require_role("admin")
def field_delete(field_id: int, account_id: int) -> Response:
    conn = get_db()
    service_id = required_service_id()
    _related_field_account(conn, service_id, field_id, account_id)
    with transaction(conn):
        conn.execute("DELETE FROM field_values WHERE field_id=? AND account_id=?", (field_id, account_id))
        if not conn.execute("SELECT 1 FROM field_values WHERE field_id=?", (field_id,)).fetchone():
            conn.execute("DELETE FROM custom_fields WHERE id=?", (field_id,))
        _audit(conn, action="field.deleted", target_type="field_value", target_id=f"{field_id}:{account_id}", metadata={"service_id": service_id})
    return redirect(url_for("routes.index", service=service_id, ok="field_deleted"))


@routes.post("/api/accounts/<int:account_id>/secrets/password/reveal")
def reveal_password(account_id: int) -> Response:
    _require_audit_chain()
    user = g.current_user
    conn = get_db()
    with transaction(conn):
        if not consume_reveal_allowance(conn, user_id=user["id"], ip=source_ip()):
            return Response("Muitas tentativas", status=429)
        row = conn.execute(
            "SELECT password_ciphertext, password_nonce, password_key_version FROM accounts WHERE id=?", (account_id,)
        ).fetchone()
        if row is None:
            abort(404)
        value = decrypt_secret(
            EncryptedValue(row["password_ciphertext"], row["password_nonce"], row["password_key_version"]),
            aad=account_password_aad(account_id),
        )
        _audit(conn, action="secret.revealed", target_type="account_password", target_id=account_id)
    response = jsonify(value=value, expires_in=30)
    response.headers["Cache-Control"] = "no-store, private"
    return response
