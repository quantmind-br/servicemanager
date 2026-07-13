from __future__ import annotations

import secrets
import base64
import io
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any, ParamSpec, TypeVar
from flask import Blueprint, Flask, Response, abort, current_app, g, jsonify, redirect, render_template, request, session, url_for
from email_validator import EmailNotValidError, validate_email
import pyotp
import qrcode
import qrcode.image.svg
from werkzeug.middleware.proxy_fix import ProxyFix

from service_manager.crypto import (
    EncryptedValue,
    bootstrap_token_hash,
    decrypt_secret,
    encrypt_secret,
    hash_password,
    needs_password_rehash,
    user_totp_aad,
    verify_password,
)
from service_manager.db import get_db, transaction
from service_manager.audit import append_audit_event, append_audit_event_in_transaction, verify_audit_chain


auth = Blueprint("auth", __name__)

P = ParamSpec("P")
R = TypeVar("R")
_INVALID_CREDENTIALS = "Credenciais inválidas"
_MAX_SECRET_LENGTH = 4096
_SESSION_KEYS = {"user_id", "role", "session_version", "authenticated_at", "last_seen_at", "reauthenticated_at"}


def now_utc() -> datetime:
    return datetime.now(UTC)


def now_text() -> str:
    return now_utc().isoformat()


def normalize_email(value: str | None) -> str:
    candidate = (value or "").strip()
    if not candidate or len(candidate) > 254:
        return ""
    try:
        return validate_email(candidate, check_deliverability=False).normalized
    except EmailNotValidError:
        if candidate.count("@") != 1:
            return ""
        local, domain = candidate.rsplit("@", 1)
        if not domain.lower().endswith((".test", ".invalid")):
            return ""
        try:
            normalized_local = validate_email(f"{local}@example.com", check_deliverability=False).local_part
            validate_email(f"syntax-check@{domain}.example.com", check_deliverability=False)
        except EmailNotValidError:
            return ""
        return f"{normalized_local}@{domain.lower()}"


def source_ip() -> str:
    return request.remote_addr or "unknown"


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(UTC)


def _audit(conn: Any, *, action: str, target_type: str, target_id: int | str | None = None, actor_user_id: int | None = None, metadata: dict[str, Any] | None = None) -> None:
    append_audit_event(conn, action=action, target_type=target_type, target_id=target_id, actor_user_id=actor_user_id, metadata=metadata)


def _valid_secret(value: object) -> bool:
    return isinstance(value, str) and len(value) <= _MAX_SECRET_LENGTH


def _require_audit_chain() -> None:
    healthy = verify_audit_chain()
    current_app.config["AUDIT_CHAIN_HEALTHY"] = healthy
    if not healthy:
        abort(503)


def _valid_bootstrap(conn: Any) -> bool:
    return conn.execute(
        "SELECT 1 FROM bootstrap_tokens WHERE consumed_at IS NULL AND expires_at > ?", (now_text(),)
    ).fetchone() is not None


def bootstrap_available() -> bool:
    conn = get_db()
    any_activated_admin = conn.execute("SELECT 1 FROM users WHERE role = 'admin' AND is_active = 1").fetchone()
    return any_activated_admin is None and _valid_bootstrap(conn)


def _bootstrap_initial_admin(app: Flask) -> None:
    email = normalize_email(app.config.get("ADMIN_EMAIL"))
    password = app.config.get("ADMIN_INITIAL_PASSWORD")
    token = app.config.get("ADMIN_BOOTSTRAP_TOKEN")
    if not email or not _valid_secret(password) or not password or not _valid_secret(token) or not token:
        return
    with app.app_context():
        conn = get_db()
        if not verify_audit_chain(conn):
            app.config["AUDIT_CHAIN_HEALTHY"] = False
            app.logger.critical("audit chain verification failed before bootstrap initialization")
            return
        with transaction(conn):
            if conn.execute("SELECT 1 FROM users WHERE role='admin' AND is_active=1").fetchone() is not None:
                return
            users = conn.execute("SELECT id, role, is_active FROM users").fetchall()
            stamp = now_text()
            if not users:
                user_id = conn.execute(
                    "INSERT INTO users (email, password_hash, role, is_active, must_change_password, created_at, updated_at, password_changed_at) VALUES (?, ?, 'admin', 0, 1, ?, ?, ?)",
                    (email, hash_password(password), stamp, stamp, stamp),
                ).lastrowid
                _audit(conn, action="bootstrap.initialized", target_type="user", target_id=user_id)
            else:
                expired = conn.execute(
                    "SELECT user_id FROM bootstrap_tokens WHERE consumed_at IS NULL AND expires_at <= ?", (stamp,)
                ).fetchone()
                if len(users) != 1 or expired is None or users[0]["id"] != expired["user_id"] or users[0]["role"] != "admin" or users[0]["is_active"]:
                    return
                user_id = expired["user_id"]
                conn.execute("DELETE FROM bootstrap_tokens WHERE user_id=?", (user_id,))
                conn.execute(
                    "UPDATE users SET email=?, password_hash=?, must_change_password=1, totp_secret_ciphertext=NULL, totp_nonce=NULL, totp_key_version=NULL, totp_confirmed_at=NULL, last_totp_step=NULL, pending_totp_secret_ciphertext=NULL, pending_totp_nonce=NULL, pending_totp_key_version=NULL, totp_enrollment_shown_at=NULL, password_changed_at=?, updated_at=?, session_version=session_version+1 WHERE id=?",
                    (email, hash_password(password), stamp, stamp, user_id),
                )
                _audit(conn, action="bootstrap.rotated", target_type="user", target_id=user_id)
            conn.execute(
                "INSERT INTO bootstrap_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (bootstrap_token_hash(token), user_id, (now_utc() + timedelta(minutes=15)).isoformat()),
            )


def _set_session(user: Any) -> None:
    timestamp = time.time()
    session.clear()
    session.update(
        user_id=user["id"],
        role=user["role"],
        session_version=user["session_version"],
        authenticated_at=timestamp,
        last_seen_at=timestamp,
        reauthenticated_at=None,
    )


def _totp_step(secret: str, code: str, timestamp: float | None = None) -> int | None:
    timestamp = time.time() if timestamp is None else timestamp
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, for_time=timestamp, valid_window=1):
        return None
    current_step = int(timestamp // totp.interval)
    for step in (current_step - 1, current_step, current_step + 1):
        if secrets.compare_digest(totp.at(step * totp.interval), code):
            return step
    return None


def _user_secret(user: Any) -> str | None:
    if user["totp_secret_ciphertext"] is None:
        return None
    return decrypt_secret(
        EncryptedValue(user["totp_secret_ciphertext"], user["totp_nonce"], user["totp_key_version"]),
        aad=user_totp_aad(user["id"]),
    )


def _pending_totp_secret(user: Any) -> str | None:
    if user["pending_totp_secret_ciphertext"] is None:
        return None
    return decrypt_secret(
        EncryptedValue(user["pending_totp_secret_ciphertext"], user["pending_totp_nonce"], user["pending_totp_key_version"]),
        aad=user_totp_aad(user["id"]),
    )


def _rate_limited(conn: Any, *, email: str, ip: str) -> bool:
    cutoff_ip = (now_utc() - timedelta(minutes=1)).isoformat()
    cutoff_email = (now_utc() - timedelta(minutes=15)).isoformat()
    conn.execute("DELETE FROM security_events WHERE occurred_at < ?", ((now_utc() - timedelta(hours=24)).isoformat(),))
    ip_count = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE kind = 'login_failure' AND source_ip = ? AND occurred_at >= ?",
        (ip, cutoff_ip),
    ).fetchone()[0]
    account_count = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE kind = 'login_failure' AND subject = ? AND occurred_at >= ?",
        (email, cutoff_email),
    ).fetchone()[0]
    return ip_count >= 5 or account_count >= 5


def _record_login_failure(conn: Any, *, email: str, ip: str) -> None:
    conn.execute(
        "INSERT INTO security_events (kind, subject, source_ip, occurred_at) VALUES ('login_failure', ?, ?, ?)",
        (email, ip, now_text()),
    )


def consume_reveal_allowance(conn: Any, *, user_id: int, ip: str) -> bool:
    cutoff = (now_utc() - timedelta(minutes=10)).isoformat()
    conn.execute("DELETE FROM security_events WHERE occurred_at < ?", ((now_utc() - timedelta(hours=24)).isoformat(),))
    count = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE kind='reveal' AND subject=? AND occurred_at >= ?",
        (str(user_id), cutoff),
    ).fetchone()[0]
    if count >= 20:
        return False
    conn.execute(
        "INSERT INTO security_events (kind, subject, source_ip, occurred_at) VALUES ('reveal', ?, ?, ?)",
        (str(user_id), ip, now_text()),
    )
    return True
def _authentication_failure(conn: Any, *, email: str, ip: str) -> Response:
    _record_login_failure(conn, email=email, ip=ip)
    _audit(conn, action="login_failure", target_type="user", metadata={"email_present": bool(email)})
    return Response(_INVALID_CREDENTIALS, status=401)


def _authenticate(email: str, password: str, code: str, *, require_active: bool = True) -> tuple[Any | None, Response | None]:
    conn = get_db()
    ip = source_ip()
    with transaction(conn):
        if _rate_limited(conn, email=email, ip=ip):
            return None, Response("Muitas tentativas", status=429)
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user is None or (require_active and not user["is_active"]) or not verify_password(user["password_hash"], password):
            return None, _authentication_failure(conn, email=email, ip=ip)
        secret = _user_secret(user)
        step = _totp_step(secret, code) if secret else None
        if step is None or user["last_totp_step"] is not None and step <= user["last_totp_step"]:
            return None, _authentication_failure(conn, email=email, ip=ip)
        if needs_password_rehash(user["password_hash"]):
            conn.execute("UPDATE users SET password_hash=?, updated_at=? WHERE id=?", (hash_password(password), now_text(), user["id"]))
        conn.execute("UPDATE users SET last_totp_step=?, updated_at=? WHERE id=?", (step, now_text(), user["id"]))
        user = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        _audit(conn, action="login.succeeded", target_type="user", target_id=user["id"], actor_user_id=user["id"])
        return user, None


@auth.route("/login", methods=["GET", "POST"])
def login() -> Response:
    if request.method == "GET":
        return Response(render_template("login.html"), headers={"Cache-Control": "no-store, private"})
    email = normalize_email(request.form.get("email"))
    password = request.form.get("password", "")
    code = request.form.get("totp_code", "")
    if not _valid_secret(password) or not _valid_secret(code):
        conn = get_db()
        with transaction(conn):
            if _rate_limited(conn, email=email, ip=source_ip()):
                return Response("Muitas tentativas", status=429)
            return _authentication_failure(conn, email=email, ip=source_ip())
    if not code:
        conn = get_db()
        with transaction(conn):
            if _rate_limited(conn, email=email, ip=source_ip()):
                return Response("Muitas tentativas", status=429)
            onboarding_user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if onboarding_user is not None and onboarding_user["is_active"] and onboarding_user["must_change_password"] and verify_password(onboarding_user["password_hash"], password):
                _audit(conn, action="login.onboarding", target_type="user", target_id=onboarding_user["id"], actor_user_id=onboarding_user["id"])
                _set_session(onboarding_user)
                return redirect(url_for("auth.change_password"))
            return _authentication_failure(conn, email=email, ip=source_ip())
    user, error = _authenticate(email, password, code)
    if error is not None:
        return error
    if user["must_change_password"]:
        session.clear()
        return Response("Troca de senha obrigatória", status=403)
    _set_session(user)
    return redirect(url_for("routes.index"))


@auth.post("/logout")
def logout() -> Response:
    user = getattr(g, "current_user", None)
    if user is not None:
        append_audit_event_in_transaction(action="logout", target_type="user", target_id=user["id"], actor_user_id=user["id"])
    session.clear()
    return redirect(url_for("auth.login"))


def _totp_qr_svg(secret: str) -> str:
    stream = io.BytesIO()
    qrcode.make(pyotp.TOTP(secret).provisioning_uri(name="Administrador", issuer_name="Service Manager"), image_factory=qrcode.image.svg.SvgPathImage).save(stream)
    return base64.b64encode(stream.getvalue()).decode("ascii")


@auth.get("/bootstrap")
def bootstrap() -> Response:
    if not bootstrap_available():
        abort(404)
    return Response(render_template("bootstrap.html"), headers={"Cache-Control": "no-store, private"})

@auth.post("/bootstrap/issue-totp")
def issue_bootstrap_totp() -> Response:
    if not bootstrap_available():
        abort(404)
    token = request.form.get("token", "")
    initial_password = request.form.get("initial_password", "")
    if not _valid_secret(token) or not _valid_secret(initial_password):
        return Response("Bootstrap inválido", status=400)
    conn = get_db()
    with transaction(conn):
        row = conn.execute(
            "SELECT user_id FROM bootstrap_tokens WHERE token_hash=? AND consumed_at IS NULL AND expires_at > ?",
            (bootstrap_token_hash(token), now_text()),
        ).fetchone()
        user = conn.execute("SELECT * FROM users WHERE id=? AND role='admin' AND is_active=0", (row["user_id"],)).fetchone() if row else None
        if user is None or not verify_password(user["password_hash"], initial_password):
            return Response("Bootstrap inválido", status=400)
        if user["totp_enrollment_shown_at"] is not None:
            abort(404)
        secret = pyotp.random_base32()
        envelope = encrypt_secret(secret, aad=user_totp_aad(user["id"]))
        conn.execute(
            "UPDATE users SET pending_totp_secret_ciphertext=?, pending_totp_nonce=?, pending_totp_key_version=?, totp_enrollment_shown_at=? WHERE id=?",
            (envelope.ciphertext, envelope.nonce, envelope.key_version, now_text(), user["id"]),
        )
        _audit(conn, action="bootstrap.totp_issued", target_type="user", target_id=user["id"], actor_user_id=user["id"])
    return jsonify(totp_secret=secret, qr_svg_base64=_totp_qr_svg(secret))


@auth.post("/bootstrap")
def confirm_bootstrap() -> Response:
    if not bootstrap_available():
        abort(404)
    token = request.form.get("token", "")
    initial_password = request.form.get("initial_password", "")
    new_password = request.form.get("new_password", "")
    code = request.form.get("totp_code", "")
    if not all(_valid_secret(value) for value in (token, initial_password, new_password, code)):
        return Response("Bootstrap inválido", status=400)
    conn = get_db()
    with transaction(conn):
        row = conn.execute(
            "SELECT token_hash, user_id FROM bootstrap_tokens WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?",
            (bootstrap_token_hash(token), now_text()),
        ).fetchone()
        if conn.execute("SELECT 1 FROM users WHERE role='admin' AND is_active=1").fetchone() is not None:
            return Response("Bootstrap inválido", status=400)
        user = conn.execute("SELECT * FROM users WHERE id=? AND role='admin' AND is_active=0", (row["user_id"],)).fetchone() if row else None
        if user is None or len(new_password) < 16 or new_password == initial_password or not verify_password(user["password_hash"], initial_password):
            return Response("Bootstrap inválido", status=400)
        secret = _pending_totp_secret(user)
        step = _totp_step(secret, code) if secret else None
        if step is None:
            return Response("Bootstrap inválido", status=400)
        envelope = encrypt_secret(secret, aad=user_totp_aad(user["id"]))
        stamp = now_text()
        conn.execute(
            "UPDATE users SET password_hash=?, is_active=1, must_change_password=0, totp_secret_ciphertext=?, totp_nonce=?, totp_key_version=?, totp_confirmed_at=?, last_totp_step=?, pending_totp_secret_ciphertext=NULL, pending_totp_nonce=NULL, pending_totp_key_version=NULL, totp_enrollment_shown_at=NULL, password_changed_at=?, updated_at=?, session_version=session_version+1 WHERE id=?",
            (hash_password(new_password), envelope.ciphertext, envelope.nonce, envelope.key_version, stamp, step, stamp, stamp, user["id"]),
        )
        recovery_codes = [secrets.token_urlsafe(18) for _ in range(10)]
        conn.executemany("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", ((user["id"], hash_password(value)) for value in recovery_codes))
        conn.execute("UPDATE bootstrap_tokens SET consumed_at=? WHERE token_hash=?", (stamp, row["token_hash"]))
        _audit(conn, action="bootstrap", target_type="user", target_id=user["id"], actor_user_id=user["id"])
    return jsonify(recovery_codes=recovery_codes)


def _session_user() -> Any | None:
    if not _SESSION_KEYS <= set(session) or set(session) - _SESSION_KEYS - {"csrf_token"}:
        return None
    try:
        authenticated_at = float(session["authenticated_at"])
        last_seen_at = float(session["last_seen_at"])
    except (TypeError, ValueError):
        return None
    now = time.time()
    if authenticated_at > now + 60 or last_seen_at > now + 60:
        return None
    if now - authenticated_at > 8 * 60 * 60 or now - last_seen_at > 15 * 60:
        return None
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user is None or not user["is_active"] or user["role"] != session["role"] or user["session_version"] != session["session_version"]:
        return None
    session["last_seen_at"] = now
    return user


def bind_auth(app: Flask) -> None:
    trusted_proxy_hops = app.config.get("TRUSTED_PROXY_HOPS", 0)
    if not isinstance(trusted_proxy_hops, int) or trusted_proxy_hops < 0:
        raise RuntimeError("TRUSTED_PROXY_HOPS must be a non-negative integer")
    if trusted_proxy_hops:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=trusted_proxy_hops, x_proto=trusted_proxy_hops)
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_DOMAIN"] = None
    app.permanent_session_lifetime = timedelta(hours=8)
    _bootstrap_initial_admin(app)

    @app.before_request
    def guard_sensitive_mutations() -> None:
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            _require_audit_chain()

    @app.before_request
    def authenticate_protected_requests() -> Response | None:
        if request.endpoint in {"routes.healthz", "auth.login", "auth.bootstrap", "auth.issue_bootstrap_totp", "auth.confirm_bootstrap", "static"}:
            return None
        user = _session_user()
        if user is None:
            session.clear()
            return redirect(url_for("auth.login"))
        g.current_user = user
        if user["must_change_password"] and request.endpoint not in {"auth.change_password", "auth.enroll_totp", "auth.issue_enrollment_totp", "auth.enroll_totp_page", "auth.logout"}:
            abort(403)
        return None

    @app.after_request
    def protect_auth_responses(response: Response) -> Response:
        if request.endpoint in {"auth.login", "auth.bootstrap", "auth.issue_bootstrap_totp", "auth.confirm_bootstrap"} or getattr(g, "current_user", None) is not None:
            response.headers["Cache-Control"] = "no-store, private"
            response.headers["Pragma"] = "no-cache"
        return response


def require_role(*roles: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    def decorator(view: Callable[P, R]) -> Callable[P, R]:
        @wraps(view)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            user = getattr(g, "current_user", None)
            if user is None:
                return redirect(url_for("auth.login"))  # type: ignore[return-value]
            if user["role"] not in roles:
                _require_audit_chain()
                append_audit_event_in_transaction(
                    action="authorization.failed",
                    target_type="endpoint",
                    target_id=request.endpoint or request.path,
                    actor_user_id=user["id"],
                    metadata={"method": request.method},
                )
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator

def require_recent_reauth() -> Any:
    user = getattr(g, "current_user", None)
    value = session.get("reauthenticated_at")
    now = time.time()
    if user is None or not isinstance(value, (int, float)) or value > now + 60 or now - value > 5 * 60:
        abort(403)
    return user


@auth.get("/reauth")
def reauth_page() -> Response:
    return Response(render_template("reauth.html"), headers={"Cache-Control": "no-store, private"})

@auth.post("/reauth")
def reauth() -> Response:
    user = getattr(g, "current_user", None)
    if user is None:
        return redirect(url_for("auth.login"))
    email = normalize_email(user["email"])
    password = request.form.get("password", "")
    code = request.form.get("totp_code", "")
    recovery_code = request.form.get("recovery_code", "")
    if not _valid_secret(password) or not _valid_secret(code) or not _valid_secret(recovery_code):
        conn = get_db()
        with transaction(conn):
            if _rate_limited(conn, email=email, ip=source_ip()):
                return Response("Muitas tentativas", status=429)
            return _authentication_failure(conn, email=email, ip=source_ip())
    conn = get_db()
    with transaction(conn):
        if _rate_limited(conn, email=email, ip=source_ip()):
            return Response("Muitas tentativas", status=429)
        current = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        if current is None or not verify_password(current["password_hash"], password):
            return _authentication_failure(conn, email=email, ip=source_ip())
        verified = False
        if recovery_code:
            codes = conn.execute("SELECT code_hash FROM recovery_codes WHERE user_id=? AND used_at IS NULL", (current["id"],)).fetchall()
            matching = next((row for row in codes if verify_password(row["code_hash"], recovery_code)), None)
            if matching is not None:
                conn.execute("UPDATE recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL", (now_text(), current["id"], matching["code_hash"]))
                verified = True
        else:
            secret = _user_secret(current)
            step = _totp_step(secret, code) if secret else None
            if step is not None and (current["last_totp_step"] is None or step > current["last_totp_step"]):
                conn.execute("UPDATE users SET last_totp_step=?, updated_at=? WHERE id=?", (step, now_text(), current["id"]))
                verified = True
        if not verified:
            return _authentication_failure(conn, email=email, ip=source_ip())
        _audit(conn, action="reauth", target_type="user", target_id=current["id"], actor_user_id=current["id"])
    session["reauthenticated_at"] = time.time()
    return Response(status=204)


def _email_is_valid(email: str) -> bool:
    return len(email) <= 254 and bool(_EMAIL.fullmatch(email))


@auth.get("/admin/users")
@require_role("admin")
def users() -> Response:
    rows = get_db().execute("SELECT id, email, role, is_active, must_change_password FROM users ORDER BY email").fetchall()
    return jsonify(users=[dict(row) for row in rows])


@auth.post("/admin/users")
@require_role("admin")
def create_user() -> Response:
    require_recent_reauth()
    email = normalize_email(request.form.get("email"))
    role = request.form.get("role", "")
    if not email or role not in {"admin", "operador"}:
        return Response("Usuário inválido", status=400)
    temporary_password = secrets.token_urlsafe(24)
    conn = get_db()
    try:
        with transaction(conn):
            stamp = now_text()
            user_id = conn.execute("INSERT INTO users (email,password_hash,role,is_active,must_change_password,created_at,updated_at,password_changed_at) VALUES (?, ?, ?, 1, 1, ?, ?, ?)", (email, hash_password(temporary_password), role, stamp, stamp, stamp)).lastrowid
            _audit(conn, action="user.created", target_type="user", target_id=user_id, actor_user_id=getattr(g, "current_user", None)["id"], metadata={"role": role})
    except Exception as error:
        if "UNIQUE" in str(error).upper():
            return Response("Email já cadastrado", status=400)
        raise
    return jsonify(id=user_id, temporary_password=temporary_password), 201


@auth.post("/change-password")
def change_password() -> Response:
    user = getattr(g, "current_user", None)
    if user is None:
        return redirect(url_for("auth.login"))
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    if not _valid_secret(current_password) or not _valid_secret(new_password) or len(new_password) < 16:
        return Response("Senha inválida", status=400)
    conn = get_db()
    with transaction(conn):
        current = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if current is None or not verify_password(current["password_hash"], current_password):
            return Response("Senha inválida", status=400)
        if current["must_change_password"] and verify_password(current["password_hash"], new_password):
            return Response("Senha inválida", status=400)
        conn.execute("UPDATE users SET password_hash=?, must_change_password=CASE WHEN totp_secret_ciphertext IS NULL THEN 1 ELSE 0 END, password_changed_at=?, updated_at=?, session_version=session_version+1 WHERE id=?", (hash_password(new_password), now_text(), now_text(), current["id"]))
        _audit(conn, action="password.changed", target_type="user", target_id=current["id"], actor_user_id=current["id"])
    refreshed = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
    _set_session(refreshed)
    return Response(status=204)
@auth.get("/enroll-totp")
def enroll_totp_page() -> Response:
    user = getattr(g, "current_user", None)
    if user is None:
        return redirect(url_for("auth.login"))
    return Response("TOTP enrollment", headers={"Cache-Control": "no-store, private"})


@auth.post("/enroll-totp/issue")
def issue_enrollment_totp() -> Response:
    user = getattr(g, "current_user", None)
    if user is None:
        return redirect(url_for("auth.login"))
    conn = get_db()
    with transaction(conn):
        current = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if current is None or not current["must_change_password"] or current["totp_secret_ciphertext"] is not None:
            abort(403)
        if current["totp_enrollment_shown_at"] is not None:
            abort(404)
        secret = _pending_totp_secret(current)
        if secret is None:
            secret = pyotp.random_base32()
            envelope = encrypt_secret(secret, aad=user_totp_aad(current["id"]))
            conn.execute("UPDATE users SET pending_totp_secret_ciphertext=?, pending_totp_nonce=?, pending_totp_key_version=?, totp_enrollment_shown_at=? WHERE id=?", (envelope.ciphertext, envelope.nonce, envelope.key_version, now_text(), current["id"]))
        _audit(conn, action="totp.enrollment_issued", target_type="user", target_id=current["id"], actor_user_id=current["id"])
    return jsonify(totp_secret=secret)


@auth.post("/enroll-totp")
def enroll_totp() -> Response:
    user = getattr(g, "current_user", None)
    if user is None:
        return redirect(url_for("auth.login"))
    code = request.form.get("totp_code", "")
    if not _valid_secret(code):
        return Response("TOTP inválido", status=400)
    conn = get_db()
    with transaction(conn):
        current = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if current is None or not current["must_change_password"] or current["totp_secret_ciphertext"] is not None:
            abort(403)
        secret = _pending_totp_secret(current)
        step = _totp_step(secret, code) if secret else None
        if step is None:
            return Response("TOTP inválido", status=400)
        envelope = encrypt_secret(secret, aad=user_totp_aad(current["id"]))
        conn.execute("UPDATE users SET totp_secret_ciphertext=?, totp_nonce=?, totp_key_version=?, totp_confirmed_at=?, last_totp_step=?, pending_totp_secret_ciphertext=NULL, pending_totp_nonce=NULL, pending_totp_key_version=NULL, must_change_password=0, session_version=session_version+1, updated_at=? WHERE id=?", (envelope.ciphertext, envelope.nonce, envelope.key_version, now_text(), step, now_text(), current["id"]))
        conn.execute("DELETE FROM recovery_codes WHERE user_id=?", (current["id"],))
        recovery_codes = [secrets.token_urlsafe(18) for _ in range(10)]
        conn.executemany("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", ((current["id"], hash_password(value)) for value in recovery_codes))
        _audit(conn, action="totp.enrolled", target_type="user", target_id=current["id"], actor_user_id=current["id"])
    session.clear()
    return jsonify(recovery_codes=recovery_codes)


def _target_user(user_id: int) -> Any:
    target = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if target is None:
        abort(404)
    return target


def _last_admin_change_would_break(conn: Any, target: Any, *, role: str | None = None, is_active: bool | None = None) -> bool:
    resulting_admin = target["role"] if role is None else role
    resulting_active = bool(target["is_active"]) if is_active is None else is_active
    if target["role"] != "admin" or not target["is_active"] or (resulting_admin == "admin" and resulting_active):
        return False
    return conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1").fetchone()[0] <= 1


@auth.post("/admin/users/<int:user_id>/role")
@require_role("admin")
def change_role(user_id: int) -> Response:
    require_recent_reauth()
    role = request.form.get("role", "")
    if role not in {"admin", "operador"}:
        return Response("Papel inválido", status=400)
    conn = get_db()
    with transaction(conn):
        target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if target is None:
            abort(404)
        if _last_admin_change_would_break(conn, target, role=role):
            return Response("Último administrador ativo", status=400)
        conn.execute("UPDATE users SET role=?, session_version=session_version+1, updated_at=? WHERE id=?", (role, now_text(), user_id))
        _audit(conn, action="user.role_changed", target_type="user", target_id=user_id, actor_user_id=getattr(g, "current_user", None)["id"], metadata={"role": role})
    return Response(status=204)


@auth.post("/admin/users/<int:user_id>/active")
@require_role("admin")
def change_active(user_id: int) -> Response:
    require_recent_reauth()
    active = request.form.get("is_active") in {"1", "true", "on"}
    conn = get_db()
    with transaction(conn):
        target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if target is None:
            abort(404)
        if _last_admin_change_would_break(conn, target, is_active=active):
            return Response("Último administrador ativo", status=400)
        conn.execute("UPDATE users SET is_active=?, session_version=session_version+1, updated_at=? WHERE id=?", (int(active), now_text(), user_id))
        _audit(conn, action="user.active_changed", target_type="user", target_id=user_id, actor_user_id=getattr(g, "current_user", None)["id"], metadata={"active": active})
    return Response(status=204)


@auth.post("/admin/users/<int:user_id>/reset-mfa")
@require_role("admin")
def reset_mfa(user_id: int) -> Response:
    require_recent_reauth()
    conn = get_db()
    with transaction(conn):
        target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if target is None:
            abort(404)
        conn.execute(
            "UPDATE users SET totp_secret_ciphertext=NULL, totp_nonce=NULL, totp_key_version=NULL, totp_confirmed_at=NULL, last_totp_step=NULL, pending_totp_secret_ciphertext=NULL, pending_totp_nonce=NULL, pending_totp_key_version=NULL, totp_enrollment_shown_at=NULL, must_change_password=1, session_version=session_version+1, updated_at=? WHERE id=?",
            (now_text(), user_id),
        )
        conn.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
        _audit(conn, action="user.mfa_reset", target_type="user", target_id=user_id, actor_user_id=getattr(g, "current_user", None)["id"])
    return Response(status=204)
