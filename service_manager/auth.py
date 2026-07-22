from __future__ import annotations

import re
import secrets
import sqlite3
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any, ParamSpec, TypeVar

from email_validator import EmailNotValidError, validate_email
from flask import Blueprint, Flask, Response, abort, current_app, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from service_manager.audit import append_audit_event, append_audit_event_in_transaction, verify_audit_chain
from service_manager.crypto import hash_password, needs_password_rehash, verify_password
from service_manager.db import get_db, transaction


auth = Blueprint("auth", __name__)

P = ParamSpec("P")
R = TypeVar("R")
_INVALID_CREDENTIALS = "Credenciais inválidas"
_MAX_SECRET_LENGTH = 4096
_SESSION_KEYS = {"user_id", "role", "session_version", "authenticated_at", "last_seen_at", "reauthenticated_at"}
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")


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


def normalize_username(value: str | None) -> str:
    candidate = (value or "").strip().lower()
    return candidate if _USERNAME_RE.fullmatch(candidate) else ""


def source_ip() -> str:
    return request.remote_addr or "unknown"


def _audit(
    conn: Any,
    *,
    action: str,
    target_type: str,
    target_id: int | str | None = None,
    actor_user_id: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    append_audit_event(conn, action=action, target_type=target_type, target_id=target_id, actor_user_id=actor_user_id, metadata=metadata)


def _valid_secret(value: object) -> bool:
    return isinstance(value, str) and len(value) <= _MAX_SECRET_LENGTH


def _require_audit_chain() -> None:
    healthy = verify_audit_chain()
    current_app.config["AUDIT_CHAIN_HEALTHY"] = healthy
    if not healthy:
        abort(503)


def _seed_initial_admin(app: Flask) -> None:
    with app.app_context():
        conn = get_db()
        if not isinstance(app.config.get("AUDIT_KEY_V1"), str) or not app.config["AUDIT_KEY_V1"]:
            return
        with transaction(conn):
            if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                return
            username = normalize_username(app.config.get("ADMIN_USERNAME", "admin"))
            password = app.config.get("ADMIN_PASSWORD", "12345678")
            if not username or not _valid_secret(password) or not password:
                raise RuntimeError("ADMIN_USERNAME or ADMIN_PASSWORD is invalid")
            stamp = now_text()
            user_id = conn.execute(
                "INSERT INTO users (username, password_hash, role, is_active, must_change_password, created_at, updated_at, password_changed_at) "
                "VALUES (?, ?, 'admin', 1, 0, ?, ?, ?)",
                (username, hash_password(password), stamp, stamp, stamp),
            ).lastrowid
            _audit(conn, action="bootstrap.initialized", target_type="user", target_id=user_id)


def _set_session(user: Any, *, reauthenticated: bool = False) -> None:
    timestamp = time.time()
    session.clear()
    session.update(
        user_id=user["id"],
        role=user["role"],
        session_version=user["session_version"],
        authenticated_at=timestamp,
        last_seen_at=timestamp,
        reauthenticated_at=timestamp if reauthenticated else None,
    )


def _rate_limited(conn: Any, *, username: str, ip: str) -> bool:
    cutoff_ip = (now_utc() - timedelta(minutes=1)).isoformat()
    cutoff_username = (now_utc() - timedelta(minutes=15)).isoformat()
    ip_count = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE kind='login_failure' AND source_ip=? AND occurred_at>=?", (ip, cutoff_ip)
    ).fetchone()[0]
    username_count = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE kind='login_failure' AND subject=? AND occurred_at>=?", (username, cutoff_username)
    ).fetchone()[0]
    return ip_count >= 5 or username_count >= 5


def _record_login_failure(conn: Any, *, username: str, ip: str) -> None:
    conn.execute(
        "INSERT INTO security_events (kind, subject, source_ip, occurred_at) VALUES ('login_failure', ?, ?, ?)",
        (username, ip, now_text()),
    )


def consume_reveal_allowance(conn: Any, *, user_id: int, ip: str) -> bool:
    cutoff = (now_utc() - timedelta(minutes=10)).isoformat()
    count = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE kind='reveal' AND subject=? AND occurred_at>=?", (str(user_id), cutoff)
    ).fetchone()[0]
    if count >= 20:
        return False
    conn.execute(
        "INSERT INTO security_events (kind, subject, source_ip, occurred_at) VALUES ('reveal', ?, ?, ?)",
        (str(user_id), ip, now_text()),
    )
    return True


def _authentication_failure(conn: Any, *, username: str, ip: str) -> Response:
    _record_login_failure(conn, username=username, ip=ip)
    _audit(conn, action="login_failure", target_type="user", metadata={"username_present": bool(username)})
    return Response(_INVALID_CREDENTIALS, status=401)


def _authenticate(username: str, password: str, *, require_active: bool = True) -> tuple[Any | None, Response | None]:
    conn = get_db()
    ip = source_ip()
    with transaction(conn):
        if _rate_limited(conn, username=username, ip=ip):
            return None, Response("Muitas tentativas", status=429)
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user is None or (require_active and not user["is_active"]) or not verify_password(user["password_hash"], password):
            return None, _authentication_failure(conn, username=username, ip=ip)
        if needs_password_rehash(user["password_hash"]):
            conn.execute("UPDATE users SET password_hash=?, updated_at=? WHERE id=?", (hash_password(password), now_text(), user["id"]))
            user = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        _audit(conn, action="login.succeeded", target_type="user", target_id=user["id"], actor_user_id=user["id"])
        return user, None


_FAILURE_MESSAGES = {
    401: "Credenciais inválidas.",
    429: "Muitas tentativas. Aguarde alguns minutos.",
}


def _render_auth_failure(template: str, response: Response, **context: Any) -> Response:
    message = _FAILURE_MESSAGES.get(response.status_code)
    if message is None:
        return response
    return Response(
        render_template(template, error=message, **context),
        status=response.status_code,
        headers={"Cache-Control": "no-store, private"},
    )


@auth.route("/login", methods=["GET", "POST"])
def login() -> Response:
    if request.method == "GET":
        return Response(render_template("login.html"), headers={"Cache-Control": "no-store, private"})
    username = normalize_username(request.form.get("username"))
    password = request.form.get("password", "")
    if not _valid_secret(password):
        conn = get_db()
        with transaction(conn):
            if _rate_limited(conn, username=username, ip=source_ip()):
                return _render_auth_failure("login.html", Response("Muitas tentativas", status=429))
            return _render_auth_failure("login.html", _authentication_failure(conn, username=username, ip=source_ip()))
    user, error = _authenticate(username, password)
    if error is not None:
        return _render_auth_failure("login.html", error)
    _set_session(user)
    return redirect(url_for("auth.account" if user["must_change_password"] else "routes.index"))


@auth.post("/logout")
def logout() -> Response:
    user = getattr(g, "current_user", None)
    if user is not None:
        append_audit_event_in_transaction(action="logout", target_type="user", target_id=user["id"], actor_user_id=user["id"])
    session.clear()
    return redirect(url_for("auth.login"))


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
    user = get_db().execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if user is None or not user["is_active"] or user["role"] != session["role"] or user["session_version"] != session["session_version"]:
        return None
    if now - last_seen_at > 60:
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
    _seed_initial_admin(app)

    @app.before_request
    def guard_sensitive_mutations() -> None:
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            _require_audit_chain()

    @app.before_request
    def authenticate_protected_requests() -> Response | None:
        if request.endpoint is None or request.endpoint in {"routes.healthz", "auth.login", "static"}:
            return None
        user = _session_user()
        if user is None:
            session.clear()
            return redirect(url_for("auth.login"))
        g.current_user = user
        if user["must_change_password"] and request.endpoint not in {"auth.account", "auth.change_password", "auth.logout"}:
            abort(403)
        return None

    @app.after_request
    def protect_auth_responses(response: Response) -> Response:
        if request.endpoint == "auth.login" or getattr(g, "current_user", None) is not None:
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
    password = request.form.get("password", "")
    username = normalize_username(user["username"])
    conn = get_db()
    with transaction(conn):
        if _rate_limited(conn, username=username, ip=source_ip()):
            return _render_auth_failure("reauth.html", Response("Muitas tentativas", status=429))
        current = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if not _valid_secret(password) or current is None or not verify_password(current["password_hash"], password):
            return _render_auth_failure("reauth.html", _authentication_failure(conn, username=username, ip=source_ip()))
        _audit(conn, action="reauth", target_type="user", target_id=current["id"], actor_user_id=current["id"])
    session["reauthenticated_at"] = time.time()
    return Response(status=204)


@auth.get("/account")
def account() -> Response:
    user = getattr(g, "current_user", None)
    assert user is not None
    return Response(render_template("account.html", user=user), headers={"Cache-Control": "no-store, private"})


@auth.post("/account/username")
def change_username() -> Response:
    user = getattr(g, "current_user", None)
    assert user is not None
    username = normalize_username(request.form.get("username"))
    current_password = request.form.get("current_password", "")
    if not username or not _valid_secret(current_password):
        return Response(render_template("account.html", user=user, error_username="Login inválido ou senha incorreta."), status=400, headers={"Cache-Control": "no-store, private"})
    conn = get_db()
    try:
        with transaction(conn):
            current = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
            if current is None or not verify_password(current["password_hash"], current_password):
                return Response(render_template("account.html", user=user, error_username="Login inválido ou senha incorreta."), status=400, headers={"Cache-Control": "no-store, private"})
            if username == current["username"].lower():
                return redirect(url_for("auth.account"), code=303)
            conn.execute("UPDATE users SET username=?, updated_at=?, session_version=session_version+1 WHERE id=?", (username, now_text(), current["id"]))
            _audit(conn, action="user.username_changed", target_type="user", target_id=current["id"], actor_user_id=current["id"])
    except sqlite3.IntegrityError:
        return Response(render_template("account.html", user=user, error_username="Este login já está em uso."), status=409, headers={"Cache-Control": "no-store, private"})
    refreshed = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
    _set_session(refreshed, reauthenticated=True)
    return redirect(url_for("auth.account"), code=303)


@auth.post("/account/password")
def change_password() -> Response:
    user = getattr(g, "current_user", None)
    assert user is not None
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    if not _valid_secret(current_password) or not _valid_secret(new_password) or len(new_password) < 16:
        return Response(render_template("account.html", user=user, error_password="Não foi possível alterar a senha. Verifique a senha atual e use ao menos 16 caracteres em uma senha nova diferente."), status=400, headers={"Cache-Control": "no-store, private"})
    conn = get_db()
    with transaction(conn):
        current = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        if current is None or current_password == new_password or not verify_password(current["password_hash"], current_password):
            return Response(render_template("account.html", user=user, error_password="Não foi possível alterar a senha. Verifique a senha atual e use ao menos 16 caracteres em uma senha nova diferente."), status=400, headers={"Cache-Control": "no-store, private"})
        stamp = now_text()
        conn.execute(
            "UPDATE users SET password_hash=?, must_change_password=0, password_changed_at=?, updated_at=?, session_version=session_version+1 WHERE id=?",
            (hash_password(new_password), stamp, stamp, current["id"]),
        )
        _audit(conn, action="password.changed", target_type="user", target_id=current["id"], actor_user_id=current["id"])
    refreshed = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
    _set_session(refreshed, reauthenticated=True)
    return redirect(url_for("auth.account"), code=303)


@auth.get("/admin/users")
@require_role("admin")
def users() -> Response:
    rows = get_db().execute("SELECT id, username, role, is_active, must_change_password FROM users ORDER BY username").fetchall()
    return Response(render_template("admin_users.html", users=rows), headers={"Cache-Control": "no-store, private"})


def _request_value(name: str) -> Any:
    payload = request.get_json(silent=True)
    return payload.get(name) if isinstance(payload, dict) else request.form.get(name)


@auth.post("/admin/users")
@require_role("admin")
def create_user() -> Response:
    require_recent_reauth()
    username = normalize_username(_request_value("username"))
    role = _request_value("role") or ""
    if not username or role not in {"admin", "operador"}:
        return Response("Usuário inválido", status=400)
    temporary_password = secrets.token_urlsafe(24)
    conn = get_db()
    try:
        with transaction(conn):
            stamp = now_text()
            user_id = conn.execute(
                "INSERT INTO users (username,password_hash,role,is_active,must_change_password,created_at,updated_at,password_changed_at) "
                "VALUES (?, ?, ?, 1, 1, ?, ?, ?)",
                (username, hash_password(temporary_password), role, stamp, stamp, stamp),
            ).lastrowid
            _audit(conn, action="user.created", target_type="user", target_id=user_id, actor_user_id=g.current_user["id"], metadata={"role": role})
    except sqlite3.IntegrityError:
        return Response("Login indisponível", status=409)
    return jsonify(id=user_id, temporary_password=temporary_password), 201


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
        _audit(conn, action="user.role_changed", target_type="user", target_id=user_id, actor_user_id=g.current_user["id"], metadata={"role": role})
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
        _audit(conn, action="user.active_changed", target_type="user", target_id=user_id, actor_user_id=g.current_user["id"], metadata={"active": active})
    return Response(status=204)
