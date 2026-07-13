from __future__ import annotations

from urllib.parse import urlsplit

from flask import Flask, abort, request, session
from flask_wtf.csrf import CSRFError, CSRFProtect

csrf = CSRFProtect()
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def validate_public_origin(value: object) -> str:
    if not isinstance(value, str):
        raise RuntimeError("PUBLIC_ORIGIN must be an exact HTTPS origin")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
        or value != f"https://{parsed.netloc}"
    ):
        raise RuntimeError("PUBLIC_ORIGIN must be an exact HTTPS origin")
    return value


def _same_origin(value: str, public_origin: str) -> bool:
    candidate = urlsplit(value)
    trusted = urlsplit(public_origin)
    return (
        candidate.scheme == trusted.scheme
        and candidate.netloc == trusted.netloc
        and not candidate.username
        and not candidate.password
        and public_origin == f"{trusted.scheme}://{trusted.netloc}"
    )


def init_app(app: Flask) -> None:
    """Enforce Flask-WTF tokens plus the single public browser origin."""
    app.config["PUBLIC_ORIGIN"] = validate_public_origin(app.config["PUBLIC_ORIGIN"])
    app.config.setdefault("WTF_CSRF_ENABLED", not app.testing)
    app.config.setdefault("CSRF_ORIGIN_CHECK", not app.testing)
    # Referrer-Policy: no-referrer strips the Referer that Flask-WTF's SSL-strict
    # check requires; the Origin gate below plus the CSRF token are authoritative.
    app.config.setdefault("WTF_CSRF_SSL_STRICT", False)
    csrf.init_app(app)

    @app.before_request
    def reject_untrusted_mutation_origin() -> None:
        if not app.config["CSRF_ORIGIN_CHECK"] or request.method not in _UNSAFE_METHODS:
            return None
        public_origin = app.config["PUBLIC_ORIGIN"]
        claimed_origin = request.headers.get("Origin") or request.headers.get("Referer")
        if not claimed_origin or not _same_origin(claimed_origin, public_origin):
            app.logger.warning("CSRF_DBG origin_gate reject has_origin=%s has_referer=%s", bool(request.headers.get("Origin")), bool(request.headers.get("Referer")))
            abort(403)
        return None

    @app.errorhandler(CSRFError)
    def csrf_failure(error: CSRFError):
        app.logger.warning(
            "CSRF_DBG csrf_failure desc=%r has_cookie=%s has_session_token=%s has_header=%s has_form=%s ctype=%r",
            getattr(error, "description", None),
            bool(request.cookies.get("session")),
            "csrf_token" in session,
            bool(request.headers.get("X-CSRFToken")),
            bool(request.form.get("csrf_token")),
            request.headers.get("Content-Type"),
        )
        return "Forbidden", 403
