from __future__ import annotations

from urllib.parse import urlsplit

from flask import Flask, abort, request
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
    # `same-origin` Referrer-Policy preserves a same-origin fallback when a
    # browser omits Origin for a native form POST. The explicit Origin/Referer
    # gate below remains authoritative alongside Flask-WTF's token validation.
    app.config.setdefault("WTF_CSRF_SSL_STRICT", False)
    csrf.init_app(app)
    @app.before_request
    def reject_untrusted_mutation_origin() -> None:
        if not app.config["CSRF_ORIGIN_CHECK"] or request.method not in _UNSAFE_METHODS:
            return None
        public_origin = app.config["PUBLIC_ORIGIN"]
        claimed_origin = request.headers.get("Origin") or request.headers.get("Referer")
        if not claimed_origin or not _same_origin(claimed_origin, public_origin):
            abort(403)
        return None

    @app.errorhandler(CSRFError)
    def csrf_failure(_: CSRFError):
        return "Forbidden", 403
