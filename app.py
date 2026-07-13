from __future__ import annotations

import os
from pathlib import Path
from collections.abc import Mapping
from typing import Any

from flask import Flask, request
from service_manager.auth import auth, bind_auth
from service_manager.csrf import init_app as init_csrf_app
from service_manager.audit import verify_audit_chain

from service_manager.db import init_app as init_db_app
from service_manager.routes import routes


def _trusted_proxy_hops(config: Mapping[str, Any] | None) -> int:
    value = config["TRUSTED_PROXY_HOPS"] if config and "TRUSTED_PROXY_HOPS" in config else os.environ.get("TRUSTED_PROXY_HOPS", "0")
    if isinstance(value, bool):
        raise RuntimeError("TRUSTED_PROXY_HOPS must be a non-negative integer")
    if isinstance(value, str):
        if not value.isascii() or not value.isdecimal():
            raise RuntimeError("TRUSTED_PROXY_HOPS must be a non-negative integer")
        value = int(value)
    if not isinstance(value, int) or value < 0:
        raise RuntimeError("TRUSTED_PROXY_HOPS must be a non-negative integer")
    return value


def create_app(config: Mapping[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    environment = os.environ.get("FLASK_ENV", "development").lower()
    configured_database_path = config.get("DATABASE_PATH") if config else None
    database_path = configured_database_path if configured_database_path is not None else os.environ.get("DATABASE_PATH")
    if database_path is None:
        database_path = "/data/service-manager.db" if environment == "production" else str(Path(app.instance_path) / "service-manager.db")
    configured_secret_key = config.get("SECRET_KEY") if config else None
    secret_key = configured_secret_key if configured_secret_key is not None else os.environ.get("SECRET_KEY")
    configured_data_key = config.get("DATA_KEY_V1") if config else None
    data_key = configured_data_key if configured_data_key is not None else os.environ.get("DATA_KEY_V1")
    configured_audit_key = config.get("AUDIT_KEY_V1") if config else None
    audit_key = configured_audit_key if configured_audit_key is not None else os.environ.get("AUDIT_KEY_V1")
    if audit_key is None and environment != "production":
        audit_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    configured_origin = config.get("PUBLIC_ORIGIN") if config else None
    public_origin = configured_origin if configured_origin is not None else os.environ.get("PUBLIC_ORIGIN", "https://servicemanager.quantmind.com.br")
    bootstrap_config = {
        name: config[name] if config and name in config else os.environ.get(name)
        for name in ("ADMIN_EMAIL", "ADMIN_INITIAL_PASSWORD", "ADMIN_BOOTSTRAP_TOKEN")
    }
    trusted_proxy_hops = _trusted_proxy_hops(config)
    if environment == "production" and not secret_key:
        raise RuntimeError("SECRET_KEY must be configured in production")
    app.config.from_mapping(
        DATABASE_PATH=database_path,
        DATA_KEY_V1=data_key,
        AUDIT_KEY_V1=audit_key,
        PUBLIC_ORIGIN=public_origin,
        IS_PRODUCTION=environment == "production",
        SECRET_KEY=secret_key or "development-only-not-for-production",
        TRUSTED_PROXY_HOPS=trusted_proxy_hops,
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,
        **bootstrap_config,
    )
    if config:
        app.config.update(config)
    app.config["IS_PRODUCTION"] = environment == "production"

    init_db_app(app)
    with app.app_context():
        app.config["AUDIT_CHAIN_HEALTHY"] = verify_audit_chain()
        if not app.config["AUDIT_CHAIN_HEALTHY"]:
            app.logger.critical("audit chain verification failed during startup")
    init_csrf_app(app)
    app.register_blueprint(routes)
    app.register_blueprint(auth)
    bind_auth(app)
    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    @app.errorhandler(429)
    @app.errorhandler(500)
    def render_generic_error(error):
        from flask import render_template

        return render_template(f"{error.code}.html"), error.code

    @app.after_request
    def apply_security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-Frame-Options"] = "DENY"
        if app.config["IS_PRODUCTION"] and request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    return app
