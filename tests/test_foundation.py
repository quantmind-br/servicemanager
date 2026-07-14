from __future__ import annotations

import io
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from itsdangerous import URLSafeTimedSerializer

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
import app as app_module
from service_manager.db import get_db
from service_manager.crypto import EncryptedValue, account_field_aad, account_password_aad, decrypt_secret, encrypt_secret, hash_password
from service_manager.imports import parse_import_file

PUBLIC_ORIGIN = "https://servicemanager.quantmind.com.br"


def csrf_headers(client, app) -> dict[str, str]:
    with client.session_transaction() as session:
        session["csrf_token"] = "foundation-csrf-token"
    token = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="wtf-csrf-token").dumps("foundation-csrf-token")
    return {"X-CSRFToken": token, "Origin": PUBLIC_ORIGIN}


def authenticate(client, app, *, role: str = "admin") -> int:
    with app.app_context():
        now = datetime.now(UTC).isoformat()
        user_id = get_db().execute(
            "INSERT INTO users (username, password_hash, role, is_active, must_change_password, created_at, updated_at) "
            "VALUES (?, ?, ?, 1, 0, ?, ?)",
            (f"fixture-{role}", hash_password("foundation-test-password"), role, now, now),
        ).lastrowid
        get_db().commit()
    with client.session_transaction() as session:
        now = time.time()
        session.update(user_id=user_id, role=role, session_version=0, authenticated_at=now, last_seen_at=now, reauthenticated_at=now)
    return user_id

@pytest.fixture()
def app(tmp_path: Path):
    app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "service-manager-test.db"),
            "DATA_KEY_V1": "A" * 43 + "=",
            "SECRET_KEY": "test-session-key",
            "PUBLIC_ORIGIN": PUBLIC_ORIGIN,
            "WTF_CSRF_ENABLED": True,
            "CSRF_ORIGIN_CHECK": True,
        }
    )
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


def seed_account(app, *, password: str, field_value: str) -> int:
    with app.app_context():
        conn = get_db()
        service_id = conn.execute("INSERT INTO services (name) VALUES ('Email')").lastrowid
        account_id = conn.execute(
            "INSERT INTO accounts (email, password_ciphertext, password_nonce, password_key_version) VALUES (?, ?, ?, ?)",
            ("person@example.test", b"", b"0" * 12, 1),
        ).lastrowid
        password_value = encrypt_secret(password, aad=account_password_aad(account_id))
        conn.execute(
            "UPDATE accounts SET password_ciphertext = ?, password_nonce = ?, password_key_version = ? WHERE id = ?",
            (password_value.ciphertext, password_value.nonce, password_value.key_version, account_id),
        )
        conn.execute(
            "INSERT INTO account_service (account_id, service_id, status) VALUES (?, ?, 'ativo')",
            (account_id, service_id),
        )
        field_id = conn.execute(
            "INSERT INTO custom_fields (service_id, name) VALUES (?, 'Recovery code')",
            (service_id,),
        ).lastrowid
        field_value_envelope = encrypt_secret(field_value, aad=account_field_aad(account_id, field_id))
        conn.execute(
            "INSERT INTO field_values (field_id, account_id, value_ciphertext, value_nonce, value_key_version) VALUES (?, ?, ?, ?, ?)",
            (field_id, account_id, field_value_envelope.ciphertext, field_value_envelope.nonce, field_value_envelope.key_version),
        )
        conn.commit()
        return service_id


def test_healthz_is_non_secret_and_does_not_require_database_contents(client):
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_index_requires_authentication_and_never_renders_stored_secrets(app, client):
    service_id = seed_account(app, password="known-password", field_value="known-field-value")

    anonymous = client.get(f"/?service={service_id}")

    assert anonymous.status_code == 302
    assert anonymous.headers["Location"] == "/login"

    authenticate(client, app)
    response = client.get(f"/?service={service_id}")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "person@example.test" in body
    assert "known-password" not in body
    assert "known-field-value" not in body
    assert "Protegido" in body


@pytest.mark.parametrize(
    ("rule", "method"),
    [
        ("/", "GET"),
        ("/add", "POST"),
        ("/template.csv", "GET"),
        ("/template.xlsx", "GET"),
        ("/import", "POST"),
        ("/update/<int:item_id>", "POST"),
        ("/delete/<int:item_id>", "POST"),
        ("/service/add", "POST"),
        ("/service/delete/<int:service_id>", "POST"),
        ("/field/add", "POST"),
        ("/field/update/<int:field_id>/<int:account_id>", "POST"),
        ("/field/delete/<int:field_id>/<int:account_id>", "POST"),
    ],
)
def test_legacy_account_service_and_field_endpoints_are_owned_by_a_blueprint(app, rule, method):
    matching_rules = [
        registered_rule
        for registered_rule in app.url_map.iter_rules()
        if registered_rule.rule == rule and method in registered_rule.methods
    ]

    assert matching_rules
    assert all(registered_rule.endpoint.startswith("routes.") for registered_rule in matching_rules)


def test_secret_field_mutation_without_csrf_does_not_change_existing_value(app, client):
    service_id = seed_account(app, password="known-password", field_value="existing-value")
    authenticate(client, app, role="operador")
    with app.app_context():
        conn = get_db()
        account_id = conn.execute("SELECT id FROM accounts WHERE email = ?", ("person@example.test",)).fetchone()["id"]

    response = client.post(
        "/field/add",
        data={"service": service_id, "name": "Recovery code", "value": "", "account_ids": str(account_id)},
        headers={"Origin": PUBLIC_ORIGIN},
    )

    assert response.status_code == 403
    with app.app_context():
        row = get_db().execute(
            "SELECT field_id, value_ciphertext, value_nonce, value_key_version FROM field_values WHERE account_id = ?",
            (account_id,),
        ).fetchone()
        value = decrypt_secret(
            EncryptedValue(row["value_ciphertext"], row["value_nonce"], row["value_key_version"]),
            aad=account_field_aad(account_id, row["field_id"]),
        )
    assert value == "existing-value"


def test_corrupt_xlsx_import_redirects_with_format_error_without_mutating(app, client):
    with app.app_context():
        conn = get_db()
        service_id = conn.execute("INSERT INTO services (name) VALUES ('Email')").lastrowid
        conn.commit()
    authenticate(client, app)

    response = client.post(
        "/import",
        data={"service_id": str(service_id), "file": (io.BytesIO(b"not a workbook"), "broken.xlsx")},
        content_type="multipart/form-data",
        headers=csrf_headers(client, app),
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/?service={service_id}&error=format")
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0


def test_labeled_import_without_password_column_does_not_shift_status_into_password():
    records = parse_import_file("accounts.csv", b"email,status\nperson@example.test,ativo\n")

    assert records == [("person@example.test", "", "ativo")]

def test_labeled_import_without_email_column_is_rejected():
    with pytest.raises(ValueError, match="email"):
        parse_import_file("accounts.csv", b"password,status\nsecret,ativo\n")


def test_labeled_import_without_email_redirects_with_format_error_without_mutating(app, client):
    with app.app_context():
        conn = get_db()
        service_id = conn.execute("INSERT INTO services (name) VALUES ('Email')").lastrowid
        conn.commit()
    authenticate(client, app)

    response = client.post(
        "/import",
        data={"service_id": str(service_id), "file": (io.BytesIO(b"password,status\nsecret,ativo\n"), "accounts.csv")},
        content_type="multipart/form-data",
        headers=csrf_headers(client, app),
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/?service={service_id}&error=format")
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0



@pytest.mark.parametrize(
    ("environment_key", "configured_key"),
    [(None, None), ("", None), ("environment-session-key", "")],
)
def test_production_factory_rejects_missing_or_empty_secret_key(
    monkeypatch, tmp_path: Path, environment_key: str | None, configured_key: str | None
):
    monkeypatch.setenv("FLASK_ENV", "production")
    if environment_key is None:
        monkeypatch.delenv("SECRET_KEY", raising=False)
    else:
        monkeypatch.setenv("SECRET_KEY", environment_key)
    config = {"DATABASE_PATH": str(tmp_path / "service-manager.db")}
    if configured_key is not None:
        config["SECRET_KEY"] = configured_key

    with pytest.raises(RuntimeError, match="SECRET_KEY") as error:
        create_app(config)

    assert str(error.value) == "SECRET_KEY must be configured in production"

def test_production_factory_accepts_secret_key_from_environment(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("SECRET_KEY", "environment-session-key")

    production_app = create_app({"DATABASE_PATH": str(tmp_path / "service-manager.db")})

    assert production_app.config["SECRET_KEY"] == "environment-session-key"


def test_production_factory_prefers_explicit_secret_key_config(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("SECRET_KEY", "environment-session-key")

    production_app = create_app(
        {
            "DATABASE_PATH": str(tmp_path / "service-manager.db"),
            "SECRET_KEY": "configured-session-key",
        }
    )

    assert production_app.config["SECRET_KEY"] == "configured-session-key"


def test_development_factory_retains_non_production_secret_key_fallback(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.delenv("SECRET_KEY", raising=False)

    development_app = create_app({"DATABASE_PATH": str(tmp_path / "service-manager.db")})

    assert development_app.config["SECRET_KEY"] == "development-only-not-for-production"


def test_production_factory_loads_environment_data_key_for_authenticated_encrypted_add(monkeypatch, tmp_path: Path):
    environment_data_key = "A" * 43 + "="
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("SECRET_KEY", "environment-session-key")
    monkeypatch.setenv("DATA_KEY_V1", environment_data_key)
    monkeypatch.setenv("AUDIT_KEY_V1", "B" * 43 + "=")

    production_app = create_app({"DATABASE_PATH": str(tmp_path / "production" / "service-manager.db")})
    assert production_app.config["DATA_KEY_V1"] == environment_data_key

    with production_app.app_context():
        service_id = get_db().execute("INSERT INTO services (name) VALUES ('Mail')").lastrowid
        get_db().commit()

    production_client = production_app.test_client()
    authenticate(production_client, production_app)
    response = production_client.post(
        "/add",
        data={"service": service_id, "email": "person@example.test", "password": "environment-key-secret", "status": "ativo"},
        headers=csrf_headers(production_client, production_app),
    )

    assert response.status_code == 302
    with production_app.app_context():
        row = get_db().execute(
            "SELECT id, password_ciphertext, password_nonce, password_key_version FROM accounts WHERE email = ?",
            ("person@example.test",),
        ).fetchone()
        assert row is not None
        assert decrypt_secret(
            EncryptedValue(row["password_ciphertext"], row["password_nonce"], row["password_key_version"]),
            aad=account_password_aad(row["id"]),
        ) == "environment-key-secret"


def test_explicit_data_key_config_overrides_environment(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("DATA_KEY_V1", "A" * 43 + "=")
    configured_data_key = "B" * 43 + "="

    configured_app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "service-manager-test.db"),
            "DATA_KEY_V1": configured_data_key,
            "SECRET_KEY": "test-session-key",
        }
    )

    assert configured_app.config["DATA_KEY_V1"] == configured_data_key

def test_default_development_factory_uses_writable_instance_database(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("DATABASE_PATH", raising=False)
    monkeypatch.setenv("FLASK_ENV", "development")
    flask_constructor = app_module.Flask
    instance_path = tmp_path / "instance"
    monkeypatch.setattr(
        app_module,
        "Flask",
        lambda *args, **kwargs: flask_constructor(*args, instance_path=str(instance_path), **kwargs),
    )

    default_app = app_module.create_app()
    database_path = Path(default_app.config["DATABASE_PATH"])

    assert database_path == instance_path / "service-manager.db"
    assert database_path != Path("/data/service-manager.db")
    with default_app.app_context():
        get_db().execute("SELECT 1")
    assert database_path.is_file()


def test_dockerignore_excludes_entire_tests_tree():
    dockerignore = Path(__file__).resolve().parents[1] / ".dockerignore"

    assert "tests/" in dockerignore.read_text().splitlines()
