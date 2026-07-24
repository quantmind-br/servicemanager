from __future__ import annotations

import base64
import io
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from itsdangerous import URLSafeTimedSerializer
from openpyxl import Workbook

from app import create_app
from service_manager.audit import verify_audit_chain
from service_manager.crypto import EncryptedValue, account_field_aad, account_password_aad, decrypt_secret, hash_password
from service_manager.db import get_db, inserted_id
from service_manager.imports import MAX_XLSX_UNCOMPRESSED_BYTES, parse_import_file


PUBLIC_ORIGIN = "https://servicemanager.quantmind.com.br"


@pytest.fixture()
def app(tmp_path: Path):
    return create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "imports.db"),
            "DATA_KEY_V1": base64.b64encode(b"i" * 32).decode("ascii"),
            "AUDIT_KEY_V1": base64.b64encode(b"a" * 32).decode("ascii"),
            "SECRET_KEY": "imports-session-secret",
            "PUBLIC_ORIGIN": PUBLIC_ORIGIN,
            "WTF_CSRF_ENABLED": True,
            "CSRF_ORIGIN_CHECK": True,
        }
    )


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf_headers(client, app) -> dict[str, str]:
    with client.session_transaction() as session:
        session["csrf_token"] = "imports-csrf-token"
    token = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="wtf-csrf-token").dumps("imports-csrf-token")
    return {"X-CSRFToken": token, "Origin": PUBLIC_ORIGIN}


def authenticate_admin(app, client) -> int:
    with app.app_context():
        conn = get_db()
        service_id = inserted_id(conn.execute("INSERT INTO services (name) VALUES ('Mail')"))
        user_id = inserted_id(conn.execute(
            "INSERT INTO users (username, password_hash, role, is_active, must_change_password, created_at, updated_at) "
            "VALUES (?, ?, 'admin', 1, 0, ?, ?)",
            ("import-admin", hash_password("not-an-import-secret"), datetime.now(UTC).isoformat(), datetime.now(UTC).isoformat()),
        ))
        conn.commit()
    with client.session_transaction() as session:
        now = time.time()
        session.update(user_id=user_id, role="admin", session_version=0, authenticated_at=now, last_seen_at=now, reauthenticated_at=now)
    return service_id


def csv_upload(client, app, service_id: int, data: bytes, *, filename: str = "accounts.csv", mimetype: str | None = None):
    uploaded_file = (io.BytesIO(data), filename) if mimetype is None else (io.BytesIO(data), filename, mimetype)
    return client.post(
        "/import",
        data={"service_id": str(service_id), "file": uploaded_file},
        content_type="multipart/form-data",
        headers=csrf_headers(client, app),
    )


def workbook_bytes(rows: list[tuple[str, ...]]) -> bytes:
    workbook = Workbook()
    worksheet = workbook.active
    if worksheet is None:
        raise RuntimeError("new workbook has no active worksheet")
    for row in rows:
        worksheet.append(row)
    stream = io.BytesIO()
    workbook.save(stream)
    return stream.getvalue()


def test_csv_parser_rejects_invalid_utf8_in_a_stream():
    with pytest.raises(ValueError, match="UTF-8"):
        parse_import_file("accounts.csv", io.BytesIO(b"email,password,status\nuser@x.test,\xff,ativo\n"))


def test_parser_enforces_record_column_cell_and_cell_count_limits():
    with pytest.raises(ValueError, match="columns"):
        parse_import_file("accounts.csv", io.BytesIO((",".join(["x"] * 21) + "\n").encode()))
    with pytest.raises(ValueError, match="cell"):
        parse_import_file("accounts.csv", io.BytesIO(b"email,password,status\nuser@x.test," + b"x" * 4097 + b",ativo\n"))
    over_limit = b"email,password,status\n" + b"".join(f"user{number}@x.test,p,ativo\n".encode() for number in range(5001))
    with pytest.raises(ValueError, match="records"):
        parse_import_file("accounts.csv", io.BytesIO(over_limit))


def test_parser_preserves_additional_field_columns_and_rejects_invalid_headers():
    parsed = parse_import_file(
        "accounts.csv",
        b"email,password,status,campo:API Key,campo:email,cadastrada\n"
        b"user@x.test,secret,ativo,abc123,alias@x.test,2024-01-01\n"
        b"short@x.test,secret,ativo\n",
    )
    assert parsed.field_names == ("API Key", "email")
    assert parsed.records[0].email == "user@x.test"
    assert parsed.records[0].field_values == ("abc123", "alias@x.test")
    # A short row still yields exactly one value per field name, defaulting to "".
    assert parsed.records[1].field_values == ("", "")

    with pytest.raises(ValueError, match="name"):
        parse_import_file("accounts.csv", b"email,campo:\nuser@x.test,value\n")
    with pytest.raises(ValueError, match="duplicate"):
        parse_import_file("accounts.csv", b"email,campo:Token,campo:Token\nuser@x.test,a,b\n")


def test_parser_rejects_more_than_one_hundred_thousand_cells():
    row = ("x," * 19 + "x\n").encode()
    data = row + row * 5_000
    with pytest.raises(ValueError, match="cells"):
        parse_import_file("accounts.csv", io.BytesIO(data))


def test_xlsx_zip_validation_rejects_traversal_macro_and_external_members():
    for member in ("../escape", "xl/vbaProject.bin", "xl/externalLinks/externalLink1.xml"):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(member, b"data")
        with pytest.raises(ValueError, match="XLSX"):
            parse_import_file("accounts.xlsx", io.BytesIO(stream.getvalue()))



@pytest.mark.parametrize("member", ["C:/escape", "//server/share/escape"])
def test_xlsx_zip_validation_rejects_windows_rooted_member_paths(member: str):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(member, b"data")

    with pytest.raises(ValueError, match="unsafe XLSX member path"):
        parse_import_file("accounts.xlsx", io.BytesIO(stream.getvalue()))


@pytest.mark.parametrize(
    ("content_types", "relationship"),
    [
        (
            b'<Types><Override PartName="/xl/custom.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>',
            None,
        ),
        (
            b"<Types/>",
            b'<Relationships><Relationship Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="xl/custom.bin"/></Relationships>',
        ),
    ],
)
def test_xlsx_zip_validation_rejects_macros_declared_by_ooxml_type(content_types: bytes, relationship: bytes | None):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("[Content_Types].xml", content_types)
        if relationship is not None:
            archive.writestr("_rels/.rels", relationship)

    with pytest.raises(ValueError, match="macros"):
        parse_import_file("accounts.xlsx", io.BytesIO(stream.getvalue()))


@pytest.mark.parametrize("content_type", ["application/vnd.ms-excel.macrosheet+xml", "application/vnd.ms-excel.intlmacrosheet+xml"])
def test_xlsx_zip_validation_rejects_excel_macrosheet_content_types(content_type: str):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(
            "[Content_Types].xml",
            f'<Types><Override PartName="/xl/sheets/sheet1.xml" ContentType="{content_type}"/></Types>',
        )

    with pytest.raises(ValueError, match="macros"):
        parse_import_file("accounts.xlsx", io.BytesIO(stream.getvalue()))

def test_xlsx_zip_validation_rejects_external_relationship_targets():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("_rels/.rels", b'<Relationships><Relationship Target="https://evil.example" TargetMode="External"/></Relationships>')
    with pytest.raises(ValueError, match="external"):
        parse_import_file("accounts.xlsx", io.BytesIO(stream.getvalue()))


def test_xlsx_zip_validation_rejects_excessive_expansion_ratio():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("xl/worksheets/sheet1.xml", b"x" * 100_000)
    with pytest.raises(ValueError, match="ratio"):
        parse_import_file("accounts.xlsx", io.BytesIO(stream.getvalue()))


def test_xlsx_zip_validation_rejects_excessive_members_and_unpacked_size():
    member_count = io.BytesIO()
    with zipfile.ZipFile(member_count, "w") as archive:
        for number in range(101):
            archive.writestr(f"xl/worksheets/sheet{number}.xml", b"x")
    with pytest.raises(ValueError, match="members"):
        parse_import_file("accounts.xlsx", io.BytesIO(member_count.getvalue()))

    unpacked_size = io.BytesIO()
    with zipfile.ZipFile(unpacked_size, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("xl/worksheets/sheet1.xml", b"x" * (25 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="unpacked"):
        parse_import_file("accounts.xlsx", io.BytesIO(unpacked_size.getvalue()))


def test_admin_import_encrypts_password_skips_casefolded_duplicates_and_audits(app, client):
    service_id = authenticate_admin(app, client)
    response = csv_upload(
        client,
        app,
        service_id,
        b"email,password,status\nPerson@example.test,known-secret,ativo\nperson@example.test,other-secret,nunca\n",
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/?service={service_id}&added=1&skipped=1")
    with app.app_context():
        conn = get_db()
        account = conn.execute("SELECT * FROM accounts WHERE email='Person@example.test'").fetchone()
        assert account is not None
        assert decrypt_secret(
            EncryptedValue(account["password_ciphertext"], account["password_nonce"], account["password_key_version"]),
            aad=account_password_aad(account["id"]),
        ) == "known-secret"
        event = conn.execute("SELECT metadata_json FROM audit_events WHERE action='accounts.imported'").fetchone()
        assert event["metadata_json"] == '{"added":1,"skipped":1}'
        assert "known-secret" not in event["metadata_json"]
        assert verify_audit_chain()


def test_import_validation_error_rolls_back_entire_batch(app, client):
    service_id = authenticate_admin(app, client)
    response = csv_upload(
        client,
        app,
        service_id,
        b"email,password,status,campo:Token\nvalid@example.test,secret,ativo,tok\nnot-an-email,secret,ativo,tok2\n",
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/?service={service_id}&error=validation")
    with app.app_context():
        conn = get_db()
        assert conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM custom_fields").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM field_values").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action != 'bootstrap.initialized'").fetchone()[0] == 0


@pytest.mark.parametrize("extension", ["csv", "xlsx"])
def test_import_additional_fields_csv_and_xlsx_are_encrypted(app, client, extension: str):
    service_id = authenticate_admin(app, client)
    with app.app_context():
        conn = get_db()
        existing_token_id = inserted_id(conn.execute(
            "INSERT INTO custom_fields (service_id, name) VALUES (?, 'Token')", (service_id,)
        ))
        conn.commit()

    header = ("email", "password", "status", "campo:Token", "campo:Observação", "cadastrada", "ignorada")
    row_a = ("a@example.test", "secret-a", "ativo", "tok-a", "obs-a", "2024-01-01", "noise")
    row_b = ("b@example.test", "secret-b", "ativo", "tok-b", "", "2024-01-02", "noise")
    if extension == "csv":
        data = ("\n".join(",".join(cells) for cells in (header, row_a, row_b)) + "\n").encode()
        filename = "accounts.csv"
    else:
        data = workbook_bytes([header, row_a, row_b])
        filename = "accounts.xlsx"

    response = csv_upload(client, app, service_id, data, filename=filename)
    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/?service={service_id}&added=2&skipped=0")

    with app.app_context():
        conn = get_db()
        fields = {row["name"]: row["id"] for row in conn.execute("SELECT id, name FROM custom_fields WHERE service_id=?", (service_id,))}
        assert fields["Token"] == existing_token_id
        assert set(fields) == {"Token", "Observação"}
        assert conn.execute("SELECT COUNT(*) FROM custom_fields WHERE name='Observação'").fetchone()[0] == 1

        expected = {
            ("a@example.test", "Token"): "tok-a",
            ("a@example.test", "Observação"): "obs-a",
            ("b@example.test", "Token"): "tok-b",
            ("b@example.test", "Observação"): "",
        }
        for (email, field_name), plaintext in expected.items():
            account_id = conn.execute("SELECT id FROM accounts WHERE email=?", (email,)).fetchone()["id"]
            field_id = fields[field_name]
            stored = conn.execute(
                "SELECT value_ciphertext, value_nonce, value_key_version FROM field_values WHERE field_id=? AND account_id=?",
                (field_id, account_id),
            ).fetchone()
            assert stored is not None
            assert decrypt_secret(
                EncryptedValue(stored["value_ciphertext"], stored["value_nonce"], stored["value_key_version"]),
                aad=account_field_aad(account_id, field_id),
            ) == plaintext

        event = conn.execute("SELECT metadata_json FROM audit_events WHERE action='accounts.imported'").fetchone()
        assert event["metadata_json"] == '{"added":2,"skipped":0}'
        for leaked in ("Token", "Observação", "tok-a", "obs-a", "cadastrada", "ignorada"):
            assert leaked not in event["metadata_json"]
        assert verify_audit_chain()


def test_import_duplicate_only_does_not_create_additional_fields(app, client):
    service_id = authenticate_admin(app, client)
    csv_upload(client, app, service_id, b"email,password,status\ndup@example.test,secret,ativo\n")

    response = csv_upload(
        client,
        app,
        service_id,
        b"email,password,status,campo:Novo\ndup@example.test,other,ativo,value\n",
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/?service={service_id}&added=0&skipped=1")
    with app.app_context():
        conn = get_db()
        assert conn.execute("SELECT COUNT(*) FROM custom_fields").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM field_values").fetchone()[0] == 0


def test_import_oversized_custom_field_name_does_not_mutate(app, client):
    service_id = authenticate_admin(app, client)
    oversized = "x" * 101
    response = csv_upload(
        client,
        app,
        service_id,
        f"email,password,status,campo:{oversized}\nuser@example.test,secret,ativo,value\n".encode(),
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/?service={service_id}&error=validation")
    with app.app_context():
        conn = get_db()
        assert conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM custom_fields").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM field_values").fetchone()[0] == 0


def test_malformed_csv_quote_is_rejected_without_mutation(app, client):
    service_id = authenticate_admin(app, client)
    response = csv_upload(
        client,
        app,
        service_id,
        b'email,password,status\nvalid@example.test,"secret"x,ativo\n',
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/?service={service_id}&error=format")
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0
        assert get_db().execute("SELECT COUNT(*) FROM audit_events WHERE action != 'bootstrap.initialized'").fetchone()[0] == 0



def test_import_rejects_unrelated_upload_mime_without_mutation(app, client):
    service_id = authenticate_admin(app, client)
    response = csv_upload(
        client,
        app,
        service_id,
        b"email,password,status\nvalid@example.test,secret,ativo\n",
        mimetype="image/png",
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/?service={service_id}&error=format")
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0

def test_invalid_format_aborts_without_inserting_and_response_never_echoes_content(app, client):
    service_id = authenticate_admin(app, client)
    secret = "do-not-echo-this"
    response = csv_upload(client, app, service_id, f"email,password,status\nvalid@example.test,{secret},ativo\n".encode(), filename="accounts.txt")

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/?service={service_id}&error=format")
    assert secret not in response.get_data(as_text=True)
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0


def test_import_feedback_shows_only_safe_type_and_counts(app, client):
    service_id = authenticate_admin(app, client)
    uploaded_secret = "untrusted-upload-value"
    failed = csv_upload(client, app, service_id, f"email,password,status\ninvalid,{uploaded_secret},ativo\n".encode())
    feedback = client.get(failed.headers["Location"])

    assert "Importação rejeitada: dados inválidos. 0 adicionadas; 0 ignoradas." in feedback.get_data(as_text=True)
    assert uploaded_secret not in feedback.get_data(as_text=True)


def test_admin_can_import_minimal_xlsx(app, client):
    service_id = authenticate_admin(app, client)
    response = csv_upload(
        client,
        app,
        service_id,
        workbook_bytes([("email", "password", "status"), ("xlsx@example.test", "xlsx-secret", "inativo")]),
        filename="accounts.xlsx",
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/?service={service_id}&added=1&skipped=0")
    with app.app_context():
        assert get_db().execute("SELECT email FROM accounts").fetchone()[0] == "xlsx@example.test"


def test_upload_larger_than_five_mebibytes_returns_413_without_mutation(app, client):
    service_id = authenticate_admin(app, client)
    response = csv_upload(client, app, service_id, b"x" * (5 * 1024 * 1024 + 1))

    assert response.status_code == 413
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0


def test_operator_cannot_import_even_with_valid_csrf(app, client):
    service_id = authenticate_admin(app, client)
    with app.app_context():
        get_db().execute("UPDATE users SET role='operador' WHERE username='import-admin'")
        get_db().commit()
    with client.session_transaction() as session:
        session["role"] = "operador"
    response = csv_upload(client, app, service_id, b"email,password,status\nblocked@example.test,s,ativo\n")
    assert response.status_code == 403
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0


def test_xlsx_validates_all_members_before_opening_compressed_relationships(monkeypatch: pytest.MonkeyPatch):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("_rels/.rels", b"<Relationships/>" * (MAX_XLSX_UNCOMPRESSED_BYTES + 1))

    opened: list[str] = []
    original_open = zipfile.ZipFile.open

    def tracking_open(self, name, *args, **kwargs):
        opened.append(name.filename if isinstance(name, zipfile.ZipInfo) else name)
        return original_open(self, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", tracking_open)

    with pytest.raises(ValueError, match="unpacked"):
        parse_import_file("accounts.xlsx", io.BytesIO(stream.getvalue()))

    assert opened == []


def test_xlsx_rejects_external_relationships_independent_of_xml_serialization():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr(
            "_rels/.rels",
            b"<Relationships><Relationship Target='https://evil.example' TargetMode = 'External'/></Relationships>",
        )

    with pytest.raises(ValueError, match="external"):
        parse_import_file("accounts.xlsx", io.BytesIO(stream.getvalue()))

@pytest.mark.parametrize("member", ["[Content_Types].xml", "_rels/.rels"])
@pytest.mark.parametrize("open_error", [RuntimeError, NotImplementedError])
def test_unreadable_xlsx_metadata_returns_safe_format_error_without_mutation(
    app, client, monkeypatch: pytest.MonkeyPatch, member: str, open_error: type[Exception]
):
    service_id = authenticate_admin(app, client)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(member, b"<Relationships/>")

    original_open = zipfile.ZipFile.open

    def unreadable_metadata(self, name, *args, **kwargs):
        member_name = name.filename if isinstance(name, zipfile.ZipInfo) else name
        if member_name == member:
            raise open_error("unreadable metadata")
        return original_open(self, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", unreadable_metadata)
    response = csv_upload(client, app, service_id, stream.getvalue(), filename="accounts.xlsx")

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/?service={service_id}&error=format")
    assert b"unreadable metadata" not in response.data
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 0
        assert get_db().execute("SELECT COUNT(*) FROM audit_events WHERE action != 'bootstrap.initialized'").fetchone()[0] == 0


def test_import_preserves_password_whitespace_byte_for_byte(app, client):
    service_id = authenticate_admin(app, client)
    password = " x "
    response = csv_upload(
        client,
        app,
        service_id,
        b'email,password,status\nwhitespace@example.test," x ",ativo\n',
    )

    assert response.status_code == 302
    with app.app_context():
        account = get_db().execute("SELECT * FROM accounts WHERE email='whitespace@example.test'").fetchone()
        assert decrypt_secret(
            EncryptedValue(account["password_ciphertext"], account["password_nonce"], account["password_key_version"]),
            aad=account_password_aad(account["id"]),
        ) == password


@pytest.mark.parametrize("path", ["/template.csv", "/template.xlsx"])
def test_operator_cannot_download_import_templates(app, client, path: str):
    service_id = authenticate_admin(app, client)
    with app.app_context():
        get_db().execute("UPDATE users SET role='operador' WHERE username='import-admin'")
        get_db().commit()
    with client.session_transaction() as session:
        session["role"] = "operador"

    assert client.get(f"{path}?service={service_id}").status_code == 403
