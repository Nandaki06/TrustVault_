
import os
import io
from datetime import datetime, timezone

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

import app as trustvault


@pytest.fixture
def setup_app(tmp_path, monkeypatch):
    database = tmp_path / "test.db"
    upload_folder = tmp_path / "test_uploads"
    upload_folder.mkdir()

    monkeypatch.setattr(trustvault, "DATABASE", str(database))
    monkeypatch.setattr(trustvault, "UPLOAD_FOLDER", str(upload_folder))
    monkeypatch.setattr(trustvault, "cipher", Fernet(Fernet.generate_key()))

    trustvault.app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret-key"
    )

    trustvault.create_database()

    conn = trustvault.get_db()

    users = {}
    for email, role in [
        ("owner@test.com", "owner"),
        ("viewer@test.com", "owner"),
        ("admin@test.com", "admin"),
    ]:
        cursor = conn.execute(
            """
            INSERT INTO users (email, password, role)
            VALUES (?, ?, ?)
            """,
            (email, generate_password_hash("TestPass123"), role)
        )
        users[email] = cursor.lastrowid

    conn.commit()
    conn.close()

    return {
        "database": str(database),
        "uploads": str(upload_folder),
        "users": users,
    }


def login_as(client, user_id):
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["csrf_token"] = "test-csrf-token"


def create_document(setup_app, content=b"%PDF-1.7 test document"):
    owner_id = setup_app["users"]["owner@test.com"]

    encrypted_data = trustvault.cipher.encrypt(content)
    stored_filename = "test_document.encrypted"

    file_path = os.path.join(setup_app["uploads"], stored_filename)

    with open(file_path, "wb") as file:
        file.write(encrypted_data)

    conn = trustvault.get_db()

    cursor = conn.execute(
        """
        INSERT INTO documents (
            user_id, filename, stored_filename,
            encrypted, category, created_at
        )
        VALUES (?, ?, ?, 1, ?, ?)
        """,
        (
            owner_id,
            "test.pdf",
            stored_filename,
            "Testing",
            datetime.now(timezone.utc).isoformat()
        )
    )

    document_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return document_id


def grant_permission(setup_app, document_id, permission):
    viewer_id = setup_app["users"]["viewer@test.com"]

    conn = trustvault.get_db()
    conn.execute(
        """
        INSERT INTO document_permissions (
            document_id, user_id, permission, granted_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            document_id,
            viewer_id,
            permission,
            datetime.now(timezone.utc).isoformat()
        )
    )
    conn.commit()
    conn.close()


def test_dashboard_requires_login(setup_app):
    client = trustvault.app.test_client()
    response = client.get("/dashboard")
    assert response.status_code == 302


def test_owner_can_download_document(setup_app):
    client = trustvault.app.test_client()
    document_id = create_document(setup_app)

    login_as(client, setup_app["users"]["owner@test.com"])

    response = client.get(f"/download/{document_id}")

    assert response.status_code == 200
    assert response.data == b"%PDF-1.7 test document"


def test_unauthorized_user_cannot_download(setup_app):
    client = trustvault.app.test_client()
    document_id = create_document(setup_app)

    login_as(client, setup_app["users"]["viewer@test.com"])

    response = client.get(f"/download/{document_id}")

    assert response.status_code == 403

    conn = trustvault.get_db()
    log = conn.execute(
        """
        SELECT result FROM audit_logs
        WHERE action = 'DOWNLOAD'
        ORDER BY id DESC LIMIT 1
        """
    ).fetchone()
    conn.close()

    assert log["result"] == "denied"


def test_read_permission_cannot_edit_or_delete(setup_app):
    client = trustvault.app.test_client()
    document_id = create_document(setup_app)

    grant_permission(setup_app, document_id, "read")

    login_as(client, setup_app["users"]["viewer@test.com"])

    download_response = client.get(f"/download/{document_id}")
    assert download_response.status_code == 200

    replace_response = client.post(
        f"/replace/{document_id}",
        data={
            "csrf_token": "test-csrf-token",
            "document": (io.BytesIO(b"%PDF-new"), "new.pdf")
        }
    )
    assert replace_response.status_code == 403

    delete_response = client.post(
        f"/delete/{document_id}",
        data={"csrf_token": "test-csrf-token"}
    )
    assert delete_response.status_code == 403


def test_edit_permission_can_replace_document(setup_app):
    client = trustvault.app.test_client()
    document_id = create_document(setup_app)

    grant_permission(setup_app, document_id, "edit")

    login_as(client, setup_app["users"]["viewer@test.com"])

    response = client.post(
        f"/replace/{document_id}",
        data={
            "csrf_token": "test-csrf-token",
            "document": (
                io.BytesIO(b"%PDF-1.7 replacement"),
                "replacement.pdf"
            )
        }
    )

    assert response.status_code == 302

    download_response = client.get(f"/download/{document_id}")

    assert download_response.status_code == 200
    assert download_response.data == b"%PDF-1.7 replacement"


def test_revoked_permission_blocks_download(setup_app):
    client = trustvault.app.test_client()
    document_id = create_document(setup_app)

    grant_permission(setup_app, document_id, "read")

    owner_id = setup_app["users"]["owner@test.com"]
    viewer_id = setup_app["users"]["viewer@test.com"]

    login_as(client, owner_id)

    revoke_response = client.post(
        f"/revoke/{document_id}/{viewer_id}",
        data={"csrf_token": "test-csrf-token"}
    )

    assert revoke_response.status_code == 302

    with client.session_transaction() as session:
        session["user_id"] = viewer_id

    response = client.get(f"/download/{document_id}")
    assert response.status_code == 403


def test_csrf_protection_blocks_missing_token(setup_app):
    client = trustvault.app.test_client()
    document_id = create_document(setup_app)

    login_as(client, setup_app["users"]["owner@test.com"])

    response = client.post(f"/delete/{document_id}")

    assert response.status_code == 400

    conn = trustvault.get_db()
    document = conn.execute(
        "SELECT id FROM documents WHERE id = ?",
        (document_id,)
    ).fetchone()
    conn.close()

    assert document is not None


def test_audit_chain_detects_tampering(setup_app):
    with trustvault.app.test_request_context("/"):
        trustvault.log_event("TEST_EVENT", details="Original")

    assert trustvault.verify_audit_chain() is True

    conn = trustvault.get_db()
    conn.execute(
        """
        UPDATE audit_logs
        SET details = 'Modified'
        WHERE action = 'TEST_EVENT'
        """
    )
    conn.commit()
    conn.close()

    assert trustvault.verify_audit_chain() is False


def test_only_admin_can_view_audit_page(setup_app):
    client = trustvault.app.test_client()

    login_as(client, setup_app["users"]["owner@test.com"])

    owner_response = client.get("/admin/audit")
    assert owner_response.status_code == 403

    login_as(client, setup_app["users"]["admin@test.com"])

    admin_response = client.get("/admin/audit")
    assert admin_response.status_code == 200


def test_invalid_file_content_is_rejected(setup_app):
    client = trustvault.app.test_client()

    login_as(client, setup_app["users"]["owner@test.com"])

    response = client.post(
        "/upload",
        data={
            "csrf_token": "test-csrf-token",
            "document": (
                io.BytesIO(b"This is not a PDF"),
                "fake.pdf"
            )
        }
    )

    assert response.status_code == 200
    assert b"Invalid or unsupported file content" in response.data
