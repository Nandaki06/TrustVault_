import os
from dotenv import load_dotenv
import io
import sys
import json
import uuid
import hmac
import hashlib
import secrets
import sqlite3
import psycopg
import zipfile

from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_file, abort
)

from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from psycopg.rows import dict_row
from supabase import create_client


# =====================================================
# CONFIGURATION
# =====================================================

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "trustvault.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
KEY_FILE = os.path.join(BASE_DIR, "secret.key")

BUCKET_NAME = "trustvault-documents"

DATABASE_URL = os.environ.get("DATABASE_URL")
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY")

DB_MODE = os.environ.get("TRUSTVAULT_DB_MODE", "sqlite").lower()

USE_POSTGRES = DB_MODE == "postgres"

if USE_POSTGRES and not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required.")

if USE_POSTGRES and (not SUPABASE_URL or not SUPABASE_SECRET_KEY):
    raise RuntimeError("Supabase credentials are missing.")

secret_key = os.environ.get("TRUSTVAULT_SECRET")

if not secret_key:
    secret_key_path = os.path.join(BASE_DIR, ".flask_secret")

    if os.path.exists(secret_key_path):
        with open(secret_key_path, "r", encoding="utf-8") as f:
            secret_key = f.read().strip()
    else:
        secret_key = secrets.token_hex(32)

        with open(secret_key_path, "w", encoding="utf-8") as f:
            f.write(secret_key)

app = Flask(__name__)
app.secret_key = secret_key

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("TRUSTVAULT_HTTPS", "0") == "1"
)

ALLOWED_EXTENSIONS = {
    "pdf", "png", "jpg", "jpeg", "docx"
}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

supabase = (
    create_client(SUPABASE_URL, SUPABASE_SECRET_KEY)
    if USE_POSTGRES else None
)


# =====================================================
# ENCRYPTION
# =====================================================

def load_encryption_key():

    env_key = os.environ.get("TRUSTVAULT_ENCRYPTION_KEY")

    if env_key:
        try:
            return Fernet(env_key.encode("utf-8"))
        except Exception as error:
            raise RuntimeError(
                "Invalid TRUSTVAULT_ENCRYPTION_KEY."
            ) from error

    if USE_POSTGRES:
        raise RuntimeError(
            "Set TRUSTVAULT_ENCRYPTION_KEY before using PostgreSQL."
        )

    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())

    with open(KEY_FILE, "rb") as f:
        return Fernet(f.read())


cipher = load_encryption_key()


# =====================================================
# DATABASE ADAPTER
# =====================================================

class PostgresConnection:

    def __init__(self, connection):
        self.connection = connection

    @staticmethod
    def _convert_sql(sql):
        return sql.replace("?", "%s")

    def execute(self, sql, parameters=()):
        return self.connection.execute(
            self._convert_sql(sql), parameters
        )

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()


def get_db():

    if USE_POSTGRES and not app.config.get("TESTING", False):

        connection = psycopg.connect(
            DATABASE_URL,
            row_factory=dict_row
        )

        return PostgresConnection(connection)

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON")

    return conn


# =====================================================
# DATABASE CREATION
# =====================================================

def create_database():

    conn = get_db()

    try:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        user_columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        }

        if "role" not in user_columns:
            conn.execute("""
                ALTER TABLE users
                ADD COLUMN role TEXT NOT NULL DEFAULT 'owner'
            """)

        document_columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(documents)"
            ).fetchall()
        }

        if "encrypted" not in document_columns:
            conn.execute("""
                ALTER TABLE documents
                ADD COLUMN encrypted INTEGER DEFAULT 0
            """)

        if "category" not in document_columns:
            conn.execute("""
                ALTER TABLE documents
                ADD COLUMN category TEXT DEFAULT 'General'
            """)

        if "created_at" not in document_columns:
            conn.execute("""
                ALTER TABLE documents
                ADD COLUMN created_at TEXT
            """)

        conn.execute("""
            UPDATE documents
            SET created_at = ?
            WHERE created_at IS NULL
        """, (
            datetime.now(timezone.utc).isoformat(),
        ))

        conn.execute("""
            CREATE TABLE IF NOT EXISTS document_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                permission TEXT NOT NULL
                    CHECK(permission IN ('read', 'edit')),
                granted_at TEXT NOT NULL,
                UNIQUE(document_id, user_id),
                FOREIGN KEY(document_id) REFERENCES documents(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                document_id INTEGER,
                details TEXT,
                result TEXT NOT NULL,
                created_at TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
        """)

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def check_postgres_schema():

    if not USE_POSTGRES:
        return

    conn = get_db()

    try:

        conn.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'owner'
        """)

        conn.execute("""
            ALTER TABLE documents
            ADD COLUMN IF NOT EXISTS encrypted INTEGER NOT NULL DEFAULT 0
        """)

        conn.execute("""
            ALTER TABLE documents
            ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT 'General'
        """)

        conn.execute("""
            ALTER TABLE documents
            ADD COLUMN IF NOT EXISTS created_at TEXT
        """)

        conn.execute("""
            UPDATE documents
            SET created_at = ?
            WHERE created_at IS NULL
        """, (
            datetime.now(timezone.utc).isoformat(),
        ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


# =====================================================
# STORAGE
# =====================================================

def save_encrypted_file(data, user_id):

    stored_filename = (
        f"{user_id}_{uuid.uuid4()}.encrypted"
    )

    encrypted_data = cipher.encrypt(data)

    if USE_POSTGRES and not app.config.get("TESTING", False):

        supabase.storage.from_(BUCKET_NAME).upload(
            stored_filename,
            encrypted_data,
            file_options={
                "content-type": "application/octet-stream",
                "upsert": "false"
            }
        )

    else:

        file_path = os.path.join(
            UPLOAD_FOLDER, stored_filename
        )

        with open(file_path, "wb") as f:
            f.write(encrypted_data)

    return stored_filename


def read_stored_file(stored_filename):

    if USE_POSTGRES and not app.config.get("TESTING", False):

        return supabase.storage.from_(
            BUCKET_NAME
        ).download(stored_filename)

    file_path = os.path.join(
        UPLOAD_FOLDER, stored_filename
    )

    if not os.path.isfile(file_path):
        raise FileNotFoundError(stored_filename)

    with open(file_path, "rb") as f:
        return f.read()


def delete_stored_file(stored_filename):

    if USE_POSTGRES and not app.config.get("TESTING", False):

        supabase.storage.from_(BUCKET_NAME).remove(
            [stored_filename]
        )

        return

    file_path = os.path.join(
        UPLOAD_FOLDER, stored_filename
    )

    if os.path.isfile(file_path):
        os.remove(file_path)


# =====================================================
# AUDIT LOGGING
# =====================================================

def log_event(
    action,
    document_id=None,
    details="",
    result="success"
):

    conn = get_db()

    try:

        previous = conn.execute("""
            SELECT entry_hash
            FROM audit_logs
            ORDER BY id DESC
            LIMIT 1
        """).fetchone()

        previous_hash = (
            previous["entry_hash"]
            if previous else "GENESIS"
        )

        created_at = datetime.now(
            timezone.utc
        ).isoformat()

        user_id = session.get("user_id")

        record = {
            "user_id": user_id,
            "action": action,
            "document_id": document_id,
            "details": details,
            "result": result,
            "created_at": created_at,
            "previous_hash": previous_hash
        }

        record_text = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":")
        )

        entry_hash = hashlib.sha256(
            record_text.encode("utf-8")
        ).hexdigest()

        conn.execute("""
            INSERT INTO audit_logs (
                user_id, action, document_id, details,
                result, created_at, previous_hash, entry_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            action,
            document_id,
            details,
            result,
            created_at,
            previous_hash,
            entry_hash
        ))

        conn.commit()

    finally:
        conn.close()


def verify_audit_chain():

    conn = get_db()

    try:

        logs = conn.execute("""
            SELECT *
            FROM audit_logs
            ORDER BY id ASC
        """).fetchall()

        previous_hash = "GENESIS"

        for log in logs:

            record = {
                "user_id": log["user_id"],
                "action": log["action"],
                "document_id": log["document_id"],
                "details": log["details"],
                "result": log["result"],
                "created_at": log["created_at"],
                "previous_hash": log["previous_hash"]
            }

            record_text = json.dumps(
                record,
                sort_keys=True,
                separators=(",", ":")
            )

            expected_hash = hashlib.sha256(
                record_text.encode("utf-8")
            ).hexdigest()

            if (
                log["previous_hash"] != previous_hash
                or not hmac.compare_digest(
                    log["entry_hash"],
                    expected_hash
                )
            ):
                return False

            previous_hash = log["entry_hash"]

        return True

    finally:
        conn.close()


# =====================================================
# CSRF PROTECTION
# =====================================================

@app.before_request
def csrf_protection():

    if request.method == "POST":

        token = session.get("csrf_token")
        submitted_token = request.form.get(
            "csrf_token", ""
        )

        if (
            not token
            or not submitted_token
            or not hmac.compare_digest(
                token, submitted_token
            )
        ):

            log_event(
                "CSRF_VALIDATION",
                details=request.path,
                result="denied"
            )

            abort(400)


@app.context_processor
def inject_csrf_token():

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    return {
        "csrf_token": session["csrf_token"]
    }


# =====================================================
# AUTHENTICATION DECORATORS
# =====================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            log_event(
                "UNAUTHENTICATED_ACCESS",
                details=request.path,
                result="denied"
            )

            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


def admin_required(function):

    @wraps(function)
    @login_required
    def wrapper(*args, **kwargs):

        conn = get_db()

        try:

            user = conn.execute(
                "SELECT role FROM users WHERE id = ?",
                (session["user_id"],)
            ).fetchone()

        finally:
            conn.close()

        if not user or user["role"] != "admin":

            log_event(
                "ADMIN_ACCESS",
                details=request.path,
                result="denied"
            )

            abort(403)

        return function(*args, **kwargs)

    return wrapper


# =====================================================
# DOCUMENT ACCESS CONTROL
# =====================================================

def get_document_access(document_id):

    conn = get_db()

    try:

        document = conn.execute(
            "SELECT * FROM documents WHERE id = ?",
            (document_id,)
        ).fetchone()

        if not document:
            return None, None

        if document["user_id"] == session["user_id"]:
            return document, "owner"

        permission = conn.execute("""
            SELECT permission
            FROM document_permissions
            WHERE document_id = ? AND user_id = ?
        """, (
            document_id,
            session["user_id"]
        )).fetchone()

        return (
            document,
            permission["permission"] if permission else None
        )

    finally:
        conn.close()


# =====================================================
# FILE VALIDATION
# =====================================================

def allowed_file(filename):

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


def validate_file_content(filename, data):

    if not data:
        return False

    extension = filename.rsplit(".", 1)[1].lower()

    if extension == "pdf":
        return data.startswith(b"%PDF-")

    if extension == "png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")

    if extension in ("jpg", "jpeg"):
        return data.startswith(b"\xff\xd8\xff")

    if extension == "docx":

        try:

            with zipfile.ZipFile(
                io.BytesIO(data)
            ) as archive:

                return (
                    archive.testzip() is None
                    and "word/document.xml"
                    in archive.namelist()
                )

        except zipfile.BadZipFile:
            return False

    return False
# =====================================================
# HOME AND REGISTRATION
# =====================================================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or "@" not in email or len(password) < 8:
            log_event("REGISTER", details=email, result="denied")
            return "Enter a valid email and password with at least 8 characters."

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (email, password, role) VALUES (?, ?, 'owner')",
                (email, generate_password_hash(password))
            )
            conn.commit()
        except (sqlite3.IntegrityError, psycopg.IntegrityError):
            log_event("REGISTER", details=email, result="denied")
            return "Email already registered."
        finally:
            conn.close()

        log_event("REGISTER", details=email)
        return redirect(url_for("login"))

    return render_template("register.html")


# =====================================================
# LOGIN
# =====================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        try:
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()
        finally:
            conn.close()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            log_event("LOGIN", details=email)
            return redirect(url_for("dashboard"))

        log_event("LOGIN", details=email, result="denied")
        return "Invalid email or password."

    return render_template("login.html")


# =====================================================
# DASHBOARD
# =====================================================

@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    try:
        user = conn.execute(
            "SELECT role FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
    finally:
        conn.close()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    return render_template("dashboard.html", role=user["role"])


# =====================================================
# UPLOAD
# =====================================================

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    conn = get_db()
    try:
        user = conn.execute(
            "SELECT role FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
    finally:
        conn.close()

    if not user or user["role"] == "admin":
        log_event("UPLOAD", result="denied")
        abort(403)

    if "document" not in request.files:
        log_event("UPLOAD", details="No file selected", result="denied")
        return "No file selected."

    file = request.files["document"]

    if not file.filename:
        log_event("UPLOAD", details="Empty filename", result="denied")
        return "No file selected."

    if not allowed_file(file.filename):
        log_event("UPLOAD", details=file.filename, result="denied")
        return "File type not allowed."

    original_filename = secure_filename(file.filename)

    if not original_filename:
        log_event("UPLOAD", result="denied")
        return "Invalid filename."

    file_data = file.read()

    if not validate_file_content(original_filename, file_data):
        log_event(
            "UPLOAD",
            details="Invalid file content: " + original_filename,
            result="denied"
        )
        return "Invalid or unsupported file content."

    category = request.form.get("category", "General").strip()[:100] or "General"

    stored_filename = save_encrypted_file(file_data, session["user_id"])

    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO documents (
                user_id, filename, stored_filename, encrypted, category, created_at
            ) VALUES (?, ?, ?, 1, ?, ?)
        """, (
            session["user_id"],
            original_filename,
            stored_filename,
            category,
            datetime.now(timezone.utc).isoformat()
        ))
        conn.commit()

    except Exception:
        try:
            delete_stored_file(stored_filename)
        except Exception:
            app.logger.exception(
                "Could not clean up uploaded file after database failure."
            )
        raise

    finally:
        conn.close()

    log_event("UPLOAD", details=original_filename)
    return redirect(url_for("documents"))


# =====================================================
# DOCUMENT LIST AND SEARCH
# =====================================================

@app.route("/documents")
@login_required
def documents():
    search = request.args.get("search", "").strip()[:100]

    conn = get_db()
    try:
        files = conn.execute("""
            SELECT DISTINCT d.*, u.email AS owner_email
            FROM documents d
            JOIN users u ON u.id = d.user_id
            LEFT JOIN document_permissions p ON p.document_id = d.id
            WHERE (d.user_id = ? OR p.user_id = ?)
            AND (
                d.filename LIKE ? OR u.email LIKE ?
                OR d.category LIKE ? OR d.created_at LIKE ?
            )
            ORDER BY d.id DESC
        """, (
            session["user_id"],
            session["user_id"],
            "%" + search + "%",
            "%" + search + "%",
            "%" + search + "%",
            "%" + search + "%"
        )).fetchall()

        permissions = {}

        for file in files:
            if file["user_id"] == session["user_id"]:
                shared_users = conn.execute("""
                    SELECT p.user_id, u.email, p.permission
                    FROM document_permissions p
                    JOIN users u ON u.id = p.user_id
                    WHERE p.document_id = ?
                """, (file["id"],)).fetchall()

                permissions[file["id"]] = shared_users

    finally:
        conn.close()

    log_event("DOCUMENT_SEARCH", details=search)

    return render_template(
        "documents.html",
        files=files,
        search=search,
        permissions=permissions
    )


# =====================================================
# DOWNLOAD
# =====================================================

@app.route("/download/<int:document_id>")
@login_required
def download(document_id):
    document, permission = get_document_access(document_id)

    if not document or permission not in ("owner", "read", "edit"):
        log_event("DOWNLOAD", document_id=document_id, result="denied")
        abort(403)

    try:
        file_data = read_stored_file(document["stored_filename"])

        if document["encrypted"] == 1:
            file_data = cipher.decrypt(file_data)

        log_event("DOWNLOAD", document_id=document_id)

        return send_file(
            io.BytesIO(file_data),
            as_attachment=True,
            download_name=document["filename"]
        )

    except FileNotFoundError:
        log_event("DOWNLOAD", document_id=document_id, result="failed")
        abort(404)

    except InvalidToken:
        log_event("DOWNLOAD", document_id=document_id, result="failed")
        return "Unable to decrypt document."

    except Exception:
        app.logger.exception("Document download failed.")
        log_event("DOWNLOAD", document_id=document_id, result="failed")
        abort(404)


# =====================================================
# REPLACE DOCUMENT
# =====================================================

@app.route("/replace/<int:document_id>", methods=["POST"])
@login_required
def replace_document(document_id):
    document, permission = get_document_access(document_id)

    if not document or permission not in ("owner", "edit"):
        log_event("EDIT", document_id=document_id, result="denied")
        abort(403)

    if "document" not in request.files:
        log_event("EDIT", document_id=document_id, result="denied")
        return "Select a replacement file."

    file = request.files["document"]

    if not file.filename or not allowed_file(file.filename):
        log_event("EDIT", document_id=document_id, result="denied")
        return "File type not allowed."

    new_filename = secure_filename(file.filename)

    if not new_filename:
        return "Invalid filename."

    file_data = file.read()

    if not validate_file_content(new_filename, file_data):
        log_event("EDIT", document_id=document_id, result="denied")
        return "Invalid file content."

    stored_filename = save_encrypted_file(file_data, document["user_id"])

    conn = get_db()
    try:
        conn.execute("""
            UPDATE documents
            SET filename = ?, stored_filename = ?, encrypted = 1
            WHERE id = ?
        """, (new_filename, stored_filename, document_id))

        conn.commit()

    except Exception:
        try:
            delete_stored_file(stored_filename)
        except Exception:
            app.logger.exception("Could not clean up replacement file.")
        raise

    finally:
        conn.close()

    try:
        delete_stored_file(document["stored_filename"])
    except Exception:
        app.logger.exception(
            "Could not remove old document file after replacement."
        )

    log_event("EDIT", document_id=document_id, details=new_filename)
    return redirect(url_for("documents"))


# =====================================================
# DELETE DOCUMENT
# =====================================================

@app.route("/delete/<int:document_id>", methods=["POST"])
@login_required
def delete(document_id):
    document, permission = get_document_access(document_id)

    if not document or permission != "owner":
        log_event("DELETE", document_id=document_id, result="denied")
        abort(403)

    conn = get_db()
    try:
        conn.execute(
            "DELETE FROM document_permissions WHERE document_id = ?",
            (document_id,)
        )

        conn.execute(
            "DELETE FROM documents WHERE id = ?",
            (document_id,)
        )

        conn.commit()

    finally:
        conn.close()

    try:
        delete_stored_file(document["stored_filename"])
    except Exception:
        app.logger.exception("Could not remove deleted document from storage.")

    log_event("DELETE", document_id=document_id)
    return redirect(url_for("documents"))


# =====================================================
# SHARE DOCUMENT
# =====================================================

@app.route("/share/<int:document_id>", methods=["POST"])
@login_required
def share_document(document_id):
    document, permission = get_document_access(document_id)

    if not document or permission != "owner":
        log_event("PERMISSION_GRANT", document_id=document_id, result="denied")
        abort(403)

    email = request.form.get("email", "").strip().lower()
    access = request.form.get("permission", "read").strip().lower()

    if access not in ("read", "edit"):
        log_event("PERMISSION_GRANT", document_id=document_id, result="denied")
        return "Invalid permission."

    conn = get_db()
    try:
        target_user = conn.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()

        if not target_user:
            return "User not found. They must register first."

        if target_user["id"] == document["user_id"]:
            return "You are already the document owner."

        conn.execute("""
            INSERT INTO document_permissions (
                document_id, user_id, permission, granted_at
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(document_id, user_id)
            DO UPDATE SET
                permission = excluded.permission,
                granted_at = excluded.granted_at
        """, (
            document_id,
            target_user["id"],
            access,
            datetime.now(timezone.utc).isoformat()
        ))

        conn.commit()

    finally:
        conn.close()

    log_event(
        "PERMISSION_GRANT",
        document_id=document_id,
        details=email + ":" + access
    )

    return redirect(url_for("documents"))


# =====================================================
# REVOKE ACCESS
# =====================================================

@app.route("/revoke/<int:document_id>/<int:target_user_id>", methods=["POST"])
@login_required
def revoke_permission(document_id, target_user_id):
    document, permission = get_document_access(document_id)

    if not document or permission != "owner":
        log_event("PERMISSION_REVOKE", document_id=document_id, result="denied")
        abort(403)

    conn = get_db()
    try:
        target = conn.execute(
            "SELECT email FROM users WHERE id = ?", (target_user_id,)
        ).fetchone()

        deleted = conn.execute("""
            DELETE FROM document_permissions
            WHERE document_id = ? AND user_id = ?
        """, (document_id, target_user_id))

        conn.commit()

    finally:
        conn.close()

    if deleted.rowcount == 0:
        log_event(
            "PERMISSION_REVOKE",
            document_id=document_id,
            details=str(target_user_id),
            result="failed"
        )
        return "Permission not found."

    log_event(
        "PERMISSION_REVOKE",
        document_id=document_id,
        details=target["email"] if target else str(target_user_id)
    )

    return redirect(url_for("documents"))
# =====================================================
# ADMIN AUDIT LOGS
# =====================================================

@app.route("/admin/audit")
@admin_required
def admin_audit():
    conn = get_db()
    try:
        logs = conn.execute("""
            SELECT *
            FROM audit_logs
            ORDER BY id DESC
            LIMIT 500
        """).fetchall()
    finally:
        conn.close()

    integrity_valid = verify_audit_chain()

    return render_template(
        "admin_audit.html",
        logs=logs,
        integrity_valid=integrity_valid
    )


# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    log_event("LOGOUT")
    session.clear()
    return redirect(url_for("login"))


# =====================================================
# ERROR HANDLERS
# =====================================================

@app.errorhandler(403)
def forbidden(error):
    return "Access denied. You do not have permission.", 403


@app.errorhandler(404)
def not_found(error):
    return "Requested page or document was not found.", 404


@app.errorhandler(413)
def file_too_large(error):
    return "File is too large.", 413


# =====================================================
# CREATE ADMIN ACCOUNT
# =====================================================

def create_admin_account(email, password):
    if not email or "@" not in email:
        raise ValueError("Enter a valid admin email.")

    if len(password) < 8:
        raise ValueError("Admin password must contain at least 8 characters.")

    conn = get_db()

    try:
        existing_user = conn.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if existing_user:
            conn.execute(
                "UPDATE users SET role = 'admin', password = ? WHERE id = ?",
                (generate_password_hash(password), existing_user["id"])
            )
        else:
            conn.execute(
                "INSERT INTO users (email, password, role) VALUES (?, ?, 'admin')",
                (email, generate_password_hash(password))
            )

        conn.commit()

    finally:
        conn.close()

    print("Admin account created successfully.")


# =====================================================
# APPLICATION START
# =====================================================

if __name__ == "__main__":

    if USE_POSTGRES:
        check_postgres_schema()
    else:
        create_database()

    if len(sys.argv) == 4 and sys.argv[1] == "create-admin":
        create_admin_account(
            sys.argv[2].strip().lower(),
            sys.argv[3]
        )
        sys.exit(0)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )