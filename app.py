
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, send_file, abort
import sqlite3
import os
import io
import uuid

from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "trustvault_secret_key_2026"

UPLOAD_FOLDER = "uploads"
KEY_FILE = "secret.key"

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "docx"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# Create or load encryption key
def load_encryption_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()

        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)

    with open(KEY_FILE, "rb") as key_file:
        return Fernet(key_file.read())


cipher = load_encryption_key()


def get_db():
    conn = sqlite3.connect("trustvault.db")
    conn.row_factory = sqlite3.Row
    return conn


def create_database():
    conn = get_db()

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

    # Add encryption column to an existing database
    columns = [
        row["name"]
        for row in conn.execute("PRAGMA table_info(documents)").fetchall()
    ]

    if "encrypted" not in columns:
        conn.execute(
            "ALTER TABLE documents ADD COLUMN encrypted INTEGER DEFAULT 0"
        )

    conn.commit()
    conn.close()


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))

        return "Invalid email or password"

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not email or len(password) < 8:
            return "Enter a valid email and password with at least 8 characters."

        hashed_password = generate_password_hash(password)
        conn = get_db()

        try:
            conn.execute(
                "INSERT INTO users (email, password) VALUES (?, ?)",
                (email, hashed_password)
            )
            conn.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return "Email already registered."
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html")


@app.route("/upload", methods=["POST"])
def upload():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if "document" not in request.files:
        return "No file selected."

    file = request.files["document"]

    if file.filename == "":
        return "No file selected."

    if file and allowed_file(file.filename):
        original_filename = secure_filename(file.filename)

        stored_filename = (
            str(session["user_id"]) + "_" + str(uuid.uuid4()) + ".encrypted"
        )

        # Encrypt document before saving
        file_data = file.read()
        encrypted_data = cipher.encrypt(file_data)

        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        file_path = os.path.join(UPLOAD_FOLDER, stored_filename)

        with open(file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)

        conn = get_db()
        conn.execute(
            """INSERT INTO documents
            (user_id, filename, stored_filename, encrypted)
            VALUES (?, ?, ?, ?)""",
            (session["user_id"], original_filename, stored_filename, 1)
        )
        conn.commit()
        conn.close()

        return redirect(url_for("documents"))

    return "File type not allowed."


@app.route("/documents")
def documents():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    files = conn.execute(
        "SELECT * FROM documents WHERE user_id = ?",
        (session["user_id"],)
    ).fetchall()
    conn.close()

    return render_template("documents.html", files=files)


@app.route("/download/<int:document_id>")
def download(document_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    document = conn.execute(
        "SELECT * FROM documents WHERE id = ? AND user_id = ?",
        (document_id, session["user_id"])
    ).fetchone()
    conn.close()

    if document is None:
        abort(404)

    if document["encrypted"] == 1:
        file_path = os.path.join(
            UPLOAD_FOLDER, document["stored_filename"]
        )

        if not os.path.exists(file_path):
            abort(404)

        try:
            with open(file_path, "rb") as encrypted_file:
                encrypted_data = encrypted_file.read()

            decrypted_data = cipher.decrypt(encrypted_data)

        except InvalidToken:
            return "Unable to decrypt document. Check the encryption key."

        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=document["filename"]
        )

    # Support documents uploaded before encryption was added
    return send_from_directory(
        UPLOAD_FOLDER,
        document["stored_filename"],
        as_attachment=True,
        download_name=document["filename"]
    )


@app.route("/delete/<int:document_id>", methods=["POST"])
def delete(document_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    document = conn.execute(
        "SELECT * FROM documents WHERE id = ? AND user_id = ?",
        (document_id, session["user_id"])
    ).fetchone()

    if document is None:
        conn.close()
        abort(404)

    file_path = os.path.join(
        UPLOAD_FOLDER, document["stored_filename"]
    )

    if os.path.exists(file_path):
        os.remove(file_path)

    conn.execute(
        "DELETE FROM documents WHERE id = ? AND user_id = ?",
        (document_id, session["user_id"])
    )

    conn.commit()
    conn.close()

    return redirect(url_for("documents"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    create_database()
    app.run(debug=True)
