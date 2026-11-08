
# TrustVault
### Secure Documents. Trusted Access.

TrustVault is a secure document management and sharing web application built using Python and Flask.

It allows users to upload, organize, search, download and securely share documents with other registered users.

## Features

- User registration and login
- Password hashing
- Role-based access control
- Secure document uploads
- File encryption using Fernet
- Document search by filename, owner, category and date
- Per-document read and edit permissions
- Share documents with registered users
- Revoke document access
- Protected download, edit and delete operations
- CSRF protection for POST requests
- File extension and content validation
- Audit logging for important actions
- Admin audit dashboard
- Audit-chain verification

## Technology Stack

- Python
- Flask
- SQLite
- HTML
- CSS
- Cryptography (Fernet)
- Git and GitHub
- Pytest

## Project Structure

```text
TrustVault_/
├── app.py
├── requirements.txt
├── README.md
├── API.md
├── THREATS.md
├── PROMPTS.md
├── .gitignore
├── templates/
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── documents.html
│   └── admin_audit.html
├── static/
│   └── css/
│       └── style.css
└── uploads/
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Nandaki06/TrustVault_.git
cd TrustVault_
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the environment

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the application

```bash
python app.py
```

Open the application in your browser:

http://127.0.0.1:5000

## Admin Account

An administrator account can be created using the application's admin creation command.

```bash
python app.py create-admin admin@example.com <YOUR_PASSWORD>
```

Use a strong private password. Never commit credentials to GitHub.

## Security

TrustVault uses password hashing, encrypted document storage, server-side permission checks, CSRF protection, upload validation and audit logging.

Refer to [THREATS.md](THREATS.md) for security considerations and [API.md](API.md) for endpoint documentation.

## AI Usage

AI assistance during development is documented in [PROMPTS.md](PROMPTS.md).

## Testing

Automated security and functionality tests will be documented after implementation and execution.

## Project Status

Developed as a secure document management and sharing project for the Snovasys Fresher Hiring Challenge 2026.

Features and security controls must be verified before final deployment and submission.
```

