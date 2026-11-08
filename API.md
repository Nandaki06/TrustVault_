
# TrustVault API Documentation

## Overview

TrustVault is a Flask-based secure document management application.

The application uses session-based authentication, SQLite storage, document encryption and per-document access permissions.

## Authentication

| Endpoint | Method | Access |
|---|---|---|
| `/` | GET | Public |
| `/register` | GET, POST | Public |
| `/login` | GET, POST | Public |
| `/logout` | POST | Authenticated users |

## Dashboard and Documents

| Endpoint | Method | Access |
|---|---|---|
| `/dashboard` | GET | Authenticated users |
| `/documents` | GET | Authenticated users |
| `/upload` | POST | Authenticated users |
| `/download/<document_id>` | GET | Owner or users with read/edit permission |
| `/replace/<document_id>` | POST | Owner or users with edit permission |
| `/delete/<document_id>` | POST | Document owner |

## Document Sharing

| Endpoint | Method | Access |
|---|---|---|
| `/share/<document_id>` | POST | Document owner |
| `/revoke/<document_id>/<target_user_id>` | POST | Document owner |

Owners can grant read or edit access to registered users. Owners can revoke previously granted permissions.

Revoked users should immediately lose access to the document.

## Administration

| Endpoint | Method | Access |
|---|---|---|
| `/admin/audit` | GET | Admin only |

The admin audit page displays recorded application activities and audit-chain verification status.

## Security Controls

- Authentication is required for protected routes.
- Document access is checked on the server.
- CSRF tokens are required for protected POST requests.
- Uploaded files are validated.
- Documents are encrypted before storage.
- Important actions are recorded in audit logs.

## Error Responses

| Status Code | Meaning |
|---|---|
| 403 | Access denied |
| 404 | Resource not found |
| 413 | Uploaded file exceeds the size limit |

## Notes

This documentation describes the application's intended endpoint access rules. All endpoints and permissions must be verified through automated tests before final submission.
