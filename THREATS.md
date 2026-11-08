
# TrustVault – Threat Model

## 1. Overview

TrustVault is a secure document management and sharing application. It allows registered users to upload, store, search, download and share documents.

This document identifies possible security threats and the controls used to reduce them.

## 2. Assets to Protect

- User account credentials
- Uploaded documents
- Encryption keys
- Document permissions
- User sessions
- Audit logs
- Database records

## 3. Potential Threats and Mitigations

| Threat | Risk | Mitigation |
|---|---|---|
| Unauthorized document access | Private files may be exposed | Server-side authorization checks |
| Weak password storage | Account compromise | Password hashing |
| Session attacks | Account takeover | Secure session configuration and CSRF protection |
| Malicious file uploads | Unsafe files stored | File extension, size and content validation |
| Unauthorized downloads | Data leakage | Permission checks on download routes |
| Permission misuse | Shared files accessed improperly | Owner-controlled read/edit permissions |
| Access after revocation | Former users retain access | Check permissions on every request |
| Audit log tampering | Activity records become unreliable | Hash-chain verification |
| SQL injection | Database compromise | Parameterized SQL queries |
| Secret exposure | Encryption or session compromise | Keep keys and environment files out of Git |

## 4. Access Control

- Owners can manage their own documents.
- Viewers can access only documents shared with them.
- Edit permission is required for document modifications.
- Only document owners can share or revoke permissions.
- Administrators can access the administrative audit dashboard.
- Authorization must be checked on the server for every protected operation.

## 5. Audit Logging

Important actions should be recorded, including:

- Login and logout
- Document uploads
- Document downloads
- Document edits
- Document deletions
- Permission grants and revocations
- Denied access attempts

Audit records should be protected against unauthorized modification. Hash-chain verification helps detect changes to recorded events.

## 6. Security Testing Plan

The following scenarios should be tested:

1. A user cannot download another user's private document.
2. A user cannot delete another user's document.
3. A viewer cannot edit a read-only document.
4. Revoked users cannot access previously shared documents.
5. Invalid file uploads are rejected.
6. Requests without valid CSRF tokens are rejected.
7. Unauthorized users cannot access the admin audit dashboard.
8. Audit-chain verification detects modified records.

## 7. Limitations and Future Improvements

- Deploy behind HTTPS.
- Use secure production session-cookie settings.
- Store encryption keys in a secure secret-management service.
- Add rate limiting for login attempts.
- Add automated security testing in CI.
- Use a production WSGI server instead of Flask's development server.

## 8. Conclusion

TrustVault follows a security-focused design using authentication, authorization, encrypted document storage, upload validation and audit logging. Security tests and deployment checks are required to verify these protections before production use.
