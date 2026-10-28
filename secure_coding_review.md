# Secure Coding Review

**Project:** CodeAlpha Cyber Security Task 3  
**Application:** Minimal Python and SQLite account lookup training sample  
**Review method:** Manual source review of `sample_app_vulnerable.py`, followed by a corrected teaching example in `sample_app_secure.py`  
**Scope:** SQL construction, password storage, authorization, and error handling in these sample files

## Summary

The vulnerable sample has four issues: SQL injection in account lookup, plaintext password storage, an account deletion function without an authorization check, and raw database errors returned to the caller. The corrected sample addresses each issue with parameterized queries, salted PBKDF2-HMAC-SHA256 password hashes, an authorization check against the role on an authenticated principal, and generic errors with diagnostic logging.

This is a small local training example, not a production authentication system. The review did not cover a deployed website, network exposure, third-party dependencies, or operational controls.

## Findings

| ID | Severity | Finding | Evidence in vulnerable sample | Impact |
|---|---|---|---|---|
| CR-01 | High | SQL injection in account lookup | `lookup_user` interpolates the username into SQL with an f-string | Crafted input can change query logic and expose records. The impact depends on how similar code is exposed in a real application. |
| CR-02 | High | Passwords stored in plaintext | `create_user` stores the supplied password as-is; `login` compares it directly | A database disclosure exposes readable passwords that may be reused on other services. |
| CR-03 | High | Destructive action has no authorization check | `delete_user` deletes an account by ID without checking the actor's role | Any caller that can reach this function can delete another account. This is a broken access-control condition. |
| CR-04 | Medium | Raw database errors returned | `lookup_user` catches a database exception and returns its text | Database or query details may help someone probe the implementation. Error details should stay in protected logs. |

Severity is a qualitative estimate for this demonstration, not a formal CVSS score. The sample has no network interface, so reachability in a real application would depend on how equivalent logic is exposed.

## Fixes in the corrected example

- `lookup_user` binds the username with a SQLite `?` placeholder instead of building SQL text with user input.
- Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes. `hmac.compare_digest` checks the derived hash. For a production application, use a maintained authentication library and follow current OWASP recommendations for password hashing parameters.
- `create_user` always creates a normal user. The deletion function checks an `AuthenticatedPrincipal` returned by `authenticate`, and only allows an admin role. A real web app must create that principal from a trusted server-side session, never from a role or identity supplied by the client.
- The lookup function logs database details for developers and raises a generic error to its caller.
- Account IDs and usernames are bound SQL values. The role column is constrained to the two roles used in this small example.

The demonstration-only admin account is created by a private setup helper with a training password. Do not reuse this pattern or its sample credentials in a real system. The local Python object check demonstrates where an authorization decision belongs; production frameworks must protect the session and enforce permissions at the server boundary.

OWASP Top 10:2025 includes Broken Access Control as A01 and Injection as A05. OWASP recommends parameterized queries for SQL and adaptive password hashing rather than plaintext storage.

## Review checklist

1. Compare both source files and locate the unsafe f-string query and plaintext password field in the vulnerable version.
2. Review the corrected version and confirm that lookup values use bound parameters, password values are hashed with a random per-account salt, and hashes are compared with `hmac.compare_digest`.
3. Confirm the corrected delete function checks the authenticated principal's role before deleting an account.
4. Keep the scope limitation in mind: these samples demonstrate specific coding controls and are not a security certification or complete assessment of a production application.

## References

- OWASP, [Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/)
- OWASP, [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- OWASP, [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
