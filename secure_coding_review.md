# Secure Coding Review

**Project:** CodeAlpha Cyber Security Task 3  
**Application:** Minimal Python/SQLite account lookup training sample  
**Review method:** Manual source review of `sample_app_vulnerable.py`; corrected implementation in `sample_app_secure.py`  
**Scope:** SQL construction, password handling, query authorization, and error handling in the sample only

## Summary

The training sample has three high-impact defects: SQL injection in account lookup, plaintext password storage/comparison, and an administrative delete operation with no authorization check. It also returns raw database exceptions to callers. The sample is not production code. This focused manual review did not assess deployment, dependencies, network exposure, or a larger application.

The fixed version uses bound SQL parameters, salted PBKDF2-HMAC-SHA256 password hashes with constant-time verification, an explicit authorization check before deletion, and generic error handling. It is a teaching example, not a production-ready authentication system.

## Findings

| ID | Severity | Finding | Evidence in vulnerable sample | Impact |
|---|---|---|---|---|
| CR-01 | High | SQL injection in account lookup | `lookup_user` interpolates the username into SQL with an f-string | Crafted input can change query logic and expose records; impact depends on database access and application context. OWASP recommends parameterized queries. |
| CR-02 | High | Passwords stored in plaintext | `create_user` stores the supplied password as-is; `login` compares it directly | A database disclosure exposes reusable passwords in readable form. Users may reuse passwords elsewhere. |
| CR-03 | High | Destructive admin action lacks authorization | `delete_user` deletes by user-supplied ID without checking caller role | Any caller able to reach the function can remove another account. This is a broken access-control condition. |
| CR-04 | Medium | Raw database exceptions are returned | `lookup_user` catches an exception and returns its text | Internal table/query details may be disclosed, helping an attacker probe implementation. Errors should be logged privately and generic messages returned. |

Severity is a qualitative estimate for this small demonstration, not a formal CVSS score. The sample has no network interface, so reachability in a real system would depend on how equivalent logic is exposed.

## Remediation and corrected implementation

- Bind values with SQLite placeholders (`?`) rather than inserting input into SQL text.
- Store password hashes using a slow password hashing algorithm with a per-password salt. The fixed example uses Python's standard-library PBKDF2-HMAC-SHA256 and constant-time comparison. For production, prefer a maintained framework/library and follow current OWASP parameters; do not treat this example's iteration count as a universal current recommendation.
- Require a trusted, server-established authorization decision before destructive actions. Do not accept a role claim from an untrusted caller.
- Return a generic error to callers and record diagnostic details only in protected logs.
- Apply least privilege to the database account and add automated tests for authorization and malformed input.

The corresponding changes are in `sample_app_secure.py`. The OWASP Top 10:2025 lists broken access control as A01 and injection as A05. OWASP's SQL Injection Prevention guidance recommends prepared statements with parameterized queries; OWASP's Password Storage guidance recommends modern adaptive hashes such as Argon2id, bcrypt, or PBKDF2.

## Verification checklist

1. Run the vulnerable sample and confirm its demonstration shows the unsafe query pattern and direct password storage in source.
2. Run the secure sample. It should report successful lookup for a normal username, reject a SQL-injection-shaped username as an ordinary unmatched value, verify a correct password, reject a wrong password, reject deletion without admin authorization, and allow deletion only when the explicit admin flag is true.
3. Review the secure source: user-controlled values are bound parameters; the password database column contains a derived hash and salt rather than the original password; `hmac.compare_digest` is used; errors returned to the caller are generic.
4. Treat these checks as a small demonstration, not proof of security for a production application. A real review should include the full application, threat model, framework configuration, dependencies, tests, deployment, and access-control boundaries.

## References

- OWASP, [Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/)
- OWASP, [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- OWASP, [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
