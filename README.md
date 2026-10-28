# CodeAlpha Cyber Security Tasks

This project completes two items from the supplied internship task sheet:

1. **Task 2 - Phishing Awareness Training:** `phishing_awareness.html` is a self-contained browser lesson with warning signs, a realistic training example, safe-response steps, and an interactive quiz.
2. **Task 3 - Secure Coding Review:** `secure_coding_review.md` documents a manual review of the intentionally vulnerable `sample_app_vulnerable.py`, the fixes in `sample_app_secure.py`, and a repeatable verification checklist.

## Run the lesson

Open `phishing_awareness.html` in a current browser. It needs no install, server, or network connection for the lesson and quiz. Source links at the bottom need internet access.

## Run the sample apps

Both sample programs use only Python's standard library. Run either from this directory:

```powershell
python sample_app_vulnerable.py
python sample_app_secure.py
```

The sample creates `training.db` in its working directory and prints a small demonstration. The vulnerable version is intentionally unsafe. Use only with disposable training data; do not expose it to a network or use real credentials. The secure version uses parameterized SQL and PBKDF2 password hashes. Neither script is a production web application or a substitute for a full security assessment.

## Suggested repository name

`CodeAlpha_CyberSecurity`

Before submitting, replace the author line in the report if desired, create your own GitHub repository, upload the project files, and paste its URL in the official submission form. The internship sheet also asks participants to post an internship status and a project video on LinkedIn; those are personal account actions for you to complete.

## References

- CISA, [Phishing: Simple Tips](https://www.cisa.gov/sites/default/files/2024-02/Update%20to%20Phishing%20General%20Security%20Postcard_01.01.2024.pdf)
- FTC, [How to Recognize and Avoid Phishing Scams](https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams)
- FBI, [Business Email Compromise](https://www.fbi.gov/how-we-can-help-you/common-frauds-and-scams/business-email-compromise)
- DOJ, [2024 BEC forfeiture action involving an alleged $6.4 million wire fraud](https://www.justice.gov/archives/opa/pr/united-states-files-forfeiture-action-recover-over-5m-funds-traceable-business-email)
- OWASP, [Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/)
- OWASP, [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- OWASP, [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
