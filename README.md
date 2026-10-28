# CodeAlpha Cyber Security Tasks

This student project covers two tasks from the internship sheet:

1. **Task 2 - Phishing Awareness Training:** `phishing_awareness.html` is a self-contained lesson with a sample message, practical response steps, and a short interactive quiz.
2. **Task 3 - Secure Coding Review:** `secure_coding_review.md` explains a manual review of `sample_app_vulnerable.py` and the fixes shown in `sample_app_secure.py`.

## Open the training lesson

Open `phishing_awareness.html` in a current browser. The lesson and quiz work locally without installing anything. The reference links at the bottom need an internet connection.

## Run the sample apps

Both scripts use Python's standard library. From this folder, run:

```powershell
python sample_app_vulnerable.py
python sample_app_secure.py
```

Each script uses its own local SQLite file. The vulnerable version is included to show the review findings. Keep it on a local machine with disposable training data; do not put it on a public server or use real passwords. The corrected example shows safer query, password, and authorization patterns, but it is not a production-ready login system.

## Submission notes

The suggested repository name is `CodeAlpha_CyberSecurity`. Before submission, add your name to the report if your instructor expects it. The internship sheet also asks for a project video on LinkedIn and submission through the CodeAlpha form; complete those steps using your own account.

## References

- CISA, [Phishing: Simple Tips](https://www.cisa.gov/sites/default/files/2024-02/Update%20to%20Phishing%20General%20Security%20Postcard_01.01.2024.pdf)
- FTC, [How to Recognize and Avoid Phishing Scams](https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams)
- FBI, [Business Email Compromise](https://www.fbi.gov/how-we-can-help-you/common-frauds-and-scams/business-email-compromise)
- DOJ, [2024 BEC forfeiture action involving an alleged $6.4 million wire fraud](https://www.justice.gov/archives/opa/pr/united-states-files-forfeiture-action-recover-over-5m-funds-traceable-business-email)
- OWASP, [Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/)
- OWASP, [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- OWASP, [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
