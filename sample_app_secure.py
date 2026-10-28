"""Corrected training sample: SQL parameters, PBKDF2 hashes, and auth check."""
import hashlib
import hmac
import os
import sqlite3

DB = "training_secure.db"
ITERATIONS = 600_000

def _hash_password(password, salt=None):
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return salt.hex(), digest.hex()

def create_user(username, password, role="user"):
    salt, digest = _hash_password(password)
    with sqlite3.connect(DB) as con:
        con.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, salt TEXT, password_hash TEXT, role TEXT)")
        con.execute("INSERT OR REPLACE INTO users (username, salt, password_hash, role) VALUES (?, ?, ?, ?)", (username, salt, digest, role))

def lookup_user(username):
    try:
        with sqlite3.connect(DB) as con:
            # Bound value is treated as data, not SQL syntax.
            return con.execute("SELECT id, username, role FROM users WHERE username = ?", (username,)).fetchall()
    except sqlite3.Error:
        # In production, log diagnostic details to a protected log here.
        return "Request could not be completed"

def login(username, password):
    with sqlite3.connect(DB) as con:
        row = con.execute("SELECT salt, password_hash FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        return False
    _, candidate = _hash_password(password, bytes.fromhex(row[0]))
    return hmac.compare_digest(candidate, row[1])

def delete_user(user_id, *, is_admin=False):
    # This flag is only illustrative. A real app must derive this privilege
    # from a trusted authenticated session, never from client-controlled input.
    if not is_admin:
        raise PermissionError("Administrator authorization required")
    with sqlite3.connect(DB) as con:
        con.execute("DELETE FROM users WHERE id = ?", (user_id,))

if __name__ == "__main__":
    create_user("alice", "training-only-password")
    print("Normal lookup:", lookup_user("alice"))
    print("Injection-shaped input treated as a value:", lookup_user("' OR '1'='1"))
    print("Correct password accepted:", login("alice", "training-only-password"))
    print("Wrong password rejected:", not login("alice", "wrong-password"))
    try:
        delete_user(1)
    except PermissionError:
        print("Unauthorised deletion blocked")
