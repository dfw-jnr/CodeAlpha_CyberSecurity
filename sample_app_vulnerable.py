"""Intentionally vulnerable training sample. Never expose to a network."""
import sqlite3

DB = "training.db"

def create_user(username, password, role="user"):
    with sqlite3.connect(DB) as con:
        con.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)")
        con.execute("INSERT OR REPLACE INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))

def lookup_user(username):
    try:
        with sqlite3.connect(DB) as con:
            # VULNERABLE: user-controlled input changes SQL syntax.
            return con.execute(f"SELECT id, username, role FROM users WHERE username = '{username}'").fetchall()
    except Exception as exc:
        # VULNERABLE: internal database details returned to the caller.
        return str(exc)

def login(username, password):
    with sqlite3.connect(DB) as con:
        row = con.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()
        # VULNERABLE: password is stored and compared as plaintext.
        return bool(row and row[0] == password)

def delete_user(user_id):
    with sqlite3.connect(DB) as con:
        # VULNERABLE: no caller/role authorization before destructive action.
        con.execute("DELETE FROM users WHERE id = ?", (user_id,))

if __name__ == "__main__":
    create_user("alice", "training-only-password")
    print("Lookup:", lookup_user("alice"))
    print("Injection-shaped lookup (shows the flaw):", lookup_user("' OR '1'='1' -- "))
    print("Login:", login("alice", "training-only-password"))
    print("This sample is intentionally vulnerable and for local training only.")
