"""A small corrected example for the secure-coding review."""
from dataclasses import dataclass
import hashlib
import hmac
import logging
import os
import sqlite3

DB = "training_secure.db"
PBKDF2_ITERATIONS = 600_000
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Identity returned after a successful password check."""

    user_id: int
    username: str
    role: str


def initialize_database():
    """Create the account table if it does not already exist."""
    with sqlite3.connect(DB) as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('user', 'admin'))
            )"""
        )


def _hash_password(password, salt=None):
    """Return a per-password salt and a slow PBKDF2-HMAC-SHA256 hash."""
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return salt.hex(), digest.hex()


def _save_account(username, password, role):
    """Shared insert helper; role is chosen by trusted program logic."""
    salt, password_hash = _hash_password(password)
    with sqlite3.connect(DB) as connection:
        connection.execute(
            """INSERT INTO users (username, salt, password_hash, role)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(username) DO UPDATE SET
                   salt = excluded.salt,
                   password_hash = excluded.password_hash,
                   role = excluded.role""",
            (username, salt, password_hash, role),
        )


def create_user(username, password):
    """Create or reset a normal training account, never an administrator."""
    if not username.strip() or not password:
        raise ValueError("Username and password are required")
    _save_account(username, password, "user")


def _create_demo_admin(username, password):
    """Set up an admin account for this local demonstration only."""
    _save_account(username, password, "admin")


def lookup_user(username):
    """Look up a username safely and return public account fields."""
    try:
        with sqlite3.connect(DB) as connection:
            return connection.execute(
                "SELECT id, username, role FROM users WHERE username = ?",
                (username,),
            ).fetchall()
    except sqlite3.Error:
        logger.exception("Account lookup failed")
        raise RuntimeError("Could not complete account lookup") from None


def authenticate(username, password):
    """Verify a password and return a trusted principal on success."""
    with sqlite3.connect(DB) as connection:
        row = connection.execute(
            """SELECT id, username, salt, password_hash, role
               FROM users WHERE username = ?""",
            (username,),
        ).fetchone()

    if row is None:
        return None

    salt = bytes.fromhex(row[2])
    _, candidate_hash = _hash_password(password, salt)
    if not hmac.compare_digest(candidate_hash, row[3]):
        return None

    return AuthenticatedPrincipal(user_id=row[0], username=row[1], role=row[4])


def delete_user(target_user_id, actor):
    """Delete an account only when the authenticated actor is an admin.

    In a real web application, build `actor` from the server-side authenticated
    session. Never accept a role or principal supplied directly by the client.
    """
    if not isinstance(actor, AuthenticatedPrincipal) or actor.role != "admin":
        raise PermissionError("Administrator authorization required")

    with sqlite3.connect(DB) as connection:
        connection.execute("DELETE FROM users WHERE id = ?", (target_user_id,))


def main():
    initialize_database()
    create_user("alice", "training-only-user-password")
    _create_demo_admin("trainer-admin", "training-only-admin-password")

    print("Normal lookup:", lookup_user("alice"))
    print("Injection-shaped lookup:", lookup_user("' OR '1'='1"))
    print("Correct password accepted:", authenticate("alice", "training-only-user-password") is not None)
    print("Wrong password rejected:", authenticate("alice", "wrong-password") is None)

    alice = authenticate("alice", "training-only-user-password")
    alice_id = lookup_user("alice")[0][0]
    try:
        delete_user(alice_id, alice)
    except PermissionError:
        print("Unauthorised deletion blocked")

    admin = authenticate("trainer-admin", "training-only-admin-password")
    delete_user(alice_id, admin)
    print("Admin deletion allowed for the demonstration")


if __name__ == "__main__":
    main()
