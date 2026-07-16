"""M4.2 RBAC: user store (SQLite, stdlib-only).

Password hashing via `hashlib.scrypt` (stdlib since Python 3.6, a memory-hard
KDF on NIST's approved list) rather than adding argon2-cffi/bcrypt as a new
dependency -- this project is stdlib-first by convention (CLAUDE.md), and
scrypt via the standard library gets the same security property (slow,
memory-hard, salted) without the dependency-addition guardrail.

Mirrors services/ws6-inventory/store.py's SQLite conventions: stdlib sqlite3,
check_same_thread=False + a write lock for the shared connection, `:memory:`
default for zero-infra tests.

Roles (least to most privilege): read_only < analyst < admin. See rbac.py
for the permission model built on top of this.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from typing import Optional

ROLES = ("read_only", "analyst", "admin")
DEFAULT_TENANT = "default"

_SCRYPT_N = 2 ** 14  # ~50ms/call on a modern CPU -- slow enough to matter
_SCRYPT_R = 8        # against brute force, fast enough not to DoS login.
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                         n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN)
    return f"scrypt${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time-compare verify. Any malformed `stored` value (wrong
    algo tag, bad hex, etc.) fails closed to False, never raises -- a
    corrupt row must not become a crash or, worse, an auth bypass."""
    try:
        algo, salt_hex, hash_hex = stored.split("$")
        if algo != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                             n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


# M4.6: forward-only schema migrations, tracked via SQLite's built-in
# `PRAGMA user_version` (an integer stored in the file header -- no extra
# bookkeeping table needed). Each entry is (version, sql-to-reach-it) applied
# in order starting from whatever version an existing DB file is already at,
# so an operator's users.db from an older FENGARDE release upgrades in place
# instead of needing a hand-run ALTER or a fresh DB (which would silently
# discard every existing account). Never edit a past migration in place --
# add a new one, same discipline as any real migration tool.
_SCHEMA_MIGRATIONS: list[tuple[int, str]] = [
    (1, """
        CREATE TABLE IF NOT EXISTS users (
          username TEXT PRIMARY KEY,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL,
          tenant_id TEXT NOT NULL DEFAULT 'default',
          created_at INTEGER NOT NULL
        );
        """),
    (2, "ALTER TABLE users ADD COLUMN last_login_at INTEGER"),
]

CURRENT_SCHEMA_VERSION = _SCHEMA_MIGRATIONS[-1][0]


def migrate(db: sqlite3.Connection) -> int:
    """Apply every pending migration in order. Returns the version the DB
    ends up at (== CURRENT_SCHEMA_VERSION on success). A DB already at the
    latest version is a no-op -- safe to call on every startup."""
    current = db.execute("PRAGMA user_version").fetchone()[0]
    for version, sql in _SCHEMA_MIGRATIONS:
        if version <= current:
            continue
        db.executescript(sql)
        db.execute(f"PRAGMA user_version = {version}")
        db.commit()
        current = version
    return current


class UserStore:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._write_lock = threading.Lock()  # same rationale as InventoryStore
        self._init()

    def _init(self):
        migrate(self.db)

    def count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def create_user(self, username: str, password: str, role: str,
                     tenant_id: str = DEFAULT_TENANT) -> None:
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}, must be one of {ROLES}")
        with self._write_lock:
            self.db.execute(
                "INSERT INTO users (username, password_hash, role, tenant_id, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (username, hash_password(password), role, tenant_id, int(time.time())),
            )
            self.db.commit()

    def get_user(self, username: str) -> Optional[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

    def verify_login(self, username: str, password: str) -> Optional[sqlite3.Row]:
        """Return the user row on success, None on any failure (unknown
        user or wrong password -- deliberately the SAME failure shape for
        both, so a login endpoint never leaks "username exists but
        password wrong" vs "username doesn't exist" via a different
        response, an enumeration side channel)."""
        row = self.get_user(username)
        if row is None:
            # Still run a scrypt hash so a nonexistent-username request takes
            # roughly the same wall-clock time as a real one (timing-based
            # username enumeration defense).
            verify_password(password, hash_password("decoy"))
            return None
        if not verify_password(password, row["password_hash"]):
            return None
        with self._write_lock:
            self.db.execute(
                "UPDATE users SET last_login_at = ? WHERE username = ?",
                (int(time.time()), username),
            )
            self.db.commit()
        return row

    def set_password(self, username: str, new_password: str) -> None:
        with self._write_lock:
            self.db.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (hash_password(new_password), username),
            )
            self.db.commit()

    def list_users(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT username, role, tenant_id, created_at FROM users").fetchall()


def ensure_first_boot_admin(store: UserStore, username: str = "admin") -> Optional[str]:
    """If the user store is empty, create one admin user with a random
    password and return it (caller prints it ONCE, per PLAN_A's ask -- no
    default admin/admin credential ever exists). Returns None if users
    already exist (nothing to do, not a first boot)."""
    if store.count() > 0:
        return None
    password = secrets.token_urlsafe(18)  # ~24 chars, printable, no shell-quoting surprises
    store.create_user(username, password, role="admin", tenant_id=DEFAULT_TENANT)
    return password
