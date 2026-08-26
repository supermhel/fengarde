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
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Optional

# FENGARDE E3 MFA: the stdlib-only TOTP primitive is `shared/mfa.py`, a SIBLING
# of this module. It imports nothing from shared, so there is no circular
# import; the sys.path insert only makes it importable when users.py is loaded
# as a top-level module rather than as `shared.users`.
#
# It lived in services/ws6-inventory/mfa.py until 2026-08-11, reached from here
# by walking `parent.parent / "ws6-inventory"`. That path is correct in a source
# checkout and WRONG in every deployed image: ws3-indexer's Dockerfile copies
# `services/shared` to /app/shared and does NOT copy ws6-inventory, so the walk
# resolved to a nonexistent /app/ws6-inventory, the import failed, and the
# `except` below silently set _TOTP_AVAILABLE = False. In the shipped
# ws3-indexer container that meant `provision_totp()` raised and `verify_totp()`
# returned False for EVERY code -- MFA inert in production while its zero-infra
# tests passed, because in a checkout the path resolves fine. Found 2026-08-11
# by running the MFA flow against the real container for the first time.
# ws6-inventory never imported this module at all (its own INTERFACE.md said so:
# "hosted here, NOT wired into this service's own auth"), so shared/ was always
# the right home.
try:
    _SHARED_DIR = Path(__file__).resolve().parent
    if str(_SHARED_DIR) not in sys.path:
        sys.path.insert(0, str(_SHARED_DIR))
    import mfa as _mfa  # noqa: E402
    _TOTP_AVAILABLE = True
except Exception as _totp_exc:  # noqa: BLE001 - TOTP must never take the whole store down
    # Still defensive -- a broken TOTP import must not stop the user store from
    # serving password auth -- but no longer SILENT. A security control that
    # disables itself without a trace is the worst of both worlds: operators
    # believe MFA is enforced while every code is rejected. Call sites that
    # genuinely need TOTP still fail loudly (see provision_totp).
    import warnings as _warnings
    _warnings.warn(
        f"FENGARDE: TOTP/MFA support is UNAVAILABLE ({type(_totp_exc).__name__}: "
        f"{_totp_exc}). Password auth still works, but provision_totp() will "
        f"raise and verify_totp() will reject every code. If this deployment "
        f"expects MFA, it is NOT being enforced.",
        RuntimeWarning, stacklevel=2)
    _mfa = None  # type: ignore[assignment]
    _TOTP_AVAILABLE = False

ROLES = ("read_only", "analyst", "admin")
DEFAULT_TENANT = "default"

# _SCRYPT_N bumped 2**14 -> 2**16 (RFC 7914's "interactive" preset was
# 2**14; current OWASP Password Storage Cheat Sheet guidance has moved
# higher). Not doubled all the way to OWASP's 2**17 default -- this module's
# own original rationale ("~50ms/call... fast enough not to DoS login") is
# still the binding constraint on an interactive login path, and 2**17 was
# measured noticeably heavier. The stored hash now self-describes its N
# (``scrypt$<n>$<salt>$<hash>``) specifically so N can be raised again later
# without a migration or breaking any already-stored hash: verify_password
# reads N back out of the string it's checking instead of assuming today's
# constant, so a hash written under an older N keeps verifying correctly
# even after this constant next changes.
_SCRYPT_N = 2 ** 16
_SCRYPT_R = 8        # against brute force, fast enough not to DoS login.
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_LEGACY_SCRYPT_N = 2 ** 14  # every hash stored before this fix used this N,
                            # unlabeled (3-field "scrypt$salt$hash" format).


def _scrypt_maxmem(n: int, r: int, p: int) -> int:
    """OpenSSL's scrypt refuses to run above a default 32MB working-set cap
    (hashlib.scrypt's own default maxmem) and raises ValueError('memory
    limit exceeded') instead of silently ignoring it -- discovered live when
    bumping _SCRYPT_N to 2**16 (RFC 7914's memory formula: 128*N*r*p bytes =
    64MB at N=2**16,r=8,p=1, double the default cap) made every login and
    every process-start (_DECOY_HASH's own hash_password("decoy") call at
    import time) crash outright. Compute the real requirement plus headroom
    explicitly instead of leaving it to guesswork or silently capping N low
    enough to fit under an unrelated library default."""
    return 128 * n * r * p * 2


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                         n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN,
                         maxmem=_scrypt_maxmem(_SCRYPT_N, _SCRYPT_R, _SCRYPT_P))
    return f"scrypt${_SCRYPT_N}${salt.hex()}${dk.hex()}"


# Fixed decoy hash for the unknown-username timing defense in verify_login().
# Computed once at import time (one scrypt call, not two) so the "unknown
# username" path costs exactly one hash_password + one verify_password call --
# the same as the "known username, wrong password" path. A per-call
# hash_password("decoy") would run scrypt twice (once to build the decoy hash,
# once inside verify_password to check it), making the unknown-username path
# ~2x slower than the wrong-password path and reopening the enumeration
# side-channel this is meant to close.
_DECOY_HASH = hash_password("decoy")


def verify_password(password: str, stored: str) -> bool:
    """Constant-time-compare verify. Any malformed `stored` value (wrong
    algo tag, bad hex, etc.) fails closed to False, never raises -- a
    corrupt row must not become a crash or, worse, an auth bypass.

    Accepts both the current 4-field format (``scrypt$N$salt$hash``, N
    self-described so a future N bump doesn't invalidate every existing
    hash) and the legacy 3-field format written before this fix
    (``scrypt$salt$hash``, implicitly N=_LEGACY_SCRYPT_N)."""
    try:
        parts = stored.split("$")
        if len(parts) == 4:
            algo, n_str, salt_hex, hash_hex = parts
            n = int(n_str)
            if n <= 0:
                return False
        elif len(parts) == 3:
            algo, salt_hex, hash_hex = parts
            n = _LEGACY_SCRYPT_N
        else:
            return False
        if algo != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                             n=n, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN,
                             maxmem=_scrypt_maxmem(n, _SCRYPT_R, _SCRYPT_P))
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
    # FENGARDE E3 MFA: opt-in per-user TOTP. Both columns are ADDITIVE and
    # default-null/zero, so existing pre-E3 users.db files upgrade in place
    # and every existing account starts with TOTP DISABLED -- login for them
    # is byte-for-byte unchanged until an admin/user provisions and verifies.
    (3, """
        ALTER TABLE users ADD COLUMN totp_secret TEXT;
        ALTER TABLE users ADD COLUMN totp_active INTEGER NOT NULL DEFAULT 0;
        """),
    # Gap-hunt finding (2026-08-23): verify_totp() had no replay protection --
    # a captured valid code could be resubmitted within its ~90s validity
    # window to open a second session. -1 means "no code ever accepted yet"
    # (a real counter is always >= 0, floor(unix_time/30)), so every existing
    # account upgrades in place with no behavior change until its next TOTP use.
    (4, "ALTER TABLE users ADD COLUMN totp_last_counter INTEGER NOT NULL DEFAULT -1"),
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
            # Still run a scrypt verify so a nonexistent-username request takes
            # roughly the same wall-clock time as a real one (timing-based
            # username enumeration defense) -- one scrypt op, matching the
            # wrong-password path's cost exactly (see _DECOY_HASH above).
            verify_password(password, _DECOY_HASH)
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

    # -- FENGARDE E3 MFA: opt-in per-user TOTP ------------------------------
    # Every helper is a graceful no-op when the mfa module is unavailable
    # (_TOTP_AVAILABLE is False), so an environment that somehow lacks
    # shared/mfa.py simply behaves as if MFA were never enabled --
    # never a crash, and never an auth lock-out.

    def enable_totp(self, username: str, secret: str) -> None:
        """Provision a TOTP secret for `username` (stored, NOT yet active).

        The account keeps logging in with password only until
        `verify_totp` confirms a first valid code -- this two-step enable
        (store secret, then confirm) prevents an operator from turning on
        MFA for an account whose authenticator app is pointed at the wrong
        key and locking that user out. Unknown usernames are a silent no-op
        (UPDATE matches zero rows), same non-enumerating posture as login.
        """
        with self._write_lock:
            self.db.execute(
                "UPDATE users SET totp_secret = ?, totp_active = 0 WHERE username = ?",
                (secret, username),
            )
            self.db.commit()

    def provision_totp(self, username: str, issuer: str = "FENGARDE") -> str:
        """Generate a fresh secret, store it (one step of two), and return
        the `otpauth://` provisioning URI for a QR code.

        The caller shows the URI to the user; the account is only actually
        MFA-protected once `verify_totp` confirms a code.
        """
        if not _TOTP_AVAILABLE:
            raise RuntimeError("TOTP support unavailable (shared/mfa.py not loadable)")
        secret = _mfa.generate_secret()
        self.enable_totp(username, secret)
        return _mfa.otpauth_uri(secret, label=username, issuer=issuer)

    def is_totp_enabled(self, username: str) -> bool:
        """True once this account has an ACTIVE TOTP (secret verified)."""
        row = self.get_user(username)
        return bool(row and row["totp_active"])

    def verify_totp(self, username: str, code: str) -> bool:
        """Check `code` against the account's stored secret and record it as
        the last accepted step for this account.

        Returns False for any failure (no secret, wrong code, missing mfa
        module, unknown user, OR a code whose time-step has already been
        accepted once -- replay protection, see below) -- never raises.

        This is the LOGIN-path entry point. For enrollment confirmation
        (after ``/auth/mfa/enable``) use :meth:`confirm_totp`, which
        activates the secret without advancing the per-account
        ``totp_last_counter`` (otherwise the very next login within the
        code's +/-1-step window would be rejected as a replay).
        """
        if not _TOTP_AVAILABLE:
            return False
        row = self.get_user(username)
        if row is None:
            return False
        secret = row["totp_secret"]
        if not secret:
            return False
        matched_counter = _mfa.verify_code_returning_counter(secret, code)
        if matched_counter is None:
            return False
        # The counter read, replay check, and UPDATE must all happen under
        # the SAME lock -- otherwise two threads verifying the same code
        # concurrently can both read totp_last_counter=5, both pass the
        # check, and both write counter=6 (the TOCTOU this finding fixed).
        with self._write_lock:
            row = self.db.execute(
                "SELECT totp_active, totp_last_counter FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                return False
            if matched_counter <= row["totp_last_counter"]:
                return False
            self.db.execute(
                "UPDATE users SET totp_active = 1, totp_last_counter = ? WHERE username = ?",
                (matched_counter, username),
            )
            self.db.commit()
        return True

    def confirm_totp(self, username: str, code: str) -> bool:
        """Confirm an enrollment code (after ``/auth/mfa/enable``).

        Unlike :meth:`verify_totp`, this does NOT advance
        ``totp_last_counter`` -- its only job is to flip ``totp_active``
        from 0 to 1 so the account is MFA-protected going forward.
        If it burned the counter the user's very next real login (within
        the same +/-1-step window) would be rejected as a replay.
        """
        if not _TOTP_AVAILABLE:
            return False
        row = self.get_user(username)
        if row is None:
            return False
        secret = row["totp_secret"]
        if not secret:
            return False
        matched_counter = _mfa.verify_code_returning_counter(secret, code)
        if matched_counter is None:
            return False
        with self._write_lock:
            self.db.execute(
                "UPDATE users SET totp_active = 1 WHERE username = ?",
                (username,),
            )
            self.db.commit()
        return True


    def list_users(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT username, role, tenant_id, created_at FROM users").fetchall()


def ensure_first_boot_admin(store: UserStore, username: str = "admin") -> Optional[str]:
    """First-boot bootstrap: if the user store is empty, create one admin.

    The initial password comes from the operator via FENGARDE_ADMIN_PASSWORD
    (read here at first boot only). The service itself never generates,
    stores, logs, or returns a plaintext credential -- only the scrypt hash
    ever touches disk. This closes both CodeQL findings the earlier designs
    hit in turn (py/clear-text-logging for print-the-password, then
    py/clear-text-storage for write-it-to-a-0600-file): the only party that
    ever holds the plaintext is the operator who chose it. Still no
    admin/admin or any other default credential (PLAN_A's ask) -- env var
    unset means NO account is created and RBAC stays fail-closed (nobody
    can log in) until the operator provides one and restarts.

    Returns the username if an account was created by this call, else None
    (users already exist, or the env var is unset). Never the password.
    """
    if store.count() > 0:
        return None
    password = os.getenv("FENGARDE_ADMIN_PASSWORD")
    if not password:
        return None
    store.create_user(username, password, role="admin", tenant_id=DEFAULT_TENANT)
    return username
