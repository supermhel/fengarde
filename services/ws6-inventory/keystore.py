"""F1 second follow-up (2026-07-30): per-tenant API keys, hashed at rest.

The first F1 follow-up added `FENGARDE_API_KEYS` (plaintext `tenant:key` pairs
in an env var, compared with `hmac.compare_digest`) -- real isolation, but the
key material itself lived in cleartext for as long as the process/env
persisted, and rotating/provisioning meant hand-editing an env var. This
replaces that with a real keystore: one SQLite table (`api_keys`, in the same
file as `INVENTORY_DB`), one scrypt hash per tenant, no raw key ever written
to disk. Hashing mirrors `services/shared/users.py::hash_password` exactly
(same KDF, same cost parameters, same "scrypt$salt$hash" format) for
consistency with the one other place this codebase hashes a secret --
ws6's Docker image doesn't bundle `services/shared` (see Dockerfile), so this
stays a standalone copy rather than an import, same rationale as authz.py.

Backward compatibility: `ensure_legacy_keys_migrated()` is a first-boot
bootstrap, same shape as `shared/users.py::ensure_first_boot_admin` -- if the
keystore is empty and an operator already has `FENGARDE_API_KEYS` or the
original single `FENGARDE_API_KEY` configured, their EXISTING key value(s)
are hashed and provisioned as-is. Nothing the operator holds today needs to
change; they keep sending the exact same X-Api-Key they always did, and it
now authenticates via the hashed keystore instead of a live plaintext
compare. FENGARDE_API_KEYS/FENGARDE_API_KEY are consulted ONLY as migration
input, once, at startup -- once the keystore has any row, it is the sole
source of truth for every subsequent request (see app.py::_check_auth).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone

from store import DEFAULT_TENANT

ADMIN_TENANT_MARKER = "*"

# Same cost parameters as shared/users.py::hash_password -- ~50ms/call on a
# modern CPU, deliberately slow/memory-hard (NIST-approved KDF) against an
# offline attack on a stolen DB, without adding argon2-cffi/bcrypt as a new
# dependency (this project is stdlib-first by convention, CLAUDE.md).
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def generate_raw_key() -> str:
    """A fresh, high-entropy key for provisioning a new tenant. 32 random
    bytes, url-safe base64 -- same primitive `shared/sessions.py` already
    uses for session tokens (`secrets.token_urlsafe`)."""
    return secrets.token_urlsafe(32)


def _hash_key(raw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(raw.encode("utf-8"), salt=salt,
                         n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN)
    return f"scrypt${salt.hex()}${dk.hex()}"


def _verify_key(raw: str, stored: str) -> bool:
    """Constant-time-compare verify. A malformed `stored` value (wrong algo
    tag, bad hex) fails closed to False, never raises -- a corrupt row must
    not become a crash or, worse, an auth bypass. Mirrors
    shared/users.py::verify_password exactly."""
    try:
        algo, salt_hex, hash_hex = stored.split("$")
        if algo != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.scrypt(raw.encode("utf-8"), salt=salt,
                             n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def _lookup_hash(raw: str) -> str:
    """A fast (non-memory-hard) SHA-256 of the raw key, used ONLY to narrow
    an incoming request down to a single candidate row via an indexed
    lookup -- the actual authentication decision is always _verify_key()'s
    salted scrypt compare below. Without this, verifying a request against
    N provisioned tenants would cost N scrypt calls (~50ms each, per
    shared/users.py's own budget) on every single request: fine for a
    handful of tenants, a real latency problem -- and a cheap
    computational-DoS lever for an attacker sending garbage keys -- at MSP
    scale. A collision or reversal of this hash only wastes an attacker's
    time confirming they guessed the wrong row; it is never itself the
    security boundary, so an unsalted fast hash is the right tool here,
    same tradeoff production API-key systems (e.g. GitHub PATs) make."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _parse_legacy_tenant_keys(raw: str | None) -> dict[str, str]:
    """`FENGARDE_API_KEYS='acme:key1,globex:key2,*:adminkey'` -> {tenant: key}.
    Migration input only (see ensure_legacy_keys_migrated) -- this env var is
    never consulted live once the keystore has been seeded. A malformed
    entry (no ':', empty tenant, empty key) is skipped rather than raising --
    a typo'd extra entry must never crash startup; the entries that DO parse
    still migrate correctly."""
    if not raw:
        return {}
    out: dict[str, str] = {}
    for pair in raw.split(","):
        tenant, sep, key = pair.strip().partition(":")
        tenant, key = tenant.strip(), key.strip()
        if sep and tenant and key:
            out[tenant] = key
    return out


class TenantKeyStore:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._write_lock = threading.Lock()
        self._init()

    def _init(self):
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
              tenant_id TEXT PRIMARY KEY,
              lookup_hash TEXT NOT NULL UNIQUE,
              key_hash TEXT NOT NULL,
              source TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            """
        )
        self.db.commit()

    def count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]

    def provision(self, tenant_id: str, raw_key: str, source: str = "generated") -> None:
        """Create or ROTATE (overwrite) tenant_id's key. One active key per
        tenant by design -- provisioning a new key for a tenant immediately
        invalidates whatever key it had before (no dual-key grace period;
        out of scope for this pass -- an operator rotating a key needs to
        update the caller in the same maintenance window)."""
        with self._write_lock:
            self.db.execute(
                "INSERT INTO api_keys(tenant_id, lookup_hash, key_hash, source, created_at) "
                "VALUES (?,?,?,?,?) "
                "ON CONFLICT(tenant_id) DO UPDATE SET "
                "lookup_hash=excluded.lookup_hash, key_hash=excluded.key_hash, "
                "source=excluded.source, created_at=excluded.created_at",
                (tenant_id, _lookup_hash(raw_key), _hash_key(raw_key), source, _now_iso()),
            )
            self.db.commit()

    def verify(self, raw_key: str):
        """Returns (True, tenant_id_or_None) on success -- None means the
        `*` admin key (unrestricted, caller's own tenant_id trusted as-is,
        same as the pre-F1/legacy shared-key trust level). Returns
        (False, None) on any failure: empty header, unknown key, or a key
        that fails the scrypt compare. Exactly one scrypt call per request
        regardless of how many tenants are provisioned (see
        _lookup_hash's docstring)."""
        if not raw_key:
            return False, None
        row = self.db.execute(
            "SELECT tenant_id, key_hash FROM api_keys WHERE lookup_hash=?",
            (_lookup_hash(raw_key),),
        ).fetchone()
        if row is None:
            # Still spend one scrypt call so a nonexistent key takes roughly
            # the same wall-clock time as a real near-miss -- same timing
            # discipline as shared/users.py::verify_login's decoy hash.
            _verify_key(raw_key, _hash_key("decoy"))
            return False, None
        if not _verify_key(raw_key, row["key_hash"]):
            return False, None
        tenant_id = row["tenant_id"]
        return True, (None if tenant_id == ADMIN_TENANT_MARKER else tenant_id)

    def list_tenants(self) -> list[str]:
        """Provisioned tenant ids (never key material) -- for ops tooling
        and the migration startup log line."""
        return [r["tenant_id"] for r in
                self.db.execute("SELECT tenant_id FROM api_keys ORDER BY tenant_id").fetchall()]


def ensure_legacy_keys_migrated(store: TenantKeyStore) -> list[str]:
    """First-boot bootstrap (mirrors shared/users.py::ensure_first_boot_admin):
    if the keystore is empty and a legacy env-based key is configured,
    hash and provision it AS-IS -- an operator's existing X-Api-Key
    credential(s) keep working, completely unchanged, the moment they
    upgrade. This function never generates, logs, or stores a plaintext
    key of its own; it only hashes what the operator already configured.

    Priority when both legacy mechanisms are set (FENGARDE_API_KEYS wins --
    it is the newer, more specific one, and its presence means the operator
    already adopted the first F1 follow-up):
      1. FENGARDE_API_KEYS ("tenant:key,tenant:key,*:key") -> one row per
         entry, source='migrated_legacy_tenant_keys'.
      2. FENGARDE_API_KEY (the original single shared secret) -> one row
         for the 'default' tenant, source='migrated_legacy_shared_key'.
      3. Neither set -> no-op, returns [] (auth stays fully disabled, same
         zero-infra default as always).

    Returns the list of tenant_ids migrated (never the key values), for a
    one-line, secret-free startup log entry. A store that already has ANY
    row is left untouched -- this only ever runs once, on the very first
    boot after upgrade; re-provisioning/rotation afterward is
    manage_keys.py's job, not this function's."""
    if store.count() > 0:
        return []
    tenant_keys_raw = os.getenv("FENGARDE_API_KEYS")
    if tenant_keys_raw:
        parsed = _parse_legacy_tenant_keys(tenant_keys_raw)
        for tenant_id, key in parsed.items():
            store.provision(tenant_id, key, source="migrated_legacy_tenant_keys")
        return sorted(parsed.keys())
    legacy = os.getenv("FENGARDE_API_KEY")
    if legacy:
        store.provision(DEFAULT_TENANT, legacy, source="migrated_legacy_shared_key")
        return [DEFAULT_TENANT]
    return []
