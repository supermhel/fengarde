"""F1 third follow-up (2026-07-31): per-tenant API keys -- fast keyed hash,
multi-key rotation, scoped (read-only/read-write), validated tenant ids.

History, so the design tradeoffs below make sense:
  - 2nd follow-up shipped scrypt (matching services/shared/users.py's
    password hashing) with a separate fast SHA-256 "lookup_hash" column to
    avoid an O(n)-scrypt-calls-per-request scaling problem.
  - An independent review (cavecrew-reviewer, 2026-07-31) measured ~150ms
    per scrypt verify and pointed out this was the wrong primitive: scrypt
    exists to slow down an offline attacker brute-forcing a LOW-entropy,
    human-chosen secret (a password). These keys are
    `generate_raw_key()`-produced 256-bit random values -- offline brute
    force is already infeasible regardless of hash speed, so paying a
    memory-hard KDF on every single request bought nothing but a throughput
    ceiling and a cheap unauthenticated-DoS lever (send garbage keys,
    force ~150ms of CPU per request). The review also found the review's
    OWN "timing defense" (a decoy hash on a miss) was inverted: it ran the
    slow hash TWICE on a miss vs once on a hit, doubling that DoS cost
    instead of equalizing timing.

This version replaces scrypt with HMAC-SHA256 keyed by a server-side
pepper (FENGARDE_API_KEY_PEPPER). For a high-entropy random token, a fast
keyed hash is the standard choice (this is the GitHub/Stripe/AWS
personal-access-token model: SHA-256 (or HMAC) the token, index it,
compare in O(1) -- no memory-hard KDF, because the token's own entropy,
not hash slowness, is the thing resisting brute force). The pepper is
defense-in-depth on top of that: if the keystore's DB leaks WITHOUT the
pepper leaking too (different secret store), a stored hash reveals
nothing offline-crackable. Because the primary key_hash is now itself
fast, the previous round's separate fast "lookup_hash" column serves no
purpose and is removed -- one column does both jobs.

One real gap this does NOT close: a MIGRATED legacy key (an operator's old
FENGARDE_API_KEY, which could be a short human-chosen string, not a
generated token) gets weaker offline-brute-force protection under a fast
hash than it had under scrypt. ensure_legacy_keys_migrated() flags this at
migration time (see its docstring) rather than silently accepting the
same risk profile as a generated key.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from store import DEFAULT_TENANT, InvalidTenantId, _validated_tenant

# Make `shared` resolvable regardless of how keystore.py is imported.
_SERVICES_DIR = Path(__file__).resolve().parent.parent
if str(_SERVICES_DIR) not in sys.path:
    sys.path.insert(0, str(_SERVICES_DIR))

from shared.log import get_logger  # noqa: E402

_log = get_logger("ws6-inventory")

ADMIN_TENANT_MARKER = "*"
SCOPE_READ_ONLY = "read_only"
SCOPE_READ_WRITE = "read_write"
VALID_SCOPES = (SCOPE_READ_ONLY, SCOPE_READ_WRITE)

# Fixed, non-secret sentinel HMAC'd with the pepper to detect a later pepper
# change (see TenantKeyStore._check_pepper_canary). Its value doesn't matter,
# only that it's constant across runs.
_PEPPER_CANARY_PLAINTEXT = "fengarde-ws6-pepper-canary-v1"

# A legacy key shorter than this is treated as "possibly human-chosen" for
# the migration weak-key warning -- generate_raw_key() produces 43-char
# token_urlsafe(32) values, so anything meaningfully shorter was never one
# of ours.
_LIKELY_WEAK_KEY_LEN = 24


class DuplicateKeyError(ValueError):
    """Raised by provision() when the given raw key already belongs to a
    DIFFERENT tenant -- a key must uniquely identify one tenant (that is
    the entire mechanism verify() relies on), so this can never be
    resolved by guessing; the caller must pick a different key or fix the
    input. Re-provisioning the SAME key for the SAME tenant is NOT an
    error (see provision()'s docstring) -- only a genuine cross-tenant
    collision raises this."""


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def generate_raw_key() -> str:
    """A fresh, high-entropy key for provisioning a tenant. 32 random
    bytes, url-safe base64 -- same primitive shared/sessions.py already
    uses for session tokens (secrets.token_urlsafe)."""
    return secrets.token_urlsafe(32)


def generate_key_id() -> str:
    """A short, non-secret identifier for one specific provisioned key --
    shown in `manage_keys.py list`/logs so an operator can name a key to
    revoke without it ever containing the secret itself."""
    return secrets.token_hex(8)


def _pepper() -> bytes:
    """Server-side pepper for the keyed hash. Unlike the KDF salt this
    replaces, absence is NOT a per-row concern (there's only one, from the
    environment) and must never block the zero-infra/quickstart default:
    unset -> empty pepper, loud warning (see warn_missing_pepper), same
    "insecure-but-functional default, warn don't crash" convention as
    FENGARDE_API_KEY being unset meaning auth-off. Even with an empty
    pepper, a stolen keystore DB alone still doesn't recover a raw
    GENERATED key (SHA-256 preimage resistance) -- the pepper's value is
    specifically in the leak-DB-without-leaking-pepper-too scenario."""
    return os.getenv("FENGARDE_API_KEY_PEPPER", "").encode("utf-8")


def warn_missing_pepper() -> None:
    if not os.getenv("FENGARDE_API_KEY_PEPPER"):
        _log.warn(
            "FENGARDE_API_KEY_PEPPER not set: keys are still unrecoverable "
            "from a DB leak alone (SHA-256 preimage), but the pepper's "
            "defense-in-depth is inactive"
        )


# CodeQL py/weak-sensitive-data-hashing (alerts #71/#72) flags both HMAC calls
# below as "weak hashing of sensitive data" -- that rule targets *password*
# hashing, where a fast hash is wrong because the attacker's search space is
# small (a human-chosen secret) and hash speed is the only cost. `raw` here is
# never a password: it is a `generate_raw_key()`-produced 256-bit random
# token (or, for a migrated legacy key, flagged separately at migration time
# -- see this module's docstring above). For a high-entropy token, a fast
# keyed hash is the correct, standard choice (GitHub/Stripe/AWS
# personal-access-token model) -- see the module docstring for the full
# tradeoff writeup, including why scrypt was tried first and reverted.
def _hash_key(raw: str) -> str:
    digest = hmac.new(_pepper(), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"hmac-sha256${digest}"


def _verify_key(raw: str, stored: str) -> bool:
    """Constant-time-compare verify. A malformed `stored` value (wrong algo
    tag) fails closed to False, never raises -- a corrupt row must not
    become a crash or, worse, an auth bypass."""
    try:
        algo, digest_hex = stored.split("$", 1)
        if algo != "hmac-sha256":
            return False
        computed = hmac.new(_pepper(), raw.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(computed, digest_hex)
    except Exception:
        return False


def _validated_scope(scope: str | None) -> str:
    if scope is None:
        return SCOPE_READ_WRITE
    if scope not in VALID_SCOPES:
        raise ValueError(f"invalid scope {scope!r}: must be one of {VALID_SCOPES}")
    return scope


def _validated_provision_tenant(tenant_id: str) -> str:
    """Same validation store.py applies to every request's tenant_id,
    reused here so a key can never be provisioned for a tenant_id that
    will then fail on every actual request (the "silently useless
    credential" gap an independent review caught: manage_keys.py accepted
    any string, e.g. "ACME Corp", which authenticated fine and then 400'd
    downstream forever). "*" (the admin marker) is not a real tenant_id and
    is special-cased past this check."""
    if tenant_id == ADMIN_TENANT_MARKER:
        return tenant_id
    return _validated_tenant(tenant_id)


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
        # Gap-hunt #9 (2026-08-26): app.py defaults this store to the SAME
        # SQLite file as InventoryStore (INVENTORY_KEYSTORE_DB falls back to
        # INVENTORY_DB), with independent connections and uncoordinated locks.
        # WAL lets both coexist, but a concurrent write from the inventory
        # connection can transiently hold the writer; time out coarsely (30s)
        # instead of immediately 500ing on "database is locked" -- and a
        # genuine stall now shows up in app.py's exception logging (#2).
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.db.row_factory = sqlite3.Row
        self._write_lock = threading.Lock()
        self._init()

    def _init(self):
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self._migrate_pre_hmac_schema()
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
              key_id TEXT PRIMARY KEY,
              tenant_id TEXT NOT NULL,
              key_hash TEXT NOT NULL UNIQUE,
              scope TEXT NOT NULL DEFAULT 'read_write',
              source TEXT NOT NULL,
              created_at TEXT NOT NULL,
              last_used_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
            CREATE TABLE IF NOT EXISTS keystore_meta (k TEXT PRIMARY KEY, v TEXT);
            """
        )
        self.db.commit()
        self._check_pepper_canary()

    def _migrate_pre_hmac_schema(self) -> None:
        """An independent review (2026-07-31) caught that a DB file written
        by the previous (scrypt) keystore round -- schema `api_keys(tenant_id
        PRIMARY KEY, lookup_hash, key_hash, source, created_at)`, no `key_id`
        /`scope`/`last_used_at` columns -- would make this round's verify()
        query ("...scope, key_id FROM api_keys") raise OperationalError
        ("no such column: scope"), which app.py's broad handler turns into a
        500 on EVERY request: a silent, total lockout on upgrade for any
        deployment that keeps its DB across versions (the shipped container's
        /data/inventory.db does).

        The scrypt round's stored hashes are `scrypt$...`, cryptographically
        incompatible with this round's HMAC verify -- there is no way to
        carry the actual keys forward (we never stored the raw keys). So the
        honest migration is: preserve the old rows aside for forensics
        (rename, never DROP -- same discipline as store.py::
        _migrate_pre_tenant_schema), let the fresh HMAC-shaped table be
        created empty below, and warn LOUDLY. Because the new table is then
        empty, ensure_legacy_keys_migrated() will re-provision from
        FENGARDE_API_KEYS/FENGARDE_API_KEY if those are still set (the common
        case -- most upgraders still have them); if not, the operator must
        re-issue keys via manage_keys.py, which the warning says explicitly.
        No-op on a fresh DB or an already-HMAC-shaped one."""
        tables = {r["name"] for r in self.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "api_keys" not in tables:
            return  # fresh DB
        cols = {r["name"] for r in self.db.execute("PRAGMA table_info(api_keys)").fetchall()}
        if "key_id" in cols:
            return  # already this round's schema
        # Rename aside under a unique name (append a counter if a prior failed
        # upgrade already left one) so this can never itself collide/crash.
        base = "api_keys_pre_hmac"
        name, n = base, 1
        while name in tables:
            n += 1
            name = f"{base}_{n}"
        self.db.execute(f"ALTER TABLE api_keys RENAME TO {name}")
        self.db.commit()
        _log.warn(
            f"upgraded a pre-HMAC (scrypt) keystore: old scrypt-hashed keys "
            f"cannot be verified under HMAC and were preserved aside as "
            f'"{name}"; keys will re-provision from FENGARDE_API_KEYS/'
            f"FENGARDE_API_KEY if still set, otherwise re-issue via "
            f"manage_keys.py"
        )

    def _check_pepper_canary(self) -> None:
        """Pepper-drift guard (independent review, 2026-07-31): a stored
        HMAC verifies only under the exact pepper it was written with, so if
        FENGARDE_API_KEY_PEPPER is changed/unset after keys were provisioned,
        EVERY key silently fails to verify -- a total (fail-closed, not
        bypass) lockout with no obvious cause. We can't test a real key at
        startup (we never store raw keys), so we keep a canary: HMAC(pepper,
        a fixed sentinel), written once when the first key is provisioned
        (see provision()). At startup, if a canary exists and does NOT match
        the current pepper, warn loudly -- turning a baffling 'all auth
        broke' into a named, actionable cause."""
        row = self.db.execute(
            "SELECT v FROM keystore_meta WHERE k='pepper_canary'").fetchone()
        if row is None:
            return  # no keys provisioned yet (or pre-canary DB) -- nothing to check
        current = hmac.new(_pepper(), _PEPPER_CANARY_PLAINTEXT.encode("utf-8"),
                           hashlib.sha256).hexdigest()
        if not hmac.compare_digest(row["v"], current):
            _log.error(
                "FENGARDE_API_KEY_PEPPER changed since keys were provisioned: "
                "ALL keys will fail to verify (fail-closed lockout). Restore the "
                "previous pepper value, or re-provision every key via manage_keys.py"
            )

    def _ensure_pepper_canary(self) -> None:
        """Write the pepper canary if absent -- called from provision() so it
        captures the pepper in effect when the first key is created. Must be
        called while holding _write_lock (provision() does)."""
        current = hmac.new(_pepper(), _PEPPER_CANARY_PLAINTEXT.encode("utf-8"),
                           hashlib.sha256).hexdigest()
        self.db.execute(
            "INSERT OR IGNORE INTO keystore_meta(k, v) VALUES('pepper_canary', ?)",
            (current,))

    def count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]

    def provision(self, tenant_id: str, raw_key: str, source: str = "generated",
                  scope: str | None = None) -> str:
        """Add a new, independently revocable key for tenant_id. Returns
        its key_id. Unlike the previous round, this does NOT overwrite any
        existing key for the tenant -- a tenant can hold multiple live
        keys at once (rotation = provision a new one, confirm the caller
        cut over, then revoke() the old key_id -- no forced downtime).

        Re-provisioning the exact same raw_key for the SAME tenant is a
        no-op returning the existing key_id (idempotent). Provisioning the
        same raw_key for a DIFFERENT tenant raises DuplicateKeyError -- a
        key is the sole thing verify() uses to determine the tenant, so
        two tenants sharing one key is not a state that can be resolved by
        guessing (the previous round crashed the whole service on this
        with an unhandled sqlite3.IntegrityError at import time; this
        raises a clear, catchable error instead -- see
        ensure_legacy_keys_migrated for how migration handles it without
        aborting startup).

        Raises InvalidTenantId (tenant_id) or ValueError (scope) on bad
        input -- never silently accepts a tenant_id/scope that would make
        the resulting key authenticate but then fail on every real
        request."""
        tenant_id = _validated_provision_tenant(tenant_id)
        scope = _validated_scope(scope)
        key_hash = _hash_key(raw_key)
        with self._write_lock:
            existing = self.db.execute(
                "SELECT key_id, tenant_id FROM api_keys WHERE key_hash=?", (key_hash,)
            ).fetchone()
            if existing is not None:
                if existing["tenant_id"] == tenant_id:
                    return existing["key_id"]
                raise DuplicateKeyError(
                    f"this key is already provisioned for tenant {existing['tenant_id']!r}; "
                    f"a single key cannot identify two different tenants "
                    f"(attempted for {tenant_id!r})")
            key_id = generate_key_id()
            self.db.execute(
                "INSERT INTO api_keys(key_id, tenant_id, key_hash, scope, source, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (key_id, tenant_id, key_hash, scope, source, _now_iso()),
            )
            # Capture the pepper in effect the first time a key is created, so
            # _check_pepper_canary can flag a later pepper change at startup.
            self._ensure_pepper_canary()
            self.db.commit()
            return key_id

    def revoke(self, key_id: str) -> bool:
        """Deletes one specific key. Idempotent -- revoking an already-gone
        (or never-existed) key_id is not an error, just returns False, so
        a retried/duplicate revoke request is safe."""
        with self._write_lock:
            cur = self.db.execute("DELETE FROM api_keys WHERE key_id=?", (key_id,))
            self.db.commit()
            return cur.rowcount > 0

    def verify(self, raw_key: str):
        """Returns (True, tenant_id_or_None, scope) on success --
        tenant_id is None for the `*` admin key (unrestricted, caller's
        own tenant_id trusted as-is). Returns (False, None, None) on any
        failure: empty header, unknown key, or a key that fails the HMAC
        compare. Exactly one fast hash + one lookup per request regardless
        of how many keys are provisioned (see this module's docstring for
        why a memory-hard KDF, used by the previous round, was the wrong
        choice here)."""
        if not raw_key:
            return False, None, None
        key_hash = _hash_key(raw_key)
        row = self.db.execute(
            "SELECT tenant_id, key_hash, scope, key_id FROM api_keys WHERE key_hash=?",
            (key_hash,),
        ).fetchone()
        if row is None:
            return False, None, None
        # Defense in depth: don't let a single indexed equality lookup BE
        # the entire auth decision -- explicitly re-verify with a
        # constant-time compare of the retrieved value against a freshly
        # computed one. Costs microseconds on top of a lookup that already
        # matched; guards against ever depending on SQLite text-equality
        # semantics alone for a security decision.
        if not _verify_key(raw_key, row["key_hash"]):
            return False, None, None
        self._touch_last_used(row["key_id"])
        tenant_id = row["tenant_id"]
        return True, (None if tenant_id == ADMIN_TENANT_MARKER else tenant_id), row["scope"]

    def _touch_last_used(self, key_id: str) -> None:
        """Records last-use, throttled to at most once/hour per key so a
        hot key doesn't cost a write on every single request. Single
        conditional UPDATE (no SELECT-then-write round trip)."""
        cutoff = datetime.now(tz=timezone.utc).timestamp() - 3600
        cutoff_iso = datetime.fromtimestamp(cutoff, tz=timezone.utc).isoformat()
        with self._write_lock:
            self.db.execute(
                "UPDATE api_keys SET last_used_at=? WHERE key_id=? "
                "AND (last_used_at IS NULL OR last_used_at < ?)",
                (_now_iso(), key_id, cutoff_iso),
            )
            self.db.commit()

    def list_keys(self, tenant_id: str | None = None) -> list[dict]:
        """Provisioned key metadata (key_id, tenant_id, scope, source,
        created_at, last_used_at) -- NEVER key material, hashed or
        otherwise. For ops tooling (manage_keys.py list) and the migration
        startup log line."""
        q = "SELECT key_id, tenant_id, scope, source, created_at, last_used_at FROM api_keys"
        args: list = []
        if tenant_id is not None:
            q += " WHERE tenant_id=?"
            args.append(tenant_id)
        q += " ORDER BY tenant_id, created_at"
        return [dict(r) for r in self.db.execute(q, args).fetchall()]


def ensure_legacy_keys_migrated(store: TenantKeyStore) -> list[str]:
    """First-boot bootstrap (mirrors shared/users.py::ensure_first_boot_admin):
    if the keystore is empty and a legacy env-based key is configured,
    hash and provision it AS-IS -- an operator's existing X-Api-Key
    credential(s) keep working, completely unchanged, the moment they
    upgrade. This function never generates, logs, or stores a plaintext
    key of its own; it only hashes what the operator already configured.

    Priority when both legacy mechanisms are set (FENGARDE_API_KEYS wins --
    it is the newer, more specific one, and its presence means the operator
    already adopted an earlier per-tenant-key follow-up):
      1. FENGARDE_API_KEYS ("tenant:key,tenant:key,*:key") -> one row per
         entry, source='migrated_legacy_tenant_keys'.
      2. FENGARDE_API_KEY (the original single shared secret) -> one row
         for the 'default' tenant, source='migrated_legacy_shared_key'.
      3. Neither set -> no-op, returns [] (auth stays fully disabled, same
         zero-infra default as always).

    Two adversarial-input cases handled loudly instead of crashing startup:
      * An entry's tenant_id fails store.py's validation (e.g. "ACME Corp"
        from an env var typo) -- SKIPPED with a warning naming the tenant,
        rather than provisioning a key that would authenticate and then
        400 on every real request.
      * Two entries share the same raw key value (operator copy-paste
        error) -- the SECOND one to migrate is SKIPPED with a warning
        naming both tenants, rather than crashing the whole service with
        an unhandled sqlite3.IntegrityError (this was a real regression in
        the previous round: the plaintext-era config tolerated a duplicate
        key by silently misauthenticating one tenant as the other, which
        is worse, but this fix must not trade that for "the service does
        not start at all"). The first entry still migrates normally.

    A migrated key shorter than a generated key would ever be (see
    _LIKELY_WEAK_KEY_LEN) gets an additional warning: a fast keyed hash
    protects a 256-bit generated key just fine, but offers less margin
    than the previous round's scrypt did for a short, possibly
    human-chosen legacy secret if the DB *and* the pepper both leak --
    worth an explicit nudge to rotate onto a generated key via
    manage_keys.py, not a silent downgrade in protection.

    Returns the list of tenant_ids actually migrated (never key values),
    for a one-line, secret-free startup log entry. A store that already
    has ANY row is left untouched -- this only ever runs once, on the very
    first boot after upgrade; re-provisioning/rotation afterward is
    manage_keys.py's job, not this function's."""
    if store.count() > 0:
        return []

    def _migrate_one(tenant_id: str, key: str, source: str) -> bool:
        try:
            store.provision(tenant_id, key, source=source)
        except InvalidTenantId:
            _log.warn(
                f"skipped migrating tenant_id {tenant_id!r} from a legacy env var: "
                f"not a valid tenant_id, would authenticate then fail every request"
            )
            return False
        except DuplicateKeyError:
            _log.warn(
                f"skipped migrating tenant_id {tenant_id!r}: its key is a duplicate "
                f"of an already-migrated tenant's key -- one key cannot identify two "
                f"tenants, fix the duplicate and provision it separately via manage_keys.py"
            )
            return False
        if len(key) < _LIKELY_WEAK_KEY_LEN:
            _log.warn(
                f"tenant_id {tenant_id!r} migrated a short (possibly human-chosen) "
                f"key -- consider rotating to a generated one via manage_keys.py provision"
            )
        return True

    tenant_keys_raw = os.getenv("FENGARDE_API_KEYS")
    if tenant_keys_raw:
        parsed = _parse_legacy_tenant_keys(tenant_keys_raw)
        migrated = [t for t, k in parsed.items()
                    if _migrate_one(t, k, "migrated_legacy_tenant_keys")]
        return migrated

    legacy = os.getenv("FENGARDE_API_KEY")
    if legacy:
        return [DEFAULT_TENANT] if _migrate_one(DEFAULT_TENANT, legacy, "migrated_legacy_shared_key") else []

    return []


def warn_if_legacy_env_now_ignored() -> None:
    """Loud, cheap drift guard: a legacy env var is being silently ignored
    because the keystore was already seeded on an earlier boot (so this
    boot's ensure_legacy_keys_migrated() call was a no-op) -- editing the
    env var now does nothing. The caller is responsible for only invoking
    this when that's actually true: after calling
    ensure_legacy_keys_migrated(), if it returned [] (migrated nothing
    THIS boot) AND store.count() > 0 (yet the keystore is non-empty, i.e.
    it was already seeded before)."""
    if os.getenv("FENGARDE_API_KEYS") or os.getenv("FENGARDE_API_KEY"):
        _log.warn(
            "FENGARDE_API_KEYS/FENGARDE_API_KEY is set but the keystore already has "
            "provisioned keys from a previous boot -- these env vars are IGNORED once "
            "migrated; use manage_keys.py to change keys, not the env var"
        )
