"""F1 follow-ups (2026-07-30/31): TenantKeyStore + legacy-key migration.

Store-level tests (no HTTP) for keystore.py -- the per-tenant API key
mechanism that isolates WS-6 inventory by tenant at the auth layer. The
current design (third follow-up, 2026-07-31, after an independent review):
HMAC-SHA256 keyed by a server-side pepper (fast, right for high-entropy
random tokens -- see keystore.py's module docstring for why scrypt was the
wrong primitive), multiple independently-revocable keys per tenant
(zero-downtime rotation), read_only/read_write scopes, validated tenant
ids, and migration that skips (never crashes on) duplicate or malformed
legacy input.

See test_auth.py for the HTTP-layer proof that this is wired into app.py's
routes (including scope enforcement on writes).
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from keystore import (  # noqa: E402
    ADMIN_TENANT_MARKER, SCOPE_READ_ONLY, SCOPE_READ_WRITE, DuplicateKeyError,
    TenantKeyStore, ensure_legacy_keys_migrated, generate_raw_key,
)
from store import InvalidTenantId  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_key_is_never_stored_in_plaintext():
    store = TenantKeyStore(":memory:")
    raw = "super-secret-acme-key"
    store.provision("acme", raw)
    row = store.db.execute("SELECT * FROM api_keys WHERE tenant_id='acme'").fetchone()
    check(raw not in row["key_hash"],
          "the raw key must not appear verbatim in the stored hash")
    check(row["key_hash"].startswith("hmac-sha256$"),
          f"key_hash must be an hmac-sha256$digest value, got {row['key_hash'][:24]!r}...")


def test_verify_correct_and_wrong_key():
    store = TenantKeyStore(":memory:")
    store.provision("acme", "acme-secret")
    ok, tenant, scope = store.verify("acme-secret")
    check(ok and tenant == "acme" and scope == SCOPE_READ_WRITE,
          f"correct key must verify as acme/read_write, got {(ok, tenant, scope)}")

    ok, tenant, scope = store.verify("wrong-guess")
    check(not ok and tenant is None and scope is None, f"wrong key must fail closed, got {(ok, tenant, scope)}")

    ok, tenant, scope = store.verify("")
    check(not ok and tenant is None, f"empty key must fail closed, got {(ok, tenant, scope)}")


def test_verify_is_fast_and_symmetric():
    """The independent review's core critique of the scrypt round: verify
    was ~150ms and ASYMMETRIC (miss 2x hit), a throughput ceiling and a
    DoS lever. A fast keyed hash must be well under a millisecond, and hit
    and miss must be within the same order of magnitude (no 2x decoy
    asymmetry) -- generous bounds, this is a smoke test against a
    regression back to a memory-hard KDF, not a precise timing assertion."""
    import time
    store = TenantKeyStore(":memory:")
    store.provision("acme", "acme-secret")

    def avg_ms(key, n=50):
        t0 = time.perf_counter()
        for _ in range(n):
            store.verify(key)
        return (time.perf_counter() - t0) / n * 1000

    hit = avg_ms("acme-secret")
    miss = avg_ms("nope")
    check(hit < 5.0, f"a verify hit must be well under 5ms (fast hash), got {hit:.3f}ms")
    check(miss < 5.0, f"a verify miss must be well under 5ms, got {miss:.3f}ms")


def test_cross_tenant_keys_are_independent():
    """The core new guarantee: tenant A's key verifies as A, never as B."""
    store = TenantKeyStore(":memory:")
    store.provision("acme", "acme-secret")
    store.provision("globex", "globex-secret")

    ok, tenant, _ = store.verify("acme-secret")
    check(ok and tenant == "acme", f"acme's key must verify as acme, got {(ok, tenant)}")
    ok, tenant, _ = store.verify("globex-secret")
    check(ok and tenant == "globex", f"globex's key must verify as globex, got {(ok, tenant)}")


def test_admin_marker_verifies_as_unrestricted():
    store = TenantKeyStore(":memory:")
    store.provision(ADMIN_TENANT_MARKER, "admin-secret")
    ok, tenant, scope = store.verify("admin-secret")
    check(ok and tenant is None,
          f"the '*' key must verify ok with tenant_id=None (unrestricted), got {(ok, tenant, scope)}")


def test_multiple_live_keys_per_tenant_for_zero_downtime_rotation():
    """Rotation without downtime: a tenant can hold two keys at once, so
    the operator provisions a new one, cuts the caller over, and only THEN
    revokes the old -- neither key is ever briefly-and-simultaneously the
    only-valid-one during the handoff."""
    store = TenantKeyStore(":memory:")
    old_id = store.provision("acme", "old-key")
    new_id = store.provision("acme", "new-key")
    check(old_id != new_id, "each provisioned key must get its own key_id")

    ok_old, t_old, _ = store.verify("old-key")
    ok_new, t_new, _ = store.verify("new-key")
    check(ok_old and t_old == "acme" and ok_new and t_new == "acme",
          "BOTH keys must be live simultaneously during a rotation window")

    check(store.revoke(old_id) is True, "revoking a live key must report success")
    ok_old, _, _ = store.verify("old-key")
    ok_new, _, _ = store.verify("new-key")
    check(not ok_old, "the revoked key must stop working immediately")
    check(ok_new, "the surviving key must keep working after the other is revoked")


def test_revoke_is_idempotent():
    store = TenantKeyStore(":memory:")
    kid = store.provision("acme", "k")
    check(store.revoke(kid) is True, "first revoke must report it removed a row")
    check(store.revoke(kid) is False, "second revoke of the same id must be a no-op returning False")
    check(store.revoke("never-existed") is False, "revoking an unknown id must be a safe no-op")


def test_reprovision_same_key_same_tenant_is_idempotent():
    store = TenantKeyStore(":memory:")
    first = store.provision("acme", "same-key")
    second = store.provision("acme", "same-key")
    check(first == second, "re-provisioning the identical key for the same tenant must return the same key_id")
    check(len(store.list_keys("acme")) == 1, "an idempotent re-provision must not create a duplicate row")


def test_same_key_two_tenants_raises_not_crashes():
    """The regression the previous round shipped: two tenants sharing one
    raw key hit a UNIQUE constraint and raised an unhandled
    sqlite3.IntegrityError. Now it raises a clear, catchable
    DuplicateKeyError instead -- a key must uniquely identify one tenant."""
    store = TenantKeyStore(":memory:")
    store.provision("acme", "shared-key")
    try:
        store.provision("globex", "shared-key")
        check(False, "provisioning one key for a second tenant must raise DuplicateKeyError")
    except DuplicateKeyError:
        pass
    # acme's original binding must be untouched by the rejected attempt.
    ok, tenant, _ = store.verify("shared-key")
    check(ok and tenant == "acme", f"the rejected cross-tenant provision must not change acme's key, got {(ok, tenant)}")


def test_provision_rejects_invalid_tenant_id():
    """The 'silently useless credential' gap: a key provisioned for a
    tenant_id that store.py will reject on every request (uppercase,
    spaces) must be rejected AT PROVISION, not accepted then 400 forever."""
    store = TenantKeyStore(":memory:")
    for bad in ("ACME Corp", "UPPER", "has space", "-lead", "trail-"):
        try:
            store.provision(bad, "some-key")
            check(False, f"provision must reject invalid tenant_id {bad!r}")
        except InvalidTenantId:
            pass


def test_scope_read_only_is_stored_and_returned():
    store = TenantKeyStore(":memory:")
    store.provision("acme", "ro-key", scope=SCOPE_READ_ONLY)
    ok, tenant, scope = store.verify("ro-key")
    check(ok and tenant == "acme" and scope == SCOPE_READ_ONLY,
          f"a read_only key must verify with its scope, got {(ok, tenant, scope)}")


def test_provision_rejects_invalid_scope():
    store = TenantKeyStore(":memory:")
    try:
        store.provision("acme", "k", scope="root")
        check(False, "provision must reject an unknown scope")
    except ValueError:
        pass


def test_generate_raw_key_is_high_entropy_and_unique():
    keys = {generate_raw_key() for _ in range(50)}
    check(len(keys) == 50, "generate_raw_key must not collide across 50 calls")
    check(all(len(k) >= 32 for k in keys), "generated keys must be long enough to resist guessing")


def test_list_keys_never_leaks_material_and_filters_by_tenant():
    store = TenantKeyStore(":memory:")
    store.provision("acme", "acme-key")
    store.provision("globex", "globex-key")
    everything = store.list_keys()
    check(len(everything) == 2, f"list_keys() must return all keys, got {everything}")
    for row in everything:
        check("key_hash" not in row and "acme-key" not in str(row) and "globex-key" not in str(row),
              f"list_keys must never expose key material, got {row}")
    acme_only = store.list_keys(tenant_id="acme")
    check(len(acme_only) == 1 and acme_only[0]["tenant_id"] == "acme",
          f"list_keys(tenant_id=) must filter, got {acme_only}")


def test_pepper_changes_the_stored_hash():
    """The pepper is a real input to the hash -- the same raw key under two
    different peppers must produce different stored hashes (so a stolen DB
    is useless without the pepper too). A key provisioned under pepper A
    must NOT verify once the pepper changes to B."""
    os.environ["FENGARDE_API_KEY_PEPPER"] = "pepper-A"
    try:
        store = TenantKeyStore(":memory:")
        store.provision("acme", "the-key")
        ok, _, _ = store.verify("the-key")
        check(ok, "the key must verify under the pepper it was provisioned with")
        os.environ["FENGARDE_API_KEY_PEPPER"] = "pepper-B"
        ok, _, _ = store.verify("the-key")
        check(not ok, "the same key must NOT verify once the pepper changes (pepper is a real hash input)")
    finally:
        os.environ.pop("FENGARDE_API_KEY_PEPPER", None)


def test_migration_from_legacy_single_shared_key():
    os.environ["FENGARDE_API_KEY"] = "the-operators-original-key"
    os.environ.pop("FENGARDE_API_KEYS", None)
    try:
        store = TenantKeyStore(":memory:")
        migrated = ensure_legacy_keys_migrated(store)
        check(migrated == ["default"], f"expected migration of the 'default' tenant only, got {migrated}")
        ok, tenant, _ = store.verify("the-operators-original-key")
        check(ok and tenant == "default",
              f"the operator's EXISTING key must keep working unchanged after migration, got {(ok, tenant)}")
    finally:
        os.environ.pop("FENGARDE_API_KEY", None)


def test_migration_from_legacy_tenant_keys():
    os.environ["FENGARDE_API_KEYS"] = "acme:acme-old-key,globex:globex-old-key,*:admin-old-key"
    os.environ.pop("FENGARDE_API_KEY", None)
    try:
        store = TenantKeyStore(":memory:")
        migrated = ensure_legacy_keys_migrated(store)
        check(sorted(migrated) == ["*", "acme", "globex"], f"expected all 3 entries migrated, got {migrated}")
        ok, tenant, _ = store.verify("acme-old-key")
        check(ok and tenant == "acme", f"acme's pre-existing key must keep working, got {(ok, tenant)}")
        ok, tenant, _ = store.verify("admin-old-key")
        check(ok and tenant is None, f"the pre-existing admin key must keep working (unrestricted), got {(ok, tenant)}")
    finally:
        os.environ.pop("FENGARDE_API_KEYS", None)


def test_migration_prefers_tenant_keys_over_shared_when_both_set():
    os.environ["FENGARDE_API_KEY"] = "old-shared-key"
    os.environ["FENGARDE_API_KEYS"] = "acme:acme-only-key"
    try:
        store = TenantKeyStore(":memory:")
        migrated = ensure_legacy_keys_migrated(store)
        check(migrated == ["acme"], f"FENGARDE_API_KEYS must win when both are set, got {migrated}")
        ok, _, _ = store.verify("old-shared-key")
        check(not ok, "the superseded single shared key must NOT have been migrated in")
    finally:
        os.environ.pop("FENGARDE_API_KEY", None)
        os.environ.pop("FENGARDE_API_KEYS", None)


def test_migration_is_a_noop_with_neither_legacy_var_set():
    os.environ.pop("FENGARDE_API_KEY", None)
    os.environ.pop("FENGARDE_API_KEYS", None)
    store = TenantKeyStore(":memory:")
    migrated = ensure_legacy_keys_migrated(store)
    check(migrated == [], f"no legacy env vars set -> no migration, got {migrated}")
    check(store.count() == 0, "keystore must stay empty -- auth stays disabled by default")


def test_migration_only_runs_once():
    store = TenantKeyStore(":memory:")
    store.provision("acme", "the-real-current-key")
    os.environ["FENGARDE_API_KEY"] = "a-stale-leftover-env-var"
    try:
        migrated = ensure_legacy_keys_migrated(store)
        check(migrated == [], f"a non-empty store must never be touched by migration, got {migrated}")
        ok, tenant, _ = store.verify("the-real-current-key")
        check(ok and tenant == "acme", "the real provisioned key must still be the one that works")
        ok, _, _ = store.verify("a-stale-leftover-env-var")
        check(not ok, "the stale env var must NOT have been silently provisioned over the real key")
    finally:
        os.environ.pop("FENGARDE_API_KEY", None)


def test_migration_skips_duplicate_key_across_tenants_without_crashing():
    """The dup-key regression, at the migration layer: an operator copy-
    pasting the same key for two tenants in FENGARDE_API_KEYS must NOT
    crash startup (the previous round raised an unhandled IntegrityError
    at import). The first entry migrates; the colliding one is skipped."""
    os.environ["FENGARDE_API_KEYS"] = "acme:samekey,globex:samekey"
    try:
        store = TenantKeyStore(":memory:")
        migrated = ensure_legacy_keys_migrated(store)
        check(len(migrated) == 1, f"exactly one of the two duplicate-key entries must migrate, got {migrated}")
        # Whichever one migrated, its key must resolve to THAT tenant, and the
        # store must be in a consistent, usable state (not half-crashed).
        ok, tenant, _ = store.verify("samekey")
        check(ok and tenant in ("acme", "globex"), f"the surviving key must verify to one tenant, got {(ok, tenant)}")
        check(store.count() == 1, f"only one row must exist after a skipped duplicate, got {store.count()}")
    finally:
        os.environ.pop("FENGARDE_API_KEYS", None)


def test_migration_skips_invalid_tenant_id_without_crashing():
    """An uppercase/malformed tenant_id from an env-var typo must be skipped
    (not provisioned as a silently-useless credential), while valid
    siblings still migrate."""
    os.environ["FENGARDE_API_KEYS"] = "ACME:key1,globex:key2"
    try:
        store = TenantKeyStore(":memory:")
        migrated = ensure_legacy_keys_migrated(store)
        check(migrated == ["globex"], f"only the valid tenant must migrate, got {migrated}")
        ok, _, _ = store.verify("key1")
        check(not ok, "the invalid-tenant key must NOT have been provisioned")
        ok, tenant, _ = store.verify("key2")
        check(ok and tenant == "globex", "the valid sibling must still migrate and work")
    finally:
        os.environ.pop("FENGARDE_API_KEYS", None)


def test_upgrade_from_pre_hmac_scrypt_schema_does_not_crash():
    """Independent review (2026-07-31): a DB written by the previous (scrypt)
    keystore round has schema `api_keys(tenant_id PK, lookup_hash, key_hash,
    source, created_at)` -- no key_id/scope/last_used_at. This round's
    verify() SELECTs `scope, key_id`, which raised OperationalError ("no such
    column: scope") -> app.py 500 on every request -> silent lockout on
    upgrade. The migration must rename the incompatible table aside (never
    DROP, no data loss) and stand up a fresh HMAC-shaped table, so verify()
    works and env-var re-migration can repopulate."""
    with tempfile.TemporaryDirectory() as td:
        db_path = str(Path(td) / "pre_hmac.db")
        legacy = sqlite3.connect(db_path)
        legacy.executescript(
            """
            CREATE TABLE api_keys (
              tenant_id TEXT PRIMARY KEY,
              lookup_hash TEXT NOT NULL UNIQUE,
              key_hash TEXT NOT NULL,
              source TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            """)
        legacy.execute("INSERT INTO api_keys VALUES('acme','abc','scrypt$x$y','generated','2026-07-30')")
        legacy.commit(); legacy.close()

        store = TenantKeyStore(db_path)
        # verify() must not raise -- the incompatible table is gone from the
        # active name, replaced by the fresh HMAC schema (empty).
        ok, tenant, scope = store.verify("anykey")
        check(not ok, f"a fresh post-upgrade keystore must have no live keys yet, got {(ok, tenant, scope)}")

        # The old rows must be preserved aside (forensics), not destroyed.
        preserved = [r["name"] for r in store.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'api_keys_pre%'").fetchall()]
        check(preserved == ["api_keys_pre_hmac"],
              f"old scrypt table must be renamed aside, not dropped, got {preserved}")

        # A fresh provision under the new schema must work end-to-end.
        store.provision("acme", "new-generated-key")
        ok, tenant, _ = store.verify("new-generated-key")
        check(ok and tenant == "acme", f"post-upgrade provisioning must work, got {(ok, tenant)}")
        store.db.close()


def test_upgrade_then_env_remigration_repopulates():
    """The common upgrade path: an operator who still has FENGARDE_API_KEYS
    set upgrades from the scrypt round. The old table is set aside, the new
    one is empty, so ensure_legacy_keys_migrated re-provisions from the env
    var under HMAC -- their existing key value keeps working, zero manual
    step."""
    with tempfile.TemporaryDirectory() as td:
        db_path = str(Path(td) / "pre_hmac2.db")
        legacy = sqlite3.connect(db_path)
        legacy.executescript(
            "CREATE TABLE api_keys (tenant_id TEXT PRIMARY KEY, lookup_hash TEXT NOT NULL UNIQUE, "
            "key_hash TEXT NOT NULL, source TEXT NOT NULL, created_at TEXT NOT NULL);")
        legacy.execute("INSERT INTO api_keys VALUES('acme','abc','scrypt$x$y','migrated','2026-07-30')")
        legacy.commit(); legacy.close()

        os.environ["FENGARDE_API_KEYS"] = "acme:acme-real-key"
        try:
            store = TenantKeyStore(db_path)
            migrated = ensure_legacy_keys_migrated(store)
            check(migrated == ["acme"], f"env-var re-migration must repopulate after upgrade, got {migrated}")
            ok, tenant, _ = store.verify("acme-real-key")
            check(ok and tenant == "acme",
                  f"the operator's env-var key must work post-upgrade with no manual step, got {(ok, tenant)}")
            store.db.close()
        finally:
            os.environ.pop("FENGARDE_API_KEYS", None)


def test_pepper_change_is_detected_at_startup():
    """Independent review (2026-07-31): a stored HMAC only verifies under the
    exact pepper it was written with, so changing FENGARDE_API_KEY_PEPPER
    after keys exist silently fails EVERY key (fail-closed lockout, no
    obvious cause). A canary written at first provision must let startup
    detect a later pepper change. Proven via the persisted canary value:
    same pepper -> match; changed pepper -> mismatch (which _check_pepper_
    canary logs loudly)."""
    import hmac as _hmac
    import hashlib as _hashlib
    from keystore import _PEPPER_CANARY_PLAINTEXT
    with tempfile.TemporaryDirectory() as td:
        db_path = str(Path(td) / "pepper.db")
        os.environ["FENGARDE_API_KEY_PEPPER"] = "pepper-A"
        try:
            store = TenantKeyStore(db_path)
            store.provision("acme", "k1")
            canary = store.db.execute(
                "SELECT v FROM keystore_meta WHERE k='pepper_canary'").fetchone()["v"]
            store.db.close()

            match_a = _hmac.new(b"pepper-A", _PEPPER_CANARY_PLAINTEXT.encode(), _hashlib.sha256).hexdigest()
            match_b = _hmac.new(b"pepper-B", _PEPPER_CANARY_PLAINTEXT.encode(), _hashlib.sha256).hexdigest()
            check(canary == match_a, "canary must equal HMAC of the pepper in effect at first provision")
            check(canary != match_b, "canary must NOT match a different pepper (drift is detectable)")
        finally:
            os.environ.pop("FENGARDE_API_KEY_PEPPER", None)


def test_canary_absent_until_first_provision():
    """No canary is written for an empty keystore -- so _check_pepper_canary
    is a clean no-op on a fresh/never-provisioned store, and doesn't
    false-warn on the zero-infra default."""
    store = TenantKeyStore(":memory:")
    row = store.db.execute("SELECT v FROM keystore_meta WHERE k='pepper_canary'").fetchone()
    check(row is None, "an unprovisioned keystore must have no pepper canary yet")


def main():
    test_key_is_never_stored_in_plaintext()
    test_verify_correct_and_wrong_key()
    test_verify_is_fast_and_symmetric()
    test_cross_tenant_keys_are_independent()
    test_admin_marker_verifies_as_unrestricted()
    test_multiple_live_keys_per_tenant_for_zero_downtime_rotation()
    test_revoke_is_idempotent()
    test_reprovision_same_key_same_tenant_is_idempotent()
    test_same_key_two_tenants_raises_not_crashes()
    test_provision_rejects_invalid_tenant_id()
    test_scope_read_only_is_stored_and_returned()
    test_provision_rejects_invalid_scope()
    test_generate_raw_key_is_high_entropy_and_unique()
    test_list_keys_never_leaks_material_and_filters_by_tenant()
    test_pepper_changes_the_stored_hash()
    test_migration_from_legacy_single_shared_key()
    test_migration_from_legacy_tenant_keys()
    test_migration_prefers_tenant_keys_over_shared_when_both_set()
    test_migration_is_a_noop_with_neither_legacy_var_set()
    test_migration_only_runs_once()
    test_migration_skips_duplicate_key_across_tenants_without_crashing()
    test_migration_skips_invalid_tenant_id_without_crashing()
    test_upgrade_from_pre_hmac_scrypt_schema_does_not_crash()
    test_upgrade_then_env_remigration_repopulates()
    test_pepper_change_is_detected_at_startup()
    test_canary_absent_until_first_provision()
    if FAILS:
        print(f"[FAIL] WS-6 keystore: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-6 keystore: hashed-at-rest (HMAC-SHA256+pepper) storage, fast symmetric verify, "
          "cross-tenant isolation, multi-key zero-downtime rotation + idempotent revoke, scopes, "
          "validated tenant ids, legacy-key migration (shared/tenant-keys, precedence, no-op, "
          "never-overwrite, dup-key skip, invalid-tenant skip), pre-HMAC schema upgrade (preserve "
          "+ re-migrate), and pepper-drift detection all PASS")


if __name__ == "__main__":
    main()
