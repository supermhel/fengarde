"""F1 second follow-up (2026-07-30): TenantKeyStore + legacy-key migration.

Store-level tests (no HTTP) for keystore.py -- the hashed-at-rest per-tenant
API key mechanism that replaced the plaintext FENGARDE_API_KEYS check. See
test_auth.py for the HTTP-layer proof that this is actually wired into
app.py's routes.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from keystore import (  # noqa: E402
    ADMIN_TENANT_MARKER, TenantKeyStore, ensure_legacy_keys_migrated, generate_raw_key,
)

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_key_is_never_stored_in_plaintext():
    store = TenantKeyStore(":memory:")
    raw = "super-secret-acme-key"
    store.provision("acme", raw, source="generated")
    row = store.db.execute("SELECT * FROM api_keys WHERE tenant_id='acme'").fetchone()
    check(raw not in row["key_hash"] and raw not in row["lookup_hash"],
          "the raw key must not appear verbatim anywhere in the stored row")
    check(row["key_hash"].startswith("scrypt$"),
          f"key_hash must be a scrypt$salt$hash triple, got {row['key_hash'][:20]!r}...")


def test_verify_correct_and_wrong_key():
    store = TenantKeyStore(":memory:")
    store.provision("acme", "acme-secret")
    ok, tenant = store.verify("acme-secret")
    check(ok and tenant == "acme", f"correct key must verify as acme, got {(ok, tenant)}")

    ok, tenant = store.verify("wrong-guess")
    check(not ok and tenant is None, f"wrong key must fail closed, got {(ok, tenant)}")

    ok, tenant = store.verify("")
    check(not ok and tenant is None, f"empty key must fail closed, got {(ok, tenant)}")


def test_cross_tenant_keys_are_independent():
    """The core new guarantee: tenant A's key verifies as A, never as B,
    even when both are provisioned in the same store."""
    store = TenantKeyStore(":memory:")
    store.provision("acme", "acme-secret")
    store.provision("globex", "globex-secret")

    ok, tenant = store.verify("acme-secret")
    check(ok and tenant == "acme", f"acme's key must verify as acme, got {(ok, tenant)}")
    ok, tenant = store.verify("globex-secret")
    check(ok and tenant == "globex", f"globex's key must verify as globex, got {(ok, tenant)}")

    # Cross-wiring: acme's key must never verify as globex or vice versa.
    ok, tenant = store.verify("acme-secret")
    check(tenant != "globex", "acme's key must never resolve to globex's tenant_id")


def test_admin_marker_verifies_as_unrestricted():
    store = TenantKeyStore(":memory:")
    store.provision(ADMIN_TENANT_MARKER, "admin-secret")
    ok, tenant = store.verify("admin-secret")
    check(ok and tenant is None, f"the '*' key must verify ok with tenant_id=None (unrestricted), got {(ok, tenant)}")


def test_rotation_invalidates_old_key():
    store = TenantKeyStore(":memory:")
    store.provision("acme", "old-key")
    ok, _ = store.verify("old-key")
    check(ok, "the original key must work before rotation")

    store.provision("acme", "new-key")
    ok, _ = store.verify("old-key")
    check(not ok, "the OLD key must stop working immediately after rotation")
    ok, tenant = store.verify("new-key")
    check(ok and tenant == "acme", "the NEW key must work and resolve to the same tenant")


def test_generate_raw_key_is_high_entropy_and_unique():
    keys = {generate_raw_key() for _ in range(50)}
    check(len(keys) == 50, "generate_raw_key must not produce collisions across 50 calls")
    check(all(len(k) >= 32 for k in keys), "generated keys must be long enough to resist guessing")


def test_migration_from_legacy_single_shared_key():
    """An operator who only ever set the original FENGARDE_API_KEY must be
    able to keep using that exact value after upgrading, with zero
    reconfiguration -- it lands on the 'default' tenant, matching every
    pre-M4/pre-F1 deployment's implicit single tenant."""
    os.environ["FENGARDE_API_KEY"] = "the-operators-original-key"
    os.environ.pop("FENGARDE_API_KEYS", None)
    try:
        store = TenantKeyStore(":memory:")
        migrated = ensure_legacy_keys_migrated(store)
        check(migrated == ["default"], f"expected migration of the 'default' tenant only, got {migrated}")

        ok, tenant = store.verify("the-operators-original-key")
        check(ok and tenant == "default",
              f"the operator's EXISTING key must keep working unchanged after migration, got {(ok, tenant)}")
    finally:
        os.environ.pop("FENGARDE_API_KEY", None)


def test_migration_from_legacy_tenant_keys():
    """An operator who already adopted the first F1 follow-up
    (FENGARDE_API_KEYS) must have every one of their existing per-tenant
    keys migrate in, unchanged, including an admin '*' entry."""
    os.environ["FENGARDE_API_KEYS"] = "acme:acme-old-key,globex:globex-old-key,*:admin-old-key"
    os.environ.pop("FENGARDE_API_KEY", None)
    try:
        store = TenantKeyStore(":memory:")
        migrated = ensure_legacy_keys_migrated(store)
        check(sorted(migrated) == ["*", "acme", "globex"], f"expected all 3 entries migrated, got {migrated}")

        ok, tenant = store.verify("acme-old-key")
        check(ok and tenant == "acme", f"acme's pre-existing key must keep working, got {(ok, tenant)}")
        ok, tenant = store.verify("globex-old-key")
        check(ok and tenant == "globex", f"globex's pre-existing key must keep working, got {(ok, tenant)}")
        ok, tenant = store.verify("admin-old-key")
        check(ok and tenant is None, f"the pre-existing admin key must keep working, got {(ok, tenant)}")
    finally:
        os.environ.pop("FENGARDE_API_KEYS", None)


def test_migration_prefers_tenant_keys_over_shared_when_both_set():
    os.environ["FENGARDE_API_KEY"] = "old-shared-key"
    os.environ["FENGARDE_API_KEYS"] = "acme:acme-only-key"
    try:
        store = TenantKeyStore(":memory:")
        migrated = ensure_legacy_keys_migrated(store)
        check(migrated == ["acme"], f"FENGARDE_API_KEYS must win when both are set, got {migrated}")
        ok, _ = store.verify("old-shared-key")
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
    """A store that already has a real, deliberately-provisioned key must
    never be silently overwritten by a stale legacy env var still lying
    around in the environment (e.g. left over from before an operator
    switched to manage_keys.py-provisioned keys)."""
    store = TenantKeyStore(":memory:")
    store.provision("acme", "the-real-current-key")
    os.environ["FENGARDE_API_KEY"] = "a-stale-leftover-env-var"
    try:
        migrated = ensure_legacy_keys_migrated(store)
        check(migrated == [], f"a non-empty store must never be touched by migration, got {migrated}")
        ok, tenant = store.verify("the-real-current-key")
        check(ok and tenant == "acme", "the real provisioned key must still be the one that works")
        ok, _ = store.verify("a-stale-leftover-env-var")
        check(not ok, "the stale env var must NOT have been silently provisioned over the real key")
    finally:
        os.environ.pop("FENGARDE_API_KEY", None)


def main():
    test_key_is_never_stored_in_plaintext()
    test_verify_correct_and_wrong_key()
    test_cross_tenant_keys_are_independent()
    test_admin_marker_verifies_as_unrestricted()
    test_rotation_invalidates_old_key()
    test_generate_raw_key_is_high_entropy_and_unique()
    test_migration_from_legacy_single_shared_key()
    test_migration_from_legacy_tenant_keys()
    test_migration_prefers_tenant_keys_over_shared_when_both_set()
    test_migration_is_a_noop_with_neither_legacy_var_set()
    test_migration_only_runs_once()
    if FAILS:
        print(f"[FAIL] WS-6 keystore: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-6 keystore: hashed-at-rest storage, cross-tenant isolation, rotation, "
          "and legacy-key auto-migration (single shared key, tenant-keys CSV, precedence, "
          "no-op, and never-overwrite-a-real-key) all PASS")


if __name__ == "__main__":
    main()
