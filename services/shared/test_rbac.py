"""M4.2 RBAC unit tests: users.py, sessions.py, rbac.py.

Run: python services/shared/test_rbac.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from shared.users import (  # noqa: E402
    UserStore, hash_password, verify_password, ensure_first_boot_admin,
)
from shared.sessions import SessionStore  # noqa: E402
from shared.rbac import role_at_least, can_access_tenant, LoginRateLimiter  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_password_hash_roundtrip():
    h = hash_password("correct horse battery staple")
    check(verify_password("correct horse battery staple", h), "correct password must verify")
    check(not verify_password("wrong password", h), "wrong password must not verify")
    check(h.startswith("scrypt$"), "hash must be tagged with its algorithm")


def test_password_hash_unique_salt():
    h1 = hash_password("same-password")
    h2 = hash_password("same-password")
    check(h1 != h2, "two hashes of the same password must differ (random salt)")


def test_verify_password_malformed_stored_fails_closed():
    check(not verify_password("x", "not-a-valid-hash"), "malformed stored hash must fail, not raise")
    check(not verify_password("x", "md5$deadbeef"), "wrong algo tag must fail closed")
    check(not verify_password("x", ""), "empty stored hash must fail closed")


def test_user_store_create_and_login():
    store = UserStore(":memory:")
    store.create_user("alice", "alice-password-1", role="analyst", tenant_id="acme")
    row = store.verify_login("alice", "alice-password-1")
    check(row is not None, "correct login must succeed")
    check(row["role"] == "analyst", "returned row must carry the correct role")
    check(row["tenant_id"] == "acme", "returned row must carry the correct tenant")

    check(store.verify_login("alice", "wrong-password") is None, "wrong password must fail")
    check(store.verify_login("nobody", "whatever") is None, "unknown username must fail")


def test_user_store_rejects_unknown_role():
    store = UserStore(":memory:")
    raised = False
    try:
        store.create_user("bob", "x", role="superuser")
    except ValueError:
        raised = True
    check(raised, "an unrecognized role must be rejected at creation, not silently accepted")


def test_first_boot_admin_created_once():
    store = UserStore(":memory:")
    check(store.count() == 0, "fresh store must have zero users")
    password = ensure_first_boot_admin(store)
    check(password is not None, "first boot must return a generated password")
    check(store.count() == 1, "first boot must create exactly one user")
    admin = store.get_user("admin")
    check(admin["role"] == "admin", "first-boot user must be role=admin")
    check(store.verify_login("admin", password) is not None,
          "the returned first-boot password must actually work")

    # second call (simulating a restart against the same DB) must be a no-op
    second = ensure_first_boot_admin(store)
    check(second is None, "first boot must not re-fire once a user exists (no second admin)")
    check(store.count() == 1, "user count must stay at 1 after a simulated restart")


def test_session_lifecycle():
    store = SessionStore(ttl_s=3600)
    token = store.create("alice", "analyst", "acme")
    session = store.resolve(token)
    check(session is not None, "a freshly created session must resolve")
    check(session.username == "alice" and session.role == "analyst" and session.tenant_id == "acme",
          "resolved session must carry the correct identity")

    check(store.resolve("not-a-real-token") is None, "an unknown token must not resolve")

    store.invalidate(token)
    check(store.resolve(token) is None, "an invalidated session must no longer resolve")


def test_session_expiry():
    store = SessionStore(ttl_s=0)  # expires immediately
    token = store.create("alice", "analyst", "acme")
    time.sleep(0.01)
    check(store.resolve(token) is None, "an expired session must not resolve")
    check(store.count() == 0, "resolving an expired session must evict it (lazy cleanup)")


def test_role_at_least():
    check(role_at_least("admin", "read_only"), "admin must satisfy a read_only requirement")
    check(role_at_least("admin", "analyst"), "admin must satisfy an analyst requirement")
    check(role_at_least("analyst", "read_only"), "analyst must satisfy a read_only requirement")
    check(not role_at_least("analyst", "admin"), "analyst must NOT satisfy an admin requirement")
    check(not role_at_least("read_only", "analyst"), "read_only must NOT satisfy an analyst requirement")
    check(not role_at_least("bogus_role", "read_only"),
          "an unrecognized role must fail closed, never satisfy any requirement")


def test_can_access_tenant():
    check(can_access_tenant("admin", "acme", "globex"), "admin must access any tenant's resource")
    check(can_access_tenant("admin", "acme", None), "admin must access an untenanted (pre-M4) resource")
    check(can_access_tenant("analyst", "acme", "acme"), "a user must access their own tenant's resource")
    check(not can_access_tenant("analyst", "acme", "globex"),
          "a user must NOT access a different tenant's resource")
    check(can_access_tenant("analyst", "default", None),
          "a default-tenant user must access an untenanted (pre-M4) resource")
    check(not can_access_tenant("analyst", "acme", None),
          "a non-default-tenant user must NOT access an untenanted resource "
          "(it's implicitly 'default', a different tenant)")


def test_login_rate_limiter():
    limiter = LoginRateLimiter(max_attempts=3, window_s=60)
    check(not limiter.is_locked_out("alice"), "no attempts yet -> not locked out")
    for _ in range(3):
        limiter.record_failure("alice")
    check(limiter.is_locked_out("alice"), "3 failures at max_attempts=3 must lock out")
    check(not limiter.is_locked_out("bob"), "a different username must be unaffected")

    limiter.record_success("alice")
    check(not limiter.is_locked_out("alice"), "a successful login must clear the lockout")


def main():
    test_password_hash_roundtrip()
    test_password_hash_unique_salt()
    test_verify_password_malformed_stored_fails_closed()
    test_user_store_create_and_login()
    test_user_store_rejects_unknown_role()
    test_first_boot_admin_created_once()
    test_session_lifecycle()
    test_session_expiry()
    test_role_at_least()
    test_can_access_tenant()
    test_login_rate_limiter()

    if FAILS:
        print(f"[FAIL] rbac: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] M4.2 RBAC unit tests PASS (users, sessions, roles, tenant scoping, rate limiting)")


if __name__ == "__main__":
    main()
