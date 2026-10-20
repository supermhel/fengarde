# Independent review — M4 final (WS-6 tenant isolation + hashed API keys)

**Reviewer:** independent pass, no code written this session (review-only).
**Scope:** f80d7d0 → 2bdf5f7 → 22ce005. Cavecrew-reviewer covered 2bdf5f7 only; this is the
first external check on 22ce005, and a fresh check on 2bdf5f7's design and f80d7d0's baseline.
**Date:** 2026-07-31.

## 0. Lineage check

`git rev-parse HEAD` and `git rev-parse origin/main` both resolve to `22ce005400823e9a4d161a47e501e695e102ab28`
after `git fetch origin`. Reviewing the actual current tip, not a stale local view. `git log --oneline -10`
confirms the claimed lineage f80d7d0 → 2bdf5f7 → 22ce005 with no surprise commits between.

## 1. Per-claim verdicts

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| 1 | Schema-upgrade migration handles a real pre-HMAC (scrypt) DB without crash/data loss | **CONFIRMED** | Reproduced the *exact* pre-fix crash by swapping in 2bdf5f7's keystore.py against current tests: `sqlite3.OperationalError: no such column: scope` on `verify()`, matching the commit's stated failure mode exactly. Restored current code, re-ran: old table renamed to `api_keys_pre_hmac` (not dropped, rows preserved), fresh HMAC table created empty, `verify()` returns cleanly, subsequent `provision()`/`verify()` round-trip works. Env-var re-migration path also confirmed live (old row's tenant re-provisioned from `FENGARDE_API_KEYS`, real key value works post-upgrade). |
| 2 | Pepper-drift canary detects a changed pepper at startup and fails loudly | **CONFIRMED functionally, test coverage is a gap (see §2)** | Manually reproduced: provisioned a key under pepper A, closed store, reopened same DB file under pepper B → `{"level":"error", ... "FENGARDE_API_KEY_PEPPER changed since keys were provisioned..."}` printed exactly as designed. Real behavior works. |
| 3 | Cross-tenant isolation (tenant A key can't touch tenant B's data) | **CONFIRMED** | `verify()` binds `tenant_id` to the key; `app.py::_check_auth` forces every GET's effective `tenant_id` and every POST's upsert body to `bound_tenant`, silently overriding any caller-supplied `tenant_id` — same "scope narrowing, never confirm/deny" convention as WS-3. Verified directly: a key provisioned for `acme` only ever resolves to `acme`. |
| 4 | Scope enforcement (read-only key can't write) | **CONFIRMED** | `do_POST` checks `scope == SCOPE_READ_ONLY` and returns 403 *before* routing, independent of and prior to any body parsing. Live in `test_auth.py` ("read_only scope blocks writes (403)") and passing. |
| 5 | Fail-closed on auth error | **CONFIRMED** | `_verify_key` catches all exceptions on a malformed stored value and returns `False` (never raises/bypasses). Unknown key, empty header, wrong HMAC, and DB corruption all resolve to `(False, None, None)` → 401. No path returns success on an exception. |
| 6 | HMAC-SHA256+pepper implemented correctly | **CONFIRMED** | `hmac.compare_digest` used for the final comparison (keystore.py:132, :268). Pepper read from `os.getenv("FENGARDE_API_KEY_PEPPER", "")` — not hardcoded, empty-but-functional default with a loud warning (`warn_missing_pepper`). The prior round's inverted decoy-hash timing "defense" is fully removed, not just disabled — `verify()` now does exactly one keyed hash + one indexed lookup on both hit and miss, which is the correct fix (equalizes cost) rather than reintroducing an asymmetry. |
| 7 | Rotation: revoking one `key_id` doesn't affect a tenant's other live keys; no dual-key overlap bug | **CONFIRMED** | Provisioned two keys for `acme`, both verified independently; revoked one `key_id`, confirmed the revoked key now fails closed while the sibling key still verifies to the same tenant. `revoke()` deletes by `key_id` only (not by `tenant_id`), so no overlap is structurally possible. |
| 8 | Full test suite green (ruff/mypy + `run_all_tests.sh`) | **CONFIRMED** | `ruff check .` → all checks passed. `mypy .` → no issues in 9 source files. `bash run_all_tests.sh` → `ALL TESTS PASS`, including the WS-6 contract test, M4.2 auth suite, F1 tenant-isolation suite, and the new keystore suite (26 scenarios) and auth suite (9 scenarios) shown running inline. `tools/validate_contract.py` → PASS. |
| 9 | Revert-tests: do the 4 new defect-regression tests actually fail without the fix? | **PARTIALLY CONFIRMED — one real gap found (§2)** | Schema-migration test: reverting to 2bdf5f7's keystore.py reproduces the crash exactly (see #1). Pepper-canary test: reverting the *detection comparison itself* (`_check_pepper_canary`'s `hmac.compare_digest` branch) does **not** fail any test — see §2. |

## 2. Finding — pepper-drift test doesn't test detection (test-coverage gap, not a live bug)

`test_pepper_change_is_detected_at_startup` (test_keystore.py) never calls `_check_pepper_canary()`.
It only recomputes `HMAC(pepper, sentinel)` twice by hand and asserts the *stored canary value*
matches pepper-A's recomputation and differs from pepper-B's. That's a real assertion about the
canary's storage correctness, but it is not an assertion that startup detection fires.

Proof: I edited `_check_pepper_canary`'s `if not hmac.compare_digest(row["v"], current):` down to
`if False:` (i.e., neutered the actual detection — the code path the docstring and commit message
claim is the fix) and reran `test_keystore.py`. **Full suite still reported all-green**, including
that specific test. I then restored the real code and manually exercised the actual runtime path
(provision under pepper A, reopen same DB under pepper B) and confirmed the real code *does* log
the loud error correctly — so this is not a live bug, but if `_check_pepper_canary`'s comparison
is ever broken by a future edit, no test in the suite would catch it.

**Fix (small, not blocking M4):** add a test that captures stdout (or refactors the print into a
return value / logger call the test can assert on) around an actual `_check_pepper_canary()` call
with a deliberately mismatched pepper, and asserts the warning fires. Fine to do as a fast follow-up.

## 3. Finding — migration silently drops the tenant_id index (confirmed, low severity)

`_migrate_pre_hmac_schema()` does `ALTER TABLE api_keys RENAME TO api_keys_pre_hmac`. In SQLite,
renaming a table does **not** rename its indexes — `idx_api_keys_tenant` stays attached to the
renamed table under its original name. The subsequent `CREATE INDEX IF NOT EXISTS idx_api_keys_tenant
ON api_keys(tenant_id)` then silently no-ops, because an index with that *name* already exists
(SQLite's existence check is by name, not by table) — it does **not** raise, and it does **not**
create the index on the new table.

Reproduced directly:
```
indexes after rename:            idx_api_keys_tenant -> api_keys_pre_hmac   (unwanted, stale)
indexes after new-table creation: no idx_api_keys_tenant on api_keys at all  (missing)
```
Effect: after any DB that goes through this migration path, the live `api_keys` table has **no**
index on `tenant_id` going forward — `list_keys(tenant_id=...)` and any future tenant-filtered
query fall back to a full table scan. This is a performance/schema-drift bug, **not** a security
or correctness bug (queries still return correct results; scale is small — per-tenant key counts,
not events), so it does not block M4. Worth a one-line follow-up: use a migration-unique index
name (e.g. rename or drop the stale index by name before creating the new one).

## 4. Design spot-check (2bdf5f7, first external pass)

Read the full current `keystore.py`, `app.py`, `manage_keys.py`. Design is sound:
- HMAC-SHA256 keyed hash is the right primitive for a 256-bit random token (matches the
  GitHub/Stripe/AWS PAT model); scrypt removal is correctly justified (KDF was defending against
  the wrong threat model and created a DoS lever).
- `DuplicateKeyError` is catchable and used correctly at both `provision()` and migration call
  sites — no unhandled `IntegrityError` path found.
- `_validated_provision_tenant` reuses `store.py::_validated_tenant`, closing the "authenticates
  then 400s forever" gap for both live provisioning and env-var migration.
- URL-decode fix in `app.py::_route_get` (`unquote` on the MAC path segment) is correctly placed
  before the `STORE.get()` lookup.
- `manage_keys.py` CLI (`provision`/`revoke`/`list`) matches the store API 1:1, never prints/logs
  key material except the one-time provision output, resolves `--db` the same way `app.py` does.

No other defects found in this pass beyond §§2–3.

## 5. Overall verdict

**GO.** M4 (WS-6 tenant isolation + per-tenant hashed API keys with rotation/scope) is genuinely
complete and safe to close as F1's final state. Every security property asked for — cross-tenant
isolation, scope enforcement, fail-closed auth, correct HMAC+pepper usage, no timing regression,
clean rotation with no overlap — is independently verified against real reproductions, not just
descriptions. Both of 22ce005's claimed fixes are real fixes for real, previously-reproduced
failure modes (the schema-upgrade crash reproduces exactly as described when reverted; the pepper
canary's runtime behavior was manually confirmed).

Two non-blocking follow-ups are open, both low severity and independent of each other:
- §2: pepper-canary detection logic itself is untested (only its storage is tested) — add a
  stdout-capturing test.
- §3: the schema migration silently drops the `tenant_id` index on the new table — fix the index
  name collision.

Neither is an auth-bypass, data-loss, or lockout risk; recommend filing both as fast-follow tickets
rather than reopening F1.
