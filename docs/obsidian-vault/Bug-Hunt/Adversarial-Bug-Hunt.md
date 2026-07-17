---
tags: [fengarde, security, bug-hunt]
dates: 2026-07-16/17
commits: 6e3fbe4..f7f6190
---

# Adversarial repo-wide bug hunt (post-M4/M5)

Parent: [[Home]]. Owner-requested pass: launch reviewers/bug-hunters over the **repo**,
not just a PR diff; adversarially verify each finding; rank by severity; fix plan.

## Method, stated honestly

Five parallel review subagents across two rounds all terminated early on a
session/usage quota before returning verdicts — a real environment limitation, not a
false-negative sweep. Every finding below was independently confirmed by direct code
reading (parser source, callers, schema/validation, existing tests), not by trusting
agent output. Every fix shipped a regression test independently verified via a
**revert/run/restore cycle** on the fix's own diff: revert only the fix (keep the new
test), confirm the test fails, restore the fix, confirm it passes — proving the test
actually catches the regression, not just that it passes today.

## Findings, ranked by severity

### F1 — HIGH — cross-tenant pooling in WS-4's stateful rule engine

Two separate bugs in the same mechanism, found in two passes:

1. **Window counter pooling** (original finding): `Rule.evaluate()`'s sliding-window
   counter key was `f"{rule_id}:{group}"` — no tenant component. Two tenants sharing
   a `group_by` value (e.g. overlapping RFC1918 source IPs — the normal case for an
   MSP) had their event counts pooled into one shared window, letting one tenant's
   traffic trip another tenant's threshold. Fixed by namespacing the key on
   `siem.tenant`.
2. **`alert_key()` was still unfixed** (caught by a dedicated follow-up review of fix
   #1 itself): the function that computes the actual `alert_id` persisted to storage
   and returned to API callers stayed `f"{rule_id}:{group}:{bucket}"`. Two tenants
   firing in the same window bucket on a shared IP got the **identical alert_id**,
   and `find_alert()`'s cross-index-by-id lookup returned only the first match — one
   tenant's alert became unreachable, shadowed behind the other's, regardless of
   tenant-scoped storage (the collision is on the lookup key, not where the doc
   physically lands). Fixed the same way.

Both closed a direct breach of the M4.1 tenant-isolation guarantee.

### F6 — MEDIUM/HIGH — `active_directory.py` missing the M1 OCSF field-type guards

Assigned raw, un-typechecked fields (`IpAddress`/`MacAddress`/`TargetUserSid`)
straight into OCSF schema-constrained fields — unlike every sibling parser, which
already goes through `shared/ocsf.py`'s `valid_ip`/`valid_mac`/`safe_str`. A
malformed upstream field silently dead-lettered the whole event instead of dropping
just the bad field, which can blind `common_bruteforce`/`common_password_spray`/
`common_lateral_movement` on real AD authentication events.

### F2 — MEDIUM — `GET /alerts/{id}/report` tenant-gate bypass

The tenant gate only applied `if found_alert is not None`. Once an alert aged out
(reports have independent retention from alerts), the gate was skipped and any
authenticated caller could read another tenant's incident report. Now fails closed
(404) for non-admins when the alert doc is absent.

### F5 — LOW/MEDIUM — `LoginRateLimiter` unbounded growth + no lock

Grew its per-username dict without bound (memory-DoS risk on `/auth/login`) and had
no lock despite being mutated from multiple `ThreadingHTTPServer` handler threads
(dropped failure records under concurrency). Added a lock + periodic sweep, mirroring
the pattern `window.py` already uses for its own counters.

### F4 — MEDIUM — `tools/restore.py` symlink-escape via extract-before-verify

The traversal guard only checked each member's *name* — not enough to stop a symlink
member written "through" by a later member (CVE-2007-4559 class). Switched to
`tarfile.extractall(filter="data")` (PEP 706), which rejects symlinks, absolute
paths, and `..` traversal before anything is written.

### F3 — MEDIUM — unvalidated `tenant_id` in index names / config paths

Flowed unvalidated into an OpenSearch index name (`router.py`) and a
`contracts/tenants/<id>.yml` path (`tenants.py`). An uppercase/space-containing
tenant_id produced an OpenSearch-invalid index name → silent dead-letter for that
whole tenant; a path-traversal-shaped tenant_id could construct a path outside
`contracts/tenants/`. Added `shared/envelope.py::valid_tenant_id()` (DNS-label-style
allowlist). **Owner decision: reject at the edge, never normalize** — normalizing
"Acme"/"ACME" to the same slug would silently merge two tenants' data, the exact
isolation breach this mechanism exists to prevent.

## What was checked and found clean (adversarially, not rubber-stamped)

The follow-up review re-checked F2–F6 independently after fixing F1's second half and
found no further issues in any of them.

## Coverage gaps — explicitly not reviewed this pass

Named, not silently dropped: `bus.py`/`runner.py` redelivery/DLQ depth; most
parsers' *test* coverage depth (only a targeted spot-check, not exhaustive);
`diskguard.py`'s walk-up-to-ancestor logic; `migrate_opensearch.py`'s
plan/apply-on-failed-GET path; `chaos_test.py`'s "exactly once" assertion (never run
against Docker, so can't confirm it doesn't pass vacuously); `generate_sbom.py
--check`; `spool.py::drain_into`/`_rewrite` crash-atomicity; `users.py::migrate`
downgrade path. A follow-up sweep with fresh review agents should cover these before
[[M6-Launch-Readiness|M6]].

## Verification

`bash run_all_tests.sh` → `ALL TESTS PASS`; `ruff check services/ tools/ eval/` →
`All checks passed!` — both with every fix (including the F1 follow-up) applied
together.
