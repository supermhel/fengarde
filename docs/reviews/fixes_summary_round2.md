# Fixes summary — round 2 (2026-07-30)

Scope: the 9 `review_bugs.md` Critical/High/Medium/Low findings that
`independent_review_of_fixes.md` identified as named in-scope by round 1's
own header (`review_bugs.md`) but never actually touched by round 1's diff:
H2, H4, H5, H6, H7, M1, M2, N1, L1. This document covers **only these 9
items** — it does not re-verify or re-describe round 1's 14 fixes
(`fixes_summary.md`), and it does not touch anything from
`review_architecture.md`, `review_adversarial_security.md`,
`review_code_quality.md`, `review_performance.md`, or
`review_design_decisions.md`.

Each fix was applied one at a time with the full zero-infra suite
(`PYTHON=python bash run_all_tests.sh`) run green before starting the next.
Full suite status at the end of this pass: **`ALL TESTS PASS`**.

## Fixed

| ID | Finding | Severity | What changed | Test |
|---|---|---|---|---|
| H5 | Six parsers (`db_audit`, `n8n_audit`, `opcua_audit`, `mcp_agent`, `modbus_anomaly`, `vmware_vsphere`) used the old pre-`timeutil` timestamp check; an ISO-8601 timestamp silently became `now()` | High | Each parser's `_time_ms`/`_logged_time` now routes through `timeutil.to_epoch_ms()`, exactly matching the pattern already used by `active_directory.py`/`windows_eventlog.py`/`sysmon.py`/`k8s_audit.py`/`cloudtrail.py`. No behavior change for existing epoch-ms fixtures (`to_epoch_ms` handles int/float identically to the old check); an ISO-8601 string now round-trips to its real time instead of `now()`. | One new test per parser (`test_iso_timestamp_preserved_not_replaced_by_now`, added to each of `test_db_audit.py`, `test_n8n_audit.py`, `test_opcua_audit.py`, `test_mcp_agent.py`, `test_modbus_anomaly.py`, and a new `TestVmwareTimestamp` class in `test_v05_severity_sector.py`), each asserting a fixed ISO string (`2020-01-01T00:00:00Z`) parses to the exact expected epoch-ms (`1577836800000`), not to `int(time.time()*1000)`. |
| H2 | WS-6 `_upsert_locked` applied any `seen_at` unconditionally — an out-of-order/delayed redelivery regressed `ip_current`/`last_seen` and inverted an `ip_history` interval | High | `services/ws6-inventory/store.py`: before applying an update to an *existing* row, compare the incoming `seen_at` against `row["last_seen"]`; if the incoming observation is strictly older, skip the ip/last_seen/hostname update entirely (protocol-sighting recording is unaffected — it's a historical fact, not state). If parsing either timestamp fails, fails open (applies the update) — same as pre-fix behavior, since staleness can't be proven. | New scenario in `services/ws6-inventory/test_contract.py` reproducing the exact audit repro (newer obs @12:05 then a stale redelivery @12:00): asserts `ip_current`/`last_seen` are unchanged by the stale observation and no second (inverted) `ip_history` interval is opened. |
| H4 | Three parsers (`cef`, `cloudtrail`, `k8s_audit`) used `valid_ip()` only as a boolean gate, then assigned the *original unnormalized* string — a dual-stack `::ffff:a.b.c.d` address passed the gate but then failed Contract A's `ip` schema pattern, dead-lettering the whole event | High | All three now assign `valid_ip()`'s **returned** (normalized) value, matching every other parser in the codebase (`db_audit`, `active_directory`, `n8n_audit`, etc.). | New `test_dual_stack_ip_normalized_not_dead_lettered` in `test_cef.py` (both src and dst), `test_cloudtrail.py`, and `test_k8s_audit.py` — each asserts a `::ffff:10.0.0.x` input produces `src_endpoint.ip == "10.0.0.x"` and `validate(event) == []`. |
| H6 | `tools/validate_contract.py`'s `check_invariant()` raised an unhandled `TypeError` on a type-mismatched `class_uid`/`activity_id`/`type_uid`, crashing `main()`'s file loop and skipping validation of every alphabetically-later fixture | High | Added a type guard (`isinstance(x, int) and not isinstance(x, bool)` for all three fields) before the arithmetic; returns silently (the schema pass already reports the type mismatch) instead of raising. | New `tools/test_validate_contract.py` (7 tests): type-mismatched `class_uid`/`activity_id`/`type_uid` each proven not to raise; `bool` proven not to slip through the `int` guard; a correctly-typed valid invariant stays silent; a correctly-typed **violated** invariant still reports (proves the fix didn't over-suppress); a missing field still returns silently. Wired into `run_all_tests.sh` immediately after `validate_contract.py` itself. |
| H7 | `eval/detection_accuracy/evtx_eval.py`'s `in_business_hours()` disagreed with the real engine (`services/ws4-detection/engine.py::_time_outside_hours`) at exactly 18:00:00–18:00:59, corrupting the confusion matrix for `common_after_hours_admin` | High | Removed the extra `(dt.hour == 18 and dt.minute == 0)` clause; now computes `minute_of_day = dt.hour*60 + dt.minute` and checks `480 <= minute_of_day < 1080`, the same half-open interval the real engine uses. `splunk_eval.py` reuses `evtx_eval.oracle()` verbatim, so it's fixed too — no separate copy existed. | New `eval/detection_accuracy/test_evtx_eval.py` (7 tests) cross-checks `in_business_hours()` against the real `_time_outside_hours()` at 07:59, 08:00, 12:30, 17:59, 18:00:00 (the exact regression), 18:00:30, and a weekend timestamp — all required to agree. Wired into `run_all_tests.sh`. |
| M1 | CEF parser: a blocked/dropped auth attempt (`act=blocked`) fell through `status_from_outcome`'s "Success" default because the shared `_FAILURE_TOKENS` vocabulary didn't include `blocked`/`drop`/`dropped` (only `cef.py`'s own local, network-branch-only `_DENY_TOKENS` did) | Medium-High | Added `blocked`, `block`, `drop`, `dropped` to `base.py::_FAILURE_TOKENS` (the shared vocabulary every parser's `status_from_outcome()` call reads). | New `test_blocked_and_dropped_are_failures` in `test_parser_hardening.py`, plus the exact CEF repro from the audit (`suser=admin ... act=blocked` → `status: Failure`, not `Success`) as `test_blocked_auth_attempt_is_failure_not_success` in `test_cef.py`. |
| M2 | WS-6 `_parse()`/`resolve()` assumed `seen_at` is always an ISO-8601 string; WS-1's `snmp_collector`/`syslog_collector` both emit it as a raw epoch-seconds int — SQLite silently stringified the int on write, then `resolve()` crashed on it later | Medium-High | Added `_normalize_seen_at()` in `store.py`: converts an int/float `seen_at` to a canonical ISO-8601 string via `datetime.fromtimestamp(seen, tz=utc).isoformat()` at the single write choke point (`_upsert_locked`); an already-ISO string passes through unchanged. Fixes the mismatch at the boundary rather than requiring every caller (or every collector) to agree on a shape. | New scenario in `test_contract.py`: upserts with a raw epoch int `seen_at`, asserts the asset is created (not silently dropped), `resolve()` succeeds against it (doesn't raise `ValueError`), and that a later ISO-string observation correctly supersedes it (proves the two representations now compare correctly on the same footing, which also matters for the H2 staleness check above). |
| N1 | `mcp_agent.py`'s `_DELETE_KEYWORDS` matched `"rm"` as a plain substring, misclassifying any tool name that merely *contains* "rm" (`perform_backup`, `format_report`, `confirm_action`, `terminate_session`, `warm_cache`) as a destructive delete | Medium | Pulled `"rm"` out of `_DELETE_KEYWORDS` (kept `delete`/`remove`/`drop` as substring matches — long enough to be low-risk per the audit) and added a `_tokenize()` helper (splits on `_`/`-`/whitespace/camelCase boundaries) so `"rm"` is only flagged when it appears as its own token. | New `test_rm_substring_in_benign_tool_names_not_flagged_delete` (the exact 5 false-positive names from the audit, all now correctly *not* classified as delete) and `test_rm_as_own_token_still_flagged_delete` (`rm`, `rm_file`, `rm-resource`, `fileRm` — all still correctly flagged) in `test_mcp_agent.py`. |
| L1 | `_MemoryBus.produce()`'s `self._seq += 1` was an unsynchronized read-modify-write; `SyslogUDPServer`'s worker-thread pool calls `produce()` on one shared bus, so two concurrent calls could hand two messages the same `Message.id` | Low-Medium | Added a `threading.Lock` (`_seq_lock`) spanning the read-increment-store of `_seq`, mirroring the lock `InventoryStore` already uses for its own read-modify-write. | New `services/shared/test_bus_memory_race.py`. Because a bare `int += 1` is too narrow a window to reliably race under real CPython scheduling (confirmed by hand: a 20-thread/50-iteration hammer test against the *unfixed* code produced zero collisions), the test swaps `_seq` for a `SlowInt` whose `__add__` sleeps before returning, then releases two threads at a `Barrier` — deterministically forcing the exact interleaving the audit described. Verified by hand against the pre-fix code (bare `self._seq += 1`) that this technique reliably reproduces a duplicate id there, and against the fixed code that the lock prevents it even under this widened window. Wired into `run_all_tests.sh`. |

## Verification

- `PYTHON=python bash run_all_tests.sh` passed clean (`ALL TESTS PASS`) after
  every individual fix, and again at the end of the full pass.
- Every one of the 9 fixes got a new regression test that specifically
  targets the failure mode the audit described (not just a happy-path
  re-check) — verified by hand-tracing each one against the pre-fix code,
  and for the two hardest-to-test cases (H6's crash path, L1's race) by
  literally running the reproduction against a pre-fix code path first to
  confirm the test fails there before confirming it passes against the fix.
- No fix required touching the H2/M2 tenant-isolation or CAS-locking work
  from round 1 — `_upsert_locked`'s staleness check and `_normalize_seen_at()`
  both sit inside the same tenant-scoped write path round 1 already added,
  and neither changes its locking or tenant-scoping behavior.

## Things worth flagging, not blockers

- **H2's staleness check only guards `ip_current`/`last_seen`/`ip_history`,
  not `hostname`.** A stale observation's hostname is simply never applied
  (the whole `else` branch is skipped when `stale`), which is the safe
  fail-closed direction, but it means a genuinely newer hostname arriving
  bundled with a stale `seen_at` would also be dropped rather than merged.
  Not a scenario the audit's repro covered, and splitting hostname-merge from
  ip/last_seen-staleness would be a real (if small) design decision, not a
  drive-by addition to this pass.
- **M2's `_normalize_seen_at()` assumes an epoch int/float is UTC.**
  `snmp_collector.py`/`syslog_collector.py` both use `int(time.time())`,
  which is already UTC-based, so this is correct for the two callers that
  exist today. If a future caller passed a naive local-time epoch, it would
  silently be treated as UTC — same class of assumption `_parse()` already
  makes for a timezone-less ISO string (`.replace(tzinfo=timezone.utc)` when
  unspecified), so this isn't a new risk, just worth naming.
- **N1's fix, as originally shipped in this round, was scoped to the exact
  false-positive class the audit reproduced** (English words that happen to
  contain "rm"), via a tokenizer that split only on `_`/`-`/whitespace/
  camelCase. The claim that a dot-delimited name (e.g. `resource.rm`) would
  "still correctly flag via the dot acting as a non-word-boundary-preserving
  split point" was **wrong** — `independent_review_of_fixes_round2.md` §3
  tested it directly and found `_TOKEN_SPLIT_RE` didn't split on `.` at all,
  so `resource.rm`/`fs.rm`/`rm.resource`-style names silently escaped
  delete-classification entirely, a real (if narrow) coverage regression vs.
  the original buggy substring code, which happened to still catch these via
  plain "rm" containment. **Closed in a follow-up pass** (2026-07-30,
  same day): `_TOKEN_SPLIT_RE` now also splits on `.`/`:`, so
  `resource.rm`/`fs.rm`/`rm.resource`/`fs:rm` are all tokenized to a
  standalone `rm` token and correctly flagged again, without reintroducing
  the original substring false-positive bug (none of the 5 audit-cited
  benign names — `perform_backup`, `format_report`, `confirm_action`,
  `terminate_session`, `warm_cache` — contain a `.`/`:`, so the added split
  characters don't change their tokenization). New test
  `test_rm_dot_or_colon_delimited_still_flagged_delete` in
  `services/ws2-normalization/parsers/test_mcp_agent.py` covers this
  directly. See the addendum below.
- **L1's fix does not address O3** (the separate, lower-priority latent
  check-then-act race in `_MemoryBus.consume()` that the same bug-hunt report
  flagged as "not currently reachable in production... flagging as a trap for
  whoever extends that test pattern next"). O3 was not in the 9-item scope
  for this pass and was left untouched.

## Deferred — none

All 9 items in scope were fixed; none turned out to require deferral. If any
had (e.g. needed new infrastructure, a design decision, or a multi-day
build), this section would say so explicitly rather than folding it silently
into "done" — same discipline `fixes_summary.md` used for its own two
deferred items.

## What this pass does not cover

This pass closes out `review_bugs.md`'s previously-untouched Critical/High/
Medium/Low findings. It does not re-open or re-verify round 1's 14 fixes,
and it does not touch the still-open items `independent_review_of_fixes.md`
flagged as correctly-deferred-with-rationale (Design-C's cross-alert
correlation engine, WS-6's shared-API-key/no-per-tenant-auth gap) or the
untouched items from the other five review reports
(`review_code_quality.md` #2–#7, `review_performance.md` #2–#5,
`review_architecture.md` F2–F8, `review_design_decisions.md` D/E/G/H). Those
remain exactly as characterized in the prior round's documents.

## Addendum (2026-07-30) — N1 gap closure

`independent_review_of_fixes_round2.md`'s only required correction (§3,
"GO for merging... with one required correction") was that N1's shipped fix
had a real, if narrow, false-negative regression: the tokenizer
(`_TOKEN_SPLIT_RE` in `services/ws2-normalization/parsers/mcp_agent.py`)
split on `_`/`-`/whitespace/camelCase but not on `.`/`:`, so a dot- or
colon-namespaced tool name like `resource.rm`/`fs.rm`/`fs:rm` survived as one
token that never equals the standalone `"rm"` token the fix checks for — the
name silently stopped being classified as a delete, where the original
(buggy) substring code had coincidentally still caught it.

**Fix:** extended `_TOKEN_SPLIT_RE` to also split on `.` and `:` —
`r"[_\-\s.:]+|(?<=[a-z0-9])(?=[A-Z])"` instead of `r"[_\-\s]+|(?<=[a-z0-9])(?=[A-Z])"`.
Verified this doesn't reintroduce the original substring false-positive bug:
none of the 5 audit-cited benign names (`perform_backup`, `format_report`,
`confirm_action`, `terminate_session`, `warm_cache`) contain a `.` or `:`, so
their tokenization is unchanged by the wider split set.

**Test:** `test_rm_dot_or_colon_delimited_still_flagged_delete`
(`services/ws2-normalization/parsers/test_mcp_agent.py`) asserts
`resource.rm`, `fs.rm`, `rm.resource`, and `fs:rm` all classify as
`activity_id=4` (Delete) — fails against the pre-patch tokenizer, passes
against the fix. Full zero-infra suite (`PYTHON=python bash
run_all_tests.sh`) reconfirmed green with this change applied.

This closes the one open item from both independent reviews; round 2's 9
fixes plus this follow-up are now fully addressed.
