# Independent Review of `fixes_summary_round2.md` — adversarial verification pass

**Reviewer:** independent verification, second round. Did not trust `fixes_summary_round2.md`'s
own descriptions. Read every diff hunk directly (`git diff` per file, since nothing in this
round is committed yet — all changes are in the working tree on top of `HEAD`), re-derived each
of the 9 findings from `review_bugs.md` myself, traced each new test by hand to confirm it would
fail against the pre-fix code, and ran the full zero-infra suite independently. Method follows
the same discipline as `independent_review_of_fixes.md` (round 1).

**Scope:** the 9 items `fixes_summary_round2.md` claims to have fixed — H2, H4, H5, H6, H7, M1,
M2, N1, L1 — plus the four specific stress-test angles called out for this pass (H2 hostname
interaction with the staleness guard, M2's UTC assumption against real callers, N1's scope
limits, L1's race fix under real vs. forced concurrency, and O3 being correctly left alone).

---

## 1. Per-item verdicts

| ID | Finding | Verdict | Notes |
|---|---|---|---|
| H5 | 6 parsers (`db_audit`, `n8n_audit`, `opcua_audit`, `mcp_agent`, `modbus_anomaly`, `vmware_vsphere`) used pre-`timeutil` timestamp logic | **PASS** | All six now use the exact `to_epoch_ms(a) or to_epoch_ms(b) or int(time.time()*1000)` chaining pattern already used by `active_directory.py`/`windows_eventlog.py`/`sysmon.py`. Verified this chaining is safe: `to_epoch_ms()` returns `None` for any non-positive value (`v <= 0` check inside `timeutil.py:37`), so it never returns a falsy `0` that the `or` chain could misinterpret as "missing" — the pattern cannot silently swap a legitimate epoch-0 event for `received_at`/`now()`. Every new test (`test_iso_timestamp_preserved_not_replaced_by_now`, one per parser) asserts an exact epoch-ms value (`1577836800000`) that only round-trips correctly through real ISO-8601 parsing — traced by hand that each fails against the pre-fix `isinstance(x, (int,float))` check (a string always fails that check and falls to `now()`, which is never `1577836800000`). |
| H2 | WS-6 `_upsert_locked` applied any `seen_at` unconditionally, regressing `ip_current`/`last_seen`/`ip_history` on a stale redelivery | **PASS** | `stale = _parse(seen) < _parse(row["last_seen"])`; the entire `ip_current`/`ip_history`/`last_seen`/`hostname` update block is skipped when `stale`, protocol-sighting insert unaffected (correct — a protocol observation is a historical fact independent of ordering). Parse failure fails **open** (applies the update) — explicitly disclosed, consistent with "can't prove staleness, so don't block a real update." New `test_contract.py` scenario reproduces the audit's exact repro (12:05 then a stale 12:00 redelivery) and asserts `ip_current`/`last_seen` unchanged and only one open `ip_history` interval — traced by hand that this fails against pre-fix code (which applied the stale write unconditionally, producing the inverted interval the audit described). See §2 for the hostname-merge stress test requested for this item. |
| H4 | 3 parsers (`cef`, `cloudtrail`, `k8s_audit`) discarded `valid_ip()`'s normalized return value | **PASS** | All three now assign the return value (`src_ip = valid_ip(src_ip)`) instead of using it only as a boolean gate. Matches every other parser's existing pattern exactly. New tests in all three files assert a `::ffff:10.0.0.x` input round-trips to `"10.0.0.x"` and `validate(event) == []` — verified this fails pre-fix (the dead-letter path is `validate()` rejecting the unnormalized dotted-IPv6 string against Contract A's pattern). |
| H6 | `validate_contract.py::check_invariant()` raised an unhandled `TypeError` on a type-mismatched `class_uid`/`activity_id`/`type_uid` | **PASS** | Type guard added before the arithmetic (`isinstance(x, int) and not isinstance(x, bool)` for all three fields), returns silently on mismatch (schema pass already reports the type error). New `tools/test_validate_contract.py` (7 cases) explicitly proves both directions: a type-mismatched field doesn't raise/doesn't fabricate an error, **and** a correctly-typed genuinely-violated invariant still reports (i.e., the fix didn't over-suppress the real check) — this second case is exactly the kind of self-check that catches an overly broad early-return, and it's present and correct here. Wired into `run_all_tests.sh` immediately after `validate_contract.py`. |
| H7 | `evtx_eval.py::in_business_hours()` disagreed with the real engine at 18:00:00–18:00:59 | **PASS** | Extra `(dt.hour==18 and dt.minute==0)` clause removed; now `480 <= minute_of_day < 1080`, matching `engine.py::_time_outside_hours`'s `start <= minute_of_day < end` exactly. New `test_evtx_eval.py` imports and cross-checks against the **real** `_time_outside_hours()` (not a hardcoded expectation), at 07:59/08:00/17:59/18:00:00/18:00:30/12:30/a weekend timestamp — the strongest possible regression test for this class of bug, since it fails automatically if the two ever drift again, not just at the one boundary the audit found. |
| M1 | CEF `act=blocked` fell through `status_from_outcome`'s "Success" default | **PASS** | `blocked`/`block`/`drop`/`dropped` added to the shared `_FAILURE_TOKENS`. Confirmed the match is exact-token (`s in _FAILURE_TOKENS` after `.strip().lower()`), not substring, so this can't collateral-damage an unrelated field whose value happens to *contain* one of these words. Checked all 9 call sites of `status_from_outcome` across the parser set — none pass a field where "block"/"drop" would plausibly mean something other than "not successful" (k8s uses a numeric HTTP-code key, cloudtrail uses `ConsoleLogin` Success/Failure strings). New tests hit both the shared-function level (`test_parser_hardening.py`) and the exact CEF repro end-to-end. |
| M2 | WS-6 `_parse()` assumed ISO-8601; WS-1 collectors emit raw epoch-seconds int | **PASS** | `_normalize_seen_at()` converts int/float via `datetime.fromtimestamp(seen, tz=utc)` at the single write choke point. See §2 for the UTC-assumption stress test requested for this item — it holds for both real callers, and arguably can't not hold (a Unix timestamp is UTC by definition). Test proves the epoch value is accepted, `resolve()` doesn't crash, and a later ISO-string observation correctly supersedes it — hand-verified the test's epoch constant (`1750000000` → 2025-06-15 15:06:40 UTC) is genuinely older than the ISO follow-up (`2025-06-15T16:00:00Z`), so the "later wins" assertion is testing what it claims to. |
| N1 | `mcp_agent.py` substring-matched `"rm"`, misclassifying `perform_backup`/`warm_cache`/etc. as deletes | **PASS, with a regression the summary's own caveat gets factually wrong — see §3** | `"rm"` removed from the substring `_DELETE_KEYWORDS`, replaced with a token-boundary check (`_tokenize()` splits on `_`/`-`/whitespace/camelCase, then exact-match `"rm"` against tokens). The 5 audit-cited false positives are fixed and the true positives (`rm`, `rm_file`, `rm-resource`, `fileRm`) still fire — verified both directions pass. **However**, the summary claims a dot-delimited name like `resource.rm` "would still correctly flag via the dot acting as a non-word-boundary-preserving split point" — I tested this directly and it is false (§3): the tokenizer does not split on `.`, so `resource.rm`/`rm.resource`/`fs.rm`-style names are now silently **not** flagged as deletes, where the old (buggy) substring code did flag them. This is a real, if narrow, false-negative regression the fixing session's own verification missed. |
| L1 | Unsynchronized `_seq` read-modify-write in `_MemoryBus.produce()` | **PASS** | `threading.Lock` now spans the read-increment-store of `_seq`; the `Message`/deque-append happens outside the lock using a captured local `seq` int (immutable, so this is safe — no reintroduced race on the id value itself). See §2 for why this closes the *real* race, not just the artificially-widened test window. `consume()`'s separate O3 latent race is untouched, correctly — confirmed by reading the current code (`while q: yield q.popleft()`, unchanged) and cross-checking `fixes_summary_round2.md`'s own disclosure that O3 was deliberately left out of scope. |

---

## 2. Stress-testing the fixing session's own caveats

### H2 — does the staleness guard's hostname skip introduce a new bug?

Traced `_upsert_locked` in `services/ws6-inventory/store.py`: when `stale` is `True`, the
**entire** `else`-branch body is skipped — `ip_current`/`ip_history`/`last_seen` **and**
`hostname` all stay untouched; only the (order-independent, set-like) `protocols` insert still
runs. This is genuinely fail-closed in the sense that matters: a stale write can never overwrite
newer state with older state, for any of the four fields it could otherwise touch. The disclosed
cost — a real, newer hostname that happens to arrive bundled with a stale `seen_at` gets dropped
too, not merged — is a true limitation, but it is a *conservatism* cost, not a *correctness* bug:
nothing about it can cause `last_seen`/`ip_current` to regress or invert an interval, which is the
actual failure mode H2 exists to prevent. Verdict: sound as characterized, not a new staleness
bug.

### M2 — does "epoch input is always UTC" hold for both real callers?

`_normalize_seen_at()` does `datetime.fromtimestamp(seen, tz=timezone.utc)`. Checked both actual
producers of `seen_at` as a raw number:

- `services/ws1-collectors/collectors/snmp_collector.py:55` → `polled_at = int(time.time())`
- `services/ws1-collectors/collectors/syslog_collector.py:74` → `received_at = int(time.time())`

`time.time()` returns seconds since the Unix epoch, which is **inherently** UTC — there is no
"local time zone" reading of a POSIX timestamp to get wrong; interpreting the same integer with
`tz=utc` is the only correct interpretation, not an assumption that could fail for a differently-
behaved caller. The summary's own caveat ("if a future caller passed a naive local-time epoch, it
would silently be treated as UTC") describes a scenario that isn't really coherent for a Unix
timestamp — a caller would have to be already computing the wrong number (e.g., via
`time.mktime()` misuse) for this to matter, which is a bug in that hypothetical caller, not in
`_normalize_seen_at()`. Verdict: assumption holds for both real callers, and structurally can't
not hold for any correctly-behaving future caller either.

### L1 — does the lock actually close the real race, not just the forced one?

The fix wraps `self._seq += 1` (and the subsequent read into the local `seq`) inside
`with self._seq_lock:`. The test widens the race window by swapping `_seq` for a `SlowInt` whose
`__add__` sleeps — but critically, that sleep now happens **while the lock is held** (it's inside
the `with` block), so the widened window doesn't defeat the fix; it just makes the *pre-fix*
absence of a lock deterministically demonstrable instead of relying on rare GIL-preemption timing.
Because a `threading.Lock` provides mutual exclusion regardless of how long the critical section
takes, the same lock closes the race under real, unwidened CPython scheduling too — the artificial
slowdown is a test-only aid, not a precondition for the fix to work. Traced that the
`Message`/deque-append happens outside the lock using a captured local `seq` (a plain, immutable
`int` by the time it's used, since `self._seq` was reassigned to a fresh `SlowInt`/`int` object
inside the lock and `seq = self._seq` copies that reference into a local before release) — so no
new race is reintroduced by narrowing the critical section to just the counter. Verdict: closes
the real race, not just the test's forced interleaving.

**O3 correctly left alone:** confirmed `_MemoryBus.consume()` (`services/shared/bus.py:77-81`) is
byte-for-byte unchanged (`while q: yield q.popleft()`), and `fixes_summary_round2.md` explicitly
names O3 as out-of-scope with accurate reasoning (same "not currently reachable in production"
rationale the original audit gave). No silent scope creep, no silent omission — it's named.

---

## 3. New finding: N1's fix introduces a real (narrow) false-negative regression the summary's own verification claim gets wrong

`fixes_summary_round2.md`'s "Things worth flagging" section for N1 states:

> a tool name using some other delimiter convention (e.g. dots: `resource.rm`) would still
> correctly flag via the dot acting as a non-word-boundary-preserving split point in most cases

I tested this claim directly against the actual `_TOKEN_SPLIT_RE`
(`services/ws2-normalization/parsers/mcp_agent.py`):

```python
_TOKEN_SPLIT_RE = re.compile(r"[_\-\s]+|(?<=[a-z0-9])(?=[A-Z])")
```

```
>>> _tokenize("resource.rm")
['resource.rm']
>>> _tokenize("rm.resource")
['rm.resource']
>>> _tokenize("fs.rm")
['fs.rm']
```

The regex does not include `.` (or `:`) as a split character at all — a dot-delimited name
survives as one token, which never equals `"rm"` under the new exact-token check. And because
`"rm"` was simultaneously **removed** from the substring `_DELETE_KEYWORDS` list, there is no
remaining path by which `resource.rm`/`fs.rm`/`docker.rm`-style tool names get classified as a
delete (`activity_id=4`) anymore.

**This is a behavior change from the pre-fix code, not just a "still-open gap":** the old (buggy)
substring match (`"rm" in t`) *did* flag `fs.rm`/`resource.rm` as deletes — correctly, if
coincidentally. Post-fix, those same names are silently **not** flagged. Dot- or colon-namespaced
tool naming (`module.action`, mirroring Python/RPC-style dotted calls) is a plausible real-world
MCP tool convention, and destructive `*.rm` actions specifically are exactly the class of call
this parser's Delete classification exists to catch.

**Severity assessment:** Low-Medium, not a blocker. No existing fixture in `test_mcp_agent.py`
uses a dot- or colon-delimited tool name (the tested surface is exactly the 5 false-positive +
4 true-positive underscore/hyphen/camelCase names the audit and fix both scoped to), so this
doesn't regress anything currently exercised, and it's a false-negative on a *hypothetical* naming
style rather than a demonstrated production gap. But the summary's own factual claim about why
this is safe is wrong, and should be corrected — either fix the tokenizer to also split on `.`/`:`
(cheap, low-risk), or rewrite the caveat to accurately say dot/colon-namespaced names are an
untested, unflagged gap rather than claiming they're handled.

---

## 4. Test suite — run independently

```
PYTHON=python bash run_all_tests.sh
```

Ran to completion twice (once via `tail`, once with full output captured to a log and grepped):
**exit code 0**, final line `ALL TESTS PASS` both times. Specifically confirmed, not just
trusted the tail message:

- All 9 items' new/modified tests actually executed: grepped for the H7 test class output
  (`TestInBusinessHoursMatchesEngine`, 7/7 `ok`), the N1 regression test names
  (`test_rm_as_own_token_still_flagged_delete`, `test_rm_substring_in_benign_tool_names_not_flagged_delete`),
  the 6 H5 `test_iso_timestamp_preserved_not_replaced_by_now` docstrings (one per parser), and
  `_MemoryBus.produce() is race-free under a forced concurrent-writer interleaving` (L1's test).
- `run_all_tests.sh`'s diff confirms every genuinely new standalone test file
  (`tools/test_validate_contract.py`, `eval/detection_accuracy/test_evtx_eval.py`,
  `services/shared/test_bus_memory_race.py`) is wired in, not just present on disk — H2/M2's new
  scenarios live inside the existing `services/ws6-inventory/test_contract.py`, which was already
  wired in and printed `[OK] WS-6 contract test PASS` (the `check()`-harness pattern this file
  uses only prints a message on *failure*, so a clean `[OK]` line is proof all of its assertions,
  including the new H2/M2 ones, held).
- No hidden failures behind the summary line: grepped the full captured log for `fail`/`FAIL` —
  every hit is either a section header naming "fail" as a test subject (e.g. "CAS ... fail"), an
  intentionally-thrown exception inside a `try/except` assertion, or an expected fail-closed log
  line (allowlist-missing warnings) — the same pattern round 1's independent review already
  established as the log's normal shape.

This independently confirms `fixes_summary_round2.md`'s "ALL TESTS PASS" claim as accurate.

---

## 5. Overall recommendation

**GO for merging these 9 fixes as a set**, with one required correction before calling this round
closed:

1. **Correct N1's "Things worth flagging" caveat** in `fixes_summary_round2.md` (or wherever this
   round's notes get carried into `SSOT.md`) — the dot-delimiter claim is empirically wrong, not
   just untested. Either patch `_TOKEN_SPLIT_RE` to also split on `.`/`:` (a one-line, low-risk
   follow-up matching the same shape as the fix already shipped), or restate the caveat honestly
   as "dot/colon-namespaced `rm` actions are no longer flagged as deletes; this is untested,
   unlike the fix's stated tested surface."

None of the other 8 fixes show a new race, silent data-loss path, or behavior regression under
adversarial re-verification — each has a genuine regression test that fails without its fix
(verified by tracing the logic and, for H5/H4, by hand-checking the failure path each test
exercises), and the two hardest-to-verify claims this pass specifically asked to be stress-tested
(H2's fail-closed hostname skip, M2's UTC assumption) both hold up under scrutiny, as does L1's
lock closing the real race rather than just the artificially-widened test one.

This round's scope-honesty is also good: `fixes_summary_round2.md` accurately states it only
covers these 9 items, correctly avoids re-touching round 1's work, and explicitly names what it
did *not* fix (Design-C, the WS-6 shared-API-key gap, O3) rather than silently going quiet on them
— the opposite of round 1's scope-line problem that the first independent review flagged.
