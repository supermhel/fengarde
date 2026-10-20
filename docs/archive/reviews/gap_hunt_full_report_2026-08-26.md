# FENGARDE gap-hunt full report — 2026-08-26

**Scope:** this document consolidates three review passes performed against branch
`fix/chaos-ws8-gap-hunt` (PR #74) and the repository at large, all run as parallel Claude
Opus 5 subagents with a "silence is the killer" mandate — find places where something
looks correct/covered/proven but a real failure would produce no signal (no log, no test
failure, no CI red, no nonzero exit code).

- **Round 2** — code review of PR #74's actual diff (`origin/main..HEAD`, 3 commits, 44
  files), 6 parallel reviewers, each scoped to a slice of the diff.
- **Round 3** — repo-wide gap hunt over areas *not* touched by the PR diff: WS-8
  correlation, WS-2 normalization core, Docker/compose/CI infra, eval harness + contracts
  drift, and `services/shared/` modules not covered elsewhere. 4 parallel agents.
- **Round 4** — extensive repo-wide gap hunt covering everything still unexamined: the
  remaining WS-3 indexer modules, WS-4 main/scoring, WS-5 `llm_adapter.py`, WS-6
  inventory, the full WS-7 dashboard (previously only two narrow spots had been checked),
  WS-1 collectors' main loop/spool/Dockerfile, docs-vs-code drift, the remaining `tools/`
  scripts, the test-runner meta-layer itself, and individual detection-rule semantic
  correctness. 10 parallel agents (some re-run after session interruptions; all retries
  used identical prompts).

**Verification posture:** every agent was instructed to verify claims by reading full
files and, wherever feasible, running the actual code (constructing boundary-value
events, reverting a fix and confirming a test goes red, driving real HTTP requests,
grepping for call sites) rather than asserting from inspection alone. The main thread
additionally spot-verified a sample of the highest-severity claims directly. One round-3
finding was checked and found **false** — see the note in that section — and has been
removed from the totals below. No other findings were found to be incorrect on spot-check,
though the full set was not exhaustively re-verified by the main thread; treat each
finding as agent-verified, not independently re-proven, unless the entry says otherwise.

**Totals:**

| Round | 🔴 Critical | 🟡 Risk | 🔵 Minor/nit | Total |
|---|---|---|---|---|
| Round 2 (PR #74 diff) | 8 | 33 | 2 | 43 |
| Round 3 (repo gap-hunt) | 9 | 40 | 21 | 70 |
| Round 4 (extensive gap-hunt) | 28 | 73 | 42 | 143 |
| **Total** | **45** | **146** | **65** | **256** |

Severity legend: 🔴 = confirmed/high-confidence critical bug (data loss, security bypass,
silent production failure of a core path). 🟡 = real defect or coverage gap with a
plausible-but-narrower blast radius. 🔵 = minor/latent issue, low reachability today, or a
documentation/consistency nit.

---

## ROUND 2 — PR #74 diff review (43 findings)

Diff scope: `origin/main..HEAD`, commits `418f3cf`, `87e9f80`, `beb1840` — the branch's own
two gap-hunt-and-fix rounds plus a CI-failure fix.

### Security — auth/MFA/webhooks (1🔴 6🟡)

1. **🔴 `shared/users.py:320-344`** — TOTP replay check is a TOCTOU race: the read
   (`row = self.get_user(...)`, L320) and the replay check (L337) both run outside
   `self._write_lock`; only the final UPDATE (L339) is guarded. Verified empirically: 8
   concurrent logins submitting the *same* code — 8 of 8 accepted. Fix: move read+check+write
   inside the lock and make the write conditional
   (`UPDATE ... WHERE totp_last_counter < ?`, check `rowcount == 1`).
2. **🟡 `shared/users.py:337`** — `verify_totp` does double duty (enrollment-confirm *and*
   login), sharing one counter. Enrolling burns the current time-step, so the user's very
   next real login within that ~30s window gets a false 401.
3. **🟡 `ws3-indexer/webhooks.py:109`** — only `yaml.YAMLError` is caught; a non-UTF-8 or
   unreadable config file raises `OSError`/`UnicodeDecodeError` uncaught, crashing WS-3
   startup.
4. **🟡 `ws6-inventory/authz.py:52`** — `require_auth_or_die` is boot-only; `app.py`'s
   `_check_auth` still returns auth-open whenever `KEYSTORE.count() == 0` at request time,
   ignoring `FENGARDE_REQUIRE_AUTH`. Revoking the last live key silently reopens the
   service.
5. **🟡 `ws6-inventory/test_auth.py:304`** — sets env var `KEYSTORE_DB`, but the code reads
   `INVENTORY_KEYSTORE_DB`; a dev/CI env with that var already set loses test isolation and
   one test writes a real key into it.
6. **🟡 `ws6-inventory/test_auth.py:308`** — `rc == 1` is not mutation-sound; any uncaught
   exception also yields rc 1, so the test doesn't actually prove the intended code path ran.
7. **🟡 `ws3-indexer/test_fix_mfa.py:206`** — the only HTTP-level MFA login test was *edited
   to avoid* replay (`at=+30s`) instead of extended to prove replay is rejected — the new
   protection is untested at the HTTP layer.

### WS-1 collectors (0🔴 4🟡)

8. **🟡 `main.py:60`** — `_float_env` accepts `nan`/`inf`; `SYSLOG_MAX_EVENTS_PER_SEC=nan`
   silently disables rate-limiting, `SYSLOG_SILENCE_WARN_S=nan` silently disables the
   silence watchdog.
9. **🟡 `main.py:126`** — `SYSLOG_UDP_PORT` degrades gracefully on a bad value; `PORT`
   doesn't, despite an identical stated rationale ("crash loud on bind ports").
10. **🟡 `test_syslog_udp.py:575`** — mutation-unsound: tests call `_int_env`/`_float_env`
    directly, never touch the real call sites; reverting the actual fix leaves them green.
11. **🟡 `test_syslog_udp.py:679`** — docstring claims `IndexError` is the case under test,
    but no fixture actually reaches that code path.

### WS-4/WS-5 (0🔴 7🟡)

12. **🟡 `runner.py:324`** — `bus_error` metric counts poll iterations, not events; a dead
    bus double-increments per pass, and the label is wider than "bus connection failure."
13. **🟡 `runner.py:359`** — no Grafana panel consumes the new metric; the shipped dashboard
    shows nothing for a dead bus.
14. **🟡 `test_runner.py:515`** — mutation-unsound (`>=1` passes if either of two increments
    survives, despite a comment claiming both fire).
15. **🟡 `engine.py:544`** — warn-once doesn't cover the actual silent path: "unconsumed
    tokens" rules get bucketed by class_uid at load time, so `_eval_condition` never runs
    for a quiet class.
16. **🟡 `ws5-ai/main.py:249`** — metrics payload is nested (`{"ai_triage": {...}}`);
    `render_prometheus` skips non-numeric leaves, so it renders as nothing on
    `/metrics/prom`.
17. **🟡 `test_ai_engine_metrics.py:1`** — not wired into `run_all_tests.sh` or CI, and has
    no pytest-collectable `test_*` function. Zero regression protection.
18. **🟡 `test_ai_engine_metrics.py:98`** — asserts against a self-built literal, not the
    real `metrics_provider=` wiring; deleting that kwarg from `main.py` still passes.

### WS-3 indexer core (4🔴 6🟡)

19. **🔴 `main.py:95-96`** — `triage is None` branch does a plain `store.index()`, skipping
    CAS entirely.
20. **🔴 `main.py:103-107`** — retry-exhaustion falls back to a plain overwrite — the exact
    clobber the function exists to prevent; the adjacent comment claiming "triage gets
    another chance" is factually wrong once this fires.
21. **🔴 `main.py:89`** — no backoff between the 5 CAS retry attempts; on real OpenSearch
    (near-real-time search, ~1s refresh) this guarantees 5 stale reads and a fall-through
    to the destructive write.
22. **🔴 `test_alert_triage_clobber.py`** — not wired into `run_all_tests.sh`; `make test`
    never runs it.
23. **🟡 `main.py:91-92`** — `existing is None` branch is also non-CAS; a concurrent
    create+triage between read and write is clobbered.
24. **🟡 `main.py:99`** — writes to `existing_index` (from a cross-tenant scan) rather than
    the routed index — can land a doc in the wrong tenant's index.
25. **🟡 `main.py:170` / `run()`** — the bulk-index path (`OpenSearchStore.bulk_index`, i.e.
    production) bypasses `index_doc()` entirely; only `MemoryStore` exercises the guarded
    path.
26. **🟡 `test_alert_triage_clobber.py:44`** — 4 of 6 scenarios pass identically with the
    fix reverted (not mutation-sound).
27. **🟡 `test_alert_triage_clobber.py:139`** — no scenario covers the retry-exhaustion
    branch — the one that actually destroys data.
28. **🟡 `test_api_v1.py:316`** — asserts against unprefixed routes, not the documented
    `/api/v1/...` spec paths it claims to verify.

### Tools/CI (1🔴 8🟡 1🔵)

29. **🟡 `ci.yml:195`** — `sleep 300` is the mfa-e2e container's whole lifetime; a slow
    build/test kills it mid-`docker exec`.
30. **🟡 `ci.yml:234`** — health-wait loop passes falsely: empty `Health` field counts as
    healthy, and `ws6-inventory`/`ws7-dashboard` have no `healthcheck:` defined at all — the
    job's core service is never actually waited for.
31. **🟡 `ci.yml:242`** — hardcoded container names break silently if `COMPOSE_PROJECT_NAME`
    ever changes.
32. **🟡 `check_rule_producers.py:234`** — a fixture that parses to `None` is silently
    dropped from the "has fixture" check, restoring a false coverage claim.
33. **🟡 `check_rule_producers.py:252`** — diffs against `_REGISTRY` *post*-plugin-discovery;
    a legitimate third-party parser plugin hard-fails this repo's own gate.
34. **🟡 `coverage_gate.py:197`** — mutation-unsound at the exact-floor boundary
    (`pct == min_pct`); no test covers it.
35. **🔴 `tools/test_coverage_gate.py`** — not wired into `run_all_tests.sh`, CI, or the
    Makefile — the PR's own "test exists but nothing runs it" gap class, uncaught in
    itself.
36. **🟡 `tools/test_coverage_gate.py:62`** — mutation-unsound (deleting the `[WARN]` guard
    condition still passes).
37. **🟡 `ot_new_device_e2e.py:127`** — fixed `sleep(25)` with no polling; routinely too
    short on a cold CI runner.
38. **🟡 `ot_new_device_e2e.py:153`** — prints raw stderr (up to 400 chars) to CI logs on
    failure; if `OPENSEARCH_URL` carries inline basic-auth, credentials leak into public
    logs.
39. **🔵 `chaos_test.py:292`** — stale comment ("all 5 targets") now that `KILL_TARGETS` has
    6.

### Contracts/docs/infra (2🔴 2🟡)

40. **🔴 `alerts.json`** — `triage` field absent from `properties` under
    `"dynamic": "false"`; `list_alerts()`'s `triage.status` term filter silently matches
    zero docs on the OpenSearch backend (MemoryStore masks this in tests). *(Superseded and
    generalized by round-4 finding #WS3-1 below: the root cause is that `make_alert()`
    never sets a `triage` field at all — even with the mapping fixed, the filter still
    matches nothing.)*
41. **🔴 `ws7-dashboard/index.html:1536`** — nginx's OpenSearch-outage fallback returns
    HTTP 200 with empty hits; `getAlerts()` treats that as success, so a full backend
    outage shows a green "live" badge over an empty table.
42. **🟡 `index.html:1552`** — snapshot is recorded before `renderGlobal()` awaits; a throw
    inside render leaves that state permanently un-rerendered.
43. **🟡 `index.html:1553`** — on a mid-session LIVE→false transition, the table repaints
    with fabricated `SIEM_MOCK` data instead of showing empty — contradicts the file's own
    stated no-fabrication rule for `getEvents()`.

---

## ROUND 3 — repo-wide gap hunt (70 findings after 1 correction)

### ⚠️ Refuted finding (excluded from totals)

A round-3 agent reported `services/shared/authz.py`'s `require_auth_or_exit` as having zero
call sites repo-wide. **This is false** — no function by that name exists anywhere in the
codebase. The real function is `require_auth_or_die`, and it *is* called
(`ws3-indexer/main.py:211`, `ws6-inventory/app.py:219`). The agent appears to have misread
or hallucinated the function name. Do not act on this one.

### WS-8 correlation + WS-2 normalization core (1🔴 10🟡 5🔵)

1. **🔴 `ws8-correlation/correlator.py:267`** — `member_cap` truncates members *before*
   computing `tactics`, so a sustained attack past the cap silently freezes the incident
   doc while the attack continues. Reproduced with stock defaults: 1 recon alert + 400
   brute-force alerts → alerts #199-399 emit nothing.
2. **🟡 `correlator.py:254`** — `member_cap` bounds only the emitted payload, not
   `_sides[key]` memory — unbounded per-track growth (reproduced 401 side-table entries at
   `member_cap=200`).
3. **🟡 `correlator.py:277`** — `first_seen` computed over the truncated list; the same
   conceptual incident can emit under 3 different `incident_id`s as truncation shifts the
   minimum.
4. **🟡 `correlator.py:322`** — every WS-5-produced alert is a silent no-op in correlation:
   the contract lists WS-5 as an `alerts` producer, but its payload carries no
   `actor`/`src_endpoint`/`mitre`/`tenant_id`.
5. **🟡 `correlator.py:238`** — a missing `alert_id` stringifies to the literal `"None"`,
   deduping unrelated alerts against each other.
6. **🟡 `correlator.py:342`** — the `device:` track keys on an unauthenticated, spoofable
   hostname with no allowlist (unlike the other two legs).
7. **🟡 `correlator.py:190`** — no length cap on `entity_value`; past 512 bytes it becomes
   an OpenSearch document-id rejection, treated as permanent/dead-lettered — an
   attacker-suppressible incident.
8. **🔵 `test_contract.py:350`** — the `_last_incident` pruning branch for a *promoted*
   track is never exercised.
9. **🔵** — the truncation path (`member_cap`, `truncated`, severity cap) has zero test
   coverage.
10. **🔵 `correlator.py:322`** — `.get("user", {})` missing the `or {}` guard its sibling
    line has; a string `actor.user` raises `AttributeError`.
11. **🔵 `correlator.py:314`** — docstring says "0-2 incidents"; it actually returns up to
    3.
12. **🔵 `main.py:44`** — `RedisWindowCounter` uses WS-4's default namespace `"ws4:win"`
    instead of its own.
13. **🟡 `ws2-normalization/main.py:170`** — the daemon's `handler()` and the tested
    `run()` are parallel implementations that already diverge (dead-letter `key` set vs
    `None`).
14. **🟡 `main.py:173`** — a dropped/dead-lettered event is recorded as `"acked"` in
    metrics; no drop counter, no log line.
15. **🟡 `main.py:145`** — WS-2's dead-letter payload shape isn't requeueable;
    `tools/dlq_peek.py`'s requeue re-dead-letters it and reports success anyway.
16. **🟡 `enrichment/__init__.py:62`** — both enrichment failure paths swallow exceptions
    with no logging, and the prior fix for this exact class has no regression test.

### Docker/compose/CI infra (3🔴 confirmed + 1 refuted, 8🟡, 4🔵)

17. **🔴 `docker-compose.ha.yml`** — under `--profile ha`, ws7-dashboard's nginx hardcodes
    `opensearch:9200` but isn't on the `ha` network; DNS fails → 502 → nginx's own fallback
    returns HTTP 200 empty hits. Every HA deployment shows an empty/mock dashboard with
    nothing in any log.
18. **🔴 `infra/provision.sh:54`** — `curl ... && echo ok || echo skipped` defeats
    `set -eu`; a rejected index template prints "(skipped)" and the script exits 0 anyway.
    (Also flagged independently in round 4 with the additional detail that the template
    list is hardcoded, so a new mapping file is silently never provisioned.)
19. **🔴 `ci.yml:234`** — health gate reads `.State` not `.Health` — confirmed by the main
    thread directly reading the file. Every healthcheck in the whole stack is unenforced in
    CI. *(Round 4's test-runner-meta agent found this is actually worse than initially
    described — see round-4 finding #TR-1: the loop can never fail at all, in either
    direction.)*
20. **🟡 `docker-compose.yml`** — ws3-indexer has no persistent volume; its audit log and
    RBAC/session/TOTP DB both default into the container's writable layer, destroyed on
    every rebuild.
21. **🟡** — Redis healthcheck falls back to an unauthenticated ping if the authed one
    fails — an unauthenticated bus can report healthy.
22. **🟡 `docker-compose.ha.yml`** — all 3 Sentinel healthchecks are a bare `ping`; a
    Sentinel that can't see its primary/replicas still reports healthy.
23. **🟡** — redis-2/redis-3 have no healthcheck at all; Sentinel `depends_on` is
    start-order only.
24. **🟡** — ws6-inventory has no `/health` route and no compose healthcheck; its
    bus-consumer daemon thread can die while HTTP keeps answering.
25. **🟡** — ws7-dashboard has no healthcheck and starts as soon as ws6's container starts
    (no `condition:`).
26. **🟡 `ws7-dashboard/Dockerfile`** — COPYs the whole source dir then denylists 3 paths;
    `test_contract.py`/`test_fix_ux.py`/`INTERFACE.md` are served live at the container's
    web root; the denylist already drifted once (references a `nginx.conf` that no longer
    exists there).
27. **🟡** — base `docker-compose.yml` never sets `REDIS_PASSWORD` on app services (only
    `REDIS_URL`), while `ha.yml` does — `shared/authz.py`'s "Redis with no auth" check
    evaluates differently between the two files for the same actual auth state.
28. **🔵** — `REDIS_URL` interpolates the password unescaped; special characters silently
    mis-parse the URL.
29. **🔵 `scorecard.yml`** — uses `permissions: read-all` where every other workflow uses
    `contents: read`.
30. **🔵 `fuzz.yml`** — 17-target matrix is hand-maintained with no drift check, and has no
    `pull_request` trigger.
31. **🔵 `ws4-detection/engine.py`** — two fixed-depth path walks (allowlists dir,
    `validate_rules.py` probe) break under the real container layout; the poison-pill rule
    validator is a silent no-op in the built image (bounded impact — `Rule.__init__` still
    type-checks independently).

### Eval harness + contracts drift (3🔴 11🟡 5🔵)

32. **🔴 `tools/validate_rules.py`** — zero rules found (`RULES_DIR` empty/broken) still
    prints `[OK]` and exits 0. Verified by running against a bogus dir.
33. **🔴 `tools/validate_contract.py`** — same hole: zero fixtures still prints `PASS`,
    exit 0. Verified.
34. **🔴 `validate_rules.py`'s `siem:` block** — has no unknown-key check (confirmed by
    main thread directly reading the file) — `score_weigth`/`treshold` typos ship
    silently; verified live that `common_bruteforce.yml` with a typo'd threshold field
    becomes stateless and alerts on every failed login.
35. **🟡** — the outside-hours dead-window probe only catches "never matches", not
    "always matches" — verified a 1-minute window classified 1439/1440 minutes/day as
    outside-hours and passed clean.
36. **🟡** — the validator's condition tokenizer regex is a hand-copied duplicate of the
    engine's, not imported — can silently drift from what the runtime actually parses.
37. **🟡** — `category_uid == class_uid // 1000` invariant is documented but never
    enforced by `validate_contract.py`.
38. **🟡 `eval/attack/test_coverage_layer.py:41`** — literal `... or True` makes the check
    unconditionally pass. Same "negative assertion that can't fail" class this repo's own
    docs warn about.
39. **🟡** — the MITRE-coverage firing gate only scopes rules that declare an (optional)
    `mitre:` block — a rule can opt out of positive/boundary/near-miss testing just by
    omitting one optional field.
40. **🟡 `eval/report_generator/run_eval.py`** — no floor on scenario count; an empty
    scenario list prints "[OK] all 0 drafts pass" and exits 0, contradicting the module's
    own "≥10 synthetic incidents" doc claim.
41. **🟡** — same file — the "no dropped fact" checklist item is vacuous for any scenario
    whose alert is missing that field (one shipped scenario already is).
42. **🟡 `contracts/nis2-de-schema.json`** — declares 5 required keys; the actual report
    generator produces none of them. Nothing validates against this file at all.
43. **🟡 `nis2_template.py`** — silently coerces an invalid `stage`/`lang` query param to a
    default instead of rejecting it — a typo'd stage returns a 200 with the wrong
    statutory deadline text.
44. **🟡 `contracts/triage-api.yaml`** — doesn't declare the `template`/`stage`/`lang`
    query params that the report route actually reads (a separate markdown doc does).
45. **🟡** — `contracts/triage-api.yaml` never mentions CSRF at all, despite every POST
    requiring it — a client built strictly from this spec can't perform a single write.
46. **🟡 `contracts/inventory-api.yaml`** — documents no auth scheme whatsoever, though the
    service requires an API key.
47. **🔵** — rule filenames: 13 of 28 violate the documented `<sector>_<name>.yml`
    convention; validator doesn't check it.
48. **🔵 `detection-coverage.md`** — "update every PR" claim is unenforced (currently
    accurate, but only by discipline).
49. **🔵 `triage-api.yaml`** — documents a 400 on over-limit `limit`, but the code silently
    clamps instead.

### shared/ modules — bus.py, outbound_http.py, log.py, and others (2🔴 11🟡 7🔵)

50. **🔴 `bus.py`** — `_MemoryBus.consume()` completely ignores `group=`; one deque per
    topic, no per-group cursor. Verified live: the real 3-way `alerts` fan-out
    (`cg-index`/`cg-webhook`/`cg-correlate`) delivers to only the first group to read, on
    the exact backend every test and zero-infra dev run uses.
51. **🔴 `bus.py`** — `_RedisSentinelBus` silently falls back to a plain non-HA bus
    (pinned to `REDIS_URL`) whenever Sentinel host discovery fails to initialize; zero
    failover, zero signal.
52. **🟡** — `_MemoryBus.ack()` also ignores `group` — one group's ack cancels another
    group's redelivery.
53. **🟡** — `_MemoryBus.depth()`/`lag()` exclude the PEL entirely — verified 5 unacked
    messages report `lag=0`.
54. **🟡** — `_MemoryBus`'s PEL has no cap/eviction; `ws3-indexer/main.py`'s `run()` never
    acks, so it leaks every message it ever indexed (and on Redis, pins the trim boundary
    forever).
55. **🟡** — a failed DLQ write inside `_decode_entry` skips the `xack` too — the poison
    entry is reclaimed forever, never actually quarantined.
56. **🟡** — `depth()`/`lag()`/`trim_acked()` on `_RedisBus` all return `0` on any
    exception — a Redis outage reads identically to "no backlog."
57. **🟡 `ws5-ai/llm_adapter.py`** — if `shared.outbound_http` fails to import, WS-5
    silently reverts to plain redirect-following `urlopen` (SSRF hardening disappears with
    no signal).
58. **🟡 `ws3-indexer/reporting.py`** — the security-report webhook POST has no
    `is_unsafe_target_url()`/scheme check, unlike the near-identical `webhooks.py` path.
59. **🟡 `shared/allowlist.py`** — WS-8 never calls `invalidate_dir()` (only WS-4 does); a
    fixed allowlist YAML has no effect on WS-8 until process restart, and the "fails
    closed" open-gate state persists silently.
60. **🟡 `shared/sessions.py`** — `RedisSessionStore.resolve()` never checks
    `expires_at`; expiry rests entirely on the Redis key TTL.
61. **🟡 `shared/window.py`** — `RedisWindowCounter.hit()` refreshes a redelivered
    member's timestamp (keeping its window open longer); `DequeWindowCounter` (what every
    test uses) explicitly doesn't — the two backends age differently under at-least-once
    redelivery.
62. **🟡 `shared/envelope.py`** — `default_tenant()`/`TENANT_ID` is never validated at the
    point of entry; downstream services already disagree on what to do with an invalid one.
63. **🔵** — Redis password interpolated into a URL unescaped.
64. **🔵** — `_RedisBus.consume` swallows `TimeoutError`; a misconfigured `socket_timeout`
    would silently stop all consumption forever (not currently reachable).
65. **🔵** — `outbound_http.py`'s global opener install is process-global, silently
    reversible, and untested as actually-installed in a running service.
66. **🔵 `log.py`** — setting `FENGARDE_LOG_LEVEL=error` would silence the one log line
    that reports an allowlist failing to load.
67. **🔵 `log.py`** — a caller-supplied field can silently overwrite reserved keys; no
    current caller does.
68. **🔵 `fairness.py`** — `consume()` forwards `block_ms=0` explicitly, overriding the
    bus's own 5000ms default — means "block forever" on Redis.
69. **🔵 `sanitize.py`** — control-character strip misses C1 controls and the Unicode
    RTL-override character (`U+202E`) — a real display-spoofing vector.
70. **🔵 `window.py`** — a shared internal dict between `hit()` and `hit_distinct()` would
    leak a key permanently if a rule ever used both modes (currently unreachable).

---

## ROUND 4 — extensive gap hunt (143 findings)

### WS-3 indexer remaining modules — triage_api, router, rules_view, storage/*, audit, nis2_template (3🔴 5🟡 4🔵)

1. **🔴 `storage/opensearch.py:480`** — `list_alerts` filters on `{"term":
   {"triage.status": status}}`, but `ws4-detection/main.py::make_alert()` never writes a
   `triage` field at all (confirmed by main thread: zero hits for `"triage"` in that file),
   and `alerts.json` is `"dynamic": "false"`. **`GET /api/v1/alerts?status=new` returns
   zero results, always, on the only backend that ships to production.**
   `MemoryStore.list_alerts` explicitly defaults a missing triage to `"new"`, which is why
   the offline test suite is green while OpenSearch silently violates the storage-adapter
   contract. Fix: express "default" as a `bool`/`should`/`must_not exists` query, or make
   WS-4 stamp `triage: {"status":"new",...}` on every alert at creation.
2. **🔴 `storage/opensearch.py:463`** — every read path (`_list`, `count`,
   `_search_alert`, `find_report`) swallows `HTTPError` — including 5xx — into an
   empty/`None` result, with zero log statements anywhere in the module. A red/recovering
   cluster or a circuit-breaker trip makes `GET /alerts` answer `200 {alerts:[],count:0}`
   and `POST /alerts/{id}/triage` answer `404 alert not found`. The write path deliberately
   gets this right (retries 5xx, re-raises 4xx) — the read-side asymmetry is unintentional.
   Fix: only swallow 404/400-class "index missing" cases; let 5xx propagate and log it.
3. **🔴 `triage_api.py:415`** — both HTTP dispatchers' catch-alls send a bare 500 with
   zero logging (`log_message` is a stubbed no-op). Reproduced concretely: a degenerate
   `SessionStore(ttl_s<=0)` causes `sessions.resolve(token)` to raise `AttributeError` on
   every login with no trace anywhere. Fix: log the exception with `exc_info=True` in both
   handlers before the 500; null-check `sessions.resolve()`.
4. **🟡 `reporting.py:38`** — the report cache key (`report_id`) is stable, but the index
   it's written to (`reports-%Y.%m.%d`) is daily; regenerating a report across a day
   boundary can silently return yesterday's stale draft on the next GET (both backends'
   "pick one" logic is unsorted/arbitrary). Verified: reproduced returning the old draft.
5. **🟡 `audit.py:201`** — `_read_all_locked` swallows `OSError` into `[]` with no warning
   (unlike its sibling append/trim methods, which do warn). A broken audit mount makes
   `GET /audit` answer `200 {entries:[]}` — indistinguishable from "nothing happened."
6. **🟡 `audit.py:153`** — trim is guarded only by an in-process `Lock`; two WS-3 replicas
   sharing the audit file volume (a documented supported topology) can silently discard
   each other's appends during a trim window.
7. **🟡 `rules_view.py:41`** — the regression test written specifically to catch "GET
   /rules returns zero rules under the container path layout" is mutation-unsound: main
   thread's agent reverted the fix to its pre-fix body and the whole suite stayed green,
   because the host-checkout branch is satisfied either way — the actual container branch
   is never exercised by any test.
8. **🟡 `triage_api.py:370`** — the `X-Forwarded-For` rate-limit branch has zero coverage;
   deleting it entirely (`pass` instead of the real logic) leaves all 8 ws3 HTTP/auth
   suites green, despite the docstring claiming 429 enforcement under the documented nginx
   topology.
9. **🟡 `storage/memory.py:147`** — same divergence class as #1 for tenant scoping:
   MemoryStore defaults a missing `tenant_id` to `"default"`; OpenSearch's term query
   can't match a missing field, so a `tenant_id=None` alert is readable by direct ID but
   invisible in list views on the production backend.
10. **🔵 `audit.py:123`** — `recent(0)` returns the *entire* log instead of nothing
    (`entries[-0:]` is `entries[0:]`). Currently unreachable over HTTP.
11. **🔵 `triage_api.py:836`** — oversized report-request bodies are silently accepted
    instead of rejected (the sibling triage route does reject); also both `close_connection`
    guards are dead code since the handler never negotiates HTTP/1.1 keep-alive.
12. **🔵 `storage/opensearch.py:370`** — `_search_alert` uses `size:1` with no sort; if the
    same `alert_id` ever exists in two daily indices (reachable when `time` is absent), the
    triage CAS read-modify-write can silently operate on the stale copy.

### WS-4 detection main.py + scoring (2🔴 9🟡 7🔵)

13. **🔴 `main.py:345`** — the AI-triage funnel's dedup (`Scorer.should_enqueue_llm`)
    commits its cooldown state *before* the `bus.produce("ai.requests", ...)` it guards
    runs. If that produce raises, the message is redelivered but the cooldown key is
    already set, so the redelivery silently skips re-enqueueing forever. Reproduced live: 2
    alerts produced, 0 `ai.requests`, no exception, no log, no metric — an alert is indexed
    and shown to the analyst but permanently never triaged. Fix: split check-from-record;
    only record the cooldown after `bus.produce` returns successfully.
14. **🔴 `contracts/scoring.yaml:21`** — a missing/renamed/typo'd `severity_floor` key (or
    a typo'd rule `level`) silently yields floor 0 with CI green — proven by deleting
    `severity_floor.critical` and constructing `Scorer` with no error; the only "test" is
    a bare constructor call. A critical rule then drops from score 80 to 0 and routes
    `store` instead of `llm`. Fix: raise in `Scorer.__init__` unless the floor dict's keys
    exactly match the 5 defined levels; warn-once on an unknown level at score time.
15. **🟡 `main.py:110`** — `rule_health_metrics()` only emits a series for rules that have
    *already* fired at least once — a rule that never fires (broken condition, dead
    bucket, accidentally disabled) is invisible to the exact Grafana panel
    (`rule_last_fired_timestamp`) built to catch that. Proven: a fresh Detector with 28
    rules returns `{}`.
16. **🟡 `main.py:240`** — rule-reload fingerprinting uses only the *maximum* mtime across
    all rule files; deleting (or restoring) a non-newest file never changes the max, so the
    watcher never reloads. Proven with two files, deleting the older one.
17. **🟡 `main.py:277`** — a truncated/zero-byte rule file reloads as a logged **success**
    with a silently reduced rule set (`load_rules`'s `if raw:` guard skips falsy/empty
    parsed YAML with no error). Proven: a directory with one zero-byte `.yml` loads `[]`.
18. **🟡 `scoring.py:41`** — `_recent_llm_enqueues` is documented as "bounded: ~1000
    entries" but isn't — proven growing to 5000 entries under load with no eviction, and
    the O(n) prune dict-rebuild then runs on every subsequent event.
19. **🟡 `main.py:306`** — `make_alert()` never copies `dst_endpoint`, though 6 shipped
    rules (`common_port_scan`, `common_lateral_movement`, `common_beaconing`,
    `common_dns_exfil`, `bank_db_priv_esc`, `ot_modbus_unauthorized_write`) key their
    entire detection on the destination — those alerts reach analysts with no destination
    field at all, and `alerts.json` has no mapping for it either.
20. **🟡 `contracts/opensearch-mappings/alerts.json:8`** — `classification` (the entire
    output of WS-5's cheap classifier tier) is unmapped under `dynamic:false` — it lands in
    `_source` unindexed and unsearchable in production.
21. **🟡 `main.py:463`** — the depth watchdog covers `scored.events` and `ai.requests` but
    not `alerts` itself — WS-4's highest-value output topic has no backlog alarm anywhere.
22. **🟡 `main.py:319`** — the production code path `detect_one` has exactly one test
    caller in the entire repo; every e2e/eval/bench harness (`demo_e2e.py`,
    `integration_e2e.py`, `demo_nis2.py`, `fengarde_bench.py`, `evtx_eval.py`) drives a
    parallel duplicated implementation (`run()`) instead. A divergence in the daemon path
    produces no signal from any acceptance test.
23. **🟡 `main.py:353`** — the `scored`/`alerts`/`ai_enqueued`/`classifier_enqueued`
    counters exist only in the unused `run()` path — the production daemon exposes none of
    them, which is exactly why finding #13 above is undetectable in production.
24. **🔵 `scoring.yaml:3`** — `version` key is read by nothing (grepped repo-wide).
25. **🔵 `scoring.yaml:38`** — `clamp.min` never actually binds (inputs are pre-validated
    non-negative) and isn't applied on the no-match (`score([])==0`) path.
26. **🔵 `main.py:194`** — torn read of the rule bucket index across a live reload
    (`self._by_class_uid` read twice while `reload()` swaps it in two separate statements)
    — currently harmless only because no shipped rule uses the catch-all bucket.
27. **🔵 `main.py:346`** — the `ingest_id` fallback (`event["siem"].get("ingest_id", key)`)
    only fires on absence, not on `None`/empty — a present-but-null id collapses multiple
    WS-5 triage docs onto one OpenSearch id (`"ai-None"`).
28. **🔵 `main.py:296`** — inconsistent `event.get("siem", {})` vs the defensive
    `(event.get("siem") or {})` idiom used everywhere else; a `siem: null` event raises and
    becomes a poison-pill redelivery loop instead of failing closed.
29. **🔵 `main.py:315`** — `event_ids` truncates at 50 with no marker distinguishing "that's
    all there was" from "truncated," against 365-day alert retention vs 30-day event
    retention.
30. **🔵 `main.py:251`** — `start_rule_reload_watcher`'s directory parameters are silently
    ignored (`_load()` reads module globals instead) — masked in tests only because the
    one test that uses custom dirs also monkeypatches the globals.

### WS-5 llm_adapter.py core logic (0🔴 7🟡 5🔵)

31. **🟡 `llm_adapter.py:204-212`** — a non-JSON Ollama response is caught internally and
    returned as `{verdict:"unknown", level:"low", engine:"ollama"}` — `FallbackLLM`'s stub
    degradation never runs, and the counters treat this as a normal ollama success. A model
    that has never once produced valid JSON is indistinguishable from a healthy one.
32. **🟡 `llm_adapter.py:133-134`** — an out-of-enum verdict/level is coerced to
    `unknown`/`low` with no log and no counter at all (quieter than the finding above).
33. **🟡 `llm_adapter.py:174,197`** — the 8s timeout is the only thing preventing a hung
    Ollama call from blocking WS-5's single worker thread indefinitely, and deleting it
    fails no test (every test mocks urlopen and ignores kwargs). It's also per-socket-read,
    not a total deadline — a dribbling response stays alive indefinitely while `/health`
    stays green.
34. **🟡 `llm_adapter.py:185-186`** — prompt truncation (event to 4000 chars, reasons to
    2000) is silent — no marker, no log — so an attacker padding a captured field can push
    real indicators past the cap with nothing recording it happened.
35. **🟡 mutation-unsound (verified by execution)** — bypassing the SSRF-hardening
    indirection entirely, removing the response-size cap, and removing both prompt
    truncation caps all survive the complete llm_adapter/main test suite. The "hardening"
    is real code with zero enforcing coverage.
36. **🟡 `main.py:134,153`** — the `dict(cached)`/`dict(result)` defensive copies against
    cache-corruption-by-reference have zero coverage (verified: removing both survives all
    tests, since the existing check uses value equality, which an alias also satisfies).
37. **🔵 `llm_adapter.py:125-126`** — a non-dict (but valid) JSON response discards the
    model's actual output with no log at all.
38. **🔵 `llm_adapter.py:250-257`** — Ollama reachability is probed once at boot; if it's
    down at that instant, or the configured model was never pulled, the process is pinned
    to the stub forever with one boot-time warning and no re-probe.
39. **🔵 `main.py:103-104`** — the dedup key's documented two-level fallback
    (`event_id` then `ingest_id`) is untested — every fixture sets them equal.
40. **🔵 `main.py:175`** — `alert_id = f"ai-{result['event_id']}"` lacks the `or "unknown"`
    guard its sibling lines have — an id-less request collapses onto `"ai-None"` (currently
    unreachable via the real WS-2→WS-4 path, which always assigns a uuid).

### WS-6 inventory app.py + keystore (2🔴 6🟡 1🔵)

41. **🔴 `bus_consumer.py:52-69`** — a transient `bus.produce` failure permanently loses a
    new-device alert, and the redelivery reports success. `upsert_with_diff` commits the
    asset row *before* the produce; if produce raises, the message is unacked, but on
    redelivery the device now exists in the DB so `is_new_device` is False and the message
    acks clean. Reproduced: 2 deliveries, first produce raising → 0 messages ever published
    on `raw.events`. The existing test asserts this exact loss-causing behavior as correct
    ("a repeat sighting doesn't republish") without recognizing a redelivery *is* a repeat
    sighting.
42. **🔴 `app.py:114-115, 177-178`** — both request dispatchers catch every exception and
    return a bare 500 with zero logging (`log_message` is a no-op too). A corrupt DB, an
    unwritable volume, or a `database is locked` stall becomes a silent 500 loop with
    nothing in any log.
43. **🟡 `app.py:78-79, 96-98`** — failed API-key attempts produce zero telemetry and are
    not rate-limited at all, unlike the near-identical WS-3 surface which already has this.
44. **🟡 `store.py:78-111, 294-307`** — `INVENTORY_BASELINE_SECONDS` is baked into a
    tenant's `baseline_until` at first sighting and permanently ignored after, contradicting
    the docstring's explicit claim of being "read per call ... without rebuilding the
    store." Proven: changing the env var between two boots against the same DB has no
    effect.
45. **🟡 `store.py:135-136, app.py:137-139`** — `_normalize_seen_at` accepts any non-empty
    string with no ISO validation; a corrupt stored value later makes `/assets/resolve`
    return a 400 blaming the *caller's* well-formed `?at=` parameter instead of the stored
    garbage.
46. **🟡 `store.py:167-174, 419-434`** — `ip_history`/`protocols` grow without bound and
    are inlined in full on every read, with no pruning, cap, or metric. Proven: 500
    observations of one MAC produced a 50KB single-asset response.
47. **🟡 `store.py:275, app.py:196-206`** — no length/format validation on `mac`,
    `hostname`, or `protocol` on the upsert path — proven a 100,000-character `mac` is
    accepted as a primary key.
48. **🟡 `bus_consumer.py:83-92`** — WS-6 computes its own failure counters
    (`mark_error`/`bus_error`/`failed`/`deadlettered`) via `runner.serve` but passes
    `health_port=None`, so nothing ever reads them — the only bus consumer in the repo that
    throws its own computed health signal away.
49. **🔵 `app.py:34-37`** — `InventoryStore` and `TenantKeyStore` default to the same
    SQLite file but hold independent uncoordinated locks — realistic worst case is a stall
    up to the busy-timeout, landing in the un-logged 500 path above.

### WS-7 dashboard full deep pass (4🔴 12🟡 4🔵)

50. **🔴 `index.html:1236-1247`** — both triage-update call sites discard the result of
    `updateTriage`, which returns `null` on any failure (401/403/network error) — an
    analyst's saved triage decision silently reverts to `new` on the next reload with no
    warning ever shown.
51. **🔴 `index.html:1155`** — `renderGlobal` reads `window.SIEM_MOCK.assets`
    unconditionally — the Overview's "Active devices" card and its ratio bar are the
    hardcoded mock hosts on every deployment, rendered inches from the "live data" badge.
    The real `getAssets()` path exists and is used only by the separate Inventory tab.
52. **🔴 `templates/default.conf.template:198-217` (+224-238, 245-255, 284-294)** — these
    nginx locations *inject* `X-Api-Key` server-side rather than requiring it from the
    caller. With RBAC off (the documented default), `_require_role` is a no-op and the
    injected key satisfies `_check_auth` — anyone reaching port 8080 can POST triage
    decisions (no CSRF check applies when RBAC is off) and GET the entire admin audit log.
    Setting `FENGARDE_API_KEY` protects nothing on these five routes, and the audit trail
    even records the actor as `api_key`, so it doesn't look anomalous.
53. **🔴 `index.html:802,849,876,1394` vs `default.conf.template`** — the dashboard's own
    JS never sends `X-Api-Key` on any request at all (confirmed by grep — the string
    appears only in the nginx template). So setting that key to *harden* a deployment
    401s the browser on every real data call, and every caller renders that identically to
    "no data" — hardening the deployment silently blinds the SOC.
54. **🟡 `index.html:1050-1057`** — `fetchTriage` returns a default `{status:"new"}` on any
    failure, rendering identically to a real `new` — with the triage API down, every
    already-closed alert redisplays as untriaged.
55. **🟡 `index.html:779-785,2017`** — `getAssets` never checks `r.ok`; a 401/500 JSON
    error body parses fine and is returned as the asset list, and the Inventory view has no
    `.catch`, so the resulting unhandled rejection permanently empties the table.
56. **🟡 `index.html:2016-2024`** — only the Overview tab polls; every other tab (Inventory,
    Sources, Coverage, Incidents, Events, Ops, Audit, Keys) renders once at boot and never
    refreshes, despite copy promising live `/metrics` data.
57. **🟡 `index.html:1385-1391`** — the "Service health" Ops view covers only 5 of 8
    workstreams — WS-5 (AI triage) has no proxy or entry at all, so WS-5 dying leaves the
    Ops page fully green.
58. **🟡 `index.html:2029-2037`** — a range-picker change races an in-flight `renderGlobal`
    with no mutex — two concurrent DOM writers, and the stale one can land last and get
    recorded as the current snapshot.
59. **🟡 `index.html:1558-1563`** — the poll-dedup snapshot doesn't include triage status
    despite the adjacent comment claiming it does — a second analyst's triage change is
    invisible until the underlying alert set itself changes.
60. **🟡 `index.html:1926-1948`** — an active alert filter isn't re-applied after the
    10-second full-table repaint — the UI still shows "Critical" selected while displaying
    the unfiltered table.
61. **🟡 `index.html:1994-2000`** — the playbook-enrichment cache is pinned permanently
    empty if its first warm-up fetch fails, even after the underlying API recovers.
62. **🟡 `index.html:1485-1490,1510`** — every non-200 audit response (502/500/401) is
    rendered identically to "no entries — not an admin" — an outage is presented as a
    permissions fact.
63. **🟡 `templates/default.conf.template:267-276`** — `/api/inventory/` is proxied with no
    auth check and no method restriction at all — with the keystore empty (the documented
    zero-config default), any anonymous POST can write arbitrary inventory assets that WS-2
    enrichment consults.
64. **🟡 `templates/default.conf.template:44-56`** — no security headers at all (no CSP,
    X-Frame-Options, nosniff, Referrer-Policy) on a page that renders attacker-influenced
    log fields via `innerHTML`.
65. **🔵 `index.html:1591`** — `getAlerts()` mutates a shared global (`LIVE`) as a side
    effect, racing a concurrent caller — the live-badge and the data table can disagree.
66. **🔵 `index.html:1407`** — one metrics value is interpolated into `innerHTML` without
    the file's own `esc()` helper (low reachability — requires a compromised workstream).
67. **🔵 `index.html:1834,1838`** — two label lookup functions have an unescaped fallback
    branch, currently unreachable except via `Object.prototype` key collisions.
68. **🔵 `templates/default.conf.template`** — ws3's port is hardcoded in 4 places despite
    the file being an envsubst template elsewhere; a port change 502s silently with no
    `error_page`.
69. **🟡 `test_contract.py:26-33`, `test_fix_ux.py:37-85`** — both WS-7 tests are substring
    greps over the raw HTML with no JS engine and no DOM — every finding above ships with a
    green gate, and a plain JavaScript syntax error would too.

### WS-1 main.py/spool/Dockerfile full (4🔴 4🟡 4🔵)

70. **🔴 `main.py:199`** — `serve({}, ...)` passes an **empty** handler map, so zero
    `_topic_worker` threads ever start, and `HealthState.bus_ok` is only ever flipped by
    those workers. **WS-1's `/health` is a hardcoded 200 forever** — Redis unreachable, UDP
    bind failed, both — all still green, contradicting a comment in
    `docker-compose.yml:115-116` that explicitly claims the opposite behavior was shipped.
71. **🔴 `main.py:166-193` + `shared/runner.py:166-171`** — `/metrics/prom` renders zero
    WS-1 gauges at all: `render_prometheus` only emits top-level numeric leaves, but
    `_syslog_metrics()` nests everything one level under `"syslog_udp"` — every ingest-edge
    counter this session's own hardening passes added is invisible to Prometheus scraping,
    with the scrape looking structurally valid and simply empty.
72. **🔴 `collectors/syslog_udp_server.py:599-621`** — graceful `stop()` clears `_running`
    before workers drain the queue, discarding every still-queued datagram in **no counter
    at all**. Reproduced: 200 sent, `stop()` mid-load → all counters read 0 dropped/lost/
    shed, 170 events silently gone. Up to `DEFAULT_QUEUE_MAXSIZE=20000` events can vanish on
    every graceful restart under load.
73. **🔴 `collectors/spool.py:194-202`** — `drain_into`'s remainder math assumes every
    snapshot line ends in `\n`; a torn write (the exact scenario the function's own
    docstring says it handles) breaks that assumption and can silently delete both the
    partial record *and* a concurrently-appended live event with no exception and no log.
    Reproduced: spool ends up empty (`b''`) after a drain that reported success.
74. **🟡 `spool.py:179-186`** — a corrupt/torn spool line is discarded with a bare
    `continue` — no counter, no log — and the caller's own success log line reads as a
    fully clean replay.
75. **🟡 `spool.py:99-100,110-111`** — three distinct spool-write failure classes (byte
    cap, disk-headroom refusal, generic OSError) collapse into one silent `return False`
    with the diagnostic detail discarded — an operator raising the byte cap in response
    fixes nothing if the real cause was a permissions/mount error.
76. **🟡 `syslog_udp_server.py:545-547`** — `events_queue_full` is incremented and never
    logged, never alerted on, never reaches the dashboard, and (per finding #71) never
    reaches Prometheus either.
77. **🟡 `syslog_udp_server.py:417-420`** — the bus-produce-failure log path has no
    throttle (unlike the shed-path right below it, which is explicitly throttled for
    exactly this reason) — a Redis outage at the configured event rate can produce
    thousands of log lines/sec, burying every other signal including the silence
    watchdog's warning.
78. **🔵 `spool.py:205-219`** — the "crash mid-rewrite never corrupts the spool" docstring
    claim has no `fsync` anywhere in the module — `os.replace` is atomic for the name, not
    the data; a power-loss event can leave an empty spool with the backlog gone.
79. **🔵 `syslog_udp_server.py:531-535`** — a persistent (non-close) socket `OSError` in
    the recv loop is silently retried with no counter, no log, and no backoff — can become
    an unbounded tight loop pegging a core.
80. **🔵 `syslog_udp_server.py:353,542,558`** — the silence watchdog uses wall-clock time;
    an NTP step backward or a VM suspend/resume can make the elapsed-silence calculation
    negative, silently disabling the watchdog during the exact kind of event most likely to
    accompany a real outage.
81. **🔵 `syslog_udp_server.py:381-384`** — an empty/CRLF-only datagram increments
    `events_dropped`, which is documented as meaning "bus produce failed" — a flood of
    empty datagrams reads on `/metrics` as a Redis outage when the bus is healthy.

*(WS-1 Dockerfile: checked and clean — no module-resolution bug of the class already found
once in WS-3's image.)*

### Docs vs code drift (2🔴 8🟡 6🔵)

82. **🔴 `docs/index.html:286`** — advertises "Syslog UDP, SNMP, NetFlow → raw.events" as
    a working Collect stage; SNMP/NetFlow collectors are mock-JSON skeletons with **no
    WS-2 parser at all** — every such payload silently dead-letters. `README.md` correctly
    lists both as "🚧 Planned" — the two docs contradict each other.
83. **🔴 `docs/index.html:315,504`** — claims "0 fabricated percentages" / "every number
    came back from a real HTTP request." The Overview dashboard's "Active devices" card
    (see WS-7 finding #51) is 100% mock data on every deployment — the round-4 fix for a
    related bug only patched the separate Inventory tab, not this one.
84. **🟡 `SSOT.md:106` (+ README/SECURITY mirrors)** — "Proven live" claim for CAS/OCC
    triage-preservation only covers the storage layer; this session found the batch
    (`bulk_index`, i.e. production) path bypassed it entirely (round-2 finding #25), and
    its own regression test wasn't wired into `run_all_tests.sh` until this session.
85. **🟡 `SSOT.md:119`** — the "PROVEN LIVE 2026-08-11" MFA e2e enumeration never included
    a replay attempt — the TOTP replay vulnerability (round-2 finding #1) lived in exactly
    the code this row claims was proven.
86. **🟡 `SSOT.md:128`** — `CHANGELOG.md` is labeled "authoritative for what shipped when"
    but is missing entries for at least 4 days of merged PRs and this session's own three
    commits.
87. **🟡 `SSOT.md:136`** — claims "7 files" for `services/*/INTERFACE.md`; there are 8 —
    `ws8-correlation/INTERFACE.md` is omitted from the enumeration and has never actually
    been re-verified despite carrying the row's trust label.
88. **🟡 `SECURITY.md:326`** — understates the WS-1 health gap: the real defect (round-4
    finding #70) is that `/health` never probes anything at all, not merely "probed the
    bus" as currently worded — and the same false "reports 503" claim is duplicated in
    `docker-compose.yml`.
89. **🟡 `docs/index.html:421`** — claims the audit trail is "gated to admins by session
    role, not by hiding a button" — true only with RBAC enabled; on the documented default
    demo config (RBAC off), the full audit log is reachable by anyone hitting the port
    (compounds WS-7 finding #52).
90. **🟡 `docs/adding-a-parser.md:71-79`** — the copy-paste walkthrough example omits
    `meta=`/`sector=` from its `base_event()` call, though every one of the 17 shipped
    parsers passes them — a parser written exactly from this doc silently breaks
    multi-tenancy trace/tenant propagation with no test catching it.
91. **🟡 `index.html:1161,1211` (WS-7)** — the "mock data" fallback badge/copy names a
    behavior (showing mock alerts) that this session's own fix already removed (now shows
    empty instead) — the UI's own error copy is stale relative to its recent fix.
92. **🔵 `README.md:130`** — the "27 MITRE-tagged rules, all boundary-verified" claim is
    true but silently excludes the 28th (stateful, untagged) rule from any boundary
    verification at all.
93. **🔵 `docs/index.html:292`** — "28 rules, MITRE-tagged" reads as all 28; actually 27 of
    28 (the page's own Coverage caption elsewhere correctly says 96%).
94. **🔵 `docs/index.html:280`** — "every arrow is a real Redis Streams topic" — the
    Console and Inventory-read stages are HTTP-via-nginx, a deliberate documented exception
    elsewhere that this page's caption omits.
95. **🔵 `docs/adding-a-parser.md:27`** — heading says "the three edits" but the doc
    actually walks through four.
96. **🔵 `docs/adding-a-parser.md:107` / `CONTRIBUTING.md:64`** — a hardcoded line-number
    reference (`_REGISTRY`, "around line 33") is already off by one and will keep rotting.
97. **🔵 `SECURITY.md:46`** — lists 3 of the 7 loopback-bound ports as "bound to
    127.0.0.1," implying the other listed ports aren't, when they are.

### tools/ remaining scripts (5🔴 11🟡 5🔵)

98. **🔴 `tools/integration_e2e.py:68`** — the pipeline's own smoke test asserts "at least
    1 event survived" and prints `[OK] end-to-end pipeline composes` — **live-verified
    dropping 89% of events**: WS-1's mock corpus includes SNMP/NetFlow (no parser exists at
    all) and RFC 5424 syslog lines that `generic_syslog` silently dead-letters because it
    only matches RFC 3164 headers. Only 1 of 9 seeded events survives, and the test still
    passes.
99. **🔴 `tools/chaos_test.py:266`** — `verify()` declares PASS on the first clean poll
    (~30s in), but Redis's `claim_idle_ms` for stalled-worker redelivery is 60000ms with no
    compose override — the "zero duplicate alerts" half of the chaos gate is evaluated
    before redelivery could possibly have occurred yet. A pipeline that duplicates on
    redelivery would still print PASS.
100. **🔴 `tools/chaos_test.py:194`** — both `docker compose kill` and `...start` run with
     `check=False` and their return codes are never inspected — a renamed service, wrong
     compose file, or a Docker error silently makes every kill a no-op while the run still
     prints "6 services killed mid-replay ... PASS." (Currently latent — names match today.)
101. **🔴 `tools/backup.py:83`** — an explicitly-given `--rbac-db` path that doesn't exist
     is silently skipped rather than failing — verified live: exit 0, an archive containing
     only an empty manifest, with no indication in the output that anything was missing.
102. **🔴 `contracts/opensearch-mappings/alerts.json` + `tools/migrate_opensearch.py:95`**
     — this branch's own `triage.{status,note,updated_at}` mapping addition doesn't bump
     `mapping_version` (still 5); `plan()` decides purely on that integer, so it will emit
     `action:"skip"` and this fix will **never actually reach a live/upgraded cluster**.
103. **🟡 `tools/chaos_test.py:213`** — the event replay (~5s) finishes long before the
     kill loop (~25s across 6 targets), so only the first two kills overlap any live
     traffic — the majority of the 6 targeted kills exercise an already-drained pipeline.
104. **🟡 `tools/detection_quality_eval.py:38`** — the macro-F1≥0.5 gate over 4 rules can't
     go red if only one rule silently dies (verified: zeroing one perfect rule's F1 still
     leaves the macro average above the floor).
105. **🟡 `tools/demo_e2e.py:105`** — the WS-5 triage stage's output is computed and
     printed but never asserted — verified removing WS-5's run from the script entirely
     still yields a clean `[OK]` acceptance-test pass.
106. **🟡 `tools/fengarde_bench.py:238`** — the one place that runs both the bucket-index
     and forced-linear-scan detection paths on identical input discards the count
     comparison and only compares timing — a bucket-index bug that silently drops rule
     matches would show up as a *bigger speedup* and get reported as a win.
107. **🟡 `tools/fengarde_bench.py:226`** — the published throughput number (`sustained_eps`)
     has no sanity floor tied to what was actually processed — a run where every parse fails
     still prints a large EPS figure and exits 0.
108. **🟡 `tools/fengarde_bench_live.py:176`** — the module's own documented per-invocation
     random ingest-id tagging isn't applied to the SSH-burst generator, so two runs within
     the window-counter TTL collide and get silently suppressed as duplicates, degrading
     silently to `p50/p99: None` with exit 0.
109. **🟡 `tools/fengarde_bench_live.py:289`** — `main()` returns 0 unconditionally, so a
     backlog that never drained (`reached_target=False`) is indistinguishable from a clean
     run to any scripted caller.
110. **🟡 `tools/restore.py:98`** — an archive whose manifest has an empty/absent `files`
     list restores nothing and reports success — verified as the natural second half of
     finding #101's empty backup.
111. **🟡 `tools/chaos_failover_test.py:96` / `tools/sentinel_failover_live.py:119`** — a
     `[SKIP]` result after `docker kill` has already run against the primary is treated as
     success — but a post-kill "master never moved" IS Sentinel failing to promote, the
     exact HA property under test.
112. **🟡 `tools/import_sigma_rules.py:425`** — a lossy Sigma import that narrows the
     imported rule's semantics writes the file and returns exit 0 regardless, with the loss
     reported only as a `[WARN]` on stdout that a batch-import loop would never see.
113. **🔵 `tools/chaos_test.py:256`** — `lost`/`duplicated` are pre-initialized to `[]`;
     a misconfigured zero/negative drain timeout would report PASS having queried
     OpenSearch zero times.
114. **🔵 `tools/chaos_test.py:128`** — `Scenario.alert_id` is declared and never
     assigned/read — the documented deterministic-alert-id check doesn't actually exist.
115. **🔵 `tools/test_mutmut_window.py:77`** — a test named for "key reclamation" asserts
     the opposite of its name and the actual reclamation branch is unreachable — untested.
116. **🔵 `tools/test_mutmut_window.py:149`** — the Redis `EXPIRE` call (the "quiet groups
     self-delete" guard) has zero coverage — a fake pipe records the call without ever
     honoring it.
117. **🔵 `tools/generate_sbom.py:53`** — a renamed/missing requirements file is silently
     dropped from the SBOM, and the `--check` comparison passes because both sides omit it
     identically.

### Test-runner meta layer — run_all_tests.sh / Makefile / preflight.sh / ci.yml structure (2🔴 5🟡 5🔵)

118. **🔴 `.github/workflows/ci.yml:234`** — the "wait for stack to report healthy" loop
     can **never fail in either direction**: `docker compose ps` without `-a` lists only
     RUNNING containers, so `grep -cv '^running$'` matches nothing whether the stack is
     fully healthy or fully crashed — both cases print "stack running" on iteration 1. The
     60-iteration retry loop is dead code.
119. **🔴 `tools/ot_new_device_e2e.py:106`** — `_env()`'s subprocess helper discards the
     return code, so a `docker exec` against a stopped container returns empty string,
     which matches the deliberate skip condition and returns exit 0 — a fully-crashed stack
     (per finding #118) makes this e2e job pass by silently skipping, proving nothing.
120. **🟡 `tools/backpressure_load_test.py`** — a 4th orphaned test found by systematic
     enumeration: 268 lines with real pass/fail assertions, reachable by no make target, no
     CI job, nothing — it's the sole automation behind SSOT.md's backpressure claim.
121. **🟡 `.github/workflows/ci.yml:292` / `Makefile:151`** — `mutmut run || true` is the
     *only* execution path for two real test files (`test_mutmut_shared.py`,
     `test_mutmut_window.py`, 317 combined lines) — the `|| true` is correctly justified
     for the mutation score, but it also swallows a genuinely broken baseline with zero CI
     signal.
122. **🟡 `ci.yml:145`** — 5 live-backend test files print `[SKIP]` and exit 0 when the
     backend is unreachable; nothing in either integration job asserts the run wasn't a
     silent skip, so a wrong/typo'd connection URL turns both jobs green while testing
     nothing.
123. **🟡** — no gate anywhere enforces that a new `test_*.py` file is reachable from
     `run_all_tests.sh`/CI/Makefile — this exact pattern has now produced 4 confirmed
     orphaned test files across this session alone.
124. **🔵 `Makefile:61`** — `make up` has no `preflight` prerequisite while `make demo`
     does, despite both docs and the Makefile's own help text describing preflight as
     "required before first run."
125. **🔵 `infra/preflight.sh:156`** — a machine with none of lsof/ss/netstat present gets a
     WARN and exit 0 — preflight "passes" having verified zero ports, with no distinction
     in the summary between "checked and clean" and "could not check."
126. **🔵 `Makefile:48` vs `ci.yml:46`** — `make test` runs the script via `sh`, CI runs it
     via `bash` — works today only because the script happens to be POSIX-clean, not by any
     enforced guarantee.
127. **🔵 `run_all_tests.sh:8`** — CLI arguments are silently ignored entirely (verified:
     `--help` runs the full suite with no usage text).
128. **🔵 `run_all_tests.sh:386`** — the final verdict is a single binary flag; a failure
     is never named, so "SOME TESTS FAILED" identifies nothing across 135 invocations.

*(Positive result: `run_all_tests.sh`'s actual failure-propagation mechanism was verified
correct by execution — 3 real harness runs, including one where only the first of 135
invocations failed — the exit code correctly reflected failure in every case. No
`continue-on-error` exists anywhere in the 4 GitHub Actions workflows, and no job
dependency swallows another job's failure.)*

### Individual detection-rule semantic correctness (4🔴 6🟡 1🔵)

129. **🔴 `contracts/rules/common_impossible_travel.yml:39`** — `distinct_field:
     src_endpoint.location.country` can structurally never reach its threshold of 2 on
     real traffic: the shipped `geoip.yml` map has exactly one routable prefix class
     (`INTERNAL`) and two RFC5737 documentation-only prefixes that never appear in real
     traffic. Max achievable distinct count on any real attack is 1.
130. **🔴 `contracts/rules/bank_mass_card_read.yml:33`** — `distinct_field:
     unmapped.db.object` makes the rule blind to its own headline PCI scenario: a mass
     dump is one table read N million times (distinct count stays 1 forever), while a
     benign nightly report touching 20 small tables scores 20 and could false-positive.
     The rule counts the one thing that's constant during the real attack.
131. **🔴 `services/ws2-normalization/parsers/active_directory.py:78`** — the
     `WorkstationName` field defaults to the literal string `"-"` on Windows NTLM/network
     logons — truthy, so the `or Computer` fallback never fires — meaning
     `common_bruteforce_sourceless.yml`'s stateful `group_by` groups every such event under
     one host value: `"-"`. This creates a permanently-firing noise bucket that a real
     coordinated brute-force attack against the same estate hides inside via idempotent
     alert-id collision.
132. **🔴 `eval/attack/fire_check.py:392`** — the eval harness fabricates a fresh synthetic
     `distinct_field` value on every replay iteration for all 8 distinct-field rules —
     meaning the "rule fires, fully covered" green result for `bank_mass_card_read`,
     `common_port_scan`, and `common_impossible_travel` (findings #130, #133, #129) is
     guaranteed by construction, not measured. The scorecard's headline number cannot
     currently detect any of these three structural blind spots.
133. **🟡 `contracts/rules/common_port_scan.yml:31`** — `distinct_field: dst_endpoint.port`
     can only ever detect a *vertical* scan (many ports, one host); the rule's own
     description claims horizontal-scan coverage too, but a horizontal sweep (one port
     across many hosts — the standard SMB-discovery pre-lateral-movement pattern) scores a
     constant distinct-port count of 1.
134. **🟡 `contracts/rules/common_password_spray.yml:25`** — the logic detects credential
     stuffing (many sources → one account), not password spraying (one source, few
     passwords → many accounts), yet is tagged and published as T1110.003 coverage.
     Modeled: a realistic paced spray (300 accounts, 1 attempt each, 30 minutes, one host)
     evades every rule in the shipped ruleset, including this one.
135. **🟡 `contracts/rules/common_impossible_travel.yml:36`** — the 600-second window is
     far shorter than the phenomenon it claims to detect; a stolen-session replay 30
     minutes after the real login (still physically impossible cross-continent travel)
     scores 1 distinct country and is silent.
136. **🟡 `contracts/rules/common_lateral_movement.yml:28`** — `distinct_field:
     dst_endpoint.hostname` is never populated by the AD parser that handles the exact
     event type (4624) the rule's own description cites — that parser only ever sets
     `src_endpoint.hostname`. On any deployment shipping AD logons under that source type,
     the rule is 100% blind while `/rules` shows it as active.
137. **🟡 `contracts/enrichment/geoip.yml:18`** — even once the impossible-travel rule's
     map is fixed (#129), `INTERNAL` is indexed in the same value space as real ISO
     country codes — a normal office→home login pattern would then trigger a false
     positive.
138. **🟡 `eval/detection_accuracy/evtx_eval.py:231`** — the ground-truth oracle
     reproduces the identical `"-"` placeholder-pooling bug from finding #131, 43 lines
     after a comment explaining exactly why that anti-pattern must not be mirrored into the
     oracle — meaning this eval can never surface finding #131 on its own.
139. **🔵 `contracts/rules/ot_new_engineering_connection.yml:33`** — titled "new
     engineering workstation," the actual logic detects "two concurrent sources" with no
     novelty concept at all — an off-hours single-source intrusion is silent, and two
     authorized engineers during a shift handover always fires it.

*(A large set of other rules — `common_bruteforce`, `common_beaconing`, `common_dns_exfil`,
`common_priv_grant`, `common_rapid_account_lifecycle`, `common_after_hours_admin`,
`cloud_root_console_login`, `bank_db_priv_esc`, both `dc_*`, both `n8n_*`, all 4 remaining
`ot_*`, and all 5 `agent_*` rules — were checked and found semantically sound: selections
match what their parsers actually emit, sector gates align correctly, and boolean logic
matches stated intent.)*

---

## Cross-cutting themes (for prioritization)

1. **The read side of the OpenSearch storage adapter diverges from `MemoryStore`'s
   contract in at least 4 separate ways** (triage-status filtering, tenant-id filtering,
   error-swallowing on 5xx, unsorted multi-index reads) — all masked because the entire
   offline test suite runs against MemoryStore only. This is the single highest-value area
   to fix first, since it affects the alert-list API's basic correctness in production.
2. **The detection-rule eval/validation harness has multiple "green by construction"
   gaps**: `fire_check.py` fabricates the field it should be testing; `validate_rules.py`
   and `validate_contract.py` both pass on zero rules/fixtures found; the `siem:` block has
   no unknown-key check. Fixing the harness itself should come before trusting any
   rule-level fix.
3. **At least 4 orphaned regression tests** exist across this session's own fixes
   (`test_alert_triage_clobber.py`, `tools/test_coverage_gate.py`,
   `ws5-ai/test_ai_engine_metrics.py`, `tools/backpressure_load_test.py`) — none reachable
   from `run_all_tests.sh` or CI. A generic "test file must be wired somewhere" gate (round
   4 finding #123) would prevent this recurring.
4. **Health checks that cannot fail** appear at every layer: WS-1's `/health` (finding
   #70), CI's stack-health wait loop (#118), several Docker Compose healthchecks
   (round-3 #21-25), and `ot_new_device_e2e.py`'s skip-is-success paths (#119) all compound
   into a state where the pipeline can be substantially broken with every visible signal
   still green.
5. **The WS-7 dashboard's auth story is actively backwards**: nginx grants authority via
   an injected header (finding #52) while the JS client that's supposed to hold that
   authority never sends it (finding #53) — these two findings should be fixed together,
   not independently, since fixing one without the other either breaks the dashboard or
   leaves the bypass in place.
6. **Silent-failure-to-empty-result is the dominant failure shape** across nearly every
   area audited — read paths across WS-3, WS-6, WS-1's spool, the bus abstraction, and the
   dashboard's fetch layer all convert a real error into an empty/default value with no
   log line. Several fixes could share one helper/convention (log-then-return-empty,
   rather than silently-return-empty).

---

*Compiled from 20 parallel Claude Opus 5 subagent reviews (6 in round 2, 4 in round 3, 10
in round 4) plus direct verification by the orchestrating session. Repo: FENGARDE
(supermhel/fengarde), branch `fix/chaos-ws8-gap-hunt` / PR #74, as of commit `beb1840`.*
