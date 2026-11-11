# Gap-hunt 2026-08-26: current status of its findings (read 2026-10-20 at `f236209`; closure list refreshed 2026-10-22; open and partial rows re-checked 2026-11-04)

**Status 2026-11-04: closed.** Every tracked finding is either fixed (with a test or a documented decision) or was moved to the roadmap as a task: GH-1, GH-2 and GH-3 in the section "Left work, moved to the roadmap" below (detail in the private `fengarde-sec/docs/ROADMAP.md`). Nothing here is left as an untracked open row.

The original report is `docs/archive/reviews/gap_hunt_full_report_2026-08-26.md` (256 findings: 45 CRITICAL, 146 RISK,
65 MINOR). This file is the tracker it never had. Method: three read-only reviewers read the CODE on `origin/main`
(`f236209`) for every CRITICAL and RISK finding, not commit messages. Nothing was run in that original read, and "fixed" was not mutation-tested there. WP-4.4 (2026-11-06, section near the end) later re-verified a hand-picked sample of 16 FIXED rows by running their tests, and mutation-checked 4 of them; the other FIXED rows are still claims from the code read.
MINOR findings: all 61 numbered entries were triaged and closed on 2026-11-04 (section "MINOR triage" at the end; the report's stated total of 65 does not match its entries, see GH-3). Statuses are claims from that read, re-checked only where noted. The counts table below is as of the original read; findings closed afterwards are listed in the next table and are not subtracted from it.

**Update 2026-11-04.** Every open and partial row was re-checked against `origin/main` at `921d75b` (code read; `python eval/attack/fire_check.py` run, exit 0) and then fixed in the same PR wherever a fix existed. Three rows remain (R4-129, R4-52, R2-2). The FIXED and PARTIAL counts in the table below were not recomputed; only the 16 FIXED rows listed in the WP-4.4 section were re-verified on 2026-11-06, the rest were not. The MINOR findings were triaged and closed separately (end of this file). For orientation, merged since 2026-10-22 (from the commit log): #119 (F4 clock clamp default, F2 alias map), #124 (ws8 Sentinel window counter), #126 (parser
overflow and extreme-value sweep, Ollama timeout), #127 (ws8 correlator state in Redis), #128/#132/#134 (load test, ws3 bulk
writes, pipelined ws4 window ops), #129 (LLM verdict eval), #130 (storylines name all rules), #131 (AI-to-OT demo), #133 (ws6 auth
test timeout).

## Counts

| Tier | Checked | FIXED | PARTIAL | OPEN | Other |
|---|---|---|---|---|---|
| CRITICAL | 45 | 41 | 2 | 2 | - |
| RISK (first half) | 73 | 59 | 9 | 5 | - |
| RISK (second half) | 73 | 54 | 11 | 7 | 1 unverifiable (CHANGELOG gap, R4 #86) |
| MINOR (triaged 2026-11-04) | 61 | 61 fixed or moot (4 of them in the 2026-11-04 PR) | - | - | the report states 65; it has 61 numbered entries |

## Closed since the check (PR #112, work dated 2026-10-20, merged 2026-10-21)

| Finding | Change |
|---|---|
| R4-72 (CRITICAL) | `syslog_udp_server.stop()` lets workers drain the queue; leftovers are counted in `events_lost` |
| R4-132 (CRITICAL) | `fire_check.py` now warns for rules that passed on synthetic distinct values |
| R4-52 (CRITICAL, partial) | SECURITY.md states the API key on :8080 is not an access-control boundary (the code path is unchanged) |
| R4-129 (CRITICAL, mitigated) | `common_impossible_travel` is `status: experimental` until a real geo map ships (still cannot fire on production traffic) |
| R3-25 | ws7 `depends_on` ws6 with `condition: service_healthy` (YAML-validated, not Docker-run) |
| R3-40 | `run_eval.py` enforces the documented floor of 10 scenarios |
| R3-45 | `triage-api.yaml` CSRF note corrected (writes need `X-CSRF-Token` from the login session) |
| R4-74 / R4-75 | WS-1 passes its logger to the spool and exports `spool_corrupt_lines_skipped` |
| R4-122 | live OpenSearch / Redis tests exit 1 instead of SKIP when `FENGARDE_E2E_STRICT=1` (set in those CI jobs) |
| R3-43 | the report route returns 400 for an unknown NIS2 `stage`/`lang` (regression test) |
| R3-57 | `llm_adapter._urlopen` fails closed when the no-redirect opener is unavailable (opt-out env var) |
| R4-136 | active_directory maps a logon's target host to `dst_endpoint.hostname`, so lateral-movement rules count AD logons |
| R4 #54 / #61 / #69 | the legacy console was retired (owner decision 2026-10-20), so its bugs and tests are gone |
| R4 #6 | audit append takes the cross-process lock |
| R4 #17 | hot reload rejects a zero-byte/truncated rule file and keeps the old set |
| R3-22 / R3-23 | Sentinel healthcheck verifies the monitored master; Sentinels wait for healthy Redis nodes (validated with a real 6-container run) |
| R2-14 | `bus_error` counted on each failing path, mutation-checked |
| fuzzing (new, not in the 2026-08-26 report) | the 19 atheris harnesses had no coverage feedback; repaired, and the repaired run found 5 parser bugs, all fixed (see CHANGELOG) |
| R4-108 (part) | the live bench returns 1 when a latency run collects 0 samples (the fixed SSH-burst ids are still untagged) |
| R4 #133 / #134 | `common_port_sweep` (T1046, one source denied across 15+ distinct hosts) and `common_password_spray_by_source` (T1110.003, one source across 8+ distinct accounts) |

## Closed 2026-11-04 (this tracker's re-check plus the fixes in the same PR)

| Finding | Result | Evidence |
|---|---|---|
| R3-35 | looks fixed | `fire_check._oh_anchors` searches and sweeps in 60 s steps; `python eval/attack/fire_check.py` exit 0 |
| R3-39 | mitigated by `4ad90df` (2026-10-28) | the untagged rule goes through the same probes and a failure fails the run |
| R3-4, R3-6 | documented | WS-8 skips WS-5-shaped alerts with a counted reason (`ws8_skipped_alerts_by_reason`) and `services/ws8-correlation/INTERFACE.md` documents the `device:` track's spoofability and allowlist |
| R4 #33 | test added | the wall-clock deadline already existed in `OllamaLLM.analyze`; `test_dribbling_response_hits_total_deadline` pins it |
| R4 #44 | documented | `services/ws6-inventory/INTERFACE.md`: a longer baseline never lengthens an existing tenant's window |
| R4 #85 | fixed | `services/ws3-indexer/test_mfa_live_e2e.py` step 7 re-presents the spent code and expects 401 |
| R4 #86 | fixed | `CHANGELOG.md` backfill entry for 2026-08-23 |
| R4 #107, #108 | fixed | `fengarde_bench.py` exits 1 on `eps_dropped_majority`; `fengarde_bench_live.py` burst ids carry a per-run tag; `tools/test_bench_gates.py` |
| R4 #120 | fixed | `tools/check_test_wiring.py` scans `*_load_test.py` and lists `backpressure_load_test.py` as live-only |
| R4-129, R4-52 | partly done, rest moved | see GH-1 and GH-2 below |
| R4 #121 | fixed, and the baseline was red | CI runs the mutmut test selection once, blocking. It failed on `main` (2 tests, stale fake after the 2026-10-29 window changes); repaired |

## Left work, moved to the roadmap

| Task | Finding | Why it is not done here | Done when |
|---|---|---|---|
| GH-1 | R4-129 (part) | Done: `FENGARDE_GEOIP_PATH` lets an operator supply real egress prefixes, and WS-2 now logs a warning while the sample map is active. Not done: this repo ships no real GeoIP data (licensing and the sovereignty constraint rule out a bundled MaxMind binary), the lookup scans the list linearly so it does not scale to a full database, and the rule is still `status: experimental` | a dataset is chosen and licensed (or documented as operator-supplied), the lookup is indexed, `fire_check` covers a rule fixture on a real prefix, then `common_impossible_travel` is promoted to `stable` |
| GH-2 | R4-52 | The nginx `config.js` bootstrap still gives the API key to any client that sends `Sec-Fetch-Site: same-origin`. Gating it on an RBAC session is an auth-model change, not a patch: today `/api/auth/login` and `/api/auth/me` themselves require the key, so withholding it before login would lock users out; nginx runs `return` before `auth_request`, so the gate needs `try_files` to a named location; and the SPA must re-fetch the key after login. It needs the live console e2e (`tools/console_e2e/check.mjs`, `mfa.mjs`) to verify | login and `/auth/me` no longer need the key, `config.js` returns 401 without a session when RBAC is on (and stays open when RBAC is off), the SPA loads the key after login, and `check.mjs` and `mfa.mjs` pass on the live stack |
| GH-3 (closed 2026-11-06 as a sample, see "WP-4.4 (GH-3) re-verification" below; kept here for the record) | the FIXED rows | The 2026-10-20 read marked 154 CRITICAL and RISK findings FIXED from reading code; none was mutation-tested, and this tracker only re-checked the open rows and the MINOR findings. The report's own MINOR total (65) does not match its numbered entries (61; its section headers sum to 64) | a second reviewer samples the FIXED CRITICAL and RISK rows, mutation-checks the security-relevant ones, and the count discrepancy is explained or corrected. Status: done as a sample only (16 hand-picked rows, 4 mutation-checked; 138 of the 154 were not re-verified). The count discrepancy is explained in the WP-4.4 section |

Decided, no work: R2-2 (accepted 2026-10-20): `verify_totp` stays on enrolment, `test_fix_mfa` pins that the enrolment code cannot be
replayed at login, and the cost is waiting for the next 30 s code.

## MINOR triage (2026-11-04)

Source: the archived report's blue-marked entries. There are 61 numbered ones (round 2: 1, round 3: 20, round 4: 40); the report's
headline total of 65 and its section headers (which sum to 64) do not match its own entries, so no entry is left untriaged. Ids are round-prefixed because each round numbers its findings separately.
Method: each finding was checked against `origin/main` at `921d75b` by `git grep` and reading the cited code; the open ones were then
fixed in the same PR. "Fixed" means the cited defect is gone or the code carries a comment citing the fix; nothing was
mutation-tested. Items marked * rest on a code comment or on the old text being gone, not on a detailed read.

**Fixed or moot already on `main` (57):** R2-39; R3-8 and 9 (tests `test_sweep_prunes_stale_promoted_tracks_last_incident`,
`test_member_cap_*`, `test_severity_cap_*`), 10, 11, 12, 29, 30, 48 (documented as a maintained document, not a gate), 49 (docs say
over-limit values are clamped), 63, 64, 65, 66, 67, 68, 69, 70 (`hit_distinct` has its own `_dw` dict); R4-10, 11 (all three body
readers use `_MAX_BODY_BYTES`), 12, 24*, 25*, 26, 27, 28, 29, 30, 37 (non-JSON model output raises into the fallback), 38, 39, 40, 65,
66, 67 (moot: the legacy console is retired and `getAlerts` no longer exists), 68, 78, 79, 80, 81, 92, 93, 94*, 95, 96, 97 (the port
list in `SECURITY.md` names all seven), 113, 114 (`Scenario` no longer has an `alert_id` field), 115, 116 (an `EXPIRE` assertion
exists), 117, 124, 125, 126, 127*, 128, 139 (title now matches the "concurrent sources" logic; the missing novelty logic is by design).

**Fixed in this PR (4):**

| Finding | Fix |
|---|---|
| R3-28 | the compose files still interpolate `REDIS_PASSWORD` raw into `REDIS_URL`; `make up` runs `infra/preflight.sh` first (R4-124) and the preflight now rejects `@ : / % ? #` and spaces |
| R3-31 | the ws4 Dockerfile copies `tools/validate_rules.py`, and `engine._find_up` replaces the fixed-depth path walks; `test_poison_pill_image_layout.py` rebuilds the image layout (the first version of this fix, the COPY alone, did not work: the test showed `parents[2]` resolves to `/` in the image) |
| R3-47 | `tools/validate_rules.py` enforces `FILENAME_FAMILIES`; `contracts/sigma-convention.md` states the real convention |
| R4-49 | `TenantKeyStore` shares `InventoryStore`'s write lock when both use one SQLite file; `test_shared_write_lock.py` |

## WP-4.4 (GH-3) re-verification of the FIXED rows (2026-11-06)

Scope: GH-3 asked for a second reviewer to sample the rows the 2026-10-20 and 2026-11-04 reads marked FIXED (154 CRITICAL/RISK + 61 MINOR), mutation-check the security-relevant ones, and explain the report's 65-vs-61 MINOR count. This section is that re-verification, and it is a **sample, not full coverage: 16 hand-picked FIXED rows out of the 154 FIXED CRITICAL/RISK rows (plus the MINOR rows), 4 of them mutation-checked.** The sample was picked by hand from the "Closed since" and MINOR-triage tables, i.e. rows that already name a test; it is not random, so it does not show the other rows hold. It also is not all CRITICAL/RISK: R3-28, R3-31, R3-47 and R4-49 are MINOR rows in this tracker's MINOR triage, and the fuzzing item is not in the 2026-08-26 report, so at most 11 of the 16 are among the 154. The tier of the rest is not recorded in this file. Everything below was run on a fresh worktree of `origin/main` at `182a4ab` (branch `wp/4.4-gh3-reverify`), with the repo's venv python. Every sampled suite was run one file at a time (never in parallel) and the output is quoted from those runs.

### Sample re-verification of FIXED rows (the 16, listed so the sample is reproducible)

The 16, in the order of the table: R4-72; R4-74/R4-75; R4-136; the fuzzing fixes; R4 #6; R3-43; R4 #17; R3-31; R4 #33; R3-57; R4-49; R2-14; R4-107/108; R3-47; R4-120; R3-28. Rows were counted as one fix when a single suite covers them (R4-74/75, R4-107/108). Re-run each suite named in the table to reproduce.

| Finding (row) | Workstream | Evidence (test run on this branch) | Result |
|---|---|---|---|
| R4-72: `syslog_udp_server.stop()` lets workers drain; leftovers counted in `events_lost` | ws1 | `services/ws1-collectors/test_syslog_udp.py` | `Ran 54 tests in 1.314s` / `OK` |
| R4-74/R4-75: WS-1 passes its logger to the spool; exports `spool_corrupt_lines_skipped` | ws1 | `services/ws1-collectors/test_spool_perf.py` (torn-tail corrupt-skip cases) | `[OK] spool perf/locking (P1-6) tests PASS` |
| R4-136: `active_directory` maps a logon's target host to `dst_endpoint.hostname` | ws2 | `services/ws2-normalization/parsers/test_active_directory.py` | `Ran 8 tests in 0.010s` / `OK` |
| fuzzing (not in the 2026-08-26 report): the 19 repaired atheris harnesses found 5 parser bugs, all fixed | ws2 | `services/ws2-normalization/parsers/test_fuzz_findings.py` | `[OK] fuzz findings: non-string process name, out-of-range ports (cef/asa/ssh), non-string OPC UA eventType all handled` |
| R4 #6: audit append takes the cross-process lock | ws3 | `services/ws3-indexer/test_fix_audit.py` | `[OK] E1 audit: entries on login/triage/report, /audit admin-scoped, append-only, capacity-cap tail-truncation, fail-open` |
| R3-43: the report route returns 400 for an unknown NIS2 `stage`/`lang` | ws3 | `services/ws3-indexer/test_nis2_template.py` (`test_http_report_route_rejects_unknown_stage_or_lang`) | `[OK] M5 NIS2 template: ... invalid stage/lang degrade gracefully ... and the HTTP report route correctly selects the NIS2 renderer via query params` (that final line describes the renderer coercion; the 400 itself is asserted by `test_http_report_route_rejects_unknown_stage_or_lang`, which the same file calls and which passed) |
| R4 #17: hot reload rejects a zero-byte/truncated rule file and keeps the old set | ws4 | `services/ws4-detection/test_hot_reload.py` | `[OK] B4 hot-reload: valid edit swaps in, malformed edit rejected (fail-closed, old set kept), removed rule stops firing, mtime poll watcher off by default and picks up real changes when enabled` |
| R3-31: ws4 Dockerfile COPYs `tools/validate_rules.py` and `engine._find_up` replaces fixed-depth walks | ws4 | `services/ws4-detection/test_poison_pill_image_layout.py` | `[OK] ws4 image layout: Dockerfile ships validate_rules.py and the poison-pill guard rejects a bad rule there (control without it: accepted)` |
| R4 #33: the wall-clock deadline in `OllamaLLM.analyze` is pinned | ws5 | `services/ws5-ai/test_llm_adapter.py` (`test_dribbling_response_hits_total_deadline`) | `ok` — `Ran 22 tests in 0.592s` / `OK` |
| R3-57: `llm_adapter._urlopen` fails closed when the no-redirect opener is unavailable | ws5 | `services/ws5-ai/test_llm_adapter.py` (`test_refuses_without_the_no_redirect_opener`) | `ok` — `Ran 22 tests` / `OK` |
| R4-49: `TenantKeyStore` shares `InventoryStore`'s write lock on one SQLite file | ws6 | `services/ws6-inventory/test_shared_write_lock.py` | `[OK] ws6 stores share one write lock exactly when they share a SQLite file` |
| R2-14: `bus_error` counted on each failing path | shared | `services/shared/test_runner.py` (incl. `_test_topic_worker_bus_error_each_path_counts`; the redis variant SKIPs without a reachable Redis) | `[OK] runner unit tests PASS` |
| R4-107/108: `fengarde_bench.py` exits 1 on `eps_dropped_majority`; live bench burst ids tagged per run | tools | `tools/test_bench_gates.py` | `[OK] bench gates: mass-drop run exits 1 (JSON and text), live-bench burst ids are unique per run` |
| R3-47: `tools/validate_rules.py` enforces `FILENAME_FAMILIES` | tools | `tools/test_validate_rules.py` | `Ran 65 tests in 1.281s` / `OK` |
| R4-120: `tools/check_test_wiring.py` scans `*_load_test.py` and lists `backpressure_load_test.py` as live-only | tools/CI | `tools/check_test_wiring.py` | `[OK] every test_*.py is wired into run_all_tests.sh (or a documented live-only orphan). No orphan suite silently untested.` |
| R3-28 (MINOR, fixed in the 2026-11-04 PR): `infra/preflight.sh` rejects `@ : / % ? #` and spaces in `REDIS_PASSWORD` | infra | `REDIS_PASSWORD=p@ssw0rd bash infra/preflight.sh` and `REDIS_PASSWORD=urlsafepass bash infra/preflight.sh` | bad: `[ FAIL ] REDIS_PASSWORD contains @, :, /, %, ?, # or a space -- those break the bus URL`, script exit 1; good: `[ OK ] REDIS_PASSWORD is URL-safe (no @ : / % ? # or space characters).` (The run's other `[ FAIL ]` is the MSYS-host `vm.max_map_count` platform check, unrelated to this row.) |

Verdict: every sampled FIXED row still holds on `182a4ab` — 14 distinct suites, exit 0 each, plus the two-way preflight run.

### Mutation checks of 4 FIXED rows (fix reverted in the working tree -> RED -> restored -> GREEN)

Only R3-57 and R4 #17 are security or integrity fixes in the strict sense. R4-49 is a MINOR row about a SQLite write lock shared by two stores in one file (concurrency and integrity, not tenant isolation). R2-14 is telemetry. Their property labels below say so.

Method: for each row, the fixing change was reversed in the working tree only (never committed), the row's covering test was run (must FAIL), then `git checkout --` restored the fix and the test was re-run (must PASS). Nothing mutated was committed; the tree was clean (`git status --short` empty) before the report commit.

| Row | Security property | Mutation (reverted shape) | RED evidence | GREEN evidence (fix restored) |
|---|---|---|---|---|
| R3-57 (ws5) | SSRF / outbound redirect-following (`_urlopen` fails closed) | Removed the `FENGARDE_ALLOW_REDIRECTING_URLOPEN` guard so a no-opener call falls through to plain `urllib.request.urlopen` | `test_refuses_without_the_no_redirect_opener ... ERROR` — `AttributeError: 'object' object has no attribute 'timeout'` at `llm_adapter.py:92`; `Ran 22 tests ... FAILED (errors=1)`, exit 1 | `Ran 22 tests in 0.629s` / `OK` |
| R4 #17 (ws4) | Rule-set integrity on a bad edit (a zero-byte file must not silently shrink detection) | `self._load(strict_empty=True)` back to `self._load()` in the reload path | `[FAIL] hot_reload: 2 problem(s)` — `- a zero-byte rule file must fail reload(), not shrink the rule set` / `- the PREVIOUS rule set must still fire after the rejected reload` | `[OK] B4 hot-reload: ... malformed edit rejected (fail-closed, old set kept) ...` |
| R4-49 (ws6, MINOR) | Concurrency/integrity of one SQLite file written by two stores (write lock); not a tenant-isolation fix | Dropped the shared `write_lock=` wiring in `app.py` (`KEYSTORE = TenantKeyStore(_KEYSTORE_DB)`) | `[FAIL] ws6 shared write lock: 2 problem(s)` — `- same file (keystore defaults to the inventory db) must share the lock` / `- explicit same path must share the lock`, exit 1 | `[OK] ws6 stores share one write lock exactly when they share a SQLite file` |
| R2-14 (shared) | Telemetry only (a failing bus path must count `bus_error`, not just degrade `/health`); not a security property | Set the consume-path setpoint to `bus_error_this_iter = False` in `runner.py` | `[FAIL] runner: 2 problem(s)` — `- bus.claim_pending()/consume() raising must increment metrics 'bus_error', not just /health -- got {}` / `- consume() raising ALONE must increment 'bus_error' -- got {}`, exit 1 | `[OK] runner unit tests PASS` |

### The '65 vs 61 MINOR' discrepancy — exact cause

The archived report (`docs/archive/reviews/gap_hunt_full_report_2026-08-26.md`) carries three different MINOR totals. I counted the document itself (`^\d+\.\s+\*\*🔵` numbered entries per section, per round):

- Numbered 🔵 entries actually present: **61** = round 2: **1** (item 39, `chaos_test.py`), round 3: **20**, round 4: **40**.
- Section-header sums: **64** = round 2: 1, round 3: 21, round 4: 42.
- Totals table: **65** = round 2: 2, round 3: 21, round 4: 42.

The 4 extra entries (65 − 61), each with its source:

1. **Round-2 summary-table row (1 phantom).** The table says round 2 has `2 🔵`, but the round has exactly one blue entry (Tools/CI item 39); the Tools/CI header itself correctly says `1🔵`. The same row also overstates 🟡 (33) against the 34 real ones — the table row's arithmetic, not the sections, is wrong.
2. **Round-3 "Eval harness + contracts drift" header (net +1).** The header lists `5🔵`, the section contains 3 real blue entries (#47, #48, #49). That is +2, offset by the round's "shared/ modules" header listing `7🔵` while the section contains 8 real blue entries (#63–#70) — −1. Net round-3 inflation: +1 (21 vs 20).
3. **Round-4 "WS-3 indexer remaining modules" header (+1).** Lists `4🔵`, section contains 3 real blue entries (#10, #11, #12).
4. **Round-4 "WS-5 llm_adapter.py core logic" header (+1).** Lists `5🔵`, section contains 4 real blue entries (#37, #38, #39, #40).

Net: 61 real numbered entries + 1 (R2 table row) + 1 (R3 headers) + 2 (R4 headers) = 65. The tracker's GH-3 row ("its section headers sum to 64") is confirmed: the only totals-table-vs-headers mismatch is round 2 (2 vs 1). All 61 real MINOR entries are covered by the 2026-11-04 triage; nothing numbered was left untriaged.

### What this re-verification did not run

- The full serial gate (`run_all_tests.sh`, ~30 min) was not run locally, and CI's `full-gate` job is skipped on this PR (only the fast tier runs). Each sampled suite was run individually.
- Live-stack suites were not run: `test_mfa_live_e2e.py` replay step (R4 #85; needs the console stack), the 6-container Sentinel run (R3-22/23), `*_live.py` suites needing real Redis/OpenSearch, and the ws7 dashboard browser e2e.
- Mutation checks cover 4 rows only (R3-57, R4 #17, R4-49, R2-14); the other sampled rows were re-verified as-is, not mutation-tested.
- ws7/ws9 rows have no fix-specific suite in the tracker's closed tables (ws7's close, R4 #54/#61/#69, is the legacy console being retired — the code no longer exists; ws9 had no FIXED row in the sampled set).
