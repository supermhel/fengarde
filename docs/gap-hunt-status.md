# Gap-hunt 2026-08-26: current status of its findings (read 2026-10-20 at `f236209`; closure list refreshed 2026-10-22; open and partial rows re-checked 2026-11-04)

The original report is `docs/archive/reviews/gap_hunt_full_report_2026-08-26.md` (256 findings: 45 CRITICAL, 146 RISK,
65 MINOR). This file is the tracker it never had. Method: three read-only reviewers read the CODE on `origin/main`
(`f236209`) for every CRITICAL and RISK finding, not commit messages. Nothing was run, and "fixed" was not mutation-tested.
MINOR findings: 61 of the 65 were triaged on 2026-11-04 (section "MINOR triage" at the end); the other 4 were not extracted. Statuses are claims from that read, re-checked only where noted. The counts table below is as of the original read; findings closed afterwards are listed in the next table and are not subtracted from it.

**Re-check 2026-11-04 (open and partial rows only).** Each row in "Still OPEN or PARTIAL" below was re-checked against
`origin/main` at `921d75b` by reading the code and, for `fire_check`, running it (`python eval/attack/fire_check.py`, exit 0).
Result: R3-35 looks fixed, R3-39 is mitigated and closed as reframed, R4 #86 is now a confirmed gap, and the other rows are
unchanged. The FIXED and PARTIAL counts in the table above and the FIXED rows were NOT re-verified. The MINOR findings were triaged
separately the same day (see the end of this file). For orientation, merged since 2026-10-22 (from the commit log): #119 (F4 clock clamp default, F2 alias map), #124 (ws8 Sentinel window counter), #126 (parser
overflow and extreme-value sweep, Ollama timeout), #127 (ws8 correlator state in Redis), #128/#132/#134 (load test, ws3 bulk
writes, pipelined ws4 window ops), #129 (LLM verdict eval), #130 (storylines name all rules), #131 (AI-to-OT demo), #133 (ws6 auth
test timeout). None of that work closed an open row except as noted in the re-check column below.

## Counts

| Tier | Checked | FIXED | PARTIAL | OPEN | Other |
|---|---|---|---|---|---|
| CRITICAL | 45 | 41 | 2 | 2 | - |
| RISK (first half) | 73 | 59 | 9 | 5 | - |
| RISK (second half) | 73 | 54 | 11 | 7 | 1 unverifiable (CHANGELOG gap, R4 #86) |
| MINOR (triaged 2026-11-04) | 61 | 49 fixed or moot | 1 partial | 3 open | 8 not checked; 4 of the 65 not extracted |

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

## Still OPEN or PARTIAL (not fixed here), with the suggested fix

| Finding | State | Suggested fix |
|---|---|---|
| R4-129 | needs real data. **Re-check 2026-11-04: unchanged** (`common_impossible_travel` is still `status: experimental`, still the sample geo map) | ship a GeoIP resolver or real egress prefixes, then make the rule `stable` |
| R4-52 | partial. **Re-check 2026-11-04: unchanged** (`SECURITY.md` still documents the header as forgeable and `ws7-dashboard/templates/default.conf.template` still keys on `Sec-Fetch-Site` as defense in depth; the key-issuance code was not re-read) | issue the key only after an RBAC session, not on a spoofable `Sec-Fetch-Site` check |
| R2-2 | accepted (decided 2026-10-20) | keeping `verify_totp` on enrolment: `test_fix_mfa` pins that the enrolment code cannot be replayed at login; cost is waiting for the next 30 s code |
| R3-4, R3-6 | partial. **Re-check 2026-11-04: unchanged in substance.** WS-8 skips WS-5-shaped alerts with a counted reason (`ws8_skipped_alerts_by_reason`, `test_ws5_shaped_alert_is_skipped_with_reason`, commit `1b97bb7`, 2026-08-26, which predates the 2026-10-20 read); they still do not correlate | WS-5 alerts never correlate (give them an entity or drop WS-5 from the producer list); accept/document the spoofable `device:` track |
| R3-35 | **Re-check 2026-11-04: looks FIXED.** `fire_check._oh_anchors` searches and sweeps in 60 s steps (`eval/attack/fire_check.py`, step `60_000` ms); `python eval/attack/fire_check.py` exited 0 on 2026-11-04. Not mutation-tested | probe the outside-hours window per minute (1440 samples) |
| R3-39 | **Re-check 2026-11-04: mitigated, closed as reframed.** Commit `4ad90df` (2026-10-28): the one untagged rule (`agent_tool_call_burst`) goes through the same positive, boundary and near-miss probes, and a failure fails the run. The 2026-11-04 run reported 1 untagged rule fired and held its negative half. There is still no hard failure merely for a missing `mitre:` tag | fail (not warn) in `fire_check` for a rule with no `mitre:` unless waived (one rule has none) |
| R4 #33 | partial. **Re-check 2026-11-04: still open.** The only timeout test (`ws5-ai/test_llm_adapter.py::test_timeout_degrades_to_stub`) mocks a raised `TimeoutError`; PR #126's `OLLAMA_TIMEOUT_SECONDS` tests cover parsing and the cap, not a dribbling response | add a test with a dribbling fake response asserting `TimeoutError` |
| R4 #44 | partial. **Re-check 2026-11-04: unchanged.** I found no public doc of this behaviour besides a test comment in `ws6-inventory/test_new_device_diff.py` | accepted/documented (lengthening the baseline never applies to existing devices) |
| R4 #85 | partial. **Re-check 2026-11-04: still open.** `SSOT.md` has no TOTP-replay mention in its MFA rows | add the replay step to the SSOT MFA row |
| R4 #107, #108 | partial / open. **Re-check 2026-11-04: both still open.** `tools/fengarde_bench.py` only writes `eps_dropped_majority` into its JSON and exits 1 solely on a bucket versus linear-scan mismatch (R4-106); `tools/fengarde_bench_live.py::_ssh_burst` still builds untagged ids (`bench-live-{ip}-{i}`). PR #128's separate `tools/fengarde_loadtest_live.py` is not affected: it tags every event id with a per-run `run_tag` | print and fail on `eps_dropped_majority`; tag the live bench SSH-burst ids with the run id |
| R4 #120, #121 | open. **Re-check 2026-11-04: both still open.** `tools/backpressure_load_test.py` is referenced only in `CHANGELOG.md`, `SSOT.md` and its own docstring, not in `tools/check_test_wiring.py`, `run_all_tests.sh` or CI; the CI mutmut step is still `python -m mutmut run \|\| true` with no baseline | add `backpressure_load_test.py` to the wiring check; run a baseline before `mutmut run \|\| true` |
| R4 #86 | unverifiable. **Re-check 2026-11-04: gap confirmed.** `CHANGELOG.md` has no entry dated 2026-08-22 to 2026-08-25, while three commits landed on 2026-08-23 (`87e9f80` TOTP replay and auth-scope fixes, `418f3cf` chaos-gate WS-8, `beb1840` CI fixes). The TOTP-replay fix is not mentioned in the CHANGELOG; `418f3cf` is referenced at `CHANGELOG.md:1973`, section date not checked | check git history for 2026-08-22..25 CHANGELOG gaps |

## MINOR triage (2026-11-04)

Source: the archived report's blue-marked entries. A parser found 61 of the 65 (round 2: 1 of 2, round 3: 21, round 4: 39 of 42);
the other 4 were not extracted and remain untriaged. Ids are round-prefixed because each round numbers its findings separately.
Method: each finding was checked against `origin/main` at `921d75b` by `git grep` and reading the cited code. "Fixed" means
the cited defect is gone or the code carries a comment citing the fix; nothing was mutation-tested. Items marked * rest on a
code comment or on the old text being gone, not on a detailed read.

**Fixed or moot (49):** R2-39; R3-10, 11, 12, 29, 30, 48 (documented as a maintained document, not a gate), 49 (docs now say
over-limit values are clamped), 63, 64, 65, 66, 67, 68, 69; R4-10, 12, 24*, 25*, 26, 27, 28, 29, 30, 38, 39, 40, 65, 66, 67
(moot: the legacy console is retired and `getAlerts` no longer exists), 68, 78, 79, 80, 81, 92, 93, 94*, 95, 96, 113, 115, 117,
124, 125, 126, 127*, 128, 139 (title now matches the "concurrent sources" logic; the missing novelty logic is by design).

**Open or partial (4):**

| Finding | State | Evidence |
|---|---|---|
| R3-28 | open | `infra/docker-compose.yml` (lines 119, 154, 169) still builds `REDIS_URL=redis://:${REDIS_PASSWORD:-}@redis:6379/0` with the raw password; `shared/bus.py` only quotes URLs it builds itself (R3-63, fixed) |
| R3-31 | partial | `ws4-detection/engine.py` still walks fixed directory depths but now falls back to `Rule.__init__`'s own checks when `tools/validate_rules.py` is absent; the poison-pill validator may still be a no-op in a built image (not tested in a container) |
| R3-47 | open, documented | 23 of the 46 rule files use a family prefix (`agent_`, `win_`, `ot_`, ...) instead of `<sector>_`; `contracts/detection-coverage.md` calls it a convention, not a validator-enforced invariant |
| R4-49 | open | `ws6-inventory/app.py:40` still defaults the keystore to the same SQLite path as the inventory store; lock coordination not checked |

**Not checked (8):** R3-8 and R3-9 (tests mention `_last_incident`, `member_cap` and `truncated` in four ws8 test files, but the
specific branches were not verified), R3-70 (latent, documented unreachable), R4-11 (oversized report-request body), R4-37
(non-dict JSON from the model), R4-97 (the loopback-port list in `SECURITY.md`), R4-114 (`chaos_test.Scenario.alert_id`), R4-116
(`EXPIRE` coverage in `tools/test_mutmut_window.py`).
