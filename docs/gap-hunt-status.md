# Gap-hunt 2026-08-26: current status of its findings (read 2026-10-20 at `f236209`; closure list refreshed 2026-10-22; open and partial rows re-checked 2026-11-04)

The original report is `docs/archive/reviews/gap_hunt_full_report_2026-08-26.md` (256 findings: 45 CRITICAL, 146 RISK,
65 MINOR). This file is the tracker it never had. Method: three read-only reviewers read the CODE on `origin/main`
(`f236209`) for every CRITICAL and RISK finding, not commit messages. Nothing was run, and "fixed" was not mutation-tested.
MINOR findings (65) have NOT been triaged. Statuses are claims from that read, re-checked only where noted. The counts table below is as of the original read; findings closed afterwards are listed in the next table and are not subtracted from it.

**Re-check 2026-11-04 (open and partial rows only).** Each row in "Still OPEN or PARTIAL" below was re-checked against
`origin/main` at `921d75b` by reading the code and, for `fire_check`, running it (`python eval/attack/fire_check.py`, exit 0).
Result: R3-35 looks fixed, R3-39 is mitigated and closed as reframed, R4 #86 is now a confirmed gap, and the other rows are
unchanged. The FIXED and PARTIAL counts in the table above and the FIXED rows were NOT re-verified, and the 65 MINOR findings remain
untriaged. For orientation, merged since 2026-10-22 (from the commit log): #119 (F4 clock clamp default, F2 alias map), #124 (ws8 Sentinel window counter), #126 (parser
overflow and extreme-value sweep, Ollama timeout), #127 (ws8 correlator state in Redis), #128/#132/#134 (load test, ws3 bulk
writes, pipelined ws4 window ops), #129 (LLM verdict eval), #130 (storylines name all rules), #131 (AI-to-OT demo), #133 (ws6 auth
test timeout). None of that work closed an open row except as noted in the re-check column below.

## Counts

| Tier | Checked | FIXED | PARTIAL | OPEN | Other |
|---|---|---|---|---|---|
| CRITICAL | 45 | 41 | 2 | 2 | - |
| RISK (first half) | 73 | 59 | 9 | 5 | - |
| RISK (second half) | 73 | 54 | 11 | 7 | 1 unverifiable (CHANGELOG gap, R4 #86) |
| MINOR | 0 | not triaged | | | 65 |

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
| R4 #107, #108 | partial / open. **Re-check 2026-11-04: both still open.** `tools/fengarde_bench.py` only writes `eps_dropped_majority` into its JSON and exits 1 solely on a bucket versus linear-scan mismatch (R4-106); no run id is added to the live bench ids. PR #128 added a separate `tools/fengarde_loadtest_live.py` that was not checked against this finding | print and fail on `eps_dropped_majority`; tag the live bench SSH-burst ids with the run id |
| R4 #120, #121 | open. **Re-check 2026-11-04: both still open.** `tools/backpressure_load_test.py` is referenced only in `CHANGELOG.md`, `SSOT.md` and its own docstring, not in `tools/check_test_wiring.py`, `run_all_tests.sh` or CI; the CI mutmut step is still `python -m mutmut run \|\| true` with no baseline | add `backpressure_load_test.py` to the wiring check; run a baseline before `mutmut run \|\| true` |
| R4 #86 | unverifiable. **Re-check 2026-11-04: gap confirmed.** `CHANGELOG.md` has no entry dated 2026-08-22 to 2026-08-25, while three commits landed on 2026-08-23 (`87e9f80` TOTP replay and auth-scope fixes, `418f3cf` chaos-gate WS-8, `beb1840` CI fixes). The TOTP-replay fix is not mentioned in the CHANGELOG; `418f3cf` is referenced at `CHANGELOG.md:1973`, section date not checked | check git history for 2026-08-22..25 CHANGELOG gaps |
