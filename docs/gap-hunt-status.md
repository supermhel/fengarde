# Gap-hunt 2026-08-26: current status of its findings (read 2026-10-20 at `f236209`; closure list refreshed 2026-10-22)

The original report is `docs/archive/reviews/gap_hunt_full_report_2026-08-26.md` (256 findings: 45 CRITICAL, 146 RISK,
65 MINOR). This file is the tracker it never had. Method: three read-only reviewers read the CODE on `origin/main`
(`f236209`) for every CRITICAL and RISK finding, not commit messages. Nothing was run, and "fixed" was not mutation-tested.
MINOR findings (65) have NOT been triaged. Statuses are claims from that read, re-checked only where noted. The counts table below is as of the original read; findings closed afterwards are listed in the next table and are not subtracted from it.

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
| R4-129 | needs real data | ship a GeoIP resolver or real egress prefixes, then make the rule `stable` |
| R4-52 | partial | issue the key only after an RBAC session, not on a spoofable `Sec-Fetch-Site` check |
| R2-2 | accepted (decided 2026-10-20) | keeping `verify_totp` on enrolment: `test_fix_mfa` pins that the enrolment code cannot be replayed at login; cost is waiting for the next 30 s code |
| R3-4, R3-6 | partial | WS-5 alerts never correlate (give them an entity or drop WS-5 from the producer list); accept/document the spoofable `device:` track |
| R3-35 | partial | probe the outside-hours window per minute (1440 samples) |
| R3-39 | partial | fail (not warn) in `fire_check` for a rule with no `mitre:` unless waived (one rule has none) |
| R4 #33 | partial | add a test with a dribbling fake response asserting `TimeoutError` |
| R4 #44 | partial | accepted/documented (lengthening the baseline never applies to existing devices) |
| R4 #85 | partial | add the replay step to the SSOT MFA row |
| R4 #107, #108 | partial / open | print and fail on `eps_dropped_majority`; tag the live bench SSH-burst ids with the run id |
| R4 #120, #121 | open | add `backpressure_load_test.py` to the wiring check; run a baseline before `mutmut run \|\| true` |
| R4 #86 | unverifiable | check git history for 2026-08-22..25 CHANGELOG gaps |
