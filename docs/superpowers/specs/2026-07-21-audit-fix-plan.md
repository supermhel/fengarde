# FENGARDE Audit Fix Plan (2026-07-21)

Consolidated remediation plan for the full-codebase audit run on 2026-07-21:
independent code review + logic/perf/docs bug hunts + three live evaluations
(detection accuracy on real EVTX **and** Splunk attack_data, EPS load test on the
live Docker stack, OpenSSF Scorecard). This doc is the actionable backlog; SSOT.md
remains the canonical status index and should be updated as items land.

## How this was measured (so the numbers are reproducible)

- **Detection accuracy** — replayed two independent real-attack corpora through the
  live `WS-2 → WS-4` pipeline and compared engine alerts against an *independent
  oracle* that recomputes each rule's ground truth directly from raw records:
  - **EVTX-ATTACK-SAMPLES** (173 files, 32,685 records) — single-incident captures.
  - **Splunk `attack_data`** (15 raw-XML `windows-security.log` datasets, 1,726
    supported records) — purplesharp/T1110 sets that carry real brute-force /
    password-spray **volume** the EVTX corpus lacked.
  - Harnesses: `scratchpad/evtx_eval.py`, `scratchpad/splunk_eval.py` (see
    "Test-data integration" below to fold these into the repo).
- **EPS** — multi-threaded UDP syslog flood against WS-1 on the live stack (real
  Redis + OpenSearch), reading `/proc/net/snmp` UDP counters and ws1 `/metrics`.
- **Supply chain** — live `api.securityscorecards.dev` query.

## Evidence headlines

| Test | Result |
|---|---|
| Rule **logic** correctness | Sound — **zero false positives** across both corpora; every correct fire matched the oracle |
| Detection **coverage** (EVTX) | Was **9%** of Security-channel records parseable (110/1226), 10 EventIDs, no Sysmon. **Fixed 2026-07-21 (P0-3): 32.4% of Security+Sysmon combined** (3.6x), 15 EventIDs total, 0 new false positives |
| Detection **misses** (Splunk volume) | **6 brute-force false negatives** on real red-team data — **all 6 fixed 2026-07-21** (1 by P0-1's IPv6 fix, 5 by P0-2's new sourceless rule); confusion matrix now clean (0 mismatches) on both corpora |
| EPS zero-loss ingest | Was ~300 EPS clean / ~500 EPS burst ceiling — **fixed 2026-07-21 (P0-4): ~794 EPS clean, 1,232 EPS admitted under the same 7,350-offered flood (+147%)** |
| EPS overload behavior | Was: 7,352 EPS offered → 62,466 kernel-dropped datagrams **invisible** to the app (`shed=0 dropped=0`). **Fixed 2026-07-21 (P0-4): kernel drops now surfaced on `/metrics`** (`udp_rcvbuf_errors_cumulative`), plus a new distinct `events_queue_full` counter for app-layer saturation |
| Redis retention | `raw.events` XLEN **froze at 7968 after full drain** — acked entries never trimmed |
| Scorecard | **5.6/10** (matches SSOT's documented accepted residue) |

---

## P0 — Detection-integrity (real missed detections; fix first)

### P0-1 — IPv4-mapped-IPv6 source IPs dead-letter valid auth events `[HIGH→CRITICAL]` — ✅ DONE (2026-07-21)

- **Evidence (before fix):** live-proven on BOTH corpora. Splunk
  `purplesharp_valid_users_kerberos_xml` and 4 other Kerberos/DC sets dead-lettered
  events with `.src_endpoint.ip: '::ffff:10.0.1.15' does not match pattern`. Same on
  EVTX (`kerberos_pwd_spray_4771.evtx`, DC securitylog).
- **Root cause:** [`services/shared/ocsf.py:36`](../../../services/shared/ocsf.py) `valid_ip()` accepted
  `::ffff:a.b.c.d` (via `ipaddress.ip_address`), but the OCSF schema `ip`
  pattern's IPv6 branch `^([0-9a-fA-F:]+:[0-9a-fA-F:]*)$` forbids the embedded
  dots, so `validate()` rejected the whole event and WS-2 dead-lettered it.
- **Fix applied:** `valid_ip()` now normalizes via `addr.ipv4_mapped` — when the
  parsed address is IPv4-mapped IPv6, returns the plain IPv4 string; otherwise
  returns the address unchanged (real IPv6 unaffected). See
  [`services/shared/ocsf.py`](../../../services/shared/ocsf.py).
- **Tests added:** [`services/shared/test_ocsf.py`](../../../services/shared/test_ocsf.py)
  (5 unit tests: mapped-IPv6→IPv4 normalization, plain-IPv4 passthrough, real-IPv6
  passthrough, invalid-input rejection unchanged, normalized output re-verified
  against Contract A's actual pattern), wired into `run_all_tests.sh`. Full suite:
  **ALL TESTS PASS**, no regressions.
- **Live re-verification (`splunk_eval.py` before → after):**
  - Splunk deadletters: **5 files → 0 files.** Every previously-dropped event now
    validates and reaches the detection engine.
  - `purplesharp_valid_users_kerberos_xml`: bruteforce **FN → TP** (fired, matches
    oracle).
  - Confusion matrix: bruteforce TP 2→3, FN 6→5. Zero new false positives
    introduced (spray/lateral/priv_grant/after_hours unchanged at 0 FP).
  - **Correction to the original audit split:** of the 6 original brute-force FNs,
    only 1 (`valid_users_kerberos`) was actually caused by the IPv6 dead-letter —
    the other 4 originally-attributed Kerberos sets (`invalid_users_kerberos`,
    `disabled_users_kerberos`, `multiple_users_from_process`, plus both NTLM sets)
    carry `IpAddress="-"` (no source IP at all, not a malformed one) and are P0-2's
    sourceless-auth gap, not this bug. The **deadletter count (5→0) is still fully
    attributable to this fix** — those 5 dropped files included non-bruteforce-rule
    events too (the fix is correct and complete); the *false-negative* count moving
    only 6→5 reflects that most of the FNs were always P0-2, not P0-1.
- **Remaining after this fix:** 5 brute-force FNs, all `IpAddress="-"` — tracked as
  **P0-2** below.

### P0-2 — Per-IP brute/spray rules blind to sourceless (local NTLM/Kerberos) auth failures `[MED]` — ✅ DONE (2026-07-21)

- **Evidence (before fix):** Splunk `purplesharp_invalid_users_ntlm`, `valid_users_ntlm`,
  `invalid_users_kerberos`, `disabled_users_kerberos`, `multiple_users_from_process`
  — 50+ 4625/4771 events each with `IpAddress="-"` (local auth, no network source
  recorded). Parser correctly yields no `src_endpoint.ip`; `common_bruteforce`
  groups by `src_endpoint.ip` → `group_value is None` → fail-closed no count →
  **5 of the 6 original FNs** (re-measured after P0-1 landed; was reported as 2 in
  the initial audit — see P0-1's correction note above). This was a coverage gap,
  not a code defect (fail-closed is correct behavior for the existing rule).
- **Fix applied — companion rule, not a group-key change to the existing rule:**
  [`contracts/rules/common_bruteforce_sourceless.yml`](../../../contracts/rules/common_bruteforce_sourceless.yml).
  Groups on `src_endpoint.hostname` (the field `active_directory.py` populates from
  `WorkstationName` if present, else `Computer` — the target host), distinct-counts
  `actor.user.name`, threshold 5 within 120s. Chose the "fall back to target host"
  option over "group by account" because the real data (Splunk purplesharp) is
  username-enumeration-shaped: 50 DISTINCT accounts, each tried once, against ONE
  host — grouping by account alone would never cross a per-account threshold. Left
  `common_bruteforce.yml`/`common_password_spray.yml` untouched (lower risk than
  editing a widely-relied-on existing rule); this is strictly additive detection
  coverage. Does not pool unrelated hosts — grouping is on the real hostname value,
  not a shared None/placeholder bucket (verified explicitly, see tests below).
  Passes both CI gates: `tools/validate_rules.py` (schema/mitre) and
  `tools/check_rule_producers.py` (anti-dormancy).
- **Tests added:**
  [`services/ws4-detection/test_p0_2_sourceless_bruteforce.py`](../../../services/ws4-detection/test_p0_2_sourceless_bruteforce.py)
  — fires on the real `active_directory.py` parser's output shape; proves (a) 5
  distinct accounts against one host fires, 4 does not, (b) one account repeated
  6x does NOT fire (distinct-count gate, not raw-count — that's the existing
  rules' job), (c) 3+3 distinct accounts split across TWO different hosts does
  NOT pool into one false alert. Wired into `run_all_tests.sh`. Full suite:
  **ALL TESTS PASS**, no regressions.
- **Live re-verification (`splunk_eval.py`/`evtx_eval.py` before → after, oracle
  extended with the same group-by-hostname/distinct-account logic the rule uses):**
  - `bruteforce_sourceless`: **TP=7, FN=0, FP=0** across both corpora — every one
    of the 5 previously-missed files now fires correctly, with zero false alarms
    on any of the other 20 files.
  - **Confusion matrix is now clean everywhere: mismatches=0** (Splunk and EVTX
    both). Also caught and fixed a flaw in the oracle itself while verifying: it
    had been pooling sourceless failures under a shared `IpAddress="-"` bucket for
    `common_bruteforce`'s ground truth — exactly the placeholder-pooling
    anti-pattern this fix's own rule was written to avoid. Corrected the oracle to
    mirror the engine's real fail-closed semantics (`_real_ip()` in
    `evtx_eval.py`), which is what took the mismatch count to true zero.
- **Combined P0-1 + P0-2 result:** the 6 original brute-force false negatives on
  real red-team data are **fully closed**: 1 by the IPv6 fix, 5 by this new rule.
  Zero false positives introduced by either fix.

### P0-3 — Parser coverage is 9% of Security events; zero Sysmon `[MED, scope]` — ✅ DONE (2026-07-21)

- **Evidence (before fix):** EVTX corpus — 1,116 of 1,226 Security records
  unparsed; the bulk of both corpora is `Microsoft-Windows-Sysmon/Operational`
  (process/network/registry), entirely unhandled.
- **Fix applied:** [`services/ws2-normalization/parsers/sysmon.py`](../../../services/ws2-normalization/parsers/sysmon.py)
  — EventID 1 (ProcessCreate) → 1002 Kernel/Process; EventID 3 (NetworkConnect)
  → 4001 Network Activity (always activity 7/Accept — Sysmon only logs
  established connections); EventID 11 (FileCreate) → **1001 File System
  Activity, the first-ever producer** for a class `contracts/detection-
  coverage.md` had documented as a total gap since v0.3. EventID 13
  (RegistryValueSet) deliberately left unmapped — no clean fit in Contract A's
  restricted profile, an honest gap rather than a forced wrong mapping (same
  convention as `agent_tool_call_burst.yml` shipping with no MITRE tag).
  Registered in `parsers/__init__.py` with an explicit content-sniff
  discriminator (Sysmon's EventID space is numerically disjoint from
  Security's, verified) so a sysmon-shaped payload without an explicit
  `source_type` doesn't silently fall through to `windows_eventlog`'s
  catch-all and dead-letter.
- **Tests:** [`test_sysmon.py`](../../../services/ws2-normalization/parsers/test_sysmon.py)
  (7 tests: all 3 mapped event types validate against Contract A, unmapped
  EventID 13/9999 return None cleanly, malformed input never raises,
  out-of-range port dropped not crashed, content-sniff routing verified).
  `ALL TESTS PASS`; `tools/validate_contract.py`/`check_rule_producers.py`
  green (26 rules, 15 parsers).
- **Live re-verification (`evtx_eval.py`, extended to track the Sysmon
  channel separately from Security so the "9%" baseline stays honestly
  comparable):**
  - **Combined Security+Sysmon coverage: 9.0% → 32.4% (3.6x).**
  - `sysmon_supported=873/1805` (48.4% of the Sysmon channel itself — the 3
    mapped EventIDs out of the ~7 that appear in real captures, 1/3/7/10/11/12/13).
  - **Zero new false positives**: confusion matrix stayed clean
    (`mismatches=0`) even as files-with-supported-records jumped 20→117 (5.85x
    more files now contribute data) — the new parser integrates without
    corrupting existing detection behavior.
  - `contracts/detection-coverage.md` updated: class 1001's "no producer"
    gap closed, three producer entries added, an honest "under-covered"
    note added for 1001 (zero rules yet — the parser just landed) and the
    unverified sysmon→port-scan/beaconing producer pairing.
- **Effort:** L (as estimated).

---

## P0 — Infra robustness (proven under live load)

### P0-4 — Single-threaded UDP listener drops silently at the kernel `[HIGH]` — ✅ DONE (2026-07-21)

- **Evidence (before fix):** live — 7,352 EPS offered, ~500 admitted, **`RcvbufErrors=62466`**
  in `/proc/net/snmp`, while ws1 `events_shed=0 events_dropped=0`. The 2000/s token
  bucket and the disk spool **never engage** because the datagrams are dropped
  below the app; the operator gets no signal.
- **Root cause:** `socketserver.UDPServer` = serial one-at-a-time dispatch; each
  handler did a blocking `bus.produce` RTT + a per-datagram `log.info` flush.
- **Fix applied (all 4 layers):**
  [`services/ws1-collectors/collectors/syslog_udp_server.py`](../../../services/ws1-collectors/collectors/syslog_udp_server.py)
  rewritten from `socketserver.UDPServer` to a raw socket with (1) a dedicated recv
  thread doing nothing but `recvfrom` + a non-blocking `queue.put` (never touches the
  bus, so it drains the kernel buffer as fast as the kernel can fill it) handing off
  to a fixed pool of worker threads (`SYSLOG_UDP_WORKERS`, default 4) running the
  unchanged token-bucket/spool/`bus.produce` logic; (2) `SO_RCVBUF` raised to 8MB
  by default (`SYSLOG_UDP_SO_RCVBUF`, best-effort); (3) the per-datagram `log.info`
  removed (`events_produced` already counts the same fact on `/metrics` without the
  per-event JSON-dumps + stdout-flush tax); (4) `udp_rcvbuf_errors()` reads
  `/proc/net/snmp`'s `RcvbufErrors` and is now exposed on `/metrics` under
  `syslog_udp.udp_rcvbuf_errors_cumulative`, alongside a new
  `events_queue_full` counter for the (now bounded, now honestly counted) case
  where the worker pool itself is saturated — a third, distinct drop reason
  from token-bucket shedding and bus-produce failure.
- **Tests:** all 18 pre-existing
  [`services/ws1-collectors/test_syslog_udp.py`](../../../services/ws1-collectors/test_syslog_udp.py)
  tests pass unchanged against the rewrite (same public behavior contract:
  shedding, spool fallback, accounting invariants). `ws1-collectors/test_contract.py`
  also green.
- **Live re-verification (real Docker stack, identical flood to the original
  finding — 8 threads × 1000pps × 10s, ~7,350 offered EPS):**
  - **Admitted throughput: 498 → 1,232 EPS (+147%).**
  - **Kernel loss is now VISIBLE, not just reduced:** `udp_rcvbuf_errors_cumulative`
    read **21,288** via `/metrics` during the same run that previously reported
    `events_shed=0 events_dropped=0` with zero clue anything was wrong. The new
    `events_queue_full=19,857` accounts for the app-layer overload distinctly from
    kernel-layer loss — every datagram is now attributable to a specific,
    instrumented cause, not silently vanishing.
  - **Clean-zone floor genuinely lifted, confirmed at ~794 EPS sustained:** zero
    new `events_queue_full`, zero new `udp_rcvbuf_errors_cumulative` — offered
    exactly equals admitted. (The original audit's clean baseline was ~300 EPS.)
  - Honesty note: at sustained offered load far above any real capacity (7,350
    EPS is a synthetic stress level, not a claim about production traffic), some
    loss is unavoidable and expected — no unbounded queue is the right fix for
    genuine sustained overload. What changed is the ceiling (nearly 2.5x) and,
    more importantly, that every drop is now counted and attributed correctly
    instead of vanishing invisibly below the application.
- **Effort:** M (as estimated).

### P0-5 — Redis streams never trimmed → unbounded memory `[HIGH]` — ✅ DONE (2026-07-21)

- **Evidence (before fix):** live — after full consumption+ack, `raw.events` XLEN
  stayed at 7968 (never shrank); `used_memory` climbs monotonically across all
  topics.
- **Root cause:** no `XTRIM`/`XDEL` for acked entries anywhere except the DLQ tool.
  The "no MAXLEN" audit rationale only justifies not dropping *unconsumed* entries;
  it does not justify retaining *acked* ones forever.
- **Fix applied:** [`services/shared/bus.py`](../../../services/shared/bus.py)
  `_RedisBus.trim_acked(topic)` — computes a SAFE boundary as the minimum, across
  every consumer group currently registered on the stream, of (a) that group's
  smallest still-PENDING entry id if it has any, else (b) the id just past its
  `last-delivered-id` (advanced by one, since `XTRIM MINID` is inclusive-keep —
  an off-by-one caught live during verification, see below), then
  `XTRIM MINID <boundary>`. A topic with zero consumer groups is left untouched.
  `_MemoryBus.trim_acked` is a documented no-op (no PEL/retained history to trim).
  Wired into a new [`services/shared/runner.py`](../../../services/shared/runner.py)
  `start_stream_reaper()` (mirrors `start_depth_watchdog`'s shape), called from
  [`services/ws3-indexer/main.py`](../../../services/ws3-indexer/main.py) covering
  the full `bus-topics.md` topic list (any one service can run it — `trim_acked`
  queries Redis's global `XINFO GROUPS`/`XPENDING`, not caller-local state — so one
  reaper suffices; `.deadletter` topics excluded).
- **Tests added:**
  [`services/shared/test_bus_trim_acked.py`](../../../services/shared/test_bus_trim_acked.py)
  (live-Redis-required, cleanly SKIPs otherwise, same convention as
  `test_runner.py`): proves a topic with zero groups is never touched, a fully-acked
  topic trims to 0, and — the core safety property — a group with genuinely pending
  entries blocks the trim at exactly its earliest pending id even when another group
  on the same topic is fully caught up (verified the specific still-pending entry
  remains present and reclaimable afterward). Wired into `run_all_tests.sh`
  (MemoryBus no-op path) **and** into CI's `redis-integration` job + `make
  test-live` (the RedisBus paths, which need a real broker — see Test-data
  integration note below on why this matters).
- **Live E2E re-verification (real Docker stack, not just the unit test):**
  reproduced the exact original symptom (UDP flood → `raw.events` frozen at 6567
  post-drain), then ran the fix inside the running `ws3-indexer` container against
  the real Redis: `raw.events` depth **6567 → 0**; `normalized.events`/
  `scored.events` partially trimmed in exact proportion to real consumer progress
  (proving the safety property holds under live multi-consumer-group traffic, not
  just synthetic tests). Also confirmed the background reaper thread fires
  autonomously inside the running service (`"trimmed acked stream entries"` log
  line observed without any manual intervention).
- **Effort:** M (as estimated).

---

## P1 — Isolation & correctness

### P1-1 — Non-stateful `alert_key` omits tenant_id → cross-tenant alert_id collision `[MED]` — ✅ DONE (2026-07-21)

- **Evidence (before fix):** confirmed by code read + independent reviewer.
  `services/ws4-detection/engine.py`'s non-stateful `alert_key` branch returned
  `f"{self.id}:{ingest}"`; the stateful branch was tenant-namespaced by the F1
  follow-up, this one was not. Two tenants whose ingest-less events share a
  content fingerprint (the `sha:` fallback) — or simply reuse the same
  `ingest_id` — got the SAME alert_id;
  [`storage/opensearch.py:97`](../../../services/ws3-indexer/storage/opensearch.py) `_search_alert`
  queries `alerts-*` by `_id` and returns the first hit → one tenant's alert
  shadows the other's under `find_alert`-by-id. Tenant-scoped indices don't save
  it (collision is on the lookup id, not physical location).
- **Fix applied:** [`services/ws4-detection/engine.py`](../../../services/ws4-detection/engine.py)
  now returns `f"{self.id}:{tenant}:{ingest}"`, unconditionally including tenant
  (defaulting to `"default"`) — matching the stateful branch's own format exactly,
  no special-casing.
- **Tests:** new
  [`services/ws4-detection/test_p1_1_alert_key_tenant.py`](../../../services/ws4-detection/test_p1_1_alert_key_tenant.py)
  proves the actual bug is closed (two tenants reusing the same `ingest_id`, or
  sharing identical content with no `ingest_id`, now get distinct alert_ids),
  plus same-tenant idempotency and the no-tenant-key default-tenant fallback are
  unaffected. Two pre-existing tests asserted the OLD exact string format
  (`test_engine_boolean.py`, `test_engine_hardening.py`) — updated to the new
  format rather than left broken. Wired into `run_all_tests.sh`. `ALL TESTS PASS`.
- **Effort:** S (as estimated).

### P1-2 — 20–59 "light classifier" band routes nowhere `[LOW, correctness/doc]` — ✅ DONE 2026-07-22

- **Evidence:** [`contracts/scoring.yaml:8`](../../../contracts/scoring.yaml) defines
  `classifier_min: 20` and `sigma-convention.md:94` claims "20–59 → light
  classifier (WS-5 layer 2)", but [`services/ws4-detection/main.py:129`](../../../services/ws4-detection/main.py)
  enqueues `ai.requests` only when `action == "llm"` (≥60). Scores 20–59 are
  indexed and never classified — the band is dead.
- **Fix:** decide and align: either wire the 20–59 band to the WS-5 classifier
  (`classifier.py` exists and is invoked per-event inside WS-5 already, per the
  INTERFACE audit — confirm the routing), or delete the band from `scoring.yaml`
  and correct `sigma-convention.md`. Do not leave config promising a path the code
  doesn't take.
- **Effort:** S (doc/config) or M (wire the route).
- **Resolution (2026-07-22):** wired, not deleted. `Scorer.route()` already computed
  `action=="classifier"` correctly for 20-59; `ws4-detection/main.py` only ever
  checked `action=="llm"`. Fixed: both `detect_one()` and `run()` now enqueue
  `action in ("llm","classifier")` to `ai.requests` with a new `tier` field.
  `ws5-ai/main.py`'s `AiWorker.handle()` branches on `tier`: `"classifier"` runs
  ONLY `LightClassifier.predict()` (no LLM call at all -- calling the LLM on
  every 20-59 event would defeat the entire point of a cheap second tier);
  `"llm"` (or missing `tier`, back-compat) is the unchanged full-triage path. The
  classifier tier's alert carries no fabricated `ai` (verdict) block, only
  `classification`. New `services/ws4-detection/test_p1_2_classifier_band.py`
  proves all three links end-to-end on a real rule (`agent_prompt_injection_
  indicator.yml`, score 50): action, `tier=classifier` on the wire, and — via an
  LLM stand-in that raises if ever called — that WS-5 never invokes the LLM for
  that tier. `ALL TESTS PASS`.

---

## P1 — Performance (the live EPS ceiling)

All measured/predicted against the live stack; the ~500 EPS pipeline ceiling is
dominated by per-event connection churn, not parse/detect CPU (the 13k-EPS
zero-infra baseline proves the Python work isn't the limiter).

| ID | Location | Fix | Effort |
|---|---|---|---|
| P1-3 | ✅ **DONE 2026-07-21** — `ws2 main.py`, `ws4 main.py` — `Bus()` per event → new redis client per event on the redis backend | ONE `Bus()` constructed per worker at handler-setup time, closed over (each service consumes exactly one topic → one worker thread, so no cross-thread sharing risk) | S |
| P1-4 | ✅ **DONE 2026-07-21 (partial, honestly scoped)** — one HTTP PUT per doc, new TCP each, no keep-alive; double-indexes normalized+scored | Persistent `http.client` connection (all call sites) + real `bulk_index()` `/_bulk` API, wired into the batch/tooling path (`run()`). Cross-message batching in the live daemon (which would also fix the double-index) is a separate, NOT-attempted change — see detail below | M |
| P1-5 | ✅ **DONE 2026-07-21** — `ws4-detection/window.py` — deque dedup `any(m==member ...)` O(n) → O(n²) under single-source burst (the exact brute-force traffic) | `_live_members: dict[str, set]` mirrors non-None members per key for O(1) lookup/evict; correctness relies on the existing dedup invariant (a member appears at most once live) | S |
| P1-6 | ✅ **DONE 2026-07-21** — `ws1-collectors/collectors/spool.py` — `remaining=remaining[1:]` O(n²) reslice + lock held across `produce()` network I/O | Single-pass index + one final slice (O(n)); lock released across `produce()`, re-acquired only to reconcile against concurrent `append()`s (safe: only one drain thread exists, snapshot is a stable file prefix) | S |
| P1-7 | ✅ **DONE 2026-07-21** — depth watchdog used `XLEN` (retained acked entries) not consumer lag → false-warns forever after 100k lifetime events | `_RedisBus.lag(topic)`: MAX across consumer groups of (native `XINFO GROUPS` `lag` [undelivered] + `XPENDING` pending count [delivered-unacked] — both summed, not either/or, see below) | S |
| P1-8 | ✅ **DONE 2026-07-21 (partial, honestly scoped)** — `bus.py` per-message XADD/XACK, no pipelining; `count=10` batch | Raised `XREADGROUP count` to a configurable 100 (`BUS_XREADGROUP_COUNT`) — safe, zero ack-semantics change. XACK/XADD pipelining NOT attempted — would require touching `_process_message`'s shared contract across 3 call sites (daemon, `claim_pending`, `run_once`); same class of deferred decision as P1-4's daemon batching | S |

**P1-7 detail:** `services/shared/bus.py` `_RedisBus.lag()` + `start_depth_watchdog`
in `services/shared/runner.py` switched from `bus.depth()` to `bus.lag()`.
**A real design bug caught live during verification, not just implemented
blind:** an earlier version used native `lag` (undelivered count) *or*
`XPENDING`'s pending count, whichever was available — but those measure
different things (undelivered vs. delivered-but-unacked) and must be
**summed**; using `lag` alone silently reported 0 backlog for a group that had
read everything but acked nothing. Caught by
[`services/shared/test_bus_lag.py`](../../../services/shared/test_bus_lag.py)'s
live-Redis "genuinely behind" case failing (`got 0`, expected ~30), fixed, and
re-verified live. That test suite also proves the core fix live: a topic with
500 lifetime entries, all consumed and acked, reports lag ≤5 (not 500) —
the exact false-positive this closes. `test_runner.py`'s existing depth-watchdog
test updated for the renamed log kwarg (`depth=`→`backlog=`). Wired into
`run_all_tests.sh`, CI's `redis-integration` job, and `make test-live`.

**P1-3/P1-5/P1-6 tests:** `ALL TESTS PASS`, plus targeted proofs — window.py's
fix: [`test_window_perf.py`](../../../services/ws4-detection/test_window_perf.py)
(20k unique-member hits into one group complete near-linearly — measured
1.15M hits/sec sustained; a reintroduced O(n²) scan would take far longer at
this n; also proves eviction correctness and idle-key sweep of the new
`_live_members` structure). spool.py's fix:
[`test_spool_perf.py`](../../../services/ws1-collectors/test_spool_perf.py)
(20k-entry drain stays fast; **the core safety property** — a concurrent
`append()` completes in <1s while a deliberately-blocked `produce()` is in
flight, proving the lock is genuinely released, not just faster; a
concurrently-appended event during a drain is never silently lost). Bus()-per-
worker (P1-3): verified via full-suite + `tools/integration_e2e.py` pass
(both changed files consume exactly one topic each, so one `Bus()` per
worker is safe — no new test needed beyond the existing behavior suite,
which is unaffected by the change).

**P1-4 detail:** [`services/ws3-indexer/storage/opensearch.py`](../../../services/ws3-indexer/storage/opensearch.py)
rewritten from per-call `urllib.request.urlopen` to a persistent
`http.client.HTTPConnection` kept open on `self` (one reconnect-and-retry on
a stale/closed keep-alive, transparent to every existing caller — connection
failures still surface as `urllib.error.URLError` so `index()`'s own retry
loop needed no changes). New `bulk_index()` method builds the real `/_bulk`
NDJSON request and parses per-item `created`/`errors` from the response.
Wired into `services/ws3-indexer/main.py`'s `run()` (the batch/tooling path —
`tools/integration_e2e.py`, `demo_e2e.py`, tests) via a `getattr(store,
"bulk_index", None)` capability check, so `MemoryStore` (used by every
zero-infra test) takes the byte-identical old per-doc code path — zero risk
to the existing suite. **Deliberately not attempted:** cross-message
batching in the live daemon's `handler()`, which acks each message
individually right after its own call returns (`shared/runner.py`'s
`_process_message`) — the completeness-critical mechanism behind at-least-
once redelivery. Batching across multiple messages before acking any of
them needs a runner-level redesign (buffer, bulk-index, ack-all-together,
handle a partial-bulk-failure correctly) this pass does not risk for a perf
win; this is also why the normalized.events/scored.events double-index
isn't fixed here — it's a daemon-path phenomenon, and the safe half of this
fix doesn't touch the daemon's per-message indexing at all.

**Tests:** [`test_bulk_index.py`](../../../services/ws3-indexer/test_bulk_index.py)
(zero-infra, fake-connection: empty-batch no-op, NDJSON request shape,
**partial-failure parsing** — the core correctness property, since `/_bulk`
returns 200 even when some items failed — and a 503-level failure still
raises). `storage/test_opensearch_live.py` extended with a live round-trip
test (25-item bulk insert verified via `count()`, plus an explicit assertion
that the SAME connection object survives across `index()`/`bulk_index()`/
`count()` calls — proving reuse, not just functional correctness).
**Live-verified against a real OpenSearch 2.13 cluster:**
`bulk_index()` of 50 docs took 0.437s vs 1.100s for 50 individual `index()`
calls (2.5x, on localhost — the gap widens with real network latency);
`run()`'s `bulk_index` path exercised end-to-end through a real
`make_store()`/`OpenSearchStore` and confirmed correct. Also fixed a
pre-existing test race in `test_opensearch_live.py` (a `count()` assertion
with no refresh-settle wait, which the faster connection-reused code made
newly likely to flake) — added the same explicit `_refresh` already used
elsewhere in that file.

**P1-8 detail:** `services/shared/bus.py` `_RedisBus.__init__` now reads
`BUS_XREADGROUP_COUNT` (default 100, was hardcoded 10) for `consume()`'s
`XREADGROUP count=`. **Tests:**
[`test_bus_read_count.py`](../../../services/shared/test_bus_read_count.py)
(live-Redis-required, same convention as the session's other `_RedisBus`
tests): default value, env override, and the actual win — draining 250
messages took **4 XREADGROUP calls at count=100 vs the ≥25 the old count=10
would have needed** (measured live, ~6x fewer read round-trips). Wired into
`run_all_tests.sh`, CI's `redis-integration` job, and `make test-live`.
XACK/XADD pipelining deliberately not attempted — `bus.ack()` is called
directly from `shared/runner.py`'s `_process_message`, shared by the live
daemon, the `claim_pending` redelivery path, and `run_once()`; batching acks
safely across all three call sites needs the same kind of contract change
P1-4's daemon-batching deferral avoided, for the same reason.

---

## P2 — Hardening & smaller findings

| ID | Location | Problem → Fix | Effort |
|---|---|---|---|
| P2-1 | `ws4-detection/tenants.py` `_CACHE` | Unbounded growth per distinct `siem.tenant` string (memory DoS via random tenant values) → bound with an LRU / reject invalid tenants at edge before caching | S | ✅ DONE |
| P2-2 | `tools/fengarde_bench.py:38` | `import resource` is Unix-only → crashes on Windows (the dev host); README numbers not reproducible there → guard the import, fall back to `psutil`/skip RSS on Windows | S | ✅ DONE |
| P2-3 | `services/shared/log.py:47` | Every record JSON-dumped + stdout-flushed synchronously, no level filter → add a level gate so per-event info logging isn't a hot-path tax | S | ✅ DONE |
| P2-4 | `runner.py:171` | `traceback.print_exc()` per failed message → a poison flood becomes an stderr flood; throttle/aggregate | S | ✅ DONE |
| P2-5 | `ws3-indexer/triage_api.py` write lock | Process-wide lock held across OpenSearch search+CAS network I/O (up to ~60s under a slow cluster) → the CAS loop is already the cross-writer guard; don't hold the lock across I/O | M | ✅ DONE |
| P2-6 | `ws6-inventory/store.py` | No SQL indexes on `ip_history`/`protocols`; N+1 hydrate; per-upsert fsync → add indexes, batch commits | S | ✅ DONE (partial/honest scope) |

---

## Documentation & discrepancy fixes — ✅ ALL DONE (2026-07-21)

These are the "logic vs docs" gaps the audit found. None are code bugs; all were
trust-of-docs issues. **Note:** by the time this pass landed, concurrent unrelated
work had already moved the rule count from 19 (original audit) to 25, and this
session's own P0-2 added a 26th (`common_bruteforce_sourceless.yml`) — every fix
below targets the CURRENT ground truth (re-verified at fix time), not the
audit's original numbers.

| ID | Fix |
|---|---|
| D-1 | ✅ **Rule/parser counts corrected to current ground truth (26 rules, 14 parsers)** — `SSOT.md §1`, `README.md`, `docs/vs.md` (was stuck at 17/19 depending on doc; two occurrences in `vs.md` alone) |
| D-2 | ✅ **CHANGELOG gained its two missing milestones** — added `### Added (M4 — MSP-grade)` and `### Added (M5 — NIS2 public template layer)` sections (sourced from SSOT.md's own detailed M4/M5 rows), plus a `### Added (post-merge CI hardening, PR#2 → main)` section (CodeQL 5-alert fix, 3 new CI gates, supply-chain pinning, Dependabot removal) and corrected the stale `make chaos` entry ("not yet run" → live-verified `scenarios=40 lost=0 duplicated=0`) |
| D-3 | ✅ **Kafka claim corrected in the frozen contract** — `contracts/bus-topics.md`'s two Kafka mentions ("Kafka in prod" / "swappable to Kafka") rewritten to match `bus.py`'s own docstring: Redis is the only implemented backend (dev AND prod), Kafka is an unimplemented candidate |
| D-4 | ✅ **INTERFACE.md contradictions fixed, all 4 services**: ws5 (`classifier.py` IS implemented + wired, but the 20-59 score band never actually reaches it — P1-2, documented precisely); ws6 (WS-2 enrichment does NOT call the inventory API — was falsely claimed); ws3 refreshed (report route, `/api/v1`, auth+CSRF, webhooks, tenant-conditional index naming, OpenSearchStore now live-tested not skeleton); ws7 refreshed (`templates/default.conf.template` replaces the old `nginx.conf` reference, `/api/report`, `/api/auth/`, login gate + CSRF) |
| D-5 | ✅ **SSOT §2 evidence pointer fixed** — now points to `Rule.alert_key()` by name (not a line number, which had already rotted once) in `engine.py`; also notes both branches are now tenant-namespaced (P1-1) |
| D-6 | ✅ **Marketing precision** — README tagline: "NIS2/DORA evidence" → "draft NIS2 incident notifications" (dropped "DORA" entirely — the product's own generator explicitly disclaims DORA applicability for financial entities, so claiming it in the tagline contradicted the product itself). Heading "v0.3 shipped, v0.4 in progress" → "v0.1-v0.5 shipped". Added a Multi-tenancy/RBAC/webhooks/plugins capability row (was completely absent from the table despite shipping in M4). Security section's "not a full identity/RBAC system" corrected — real opt-in RBAC exists |
| D-7 | Already reconciled — re-verified: every one of the 26 shipped rules has a row in `detection-coverage.md`'s producer-status table (initial audit finding was itself stale by the time this pass ran; no action needed) |

**Verification:** `ALL TESTS PASS` (docs-only changes, but re-ran the full suite plus
`tools/validate_contract.py` / `tools/validate_rules.py` / `tools/check_rule_producers.py`
since `contracts/bus-topics.md` and `contracts/detection-coverage.md` were touched —
all green, 26 rules validated).

---

## Test-data integration (make the eval reproducible) — ✅ DONE 2026-07-21

The audit's two accuracy harnesses should become a repeatable eval lane rather
than one-off scratchpad scripts:

**Status:** `eval/detection_accuracy/evtx_eval.py` + `splunk_eval.py` are folded
into the repo (paths made relative/portable, no more hardcoded scratchpad/`C:\sa\`
paths), plus a `README.md` documenting both corpora's licenses and fetch commands,
and a `make eval-detection` target. Both scripts SKIP CLEANLY (print `[SKIP]`,
exit 0) when their dataset directory (or `python-evtx`) isn't present — verified
by running both with no datasets fetched. Datasets themselves are gitignored, not
vendored (GPL-3.0 for EVTX-ATTACK-SAMPLES; splunk/attack_data has its own terms) —
matches this section's original "link + download... rather than vendoring" plan.
Deliberately NOT wired into `run_all_tests.sh`/CI (see the new README's "Running"
section for why a corpus-gated eval doesn't belong in the always-green zero-infra
gate).

- Add `eval/detection_accuracy/` with `evtx_eval.py` + `splunk_eval.py` (the
  independent-oracle replay), a small **committed** fixture subset (a handful of
  license-compatible EVTX/XML samples — mind EVTX-ATTACK-SAMPLES is GPL and Splunk
  `attack_data` is its own license; link + download in CI rather than vendoring if
  licenses require), and a `make eval-detection` target.
- The oracle is the valuable part: it independently recomputes brute/spray/
  lateral/priv-grant/after-hours ground truth from raw records, so it catches
  regressions the unit tests can't (e.g. it's what surfaced the 6 brute FNs).
- Wire a reduced run into CI as a non-blocking report first; promote to a gate once
  this eval lane is folded into the repo (the confusion matrix is already clean —
  P0-1 + P0-2 landed 2026-07-21, mismatches=0 on both corpora, re-confirmed live).
- The ATT&CK technique is already encoded in both corpora's paths (Splunk
  `attack_techniques/T1110.003/...`, EVTX by tactic folder), so the oracle harness
  can emit **per-technique** fired/not-fired for free — the input to P3-2's empirical
  coverage scorecard below.

---

## P3 — External / industry-standard evaluation (adversary emulation + ATT&CK scorecard)

FENGARDE already *declares* ATT&CK per rule — 18 of 19 `contracts/rules/*.yml` carry a
`mitre:` block (validated by `tools/validate_rules.py`; `agent_tool_call_burst.yml` is
the one gap), and `contracts/detection-coverage.md` maps rules to a technique/tactic.
What's missing
is (a) empirical proof that a real execution of each technique fires the mapped rule,
and (b) an exportable coverage scorecard. This section adds that, plus SigmaHQ-parity CI.

### P3-1 — Adversary-emulation eval (Atomic Red Team primary) `[L, prereq-gated]` — ⏸ DEFERRED

**Not attempted in this pass.** This item needs a real Windows test host to
run Atomic Red Team atomics on, plus a live forwarder wiring that host's
Sysmon/Security channel into WS-1 — infrastructure this pass had no access to
(the same "fail once, flag, move on" posture as any other unavailable
external dependency). Everything else in this plan that COULD be done
zero-infra or against already-available corpora was; this is the one
remaining item that genuinely requires provisioning new infrastructure
outside this repo. Runbook below is still accurate as a spec for whoever
picks this up with host access.

- **Goal:** run real technique playbooks against a test host, route the resulting logs
  through the live pipeline, and measure which techniques actually fire an alert.
- **Primary tool — Atomic Red Team** (github.com/redcanaryco/atomic-red-team): per-technique
  "atomics" map 1:1 to the T-codes already in the rules' `mitre:` blocks. Prioritize the
  techniques the pipeline claims: T1110 / T1110.003 (brute/spray), T1021 (lateral),
  T1098 (priv-group grant), T1078 (valid accounts / after-hours), T1485 (destruction),
  T1552 / T1071 / AML.T0051 (agent rules), T1046 (port scan).
- **Heavier option — MITRE Caldera** (github.com/mitre/caldera): chained multi-step
  operations and threat-group profiles, for realism once per-technique coverage is green.
- **Wiring:** attacks run on a Windows test host → Sysmon + Security channel forwarded
  (WEF or a syslog/JSON forwarder) → WS-1 syslog ingest → normal pipeline.
- **Prerequisite:** primarily **gated on P0-3 (Sysmon parser)** — the pipeline
  still parses ~9% of Security events and no Sysmon, so a full emulation would
  score artificially low for *parsing* reasons, not detection reasons. (P0-4,
  ingest silently dropping under load, is done as of 2026-07-21 — no longer a
  gating concern, though a sustained-emulation run should still watch
  `udp_rcvbuf_errors_cumulative`/`events_queue_full` on `/metrics` as a sanity
  check.) Start now with the Security-channel atomics current parsers DO cover
  (4625/4624/4728/4732/4672) for an honest *partial* scorecard; expand as P0-3
  lands.
- **Metric:** ATT&CK coverage = `techniques_fired / techniques_attempted`, sliced by
  tactic — e.g. "alerts on X% of Credential Access and Y% of Persistence atomics that
  reach the pipeline." Keep "attempted" scoped to techniques whose telemetry the parsers
  can see, and state that scope on the scorecard.
- **Test/deliverable:** `eval/attack/emulation_runner.py` + a documented runbook; a CI
  smoke variant that replays a few captured atomic-output samples (no live host needed).

### P3-2 — ATT&CK coverage scorecard + Navigator layer export `[S, doable now]` — ✅ DONE (declared half)

Two separate, honestly-labeled numbers:
- **Declared coverage** — parse every rule's `mitre.technique` → emit a MITRE ATT&CK
  Navigator layer JSON (scored heatmap). Pure metadata, zero prerequisites, buildable
  today. Tool: `eval/attack/coverage_layer.py`.
- **Empirical coverage** — from P3-1 emulation runs **and the existing oracle eval**:
  the corpora already encode the technique in their paths (Splunk
  `attack_techniques/T1110.003/...`, EVTX by tactic folder), so `evtx_eval.py` /
  `splunk_eval.py` can emit per-technique fired/not-fired for free. This is the number
  that matters — and it already shows a real hole: T1110.003 brute-force is currently a
  false negative (P0-1), which the scorecard would flag red until P0-1 lands.
- **Deliverable:** `make attack-scorecard` → prints per-tactic coverage and writes a
  Navigator layer viewable at mitre-attack.github.io/attack-navigator. Publish the layer
  as a CI artifact.
- **Effort:** S for declared; empirical folds into the eval lane (Test-data section above).
- **Status (2026-07-21):** Declared half done — `eval/attack/coverage_layer.py` parses
  all 26 rules' `mitre:` blocks (25/26 carry one; `agent_tool_call_burst.yml` is the
  known gap, flagged not silently dropped), emits per-tactic/technique summary JSON,
  and a Navigator layer per framework Navigator actually understands
  (`enterprise-attack`, `ics-attack`; `atlas`-framework rules counted in the summary
  but excluded from the layer export — different visualization tooling/schema, see the
  script's docstring). `make attack-scorecard` target added; `eval/attack/
  test_coverage_layer.py` wired into `run_all_tests.sh` and a new CI job
  (`attack-scorecard`) that also uploads the Navigator layers as a build artifact —
  `ALL TESTS PASS`. Empirical half (a technique's mapped rule actually fires on real
  telemetry) is `eval/detection_accuracy/`'s oracle-replay harnesses (folded into the
  repo below, dataset-gated, not run in CI).

### P3-3 — SigmaHQ-parity rule CI `[S]` — ✅ DONE (Navigator artifact); rest deferred

The repo already has the core of SigmaHQ's rule-CI discipline — `tools/validate_rules.py`
(schema/grammar/`mitre` validation) and `tools/check_rule_producers.py` (anti-dormancy:
every rule has a real producer, no processing dead-ends). Position these explicitly as
the SigmaHQ-equivalent gates in the docs, then adopt what's missing:
- Publish a rule→ATT&CK Navigator layer artifact on every CI run (SigmaHQ does this) —
  reuses P3-2's `coverage_layer.py`. ✅ DONE: CI's new `attack-scorecard` job (see P3-2)
  uploads `eval/attack/out/navigator_layer_*.json` as a build artifact on every run.
- Since rules are Sigma-shaped, add an optional `sigma-cli` / pySigma round-trip test
  that the YAML converts cleanly to a backend query — guards against grammar drift
  breaking parsing (the exact "rule change breaks parsing / causes loops" class SigmaHQ's
  CI defends against). ⏸ NOT attempted — FENGARDE's rule grammar (`engine.py`'s boolean
  evaluator + `group_by`/`distinct_field`/time-predicate extensions) is its own DSL,
  Sigma-*shaped* in the YAML sense but not Sigma-*compatible*; a real pySigma round-trip
  would need a custom backend translating FENGARDE's condition grammar to Sigma's,
  which is new-tooling scope beyond this pass, not a small addition.
- Add a **coverage-regression gate**: fail CI if a rule/parser change drops empirical
  technique coverage below a floor (pairs with P3-2 + the eval lane). ⏸ NOT attempted —
  depends on the empirical eval lane running in CI with real datasets, which
  `eval/detection_accuracy/README.md` explains is deliberately NOT wired into CI
  (third-party corpora, not vendored); a regression gate against a number CI never
  computes isn't a real gate.

---

## Suggested sequencing

1. ~~**P0-1** (IPv6 normalize)~~ — ✅ DONE 2026-07-21: `ocsf.py` fix + `test_ocsf.py`,
   `ALL TESTS PASS`, Splunk deadletters 5→0, one brute FN flipped to TP live.
2. ~~**P0-2** (sourceless NTLM/Kerberos)~~ — ✅ DONE 2026-07-21: new companion rule
   `common_bruteforce_sourceless.yml` + `test_p0_2_sourceless_bruteforce.py`,
   `ALL TESTS PASS`, live confusion matrix now **mismatches=0** on both corpora
   (the remaining 5 of the original 6 brute FNs all flipped TP, zero new FP).
3. ~~**P0-5** + **P1-7** (stream trim + lag metric)~~ — ✅ DONE 2026-07-21:
   `_RedisBus.trim_acked()`/`lag()` + `start_stream_reaper()`, wired into
   ws3-indexer, CI's `redis-integration` job, and `make test-live`.
   `ALL TESTS PASS`; live E2E on the real Docker stack reproduced the original
   frozen-XLEN symptom and proved the fix (`raw.events` 6567→0).
4. ~~**P0-4** (UDP threading + kernel-loss metric)~~ — ✅ DONE 2026-07-21: recv/
   worker-pool split + SO_RCVBUF + `udp_rcvbuf_errors()`/`events_queue_full`.
   All 18 pre-existing tests pass unchanged; live re-flood of the identical
   original scenario: admitted 498→1,232 EPS, kernel drops (21,288) now
   visible on `/metrics` where they were previously invisible, clean floor
   confirmed at ~794 EPS.
5. ~~**P1-1** (alert_key tenant)~~ — ✅ DONE 2026-07-21: tenant-namespaced
   non-stateful `alert_key`, `test_p1_1_alert_key_tenant.py`, `ALL TESTS PASS`.
   ~~**P1-3/P1-5/P1-6** (cheap perf wins)~~ — ✅ DONE 2026-07-21, same pass:
   Bus()-per-worker, O(1) window dedup (1.15M hits/sec, was O(n²)), spool
   drain O(n) + lock released across `produce()` (proven via a deliberately-
   blocked-produce() test). `ALL TESTS PASS` + `tools/integration_e2e.py` green.
   ~~**P1-4** (OpenSearch bulk/connection reuse)~~ — ✅ DONE, same session:
   persistent connection + real `bulk_index()`, wired into `run()`; live
   2.5x faster. Cross-message daemon batching deliberately deferred (see
   P1-4's detail). ~~**P1-8** (XREADGROUP batch size)~~ — ✅ DONE, same
   session: count 10→100 (configurable), live: 250 messages drained in 4
   calls vs ≥25 before. XACK pipelining not attempted (same deferral class).
6. ~~**Docs-sync PR** (D-1..D-7)~~ — ✅ DONE 2026-07-21: all 7 items fixed
   (D-7 was already clean). `ALL TESTS PASS` + contract/rule validators green.
7. ~~**P0-3** (Sysmon parser)~~ — ✅ DONE 2026-07-21: `sysmon.py` (first
   class-1001 producer), `test_sysmon.py`, `ALL TESTS PASS`. Live EVTX
   re-verification: coverage 9%→32.4%, zero new false positives.
   ~~**Eval-lane integration**~~ — ✅ DONE, same pass: `evtx_eval.py`/
   `splunk_eval.py` folded into `eval/detection_accuracy/` with portable
   paths, a README (licenses/fetch commands), `make eval-detection`, both
   verified to skip cleanly with no dataset present.
7b. ~~**P2-1..P2-6**~~ (hardening pass) — ✅ ALL DONE 2026-07-22: tenant cache
    LRU-bounded + invalid-tenant-never-cached (`tenants.py`, `test_tenants.py`
    extended); `shared/log.py` level gate (`FENGARDE_LOG_LEVEL`,
    `test_log.py`); `runner.py` traceback throttling per (topic, exc type)
    (`test_runner_throttle.py`); `triage_api.py`'s process-wide write lock
    removed (CAS alone is sufficient — proven by a real 20-thread concurrent-
    write test against a live `ThreadingHTTPServer`, `test_storage_cas.py`);
    `ws6-inventory/store.py` indexes on `ip_history`/`protocols` + WAL/
    `synchronous=NORMAL` (batched commits across upserts not attempted — no
    existing caller batches observations to batch across). `ALL TESTS PASS`
    after each item; wired into `run_all_tests.sh`.
8. **P3 external eval** — ✅ P3-2 (declared scorecard) + P3-3's Navigator-artifact
   half DONE 2026-07-22 (`eval/attack/coverage_layer.py`, `make attack-scorecard`,
   new CI job uploading Navigator layers). P3-1 (live adversary emulation) and
   P3-3's sigma-cli round-trip / coverage-regression-gate remain deferred — see
   their sections above for exactly why each needs infrastructure or tooling
   this pass didn't have.

## Reality Map

| Item | State | Evidence |
|---|---|---|
| Rule logic correct (no false positives) | DONE / PROVEN | EVTX + Splunk oracle: 0 FP across 32 files |
| Sysmon coverage / class-1001 gap (P0-3) | **DONE / PROVEN (fixed 2026-07-21)** | `sysmon.py` + `test_sysmon.py`; live EVTX coverage 9%→32.4%, mismatches=0 |
| IPv6 dead-letter causes missed brute-force | **DONE / PROVEN (fixed 2026-07-21)** | `ocsf.py` `valid_ip()` normalizes ipv4_mapped; `test_ocsf.py` (5 tests, wired into `run_all_tests.sh`); re-run `splunk_eval.py` shows deadletters 5→0, one FN flipped TP |
| Sourceless-auth (NTLM/Kerberos) brute-force invisible | **DONE / PROVEN (fixed 2026-07-21)** | New rule `common_bruteforce_sourceless.yml` + `test_p0_2_sourceless_bruteforce.py`; re-run oracle shows TP=7 FN=0 FP=0, mismatches=0 on both corpora |
| Kernel UDP drop invisible to app | **DONE / PROVEN (fixed 2026-07-21)** | `udp_rcvbuf_errors()` + `events_queue_full`; live re-flood: throughput 498→1,232 EPS, kernel drops now visible on `/metrics`, clean floor confirmed ~794 EPS |
| Redis streams unbounded | **DONE / PROVEN (fixed 2026-07-21)** | `trim_acked()`/`start_stream_reaper()` + `test_bus_trim_acked.py`; live E2E reproduced the original symptom then proved the fix (`raw.events` 6567→0 on the real Docker stack) |
| Depth watchdog false-warns forever (XLEN not lag) | **DONE / PROVEN (fixed 2026-07-21)** | `_RedisBus.lag()` + `test_bus_lag.py`; live: 500-entry fully-acked topic reports lag ≤5, not 500 |
| Non-stateful alert_key tenant collision | **DONE / PROVEN (fixed 2026-07-21)** | `engine.py` tenant-namespaced to match the stateful branch; `test_p1_1_alert_key_tenant.py` |
| ws2/ws4 per-event `Bus()` connection churn (P1-3) | **DONE / PROVEN (fixed 2026-07-21)** | one `Bus()` per worker now; `ALL TESTS PASS` + `integration_e2e.py` |
| window.py dedup O(n²) under burst (P1-5) | **DONE / PROVEN (fixed 2026-07-21)** | `_live_members` set, O(1); `test_window_perf.py` measured 1.15M hits/sec on 20k unique-member burst |
| spool.py drain O(n²) + lock-across-I/O (P1-6) | **DONE / PROVEN (fixed 2026-07-21)** | single-pass index + lock released across `produce()`; `test_spool_perf.py` proves concurrent `append()` unblocked |
| OpenSearch no-bulk / connection reuse (P1-4) | **DONE / PROVEN (fixed 2026-07-21)** | Persistent connection + `bulk_index()`; live: 2.5x faster (50 docs, localhost); `test_bulk_index.py` + live round-trip test |
| WS-2/scored.events double-index (P1-4 remainder) | OPEN, deliberately deferred | Needs a runner.py ack-model redesign to batch safely across messages; not attempted this pass |
| XREADGROUP batch size (P1-8) | **DONE / PROVEN (fixed 2026-07-21)** | count 10→100 configurable; live: 4 calls vs ≥25 to drain 250 messages |
| XACK/XADD pipelining (P1-8 remainder) | OPEN, deliberately deferred | Same class of ack-model contract change as the P1-4 remainder; not attempted this pass |
| Scorecard 5.6/10 accepted residue | DONE / PROVEN | live API; matches SSOT §1 |
| Rule count 19 vs docs' 17 | OPEN / PROVEN | `contracts/rules/` file count |
| CHANGELOG missing M4/M5 | OPEN / PROVEN | CHANGELOG vs git log |
| ATT&CK declared per rule (`mitre:` block) | DONE / PROVEN | `validate_rules.py` validates it; `detection-coverage.md` maps it |
| ATT&CK empirical coverage (emulation) | OPEN / gated on P0-3+P0-4 | partial today via oracle per-technique output |
