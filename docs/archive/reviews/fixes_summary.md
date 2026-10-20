# Fixes summary — 6-part review swarm follow-up (2026-07-29)

Scope: fix the Critical/High/Medium findings from `review_architecture.md`,
`review_adversarial_security.md`, `review_bugs.md`, `review_code_quality.md`,
`review_performance.md`, `review_design_decisions.md`. Each fix was applied
incrementally with `run_all_tests.sh` green before moving to the next, and a
regression test was added for every fix that didn't already have one.

Full suite status at the end of this pass: **`ALL TESTS PASS`** (zero-infra;
`make test-live` was not run — no live Docker/Redis/OpenSearch available in
this environment, see caveats below).

## Fixed

| # | Finding | Severity | What changed |
|---|---|---|---|
| C1 | `DequeWindowCounter` front-only eviction let out-of-order events stay counted forever | Critical | `hit()`/`hit_distinct()` (`services/ws4-detection/window.py`) now keep the deque time-sorted on insert (sorted re-insert only on a genuine out-of-order arrival; the common in-order case stays O(1) append, so the P1-5 near-linear-burst guarantee is preserved). New tests: `test_window.py`, `test_window_distinct.py` reproduce the exact audit scenario. |
| H1 | WS5 daemon built a fresh `Bus()` per message, silently discarding output on `BUS_BACKEND=memory` | High | `services/ws5-ai/main.py`: hoisted to one `handler_bus` per worker (matches WS-2/WS-4's existing P1-3 fix), extracted `_make_handler()` so the fix is unit-testable. New test in `test_contract.py`. |
| H3 | `MemoryStore.index_cas` check-then-write was unsynchronized — concurrent CAS writes could both report success while one silently lost | High | `services/ws3-indexer/storage/memory.py`: one `threading.Lock` now spans `index()` and `index_cas()`. New `Barrier`-forced-interleaving test in `test_storage_cas.py` proves exactly one writer wins under the race the audit reproduced. |
| Code-quality #1 | `except Exception: pass` around Redis setup in `bus.py`/`ws4-detection/main.py` silently downgraded a `BUS_BACKEND=redis` service to an isolated in-memory bus / per-replica counter, with zero log line | High | Narrowed to `except ImportError` (the one documented case) with a `warn` log; anything else now propagates and crashes loudly at startup. New `test_bus_redis_fallback.py` proves both paths (ImportError still degrades+logs; any other constructor failure propagates). |
| F1 (arch) | WS-6 inventory had no tenant column/filter/auth scoping at all — MAC-collision cross-tenant overwrite + full-inventory enumeration via the one shared API key | High | `services/ws6-inventory/store.py`: `tenant_id` added to the schema (`PRIMARY KEY (tenant_id, mac)`), every read/write scoped to it, defaulting to `"default"` everywhere (byte-for-byte pre-fix behavior for any caller that doesn't pass it). An on-disk pre-fix DB migrates in place on next open (tables renamed, data copied under `tenant_id='default'`, old tables dropped) — tested against a hand-built legacy-schema DB, including re-open idempotency. `app.py` threads `?tenant_id=` through every route; a malformed value is rejected (never normalized/merged, same convention as WS-3's `router.py`). `contracts/inventory-api.yaml` updated additively. New `test_tenant_isolation.py` (7 scenarios, store-level + real HTTP). |
| Design-A | Alert retention (365d) outliving evidence retention (30d `events-common`); a stateful alert referenced only 1 of N contributing events | High | Two parts: (1) `Rule.contributing_event_ids()` (`services/ws4-detection/engine.py`) now reads the window counter's own in-memory member/value list (`window.py`'s new `members()`/`distinct_members()`) so `make_alert()` records ALL contributing event ids (or distinct values) for a stateful rule, not just the triggering one — no new storage, reads state the counter already keeps. (2) `events-common`'s ISM retention raised 30d→90d (`ism-events-30d.json` renamed to `ism-events-common-90d.json`), and a new `ism-reports-365d.json` policy added (`reports-*` previously had none at all). `infra/provision.sh` and `test_opensearch_live.py` updated to match (not live-verified this pass — see caveats). New `test_design_a_event_ids.py`. |
| Design-B | `severity_floor` (high=70/critical=80, both ≥ `llm_min`=60) made every high/critical rule always route to LLM triage regardless of `score_weight` tuning | High | New optional `siem.llm_gate: false` per-rule flag (`engine.py`), a new `Scorer.routing_score()` (`scoring.py`) that excludes an opted-out rule's floor from the FUNNEL decision only — the stored/displayed `score`/`level` are untouched. Defaults to `true` (gate on): no existing rule's routing changes unless an operator explicitly opts a rule out. `validate_rules.py` rejects a non-bool value. New `test_design_b_llm_gate.py` (6 scenarios incl. multi-rule interaction and a full `Detector.process()` end-to-end check). |
| Security #1 | `alert_key()`/window-counter key joined attacker-controlled `group_by` values with an unescaped `:` delimiter — a crafted username could collide and overwrite a different alert | Medium | `Rule._namespaced_group()` now length-prefixes the group segment (`tenant:len(group):group`), making the join unambiguous regardless of delimiter characters inside `group`. Applied to both `alert_key()` and the window-counter key. Tests in `test_p1_1_alert_key_tenant.py`. |
| Perf #1 | Rule condition string re-tokenized and every selection's dotted path re-split on every single event | Medium | `Rule.__init__` precomputes `_condition_tokens` and `_compiled_selections` (pre-split path tuples) once at load time; `_eval_condition`/`_selection_matches`/`get_path` reuse them. No semantic change — verified against the full existing rule-firing/hardening/grammar suite. |
| Design-F | AI-triage prompt interpolated raw attacker-influenced event JSON into the LLM prompt with no injection framing, on exactly the highest-severity population | Medium | `PROMPT_TEMPLATE` (`services/ws5-ai/llm_adapter.py`) now explicitly frames the event/reasons as untrusted log data, not instructions, and tells the model to treat embedded commands/override-attempts as suspicious content rather than obeying them. Does not change the trust boundary that already bounded this (`_normalize_verdict()` still clamps to a closed enum; the verdict still lands in an additive `ai.*` namespace, never overwriting WS-4's real score) — narrows the softer verdict-poisoning gap. New tests capture the outgoing prompt and assert the framing text is present. |
| Security #2 | No Dockerfile ran as a non-root user | Medium | All 8 Dockerfiles reviewed; 7 now create and switch to an unprivileged `app` user (uid 10001). `ws6-inventory`'s fix orders `mkdir`/`chown /data` **before** the `VOLUME` instruction (Docker copies an image path's existing ownership into the volume on first use — doing it after would leave the DB unwritable). `ws7-dashboard` (nginx:alpine) is deliberately left as-is with a documented rationale: nginx's worker processes (the ones that actually parse client input) already drop to nginx's built-in unprivileged user; only the short-lived master (bind port 80 + read config, never touches request data) stays root, and forcing that non-root needs a port-mapping change this environment can't build/verify without a running Docker engine. **Not build-tested this pass** — no Docker daemon available (see caveats). |
| Design (arch F1) | WS-6 was the one workstream multi-tenancy never reached | High | Same fix as the security F1 row above — the architecture and adversarial-security reviews both flagged the identical root cause. |

## Deferred (with rationale)

**Design-C — no cross-alert correlation layer.** The review correctly
identifies this as the top remaining detection-architecture gap: every rule
evaluates independently against its own window; nothing accumulates risk for
one actor/asset across a longer horizon, so a low-and-slow attacker who
paces each technique under its own rule's threshold produces 27 isolated
tripwires instead of one aggregated incident. Building the real fix — a
second-pass consumer on the `alerts` topic, a new rolling-risk window keyed
by actor/asset over hours-to-days, a new "incident" alert shape and its own
scoring model, a dashboard surface, and its own test suite — is a genuine
multi-day feature project, not a same-pass fix, and rushing it risks exactly
the class of bug (wrong horizon, unbounded new state, false-merged
incidents) this project's fail-closed philosophy exists to avoid.

Shipped instead: `list_alerts()` (`services/ws3-indexer/storage/{memory,
opensearch}.py`, wired through `GET /api/v1/alerts?actor=&src_ip=`) now
supports exact-match filtering by actor/source IP across tenants and the
full retention window — the manual version of the query a future automated
aggregator would run itself. An analyst can pull every alert for one
actor/IP today; the automated accumulation is the open item. Tracked as an
honest open gap in `SSOT.md` §2, not hidden.

**WS-6 per-tenant API-key auth.** The tenant-isolation fix (F1) closes the
data-model half of the gap (schema, routes, migration) but the one shared
`FENGARDE_API_KEY` bearer check is unchanged — any caller holding that key
can still specify any `tenant_id` and read/write that tenant's data. Building
real per-tenant credentials would mean adding a keystore/auth subsystem to
WS-6 that doesn't exist today (unlike WS-3, which already has
`users.py`/`sessions.py`). Bolting on a single extra hardcoded per-tenant key
list risked being a worse, half-finished security boundary than being honest
about the gap. Documented in the code and `SSOT.md`.

## Regression risk that remains

- **ISM/retention changes (Design-A part 2) are config-only and not
  live-verified.** No live OpenSearch was available this pass. `python -c
  "import json; json.load(...)"` confirms every `ism-*.json` file is valid
  JSON, `infra/provision.sh`'s policy list and `test_opensearch_live.py`'s
  hardcoded policy name/count were updated to match, and the skip path was
  confirmed clean (`[SKIP] test_opensearch_live: OpenSearch not reachable`).
  The actual `_plugins/_ism/policies/*` PUT/attach behavior is unverified
  until `make test-live` runs against a real cluster.
- **Dockerfile changes are not build-tested.** `docker version` was probed
  once; the daemon wasn't running, so no `docker build`/`make up` was
  attempted (per this repo's own convention: don't launch or poll Docker
  Desktop). The non-root `USER` changes are a well-understood, low-risk
  pattern (matches every other service's existing Dockerfile shape) but
  should be build-verified before a real deploy, especially the `ws6-
  inventory` volume-ownership ordering and `ws1-collectors`'s
  `SYSLOG_SPOOL_PATH` opt-in write path.
- **`ws4-detection`'s window-counter key format changed** (Security #1 fix):
  the key now includes a length-prefix segment. Any Redis window state
  in-flight at deploy time is orphaned under the old key (self-expires via
  the existing `EXPIRE window_s+1` — no permanent leak) and a burst
  straddling the exact deploy moment restarts its count from zero. This is
  the same class of accepted, self-healing edge case the codebase already
  documents for window-bucket boundaries; not a new failure mode, but worth
  knowing before a rolling deploy of this change specifically.
- **`Rule.contributing_event_ids()` is best-effort, not exhaustive** by
  design: it reports whatever the window counter currently remembers, so it
  under-reports (never fabricates) if read long after entries aged out of
  the window. This is stated in the code and is the correct fail-closed
  direction, but a consumer of `event_ids` should not assume completeness.
- **`triage_api.py`'s new `actor`/`src_ip` params are passed conditionally**
  (only when a caller actually requests them) specifically so a third-party
  `StorageAdapter` subclass written against the pre-fix 3-parameter
  `list_alerts()` signature keeps working for every other call. If such a
  subclass exists and someone does request `actor`/`src_ip` filtering against
  it, that specific call will raise `TypeError` — the correct failure mode
  for requesting unsupported functionality, not a silent no-op.

## Verification

- `run_all_tests.sh` (zero-infra `make test` equivalent) passes clean after
  every individual fix and again at the end of the full pass.
- Every fix that didn't already have a regression test got one; every new
  test file was added to `run_all_tests.sh` so it runs in CI going forward.
- Self-review pass: read the full diff end-to-end (`git diff` per file),
  specifically checking for reintroduced races (the CAS lock's
  non-reentrant call path was checked for deadlock — confirmed
  `index_cas`/`index` call the private `_index_locked` directly, never
  re-acquiring the lock), reintroduced complexity regressions (the C1 fix's
  first draft reintroduced an O(n²) full-filter-per-hit cost, caught by the
  existing `test_window_perf.py` P1-5 trip-wire and replaced with the
  sorted-insert approach that stays O(1) on the common path), and backward
  compatibility (WS-6 schema migration tested against a hand-built legacy
  DB; WS-3's new `list_alerts` kwargs are opt-in so a legacy `StorageAdapter`
  subclass is unaffected; every `siem.llm_gate`/`tenant_id`/`actor`/`src_ip`
  addition defaults to the exact pre-fix behavior when omitted).
