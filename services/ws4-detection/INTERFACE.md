# WS-4 Detection — Interface Declaration

## Consumes
- Topic `normalized.events` (group `cg-detect`).
- Contracts: A (events), D (Sigma rules + scoring), B (bus).
- Files: `contracts/rules/*.yml`, `contracts/scoring.yaml`.
- Consume ordering is per-tenant fair, not raw FIFO: `main.py` wraps the bus in
  `FairConsumeBus` (`services/shared/fairness.py`) by default — one tenant
  flooding `normalized.events` can no longer occupy every consecutive processing
  turn ahead of another tenant's events. Default on; opt out with
  `FENGARDE_TENANT_FAIR_CONSUME=0`. Bounded within one raw consume batch, see the
  module's own docstring for the honest scope.

## Produces
- Topic `scored.events` — event + `siem.score`, partition key = src ip.
- Topic `alerts` — one per rule match, partition key = alert_id.
- Topic `ai.requests` — buffered AI funnel input: `tier="llm"` when score ≥
  `llm_min` (full LLM triage), `tier="classifier"` when `classifier_min` ≤ score <
  `llm_min` (WS-5's cheap light-classifier only, no LLM call — P1-2, 2026-07-21).
  Below `classifier_min`: indexed only, nothing enqueued to WS-5.

## Engine
- Sigma-style rules over OCSF dotted paths; stateful rules use `window_seconds` +
  `threshold` + `group_by` (sliding window, plus `distinct_field` for distinct-count).
  Score = capped sum of weights, with a severity floor; funnel route =
  store / classifier / llm per `scoring.yaml`.
- Operators: equality, comparison (`gt/gte/lt/lte/ne`), allowlist suppression
  (`not_in`, fail-OPEN on a broken allowlist file — see `engine.py`'s
  `_ALLOWLIST_CACHE` docstring), time-of-day (`outside_hours`), list membership
  (`in`, v0.4 P2), bounded substring (`contains`, v0.4 P2), Sigma-style
  wildcard (`glob` — `*`/`?`/`[seq]`/`[!seq]` via `fnmatch`, M7 2026-08-05,
  explicitly not a regex layer per ADR-005) — non-eval, fail-closed. Grammar in
  `contracts/sigma-convention.md`.
- `class_uid` prefilter: rules bucketed by a *necessary* equality class_uid so an
  event only evaluates candidate rules; multi-class/negation rules fall back to a
  catch-all bucket (always evaluated).
- Deterministic `alert_id` → idempotent alerts under at-least-once redelivery.
- Rule gates (CI): `tools/validate_rules.py` (schema/condition/operator/reference)
  and `tools/check_rule_producers.py` (anti-dormancy).

## Multi-tenancy
- Per-tenant rule enablement: `contracts/tenants/<tenant_id>.yml` lists rule ids
  DISABLED for that tenant (`tenants.py`); a missing file/tenant means every
  global rule still applies — absence never silently reduces coverage. See
  `contracts/tenants/README.md`.
- Stateful window counters are tenant-namespaced, so two tenants sharing one
  Redis-backed deployment don't pool or leak into each other's threshold counts.

## HA / scaling
- `BUS_BACKEND=redis` or `redis-sentinel` gives every stateful rule a Redis-backed
  global window counter (`RedisWindowCounter`) instead of a per-process deque, so
  the threshold count is correct across multiple WS-4 replicas. Sentinel mode
  (`REDIS_SENTINEL_HOSTS`, `REDIS_SENTINEL_MASTER`, `REDIS_PASSWORD`) resolves the
  current master via `Sentinel.master_for()` on every reconnect, so a real
  failover doesn't leave the counter pinned to a demoted read-only replica —
  live-kill-tested, see `SSOT.md`.

## Extensibility & ops
- **Plugin rule packs** (M4.5): an installed Python package can add rule YAML via
  the `fengarde.rule_packs` entry-point group (`discover_rule_pack_dirs()`,
  `docs/plugin-development.md`); a plugin rule whose id collides with an
  already-loaded one is skipped, never silently overrides a built-in rule.
- **Opt-in rule hot-reload** (B4): `RULES_RELOAD_INTERVAL_S` (default `0` = off,
  byte-identical to no-hot-reload behavior) re-parses `contracts/rules/` +
  allowlists on an mtime-poll and atomically swaps in the new set; a malformed
  edit fails closed (previous rule set stays live, logged loudly). Window state
  keys by rule id, so an unchanged rule keeps its in-flight window across a reload.
- **Rule-health watchdog**: `Detector.record_fire()` stamps a real timestamp per
  rule on every match; `rule_health_metrics()` exposes one gauge per rule that has
  actually fired (never fabricated as 0 for a rule that hasn't) on `/metrics/prom`
  — closes the gap between "a rule can fire" (CI-proven) and "a rule IS firing in
  production" (previously zero live signal).

## Behavioral baselines (WP-2-D, additive module -- NOT wired into the engine)

- `behavioral_baseline.py` ships a self-contained `BehavioralBaseline`: per-entity
  NORMAL behavior (active hours, expected source-IP set, expected event-type set,
  expected destinations) learned over a sliding warm-up window. It **reuses
  `services/shared/window.py`'s `DequeWindowCounter`** (`RedisWindowCounter`
  injectable for multi-replica) as its only store -- no new store is added
  (ADR-009/WP-2-D rule). Keys by the entity plane's ADR-009 `entity_id`, with a
  length-prefixed `(tenant, entity_type, entity_value)` composite fallback.
- Bounded (attacker-controlled entity_ids): entity table hard-capped
  (`max_entities`, deterministic LRU) + the window counter's own trim/idle-sweep
  bounds the per-key windows. Replay-safe: member dedup by OCSF `ingest_id`.
  Deterministic: caller-supplied `now_ms`, no wall clock.
- **Deliberately NOT wired into `engine.py` / rules** (roadmap: baselines first,
  wiring later). `observe(entity_key, event, now_ms) -> verdict dict` (learned /
  deviation / reasons / observations / span_ms) is the additive signal a future
  integration turns into an event flag or a `baseline_deviation` bus signal; it
  never mutates the input event.
- Test: `python test_behavioral_baseline.py` (standalone, zero-infra, injected clock).

## Contract tests
- `python test_contract.py`  (memory bus; rule firing + stateful thresholds + funnel)

## Environment (read by `main.py` / `engine.py`)
- `PORT` (default `8010`) — health/metrics listener port.
- `BUS_BACKEND` / `REDIS_URL` / `REDIS_PASSWORD` / `REDIS_SENTINEL_HOSTS` /
  `REDIS_SENTINEL_MASTER` — bus backend (memory / redis / redis-sentinel).
- `FENGARDE_TENANT_FAIR_CONSUME` — per-tenant fair consume ordering (PR #55).
  **Default on**; opt out with `=0`/`=false` (this entry said "opt-in,
  default FIFO" until 2026-08-13, contradicting this file's own module
  description above — `main.py:433`'s actual default is `"1"`).
- `RULES_RELOAD_INTERVAL_S` (default `0` = off) — opt-in rule hot-reload poll
  interval (mtime-poll + atomic swap, B4).
- `DETECTION_OUTPUT_DEPTH_WARN` — warn threshold for over-deep nested output.

## Run locally
- `python main.py`
