# WS-8 Correlation — Interface Declaration

**Status (2026-08-18): first pass, zero-infra proven, one live smoke test.**
Implements `docs/superpowers/specs/2026-08-18-ws8-correlation-build-plan.md`
and the approved design in `fengarde-sec`'s
`docs/2026-08-11-cross-alert-correlation-design.md` (private repo — read
that first for the full rationale; this file only states the shipped
interface).

## Purpose

Closes the gap named in the 2026-07-29 architecture review (Design-C,
`SSOT.md` §2): every detection rule evaluates independently against its own
short window, so a low-and-slow attacker who paces each technique under its
own rule's threshold produces N isolated alerts, never one aggregated
incident. WS-8 is a second, independent consumer of the `alerts` topic that
tracks per-entity activity over a much longer horizon and promotes a track
to an "incident" once it shows real multi-stage behavior (>=2 distinct
MITRE tactics), not just repeated single-tactic noise.

## Consumes

- Topic `alerts` (group `cg-correlate`) — the exact same enriched-alert
  payload WS-3 already indexes (`services/ws4-detection/main.py::make_alert`
  shape: `alert_id, time, rule_id, level, score, mitre, tenant_id,
  src_endpoint, actor, event_ids`). A **second, independent** consumer
  group on the same topic WS-3's `cg-index` already reads — Redis Streams
  consumer groups fan out independently, so WS-8 falling behind or dying
  cannot block or slow WS-3's indexing path, and WS-8 never imports WS-3 or
  WS-4 (bus-only coupling, ADR 004).
- Contracts: B (bus), the alert shape WS-4 already produces.

## Produces

- Topic `incidents` — one document per promoted entity track:
  `incident_id, tenant_id, entity_type, entity_value, first_seen, last_seen,
  tactics[], member_alert_ids[], member_count, severity, truncated`.
  `incident_id` is deterministic
  (`{tenant}:{entity_type}:{entity_value}:{horizon_bucket}`), mirroring
  `Rule.alert_key()`'s fixed-epoch-bucket discipline (T7) — WS-8 re-emits a
  growing incident under the SAME id so WS-3's existing OCC/CAS path updates
  one document instead of accumulating duplicates under at-least-once
  redelivery.

## Correlation model

- **Per-entity tracks, never merged.** Every alert updates BOTH an
  `actor:{name}` track and an `ip:{addr}` track independently. The two never
  join. This is deliberate (design divergence #2): a compound `actor+ip` key
  would make the engine blind to the exact "same account, new host" pivot it
  exists to catch; a transitive entity graph would let one NAT gateway merge
  unrelated tenants' alerts into a useless mega-incident. Accepted
  limitation: a genuine pivot (alice from a new IP) surfaces as two
  incidents, not one — correlating those is explicitly deferred.
- **Promotion trigger is tactic diversity, not score-sum.** A track is
  promoted to an incident when its live members carry >=2 DISTINCT
  `mitre.tactic` values. Score-sum survives as the incident's `severity`
  field (ranking), not the trigger — a single chatty rule firing fifty times
  is one tactic, not a kill chain, and must never promote on volume alone.
  Alerts with no `mitre` block (only `agent_tool_call_burst` today) still
  join a track as a member but can never themselves trigger promotion.
- **Window state**: `services/shared/window.py`'s existing (moved here from
  `services/ws4-detection/` 2026-08-18 specifically so WS-8 can reuse it
  without a cross-workstream import — see ADR 007)
  `RedisWindowCounter`/`DequeWindowCounter` (same primitive WS-4's stateful
  rules use), keyed `ws8:corr:{tenant}:{entity_type}:{entity_value}`, with
  `CORRELATION_HORIZON_SECONDS` (default 86400 = 24h — a starting default,
  not a measured one, same "untuned guess" caveat as WS-1's backpressure
  rate default until it's tuned against real traffic). Redis `EXPIRE`
  self-cleans a quiet track; there is no separate reaper to test or get
  wrong.
- **Tenant isolation**: tenant is part of the track key, not a filter
  (rejected-at-edge via the same `_validated_tenant`-style check
  `services/ws3-indexer/router.py` uses) — a tenant-agnostic key would
  silently correlate across customers, a data-isolation breach, not merely
  a wrong result.
- **Shared-infrastructure allowlist**: `contracts/allowlists/
  shared_infrastructure.yml` (CIDR/exact match, shipped EMPTY, same
  fail-open-until-populated convention as `service_accounts.yml`/
  `corp_ranges.yml`). An `ip:` track is never opened at all for an
  allowlisted address — the primary defense against one NAT gateway or
  proxy polluting unrelated alerts into a false incident.
- **Hard member cap** per incident. On overflow, `truncated: true` is set
  and the drop is logged — no silent cap.

## Environment

- `PORT` (default `8008`) — health/metrics listener port.
- `BUS_BACKEND` (default `memory` for tests, `redis` in the Docker profile).
- `CORRELATION_HORIZON_SECONDS` (default `86400`).
- `CORRELATION_MEMBER_CAP` (default `200`).
- `FENGARDE_ALLOWLISTS_DIR` (default `contracts/allowlists`, same env every
  other allowlist-consuming service already reads).

## Contract tests

- `python test_contract.py` — the 8 scenarios from the design doc's test
  plan (positive low-and-slow, no false merge on single tactic, NAT/DHCP
  allowlist, unbounded-growth EXPIRE, tenant isolation, single-tactic
  non-promotion, replay idempotency, no transitive merge) plus 2
  dead-track-sweep scenarios (2026-08-20: `_sides`/`_last_incident` prune
  correctly once a track's own `_last_touch` ages past the horizon, a
  still-live track survives, and the sweep is actually wired into
  `_update_track` at the right cadence — see `correlator.py`'s
  `_sweep_dead_tracks`).
- `python test_correlator_sensitivity.py` — mutate-and-must-fail checks on
  the promotion trigger and the no-merge guarantee (same "a negative
  assertion that cannot fail is not a test" bar `eval/attack/
  test_fire_check.py` established).

## Deliberately not built (this pass)

Pivot-correlation across a changed IP for the same actor (accepted
limitation, design divergence #2). Dashboard visual design beyond a plain
table (design doc's own stated non-goal). Tagging `agent_tool_call_burst`
with a `mitre` block (one-line follow-up, tracked separately, not bundled
in). A tuned (vs. default) `CORRELATION_HORIZON_SECONDS`.

## Run locally

- `python main.py` (memory bus unless `BUS_BACKEND=redis`)
