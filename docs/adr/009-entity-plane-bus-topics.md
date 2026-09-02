# ADR 009: Entity/context plane — two new bus topics (WS-9)

**Status:** Accepted (owner-ratified, Option 2); **implementation in progress —
WS-9 is zero-infra-proven but NOT yet live in the deployable stack**
(no `infra/docker-compose.yml` entry, not in `KILL_TARGETS`; the ADR's
Consequences below are not all met until that lands). **Date:** 2026-08-28.

## Context

The detection pipeline ends at **incidents**: WS-8 promotes a per-entity track
(`actor:{name}` / `ip:{addr}` / `device:{mac}`) to an incident once its live
members carry ≥2 distinct MITRE tactics. What an analyst cannot ask today is
*"what else did this actor touch?"* — there is no persistent entity identity,
no relationship store, and no provenance on *why* two alerts belong together
beyond the track's alert list.

Phase 2 (the **entity/context plane**) needs this. It requires (WP-2-B) a
deterministic entity identity, (WP-2-C) relationship edges carrying provenance,
and (WP-2-D) behavioral baselines — all of which, per this repo's ADR-004
bus-only coupling model, must move over the bus.

Ground truth re-derived 2026-08-28:

- `contracts/bus-topics.md` topics today: `raw.events`, `normalized.events`,
  `scored.events`, `ai.requests`, `ai.results`, `alerts`, `incidents`,
  `assets.updates`, `<topic>.deadletter`. **No** `entity.*` or `*.graph`.
- WS-8 (`services/ws8-correlation/correlator.py`) already maintains
  per-(tenant, entity_type, entity_value) tracks and emits `incidents` keyed by
  a deterministic, first_seen-bucketed `incident_id` (idempotent under
  redelivery). It does **not** emit an entity graph.
- WS-6 inventory persists assets keyed `(tenant_id, mac)`. WS-4
  `Rule.alert_key()` (`services/ws4-detection/engine.py`) is the repo's
  deterministic-id role model.
- ADRs exist 002–008. ADR 007 governs cross-alert correlation as a separate
  service; this amendment is additive to it, not a rewrite.

## Decision

Adopt **two new, purely additive bus topics** and a **new WS-9 resolver
service** that owns entity resolution, per the owner's Option-2 ratification.

### Topic A — `entity.updates`
| | |
|---|---|
| Producer | WS-9 (entity resolver); WS-6 Inventory (asset sightings) |
| Consumers | WS-9 (self), WS-3 indexer (persist), future WS-7 read path via WS-3 API |
| Payload | `{entity_id, entity_type, tenant_id, entity_value, first_seen_ms, last_seen_ms, attributes}` |
| Partition key | `entity_id` |

- `entity_id` is **deterministic and idempotent under redelivery**: the same
  discipline as `Rule.alert_key()`. Computed as
  `sha256("{tenant}|{entity_type}|{canonical_value}")`, where the canonical
  value is normalized at the edge (IPs via the shared `valid_ip`
  normalization, MACs lowercased, usernames case-folded per the parser-centric
  convention).
- An upsert carrying the same `entity_id` + a non-newer `last_seen_ms` is a
  no-op (replay-safe).

### Topic B — `incident.graph`
| | |
|---|---|
| Producer | WS-8 Correlation (when it promotes/updates an incident), WS-9 |
| Consumers | WS-9 (entity resolver), WS-3 indexer (persist) |
| Payload | `{version: 1, incident_id, tenant_id, nodes: [type:value…], edges: [{from, to, kind, event_id, ts_ms}], tactic_sources}` |
| Partition key | `incident_id` |

- **`nodes` are the incident's member tracks as `{entity_type}:{entity_value}`**
  (the SAME track identity the incident itself captures — e.g. `actor:alice`,
  `ip:10.0.0.5`) — NOT WS-9's canonical sha256 `entity_id` digests. WS-8
  keys tracks on its edge-normalized raw values by design (its proven
  identity space), so the graph references the tracks directly; the entity
  plane maps each node to its canonical `entity_id` on consumption, and
  Phase 3's `version: 2` typed-DAG upgrade is the seam that carries the
  canonical form (mirrors `ws8-correlation/INTERFACE.md` "Nodes" bullet).

- **`version: 1` is present now** so Phase 3's upgrade of the flat edges into a
  typed causal DAG (`caused_by`, `invoked`, `authenticated_as`, `wrote_to`,
  `changed`) is a self-describing `version: 2` bump, not a silent shape change.
- **No transitive inference** — the same refusal WS-8 already applies to
  actor/IP/device joins. An edge is emitted only when a single alert's own
  fields provide the relationship (same session, same source IP, same
  actor+device), with `event_id` + `ts_ms` provenance on every edge.

### WS-9 (new resolver service)
Entity resolution is a distinct concern and gets its own bus-only workstream,
following the exact precedent WS-8 set (2026-08-18): a new concern → a new
service. It must NOT be folded into WS-8 (correlation — which the roadmap says
should keep its proven tactic-accumulation path, the graph is additive), WS-3
(indexer — a persistence layer, not a resolver), or WS-6 (inventory — a device
MAC store, not an actor/IP/session resolver).

## Consequences

- **Additive**: no existing topic name/payload changes; existing consumers are
  unaffected. Both new topics are opt-in consumers by WS-3 (persist) only.
- **Backward compatible**: WS-8 can keep emitting flat `incidents`; the graph
  is a superset.
- **Lane wiring**: WS-9 (and its bus dependency) must appear in
  `tools/chaos_test.py::KILL_TARGETS` (or carry the documented exclusion) and
  satisfy every assertion of `tools/check_lane_coverage.py`; the 0.1-A guard
  will correctly flag it until it does.
- **Phase 3**: `incident.graph` is the schema Phase 3 upgrades to a typed DAG
  via `version: 2`. No new contract is invented.

## Status
Accepted 2026-08-28 (owner Option-2 ratification). Implemented alongside
WP-2-B/C/D (entity resolver, relationship edges, behavioral baselines).
