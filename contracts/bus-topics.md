# Contract B — Message Bus Topics

The bus is the **only** coupling between workstreams. No service calls another directly.
Abstraction: Redis Streams (the only implemented backend, in dev AND production —
this is the same stack `infra/docker-compose.yml` runs). Kafka is a CANDIDATE for a
future scaled/central tier, not implemented (there is no `_KafkaBus` in
`services/shared/bus.py`) — this contract's topic names/payloads are chosen to be
backend-agnostic so a third backend could slot in without a schema change, but
nothing here should be read as "Kafka already works."

## Topics

| Topic              | Producer        | Consumer(s)       | Payload                              | Partition key            |
|--------------------|-----------------|-------------------|--------------------------------------|--------------------------|
| `raw.events`       | WS-1 Collectors, WS-6 Inventory (M7 Track Y follow-up: a genuinely new device, `source_type=inventory_diff`) | WS-2 Normalization| `{source_type, raw, meta}`           | `src_endpoint.ip` (WS-1) / `mac` (WS-6) |
| `normalized.events`| WS-2 Normalization | WS-3, WS-4       | OCSF event (Contract A)              | `src_endpoint.ip`        |
| `scored.events`    | WS-4 Detection  | WS-3               | OCSF event + `siem.score`            | `src_endpoint.ip`        |
| `ai.requests`      | WS-4 Detection  | WS-5 AI worker(s) | `{event_id, event, tier, reason}`    | `event_id`               |
| `ai.results`       | WS-5 AI         | WS-3               | `{event_id, tier, verdict, summary, level, classification, engine, model}` (2026-08-20: `engine`/`model` added -- which analyzer actually produced this verdict, `"ollama"`+model name or `"stub"`; `None`/`None` on the classifier tier, which never calls an LLM) | `event_id` |
| `alerts`           | WS-4, WS-5      | WS-3, WS-8 (2026-08-18, second consumer group `cg-correlate` on the same topic — the bus's consumer-group model already fans out one topic to multiple independent groups, confirmed against this file's own "Consumer groups: one group per workstream" line below) | enriched alert | `alert_id` |
| `incidents`        | WS-8 Correlation (2026-08-18, new) | WS-3            | correlated incident (entity track promoted on >=2 distinct MITRE tactics) | `incident_id` |
| `entity.updates`   | WS-9 Resolver (2026-08-28, new — see ADR-009). WS-6 Inventory is ADR-009's planned second producer but does NOT produce this topic yet (2026-09-02 review: corrected, was listed as already producing) | WS-9 (self, `cg-entity-self` — real, wired in `services/ws9-resolver/main.py`). WS-3 does NOT consume this topic yet (2026-09-02 review: corrected, was listed as already consuming — see `services/ws3-indexer/main.py`'s `TOPICS`) | `{entity_id, entity_type, tenant_id, entity_value, first_seen_ms, last_seen_ms, attributes}` — deterministic `entity_id` = `sha256(tenant|type|canonical_value)`, idempotent under redelivery | `entity_id` |
| `incident.graph`   | WS-8 Correlation (2026-08-28, new — see ADR-009; **upgraded to `version: 2` 2026-09-02, owner-ratified — see ADR-010**). WS-9 Resolver does NOT produce this topic (2026-09-02 review: corrected, was listed as a producer — see `services/ws9-resolver/INTERFACE.md`'s "Deliberately not built (this pass)") | Nobody yet (2026-09-02 review: corrected, was listed as consumed by WS-9/WS-3 — neither wires this topic today) | `{version: 2, incident_id, tenant_id, nodes: [{entity_id, entity_type, entity_value, label}…], edges: [{from, to, kind, event_id, ts_ms}], tactic_sources}` — **v2 (WP-3-A/ADR-010):** SUPERSEDES v1 as the emitted payload; nodes are WS-9-canonical sha256 `entity_id` digests (entity_type/entity_value/label preserved for readability); edges gain typed kinds `caused_by`/`invoked`/`authenticated_as`/`wrote_to`/`changed` alongside v1's `used_ip`/`used_device`/`seen_at_ip` — a typed kind is a label on a single-alert-evidenced edge, NEVER a transitive join; still no transitive inference; edges carry `event_id`+`ts_ms` provenance. v1 builder stays in code byte-for-byte as the compat reference (emission is v2 only; consumers distinguish by `version`) | `incident_id` |
| `assets.updates`   | WS-1            | WS-6 Inventory    | `{mac, ip, hostname, seen_at}`       | `mac`                    |
| `<topic>.deadletter` | any consumer (`services/shared/runner.py`'s generic redelivery-cap logic), plus `raw.events.deadletter` produced directly by WS-2 on unparseable input | operator (`tools/dlq_peek.py`) | `{topic, group, id, delivery_count, payload}` | inherits the original message's key |

**WS-3 and WS-7 do not have the same bus relationship.** WS-3 (indexer) is the
real consumer of `normalized.events`/`scored.events`/`ai.results`/`alerts`/
`incidents` — it's the only service that persists them. WS-7 (dashboard)
never touches the bus at all; it's a static UI that reads alert/rule/
inventory/incident data over HTTP via nginx proxies to WS-3's REST API (see
`services/ws7-dashboard/INTERFACE.md`). An earlier version of this table
listed WS-6 as a `normalized.events`/`assets.updates` producer-or-consumer
beyond its actual `assets.updates`→`raw.events` role, and WS-5/WS-7 as
`scored.events`/`ai.results`/`alerts` consumers they never were — corrected
2026-08-07 against the real `bus.produce`/`bus.consume` call sites, not
assumed from an earlier draft.

## WS-8 correlation (2026-08-18)

**Never imports WS-4 or WS-3** (bus-only, ADR 004/007). Consumes `alerts` as
a second, independent consumer group alongside WS-3's `cg-index` — the two
groups each get their own copy of every alert, per Redis Streams consumer-
group semantics; WS-8 dying or lagging cannot block WS-3's indexing path.
Reuses `services/shared/window.py`'s `RedisWindowCounter`/
`DequeWindowCounter` primitive for per-entity sliding-window state (see
`docs/adr/007-cross-alert-correlation-separate-service.md` and
`docs/superpowers/specs/2026-08-18-ws8-correlation-build-plan.md` for the
full design). Produces `incidents`, consumed only by WS-3. Full topic/
payload/partition-key entries are in the table above.

## Envelope v1 (M1 correctness gate, additive)

Four fields the combined roadmap's M1 milestone asked to formalize. All are
**additive** — `tools/validate_contract.py` never enforces `additionalProperties:
false` on nested objects, so no fixture or producer breaks by their absence.
Implemented in `services/shared/envelope.py` + `Parser.base_event()`
(`services/ws2-normalization/parsers/base.py`).

| Field | Where | Meaning |
|---|---|---|
| `schema_version` | `metadata.schema_version` | Version of *this* contract (bus-topics.md + ocsf-event.schema.json), not the OCSF `metadata.version`. Currently `"1.0"`. Absent = pre-v1. |
| `tenant_id` | `siem.tenant` | **Pre-existing field, now actually wired.** Was declared in the schema since Phase 0 but no producer ever set it. WS-1 collectors stamp it from `TENANT_ID` env (default `"default"`) via `envelope.stamp_meta()`; every parser propagates it through `base_event(meta=...)`. Single-tenant deployments (the only kind that exist today) never need to touch `TENANT_ID` — this is the field M4 (multi-tenancy) will key on, not a new concept. |
| `trace_id` | `siem.trace_id` | **New.** Generated once per raw event at WS-1 ingest (`envelope.new_trace_id()`), carried unchanged through `raw.events` `meta` → the normalized OCSF event → `scored.events`/`alerts` (WS-4/WS-3 pass the event dict through, they don't rebuild `siem.*`). One trace_id = one source event's journey collector → alert. Foundation for M7's OTel tracing. |
| `event_time` vs `ingest_time` | `time` (event_time) vs `metadata.logged_time` (ingest_time) | **Pre-existing, now explicitly documented as the answer to this roadmap item.** `time` is when the event happened per the source log; `logged_time` is epoch ms when the collector received it. They differ under replay, clock skew, or forwarded/batched logs. |
| dedup key | `siem.ingest_id` (per-event) | **Pre-existing, now explicitly documented.** UUID assigned by the collector; consumers must be idempotent on this, not on the bus message/stream id (redelivery reuses the same `ingest_id`, a fresh stream id). The correlated-alert analog is the deterministic `alert_id` (WS-4, T7) — a different key for a different granularity, not a second dedup mechanism. |

Not covered by envelope v1 (left to M4): per-tenant OpenSearch data streams/ILM,
per-tenant rule enablement — `siem.tenant` being populated is the prerequisite,
not the isolation itself.

## Enrichment on `normalized.events` (A5, additive)

WS-2 adds optional OCSF-additive fields to events post-normalize (offline, local
data only): `src_endpoint.reputation` (score + categories, local IOC list) and
`src_endpoint.location` (country, local CIDR→country map). These are **additive
extensions** — an event without them is still a valid Contract A event; downstream
(WS-3/WS-4) are tolerant readers and nothing hard-depends on them. No topic or
partition-key change.

## Why partition by `src_endpoint.ip`

`normalized.events` and `scored.events` are partitioned by source IP so that **all
events from one host land in the same worker**. Stateful detection (brute-force counters,
UEBA baselines) and correlation then run without distributed locks. This is the key
decision that lets WS-4 scale horizontally by adding partitions/workers.

## Decoupling the AI funnel

`ai.requests` is a **buffer**, not a synchronous call. WS-4 only enqueues events above
the score threshold (Contract D). WS-5 workers consume at their own pace. If volume
spikes, add workers — nothing else changes. The LLM never sits inline on the log path.

## Delivery semantics

At-least-once. Consumers must be idempotent on `ingest_id` / `event_id` / `alert_id`.
Consumer groups: one group per workstream (`cg-normalize`, `cg-index`, `cg-detect`, ...).

## Dev adapter

`infra/docker-compose.yml` runs Redis (the same instance used in production, not a
dev-only stand-in). The shared `bus.py` helper (provided in each service skeleton)
exposes `produce(topic, key, payload)` and `consume(topic, group)`, with `BUS_BACKEND`
selecting between the two IMPLEMENTED backends: `redis` (real deployments) and
`memory` (zero-infra tests). See the note at the top of this file — Kafka is not one
of the options `BUS_BACKEND` currently accepts.
