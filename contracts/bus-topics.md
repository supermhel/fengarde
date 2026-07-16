# Contract B — Message Bus Topics

The bus is the **only** coupling between workstreams. No service calls another directly.
Abstraction: Redis Streams in dev, Kafka in prod — same topic names, same payloads.

## Topics

| Topic              | Producer        | Consumer(s)       | Payload                              | Partition key            |
|--------------------|-----------------|-------------------|--------------------------------------|--------------------------|
| `raw.events`       | WS-1 Collectors | WS-2 Normalization| `{source_type, raw, meta}`           | `src_endpoint.ip`        |
| `normalized.events`| WS-2 Normalization | WS-3, WS-4, WS-6 | OCSF event (Contract A)              | `src_endpoint.ip`        |
| `scored.events`    | WS-4 Detection  | WS-3, WS-5        | OCSF event + `siem.score`            | `src_endpoint.ip`        |
| `ai.requests`      | WS-4 Detection  | WS-5 AI worker(s) | `{event_id, event, reason}`          | `event_id`               |
| `ai.results`       | WS-5 AI         | WS-3, WS-7        | `{event_id, verdict, summary, level}`| `event_id`               |
| `alerts`           | WS-4, WS-5      | WS-3, WS-7        | enriched alert                       | `alert_id`               |
| `assets.updates`   | WS-1, WS-6      | WS-6 Inventory    | `{mac, ip, hostname, seen_at}`       | `mac`                    |

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

`infra/docker-compose.yml` runs Redis. The shared `bus.py` helper (provided in each
service skeleton) exposes `produce(topic, key, payload)` and `consume(topic, group)`,
backed by Redis Streams locally and swappable to Kafka via env `BUS_BACKEND`.
