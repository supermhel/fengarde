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
