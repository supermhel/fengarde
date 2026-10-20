# Phase 0 — Frozen Contracts

This directory is the foundation that makes the 7 workstreams parallelizable.
**After Phase 0, `contracts/` is read-only.** Each workstream codes against these
interfaces and mocks its neighbours.

## The five contracts

| # | Contract | File(s) | Owner of truth |
|---|----------|---------|----------------|
| A | OCSF event (pivot format) | `contracts/ocsf-event.schema.json`, `contracts/ocsf-classes.md` | all parsers emit it |
| B | Message bus topics | `contracts/bus-topics.md` | inter-service coupling |
| C | Inventory API | `contracts/inventory-api.yaml` | WS-6 implements, WS-2/7 consume |
| D | Detection & scoring | `contracts/sigma-convention.md`, `contracts/scoring.yaml`, `contracts/rules/*.yml` | WS-4 |
| E | Storage mappings | `contracts/opensearch-mappings/*.json` | WS-3 |

## Key design decisions

1. **Invariant `type_uid = class_uid*100 + activity_id`** — checked automatically, stops
   any parser emitting incoherent event types.
2. **Partition by `src_endpoint.ip`** — co-locates a host's events in one worker so
   stateful detection needs no distributed locks.
3. **AI funnel is a buffered queue** (`ai.requests`), never inline — the LLM only sees
   the ~8% of events above score 60.
4. **MAC = stable inventory key, IP historised** — `/assets/resolve?ip=&at=` is
   historically correct under DHCP churn.
5. **Isolated `events-bank-*` with 400d ILM** — PCI-DSS retention without over-storing
   the rest.

## Validate the contracts

```bash
python tools/validate_contract.py
# 3 valid fixtures pass, invalid_event.json is correctly rejected
```

## Bring up dev infra

```bash
cd infra && docker compose up -d
# redis (bus) :6379, opensearch :9200, dashboards :5601, provision runs once
```

## Workstreams (Phase 1, parallel)

```
WS-1 Collectors      services/ws1-collectors
WS-2 Normalization   services/ws2-normalization
WS-3 Indexer         services/ws3-indexer
WS-4 Detection       services/ws4-detection
WS-5 AI pipeline     services/ws5-ai
WS-6 Inventory       services/ws6-inventory
WS-7 Dashboard       services/ws7-dashboard
```

Each service carries its own `INTERFACE.md` (template in `docs/INTERFACE.template.md`)
declaring which topics/contracts it produces and consumes.
