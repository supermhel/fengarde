# ADR 001: Redis Streams as the message bus

**Status:** Accepted, live. **Date:** originally v0.1 (2026-06); backfilled 2026-07-16.

## Context

The seven workstreams communicate *only* through a message bus (`contracts/bus-topics.md`)
— no service imports or calls another directly (ADR 004). That bus needs:
at-least-once delivery, consumer groups (so WS-4 can scale detection workers
horizontally without double-processing), a pending-entries mechanism for
redelivery after a crashed consumer, and a path to run with zero external
infrastructure for the contributor test loop (`make test`).

Kafka was the original "prod backend" named in early docs and is still the
assumed central-tier bus in the (unbuilt) 3-tier production-roadmap design.
No `_KafkaBus` exists in this codebase — see SSOT.md §2.

## Decision

Ship **Redis Streams** (XADD/XREADGROUP/XACK/XAUTOCLAIM/XPENDING) as the real
backend, with an in-memory bus (`_MemoryBus`) as the zero-infra test/dev
backend behind the same `Bus()` factory interface (`services/shared/bus.py`).
**Kafka is not implemented.** A 2026-07-02 architecture review
(`docs/superpowers/specs/2026-07-02-fengarde-architecture-review.md`, finding
R-A) found the codebase claiming "prod backend = Kafka (same API)" while no
`_KafkaBus` existed anywhere — that claim was corrected, not the code changed
to match it. The honest position: Redis Streams is *the* bus; Kafka is a
candidate for a future central/multi-tenant tier, built only when that tier
is actually built (YAGNI), not before.

## Consequences

- **Positive:** Redis Streams' consumer-group model maps directly onto the
  delivery semantics the bus contract promises (at-least-once + idempotent
  consumers = effectively-once alerts, the guarantee M1's `make chaos` gate
  proves). One dependency to operate instead of two (Redis already backs
  WS-4's stateful rule-window counters via sorted sets).
- **Positive:** `BUS_BACKEND=memory` gives the zero-infra contributor loop
  (`make test`, `make e2e`) — no Docker/Redis needed to add a parser or rule.
- **Trade-off, documented (R-B in the architecture review):** Redis is a
  single instance in the current (local/air-gapped) deployment tier; there is
  no HA design yet (Sentinel/cluster) for a future central tier. Conscious
  scope cut, not an oversight.
- **Trade-off:** `_MemoryBus` fakes redelivery/DLQ semantics differently than
  `_RedisBus` (no persistent PEL — tests re-create the loop via a re-produce
  pattern). Anything depending on real PEL behavior (XAUTOCLAIM timing,
  `times_delivered` counters) is verified against real Redis in CI's
  `redis-integration` job, not assumed from the memory-bus test suite alone.
- If a central/multi-tenant tier is ever built and needs a different bus,
  implement `_KafkaBus` (or equivalent) behind the same `Bus()` interface at
  that point — the abstraction already proves the shape a third backend
  would slot into.
