# ADR 004: Seven-workstream split, bus-only coupling

**Status:** Accepted, live. **Date:** v0.1 (2026-06); backfilled 2026-07-16.

## Context

A SIEM pipeline has naturally distinct stages — collect, normalize, detect,
index, triage/AI, inventory, present — that scale differently (WS-4 detection
is CPU-bound and benefits from horizontal workers; WS-3 indexing is
I/O-bound against OpenSearch; WS-5 AI triage is optionally offloaded to a GPU
host) and change at different rates (adding a parser touches only WS-2;
adding a rule touches only WS-4 + `contracts/rules/`). A monolith would couple
all of that; a naive microservice split with services calling each other's
APIs directly would trade one form of coupling for another (a WS-4 change
breaking WS-3's contract at call time, not at a reviewable boundary).

## Decision

Seven workstreams under `services/` (WS-1 collectors, WS-2 normalization,
WS-3 indexer, WS-4 detection, WS-5 AI, WS-6 inventory, WS-7 dashboard),
coupled **only** through the message bus (ADR 001) — no service imports or
calls another directly. Bus topics, payloads, and partition keys are frozen
contracts (`contracts/bus-topics.md`), not implicit agreements discovered by
reading another service's code. This is enforced, not just documented: a grep
for cross-workstream imports has been run and re-checked twice (independently)
with zero hits (`SSOT.md` §2, "Bus-only coupling" row).

## Consequences

- **Positive:** any workstream can be rewritten, restarted, or scaled
  independently as long as it honors its topic contracts — proven in
  practice by the `_MemoryBus`/`_RedisBus` swap (ADR 001) requiring zero
  workstream code changes beyond the bus factory.
- **Positive:** the contribution funnel this enables is real, not aspirational
  — "add a parser without touching Docker" (`docs/adding-a-parser.md`) works
  because WS-2 has no compile-time or runtime dependency on WS-3/WS-4/etc.
  New parsers and rules are add-only changes to `services/ws2-normalization/parsers/`
  and `contracts/rules/`, never a cross-service edit.
- **Trade-off:** debugging a single event's journey across seven independently-
  deployed services requires correlating logs/state across process
  boundaries — Envelope v1's `trace_id` (`contracts/bus-topics.md`) exists
  specifically to make that traceable, and is the foundation for M7's planned
  OpenTelemetry tracing (one trace = one event's journey collector → alert).
- **Trade-off:** contract changes (a new bus-topic field, a new required OCSF
  property) are a coordination point across every consumer of that topic —
  which is why bus-schema changes are explicitly gated behind human sign-off
  in this project's standing guardrails (`CLAUDE.md` /
  `docs/superpowers/specs/*-agent-execution*.md`), not something a single
  service's PR can silently widen.
- **Verification discipline this decision requires:** `tools/validate_contract.py`
  (Contract A, OCSF), `tools/validate_rules.py` (Contract D shape),
  `tools/check_rule_producers.py` (cross-workstream satisfiability) all exist
  because "no service imports another" means contract drift can't be caught
  by the type system — it has to be caught by CI gates that exercise the
  real producer/consumer pair.
