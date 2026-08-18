# ADR 007: Cross-alert correlation as a separate service (WS-8), not a WS-4 thread

**Status:** Accepted, live. **Date:** 2026-08-18.

## Context

Every detection rule evaluates independently against its own short window
(`services/ws4-detection/window.py`). A low-and-slow attacker who paces each
technique under its own rule's threshold produces N isolated alerts, never
one aggregated incident — the top remaining detection-architecture gap named
by the 2026-07-29 adversarial design review (Design-C, `SSOT.md` §2), which
was deliberately deferred rather than rushed same-pass: building a real
cross-alert correlation engine needs a new long-horizon stateful consumer, a
new "incident" shape, its own scoring model, and a test suite — a genuine
multi-day feature, not a safe same-pass fix.

The scope was fixed first in `fengarde-sec`'s
`docs/2026-08-05-cross-alert-correlation-scope.md` (private repo — the
failure-mode analysis: false-merge on NAT/DHCP reuse, tenant isolation,
unbounded state growth), then decided in
`docs/2026-08-11-cross-alert-correlation-design.md` (same repo). This ADR
records the one decision from that design doc with the most architectural
blast radius for THIS repo: where the correlation consumer lives.

## Decision

A new `services/ws8-correlation`, not a thread or extra topic handler inside
WS-4. It consumes `alerts` as a **second, independent** consumer group
(`cg-correlate`) alongside WS-3's existing `cg-index` — Redis Streams
consumer groups fan out independently per group, so WS-8 falling behind or
dying cannot block or slow WS-3's indexing path, and WS-8 never imports WS-3
or WS-4 (bus-only coupling, ADR 004). It produces a new `incidents` topic,
consumed only by WS-3.

Reasoning: correlation state is stateful over hours-to-days
(`CORRELATION_HORIZON_SECONDS`, default 24h) — a fundamentally different
memory and latency profile from WS-4's hot per-event detection path.
Co-locating them means a correlation bug (a slow query, a memory leak on a
high-cardinality tenant) degrades detection itself, and detection is the
thing this product exists to do. A separate service also matches this
repo's own one-workstream-per-concern convention (ADR 004) instead of
special-casing an exception to it.

Cost, stated honestly: a new container, `Dockerfile`, `INTERFACE.md`,
compose entry, and health check for what is initially one consumer loop.

## A real cross-workstream-import risk this decision surfaced

The design doc says WS-8 "reuses `services/ws4-detection/window.py`'s
existing primitive" for its per-entity sliding-window state, but a literal
`from window import ...` sourced from `services/ws4-detection/` into
`services/ws8-correlation/` would itself be a cross-workstream source
import — the exact thing ADR 004 and `SSOT.md`'s "Bus-only coupling...
Proven... grepped, zero hits" row exist to prevent, and the whole point of
making WS-8 a separate service in the first place.

Resolved the same day, before any WS-8 code shipped: `window.py` (and the
allowlist loader it works alongside, `Allowlist`/`load_allowlist`) moved to
`services/shared/`, the established location for logic more than one
workstream needs — the same precedent already set by
`services/{ws6-inventory => shared}/mfa.py`. WS-4's 7 existing call sites
were updated to import `shared.window`/`shared.allowlist` instead; behavior
is byte-identical (`git mv`, re-verified against the full `ws4-detection`
test suite, `tools/validate_rules.py`, and `tools/check_rule_producers.py`).

## Consequences

- **Positive:** a WS-8 outage or a slow correlation query cannot delay or
  block alert indexing (WS-3) or detection itself (WS-4) — the same
  independence property ADR 004 already gives every other workstream pair.
- **Positive:** `services/shared/window.py` and `services/shared/allowlist.py`
  are now available to any future workstream needing sliding-window state or
  CIDR/exact-match allowlists, without repeating this same
  extract-to-shared exercise.
- **Trade-off:** one more container/Dockerfile/health-check/compose entry to
  operate, for a feature that starts as a single consumer loop — accepted
  because the alternative (a WS-4 thread) would couple detection's own
  availability to correlation's, which this project's bus-only-coupling
  discipline exists specifically to avoid.
- **Verification discipline this decision requires:** the 8-scenario
  contract test (`services/ws8-correlation/test_contract.py`) plus a
  sensitivity test that mutates the promotion trigger and the per-entity-key
  discipline and requires the real tests to go red against each mutation
  (`test_correlator_sensitivity.py`) — same "a negative assertion that
  cannot fail is not a test" bar `eval/attack/test_fire_check.py`
  established.

See `docs/superpowers/specs/2026-08-18-ws8-correlation-build-plan.md` for
the full phase-by-phase build record.
