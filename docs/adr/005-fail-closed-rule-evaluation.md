# ADR 005: Fail-closed detection-rule evaluation

**Status:** Accepted, live. **Date:** progressively hardened v0.3 → v0.4 P0
(`9e2745b`); backfilled 2026-07-16.

## Context

The detection engine (`services/ws4-detection/engine.py`) executes rule files
contributed by anyone — external contributors, MSP operators tuning their own
rule packs. A rule's `condition` walks event fields with a boolean grammar
(equality, `gt/gte/lt/lte/ne`, `in`, `contains`, `not_in` allowlists,
`outside_hours` time predicates). Any of those operators can hit malformed
input: a missing field, a non-numeric value where a comparison expects a
number, a NaN/inf timestamp, a malformed or missing allowlist file, an
unknown operator in a hand-edited rule. The engine's behavior on malformed
input is a real security property, not an edge case — SECURITY.md is explicit
that reviewing a rule's `condition` matters *because* the engine executes it.

A concrete incident (P0 hardening, `9e2745b`) motivated this ADR: a
far-future timestamp on one spoofed event collapsed every sliding-window
threshold to 1 (window poisoning), and a non-numeric/NaN/inf event time threw
a `TypeError` inside the counter that became an infinite redelivery loop
(poison-pill) rather than a rejected event.

## Decision

Every point of ambiguity in rule evaluation **fails closed to "no match,"
never raises, and never silently fires wide**:

- A non-numeric/NaN/inf or implausibly-far-future event time is rejected by
  `_valid_window_time` (a bounded `_MAX_CLOCK_SKEW_MS`) rather than poisoning
  the sliding window or crashing the worker.
- An unknown operator, malformed operator dict, or missing field returns
  `False` (no match), never raises (`engine.py`'s condition evaluator,
  documented inline at each such branch).
- A missing/malformed `not_in` allowlist file fails the **rule** open (keeps
  firing — a broken suppression list must never silently disable detection)
  but fails **suppression** closed (never suppresses on a broken list) — the
  asymmetry is deliberate, not an inconsistency.
- `contains`/`in` are implemented without regex specifically so a
  contributor-supplied rule can't introduce a ReDoS vector (`contracts/sigma-convention.md`).

## Consequences

- **Positive:** a hostile or merely malformed event can suppress at most
  itself from matching — it cannot suppress *other* events' detection, crash
  a worker into a redelivery loop, or (via a broken allowlist) blind the
  system to a real threat. This is the property that makes "the engine
  executes contributed rule files" (SECURITY.md) an acceptable trust model
  for an open contribution funnel.
- **Positive:** `tools/validate_rules.py` (Contract D) reuses the *real*
  engine's tokenizer/operator set to reject a rule at contribution time if it
  uses an operator the runtime doesn't implement — "valid" means exactly "the
  runtime will evaluate this," not a separate, driftable schema.
- **Cost:** a fail-closed rule can silently under-fire on an edge case a
  fail-open design would have caught (e.g., a genuinely ambiguous but
  real event that hits a "no match" branch). This is the accepted trade-off
  for a detection engine that must never be crashable or poisonable by
  attacker-controlled input reaching it — availability and non-poisonability
  win over maximal recall at the margins.
- **Regression class this decision now guards against:** `test_engine_hardening.py`
  and `test_window.py` cover the specific poison-pill/window-poisoning cases
  that motivated this ADR — every "fails closed" claim above has an
  adversarial test proving it, not just a docstring.
