# WP-4.1 findings: `false_correlation_rate = 1.0` on the AI-to-OT twin

Date: 2026-11-04 · Branch: `wp/4.1-false-correlation` (base `origin/main` @ `7a3f129`)
Verdict: **graph defect AND metric defect — but the graph side is a ratified,
waived design property (ADR-009/010), not a ws8 bug; the actionable defect is
metric/claim-side, and this PR fixes it by surfacing the twin's already-measured
time-aware counterpart and narrowing the claim.**

## 1. The claim being chased

`eval/SCORECARD.md`, AI-to-OT per-storyline row (line 41 of the card):

> | false_correlation_rate | 1.0 | lower-better | Same order-blind predicate as
> chain_fidelity: a saturated 1.0 cannot distinguish a mutation that INDUCES
> false correlation from one that merely fails to improve an already-saturated
> number. | `eval/adversarial/test_scenario_harness.py::test_directional_discrimination` |

The oracle declaring the pairs: `eval/twin/oracle.yaml:89-97` —

```yaml
# Explicit NON-edges the twin must never claim (defense / anti-ordering):
- from: process_anomaly
  to: modbus_write
  allowed: false        # the physical anomaly never precedes the write that caused it
- from: credential_use
  to: agent_mcp_tool_call
  allowed: false        # backward edge; tool call precedes credential use
```

Measured, seed 7 (this worktree, `report.py --no-trend`):
`metrics.false_correlation_rate = 1.0`, `context.causal_order_details.per_forbidden_pair`
= `[{process_anomaly->modbus_write, realised: False}, {credential_use->agent_mcp_tool_call, realised: False}]`,
`forbidden_order_realised_rate = 0.0`, `causal_order_fidelity = 1.0`,
`order_concordance = 1.0`, `temporal_discrimination = 1.0`.

## 2. Graph side — the graph REALLY joins the forbidden pairs (measured), but by ratified design

Confirmed independently three ways:

1. `eval/twin/oracle_consistency.py` on this tree prints, for ai_to_ot:
   `[FORBIDDEN]   graph claims process_anomaly -> modbus_write, oracle forbids it`
   and `[FORBIDDEN]   graph claims credential_use -> agent_mcp_tool_call, oracle forbids it`
   (both on the frozen accepted list, exit 0).
2. `eval/twin/report.py:28-38` (module docstring): *"The seed-7 graph carries ONE
   typed edge (actor:ot-engineer -> ip:10.20.0.50, kind invoked, evidenced by the
   agent_mcp_tool_call egress alert), which satisfies all 5 graded allowed joins AND
   2 of the 2 forbidden pairs (the actor+ip pair is present on both sides of every
   step cut, so entity-presence joins cannot discriminate direction)."*
3. The join predicate `_fidelity_join` (`eval/twin/report.py:925-939`) answers
   "joined" for entity-presence only; the ORDER-REVERSAL CONTROL comment
   (`report.py:994-1004`) records that it answers the same for a pair and its
   reverse.

Why the graph is NOT what this PR "fixes": the join is entity-sharing, and the
per-entity tracks **never merge by ratified design** (ADR-009/010), each edge is
evidenced by ONE alert, and edge direction comes from entity TYPE, never from
time (documented in `docs/handoff/design-specs/step3_causal-order.json` § "Basis",
fact 3). The oracle's `allowed: false` pairs are anti-CAUSAL direction
constraints, which this correlator cannot express. `oracle_consistency.py:110-151`
records the whole class on the frozen `_ORDER_BLIND` waiver list (2026-10-02, SSOT
2026-10-01): *"closing it means grading edge direction by event time or by WS-8
typed caused_by edges, a separate ratified step."* A ws8 code change here would
break the ratified invariant AND the frozen ratchet atoms
(`scn/ai_to_ot/base/false_correlation_rate = 1.0`, `base/chain_fidelity = 0.6` in
`eval/twin/baseline_scenarios.json`, both PINNED) — out of scope for this PR.

## 3. Metric side — `false_correlation_rate` is order-blind and saturated

The metric never reads a clock. Proven by the repo's own time-mirror control:
`eval/adversarial/order_controls.py` and `docs/handoff/design-specs/step3_causal-order.json`
measure that a time-mirrored copy of every storyline scores **identically** on
`false_correlation_rate` (1.0), `chain_fidelity`, `directional_discrimination` (0.0)
and `incident_count`; only `alert_order_ok` flips. `eval/twin/causal_order.py` exists
exactly for this reason: *"chain_fidelity and false_correlation_rate are provably
order-blind … never read a clock."* A saturated 1.0 therefore cannot distinguish "a
mutation INDUCED a false correlation" from "the entity bridge was already there" —
the scorecard already says this in the row's own blind-spot cell.

The twin already MEASURES the honest, time-aware answer for the same two pairs —
`causal_order.grade_causal_order().forbidden_order_realised_rate = 0.0` (the clock
never realises the forbidden direction) — but it is only exposed under
`context.causal_order_details`, never in `report.metrics`, and therefore never on
the scorecard. The order-blind saturated 1.0 is the headline; its truthful,
clock-graded, same-denominator counterpart is invisible to a card reader.

## 4. Fix chosen (this PR)

- **No ws8 change** (ratified ADR-009/010; would move frozen pinned atoms).
- **No frozen baseline change** (`baseline_scenarios.json`, `baseline.json`,
  `oracle_strength.json`, trend rows all untouched; ratchet atoms unchanged).
- **Replace nothing, add the honest counter-metric**: `report.py` now emits
  `forbidden_order_realised_rate` (0.0, true chain) / `forbidden_timed` (2) /
  `temporal_discrimination` (1.0) as first-class `metrics`; the card gains a
  twin-only row `forbidden_order_realised_rate` (lower-better, control: the
  mirrored-chain goes 1.0) and the `false_correlation_rate` blind-spot text now
  names the time-aware counterpart. The scorecard row set therefore changes in the
  same PR (acceptance criterion), the claim no longer overstates, and a reader who
  sees `FCR 1.0` can immediately read `forbidden_order_realised_rate 0.0` on the
  same card.
- **Negative tests**: `test_causal_order.py (d)` now requires
  `metrics.forbidden_order_realised_rate == 0.0` while `metrics.false_correlation_rate == 1.0`
  on the true chain (revert the metric emission -> check fails); and
  `tools/test_generate_scorecard.py` gains a registry check that the twin row
  exists and the FCR blind-spot names it (revert the registry edit -> check fails;
  `generate_scorecard.py --check` also fails on any divergence).

### Limits of the new metric (read before quoting the 0.0)

- **It is true by construction on the true chain.** The twin generates its events in the oracle's causal order, so
  `forbidden_order_realised_rate` is 0.0 there by design. It certifies that the harness and the clock agree with the oracle; it
  does not measure how well the correlator avoids false correlation. The mirrored-chain control (1.0) only shows that the metric
  can move.
- **n = 2.** It is graded on the two oracle-forbidden pairs of one synthetic storyline.
- **The headline `false_correlation_rate` stays 1.0.** The graph still joins both forbidden pairs, by ratified design. Nothing in this
  change makes the correlator better; it makes the claim more precise.
- **Open (owner decision):** `README.md` still says incidents carry a "typed causal graph". The graph's direction comes from entity
  type, not event time (ADR-009/010), so "typed entity graph" would be the accurate wording. This PR does not change the README.

## 5. Evidence file:line index

| claim | evidence |
|---|---|
| graph joins both forbidden pairs | `report.py:28-38`, `report.py:925-939`, `oracle_consistency.py:124-125` (waiver entries), measured `[FORBIDDEN]` lines |
| join is order-blind | `report.py:994-1004`, `eval/twin/causal_order.py:3-14` (module docstring), `eval/adversarial/order_controls.py:9` |
| graph side is ratified/waived | `oracle_consistency.py:110-151` (`_ORDER_BLIND`, all dated 2026-10-02/03/14), scorecard blind-spot + LIMIT 3, `docs/handoff/design-specs/step3_causal-order.json` fact 3 |
| oracle pairs | `eval/twin/oracle.yaml:89-97` |
| time-aware counterpart measured 0.0 | this run: `report.latest.json` `causal_order_details.per_forbidden_pair` (both `realised: False`), `forbidden_order_realised_rate = 0.0` |
| once-frozen baselines unchanged | `eval/twin/baseline_scenarios.json` atoms `scn/ai_to_ot/base/false_correlation_rate=1.0`, `chain_fidelity=0.6` (pinned); `baseline.json` sha256 asserted in `test_causal_order.py:363-364` |