# Proposal: giving WS-8 an honest notion of event time on its edges

**Status:** proposal only. **Needs an owner decision** before anything in `services/` or `contracts/` changes; nothing in this document is ratified, and ADR-009 / ADR-010 stay authoritative.
**Date:** 2026-10-02 · **Nothing in `services/` or `contracts/` changes in the step that wrote this.** The evaluation harness gained `eval/twin/causal_order.py` and `eval/adversarial/order_controls.py` (read-only consumers of the existing `incident.graph` payload).
**Touches if adopted:** option A, docs and a contract test only. Option B, one new pure read-side module beside `campaigns.py`. Options C and D are listed for the owner and are not designed here.

## The problem, measured

`chain_fidelity` and `false_correlation_rate` ask "is there an edge from an entity on the earlier side to an entity at step *t*?" and never read a clock. To check what that means in practice, each registered storyline was replayed with every event moved to `lo + hi - t` (the attack happens backwards) and delivery re-sorted so it follows the logs. Seed 7, measured by `python eval/adversarial/order_controls.py` and pinned by `eval/adversarial/test_order_controls.py`:

| storyline | tpr | chain_fidelity | false_correlation_rate | directional_discrimination | incident_count | `alert_order_ok` | `order_concordance` |
|---|---|---|---|---|---|---|---|
| `ai_to_ot`, true order | 1.0 | 0.6 | 1.0 | 0.0 | 2 | True | 1.0 |
| `ai_to_ot`, mirrored | 1.0 | 0.6 | 1.0 | 0.0 | 2 | False | 0.0 |
| `it_intrusion`, true order | 1.0 | 0.5 | 1.0 | 0.0 | 3 | True | 1.0 |
| `it_intrusion`, mirrored | 1.0 | 0.5 | 1.0 | 0.0 | 3 | False | 0.0 |
| `infra_takeover`, true order | 1.0 | 0.5 | 1.0 | 0.0 | 1 | True | 1.0 |
| `infra_takeover`, mirrored | 1.0 | 0.5 | 1.0 | 0.0 | 1 | False | 0.0 |

Every legacy join metric is identical on the true and the reversed attack. Only the order metrics move, and `order_concordance` is a **timestamp invariant**: it is 1.0 by construction on the harness's own chains because the storylines are authored in oracle order. It shows the harness, the parser and WS-3's chronology keep the clock intact. It does **not** show that WS-8 reconstructs causal order.

Why WS-8 cannot, as designed:

1. **An edge is evidenced by one alert, so it has one instant.** Under ADR-009 / ADR-010 an edge exists iff ONE member alert carries both endpoints in its own fields. `ts_ms` is that alert's time. A single instant cannot say "A before B".
2. **Direction comes from entity type, not time.** `correlator._edge_spec` fixes `actor → ip`, `actor → device`, `device → ip` from the two node types. The same pair renders the same directed edge in every incident.
3. **`ts_ms` is the earliest evidence of the WINNING kind, not the first co-occurrence of the pair.** The winner is chosen by kind rank first (typed kinds outrank the field-pair fallback), then `(ts_ms, event_id)`. A typed kind arriving later can displace an earlier field-pair edge and move `ts_ms` later.
4. **Two incidents can carry different `ts_ms` for the same pair.** The harness therefore takes the minimum `ts_ms` per pair over attributed edges across the per-incident graphs, and never the first-seen edge of a deduplicated union.
5. On `ai_to_ot` the union graph is a single edge, so the edge-time term is vacuous there; only event order discriminates.

The consequence for the evaluation: while the graph cannot express order, any order metric reported beside `chain_fidelity` is measuring the input, not WS-8. The harness reports `causal_order_fidelity` and `order_concordance` as co-metrics for exactly this reason and labels the second one as an invariant. Which metric leads the report is a separate owner decision and has not been made.

## What this proposal is not

- Not a change to promotion, tracks, incident ids, scoring or the `incidents` topic. Tracks still never merge.
- Not a claim that "A caused B". Even with every option below, time order is necessary for causation and nowhere near sufficient.
- Not a request to relax the single-alert rule. Options A and B keep it. Option D would break it and is listed only so the owner can see the cost.

## Options, cheapest first

### A. Document and contract-test the existing `ts_ms` semantics (no schema change)

State plainly, in `services/ws8-correlation/INTERFACE.md`, what `ts_ms` is: the sanitized time of the alert that evidenced the winning kind, chosen by kind rank before time; the digest value used for time-less alerts can never equal a real alert time. Add a test in `test_incident_graph_v2.py` that pins the three cases the harness already relies on: (1) a typed kind arriving later displaces an earlier field-pair edge and `ts_ms` follows the winner; (2) the same pair in two incidents can carry two `ts_ms` values; (3) a time-less alert yields a digest `ts_ms` that matches no alert time.

- **Cost:** a documentation paragraph and one test file. No behaviour change.
- **Unlocks:** the harness's edge-attribution rule (`causal_order.attribute_edges`) becomes a documented contract instead of an observed behaviour, so a legitimate change to kind precedence turns the harness red on purpose rather than by accident.
- **Does not unlock:** any new product capability, and it cannot move `directional_discrimination`.

### B. A read-side `timeline` over an incident's member alerts (like `campaigns.py`)

Add a new pure module `services/ws8-correlation/timeline.py`, mirroring `campaigns.py`: given an incident document and its member alerts, return the alerts ordered by time and grouped by tactic, with ties kept visible. It is computed on read. It does not touch promotion, ids, topics or mappings, and it makes no cross-alert inference: it sorts alerts the incident already contains. `services/ws3-indexer/evidence_package.py` already presents alert blocks chronologically (`_sort_time`), so this gives the same ordering a named, testable, non-package home.

- **Cost:** one pure module plus tests, in the same shape as the campaign view. Needs the owner's yes because it is a product addition even though it touches no contract.
- **Unlocks:** a product output the harness can grade for order beyond the evidence package: a `timeline_order_ok` against the oracle's `allowed_relationships` DAG, graded by `causal_order.grade_causal_order` with the timeline as the source of event times instead of the alert list the harness rebuilds itself.
- **Does not unlock:** `directional_discrimination`, because the graph edges are unchanged.

### C. Additive optional edge fields (owner decision, not designed here)

Optional fields such as `first_ts_ms`, `last_ts_ms`, `evidence_count` on `incident.graph` edges, taken over all evidencing members regardless of kind. This changes a frozen bus message schema, needs roadmap section 5.2 sign-off, and consumer strictness has to be checked first. Listed for the owner; no design or estimate is committed here.

### D. A temporal edge family such as `precedes` (owner decision, not recommended as written)

An edge that says one alert preceded another. This contradicts the ratified ADR-009 / ADR-010 rule "no transitive inference; an edge exists iff one alert carries both endpoints" and would need an ADR that explicitly supersedes it. Listed so the cost is visible; not recommended without that ADR.

## What each option would let the harness claim

| option | new harness claim it supports | can move `directional_discrimination`? |
|---|---|---|
| none (today) | event order is intact end to end (timestamp invariant) | no |
| A | edge time semantics are a tested contract | no |
| B | the analyst-facing timeline presents the attack in oracle order | no |
| C, D | the graph itself carries order | possibly; if it reaches 0.5 or more the harness's `reporting_policy` would re-promote the legacy pair to co-headline |

## Decisions for the owner

1. Option A: yes or no. (Low risk; recommended as the first step.)
2. Option B: may a read-side `timeline.py` be added under `services/ws8-correlation/`, following the `campaigns.py` precedent?
3. Options C and D: is either wanted at all? C needs the bus-schema sign-off and a consumer-strictness check. D needs a superseding ADR.
4. Separate from the product: the harness currently **co-reports** `causal_order_fidelity` and `order_concordance` beside `chain_fidelity` and leads with neither. Whether the report should lead with the order metric, and whether `chain_fidelity` / `false_correlation_rate` should be relabelled "entity-bridge only", is the owner's call. It has not been applied.
