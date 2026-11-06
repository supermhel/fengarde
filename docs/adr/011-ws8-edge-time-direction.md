# ADR 011: Event time on `incident.graph` edges (WS-8 edge-time, option C)

**Status:** Proposed. **Not Accepted: owner sign-off pending.** Nothing in
`services/`, `contracts/` or `eval/` changes until the owner ticks the
checklist at the end. **Date:** 2026-11-06. **Amends, if accepted:** the
`incident.graph` v2 payload of ADR-010 (additive optional edge fields only;
`version` stays 2). Everything else in ADR-009 / ADR-010 (no transitive
inference, tracks never merge, the `incidents` payload, partition key) is kept.

**How to read the claims below.** Every number or code fact cites the file I
read in the 2026-11-06 worktree (`origin/main` `182a4ab`). Anything I did not
run or open is marked **[UNVERIFIED]**. I ran no code and no eval for this ADR.

## Context

### What the README says versus what the graph does

`README.md:61` says "Incidents carry a typed causal graph". The graph's edges
are entity links. `correlator._edge_spec` fixes the direction from the two
entity *types* (`actor -> ip`, `actor -> device`, `device -> ip`;
`services/ws8-correlation/correlator.py:166-182`), and an edge exists iff ONE
member alert carries both endpoints. One alert has one instant, so a single
edge cannot say "A happened before B"
(`services/ws8-correlation/INTERFACE.md`, "What `ts_ms` means", item list and
closing sentence).

### Measured facts (read from the repo; not re-run)

1. **Twin scorecard, AI-to-OT, seed 7:** `false_correlation_rate` 1.0,
   `chain_fidelity` 0.6, `directional_discrimination` 0.0
   (`eval/SCORECARD.md:40-42`). The card's own text says the join "answers
   'joined' for a step pair and for the same pair reversed".
2. **The time-aware counterpart is 0.0 only by construction, on n = 2.**
   `forbidden_order_realised_rate` = 0.0 over `forbidden_timed` = 2 pairs
   (`process_anomaly->modbus_write`, `credential_use->agent_mcp_tool_call`;
   `eval/twin/oracle.yaml:89-97`). The twin authors its events in oracle order,
   so the clock cannot realise a forbidden direction; the findings doc says so
   in its "Limits of the new metric" section
   (`docs/false-correlation-findings.md` section 4). It certifies harness and
   clock agreement, not correlator quality.
3. **The legacy join metrics do not read a clock.** Time-mirrored copies of
   three storylines score identically on `chain_fidelity` (0.6 / 0.5 / 0.5),
   `false_correlation_rate` (1.0), `directional_discrimination` (0.0) and
   `incident_count`; only `alert_order_ok` and `order_concordance` move
   (`docs/proposals/2026-10-02-ws8-edge-time.md`, "The problem, measured";
   re-statement in `eval/twin/causal_order.py:1-14`). **[VERIFIED
   2026-11-06]** `python eval/adversarial/order_controls.py` runs and prints
   "order controls can say yes and no": under `mirror` the order-aware columns
   (`alert_order_ok`, `order_concordance`, `forbidden_order_realised_rate`) flip
   while the join metrics stay equal; under `shift_1h` they do not move.
4. **The class is waived, not fixed.** `eval/twin/oracle_consistency.py`
   carries a frozen `_ORDER_BLIND` waiver on **13** `("<storyline>", "forbidden",
   ...)` entries across 8 storylines (I counted the entries in the file; I did
   not run the check). Its text names the exit: "grading edge direction by event
   time or by WS-8 typed caused_by edges, a separate ratified step."
5. **Option A and option B of the 2026-10-02 proposal are already shipped.**
   Commit `b49e90f` (`feat(ws8): ts_ms contract test and read-side timeline
   view`): `INTERFACE.md` documents what `ts_ms` is and is not (owner decision
   2026-10-14), `test_incident_graph_v2.py::test_ts_ms_semantics_contract` pins
   it, and `services/ws8-correlation/timeline.py` exists. The proposal itself
   says A "cannot move `directional_discrimination`". **So "A first" is
   already done, and by its own definition cannot make the claim true.** This
   ADR therefore records A as the foundation and puts the real decision on C.
   (See checklist item 1: the owner should confirm that is what was meant.)
6. **What the edge time is today.** `ts_ms` is the sanitized time of the one
   alert that evidenced the *winning kind*; the winner is chosen by kind rank
   before time, then `(ts_ms, event_id)` (`correlator.py:371-380`, `:702-757`).
   A later typed kind displaces an earlier field-pair edge and moves `ts_ms`
   later. It is not "when the pair first co-occurred".
7. **The edge time is the raw event time, not the clamped window time.** WS-4's
   `make_alert` copies `"time": event.get("time")`
   (`services/ws4-detection/main.py:665`). The `FENGARDE_WINDOW_TIME_SOURCE`
   clamp changes the clock WS-4's *windows* and alert-id bucket use
   (`services/ws4-detection/engine.py`, `_window_time_of`), not the alert's
   `time`. I read lines 660-730 of `make_alert` and saw no `received_ms` or
   `time_clamped` field copied onto the alert; I did not read the rest of the
   function. **[UNVERIFIED beyond that range]** WS-8 then applies
   `_valid_window_time` (rejects bool, non-numeric, NaN/inf and times far ahead
   of wall clock; past times always pass) and falls back to processing time,
   flagged `time_fallback`, for a rejected time (`correlator.py:842-863`).
8. **Consumers.** The dashboard types an edge as `{from, to, kind, ts_ms?,
   event_id?}` (`services/ws7-dashboard/app/src/data/api.ts:70`). WS-3's
   evidence package sorts graph edges by `ts_ms or 0` for its timeline
   (`services/ws3-indexer/evidence_package.py:369-373`). WS-3 indexes
   `incident.graph` into `incident-graphs[-{tenant}]` keyed by `incident_id`,
   and `_coalesce` keeps the last payload per `(index, doc_id)`
   (`services/ws3-indexer/main.py:137-150`, `router.py:99-110`). There is no
   `incident-graphs` file under `contracts/opensearch-mappings/`, so I expect
   dynamic mapping, but I did not find where the index is created (re-checked
   2026-11-06: `incident-graphs` appears only in `services/ws3-indexer/router.py`
   and the storage adapters; the mapping files that exist for other indices set
   `"dynamic": "false"`, which would keep unknown keys in `_source` but not index
   them, so an `incident-graphs` template, if one is ever added, must list the
   four new keys or accept that they are stored but not searchable).
   **[UNVERIFIED]** Whether any consumer rejects unknown edge keys: I found no
   strict-schema check in the files above; re-checked 2026-11-06: the only in-repo consumers are the ws7 console (`app/src/data/api.ts` declares `IncidentGraph` as a TypeScript interface, no runtime schema validation; `Incidents.tsx` passes `graph.data.edges` to a `Graph` component) and ws3 storage, none of which rejects unknown keys; I did not audit every consumer
   (the roadmap section 5.2 "consumer strictness" check the 2026-10-02
   proposal asks for is therefore still open).

### The problem this ADR addresses

The owner decided (2026-11-05, `SSOT.md` row "0.12.0 prep") to make the claim
true before changing the README wording. The graph cannot currently support an
order statement, so no graded metric can show the claim is true, and the
frozen waiver list cannot be closed.

## Decision (proposed)

Add event-time **evidence intervals** to `incident.graph` v2 edges as optional,
additive fields (the proposal's option C), and add a **new** time-aware graph
metric that reads them. Keep every existing field, every edge direction and
every legacy metric exactly as is.

### Step 0 (option A): already in place, kept

Nothing to build. If C is accepted, the A contract test is extended (below) so
a change to either the winning-kind time or the new interval fails on purpose.

### Step 1 (option C): the bus-schema change

Why C needs a bus-schema change: the information a consumer needs (when the
*first and last* alert that carried both endpoints happened, across all kinds)
exists only inside WS-8's side table. `ts_ms` is the winning kind's time, so it
cannot be reused without changing the meaning of a field the harness and the
test already pin (see Alternatives, F). `incident.graph` is a frozen bus
message (`contracts/bus-topics.md:23`), and the roadmap section 5.2 guardrail
(quoted in ADR-010) requires explicit sign-off for such a change.

### What C adds, and what it does not

C makes the graph carry **when evidence for each edge was logged**, so that a
consumer can ask "did the evidence for edge X start before the evidence for
edge Y?". It does not make edge `from -> to` mean "caused" or "happened
before". Direction stays by entity type. Time order between edges is necessary
for causation and nowhere near sufficient. Consequence for the README: even
if every measurement below passes, "causal" will not be *proven* by time order
alone; the accurate wording after C is closer to "typed entity graph with
event-time evidence". The owner decided to keep the README wording until the
metric moves; checklist item 6 asks them to also decide what wording a pass
would justify.

## Exact bus payload change

Topic `incident.graph`, `version` stays **2**. Each element of `edges[]` gains
four optional keys. Existing keys, types, ordering and semantics are
unchanged.

| field | type | meaning |
|---|---|---|
| `first_ts_ms` | integer or `null` | minimum sanitized alert time over **all live member alerts of this incident that carry both endpoints**, any kind, excluding alerts whose time was the fallback |
| `last_ts_ms` | integer or `null` | maximum over the same set |
| `evidence_count` | integer >= 1 | number of distinct live member alerts (distinct member ids) carrying both endpoints, including untimed ones |
| `timed_evidence_count` | integer >= 0 | how many of those had a usable time; `first_ts_ms`/`last_ts_ms` are `null` iff this is 0 |

Rules:

- **Optionality / back-compat.** A producer that predates C omits all four.
  A consumer MUST treat absent and `null` identically: "no time claim". Because
  they are additive optional keys on an object array, a v2 consumer that ignores
  unknown keys is unaffected. `version` is not bumped: ADR-010 uses the integer
  to distinguish *shapes*, and no shape changes. Presence of the keys is the
  feature test. Dashboard `GraphEdge` and WS-3 need no change to keep working.
- **`ts_ms`, `event_id`, `kind`, `from`, `to` unchanged.** `ts_ms` keeps the
  option-A semantics. `first_ts_ms <= ts_ms <= last_ts_ms` holds whenever the
  winning alert was timed (a property test must assert it; the winning alert is
  one of the carriers).
- **Time-less alerts.** Never contribute to `first_ts_ms`/`last_ts_ms`; the
  sha256 digest used for `ts_ms` is never copied into the new fields. They are
  visible only through `evidence_count - timed_evidence_count`.
- **Determinism and idempotency under at-least-once delivery.** The four
  values are pure functions of the live member set, computed in the same
  `_build_incident_graph_v2` pass as `edges`, over the same `side` table keyed
  by member id. Redelivering an alert overwrites its own entry, so the count is
  of distinct members, never of deliveries; min, max and count are order
  independent. The same incident promoted twice, even from a fresh process,
  must emit byte-identical payloads (extend
  `test_redelivery_and_fresh_instance_emit_byte_identical_v2`). The cache-skip
  fingerprint `_graph_signature` already contains `(mid, time, tactic,
  event_id, time_fallback, cooccur, typed_signal)` per member
  (`correlator.py:644-656`), which are the only inputs, so no new fingerprint
  term is needed; a test must still prove that a changed member time
  invalidates the cache (the existing mutation test is the model).
  **[UNVERIFIED]** that the fingerprint covers every input once the code is
  written; it is verified only by that test.
- **Known non-monotonicity (documented, not fixed).** The values are over
  *live* members. Horizon sweep and the member cap (default 200; eviction
  drops the oldest by time, `correlator.py:907`) can remove the earliest
  evidence, so `first_ts_ms` can move *later* across successive messages for
  one incident, as `ts_ms` can today. Consumers must treat each message as the
  current snapshot, which the WS-3 last-wins coalescing already does.
- **Partition key: unchanged (`incident_id`).** No new topic, no new
  correlation unit. Ordering per incident is the Redis Streams order that
  ADR-010 already relies on.
- **Size.** Edges are bounded by 3 x live members (<= 600 at the default cap);
  four integers per edge. I did not measure the payload growth.
  **[UNVERIFIED]**
- **Scope of evidence.** Per incident, not per pair. Two incidents can carry
  different intervals for the same pair (option-A finding 2). Harness code
  keeps taking the per-pair minimum over incidents (`causal_order.collapse_min_ts`
  pattern) for `first_ts_ms`, and the maximum for `last_ts_ms`.

Files that change if accepted (listed so the owner can see blast radius; **no
file is changed by this ADR**): `services/ws8-correlation/correlator.py`,
`services/ws8-correlation/INTERFACE.md`, `contracts/bus-topics.md` (row 23),
`services/ws8-correlation/test_incident_graph_v2.py`, plus the eval files in
Migration step 3.

## How direction is derived from event time

Edge `from`/`to` stay type-derived. "Order" is a **derived relation between two
edges (or a step's evidence and an edge)**, computed by the consumer:

- `X before Y` iff `X.last_ts_ms < Y.first_ts_ms` (the intervals do not
  overlap and X is earlier).
- `X concurrent Y` otherwise. **Ties (equal timestamps) and overlapping
  intervals are `concurrent`, never ordered by an arbitrary key.** This
  mirrors what `timeline.py` already does with simultaneous alerts (same
  INTERFACE.md section).
- Either side `null` or absent: `unordered` (excluded from any denominator,
  reported as a count; never counted as 0 and never as 1).

**Clock skew and the clamp.** The new fields use the same clock `ts_ms` uses:
the alert's raw event `time` after WS-8's `_valid_window_time` (fact 7).
Consequences, stated plainly:

1. `FENGARDE_WINDOW_TIME_SOURCE=clamp` does **not** protect these fields. A log
   author who forges `time` forges the order this ADR exposes. The order is
   "as logged", and the docs must say so. This is the same trust level as
   `ts_ms` and the evidence-package timeline today, not a new exposure.
2. `FENGARDE_WINDOW_TIME_SOURCE=event` (replay and backfill) is the *correct*
   setting for order, and the clamp's documented residual (a) in
   `services/ws4-detection/INTERFACE.md` (clamped batches landing in one
   window) does not apply to these fields. **[UNVERIFIED]** by test; follows
   from fact 7.
3. Cross-source skew: two sources with different clock offsets can produce a
   false `before`. The ADR does **not** add a tolerance in this step.
   Recommendation (checklist item 4): ship strict ordering, and let the
   *metric* take an explicit tolerance parameter reported alongside the number,
   so skew sensitivity is measured, not hidden.
4. Not in this step: a trust flag for clamped events (it would need WS-4 to
   put `time_clamped` on the alert, a second schema change). Listed as Open
   question 2.

## Effect on the twin metrics, and what new measurements prove the claim

**Unchanged, by construction:** `chain_fidelity`, `false_correlation_rate`,
legacy `directional_discrimination`, and the pinned atoms
`scn/ai_to_ot/base/false_correlation_rate = 1.0` and `base/chain_fidelity = 0.6`
in `eval/twin/baseline_scenarios.json` (named in the findings doc as PINNED; I
did not re-read that file). The legacy join predicate reads entity presence
only, so adding edge fields cannot move it. Anyone expecting the scorecard's
`false_correlation_rate` to fall after C is wrong: it will stay 1.0 until the
join predicate itself changes, which this ADR does not propose (the legacy
metrics are frozen and honestly labelled).

**New metric (names provisional):** `directional_discrimination_timed` (and
companion `forbidden_order_graph_realised_rate`), computed from the emitted
graph's `first_ts_ms`/`last_ts_ms`, not from the harness's own event list.

Requirements the implementation spec must meet, because the existing numbers
are weak exactly where a naive version would be weak:

- **Not true by construction.** `order_concordance` and
  `forbidden_order_realised_rate` are properties of the authored input
  (fact 2). The new metric must be a function of the *pipeline output*.
- **Must fall under the existing negative controls.** The mirror, swap and
  shift controls in `eval/adversarial/order_controls.py` must drive the new
  metric toward its failing value on every storyline where the legacy metrics
  did not move (fact 3). A metric that does not move under mirroring is
  rejected.
- **Vacuity is reported, not scored.** On `ai_to_ot` the union graph is one
  edge (proposal, problem item 5), so an edge-to-edge order test has nothing to
  compare. Such pairs go into `ungradable` with a count and are excluded from
  the denominator. A pair is gradable only if both steps are timed,
  entity-bearing, and bridged by edges that carry non-null intervals.
- **A candidate predicate has a known weakness.** "Edge available by the end of
  step f" (`first_ts_ms <= last_event_time(f)`) holds for the forward and the
  reverse question when the bridging alert fires at step f, so it would not
  discriminate. The spec needs a predicate that compares *evidence intervals of
  different edges* (or an edge against a step's own interval), and it must be
  validated against the mirror control before it is trusted. I have not built
  or run any candidate. **[UNVERIFIED]** that any simple predicate reaches 0.5.
- **Minimum n.** To state that the claim holds I propose **at least 30
  gradable allowed-or-forbidden pairs across at least 6 storylines, with no
  storyline contributing more than 25 %**, reported with a 95 % Wilson interval,
  and at least 10 forbidden pairs among them (13 forbidden pairs are on the
  waiver list today, but only those whose steps are timed and bridged are
  gradable, which I have not counted). With 0 failures in 13 forbidden pairs
  the rule-of-three upper bound is about 23 %, which is why 13 alone cannot
  support a strong claim, and why n = 2 supports none. A parsed count
  (2026-11-06, YAML load of the 11 `eval/twin/oracle*.yaml` files, nodes carrying
  a boolean `allowed`) gives 49 allowed and 16 forbidden pairs, 65 in total, so 30
  and 10 are within the raw pool; that is an UPPER bound, because the gradable
  subset (timed, entity-bearing, emitted as a graph edge) is still not counted.
  **[UNVERIFIED]** that 30 gradable pairs are attainable; if it is not, the honest outcome is "claim not demonstrated", not
  a lower n.
- **Pass criterion for the README gate (owner to ratify).**
  `directional_discrimination_timed >= 0.5` (the threshold the existing
  `causal_order.reporting_policy` already uses) at n >= 30 as above, *and* the
  mirror/swap/shift controls fail it, *and* the timed forbidden-pair metric
  reads below its failing value on pairs the graph really joins. Until then the
  README wording is kept (the owner's decision), and `reporting_policy` stays
  `co_reported`.
- **Ratchet.** New atoms are added; no frozen atom changes. How atoms are added
  to `ratchet_history.jsonl` / `baseline_scenarios.json` and who approves is
  not specified here. **[UNVERIFIED]** process; the implementation spec must
  read `eval/twin/ratchet.py` first.

## Migration

0. (done) Option A and B shipped 2026-10-14.
1. On acceptance: ws8 emits the four fields; `INTERFACE.md`, `bus-topics.md`
   row 23 and `test_incident_graph_v2.py` updated in one PR. Emission starts
   immediately; consumers need no change.
2. Consumer-strictness audit (roadmap 5.2): confirm WS-3 mapping, dashboard
   and `fengarde-sec` (the cross-repo consumer mentioned in `SSOT.md`) tolerate
   unknown edge keys, before step 1 merges. **[UNVERIFIED]** for the
   cross-repo consumer, which I did not open.
3. Harness: add the timed metric, its negative controls, the `ungradable`
   count and the minimum-n guard (a run below the minimum reports the number as
   `insufficient_n`, not as a score). New scorecard rows via
   `tools/generate_scorecard.py`; legacy rows untouched.
4. Grow the pair set to the minimum n (new or extended storylines) as a
   separate PR.
5. Only after step 4 passes the criterion above: owner decides README wording.
   Rollback of 1 is deleting the four keys; no data migration, because the
   fields are recomputed from live state on every promotion and the indexed
   `incident-graphs` documents are overwritten per incident.
   Old indexed documents simply lack the keys.
6. The `_ORDER_BLIND` waiver is **not** removed by this ADR; closing it
   requires a later ratified step that changes what the oracle consistency
   check compares.

## Risks

- **False confidence.** A metric that moves because the harness authored the
  input in order. Mitigated by the controls and the pipeline-output rule above;
  not eliminated until the controls are actually run.
- **Forged or skewed logged times** (above). Order is as logged.
- **Metric may not move.** Because the legacy atoms are frozen, the graph can
  carry correct intervals and `directional_discrimination_timed` can still stay
  low if the oracle pairs share one bridging alert (the `ai_to_ot` shape). The
  outcome "the claim is not demonstrable on this twin" is acceptable and must
  be reported as such.
- **Live-member window.** Intervals can shrink or shift as evidence is evicted.
- **Cross-repo consumer.** `fengarde-sec` may validate edges strictly.
  **[UNVERIFIED]**
- **Scope creep toward D.** Once intervals exist it is tempting to emit
  `precedes` edges. Rejected below; reopening it needs its own ADR.

## Alternatives considered and rejected

- **D. A temporal edge family (`precedes`, between alerts or entities).**
  Rejected. It contradicts ADR-009 / ADR-010's rule that an edge exists iff one
  alert carries both endpoints; it would be a cross-alert inference, with up to
  quadratic edge growth, and it still needs a tie and skew policy. The
  proposal itself marks it "not recommended as written". Needs a superseding
  ADR if ever wanted.
- **E. Make edge direction follow time** (`from` = the entity seen first).
  Rejected. One alert gives one instant, so there is nothing to compare;
  it breaks the documented rule that the same pair is the same directed edge in
  every incident, and the frozen atoms and tests built on it.
- **F. Redefine `ts_ms` as the first co-occurrence of the pair.** Rejected.
  It changes the meaning of a field `eval/twin/causal_order.attribute_edges`
  and `test_ts_ms_semantics_contract` pin, without a schema change that a
  consumer could detect.
- **G. Carry every evidencing `(event_id, time)` per edge.** Rejected for now:
  unbounded by member cap per edge (up to 200 entries x up to 600 edges),
  larger payload, and `first`/`last`/`count` answer the ordering question.
  Can be reconsidered if consumers need per-evidence drill-down (the evidence
  package already holds it).
- **H. Only the read-side timeline (option B).** Shipped and kept, but it
  orders alerts, not graph edges, so it cannot make the graph claim true or
  move any graph metric (proposal, table "What each option would let the
  harness claim").
- **I. Change the README wording now and stop.** Cheapest and honest
  (`docs/false-correlation-findings.md` section 4 suggests "typed entity
  graph"). Not chosen by the owner decision of 2026-11-05, but it remains the
  fallback if the criterion cannot be met at the minimum n.
- **J. Clamped time on edges** (carry WS-4's window time). Rejected here: the
  alert does not carry it (fact 7) and the clamp is a defence for window
  counting, not an ordering truth; replay would be wrongly flattened.

## Open questions

1. Is a `time_clamped`/`time_source` flag on the alert (WS-4) wanted so the
   graph can mark forged-time edges? Second schema change; not proposed here.
2. Should an incident-level `first_ts_ms`/`last_ts_ms` also be added to the
   `incidents` topic? Not proposed: that payload stays byte-for-byte untouched.
3. Where does `fengarde-sec` read `incident.graph`? **[UNVERIFIED]**

## Owner sign-off checklist

Tick each line (or edit the line) before any code starts.

- [ ] 1. Confirm "option A first" means what is already shipped (2026-10-14:
  `ts_ms` contract + `timeline.py`), so the build step is C. Or say what else A
  should include.
- [ ] 2. Approve the bus-schema change: four optional `incident.graph` v2 edge
  fields (`first_ts_ms`, `last_ts_ms`, `evidence_count`,
  `timed_evidence_count`), `version` stays 2, partition key `incident_id`
  unchanged (roadmap section 5.2 gate).
- [ ] 3. Approve the semantics: evidence over live members of this incident,
  any kind, time-less alerts excluded from the interval, `first_ts_ms` may move
  later under eviction.
- [ ] 4. Approve strict ordering (ties and overlap are `concurrent`), no
  skew tolerance in the payload, tolerance as an explicit metric parameter.
- [ ] 5. Accept that edge times are raw logged times and are NOT protected by
  `FENGARDE_WINDOW_TIME_SOURCE=clamp` (and say whether Open question 1 should
  become its own ADR).
- [ ] 6. Ratify the gate for changing README wording: `directional_discrimination_timed
  >= 0.5`, n >= 30 gradable pairs, >= 6 storylines, <= 25 % per storyline,
  >= 10 forbidden pairs, controls fail it, 95 % interval reported. Decide
  also what wording a pass justifies (this ADR argues "typed entity graph with
  event-time evidence", not "causal").
- [ ] 7. Confirm the legacy metrics and pinned atoms stay frozen and new atoms
  are added beside them.
- [ ] 8. Confirm the consumer-strictness audit (including `fengarde-sec`) is a
  precondition to merging step 1.
- [ ] 9. Confirm D, E, F, G, J stay rejected and that alternative I is the
  fallback if the gate cannot be met.

## Status

Proposed 2026-11-06. Awaiting owner sign-off. No code, contract, schema or eval
file is changed by this document.
