# ADR 011: Event time on `incident.graph` edges (WS-8 edge-time, option C)

**Status:** Proposed. **Not Accepted: owner sign-off pending.** Nothing in
`services/`, `contracts/` or `eval/` changes until the owner ticks the
checklist at the end. **Date:** 2026-11-06. **Amends, if accepted:** the
`incident.graph` v2 payload of ADR-010 (additive optional edge fields only;
`version` stays 2). Everything else in ADR-009 / ADR-010 (no transitive
inference, tracks never merge, the `incidents` payload, partition key) is kept.

**How to read the claims below.** Every number or code fact cites the file I
read in the 2026-11-06 worktree (`origin/main` `182a4ab`). Anything I did not
run or open is marked **[UNVERIFIED]**. Items tagged **[MEASURED 2026-11-06]**
were produced by running the real twin pipeline in-process (memory bus, seed 7,
all 11 registered storylines, HEAD `27b54a3`) with throwaway scripts kept
outside the repo; the method, commands and full tables are in the new section
"Measurements (2026-11-06)" before the sign-off checklist. No service,
contract or eval file was changed to take them: the four proposed fields were
computed inside the scripts only. The first draft of this ADR ran no code.

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
  **[UNVERIFIED]** that this in-correlator cache fingerprint (`_graph_signature`)
  covers every input once the code is written; it is verified only by that
  test. (Not to be confused with the eval-side `system_fingerprint`, which is
  now **[MEASURED 2026-11-06]**: see Measurements, item 4.)
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
  four integers per edge. **[MEASURED 2026-11-06]** across the 21 incident
  graphs the 11 storylines emit (mean 3.2, max 7 edges): compact JSON grows from
  mean 1,681 B (p95 2,939, max 2,939) to mean 1,997 B (p95 3,632, max 3,632),
  +316 B per incident on average (+18.8 %), +693 B at most; exactly +99 B per edge.
  Arithmetic (not measured) at the 600-edge ceiling: about +59 KB. Details in
  Measurements, item 2.
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
   window) does not apply to these fields. **[MEASURED 2026-11-06, twin path
   only]** all 67 emitted edges carry identical `ts_ms` and intervals under
   `event` and `clamp`. **[UNVERIFIED]** on a live WS-4 deployment and by a
   committed test.
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
  validated against the mirror control before it is trusted.
  **[MEASURED 2026-11-06]** Two simple candidates were built and run in a
  script (Measurements, item 5). Both are non-vacuous (mirror drives them to
  0.0, shift_1h leaves them unchanged), but **neither reaches 0.5 on the
  evidence-carrying definition of a graded pair**: the strict predicate scores
  0.375 (6 of 16, 95 % Wilson 0.185 to 0.614) because 10 of the 16 pairs read
  `concurrent` (an edge's interval spans evidence from several steps). The one
  variant above 0.5 (0.625, 5 of 8) rests on 8 pairs, below the n bar, with an
  interval (0.306 to 0.863) that contains 0.5.
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
  and 10 are within the raw pool; that is an UPPER bound.
  **[MEASURED 2026-11-06]** The gradable subset is now counted (Measurements,
  item 1): both endpoints entity-bearing nodes of one emitted incident graph
  AND timed evidence on each side gives **23 allowed + 6 forbidden = 29**;
  requiring the two sides to rest on two *distinct* edges (the only case an
  edge-to-edge order test can read) gives **16 + 5 = 21**; and restricting to
  what a consumer can attribute from the graph alone (the edge's winning
  alert, `causal_order.attribute_edges`) gives **8 + 4 = 12**. **The bar
  (n >= 30, >= 10 forbidden) is not reachable today under any of the three
  definitions** (max 29 with 6 forbidden; the storyline-count and 25 % limits
  pass for the first two). The honest outcome stays "claim not demonstrated",
  not a lower n. What would be needed is in Measurements, item 1.
- **Pass criterion for the README gate (owner to ratify).**
  `directional_discrimination_timed >= 0.5` (the threshold the existing
  `causal_order.reporting_policy` already uses) at n >= 30 as above, *and* the
  mirror/swap/shift controls fail it, *and* the timed forbidden-pair metric
  reads below its failing value on pairs the graph really joins. Until then the
  README wording is kept (the owner's decision), and `reporting_policy` stays
  `co_reported`. **[MEASURED 2026-11-06] Status today: not met, on two counts.**
  (1) n: 29 / 21 / 12 gradable pairs and 6 / 5 / 4 forbidden, against 30 and 10.
  (2) The number itself: on the 21-pair set the strict predicate reads 0.375,
  not 0.5. The controls part is met (mirror 0.0, swap 0.25, shift_1h unchanged),
  except that the weaker "evidence starts earlier" predicate on the 8-pair set
  reads exactly 0.5 under swap, which a `>= 0.5` bar would pass: use the strict
  predicate, not the weak one, in the spec. Because 10 of 16 pairs read
  `concurrent`, the four edge-level fields as proposed cap what the metric can
  show; reaching 0.5 probably needs finer evidence than one interval per edge
  (for example per-kind or per-step intervals), which is a different payload
  than this ADR proposes and would need its own sign-off. **[UNVERIFIED]** that
  any payload reaches 0.5; nothing finer was built.
- **Ratchet.** New atoms are added; no frozen atom changes.
  **[MEASURED 2026-11-06]** (read from `eval/twin/ratchet*.py`, plus a run that
  shows no existing graded value moves when the four fields are present): no
  waiver is needed; one `ratchet.py refresh --reason` history row is. Today no
  order metric is an atom at all, so the metric must first be wired into the
  atom builders. Exact steps, with line citations, in Measurements, item 3.

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
   separate PR. **[MEASURED 2026-11-06]** this is not optional: the current 11
   storylines top out at 21 distinct-edge pairs (5 forbidden). Extrapolated
   need (Measurements, item 1): about 5 new storylines at the best observed
   rate, about 11 at the average rate. It should be sequenced BEFORE step 1
   if the owner wants to know whether the gate is reachable before touching the
   bus schema.
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
  be reported as such. **[MEASURED 2026-11-06]** This is the current state: the
  metric moves (mirror 0.0), but identity reads 0.375 on 16 pairs and n is short.
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

## Measurements (2026-11-06)

**Method.** Throwaway scripts, kept outside the repo (nothing under `services/`,
`contracts/` or `eval/` was edited), drive the real twin in-process: payloads ->
real WS-2 parse -> real WS-4 rules -> real WS-8 `Correlator` on the memory bus,
seed 7, all 11 registered storylines (`scenario_registry.ALL`), via
`scenario_registry.grade()`. Two wrappers are installed at run time only: one
around `Correlator._build_incident_graph_v2` that recomputes, from the same
`side` table, the four proposed fields per edge (min and max alert `time` over
distinct member ids that evidence the edge's `(from, to)` pair, any kind,
excluding `time_fallback` members; counts of distinct and of timed members)
and returns the **unchanged** v2 graph; one around
`causal_order.grade_causal_order` that records its inputs. The recorded graphs
were asserted equal to the graphs the grader received. Scripts (names only,
re-creatable from this paragraph): `cap.py` (harness), `a1.py` (pair funnel),
`a2.py` (predicate and controls; ~3 min), `a3.py` (payload), `a4.py`
(no-regression), `a5.py` (env). Run as `python aN.py` from one directory with
the repo's `eval/twin`, `eval/adversarial`, `services` on `sys.path`; the
controls reuse `eval/adversarial/order_controls.py` (`mirror_event_time`,
`swap_adjacent_steps`, `pick_swap_pair`) and `mutate_generic` `timing/shift_1h`
unchanged. `cloud_iam_abuse` promotes no incident (0 graphs), so it contributes
0 to every graph-based count.

**Two checks that the fields are inert for today's numbers.** (a) Running every
storyline twice, once with the four fields present on the graphs the grader
reads and once without, the full `_grade_chain` result dict differs only in
the echoed `graph_edges` (the new keys), the wall-clock `assembly_*` samples
(documented informational) and `incident_reconstruction.package_id` (10 of 11
storylines; it is a content hash that includes the edges, and the repo only
compares it run-to-run, `eval/twin/test_chain_fidelity.py:258`, so nothing pins
its value); `chain_fidelity`, `false_correlation_rate`,
`directional_discrimination`, `order_concordance`, `causal_order_fidelity`
and every other value are identical on all 11. (b) The edge intervals and
`ts_ms` of all 67 emitted edges are identical with
`FENGARDE_WINDOW_TIME_SOURCE=event` and with the default `clamp` on the twin,
consistent with fact 7 (the alert's `time` is the raw event time); this is the
twin path only, not a live WS-4 deployment.

### 1. Gradable-pair count **[MEASURED 2026-11-06]**

Allowed/forbidden counts, per oracle relationship, by cumulative stage:
raw = pairs in the oracle yaml; **F1** = both steps entity-bearing and timed
(the set `causal_order` already grades); **F2** = F1 and both steps' entities
appear as nodes of one emitted incident graph; **F3** = F2 and each step has a
timed alert that evidences some edge of that graph (both sides have timed edge
evidence); **F4** = F3 and the two sides rest on two distinct edges of the same
graph (the only case an edge-to-edge order test can compare); **F4w** = like F4
but each edge is attributed to a step only through its winning alert
(`causal_order.attribute_edges`), i.e. what a consumer can derive from the
graph without re-deriving evidence.

| storyline | raw | F1 | F2 | F3 | F4 | F4w |
|---|---|---|---|---|---|---|
| ai_to_ot | 7/2 | 5/2 | 5/2 | 2/1 | 0/0 | 0/0 |
| it_intrusion | 6/2 | 6/2 | 6/2 | 1/1 | 1/1 | 1/1 |
| infra_takeover | 2/1 | 2/1 | 2/1 | 2/1 | 2/1 | 2/1 |
| cloud_iam_abuse | 6/1 | 6/1 | 0/0 | 0/0 | 0/0 | 0/0 |
| insider_exfil | 5/2 | 5/2 | 5/2 | 1/0 | 0/0 | 0/0 |
| network_credential_abuse | 2/1 | 2/1 | 2/0 | 1/0 | 0/0 | 0/0 |
| ot_opcua_sabotage | 4/1 | 4/1 | 4/1 | 3/0 | 2/0 | 1/0 |
| phishing_bec | 4/2 | 4/2 | 4/2 | 3/1 | 3/1 | 3/1 |
| ransomware | 6/2 | 6/2 | 6/2 | 3/1 | 3/1 | 0/1 |
| supply_chain_ci | 3/1 | 3/1 | 3/1 | 3/1 | 1/1 | 0/0 |
| win_credential_theft | 4/1 | 4/1 | 4/0 | 4/0 | 4/0 | 1/0 |
| **total** | **49/16** | **47/16** | **41/13** | **23/6** | **16/5** | **8/4** |

The raw column reproduces the 49 allowed / 16 forbidden count of the first
draft. Against the proposed bar:

| bar | F3 (29 pairs) | F4 (21 pairs) | F4w (12 pairs) |
|---|---|---|---|
| n >= 30 | **no (29)** | **no (21)** | **no (12)** |
| >= 6 storylines contribute | yes (10) | yes (7) | yes (6) |
| <= 25 % from one storyline | yes (max 4/29 = 13.8 %) | yes (max 4/21 = 19.0 %) | **no (phishing_bec 4/12 = 33 %)** |
| >= 10 forbidden | **no (6)** | **no (5)** | **no (4)** |

**Plainly: the bar is not reachable today.** The closest reading (F3) is one
pair short on n and four short on forbidden pairs; the reading an edge-to-edge
predicate can actually use (F4) is nine short on n and five short on forbidden
pairs. The binding constraint is forbidden pairs: no storyline contributes more
than one forbidden pair at F4 (it_intrusion, infra_takeover, phishing_bec,
ransomware, supply_chain_ci one each; 5 in total). **What would be needed
(extrapolation, not a measurement):** at F4 the registry yields 1.9 pairs and
0.45 forbidden pairs per storyline on average, and at best 4 pairs and 1
forbidden pair. To reach 30 pairs and 10 forbidden: at least 5 new storylines,
each authored so one forbidden pair survives to distinct timed edges (best
observed rate), and about 11 at the average rate. At F4w (12 pairs, 4 forbidden)
the figures are about 6 at best rate and about 17 at average. Pairs inside one
storyline share edges, so n overstates the independent evidence; the bar's
Wilson interval is therefore optimistic. `ai_to_ot`, the headline storyline,
contributes 0 at F4 (its two incidents each have a single edge): it cannot be
graded by any edge-to-edge predicate, only noted as ungradable.

### 2. Payload growth **[MEASURED 2026-11-06]**

Compact JSON (`separators=(",", ":")`, sorted keys, UTF-8), per emitted
`incident.graph` v2 payload, 21 payloads across 10 storylines:

| | mean | p95 | max |
|---|---|---|---|
| today | 1,681.4 B | 2,939 B | 2,939 B |
| with the four fields | 1,997.2 B | 3,632 B | 3,632 B |
| delta | +315.9 B (+18.8 %) | +693 B | +693 B |

Edges per payload: mean 3.2, max 7. Each edge grows by exactly 99 B (13-digit
millisecond times, one-digit counts). p95 equals max because n = 21 and two
ransomware payloads tie at the top. Arithmetic, not measured: 600 edges (3 x
the 200-member cap) x 99 B is about 59 KB extra, a few bytes more with
three-digit counts. Not measured: Redis stream, WS-3 index or dashboard cost.

### 3. Ratchet: what introducing new pinned atoms takes **[MEASURED 2026-11-06]**

Read from `eval/twin/ratchet.py`, `ratchet_measure.py`, `ratchet_history.jsonl`,
`ratchet_waivers.json`, `fingerprint.py`.

1. **Today no order metric is an atom.** `eval/twin/baseline_scenarios.json`
   holds no `order_concordance`, `causal_order_fidelity` or similar key (grep).
   Per-scenario base atoms come only from the whitelist `base_fields` in
   `ratchet_measure.py:40-46` (11 fields) read out of each scenario's
   `baseline` dict, which `eval/adversarial/scenario_matrix.py:271-285` builds.
   A new `scn/<s>/base/directional_discrimination_timed` therefore needs:
   (a) the value added to that `baseline` dict (an `eval/adversarial` file, so
   it is fingerprinted); (b) its name added to `base_fields`
   (`ratchet_measure.py:40`); (c) a direction rule in `DIRECTION_RULES`
   (`ratchet.py:30-58`; base rules at `:31` higher and `:33` pinned). Without
   (c) the atom silently defaults to `pinned` (`direction_for`, `:84-88`) and
   `unmatched_direction_atoms` (`:91-96`) would list it. Pin it first; a
   string status such as `insufficient_n` is legal for a pinned atom because
   pinned compares by equality (`ratchet.py:219-224`, `_equal`).
2. **The existing frozen atoms are not touched** (check (a) above: no graded
   value moves). `scn/ai_to_ot/base/chain_fidelity = 0.6` and
   `base/false_correlation_rate = 1.0` are in `baseline_scenarios.json:612,614`
   and match the pinned rules.
3. **A new atom is a `NEW` failure until recorded.** `ratchet.py check` fails on
   it (`compare`, `ratchet.py:208-211`, summary at `:366`). `ratchet.py refresh
   --reason "<at least 20 characters>"` accepts it (`NEW` is excluded from the
   "hard" failures, `:426`; reason length `:414-416`), rewrites the baseline
   (`:470`) and appends one history row (`:471-474`). **No waiver is needed**:
   waivers cover regressions of existing atoms only (`_waivers_for`, `:189`,
   used at `:246`) and `ratchet_waivers.json` is empty. **A history entry is
   required** and is produced by `refresh`; precedent: the 2026-10-28 row
   ("storylines 10-11 ... new atoms only, no regression", 594 atoms added, no
   waiver). The baseline file says "Never edit by hand" (`:306`).
4. **The PR guard** (`ratchet.py guard --base origin/main`, `guard_compare`,
   `:489`) iterates the base atoms only (`:521`), so additions pass; it fails
   if the history is not a pure append (`:499`).
5. **Every lane must be re-run first.** The correlator change and the
   `scenario_matrix.py` change alter the system fingerprint, so
   `measure_artifacts` marks every artifact stale (`ratchet_measure.py:258`,
   `:289`: layer_a, scenario_matrix, evasion, corpus, report, fire_check) and
   `check`/`refresh` refuse until each lane is regenerated. Editing only
   `ratchet.py`/`ratchet_measure.py` would not do this (they are excluded from
   the fingerprint, `fingerprint.py:34-35`).

### 4. Fingerprint coverage **[MEASURED 2026-11-06]**

`system_fingerprint` hashes `fingerprint_files()`; I ran it (236 files) and
tested the paths that would change once edge times exist:

| input that changes | covered? | basis |
|---|---|---|
| `services/ws8-correlation/correlator.py` (new fields) | yes | `services/**/*.py`, `fingerprint.py:29` |
| `services/ws4-detection/main.py` (alert `time`) | yes | same glob |
| new/edited metric code in `eval/twin/*.py`, `eval/adversarial/*.py` (`causal_order.py`, `scenario_matrix.py`, `order_controls.py`) | yes | `:20`, `:22` |
| storyline builders and oracles (`storyline_*.py`, `oracle*.yaml`, `scenario.py`) | yes | `:20`, `eval/twin/oracle*.yaml` glob |
| contract JSON/YAML (an edge schema, if one is ever added there) | yes | `contracts/**/*.{yml,yaml,json}`, `:12-14` |
| `services/ws8-correlation/INTERFACE.md`, `contracts/bus-topics.md` | **no** (docs; they do not feed a measured atom) | `contracts/**` is yaml/yml/json only |
| `tools/generate_scorecard.py`, `eval/scorecard_registry.py` | **no** (they read artifacts, not produce atoms) | not in the globs |
| `eval/twin/ratchet.py`, `ratchet_measure.py`, `fingerprint.py`, `test_*.py` | excluded on purpose | `:34-35`, `:46` |
| `FENGARDE_WINDOW_TIME_SOURCE` (environment) | **no** (env is never hashed; pre-existing for every atom) | `engine.py:303` reads it |

For the last row, the edge times on the twin are identical under `event` and
`clamp` (67 of 67 edges), so the gap does not affect the new fields on the
twin; it would matter only if a future metric read WS-4 window state. Python
and PyYAML versions are not hashed either (pre-existing, not specific to this
change). Conclusion: **every code input that changes once edge times exist is
covered**; the uncovered ones are documentation or environment that does not
move twin output. No fingerprint change is needed for this ADR.

### 5. Candidate predicate `directional_discrimination_timed` **[MEASURED 2026-11-06]**

Two simple predicates, for a graded allowed pair `f -> t`, where `E_f`, `E_t`
are the edges attributed to each step in graphs where both appear, `first(S)` =
min `first_ts_ms`, `last(S)` = max `last_ts_ms`:

- **P1 strict (the ADR rule):** forward iff `last(E_f) < first(E_t)`; the pair
  discriminates iff forward and not reverse (`last(E_t) < first(E_f)`).
  Overlap or tie is `concurrent` and counts as a failure of discrimination.
- **P2 start (weak):** forward iff `first(E_f) < first(E_t)`; same
  "forward and not reverse" rule.

Score = discriminating pairs / graded allowed pairs. Companion
`forbidden_order_graph_realised` = forbidden pairs whose forward test is true /
graded forbidden pairs (failing value 1.0, passing 0.0). Attribution of edges
to steps is either **carrier** (a timed alert of the step evidences the edge;
the F4 set, 16 allowed + 5 forbidden; needs the harness to know the carriers,
which the four fields do not expose) or **winner** (F4w, 8 + 4;
derivable from the graph today).

| variant (attribution, predicate) | identity | mirror | swap | shift_1h |
|---|---|---|---|---|
| carrier, P1 | **6/16 = 0.375**; concurrent 10; forbidden realised 0/5 | 0/15 = 0.0; reverse-only 5; forbidden realised 3/4 | 4/16 = 0.25; forbidden 0/5 | 6/16 = 0.375 |
| carrier, P2 | 6/16 = 0.375; forbidden 0/5 | 0/15 = 0.0; forbidden 4/4 | 5/16 = 0.3125; forbidden 0/5 | 6/16 = 0.375 |
| winner, P1 | 5/8 = 0.625; concurrent 3; forbidden 0/4 | 0/9 = 0.0; forbidden 3/3 | 2/8 = 0.25; forbidden 0/4 | 5/8 = 0.625 |
| winner, P2 | 7/8 = 0.875; forbidden 0/4 | 1/9 = 0.111; forbidden 3/3 | **4/8 = 0.5**; forbidden 0/4 | 7/8 = 0.875 |

Wilson 95 % intervals: carrier P1 identity 6/16 is 0.185 to 0.614; winner P1
identity 5/8 is 0.306 to 0.863. The swap pairs picked by `pick_swap_pair` are the
ones `order_controls.py` prints (e.g. `infra_takeover` cloud_root_login /
privileged_container); the mirrored runs keep the same incident count on every
storyline (the validity rule of `order_controls`).

Honest reading:

- **It discriminates.** Unlike `chain_fidelity`, `false_correlation_rate` and
  `directional_discrimination`, which are identical under mirror (fact 3), every
  variant falls to 0.0 (or 0.111) under mirror, the forbidden-realised rate
  rises from 0 to all or nearly all, and shift_1h changes nothing. So the
  quantity is a function of the clock in the pipeline's output, not just of the
  authored event list.
- **It does not pass the 0.5 bar where it counts.** On the 21-pair carrier set
  it reads 0.375; the winner-attribution 0.625 is on 8 pairs with an interval
  containing 0.5, and the 8-pair weak predicate reaches 0.5 under swap, so it
  would not "fail" the swap control at a `>= 0.5` bar.
- **Why it is low.** 10 of 16 carrier pairs are `concurrent`: an edge such as
  `actor -> ip` is evidenced by alerts from several steps, so its single
  `[first, last]` interval overlaps its neighbours'. Concretely, win_credential_theft
  has 4 gradable pairs and 0 discriminating, ransomware 3 and 0. Storylines that
  do discriminate are infra_takeover (2 of 2), phishing_bec (2 of 3),
  ot_opcua_sabotage (1 of 2), supply_chain_ci (1 of 1).
- **Identity is partly authored.** The twin authors steps in oracle order, so a
  high identity value is expected; only the mirror and swap rows carry
  evidence that the metric can say no.
- **Not done:** a fixed-pair-set comparison across variants (the graded set
  changes with the variant, e.g. 16 to 15 under mirror), predicates that use
  per-kind or per-step intervals, and any tolerance parameter.

## Recommendation changes from the measurements

1. The cost side is small: +99 B per edge, no existing graded value moves, no
   waiver, one ratchet history row. Building C as an *instrument* is cheap.
2. The gate side is not reachable on the current twin (n 29/21/12 vs 30; forbidden
   6/5/4 vs 10) and the value on the usable set (0.375) is below 0.5 even if n
   were met. Decision for the owner: either fund roughly 5 to 11 new storylines
   designed for distinct-edge forbidden pairs (checklist item 10), or accept
   alternative I (change the README wording to "typed entity graph") now and
   treat C as optional telemetry. This ADR does not recommend lowering n.
3. The four fields as proposed probably cap the metric: if the owner wants a
   chance at 0.5, ask the spec to evaluate per-step or per-kind intervals
   first (not built, **[UNVERIFIED]**).
4. Make the spec use the strict predicate (P1) and report `concurrent` as its
   own count; the weak predicate fails the swap control at `>= 0.5`.

## Owner sign-off checklist

Tick each line (or edit the line) before any code starts.

- [ ] 1. Confirm "option A first" means what is already shipped (2026-10-14:
  `ts_ms` contract + `timeline.py`), so the build step is C. Or say what else A
  should include.
- [ ] 2. Approve the bus-schema change: four optional `incident.graph` v2 edge
  fields (`first_ts_ms`, `last_ts_ms`, `evidence_count`,
  `timed_evidence_count`), `version` stays 2, partition key `incident_id`
  unchanged (roadmap section 5.2 gate). Measured cost: +99 B per edge, mean
  +316 B (+18.8 %) per incident payload, max +693 B on the twin; no existing
  graded value moves.
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
  event-time evidence", not "causal"). **Measured: this bar is NOT reachable on
  the current twin** (29 / 21 / 12 gradable pairs and 6 / 5 / 4 forbidden, vs 30
  and 10; the strict predicate reads 0.375 on the 21-pair set). Ratifying it
  means ratifying item 10, or choosing alternative I.
- [ ] 7. Confirm the legacy metrics and pinned atoms stay frozen and new atoms
  are added beside them. Measured: the process is `ratchet.py refresh --reason`
  (one history row, no waiver), after wiring the metric into
  `scenario_matrix.py`, `ratchet_measure.py` `base_fields` and `DIRECTION_RULES`,
  and re-running every lane (the fingerprint changes). Pin the new atoms first.
- [ ] 8. Confirm the consumer-strictness audit (including `fengarde-sec`) is a
  precondition to merging step 1.
- [ ] 9. Confirm D, E, F, G, J stay rejected and that alternative I is the
  fallback if the gate cannot be met. Measured: the gate cannot be met today.
- [ ] 10. Decide how to close the n gap, or accept I: fund at least 5 new
  storylines (about 11 at the average observed rate) authored so that at least
  one forbidden oracle pair per storyline survives to two distinct timed edges
  (10 forbidden pairs needed, 5 exist), BEFORE the bus-schema change merges.
  Or state that C is built as telemetry only and the README wording changes now.
- [ ] 11. Decide whether edge-to-step attribution may use the harness re-deriving
  carriers from alerts (21 pairs today) or only what the graph exposes through
  the winning alert (12 pairs). The four proposed fields support only the
  second; the first needs the harness to re-derive evidence from alerts.
- [ ] 12. Acknowledge that the four edge-level fields alone probably cannot
  reach 0.5 (10 of 16 pairs read `concurrent`), and say whether a finer payload
  (per-step or per-kind intervals) should be evaluated before accepting C.

## Status

Proposed 2026-11-06, measurements added the same day. Awaiting owner sign-off.
No code, contract, schema or eval file is changed by this document. What remains
**[UNVERIFIED]**: fact 7 beyond `make_alert` lines 660-730; consumer strictness
for `fengarde-sec` and the unaudited in-repo consumers; whether any payload
shape reaches 0.5; every extrapolated storyline count; Redis, WS-3 index and
dashboard behaviour with the larger payload; the `_ORDER_BLIND` entry count (not
re-run); the `incident-graphs` index mapping. The throwaway scripts are not in
the repo, so the measurements are reproducible only from the Method paragraph.
