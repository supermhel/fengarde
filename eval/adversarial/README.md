# FENGARDE adversarial system-level validation (Phase 4, WP-4-A)

The roadmap's Phase 4 engine: does an adaptive attacker who mutates identity,
timing, protocol, and telemetry — not just the prompt — still get caught **as
one incident**? Three layers, per the forward-roadmap:

| Layer | What it is | Blocks the gate? |
|---|---|---|
| **A** (`mutate.py` + `layer_a.py`) | Deterministic mutation engine (8 axes, 36 catalogue entries) replayed through the REAL WS-2→WS-4→WS-8 path. | **YES** — determinism is the license to block. |
| **B** (`corpus_b.py`) | Curated attack corpus (prompt-injection / tool-poisoning / destructive / credential / egress / OT-write cases) replayed through the real path. | **YES** — curated = deterministic = blockable. |
| **C** (`adversary_c.py` + `.github/workflows/nightly-adversary.yml`) | Nightly adaptive local-LLM adversary composing cross-axis mutations; stochastic by design. | **NEVER.** Stochastic output stays out of `run_all_tests.sh` — the single most important constraint of this phase. |

## Why Layer A can block (the honesty contract)

- A mutation that **keeps the alert but breaks the causal join is a FAILURE,
  not a pass** — the distinguishing insight of Phase 4 (only askable after
  Phase 3's causal graph exists). `layer_a.py` grades each variant on the
  three criteria: detection retained **and** chain fidelity retained **and**
  false-correlation rate unchanged; a row with `causal_join_broken=True` is
  `pass=False` by construction.
- Every measurement is labeled `harness-measured`; metrics the twin cannot
  measure stay `null` with a documented reason, never a fabricated number
  (the same discipline the Phase-0..3.5 eval stacks use).
- Determinism is proven by execution (`test_layer_a.py` runs the full matrix
  twice and asserts byte-identical output) — a green run is reproducible,
  which is what makes blocking safe.

## Measured results (seed 7, harness-measured, 2026-09-03)

- `mutation_robustness = 0.6111` (22/36 catalogue variants pass all three
  criteria). Per axis: identity/timing **1.0**, network 0.75, protocol/tool
  0.667, credential/telemetry 0.5, composition 0.333, **prompt 0.4**.
- The prompt axis is the honest headline: six of ten content mutations
  (whitespace, Cyrillic homoglyphs, equivalent phrasing, language switch,
  URL-encoding, base64 wrapping) defeat the bounded ASCII injection regex.
  Reported raw with per-row detail — a real coverage gap, never hidden.
- `causal_join_broken` is a live, demonstrated verdict: the `segment_ips`
  mutation (and comp-3 `actor_split+segment_ips`) keeps every alert firing
  while chain_fidelity drops 0.6 → 0.2 and FCR 1.0 → 0.5. Recorded as
  FAILURE, exactly as the roadmap mandates.
- `eval/twin/report.py`'s `mutation_robustness` metric reads the
  deterministic, gitignored `out/matrix.latest.json` (same convention as
  `eval/twin/report.latest.json`).

## Multi-storyline harness (2026-10-01)

Everything above was measured on **one** attack storyline (AI-to-OT). A seed
varied identifiers only, never the attack's structure, so "robust across seeds"
was one data point measured four times. The harness now runs over a registry of
storylines (`eval/twin/scenario_registry.py`), each with its own raw-format
builder on the REAL parsers and its own oracle:

| Storyline | Shape | What it can show that the others cannot |
|---|---|---|
| `ai_to_ot` | prompt-injected agent -> credential read -> unauthorized Modbus write | cross-domain (AI -> OT); almost entirely single-shot rules |
| `it_intrusion` | scan -> SSH brute force -> login -> lateral movement -> priv grant -> DNS exfil | stateful **volume/window** rules; an attack that **pivots** across three entities |
| `infra_takeover` | cloud root login (no MFA) -> privileged container -> mass VM delete | three control planes, a different actor at every step, one shared source IP |

`it_intrusion` / `infra_takeover` seeds vary **structure** (attacker address,
burst sizes, account and host names).

New instruments, each tested with a positive **and** a negative control
(`test_scenario_harness.py`):

- **`scenario_matrix.py`** -- scenario-agnostic operators (`mutate_generic.py`:
  thin a burst, slow it down, spread it over addresses/accounts, drop a log
  source, scramble *arrival* order, inject benign decoys). A variant that
  changes nothing is `N/A` and excluded -- never a free pass. Losing a source is
  graded as *graceful degradation* (no collateral), not as a failure.
- **`evasion_search.py`** -- instead of sampling fixed points, *searches* each
  burst step for the smallest thinning / slowdown / address-spread /
  account-split that evades it, and cross-checks the boundary against what the
  rule's own YAML declares (`threshold`, `window_seconds`, `group_by`). Agreement
  means the end-to-end pipeline honours the rule as written; a mismatch is a
  hidden blind spot or hidden slack.
- **`oracle_consistency.py`** -- reconciles every oracle against what its own
  pipeline run does (stale gaps, decorative expectations, unexpected firings).

What the metrics can and cannot say (measured, not assumed):

- `directional_discrimination` is **0.0 on all three storylines**. The legacy
  `chain_fidelity` join predicate returns "joined" for a step pair *and* for the
  same pair in reverse. The WS-8 v2 graph only has edges between entities that
  co-occur in a single alert, so it cannot encode "A caused B"; fidelity and
  false-correlation rate therefore measure "do the steps share an entity", not
  "was the causal chain reconstructed". They are kept (frozen baseline) and
  flagged in every `baseline_quality`.
- Order is graded separately (`alert_order_ok`, the oracle's own `strict_order`
  constraint, previously never enforced) and false correlation is graded by
  `decoy_contamination` -- benign look-alike activity on disjoint entities must
  not land inside the attack incident (control: a decoy on the attacker's own
  address *is* absorbed, so the metric can go non-zero).
- MTTD for a burst step is measured to the event the rule fired on, not the
  step's first event.

## Running

```bash
make adversarial                       # the whole deterministic lane
python eval/adversarial/mutate.py --selfcheck      # engine self-check
python eval/adversarial/layer_a.py --seed 7        # Layer A matrix (blocking)
python eval/adversarial/corpus_b.py                # Layer B corpus (blocking)
python eval/adversarial/test_layer_a.py            # acceptance + determinism + probes
python eval/adversarial/scenario_matrix.py --seed 7   # mutation lane over EVERY storyline (blocking)
python eval/adversarial/evasion_search.py --seed 7    # measured evasion boundary vs declared rule params (blocking)
python eval/adversarial/test_scenario_harness.py      # positive+negative controls for the new instruments
python eval/twin/oracle_consistency.py                # every oracle vs its own pipeline run
python eval/adversarial/adversary_c.py --dry-run   # Layer C dry-run (deterministic stub)
```

Layer C's adaptive mode is invoked only by the nightly workflow — never by
`make test` / `run_all_tests.sh` / CI.

## Out of scope / honest scope

- No parser, rule, engine, or service code is touched by this phase's
  mutation work (it replays through the shipped pipeline); the one exception
  is the `scenario.run_chain` `payload_source` seam + the
  `report._incident_membership_grade` early-return key fix, both additive.
- Layer C is advisory: a stochastic finding is a review item, not a CI
  failure.

### Causal-order grading and the reversed-order control (2026-10-02)

chain_fidelity, false_correlation_rate and directional_discrimination never read a clock. They are provably order-blind: a time-mirrored copy of each storyline scores the same on them. Only the boolean alert_order_ok flips.

eval/twin/causal_order.py grades the oracle's allowed_relationships DAG on event time and on the ts_ms carried by the WS-8 edges. It uses per-incident graphs with the minimum ts_ms per pair, and a typed-kind winner can displace an earlier field-pair edge.

report.py co-reports `causal_order_fidelity` and `order_concordance`. order_concordance is a timestamp invariant: 1.0 by construction on the harness's own chain. Do not read it as product capability. `alert_order_ok` is now emitted too.

layer_a rows RECORD `causal_order_fidelity` and `causal_order_retained`, but `pass` is computed as before. Promoting the flag is an owner decision. The Stage 1 comparison (84 rows, 0 pass flips) is in eval/adversarial/stage1_row_diff.md.

eval/adversarial/order_controls.py is a metric control (mirror, swap, shift). It checks that the order metrics say no on a reversed chain while the legacy join metrics do not move. scenario_matrix prints it under `metric_controls`, never pooled into a pass rate or mutation_robustness, and fails the lane if the control cannot say yes or no.

### Oracle cross-check (eval/twin)

The three hand-written oracles are checked two ways. `python eval/twin/oracle_mutate.py [--seed 7|11]` applies about 223 small edits to in-memory copies of each oracle and grades them against one observed run. A sound grader must score a WRONG oracle worse, and notice a WEAKER one. Kills are split into HEADLINE (graded metrics) and COUPLED (severity and reconcile, which only measure coupling to the current output). Survivors need a dated, capped waiver, and `eval/twin/oracle_strength.json` is the ratchet. Only `--update-baseline` writes it. `python eval/twin/oracle_derive.py` derives an oracle from the rule files alone and diffs it against the hand oracles. `python eval/twin/oracle_consistency.py --triangulate` adds the observed column. LIMIT: the derived oracle shares the rule YAML, parsers and scenario builders with the system, so it detects skew and drift, not original error. A third-party labelled corpus is the remedy.

### Adaptive evasion: the cost vector, the floor and the findings register (2026-10-02)

`evasion_search.py` measures four axes; this lane measures what it COSTS to get past each stateful rule-set and refuses to let that cost silently shrink.

- `probe_session.FastProbe` replays a stream through ONE Detector with a fresh window counter per probe (~0.01-0.1 s instead of 1.5-4.7 s). Speed is only allowed because it is proven not to change the answer: `verify_parity` (baseline + thin / ip_rotate_2 / stretch_6x) against `report._real_detection`, a leaky-counter negative control that MUST fail parity, an A,B,A state-leak check, and a refusal of any event whose time comes from the wall clock. `FENGARDE_SLOW_PROBE=1` restores the slow path in `evasion_search`; the JSON is byte-identical either way.
- `evasion_cost.py --seed 7` writes `out/evasion_cost.latest.json`: per rule-set (a rule plus its `companion_of` siblings) a VECTOR, never a weighted scalar: forgone events, extra seconds of the optimal slow schedule, sustainable stealth rate, fewest keys per kind (`immune` when a companion on another kind still detects), the joint Pareto frontier over a key grid, and the respelling / forgery / clock-forgeable flags. Every number carries an independent prediction (`evasion_axes.predict_*`); a disagreement fails.
- `evasion_floor.yaml` is the ratchet: each field has `better: min|max`; a worse value, a changed rule parameter / selection clause / allowlist hash (fingerprint), a lost axis, a vanished companion or an uncovered stateful rule FAILS and names rule, axis, measured value and floor. `--update-floor` only moves toward the defender; lowering needs `--update-floor --allow-lower --reason '...'` and appends a dated `lowered:` entry. Lowering by hand editing the file is not detected by the tool: review the diff.
- `evasion_findings.yaml` is the closed register (F1 cross-window sweep, F2 identity canonicalisation, F3 attribution forgery = open BUGs; F4 record-clock trust = TRUST_MODEL). An unlisted evasion fails (once the tables are ratified), a listed one that no longer reproduces is STALE and fails until deleted. Thinning, slowing and spreading across truly distinct entities are INHERENT to threshold rules: reported as cost, never as fix items.
- `evasion_tables.yaml` holds the security-judgement inputs (which fields an attacker controls, which respellings a source treats as one identity). Every row is `ratified: false`; findings resting on unratified rows are WARN/INFO and do not gate. Ratifying a row is the deliberate act that turns it into a gate.
- `noise_dilution.py --blocking-subset` turns F1 into an end-to-end instrument: benign noise on a 60 s rule sweeps the live state of every longer-window rule; the noise count is in counter hits (a companion makes one event two hits), found by bisection on full-stream replays, predicted independently from `_SWEEP_EVERY`, and the mandatory >60 s pause is part of the cost. Controls: no noise, key-not-idle, N*-1, per-key-sweep fix turns it green, phase shift, parity on the noise stream. Deque backend only (Redis expires per key).
- The generated table in `contracts/detection-coverage.md` is bracketed by `evasion-cost` markers and its header is `| Rule-set (key) |`, deliberately not `| Rule |` (check_lane_coverage would read it as the rule scorecard). `evasion_cost.py --write-doc` regenerates it; the default run fails if it is stale.
- Not covered: the WS-8 member-cap flood and the incident/triage metrics (need `reg.grade` and metrics that do not exist yet).
