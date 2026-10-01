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