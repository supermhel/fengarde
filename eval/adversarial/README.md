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

## Running

```bash
make adversarial                       # the whole deterministic lane
python eval/adversarial/mutate.py --selfcheck      # engine self-check
python eval/adversarial/layer_a.py --seed 7        # Layer A matrix (blocking)
python eval/adversarial/corpus_b.py                # Layer B corpus (blocking)
python eval/adversarial/test_layer_a.py            # acceptance + determinism + probes
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