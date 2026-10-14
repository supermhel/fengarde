# FENGARDE detection benchmark

An externally-presentable snapshot of what FENGARDE's detection layer
measures on replayable inputs — real attack corpora, an independent oracle,
and a deterministic AI-to-OT twin. Every number here is a measured run, with
units documented in [`results.json`](results.json) and honest scope
limitations in [`methodology.md`](methodology.md).

> **Read the method first.** Macro-F1 here is *engine-vs-oracle agreement on
> hand-labeled corpora*, not a field-trial detection rate. The benchmark's
> credibility is exactly this boundary being stated, not blurred.

## Current snapshot (corpus run **2026-10-14**, nightly CI on the PR branch, run 38541350947; twin run **2026-10-14T09:29Z**, same run)

| Metric | Value | Meaning (see methodology.md) |
|---|---|---|
| Detection macro-F1 | **0.875** | unweighted mean per-rule F1, engine-vs-labels, 10-event canary (4 scored rules) |
| Corpus records replayed | **265,404** | EVTX-ATTACK-SAMPLES 2,082 (278 files) + splunk/attack_data 263,322 (1,055 raw-XML files) supported records; 0 parser dead-letters, 0 oracle mismatches |
| Per-rule confusion (corpus files) | `bruteforce` TP=3, `lateral_movement` TP=3, `priv_grant` TP=5, `after_hours_admin` TP=12, `bruteforce_sourceless` TP=8; **FP=0, FN=0 everywhere** | TP/FP/FN/TN per rule, counted in corpus FILES (not events); synthetic fixtures excluded |
| Untested in the corpora | `password_spray` | zero expected-positive files in either corpus — graded only by a committed synthetic fixture (below) |
| Parser coverage | **43.2%** | % of Security+Sysmon records in the EVTX corpus a parser can normalize (corpus-shape-limited — stated plainly) |
| Twin TPR / FPR | **1.0 / 0.0** | deterministic PLC-sim replay, seed 7 |
| Twin time to detect | **60 s** | chain start → first expected detection, seed-derived timestamps of one scenario |
| Twin MTTI | 360 s | **modeled**: 12 measured investigation steps × a documented 30 s/step constant |
| Chain fidelity | **0.6** | share of the oracle's allowed causal pairs joined in the incident graph |
| Evidence completeness | 0.9375 | share of expected evidence fields present |
| False-correlation rate | **1.0 (worst possible)** | share of oracle-*forbidden* causal pairs the graph joined anyway — 2 of 2; lower is better |
| Alert-reduction ratio | 0.7143 | 1 − incidents/raw alerts (7 alerts → 2 incidents) |

Full machine-readable detail with per-metric units:
[`results.json`](results.json). Sources for numbers not in it: per-lane record
counts, dead-letters and mismatches come from that run's CI log; the twin's 2/2 forbidden
pairs, 12 investigation steps and 7 alerts → 2 incidents from the committed
[`eval/twin/report.json`](../eval/twin/report.json) `context`.

## The honest boundaries (full text in methodology.md)

- **Parser coverage (43.2% in this snapshot) is real and disclosed.** It
  measures this corpus — Security/Sysmon-centric — not FENGARDE's reach; most
  of the 17 shipped parsers cover IT/OT sources these corpora never contain.
- **`password_spray` is untested by the corpora** — neither public corpus
  contains the one-account-many-IPs shape. A committed synthetic fixture
  (`eval/detection_accuracy/attack_fixtures.py`) exercises that shape through
  the same oracle + real pipeline (TP, 0 mismatches — pinned by
  `test_evtx_eval.py`); published separately as `fixture_per_rule_confusion`
  (`password_spray` TP=1) / `fixture_tested_rules`, never in the corpus
  confusion, record counts or coverage.
- **False-correlation rate 1.0 is a real weakness, not a typo.** The WS-8
  entity-presence join cannot yet tell causal direction, so both forbidden
  relationships in the twin scenario get joined.
- **Twin metrics are harness-measured** on a deterministic simulation —
  repeatable and honest, not a field deployment result. MTTI is a model
  (measured step count × a stated constant), not a wall-clock measurement.

## Regeneration

`benchmark/results.json` is regenerated nightly
(`.github/workflows/nightly-eval.yml`, 03:00 UTC) from the latest rows in
`eval/trend.jsonl`, and by hand via `make benchmark`. It is a committed
snapshot: the nightly run publishes the fresh file as an artifact, and the
row lands in git when someone syncs it — exactly the convention
`eval/trend.jsonl` itself follows. The zero-infra gate fails if the committed
`results.json` drifts from a fresh render (`generate_benchmark.py --check`).
Recipe: [`reproduction.md`](reproduction.md).

## Files

- `results.json` — the machine-readable snapshot (schema v1.0, units in-file)
- `methodology.md` — definitions, the parser-coverage number stated plainly, limits
- `reproduction.md` — exact commands to regenerate every number
- `README.md` — this summary
