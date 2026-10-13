# FENGARDE detection benchmark

An externally-presentable snapshot of what FENGARDE's detection layer
measures on replayable inputs — real attack corpora, an independent oracle,
and a deterministic AI-to-OT twin. Every number here is a measured run, with
units documented in [`results.json`](results.json) and honest scope
limitations in [`methodology.md`](methodology.md).

> **Read the method first.** Macro-F1 here is *engine-vs-oracle agreement on
> hand-labeled corpora*, not a field-trial detection rate. The benchmark's
> credibility is exactly this boundary being stated, not blurred.

## Current snapshot (corpus run **2026-10-13**, twin run **2026-09-04T07:51Z**)

| Metric | Value | Meaning (see methodology.md) |
|---|---|---|
| Detection macro-F1 | **0.875** | unweighted mean per-rule F1, engine-vs-labels, 10-event canary (4 scored rules) |
| Corpus records replayed | **14,663** | evtx (2,082) + splunk (12,561) supported records, 0 parser dead-letters, 0 oracle mismatches |
| Per-rule confusion | `password_spray` TP=2, `priv_grant` TP=1, `after_hours_admin` TP=4; **FP=0, FN=0 everywhere** | TP/FP/FN/TN per rule over EVTX + splunk corpora, per-file graded |
| Parser coverage | **43.2%** | % of Security+Sysmon records in the EVTX corpus a parser can normalize (corpus-shape-limited — stated plainly) |
| Untested rules (this run) | `bruteforce`, `lateral_movement`, `bruteforce_sourceless` | zero attack-shaped expected-positives in the corpora this snapshot fetched; all 28 rules still fire on real producer fixtures (`eval/attack/fire_check.py`) |
| Twin TPR / FPR | **1.0 / 0.0** | deterministic PLC-sim replay, seed 7 |
| Twin MTD | **60 s** | mean time to detect |
| Twin MTI | 360 s | mean time to investigate |
| Chain fidelity | **0.6** | causal-chain reproduction fraction in the incident graph |
| Evidence completeness | 0.9375 | fraction of expected evidence items present |
| False-correlation rate | 1.0 | false correlations per true incident (every positive had one genuine link) |
| Alert-reduction ratio | 0.7143 | (raw − correlated)/raw alert volume |

Full machine-readable detail with per-metric units:
[`results.json`](results.json)

## The honest boundaries (full text in methodology.md)

- **Parser coverage (43.2% in this snapshot) is real and disclosed.** It
  measures this corpus — Security/Sysmon-centric — not FENGARDE's reach;
  17 parsers ship for IT/OT sources these corpora never contain. The
  statement, not the hiding, is the point.
- **`password_spray` is tested by a committed synthetic fixture**, not by
  luck of the corpora: neither public corpus contains the one-account-many-IPs
  shape, so `attack_fixtures.py` supplies exactly that shape through the same
  oracle + real pipeline. It is labeled `fixture:` in every output and never
  inflates coverage or corpus counts.
- **Twin metrics are harness-measured** on a deterministic simulation —
  repeatable and honest, not a field deployment result.

## Regeneration

`benchmark/results.json` is regenerated nightly
(`.github/workflows/nightly-eval.yml`, 03:00 UTC) from the latest rows in
`eval/trend.jsonl`, and by hand via `make benchmark`. It is a committed
snapshot: the nightly run also publishes the fresh file as an artifact, and
whoever runs the lane locally commits it — exactly the convention
`eval/trend.jsonl` itself follows. Recipe: [`reproduction.md`](reproduction.md).

## Files

- `results.json` — the machine-readable snapshot (schema v1.0, units in-file)
- `methodology.md` — definitions, the parser-coverage number stated plainly, limits
- `reproduction.md` — exact commands to regenerate every number
- `README.md` — this summary