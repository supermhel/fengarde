# FENGARDE detection benchmark

An externally-presentable snapshot of what FENGARDE's detection layer
measures on replayable inputs — real attack corpora, an independent oracle,
and a deterministic AI-to-OT twin. Every number here is a measured run, with
units documented in [`results.json`](results.json) and honest scope
limitations in [`methodology.md`](methodology.md).

> **Read the method first.** Macro-F1 here is *engine-vs-oracle agreement on
> hand-labeled corpora*, not a field-trial detection rate. The benchmark's
> credibility is exactly this boundary being stated, not blurred.
>
> **Scope:** the real-corpus numbers below grade **6 of the 46 rules**. What evidence exists for each rule, what is not
> measured anywhere, and the plan to close the gap: [`rule-evidence.md`](rule-evidence.md).

> **Throughput and saturation** (zero-infra per-stage rates, live-stack ramp/soak, bottleneck): see [`loadtest.md`](loadtest.md). The detection numbers below are a separate lane.

## Current snapshot (corpus run **2026-10-22**, nightly CI run 39747085824 on `25f22ba` — the first nightly after the 46-rule build of PR #112 (the CI log reports `rules loaded : 46`); pinned corpora EVTX `4ceed2f` / splunk `800ef65`, the pre-registered Q13 LFS subset; twin run **2026-10-22T08:24Z**, same run)

| Metric | Value | Meaning (see methodology.md) |
|---|---|---|
| Detection macro-F1 | **0.875** | unweighted mean per-rule F1, engine-vs-labels, 10-event canary (4 scored rules) |
| Corpus records replayed | **3,317** | EVTX-ATTACK-SAMPLES 2,082 (278 files) + splunk/attack_data 1,235 (57 raw-XML files, the pre-registered Q13 subset) supported records; 0 parser dead-letters, 0 oracle mismatches. **Not comparable to the earlier 265,404-record snapshot (2026-10-14, 36 rules, full 1,055-file splunk corpus)**: the nightly no longer reads that corpus, and no full-corpus run on the 46-rule build exists |
| Per-rule confusion (corpus files) | `priv_grant` TP=3, `after_hours_admin` TP=4, `bruteforce_sourceless` TP=2; **FP=0, FN=0 everywhere** | TP/FP/FN/TN per rule, counted in corpus FILES (not events); synthetic fixtures excluded |
| Untested in the corpora | `bruteforce`, `password_spray`, `lateral_movement` | zero expected-positive files in the 57-file splunk subset or the EVTX corpus. `password_spray` is graded only by a committed synthetic fixture (below); `bruteforce` and `lateral_movement` were TP=3 each on the full 1,055-file corpus (2026-10-14, 36 rules) and have **not** been re-measured at that scale on the 46-rule build |
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

## Earlier snapshot: full corpus, 36 rules (2026-10-14)

The table above is the latest nightly (46 rules, 57-file splunk subset, because the nightly pulls only the pre-registered Q13
LFS subset; a full clone is over 9 GB), so it is **not comparable** with the table below, the last CI run on the **full**
splunk corpus before the ten recall rules of PR #112. The full corpus has since been re-measured on 46 rules (next section).

Run **2026-10-14**, nightly CI run 38619447630, pinned corpora EVTX `4ceed2f` / splunk `eac2f8f`, 36 rules.

| Metric | Value |
|---|---|
| Corpus records replayed | **265,404** (EVTX 2,082 in 278 files + splunk 263,322 in 1,055 raw-XML files); 0 parser dead-letters, 0 oracle mismatches |
| Per-rule confusion (corpus files) | `bruteforce` TP=3, `lateral_movement` TP=3, `priv_grant` TP=5, `after_hours_admin` TP=12, `bruteforce_sourceless` TP=8; **FP=0, FN=0 everywhere** |
| Untested in the corpora | `password_spray` (graded only by the committed synthetic fixture) |
| Detection macro-F1 / parser coverage | 0.875 (10-event canary, 4 scored rules) / 43.2% |

### Full corpus on the 46-rule build (measured 2026-10-23, Linux container)

The same lanes (`evtx_eval.py`, `splunk_eval.py`) on the 46-rule build of `main` plus PR #126, run inside a `python:3.12` Linux
container (so no antivirus host can quarantine corpus files), with **every** `datasets/attack_techniques/**/*.log` Git LFS file pulled.
Two Splunk pins were run, so the comparison with the 36-rule snapshot is on the **identical** corpus:

| Metric | 36 rules, 2026-10-14 (pin `eac2f8f`) | 46 rules, same pin `eac2f8f` | 46 rules, current manifest pin `800ef65` |
|---|---|---|---|
| EVTX files / supported records | 278 / 2,082 | 278 / 2,082 | 278 / 2,082 |
| Splunk raw-XML files / supported records | 1,055 / 263,322 | **1,055 / 263,322** | 1,034 / 263,261 |
| Dead-letters / oracle mismatches | 0 / 0 | 0 / 0 | 0 / 0 |
| `bruteforce` / `lateral_movement` TP (splunk) | 3 / 3 | 3 / 3 | 3 / 3 |
| `priv_grant` TP (EVTX + splunk) | 5 | 1 + 4 = 5 | 1 + 4 = 5 |
| `after_hours_admin` TP (EVTX + splunk) | 12 | 4 + 8 = 12 | 4 + 8 = 12 |
| `bruteforce_sourceless` TP (splunk) | 8 | 8 | 8 |
| FP / FN | 0 / 0 | 0 / 0 | 0 / 0 |
| `password_spray` | untested in the corpora | untested (TP=FP=FN=0) | untested (TP=FP=FN=0) |

Reading it:

- On the identical corpus (middle column) the ten rules added since 2026-10-14 change **none** of the six graded results.
- The 21-file difference between the middle and right columns is the splunk pin (`800ef65` vs `eac2f8f`): checking the same
  container out at `eac2f8f` reproduces the snapshot's 1,055 files and 263,322 records exactly.
- Both lanes grade only the six oracle-backed rules. The other 40 rules fire on Sysmon files with no oracle label (neither TP
  nor FP), so "FP = 0" holds for the six graded rules only, never for all 46.
- Commands: `fetch_corpora.py --corpus evtx-attack-samples --corpus splunk-attack-data --no-lfs`, then
  `git lfs pull --include="datasets/attack_techniques/**/*.log"` in the splunk checkout, then `evtx_eval.py` and `splunk_eval.py`
  (EVTX pin `4ceed2f`; about 17 min LFS pull, 7 min EVTX lane, 10 to 16 min splunk lane in the container).
- Local runs on a Windows host with antivirus are not supported: Defender quarantined 13 of these `.log` files in an earlier attempt.

## The honest boundaries (full text in methodology.md)

- **Parser coverage (43.2% in this snapshot) is real and disclosed.** It
  measures this corpus — Security/Sysmon-centric — not FENGARDE's reach; most
  of the 19 shipped parsers cover IT/OT sources these corpora never contain.
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
