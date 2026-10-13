# Reproducing the FENGARDE detection benchmark

This benchmark is a **packaging of measured rows** — every number in
`results.json` traces to a run of the repo's own eval lanes against real
inputs. This file is the exact recipe; `methodology.md` is the meaning and
the caveats; `README.md` is the summary.

## What the numbers are, and which run produces which

| `results.json` section | Produced by | Records to run |
|---|---|---|
| `detection_quality.macro_f1`, `quality_corpus_events` | Detection-quality canary (`tools/detection_quality_eval.py`) | hand-labeled OCSF corpus (10 events, 4 scored rules) |
| `detection_quality.per_rule_confusion`, `corpus_records`, `parser_coverage_pct`, `untested_rules` | Corpus replay lanes `eval/detection_accuracy/evtx_eval.py` + `splunk_eval.py`, merged per the trend file's row schema | EVTX-ATTACK-SAMPLES + splunk/attack_data (gitignored, fetched per below) |
| `twin.*` | Twin scorecard `eval/twin/report.py` (`make twin`) | deterministic in-process PLC-sim attack chain (seed 7) |

`eval/trend.jsonl` is the append-only ledger: the nightly workflow (03:00 UTC,
`.github/workflows/nightly-eval.yml`) appends **one row per run**, and
`tools/generate_benchmark.py` packages the **latest** corpus row plus the
**latest** twin row into `benchmark/results.json`. The committed
`results.json` is the latest stored snapshot; the per-run artifact
(`detection-accuracy-trend`) carries the fresh one each night.

## Prerequisites

Both third-party corpora are **not vendored** (their licenses do not permit
redistribution — the EVTX corpus is GPL-3.0):

```sh
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES \
  eval/detection_accuracy/evtx-samples
git clone --depth 1 https://github.com/splunk/attack_data \
  eval/detection_accuracy/splunk-attack-data
pip install python-evtx        # EVTX lane only
```

A lane whose dataset is missing prints `[SKIP]` and exits 0 — it proves
nothing that run, and `parser_coverage_pct` / `per_rule_confusion` will be
`null`/empty for it. Both corpora are present and verified for the numbers
in this snapshot.

## Full reproduction (one command each block)

```sh
# 1. Detection-quality canary (zero-infra, needs nothing) + its self-test
python tools/detection_quality_eval.py
python tools/test_detection_quality.py

# 2. Corpus replay lanes (need the two corpora above)
python eval/detection_accuracy/evtx_eval.py
python eval/detection_accuracy/splunk_eval.py
python eval/detection_accuracy/test_evtx_eval.py

# 3. Twin scorecard (zero-infra, deterministic seed 7)
python eval/twin/report.py

# 4. Append ONE corpus+canary row to eval/trend.jsonl — the exact same
#    append logic the nightly workflow runs (see .github/workflows/
#    nightly-eval.yml, step "Append ONE trend row to eval/trend.jsonl").
#    The twin row is appended by report.py itself (step 3).
#    Local convention: append, then commit the grown file.

# 5. Repackage the public benchmark + self-test
python tools/generate_benchmark.py
python tools/test_generate_benchmark.py
# or, in one shot:
make eval-detection && python eval/twin/report.py && make benchmark
```

Step 4's append code is deliberately not forked into a separate script: the
workflow's inline Python is the canonical implementation, and the packed
boolean appended there is exactly what `generate_benchmark.py` reads. A local
re-run that skips step 4 produces a `results.json` from the previous stored
rows — the committed snapshot, still honest, just not fresh.

## Determinism and honesty guarantees

- **Fixed seeds/timestamps**: the canary corpus, the twin (seed 7), and the
  committed fixtures in `eval/detection_accuracy/attack_fixtures.py` all use
  fixed UTC epoch-ms timestamps and deterministic ordering — reruns produce
  identical confusion/scorecard entries, which is what makes the append-only
  trend file comparable across days.
- **No retroactive edits**: trend history is append-only, including the one
  historically *fabricated* pilot row (kept in place with a comment block
  labeling it, per `SSOT.md` §2's proven-vs-claim discipline).
  `generate_benchmark.py` selects the latest rows by date and **refuses
  loudly** if a fabricated-shaped row (fpr=0.25) ever wins the selection.
- **Synthetic fixtures don't inflate corpus metrics**: `attack_fixtures.py`
  gives attack-shaped positives to rules the third-party corpora never
  exercise (see methodology.md); fixture records are graded like corpus
  files but are never counted in `records_supported` or the parser-coverage
  denominator.
- **Nothing zero-fills an unmeasured metric**: `null` in `results.json`
  means "not measured in that run", not zero.