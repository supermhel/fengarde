# Reproducing the FENGARDE detection benchmark

This benchmark is a **packaging of measured rows** — every number in
`results.json` traces to a run of the repo's own eval lanes against real
inputs. This file is the exact recipe; `methodology.md` is the meaning and
the caveats; `README.md` is the summary.

## What the numbers are, and which run produces which

| `results.json` section | Produced by | Records to run |
|---|---|---|
| `detection_quality.macro_f1`, `quality_corpus_events` | Detection-quality canary (`tools/detection_quality_eval.py`) | hand-labeled OCSF corpus (10 events, 4 scored rules) |
| `detection_quality.per_rule_confusion`, `corpus_records`, `corpus_files`, `parser_coverage_pct`, `untested_rules` | Corpus replay lanes `eval/detection_accuracy/evtx_eval.py` + `splunk_eval.py`, merged into one trend row by `tools/append_trend_row.py` | EVTX-ATTACK-SAMPLES + splunk/attack_data (gitignored, fetched per below) |
| `detection_quality.fixture_per_rule_confusion`, `fixture_tested_rules` | The same lanes' separately graded synthetic fixtures (`attack_fixtures.py`), taken once by `append_trend_row.py` | committed fixtures, no download |
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
bash eval/detection_accuracy/fetch_corpora.sh     # both corpora at the PINNED commits; needs git-lfs (multi-GB)
pip install --require-hashes -r eval/requirements.txt   # pyyaml + python-evtx, hash-pinned
```

The nightly fetches both corpora at the commits in `eval/detection_accuracy/corpus_manifest.json` via `fetch_corpora.py`
(EVTX-ATTACK-SAMPLES `4ceed2f`, splunk/attack_data `800ef65`, only the pre-registered LFS subset: 57 raw-XML files).
`fetch_corpora.sh` (full splunk corpus at `eac2f8f`, multi-GB) is the route to the older 2026-10-14 full-corpus snapshot.
Both corpora are pinned to commits,
and every trend row records the commits its lanes actually read
(`corpus_commits`). New upstream splunk data arrives only through a PR that
bumps the pin in `fetch_corpora.sh`; that PR's nightly run shows the change.

splunk/attack_data stores its datasets in **Git LFS**. Without `git-lfs`
the `.log` files are pointer stubs, and `splunk_eval.py` fails loudly on
them. It also fails loudly when tracked `.log` files are missing from the
checkout (sparse/partial clone, or **antivirus quarantine**: Windows Defender
removed 23 attack-sample `.log` files from a local clone on 2026-10-14). The
row's `lane_files` should match the published snapshot (278 evtx / 57
splunk files). **The corpus lanes are run in CI only** (the nightly
workflow on `ubuntu-latest`, or `workflow_dispatch` on a branch); that row is
the source of truth. Local runs are not supported on Windows hosts whose
antivirus quarantines attack samples, and antivirus settings are never
weakened to make them pass.

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

# 4. Append ONE corpus+canary row to eval/trend.jsonl -- the same script
#    the nightly workflow runs. The twin row is appended by report.py (step 3).
python tools/append_trend_row.py
python tools/test_append_trend_row.py

# 5. Repackage the public benchmark + self-test
python tools/generate_benchmark.py
python tools/test_generate_benchmark.py
# or, in one shot:
make eval-detection && python eval/twin/report.py && python tools/append_trend_row.py && make benchmark
```

A local re-run that skips step 4 produces a `results.json` from the previous
stored corpus row (and, after step 3, a fresher twin row) -- the committed
snapshot, still honest, just not fresh. Each lane deletes its own results
file when it SKIPs, so step 4 never re-publishes a stale lane result under
today's date.

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
  exercise (see methodology.md); fixtures are graded like corpus files but
  in a separate matrix, counted once, and never appear in
  `per_rule_confusion`, `untested_rules`, `records_supported` or the
  parser-coverage denominator.
- **Nothing zero-fills an unmeasured metric**: `null` in `results.json`
  means "not measured in that run", not zero.