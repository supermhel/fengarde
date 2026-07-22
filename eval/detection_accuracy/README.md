# Detection-accuracy eval lane (P3, 2026-07-21 audit fix plan)

Independent-oracle detection-accuracy replay: real Windows Security/Sysmon
event corpora are fed through the live WS-2 → WS-4 pipeline (memory bus, zero
infra), and the resulting alerts are compared against an oracle that
recomputes each rule's ground truth directly from the raw records — not
against the engine's own logic. This is what caught the six brute-force false
negatives P0-1/P0-2 fixed (2026-07-21): a unit test that mirrors the engine's
own code can't catch a bug in that code, but an independently-computed
ground truth can.

Two corpora, two scripts, same oracle (`evtx_eval.py`'s `oracle()` /
`replay_file()`, reused by `splunk_eval.py`):

| Script | Corpus | What it adds |
|---|---|---|
| `evtx_eval.py` | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | Broad per-technique coverage (Security + Sysmon channels), one incident per file |
| `splunk_eval.py` | [splunk/attack_data](https://github.com/splunk/attack_data) | Real brute-force/password-spray **volume** (purplesharp/T1110 runs) that a single-incident EVTX sample can't exercise |

## Datasets are NOT vendored

Both corpora are third-party, with their own licenses (EVTX-ATTACK-SAMPLES is
GPL-3.0; splunk/attack_data has its own terms) — neither is committed to this
repo. Fetch them yourself:

```sh
# EVTX-ATTACK-SAMPLES (GPL-3.0 — review the license before redistributing
# anything derived from it)
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES \
  eval/detection_accuracy/evtx-samples

# splunk/attack_data (review its own LICENSE)
git clone --depth 1 https://github.com/splunk/attack_data \
  eval/detection_accuracy/splunk-attack-data
```

Both target directories are gitignored. `evtx_eval.py` also needs the
`python-evtx` package to parse `.evtx` binary files:

```sh
pip install python-evtx
```

## Running

```sh
make eval-detection
# or individually:
python eval/detection_accuracy/evtx_eval.py
python eval/detection_accuracy/splunk_eval.py
```

**Both scripts skip cleanly (print a `[SKIP]` message, exit 0) if their
dataset directory or `python-evtx` isn't present** — same "safe to run with
no setup, just proves nothing that time" convention as `make test-live`'s
live-Redis/OpenSearch-gated tests. This target is intentionally NOT wired
into `make test`/`run_all_tests.sh` (the zero-infra CI gate) for that reason:
a green `make test` must mean something even on a machine with no datasets
fetched, and a report that always skips would be noise there.

Each run writes `evtx_eval_results.json` / `splunk_eval_results.json`
(gitignored) with the full per-file confusion breakdown, mismatches, and
parser dead-letters — not just the stdout summary.

## Relationship to `make attack-scorecard` (P3-2)

This eval lane produces the **empirical** half of the ATT&CK coverage
scorecard (a technique's mapped rule actually fired on real technique
telemetry). `make attack-scorecard` (`eval/attack/coverage_layer.py`)
produces the **declared** half (a rule's `mitre:` block claims the
technique). The two are deliberately kept separate — see that script's module
docstring for why conflating them would be dishonest.
