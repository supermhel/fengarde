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

## Real numbers observed (2026-08-19)

First actual run of both harnesses on record for this project — both were
wired since 2026-07-21 but, being dataset-gated, had never been executed
until this pass fetched both corpora. Read as a real, honestly-narrow
snapshot, not a comprehensive detection-accuracy claim:

- **EVTX-ATTACK-SAMPLES**: 278 files / 37,364 records replayed. `priv_grant`
  TP=1, `after_hours_admin` TP=4, all other tagged rules TN across the whole
  corpus (0 FP, 0 FN everywhere), 0 mismatches, 0 parser dead-letters. Sysmon
  parser coverage measured at 1864/3241 (57.5%) of the corpus's Sysmon
  records. Most of the shipped rules (bruteforce, password_spray,
  lateral_movement, bruteforce_sourceless) saw zero corpus events shaped to
  fire them — a real, disclosed coverage gap in what THIS corpus happens to
  contain (mostly single-incident technique samples, not sustained bursts),
  not a claim those rules are broken (see `eval/attack/fire_check.py` for
  the harness that DOES exercise them, via synthetic fixtures).
- **splunk/attack_data**: this eval lane's XML block extractor (shared with
  the EVTX harness) only consumes XML-shaped `windows-security.log` files;
  4 of the 22 such files in the cloned corpus are XML-shaped, yielding 20
  replayable records, 0 TP/FP/FN (none of those specific 4 files happened to
  carry brute-force/spray volume). The corpus's real value — brute-force/
  spray VOLUME the single-incident EVTX corpus lacks — mostly lives in the
  non-XML files this harness's current extractor doesn't parse; broadening
  it to also read Splunk's non-XML raw-text export format is a real,
  disclosed follow-up, not attempted this pass.

Both are reproducible: `git clone` the two corpora per this file's fetch
commands above, then `make eval-detection`.

## Relationship to `make attack-scorecard` (P3-2)

This eval lane produces the **empirical** half of the ATT&CK coverage
scorecard (a technique's mapped rule actually fired on real technique
telemetry). `make attack-scorecard` (`eval/attack/coverage_layer.py`)
produces the **declared** half (a rule's `mitre:` block claims the
technique). The two are deliberately kept separate — see that script's module
docstring for why conflating them would be dishonest.
