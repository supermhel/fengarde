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

## Nightly cadence and the committed trend file

**Cadence: nightly, 03:00 UTC.** `.github/workflows/nightly-eval.yml`
(`workflow_dispatch` also available) re-measures detection accuracy on a
schedule so a published macro-F1 number cannot silently decay into a claim
nobody regenerated. The lane is **opt-in and live** — it is deliberately NOT
part of the zero-infra PR gate, because it fetches the two gitignored corpora
above (it clones `EVTX-ATTACK-SAMPLES` and `splunk/attack_data` into
`evtx-samples/` / `splunk-attack-data/` on a fresh runner). A corpus download
that is attempted and errors **fails the job loudly**; only an explicitly-off
lane (repo variable `NIGHTLY_EVAL_MODE=quality-only`) skips cleanly with a
message. `eval/attack/fire_check.py` is intentionally **not** wired here — it
is already a blocking step of the zero-infra gate (M7 in `run_all_tests.sh`)
and needs no corpus.

The workflow runs `tools/detection_quality_eval.py` (the macro-F1 canary) plus
`evtx_eval.py` and `splunk_eval.py` against the fetched corpora, then appends
**one row per run** to `eval/trend.jsonl` (committed — the file's first line is
a `#` header comment; each object carries `"_schema": "1"`):

| Field | Meaning |
|---|---|
| `_schema` | `"1"` — stable, so trend rows stay comparable across runs |
| `date` | ISO date (`YYYY-MM-DD`, UTC) of the run |
| `corpora` | which lanes contributed (`evtx` / `splunk` / `quality`) |
| `corpus_size` | total supported records replayed by the corpus lanes (evtx `records_supported` + splunk `supported_records`) |
| `per_rule` | `rule_id -> {tp,fp,fn,tn}`, keyed by the stable ORACLE rule ids from `evtx_eval.py`, summed across the corpus lanes |
| `macro_f1` | the detection-quality canary's macro-F1 (≥ the documented 0.5 floor) |
| `quality_corpus_events` | size of the canary's hand-authored labeled corpus |
| `parser_coverage_pct` | combined Security+Sysmon parser coverage from the EVTX corpus (e.g. 42.3%) or `null` when no corpus lane ran |
| `untested_rules` | ORACLE rules with `tp+fn == 0` — they never met attack-shaped events in the corpus, surfaced so they are never implied-passing (the stateful burst rules reliably land here, matching the event-description gap noted below) |

The grown file is also published as a per-run `detection-accuracy-trend`
artifact; the job does not push back to `main` (least-privilege
`contents: read`, no-auto-commit convention), so local runs append in place.

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

## Coverage broadened (2026-09-10)

Both of the above were stuck, untouched, since 2026-08-19 — not a technical
blocker, just never re-picked-up (flagged as such in `fengarde-sec`'s backlog).
Fixed for real, re-run against the same two real corpora:

- **Sysmon parser coverage**: `sysmon.py` gained EventID 5 (ProcessTerminate,
  mapped to class 1002 activity 3 — a clean sibling of EventID 1's Launch
  under the same class Contract A leaves open 0-99). Coverage moved
  1864/3241 (57.5%) → **1910/3241 (58.9%)**; combined Security+Sysmon 42.3%
  → 43.2%. The module docstring now names every remaining excluded Sysmon
  ID (7 ImageLoad, 8 CreateRemoteThread, 10 ProcessAccess, 12/13/14
  Registry*, 18 PipeConnected) with the specific reason none of them has a
  clean class fit in the current restricted OCSF profile — closing the gap
  further needs a schema decision (a Module/Process-Access/Registry class),
  not another parser tweak. Still 0 mismatches against the independent
  oracle after the change.
- **splunk/attack_data lane**: the loader required the filename to contain
  "security" AND raw content to start `<Event` — the filename check was
  filtering on the wrong signal. `attack_techniques/` ships 57 genuinely
  raw-XML `.log` files corpus-wide (only 4 had "security" in the name), and
  the lane never read the Sysmon channel at all even inside the files it
  did load. Dropped the filename gate (content alone decides now) and added
  Sysmon-channel routing identical to the EVTX lane's. Files usable: 4 → 57;
  supported records: 20 → **12,561** (security=47, sysmon=12,514). Still 0
  mismatches. Every other format in the corpus (Splunk's plaintext export,
  CrowdStrike Falcon JSON, Zeek JSON, PowerShell transcripts, Linux auditd)
  is a genuinely different schema needing its own extractor — left as an
  honest, disclosed gap, not forced through this one.

## Blind-recall lane (third-party labels)

`evtx_eval.py` / `splunk_eval.py` compare the engine to an oracle **this repo
wrote** (`oracle()` recomputes six rules' logic from the raw records) and throw
the dataset's own ATT&CK label away. `blind_recall.py` is the other half: the
label comes from the **dataset author**, and the question is "did any rule in
that technique's family fire?". Nothing FENGARDE wrote (rule id, rule name,
oracle output, alert) is visible to an adapter; `test_blind_recall.py` pins that.

| File | Role |
|---|---|
| `corpus_manifest.json` | per corpus: pinned commit, licence SPDX id, label source, lanes, `vendored: false` for all |
| `fetch_corpora.py` | on-demand fetch at the pin (`git fetch --depth 1 origin <sha>` + detached checkout, HEAD verified); splunk data files are git-lfs, pulled **only** for the pre-registered selection (below). Never part of `run_all_tests.sh` |
| `corpus_adapters.py` | `SplunkAttackData` (Windows `XmlWinEventLog:*` only) and `EvtxToMitre` (`.evtx`, python-evtx imported lazily) |
| `technique_match.py` | label vs rule-technique matching, rule index, funnel bucket assignment |
| `blind_recall.py` | driver: replay each scenario on a fresh bus + `Detector(rules_dir=...)`, bucket, aggregate, write `blind_recall_results.json` |
| `test_blind_recall.py` | **blocking, zero-infra, synthetic CONTROLS only** (below) |

```sh
python eval/detection_accuracy/fetch_corpora.py            # splunk-attack-data + evtx-to-mitre
python eval/detection_accuracy/blind_recall.py [--require-corpus]
python eval/detection_accuracy/test_blind_recall.py        # the gate, no data needed
```

**Unit of scoring.** One *scenario* = one Splunk YAML with **all** of its
`datasets[]` files merged and replayed together (17% of labelled YAMLs declare
more than one file, and Security + Sysmon together changes which rules can
fire), or one `.evtx` file. A scenario with *k* labels is *k* units, each scored
independently against the same single replay (alert reuse across labels is
allowed and visible in `fired_in_family` / `off_label_rules`).

**Label provenance** (recorded in every result row as `label_source`):
Splunk = the YAML's `mitre_technique` list; the technique directory name is kept
as `dir_label` (disagreements flagged `label_dir_disagree`) and is the only
label for the old-style YAMLs that carry a `dataset:` URL list. EVTX-to-MITRE =
the folder `TAxxxx-<Tactic>/Txxxx[.yyy|.xxx]-<name>/`; the literal `.xxx` is a
family-level label (`sub_unspecified`), the sub-technique is never invented;
anything outside that layout (e.g. `Antivirus/`) is `UNLABELLED`.

**Funnel buckets** (every unit lands in exactly one; the bucket counts are
asserted to sum to the units, and the units to `sum(max(1, labels))` over the
scenarios):

| Bucket | Meaning |
|---|---|
| `NOT_FETCHED` | declared, but no readable file (absent, empty, or an un-pulled git-lfs pointer); outside the denominator, never a miss |
| `READER_UNAVAILABLE` | files present, python-evtx missing: a tooling gap, not a verdict |
| `UNLABELLED` | no usable technique label from the dataset's own metadata/path |
| `NO_PARSER` | no shipped WS-2 parser normalised any record (unsupported source, or 0 of N records) |
| `NO_RULE` | ingested, but no loaded enterprise-ATT&CK rule is in the label's technique family: the **gap list** |
| `HIT_EXACT` / `HIT_FAMILY` | an in-family alert fired; rule technique == label / same parent |
| `MISS` | parser **and** rule exist, nothing in the family fired |

`partial_parse` (+ `parsed_fraction`, `unparsed_event_ids`) flags a unit where
some records had no parser class (e.g. Sysmon 10/13, PowerShell 4104), so a
`MISS`/`NO_RULE` there may be missing telemetry rather than missing detection.
Match rule: exact, or same parent with at least one side being the parent;
**sibling sub-techniques never match**. `common_password_spray.yml` is T1110.004
(credential stuffing) by documented design, and true one-source-many-accounts
spraying (T1110.003) is a disclosed gap, so a T1110.003 dataset is at best
`HIT_FAMILY` via the T1110 brute-force rules and is listed under
"no exact rule". The rule index keeps rules with no `framework` key (default
`attack`) and skips `atlas` / `attack-ics` / no-`mitre` rules.
`oracle` is `agrees_no_fire` / `disagrees_oracle_expects_fire` **only** for a
`MISS` whose family contains one of the six `ORACLE_RULES` ids; every other
`MISS` is `not_applicable` (the oracle has no answer there). `HIT_TACTIC` is not
implemented.

**Selection is pre-registered.** `fetch_corpora.py` pulls LFS data only for
scenarios chosen from dataset metadata and the rule families, never outcomes:
Windows-XML scenarios whose label shares a parent with a rule technique; per
parent the N smallest by declared LFS size (tie-break `dataset_id`), capped by
`max_files` / `max_bytes` (manifest). A pull that does not deliver a file leaves
a pointer, which scores `NOT_FETCHED` and makes the fetcher exit 1.

**Exit codes.** Zero fetched units: `[SKIP]`, rc 0 (same as `evtx_eval.py`).
`--require-corpus`: rc 1 on zero fetched units **or** zero units in a scoreable
bucket (`HIT_*`/`MISS`: parser and rule both present), so a nightly cannot go
green on nothing. `--baseline` (optional `{unit_key: bucket}` JSON) fails when a
unit that was `HIT_*` becomes anything else; no absolute recall threshold exists
and none is invented.

**What this does not tell you.** Labels are per *dataset*, not per event: a hit
means a rule fired somewhere in a file that contains the technique *plus*
background, not that it isolated the technique event. There is no benign corpus,
so **no false-positive rate**. Most corpus techniques have no FENGARDE rule at
all (`NO_RULE`), and a `MISS` can mean the rule was never designed for that
procedure. A rule whose own `mitre:` block is wrong shows up falsely as
`NO_RULE` (`off_label_rules` is the check). Per-technique numbers are printed as
`hits/n` text, never a bare percent. `linux_secure`, CloudTrail, k8s and OTRF
Security-Datasets adapters are deferred until each has a fixture-backed positive
control; EVTX-ATTACK-SAMPLES (GPL-3.0, tactic-level labels only) stays with
`evtx_eval.py`.

**The blocking test is not a third-party measurement.** `test_blind_recall.py`
builds tiny synthetic trees in a temp dir (P1 burst, P2 lateral, P3 two-file
merge, P4 parent label; negatives: label-not-alert, sensitivity, rules removed,
no vacuous green, sibling labels, determinism, partial parse, LFS pointers,
unsupported sources, reader missing, selection/pin tooling) to prove the
*instrument* works. Real third-party data is never in the blocking gate;
vendoring a subset is an owner decision (it needs licence sign-off and a new
`THIRD_PARTY_NOTICES` file; the repo has only `LICENSE`).

## Relationship to `make attack-scorecard` (P3-2)

This eval lane produces the **empirical** half of the ATT&CK coverage
scorecard (a technique's mapped rule actually fired on real technique
telemetry). `make attack-scorecard` (`eval/attack/coverage_layer.py`)
produces the **declared** half (a rule's `mitre:` block claims the
technique). The two are deliberately kept separate — see that script's module
docstring for why conflating them would be dishonest.
