# FENGARDE detection benchmark — methodology and honest scope

This benchmark reports what FENGARDE's detection layer measures on replayable
inputs. It is **engine-vs-oracle agreement on corpora**, not a field-trial
detection-fidelity claim. Every metric, its exact definition, and the limits
of what it can mean are documented here so the numbers are usable without
over-reading them. Reproducible recipe: [`reproduction.md`](reproduction.md).

## 1. Detection quality (macro-F1)

**Definition.** Macro-F1 is the unweighted mean of per-rule F1 over the four
rules the hand-labeled quality canary (`tools/detection_quality_eval.py`)
scores: `common_after_hours_admin`, `common_priv_grant`,
`agent_prompt_injection_indicator`, `cloud_root_console_login`.

**How it's measured.** A 10-event hand-authored corpus of normalized OCSF
events (the shape the parsers emit) is run, one event at a time, through the
**real** WS-4 engine (`engine.Rule.evaluate` on the **real** rules from
`contracts/rules/*.yml`). Each corpus entry carries the rule id(s) a human
judge expects to fire; agreement yields per-rule precision/recall/F1 and the
macro-F1. Two of the 10 labels are deliberately adversarial (a missing
timestamp the engine fail-closes on → an FN by design; a service account the
empty allowlist doesn't suppress → an FP by design), so precision and recall
are not trivially 1.0 (docs/detection-quality.md).

**Stateful rules are not scored in the canary.** Windowed/threshold rules
cannot legitimately fire on a single event, so the canary skips them by
definition. Those rules are covered by the corpus replay lanes below and by
`eval/attack/fire_check.py`, not by this macro-F1.

**What it does NOT mean.** It is not a real-world detection rate. It is not
a per-rule benchmark over real traffic. It is a regression trip-wire that
became a published number: it measures that the engine and rules still agree
with hand-labeled ground truth on the shapes the canary covers. The gate
floor is deliberately low (0.5); the published value is what the run
actually measured.

## 2. Per-rule confusion over real attack corpora

**Definition.** For each of the 6 oracle rules (`bruteforce`,
`password_spray`, `lateral_movement`, `priv_grant`, `after_hours_admin`,
`bruteforce_sourceless`), TP/FP/FN/TN counts graded **per corpus file**.

**How it's measured.** Real event corpora are replayed through the full
zero-infra pipeline (WS-2 parsers → WS-4 detector on a memory bus, fresh
window state per file), and the alerts are compared against an **independent
oracle** that recomputes each rule's ground truth directly from the raw
records — deliberately not the engine's own logic (this is the mechanism that
caught real brute-force false negatives in 2026-07). Corpora:

- **EVTX-ATTACK-SAMPLES** (GPL-3.0, not vendored): single-incident Security +
  Sysmon technique samples.
- **splunk/attack_data** (own terms, not vendored): real brute-force/spray
  volume. Its datasets are **Git LFS objects** — a clone without `git-lfs`
  leaves pointer stubs, and the splunk lane now fails loudly on them. The
  lane reads every raw-XML `.log` export (1,055 files in this snapshot's
  nightly run); plaintext/JSON exports are a documented, disclosed gap.

Each trend row records `lane_files` (how many files each lane read) so a
partial checkout can never pass as the full corpus. This is not
hypothetical: the first cut of this benchmark (trend row 2026-10-13) was
measured on a **partial local splunk checkout** (57 files: 14,663
records instead of 265,404) and wrongly reported `bruteforce`,
`lateral_movement` and `bruteforce_sourceless` as untested. That row stays
in `eval/trend.jsonl` with a comment block labeling it; the published
snapshot is the nightly CI row.

A rule with `tp+fn == 0` across all corpus files is reported as `untested`
— surfaced, never implied passing. **Expected-positives are
corpus-composition-dependent**: both corpora are pinned to fixed commits
(`eval/detection_accuracy/fetch_corpora.sh`; EVTX-ATTACK-SAMPLES `4ceed2f`,
static since 2023; splunk/attack_data `eac2f8f`, 2026-10-13), and each row
records the commits read (`corpus_commits`). splunk/attack_data keeps
growing upstream; adopting newer data is a pin bump in a PR, so which rules
see attack-shaped volume can only change with a commit. In this snapshot
only `password_spray` is untested.
`eval/attack/fire_check.py` is the compensating check: it proves all 28
MITRE-tagged rules (of 29 shipped; one rule carries no MITRE tag and is
reported as unverified by that gate) fire on their own real producer
fixtures, including the 12 stateful ones — so an `untested` here means "this
corpus composition didn't exercise it", not "the rule does not work".

**Committed synthetic fixtures** (`eval/detection_accuracy/attack_fixtures.py`)
complement the corpora: shapes the two public corpora never contain (one
account failed from 8+ distinct source IPs in 300 s for `password_spray`)
are replayed through the same oracle + real pipeline and graded like corpus
files (labeled `fixture:<name>`) — but in a **separate** matrix. Both lanes
replay the same fixtures, so the trend row takes them once into
`fixture_per_rule` / `fixture_tested_rules`, published as
`fixture_per_rule_confusion` / `fixture_tested_rules`. They are never counted
in `per_rule_confusion`, `untested_rules`, `corpus_records`, or the
parser-coverage denominator. (The first cut folded them into each lane's
corpus matrix, which double-counted one fixture as two corpus TPs; fixed
before merge.)

## 3. Parser coverage — stated plainly

`parser_coverage_pct` is the share of Security+Sysmon records in the EVTX
corpus that a shipped parser can normalize at all:

    records_supported / (records_security + records_sysmon)

**The current value is low and that is a real limitation, not a rounding
artifact.** The published snapshot's value (see `results.json` and
`README.md`) is below 50%. What it means and what it does not:

- It is a **corpus-shape measurement**: the EVTX corpus is Windows-centric
  (Security + Sysmon channels), so "42–43%" reads as *"about 57% of THIS
  corpus's records are event types the shipped parser set does not cover."*
- It is **not** a statement that FENGARDE ingests only ~43% of log formats.
  Of the 19 shipped parsers, three read this corpus (Windows event log,
  Active Directory, Sysmon); the other 14 cover sources it does not contain
  at all (Linux SSH, Cisco ASA, VMware vSphere, DB audit, MCP/AI-agent,
  OPC UA, n8n, DNS query log, Kubernetes audit, CEF, AWS CloudTrail, Modbus,
  generic syslog, inventory-diff). The uncovered share is dominated by Sysmon event types
  (ImageLoad/CreateRemoteThread/ProcessAccess/Registry/PipeConnected) that
  have no clean fit in the repo's restricted OCSF profile — closing that
  half is a schema decision, not a parser tweak.
- Raising the number materially would mean either extending the restricted
  OCSF profile (a contract decision) or adding Windows event types beyond the
  current supported set — both tracked, neither silently hidden.

**Why this is published instead of hidden.** The benchmark's purpose is
credibility. A methodology section that omitted its own weakest number would
defeat it; the number is stated with its definition so a reader can judge it.
The earliest trend rows (2026-08-28: 42.3%) and this snapshot (2026-10-14:
43.2%, 2,082 of 4,818 Security+Sysmon records) differ only in the small
Sysmon-EventID-5 parser addition — the number has not been gamed, it has been
moved by real parser coverage work.

## 4. Twin scorecard (system-level operational metrics)

**Definition.** The twin is a deterministic, in-process digital-twin replay
(`eval/twin/report.py`, seed 7): an PLC-simulated OT attack chain is run
through the **real** parsers, detector, and correlation layer, and graded
against a documented oracle scenario (`eval/twin/oracle_it_intrusion.yaml`).

**Metric units** (all as in `results.json`/`units`; definitions follow
`eval/twin/report.py`'s own metric docstring):

| Metric | Unit | Meaning |
|---|---|---|
| `tpr` | [0,1] | share of the scenario's oracle-expected detections that fired |
| `fpr` | [0,1] | share of benign negative-control replays that raised an incident |
| `mttd_seconds` | seconds | chain start → first step whose expected rule fired, on seed-derived timestamps of ONE scenario (not a mean, not wall-clock) |
| `mtti_seconds` | seconds, **modeled** | measured investigation step count over the incident's own graph × a documented 30 s/step constant |
| `mttr_seconds` | — | always `null`: the twin has no remediation/closure event to time |
| `chain_fidelity` | [0,1] | share of the oracle's allowed causal step-pairs a real WS-8 graph edge joined |
| `evidence_completeness` | [0,1] | share of oracle per-step evidence fields present (unparsed steps count against it) |
| `false_correlation_rate` | [0,1], **lower is better** | share of the oracle's *forbidden* causal pairs a graph edge joined anyway (1.0 = all of them) |
| `alert_reduction_ratio` | [0,1] | 1 − incidents / raw alerts |
| `incident_reconstruction_time_ms` | ms, informational | median wall-clock to assemble the WS-3 evidence package; machine-dependent |
| `severity_calibration_error` | binary 0/1 | 0 when the peak alert score is inside the oracle's severity band, 1 when not — **not** a mean error |
| `attribution_accuracy` | [0,1] | share of actor-bearing steps whose actor matches ground truth |

**Limits.** All twin metrics are harness-measured on a deterministic
simulation — a fast, repeatable signal, not a field deployment measurement.
`null` fields mean "not measured in that run", never zero.

## 5. The selection rule for the snapshot

`benchmark/results.json` packages the **latest dated corpus row** (a row
that actually replayed the evtx/splunk corpora — quality-only rows never
win) and the **latest dated twin row** in `eval/trend.jsonl`; on a same-day
tie the row with more corpus records wins, then the last-appended one. Every caveat that cites a number is derived
from the selected rows, never typed in. The trend file is
append-only; its one historically fabricated pilot row (labeled as such in a
comment block) is excluded by date selection, and `tools/generate_benchmark.py`
refuses loudly if a fabricated-shaped row (fpr=0.25) ever wins selection.
The committed `results.json` is a snapshot with `generated_at`; the nightly
workflow regenerates it after every run and publishes the fresh file as an
artifact, which lands in git when someone commits it locally — same
convention as `eval/trend.jsonl` itself.

## 6. Code coverage (as reported for the OpenSSF Best Practices badge)

One-off measurement (no artifact committed; re-run to reproduce), 2026-10-14,
with `python tools/coverage_summary.py`: every suite the
M2 coverage gate runs (118 suite invocations, 0 failures), one combined
`coverage.py --branch` data file:

- **Statement coverage: 81.23%** (6,403 / 7,883 statements)
- **Branch coverage: 73.47%** (2,041 / 2,778 branch arcs)
- coverage.py's combined TOTAL (statements + branches): 79.2%

The repo's own gate (`tools/coverage_gate.py`) does not block on a fixed
80%: it enforces per-service measured floors (WS-2 88%, WS-3 65%,
services-shared 42%, WS-4 40%, WS-6 60%, WS-8 60%, WS-9 68%) as regression
guards. Against the OpenSSF tiers: Silver's `test_statement_coverage80`
(≥80% statement) **is met** by the number above; Gold's
`test_statement_coverage90` (≥90% statement) and `test_branch_coverage80`
(≥80% branch) **are not met**. Raising them is a per-service test-writing
program, not a gate edit.

(The first cut of this section published 79.25% "statement" and 79.73%
"branch" from a one-off script: the first was coverage.py's combined total,
the second gave partially covered branch lines half credit. Neither is a
coverage.py metric; `tools/coverage_summary.py` replaces that script.)

## 7. What is deliberately NOT in this benchmark

- No field-deployment detection rates, no vendor-comparative claims.
- No latency/throughput/HA numbers (those live in `tools/fengarde_bench*.py`
  and the chaos gate, and are measured against a live compose stack, not
  replay corpora).
- No LLM/triage quality numbers (the deterministic twin covers correlation,
  not model quality).
- No GitHub traffic numbers: clone counts are contaminated by CI checkouts
  and are not usable evidence (see the repo's distribution audit).