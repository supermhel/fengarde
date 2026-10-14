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
  volume, 57 raw-XML files.

A rule with `tp+fn == 0` across all corpus files is reported as `untested`
— surfaced, never implied passing. **Expected-positives are
corpus-composition-dependent**: the corpora are fetched at clone time and
are not version-pinned, so a later clone can shift which rules see
attack-shaped volume (this snapshot's run: `bruteforce` /
`lateral_movement` / `bruteforce_sourceless` had zero expected-positives in
either corpus — the splunk lane reads only raw-XML `.log` exports, and
splunk/attack_data's brute-force/spray *volume* (purplesharp/T1110) lives in
its non-XML exports, a documented extractor limitation of the lane).
`eval/attack/fire_check.py` is the compensating check: it proves all 28
MITRE-tagged rules fire on their own real producer fixtures, including the
12 stateful ones — so an `untested` here means "this corpus composition
didn't exercise it", not "the rule does not work".

**Committed synthetic fixtures** (`eval/detection_accuracy/attack_fixtures.py`)
complement the corpora: shapes the two public corpora never contain (one
account failed from 8+ distinct source IPs in 300 s for `password_spray`)
are replayed through the same oracle + pipeline and graded like corpus files
(labeled `fixture:<name>`), but are **never counted** in `corpus_records`,
`records_supported`, or the parser-coverage denominator. They can only add
expected-positives; they cannot inflate coverage percentages.

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
- It is **not** a statement that FENGARDE ingests only ~42% of log formats.
  17 parsers ship for IT/OT sources the corpus does not contain at all
  (Linux SSH, Cisco ASA, VMware vSphere, DB audit, MCP/AI-agent, OPC UA/OT,
  n8n, DNS query log, Kubernetes audit, CEF, AWS CloudTrail, Sysmon, Modbus,
  generic syslog, inventory-diff …), and other corpora (splunk/attack_data)
  add more. The uncovered share is dominated by Sysmon event types
  (ImageLoad/CreateRemoteThread/ProcessAccess/Registry/PipeConnected) that
  have no clean fit in the repo's restricted OCSF profile — closing that
  half is a schema decision, not a parser tweak.
- Raising the number materially would mean either extending the restricted
  OCSF profile (a contract decision) or adding Windows event types beyond the
  current supported set — both tracked, neither silently hidden.

**Why this is published instead of hidden.** The benchmark's purpose is
credibility. A methodology section that omitted its own weakest number would
defeat it; the number is stated with its definition so a reader can judge it.
The earliest trend rows (2026-08-28: 42.3%) and this snapshot (2026-10-13:
43.2%, 2,082 of 4,818 Security+Sysmon records) differ only in the small
Sysmon-EventID-5 parser addition — the number has not been gamed, it has been
moved by real parser coverage work.

## 4. Twin scorecard (system-level operational metrics)

**Definition.** The twin is a deterministic, in-process digital-twin replay
(`eval/twin/report.py`, seed 7): an PLC-simulated OT attack chain is run
through the **real** parsers, detector, and correlation layer, and graded
against a documented oracle scenario (`eval/twin/oracle_it_intrusion.yaml`).

**Metric units** (all as in `results.json`/`units`):

| Metric | Unit | Meaning |
|---|---|---|
| `tpr` | [0,1] | true-positive rate on the intrusion replay |
| `fpr` | [0,1] | false-positive rate on negative-control replays |
| `mttd_seconds` | seconds | mean time to detect |
| `mtti_seconds`, `mttr_seconds` | seconds | mean time to investigate / respond (`null` when that stage wasn't exercised) |
| `chain_fidelity` | [0,1] | fraction of the scenario's causal chain reproduced in the incident graph |
| `evidence_completeness` | [0,1] | fraction of expected evidence items present |
| `false_correlation_rate` | ratio | false correlations per true positive incident |
| `alert_reduction_ratio` | [0,1] | (raw − correlated)/raw alert volume |
| `incident_reconstruction_time_ms` | ms | wall time to rebuild an incident from member alerts |
| `severity_calibration_error` | abs | mean |predicted − true| severity over scored alerts |
| `attribution_accuracy` | [0,1] | share of incident attributions matching ground truth |

**Limits.** All twin metrics are harness-measured on a deterministic
simulation — a fast, repeatable signal, not a field deployment measurement.
`null` fields mean "not measured in that run", never zero.

## 5. The selection rule for the snapshot

`benchmark/results.json` packages the **latest dated corpus row** and the
**latest dated twin row** in `eval/trend.jsonl`. The trend file is
append-only; its one historically fabricated pilot row (labeled as such in a
comment block) is excluded by date selection, and `tools/generate_benchmark.py`
refuses loudly if a fabricated-shaped row (fpr=0.25) ever wins selection.
The committed `results.json` is a snapshot with `generated_at`; the nightly
workflow regenerates it after every run and publishes the fresh file as an
artifact, which lands in git when someone commits it locally — same
convention as `eval/trend.jsonl` itself.

## 6. Code coverage (as reported for the OpenSSF Best Practices badge)

Measured 2026-10-14 across the full gate suite set (118 suite invocations,
0 suite failures; `coverage.py --branch`, data combined over every suite the
M2 coverage gate runs):

- **Statement coverage: 79.25%** (6,407 / 7,883 statements)
- **Branch coverage: 79.73%** (2,042 fully covered + 346 partial / 2,778)

The repo's own gate (`tools/coverage_gate.py`) does not block on a fixed
80%: it enforces per-service measured floors (WS-2 88%, WS-3 65%,
services-shared 42%, WS-4 40%, WS-6 60%, WS-8 60%, WS-9 68%) as regression
guards. The higher OpenSSF badge tiers ask for published 80% statement and
90% branch coverage; with the honest numbers above, **that criterion is
stated as not-met** — the published value is the measured one, and raising
it toward the tier is a per-service test-writing program, not a gate edit.

## 7. What is deliberately NOT in this benchmark

- No field-deployment detection rates, no vendor-comparative claims.
- No latency/throughput/HA numbers (those live in `tools/fengarde_bench*.py`
  and the chaos gate, and are measured against a live compose stack, not
  replay corpora).
- No LLM/triage quality numbers (the deterministic twin covers correlation,
  not model quality).
- No GitHub traffic numbers: clone counts are contaminated by CI checkouts
  and are not usable evidence (see the repo's distribution audit).