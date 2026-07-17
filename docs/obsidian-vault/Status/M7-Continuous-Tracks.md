---
tags: [fengarde, milestone, status/not-started]
milestone: M7
role: continuous, never blocks M1-M6
---

# M7 — Continuous tracks

Parent: [[Home]]. Start whenever capacity allows; **never blocks M1–M6**. Not started.

## Detection quality (Tier 4)

MITRE ATT&CK + severity/confidence/FP-notes metadata on all rules; detection eval
harness (labeled public corpora → per-rule precision/recall); no-fire fixture sets
per rule (regressions block CI); Sigma import layer (≥20 rules importable).

## Self-observability (Tier 5)

Structured JSON logging, Prometheus metrics per workstream, shipped Grafana
dashboard, OTel traces via the M1 `trace_id` — `make demo` showing one event's full
journey.

## OT expansion

Inventory-diff "new device on OT segment" rule, `docs/ot-monitoring.md`, S7/PROFINET
parser (deferred — needs obtainable real fixtures, else stays deferred, not dropped).

## Deferred backlog (v0.4 Track X carry-overs, named not dropped)

B3 dual-backend storage test, B4 rule hot-reload, B5 HA design, C2 live dashboard
updates, C3 MITRE heatmap (folds into Tier 4), remaining A4 parsers (DNS/k8s/CEF/
cloud — `good first issue` candidates), periodicity window primitive.

## Cut order under schedule pressure

Tier 5 first, then Sigma import, then OT expansion — **never M1, never the
MSP-readiness launch gate (M4) before M6**. If a milestone slips >30%: cut scope,
never tests or honesty docs.
