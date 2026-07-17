---
tags: [fengarde, open-items]
---

# Open items — consolidated

Parent: [[Home]]. Nothing here is hidden or silently dropped, per SSOT.md §2's own
rule: "proven" requires actual evidence, a checked box requires a gate that ran, not
just code that merged.

## Blocking [[M6-Launch-Readiness|launch]]

- **`make chaos` has never run** against a live Docker daemon ([[M1-Correctness-Gates]]).
  This is the one gate criterion that's genuinely red, not just unverified-but-probably-fine.

## Blocking a merge

- **PR #2 has 14 conflicting files against `main`** ([[PR-and-Merge-Status]]) —
  deferred by owner decision, needs manual semantic reconciliation of parser logic,
  not an automated resolve.

## Real, disclosed gaps (not blocking anything specific, but genuinely open)

- **OpenSearch ILM/retention policies were never installable on a live cluster**
  ([[M4-MSP-Grade]]) — the policy file uses Elasticsearch ILM syntax, this stack runs
  OpenSearch ISM (a different schema/endpoint). Needs a live cluster to fix correctly.
- **Dashboard has no login UI** wired to the real RBAC backend ([[M3-Product-Completeness]])
  — the API (`/auth/login` etc.) is real and tested; nothing in
  `services/ws7-dashboard/` calls it yet.
- **CSRF protection is not implemented** anywhere ([[M3-Product-Completeness]]).
- **CI badges (CodeQL/Scorecard/Dependabot) are wired but unfired** ([[M2-Proof-Artifacts]])
  — waiting on the first workflow run on `main`, which needs the PR merged.
- **mutmut mutation testing on the rule engine** — not started ([[M2-Proof-Artifacts]]).
- **Live-stack (real Redis/OpenSearch) load numbers** — the published bench numbers
  are zero-infra only; B2 backpressure defaults (2000/s, 100k depth) are untuned
  guesses, never validated against a real flood ([[M2-Proof-Artifacts]]).
- **RBAC session store is single-process, not HA-ready** — a real multi-replica
  deployment needs a shared (e.g. Redis-backed) session store; not built since it
  needs a live Redis to test against.
- **`tools/migrate_opensearch.py`** — proven correct at the wire-format level against
  a fake transport only, never exercised against a real OpenSearch cluster.
- **v0.5.0 has not been cut** as a signed release tag, despite M3 calling for it.

## Coverage gaps in the bug-hunt itself

See [[Adversarial-Bug-Hunt]]'s "coverage gaps" section — `bus.py`/`runner.py`
redelivery, most parsers' test-coverage depth, `diskguard.py`, `migrate_opensearch.py`,
`chaos_test.py`'s own vacuous-pass risk, `generate_sbom.py --check`, spool atomicity,
`users.py::migrate` downgrade. A fresh-agent follow-up sweep should cover these.

## Named-but-deferred (not oversights — see [[M7-Continuous-Tracks]])

MITRE ATT&CK metadata, detection precision/recall eval, no-fire fixtures, Sigma
import, Prometheus/Grafana observability, OTel tracing, S7/PROFINET OT parser, B3–B5
v0.4 Track X carry-overs, remaining A4 parsers (DNS/k8s/CEF/cloud).
