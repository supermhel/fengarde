---
tags: [fengarde, milestone, status/green]
milestone: M5
version-target: v0.7.0
---

# M5 — NIS2 public template layer

PLAN_A Phase 4, re-scoped per [[Decisions|locked decision 1]]. Parent: [[Home]].
**Done 2026-07-16.**

## What shipped

- `contracts/nis2-de-schema.json` — stage-aware field structure
  (`early_warning`/`notification`/`final_report`), a citation + rationale in every
  field's description, structurally-required disclaimer. The schema itself states
  the DORA-vs-NIS2 scope caveat (financial entities are typically DORA-governed —
  FENGARDE's `sector: bank` tag is a detection-routing label, never a regulatory
  classification).
- `services/ws3-indexer/nis2_template.py` — German (English toggle) deterministic
  renderer, additive query params (`?template=nis2&stage=&lang=`) on the existing
  `/alerts/{id}/report` route. Every fact not knowable from the alert (entity name,
  the Art. 23(3) "significant incident" judgment call, root cause) renders as an
  explicit `[ANALYST MUST PROVIDE]` placeholder — proven by a dedicated test, not
  just claimed. Stages are cumulative, matching Art. 23(4)(b)'s actual "the
  notification shall update the early warning" semantics.
- `eval/report_generator/` — 12 synthetic incidents × 3 stages × 2 languages = 72
  drafts, each checked against a full checklist. CI-runnable.
- Dashboard "NIS2 (DE)" button — verified in a real browser (Playwright/Chromium).
  `make nis2-demo` — zero-infra, real privileged-GRANT event → real alert → German
  draft, end to end.
- LLM enhancement explicitly **not** built this pass — stays available via the
  existing `REPORT_BACKEND=http` / `fengarde-sec` seam, untouched.

## Gate (from the plan)

> Eval harness green ✅ (72/72); HTTP wiring + stage-cumulativeness +
> never-fabricates-entity-facts tests green ✅; dashboard button verified in a real
> browser ✅; `make nis2-demo` green ✅.

**Met.** PLAN_A's original "clone → firing detection + German draft in <10 min" DoD
is satisfiable today with zero Docker.
