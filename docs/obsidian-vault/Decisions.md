---
tags: [fengarde, decisions]
locked: 2026-07-15
owner: Mel
---

# Locked decisions

From `docs/superpowers/specs/2026-07-15-fengarde-combined-plan.md` — these override
anything the source plans (PLAN_A / PLAN_C) said, and later work has not revisited them.

## 1. NIS2 draft generator is a public template layer, in this (open) repo

The field schema + deterministic German template + eval harness, with the disclaimer
structurally enforced, live in `fengarde` (this repo). `fengarde-sec` (the private,
closed layer) keeps only the trained-model / legally-validated half, plugged in through
the existing `REPORT_BACKEND=http` seam frozen in `contracts/reporting.md`. This
resolves an apparent conflict between the source plan and the open-core split: the
*seam* doesn't move, only "how good the free draft is" moved up.

→ Executed as [[M5-NIS2-Template]], done 2026-07-16.

## 2. No launch or public posting of any kind before MSP readiness

The launch wave (`docs/posts/launch-checklist.md`) fires only after **Tier-1
correctness gates + Tier-2 proof artifacts + Tier-3 MSP-grade features** (multi-tenancy,
RBAC, ops lifecycle) are all green. This is *stricter* than the original PLAN_C
sequencing (which only gated on Tier 2) and overrides PLAN_A's original week-11/12
launch phase.

→ Tracked as [[M6-Launch-Readiness]] — assessed, **not executed**. Standing instruction
independent of gate status: launch/posting needs explicit human sign-off regardless.
