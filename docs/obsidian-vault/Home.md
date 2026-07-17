---
tags: [fengarde, dashboard]
updated: 2026-07-17
source-of-truth: SSOT.md (in the repo — this vault is a derived snapshot, not a replacement)
---

# FENGARDE — Project Vault

FENGARDE is an open-source SIEM pipeline (Apache-2.0): raw security logs → OCSF
normalization → correlation rules → alerts. Seven workstreams (WS-1..WS-7) coupled
only through a message bus. Repo: `github.com/supermhel/argiem`, branch
`claude/repo-status-plan-ehbr6k`.

This vault is a snapshot as of **2026-07-17, commit `fd35995`**, built from the repo's
`SSOT.md` (canonical status) and
`docs/superpowers/specs/2026-07-15-fengarde-combined-plan.md` (the forward roadmap it
tracks against). If this vault and the repo ever disagree, **the repo wins** — re-derive,
don't trust a stale note.

## Quick status

| Milestone | Status | Note |
|---|---|---|
| [[M1-Correctness-Gates]] | 🟡 Mostly green | `make chaos` genuinely never run — no Docker daemon available |
| [[M2-Proof-Artifacts]] | 🟡 Mostly green | Bench numbers real; CI badges wired but unfired (waiting on a merged CI run) |
| [[M3-Product-Completeness]] | 🟡 Mostly green | Dashboard login UI + CSRF pass still open (RBAC *backend* is done) |
| [[M4-MSP-Grade]] | 🟢 Done — **the launch gate** | Multi-tenancy, RBAC, versioned API, webhooks, plugins, ops lifecycle |
| [[M5-NIS2-Template]] | 🟢 Done | German/English deterministic drafts, browser-verified |
| [[M6-Launch-Readiness]] | 🔴 Assessed, NOT executed | 3 of 4 gate criteria green; `make chaos` is the blocker. **No launch/posting has happened.** |
| [[M7-Continuous-Tracks]] | ⚪ Not started | Explicitly never blocks M1–M6 |

## What's happened since the plan doc was written

The plan (`2026-07-15-...-combined-plan.md`) ends at M5 done / M6 assessed. Since then:

- **[[Adversarial-Bug-Hunt]]** — a dedicated owner-requested reviewer/bug-hunter pass over
  the whole M4/M5 surface found and fixed 6 real bugs (F1–F6), each with an independently
  verified regression test. A follow-up review of the fix itself caught one fix (F1) was
  incomplete and closed that too.
- **[[PR-and-Merge-Status]]** — PR #2 now describes the true scope of this branch (26
  commits) but is **not cleanly mergeable against `main`** — an unrelated hardening series
  landed on `main` touching 14 of the same files. Unresolved, by owner decision (deferred,
  not attempted).

## Open items across everything

See [[Open-Items]] for the consolidated list — nothing here is hidden or silently dropped,
per the project's own honesty convention (SSOT.md §2: "proven" requires actual evidence,
not a status label).

## Standing constraints (do not relax without the owner)

- **No public launch, post, or announcement of any kind** until M6's gate criteria are
  actually met (see [[M6-Launch-Readiness]]) — and even then, launch needs explicit
  human sign-off regardless of gate status.
- **No proprietary `fengarde-sec` content** in this (public) repo — regulatory templates
  with public-source citations are fine, trained weights/corpora/legal mappings are not.
- Every "done" claim in this vault means *a gate actually ran*, not that code merged.
