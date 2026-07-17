---
tags: [fengarde, milestone, status/red]
milestone: M6
role: single wave, LAST
---

# M6 — LAUNCH

Parent: [[Home]]. **Assessed, NOT executed** — no public post, announcement, or
launch of any kind has happened. Fires only when M1 chaos gate + M2 bench/badges +
M4 MSP-grade are all green (per [[Decisions|locked decision 2]]).

## Gate criteria and where they actually stand

| Gate | Status | Why |
|---|---|---|
| [[M4-MSP-Grade\|M4 MSP-grade]] | 🟢 Green | Fully done and tested zero-infra. The one disclosed gap (ILM/ISM schema mismatch) doesn't block the gate — it was never M4's scope, just surfaced during it. |
| [[M2-Proof-Artifacts\|M2 bench numbers]] | 🟢 Green | Real, reproducible EPS/RSS numbers in README, not fabricated. |
| [[M2-Proof-Artifacts\|M2 badges]] | 🟡 Wired, not fired | Workflows correctly configured; read "unknown" until first run completes on `main` — blocked on [[PR-and-Merge-Status\|PR #2 merging]]. |
| [[M1-Correctness-Gates\|M1 `make chaos`]] | 🔴 RED — not run | Written, reviewed, wired — genuinely never executed against a live Docker daemon in any environment this project has run in. |

**Bottom line: 3 of 4 gate criteria are green; `make chaos` is the one genuinely open
item.** Whether that blocks a launch decision is the repo owner's call — this note
states facts, not a decision.

[[M5-NIS2-Template|M5]] is strongly preferred in the launch narrative (README's
Mittelstand/NIS2 headline) but is **not** a hard gate; it's done anyway.

## What has NOT happened

- Nothing in `docs/posts/launch-checklist.md` has been executed.
- No `r/netsec` / `r/selfhosted` / Show HN / `r/blueteamsec` post.
- No promotion of any kind.

Even once all four gate criteria go green, launch still requires **explicit human
sign-off** — that's a standing instruction independent of gate status, not something
a passing test suite can satisfy on its own.
