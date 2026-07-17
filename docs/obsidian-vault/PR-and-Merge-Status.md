---
tags: [fengarde, pr, blocker]
pr: 2
url: https://github.com/supermhel/argiem/pull/2
branch: claude/repo-status-plan-ehbr6k -> main
mergeable_state: dirty
---

# PR #2 and merge status

Parent: [[Home]]. See also [[Open-Items]].

## What it is

PR #2 was opened 2026-07-15 for the roadmap doc + ARGIEM→FENGARDE rebrand (2
commits). The branch has since accumulated 26 commits of [[M1-Correctness-Gates|M1]]
through [[M6-Launch-Readiness|M6]] execution plus the [[Adversarial-Bug-Hunt]] fixes
(185 files, +10,544/-389). Since GitHub PRs track the branch head automatically, PR
#2 already contains all of it — its title/description were just stale until
2026-07-17, when they were updated to describe the actual current diff instead of
opening a duplicate PR.

## Not cleanly mergeable

`mergeable_state: dirty` as of 2026-07-17. `main` picked up an unrelated 5-commit
P2.x hardening series (cross-source severity rubric, backpressure visibility
metrics) since this branch diverged. That series touches the same files this
branch's envelope-v1 and F6 work touched:

- `Makefile`
- `CHANGELOG.md`
- `SSOT.md`
- 11 of the 13 files under `services/ws2-normalization/parsers/`, including
  `base.py` and `active_directory.py` — right where the [[Adversarial-Bug-Hunt|F6
  fix]] landed.

## Why this isn't resolved yet

Both sides changed real parser logic, not just formatting — a blind merge/rebase
would risk silently discarding one side's semantic change. This needs someone
reading both diffs and reconciling them field-by-field, not an automated resolution.

**Explicitly deferred, by owner decision** (2026-07-17): not attempted this pass.
Options on the table when it is tackled:

1. Rebase this branch onto `origin/main`, resolve the 14 files by hand, re-run the
   full suite, force-push with lease.
2. Merge `origin/main` into this branch instead (preserves history, one merge
   commit, no force-push).

Either way: **full `run_all_tests.sh` + `ruff check` must be green after resolution**
before considering this done — conflict resolution in parser files is exactly the
kind of change that can silently reintroduce a bug the property/fuzz tests would
catch, so don't skip re-running them.
