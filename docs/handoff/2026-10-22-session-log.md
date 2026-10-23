# Status: FENGARDE session log (2026-10-20 to 2026-10-22)

Written 2026-10-22. `SSOT.md` stays the canonical status index; this file is the dated work log of one long working
session, in the Reality Map format (DONE needs PROVEN evidence, anything unverified stays ASSUMED or OPEN).

## Just done

- Release signing and the nightly eval were fixed (PRs #105, #106). The v0.11.0 and v0.11.2 release runs still failed in
  the SLSA generator; the real cause (the generator was referenced by commit SHA, which its builder rejects) was only
  found on the v0.11.2 run and fixed in #117. **v0.11.3 is the first release that passes every documented check.**
- One combined PR (#112) landed ten new detection rules and parsers (46 rules in total), the repaired fuzz harnesses (six
  real parser bugs fixed with regression tests), the gap-hunt closure, the retired legacy console and the eval-harness
  wiring. Follow-ups: #109, #110, #111, #113 to #118, #120, #121 (supply chain, release docs, CI split, path-filter
  hardening, Dependabot bumps).
- Post-merge reviews of #112 to #118 by independent reviewers found real defects (CI path filter that could skip measured
  changes, a rule helper that could re-baseline other rules' evasion floors, docs that contradicted the shipped
  artifacts). Each finding was checked against the files and fixed in a follow-up PR.
- PR #119 (open when this was written): the F4 window-clock clamp becomes the default (window-aware), and the F2 alias map
  folds identities across WS-4/WS-8/WS-9. Its live Docker run found a real crash-loop (WS-9 missing PyYAML) that every
  zero-infra test had missed.
- The OpenSSF Best Practices entry (project 14443) went from 52% to 100% (passing); private vulnerability reporting is
  enabled; code-scanning alerts went from 19 to 0 (fixed, or dismissed with a recorded reason for the three accepted
  exceptions and the single-maintainer `CodeReview` check).
- Project page (`docs/index.html`): facts only. Stale numbers fixed (ticker said 36 rules, German text said 17 fuzz
  targets), a signed-releases row and two proof items added. The look is unchanged: a background redesign was tried,
  rejected by the owner and is not part of this change; a visual redesign needs a designer.

## Reality Map

| Item | State | Evidence |
|------|-------|----------|
| v0.11.3 release: tarball bundle, SLSA provenance, image signature pass the documented commands | DONE | PROVEN: cosign v3.0.2 `verify-blob`, `verify-blob-attestation --bundle`, `verify` on `ws4-detection:v0.11.3` all "Verified OK"; provenance subject digests match the tarball hash and the pulled image digest |
| v0.11.2 release signatures | OPEN (superseded) | PROVEN broken: its re-run by `workflow_dispatch` signs as `@refs/heads/main`, which the documented tag-anchored checks reject; use v0.11.3 |
| All ten v0.11.3 image signatures | DONE | PROVEN: documented `cosign verify` (cosign v3.0.2 in Docker) on all ten `ghcr.io/supermhel/fengarde-*:v0.11.3` images, exit 0 each, tag-anchored identity |
| OSS-Fuzz `build_fuzzers` + `check_build`, 19 targets | DONE | PROVEN: Docker run against merged `main`, 19 of 19 pass |
| OSS-Fuzz accepts the project | OPEN | not submitted; the decision is theirs |
| A long fuzzing run | OPEN | only 25 s per target were run |
| OpenSSF Best Practices | DONE | PROVEN: form saved, project page shows 100% / passing |
| Code-scanning alerts | DONE | PROVEN: `gh api` shows 0 open; three accepted exceptions and `CodeReview` dismissed with recorded reasons |
| Tiered CI (fast tier, path-filtered eval tier, full gate on `main`) | DONE | PROVEN: first full-gate run on `main` passed (fast tier 3m43s, full gate 10m13s); path-filter gaps found by review fixed in #121 |
| F4 clock clamp default, F2 alias map applied to WS-8/WS-9 | OPEN until #119 merges | CI green on #119 (46 checks); the PR reports a full local gate pass and a live Redis-bus run |
| F2 closed by default | OPEN by design | PROVEN: harness shows the evasion without a configured map; closed only under a map |
| WS-1 collectors, OpenSearch and WS-8 incident output in the live F2/F4 run, real vCenter SSO spelling | OPEN | work requested; not proven when this was written |
| Project page facts refresh (numbers, signed-releases row), look unchanged | DONE after merge | PROVEN locally: `tools/console_e2e/pages.mjs` 57 of 57 pass on this branch (desktop and mobile, no third-party requests, DE/EN, replay) |
| `docs/img/og.png` and the demo console's recorded data may still show old counts | ASSUMED | not checked |

## Open threads

- Merge #119 once its live-proof gaps are closed and reviewed (largest behaviour change: the clamp is on by default).
- Verify the remaining nine image signatures of v0.11.3.
- Cut a release that includes #119 and #121 when they are merged (by pushing a tag, never by `workflow_dispatch`).
- A second GitHub reviewer would let the `CodeReview` Scorecard check pass honestly.
