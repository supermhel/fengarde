---
tags: [fengarde, milestone, status/yellow]
milestone: M2
version-target: v0.5.0
---

# M2 — Public proof artifacts

PLAN_C Tier 2. Parent: [[Home]]. See also [[Open-Items]].

## Done

- **`fengarde_bench.py`** — one-command load generator, zero Docker required.
  Published real numbers in README: ~13,750 sustained EPS / ~84 MB peak RSS for a
  20k-event mixed-source run. Explicitly does **not** close the "B2 backpressure
  never load-tested" flag — this is a zero-infra CPU-bound batch baseline, not live
  Redis/OpenSearch throughput, and has no p50/p99 latency.
- **Supply chain** — found and fixed a real root-cause gap: every service's
  `requirements.txt` was decorative prose, never actually installed from (each
  Dockerfile hardcoded its own unpinned inline `pip install`). Rewrote all 6 as real
  pinned manifests. `.github/dependabot.yml`, `tools/generate_sbom.py` (CycloneDX,
  CI-blocking freshness check — verified to actually catch staged staleness),
  CodeQL + Scorecard workflows wired, README badges added.
- **Quality floor** — `pyproject.toml` (ruff/black/mypy/coverage), `.pre-commit-config.yaml`.
  ruff: 0 errors, CI-blocking. mypy: informational only (20 real findings, honest
  baseline on a largely-unannotated codebase). Coverage: CI-blocking at
  measured-minus-buffer (WS-2 88%, WS-3 68%) — a regression guard, not a claim the
  85% target is met everywhere (WS-3 measures 71%, below target, disclosed not hidden).
- **ADR backfill** — 6 architecture decision records (Redis bus, OCSF, OpenSearch,
  microservice split, fail-closed rules, local-first LLM triage), each citing the
  code/doc proving the decision is live.

## Open

- **CI badges wired, not yet fired.** CodeQL/Scorecard/Dependabot workflows exist and
  are correctly configured, but read "unknown" until each workflow's first run
  completes on `main` — which needs [[PR-and-Merge-Status|PR #2 to actually merge]]
  first (currently blocked by conflicts).
- **mutmut on the rule engine** — not started.
- Live-stack (real Redis/OpenSearch) bench numbers on a defined reference box — needs
  Docker, same standing gap as `make chaos`.
- black — configured but deliberately not force-applied (98/100 files would reformat
  against the established style); a documented, separate decision, not an oversight.

## Gate (from the plan)

> CI blocks on lint + coverage (both true now); types is informational, not blocking
> (documented deviation); bench numbers live in README (done); badges + mutation
> score still open.

**Partially met** — lint/coverage/bench are real; badges are inert until merge.
