---
tags: [fengarde, milestone, status/yellow]
milestone: M1
version-target: v0.5.0
---

# M1 — Correctness gates

PLAN_C Tier 1 remainder. Parent: [[Home]]. See also [[Open-Items]].

## Done

- **Envelope v1** — `schema_version`, `tenant_id`, `trace_id`, documented `event_time`/
  `ingest_time`/dedup-key semantics. Additive bus-schema change, owner-authorized.
  Wired through all 10 parsers + all 4 live WS-1 collectors.
- **Degradation matrix** — `docs/degradation-matrix.md`, sourced from the actual
  fail-open/fail-closed code paths (Redis, OpenSearch write+OCC, Ollama, fengarde-sec
  backend, syslog spool, enrichment, allowlists, poison events, parser crashes).
- **Hypothesis property tests** — one test per registered parser, 100 generated
  examples each. Found and fixed a real bug: 6 structured-record parsers assigned
  unguarded JSON-field values into schema-constrained `ip`/`mac`/hostname fields;
  `shared/ocsf.py` gained `valid_ip`/`valid_mac`/`safe_str` to fix all six.
- **atheris fuzz harnesses** — top 3 parsers by regex complexity (linux_ssh,
  cisco_asa, windows_eventlog) + nightly CI job. Locally spot-verified: millions of
  executions, zero crashes. Full nightly budget only runs once merged to `main`.
- **Log-injection defense** — `shared/sanitize.py` strips ANSI escapes (blocks
  OSC-52/terminal injection) and C0/DEL control chars (blocks newline log forging),
  wired into `normalize_one()` between parse and enrich.

## Open — genuinely red

- **`make chaos` has never been run.** `tools/chaos_test.py` (kills each of
  ws1–ws5 mid-replay across 40 brute-force scenarios, asserts zero lost/duplicate
  alerts) is written, reviewed, and wired to `infra/docker-compose.yml` — but no
  environment this project has executed in has had a Docker daemon available. **This
  is the single open item blocking [[M6-Launch-Readiness]].** Do not treat it as
  proven until a real run's output lands in a PR.
- The 60-second OpenSearch-outage-under-load chaos variant — not written yet either.
- No documented Redis reconnect/backoff strategy (degradation matrix flags this).

## Gate (from the plan)

> `make chaos` green in CI (still open); fuzz corpus runs 10 min clean (harnesses
> done + locally spot-verified, full nightly budget only runs once merged).

**Not met** — one real, disclosed gap standing between "written" and "proven."
