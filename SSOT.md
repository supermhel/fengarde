# ARGUS — Single Source of Truth

**This file is the canonical status/roadmap pointer for BOTH repos:**
- `argus` (this repo, public, Apache-2.0) — the shipped SIEM
- `argus-sec` (private, closed) — the proprietary LLM layer, see its own `docs/STATUS.md`

Every other doc below is historical detail, not competing truth. If a doc disagrees
with this file, **this file wins** — go fix the doc, don't trust it standalone.
Update this file whenever status changes; it's a living index, not an archive.

---

## 1. Current state (as of 2026-07-05, commit `d1ce1e4`)

| Fact | Value |
|---|---|
| Latest release | **v0.2.0** (tag `v0.2.0`, 2026-07-01); v0.3 Tracks A/B (incl. B2 backpressure) + C1 landed on `main` unreleased |
| License | Apache-2.0, public, `github.com/supermhel/argus` |
| Parsers shipped | 7: Linux SSH, Cisco ASA, Active Directory, VMware vSphere, generic syslog, Windows Event Log (incl. account-change 4720/4722/4726/4728/4732), DB audit |
| Detection rules shipped | 8: brute-force, port-scan, lateral-movement, password-spray, privileged-group grant, after-hours admin, bank DB priv-esc, DC mass-VM-delete |
| Rule engine | Boolean grammar + comparison operators (`gt/gte/lt/lte/ne`) + allowlist suppression (`not_in`) + time-of-day predicate (`outside_hours`), class_uid prefilter buckets. Two CI gates on `contracts/rules/`: `tools/validate_rules.py` (B4 — schema/condition/operator/reference validation, reusing the real engine parser) and `tools/check_rule_producers.py` (A6 — anti-dormancy). Grammar documented in `contracts/sigma-convention.md` |
| Backpressure (B2) | Ingest-edge shedding: WS-1 syslog listener token-bucket (`SYSLOG_MAX_EVENTS_PER_SEC`, default 2000/s) sheds excess datagrams before the bus; no mid-pipeline MAXLEN trim (would drop unconsumed = audit violation). Depth watchdog (`Bus.depth()`, `RAW_EVENTS_DEPTH_WARN`) is monitoring-only. Opt-in zero-loss fallback: `BoundedSpool` (disk-backed, `SYSLOG_SPOOL_PATH`) replays shed/dropped events; bounded, `events_lost` counts overflow. |
| Enrichment (A5) | WS-2 post-normalize stage (`services/ws2-normalization/enrichment/`) adds OCSF-additive `src_endpoint.reputation` (local IOC list) + `src_endpoint.location` (local CIDR→country map). Offline/air-gap-safe, additive, fail-open. No detection rule consumes it yet — it's the substrate for reputation/impossible-travel rules (A2 follow-up). |
| Triage workflow | Status + note per alert (WS-3 triage API port 8013 + dashboard UI). Concurrent writes protected at two layers: in-process lock (single replica) + OpenSearch `_seq_no`/`_primary_term` OCC (`find_alert_versioned`/`index_cas`, bounded retry, honest 409 on exhaustion). CAS wire format unit-tested via fake transport (`test_storage_cas.py`); not yet exercised against a live cluster. Container nginx path validated by config review only — live-stack smoke test still pending |
| Proven live | Full 7-workstream stack on real Docker/Redis/OpenSearch (not just zero-infra) — see build plan §"Docker — RESOLVED" |
| AI triage | Real Ollama integration + StubLLM fallback (`services/ws5-ai/llm_adapter.py::make_llm()`) |
| Open-core split | **Decided** (2026-07-01, via `/plan-ceo-review`): this repo stays fully open forever; ARGUS-Sec (trained model + regulatory compliance) is the paid, closed layer in a separate repo. No relicensing planned. |
| Bus backend | Redis Streams (real) + in-memory (tests). **Kafka is NOT implemented** despite older docs mentioning it as a "prod backend" — see architecture review §3 R-A. |
| Security posture | Stored-XSS in dashboard: **fixed** (`35f80fc`). Poison-message DLQ, input validation, prompt bounds: **fixed** (`a60e6d4`). No auth on any service (documented, accepted for v0.1/v0.2, see `SECURITY.md`). |

## 2. What's proven vs. what's still a claim

Read this before trusting any status word ("done", "proven", "resolved") in an older doc —
those words get reused loosely across specs written weeks apart.

- **Proven** = ran against real infra (real Redis, real Docker, a real adversarial subagent
  review with independent re-derivation) and the evidence is in a commit or a doc section
  with actual command output, not just a status label.
- **Design/claim** = written down as intent, not yet executed or verified. Treat as a plan,
  not a fact.

| Claim | Status | Evidence |
|---|---|---|
| Bus-only coupling (zero cross-workstream imports) | **Proven** | Grepped, zero hits — confirmed twice (this session + a subagent re-check) |
| WS-4 redelivery + DLQ on real Redis (XAUTOCLAIM/XPENDING) | **Proven** | Live-infra session, build plan §CI+live-infra |
| Deterministic `alert_id` (T7, dedup under redelivery) | **Proven** | `services/ws4-detection/main.py:52`, tested live |
| 3-tier edge/local/central deployment topology | **Design only** | `2026-06-27-argus-production-roadmap-design.md` — nothing built |
| Kafka as central-tier bus | **Design only, contradicted by code** | No `_KafkaBus` exists; docstring now corrected |
| Rule matching scales past ~50 rules | **Fixed (v0.3 B1)** | Detector buckets rules by class_uid equality selection, only candidate bucket evaluated per event (`services/ws4-detection/main.py`); byte-identical firing behavior verified |
| Every shipped rule has a real producer (no dormant rules) | **Proven** | `tools/check_rule_producers.py` in `run_all_tests.sh` — found and fixed `bank_db_priv_esc` dormancy (class 6005 had no emitting parser until the DB-audit parser) |
| Triage workflow works through the live Docker/nginx stack | **Design/claim** | Zero-infra tests green (`test_triage_api.py`, incl. a concurrency regression); container-to-container path (nginx `/api/triage` → `ws3-indexer:8013`) validated by config review + reading only, never live-tested. **Single-replica concurrent writes are lock-serialized; a multi-replica OpenSearch deployment has an unaddressed triage lost-update window** (needs OpenSearch optimistic concurrency, deferred with HA/B5). |
| B2 backpressure protects Redis under a real flood | **Unit-tested, not load-tested** | Token-bucket shedding + spool replay have unit/integration tests (`test_syslog_udp.py`), but no real high-rate flood against a live Redis was run — the "protects against OOM" claim is by-design, not measured. Rate default (2000/s) and depth threshold (100k) are untuned guesses. |
| Open-core split (this repo free / argus-sec paid) | **Decided, not yet legally documented** | Decision made 2026-07-01; LICENSE/README don't yet state it explicitly (see §4 below) |

## 3. Doc index — what each file is for, and its trust level

**Read `SSOT.md` (this file) first. Then only open a doc below if you need its specific detail.**

| File | Purpose | Trust level |
|---|---|---|
| `README.md` | Public-facing intro | Current |
| `CHANGELOG.md` | Version history | Current, authoritative for "what shipped when" |
| `SECURITY.md` | Threat boundary | Current |
| `CONTRIBUTING.md` | How to add a parser/rule | Current |
| `contracts/*.md` (bus-topics, ocsf-classes, sigma-convention) | Frozen Phase-0 contracts (A/B/D) | Current — these are the schema source of truth, don't restate them elsewhere |
| `docs/PHASE0_README.md`, `docs/INTERFACE.template.md` | Historical Phase-0 process docs | Historical, still accurate for what they describe |
| `docs/adding-a-parser.md` | Contributor walkthrough | Current |
| `services/*/INTERFACE.md` (7 files) | Per-workstream contract | **Partially stale** — e.g. ws2's lists 3 parsers, repo now ships 6; ws5's/ws1's predate the real Ollama/syslog-UDP work. Treat as "what WS-N's *contract* is", not "what's implemented" — cross-check against the actual `services/wsN/` code. |
| `docs/superpowers/specs/2026-06-27-argus-v0.1-build-plan.md` | v0.1 execution record | Historical — DONE, superseded by v0.2 but factually accurate for its era |
| `docs/superpowers/specs/2026-06-27-argus-production-roadmap-design.md` | 3-tier production vision + §9 open-core design | **Design/aspiration, not built** — don't read as current architecture |
| `docs/superpowers/specs/2026-06-28-T3-loop-ownership-decision.md` | Bus/runner design decision | Historical, now annotated RESOLVED (was marked unproven; gaps closed since — see file header) |
| `docs/superpowers/specs/2026-07-02-argus-architecture-review.md` | Cross-cutting architecture review (v0.2, current) | **Current** — the most up-to-date structural analysis; adversarially reviewed, claims confirmed against code |
| `docs/superpowers/specs/2026-07-02-argus-v0.3-improvement-plan.md` | v0.3 plan: more rules, robust rule logic, the rule-prefilter architecture fix, triage-first dashboard | **Current** — the forward roadmap; nothing built yet, this is the plan |
| `docs/posts/launch-drafts.md` | Marketing draft | Draft, not published |
| `AGENTS.md` | Imported cowork stub | Minimal, ignore |

## 4. Known doc debt (don't fix silently, flag before touching)

- ~~`services/ws2-normalization/INTERFACE.md` says "3 parsers"; code has 7.~~ **Fixed 2026-07-04** — now lists all 7.
- **Open-core decision isn't yet reflected in `README.md`/`LICENSE`/`SECURITY.md`.** The
  decision (§2 above) is real and made, but nothing in the public-facing docs *says* "this
  repo is free forever, there's a paid layer elsewhere." Worth a short README section once
  the ARGUS-Sec product is closer to real (no rush — premature to advertise a product that's
  still Wave 0 corpus/tooling prep).
- **Production roadmap doc (`2026-06-27-...-design.md`) reads confidently** ("3-tier",
  "edge agents") but is 100% unbuilt design. A future reader skimming only that file would
  overestimate what exists. This SSOT file is the correction.

---

*Update this file, don't create a new status doc, whenever a fact in §1/§2 changes. If a
new spec doc is added under `docs/superpowers/specs/`, add one line to §3 immediately.*
