# ARGIEM — Single Source of Truth

**This file is the canonical status/roadmap pointer for BOTH repos:**
- `argiem` (this repo, public, Apache-2.0) — the shipped SIEM
- `argiem-sec` (private, closed) — the proprietary LLM layer, see its own `docs/STATUS.md`

Every other doc below is historical detail, not competing truth. If a doc disagrees
with this file, **this file wins** — go fix the doc, don't trust it standalone.
Update this file whenever status changes; it's a living index, not an archive.

---

## 1. Current state (as of 2026-07-10, commit `d404acf` — v0.4 Tracks 0/S/R/P/D executed)

| Fact | Value |
|---|---|
| Latest release | **v0.3.0** (tag `v0.3.0`, 2026-07-10); v0.4 Tracks 0/S/R/P/D landed on `main`, unreleased |
| License | Apache-2.0, public, `github.com/supermhel/argiem` |
| Parsers shipped | 10: Linux SSH, Cisco ASA, Active Directory, VMware vSphere, generic syslog, Windows Event Log (incl. account-change 4720/4722/4726/4728/4732), DB audit, MCP/AI-agent tool-call audit (v0.4 P1), OPC UA/OT audit (v0.4 P2), n8n automation-platform audit (v0.4 P3) |
| Detection rules shipped | 17: brute-force, port-scan, lateral-movement, password-spray, privileged-group grant, after-hours admin, bank DB priv-esc, DC mass-VM-delete, impossible-travel (v0.4 P4), agent credential-file access / tool-call burst / prompt-injection indicator (v0.4 P1), OT write-outside-maintenance / new-engineering-connection / config-change (v0.4 P2), n8n new-webhook-exposed / workflow-modified-after-hours (v0.4 P3) |
| Rule engine | Boolean grammar + comparison operators (`gt/gte/lt/lte/ne`) + allowlist suppression (`not_in`) + time-of-day predicate (`outside_hours`), class_uid prefilter buckets. Two CI gates on `contracts/rules/`: `tools/validate_rules.py` (B4) and `tools/check_rule_producers.py` (A6 anti-dormancy — v0.4: now runs the real enrich() step too, not just parsers). Grammar documented in `contracts/sigma-convention.md`. **v0.4 lesson**: a rule sharing `class_uid` with another source's producer needs an explicit `siem.source_type` selection or it can mis-fire/pool counters across sources — see `contracts/detection-coverage.md`'s "Cross-source rule scoping" note |
| Backpressure (B2) | Ingest-edge shedding: WS-1 syslog listener token-bucket (`SYSLOG_MAX_EVENTS_PER_SEC`, default 2000/s) sheds excess datagrams before the bus; no mid-pipeline MAXLEN trim (would drop unconsumed = audit violation). Depth watchdog (`Bus.depth()`, `RAW_EVENTS_DEPTH_WARN`) is monitoring-only. Opt-in zero-loss fallback: `BoundedSpool` (disk-backed, `SYSLOG_SPOOL_PATH`) replays shed/dropped events; bounded, `events_lost` counts overflow. |
| Enrichment (A5) | WS-2 post-normalize stage (`services/ws2-normalization/enrichment/`) adds OCSF-additive `src_endpoint.reputation` (local IOC list) + `src_endpoint.location` (local CIDR→country map). Offline/air-gap-safe, additive, fail-open. **Consumed as of v0.4**: `common_impossible_travel.yml` (P4) is the first rule reading `src_endpoint.location.country`. |
| Triage workflow | Status + note per alert (WS-3 triage API port 8013 + dashboard UI). Concurrent writes protected at two layers: in-process lock (single replica) + OpenSearch `_seq_no`/`_primary_term` OCC (`find_alert_versioned`/`index_cas`, bounded retry, honest 409 on exhaustion). CAS wire format unit-tested via fake transport (`test_storage_cas.py`); not yet exercised against a live cluster. Container nginx path validated by config review only — live-stack smoke test still pending |
| Incident-report hook (v0.4 Track R) | `POST/GET /alerts/{id}/report` on the WS-3 triage port (`services/ws3-indexer/reporting.py`). Builtin generic-template backend (open, zero AI/network dependency); optional `REPORT_BACKEND=http` seam for a paid backend (argiem-sec) — frozen contract in `contracts/reporting.md`. Every report is `status: "draft"` with a mandatory disclaimer, enforced structurally (schema-validated, not by convention); citations optional (additive-field discipline). Dashboard has a "Rapport" button per alert row, renders as text (no innerHTML). |
| Opt-in auth (v0.4 Track S) | `ARGIEM_API_KEY` shared-secret on the WS-3 triage + WS-6 inventory APIs (`services/shared/authz.py`); opt-in dashboard basic-auth via `infra/docker-compose.auth.yml` override; opt-in Redis `AUTH` via `REDIS_PASSWORD`. All default OFF (unset = fully open, matching v0.1-v0.3 behavior) — a real deployment opts in. OpenSearch/Redis/Dashboards ports now bound to `127.0.0.1` by default (were `0.0.0.0`); OpenSearch's own security plugin stays disabled (documented scope cut, see `SECURITY.md` §2). |
| Proven live | Full 7-workstream stack on real Docker/Redis/OpenSearch (not just zero-infra) — see build plan §"Docker — RESOLVED". **v0.4 S + R verified live 2026-07-10** (`38341ce`): with `ARGIEM_API_KEY` set, the pipeline produces alerts end-to-end; report generation through the dashboard nginx proxy → ws3 lands in `reports-*` with `status=draft`+disclaimer; ws3/ws6 return 401 without the key / 200 with it; nginx injects the key server-side. The container-to-container triage/report path is no longer config-review-only. That live run also caught + fixed two blockers the zero-infra gate can't see (a flow-style compose YAML break from the `${REDIS_PASSWORD}` interpolation, and ws2 missing PyYAML for the A5 enrichment import). |
| AI triage | Real Ollama integration + StubLLM fallback (`services/ws5-ai/llm_adapter.py::make_llm()`) |
| Open-core split | **Decided** (2026-07-01, via `/plan-ceo-review`): this repo stays fully open forever; ARGIEM-Sec (trained model + regulatory compliance) is the paid, closed layer in a separate repo. **v0.4 made this concrete**: `contracts/reporting.md` is the first real additive-field contract between the two repos (argiem-sec's Track R implements the paid backend side against it). |
| Bus backend | Redis Streams (real) + in-memory (tests). **Kafka is NOT implemented** despite older docs mentioning it as a "prod backend" — see architecture review §3 R-A. |
| Security posture | Stored-XSS in dashboard: **fixed** (`35f80fc`). Poison-message DLQ, input validation, prompt bounds: **fixed** (`a60e6d4`). Opt-in auth (v0.4 Track S, see row above) — no auth is still the *default*, same trade-off as before, now with a real opt-in path. |
| Forward roadmap | **`docs/superpowers/specs/2026-07-10-argiem-v0.4-build-plan.md`** — Tracks 0/S/R/P1-P4/D1-D3 all landed this pass. Remaining/deferred: Track X carry-overs (B3 dual-backend test, B4 hot-reload, B5 HA design, C2 live dashboard updates, C3 MITRE heatmap, remaining A4 parsers — DNS/k8s/CEF/cloud, S7/PROFINET OT parser, periodicity primitive) — all explicitly deferred to v0.5+, not silently dropped. |

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
| 3-tier edge/local/central deployment topology | **Design only** | `2026-06-27-argiem-production-roadmap-design.md` — nothing built |
| Kafka as central-tier bus | **Design only, contradicted by code** | No `_KafkaBus` exists; docstring now corrected |
| Rule matching scales past ~50 rules | **Fixed (v0.3 B1)** | Detector buckets rules by class_uid equality selection, only candidate bucket evaluated per event (`services/ws4-detection/main.py`); byte-identical firing behavior verified |
| Every shipped rule has a real producer (no dormant rules) | **Proven** | `tools/check_rule_producers.py` in `run_all_tests.sh` — found and fixed `bank_db_priv_esc` dormancy (class 6005 had no emitting parser until the DB-audit parser) |
| Triage + report workflow works through the live Docker/nginx stack | **Proven (2026-07-10, `38341ce`)** | Live run on real Docker/Redis/OpenSearch/nginx: dashboard nginx `/api/triage` + `/api/report` proxy → `ws3-indexer:8013` works; report lands in `reports-*` (status=draft+disclaimer); auth 401/200 correct; nginx injects the key server-side. Still unproven at scale: the OCC/CAS multi-replica path (unit-tested against a fake transport only) and any high-concurrency behavior. |
| B2 backpressure protects Redis under a real flood | **Unit-tested, not load-tested** | Token-bucket shedding + spool replay have unit/integration tests (`test_syslog_udp.py`), but no real high-rate flood against a live Redis was run — the "protects against OOM" claim is by-design, not measured. Rate default (2000/s) and depth threshold (100k) are untuned guesses. |
| Open-core split (this repo free / argiem-sec paid) | **Decided, not yet legally documented** | Decision made 2026-07-01; LICENSE/README don't yet state it explicitly (see §4 below) |

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
| `docs/superpowers/specs/2026-06-27-argiem-v0.1-build-plan.md` | v0.1 execution record | Historical — DONE, superseded by v0.2 but factually accurate for its era |
| `docs/superpowers/specs/2026-06-27-argiem-production-roadmap-design.md` | 3-tier production vision + §9 open-core design | **Design/aspiration, not built** — don't read as current architecture |
| `docs/superpowers/specs/2026-06-28-T3-loop-ownership-decision.md` | Bus/runner design decision | Historical, now annotated RESOLVED (was marked unproven; gaps closed since — see file header) |
| `docs/superpowers/specs/2026-07-02-argiem-architecture-review.md` | Cross-cutting architecture review (v0.2, current) | **Current** — the most up-to-date structural analysis; adversarially reviewed, claims confirmed against code |
| `docs/superpowers/specs/2026-07-02-argiem-v0.3-improvement-plan.md` | v0.3 plan: more rules, robust rule logic, the rule-prefilter architecture fix, triage-first dashboard | **Executed (mostly), annotated** — header lists what landed vs. carried over; superseded as forward roadmap by the v0.4 plan |
| `docs/superpowers/specs/2026-07-10-argiem-v0.4-build-plan.md` | v0.4 plan: auth, MCP/OT/n8n parser packs, incident-report hook (open half of the argiem-sec split), quickstart + positioning | **Mostly executed** — Tracks 0/S/R/P1-P4/D1-D3 landed on `main`; Track X leftovers explicitly deferred to v0.5+ (see §1 forward-roadmap row) |
| `contracts/reporting.md` | Frozen cross-repo contract: incident-report hook request/response schema | **Current** — the argiem/argiem-sec seam |
| `docs/posts/ocsf-native.md`, `opensearch-not-elastic.md`, `local-ai-triage.md` | v0.4 architecture write-ups (Track D3) | Draft, not published |
| `docs/posts/launch-checklist.md` | v0.4 launch sequencing (Track D3) | Current, publishing itself is a pending human action |
| `docs/posts/launch-drafts.md` | v0.1-era marketing draft | **Historical/stale facts** — annotated, points to the current write-ups above |
| `AGENTS.md` | Imported cowork stub | Minimal, ignore |

## 4. Known doc debt (don't fix silently, flag before touching)

- ~~`services/ws2-normalization/INTERFACE.md` says "3 parsers"; code has 7.~~ **Fixed 2026-07-04** — now lists all 7.
- **Open-core decision isn't yet reflected in `README.md`/`LICENSE`/`SECURITY.md`.** The
  decision (§2 above) is real and made, but nothing in the public-facing docs *says* "this
  repo is free forever, there's a paid layer elsewhere." Worth a short README section once
  the ARGIEM-Sec product is closer to real (no rush — premature to advertise a product that's
  still Wave 0 corpus/tooling prep).
- **Production roadmap doc (`2026-06-27-...-design.md`) reads confidently** ("3-tier",
  "edge agents") but is 100% unbuilt design. A future reader skimming only that file would
  overestimate what exists. This SSOT file is the correction.

---

*Update this file, don't create a new status doc, whenever a fact in §1/§2 changes. If a
new spec doc is added under `docs/superpowers/specs/`, add one line to §3 immediately.*
