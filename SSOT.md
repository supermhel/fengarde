# FENGARDE — Single Source of Truth

**This file is the canonical status/roadmap pointer for BOTH repos:**
- `fengarde` (this repo, public, Apache-2.0) — the shipped SIEM
- `fengarde-sec` (private, closed) — the proprietary LLM layer, see its own `docs/STATUS.md`

Every other doc below is historical detail, not competing truth. If a doc disagrees
with this file, **this file wins** — go fix the doc, don't trust it standalone.
Update this file whenever status changes; it's a living index, not an archive.

---

## 1. Current state (as of 2026-07-17, commit `a4af448` — M1-M5 of the combined plan executed, plus a post-M5 adversarial bug-hunt pass and the M3 dashboard-login/CSRF remainder)

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
| Incident-report hook (v0.4 Track R) | `POST/GET /alerts/{id}/report` on the WS-3 triage port (`services/ws3-indexer/reporting.py`). Builtin generic-template backend (open, zero AI/network dependency); optional `REPORT_BACKEND=http` seam for a paid backend (fengarde-sec) — frozen contract in `contracts/reporting.md`. Every report is `status: "draft"` with a mandatory disclaimer, enforced structurally (schema-validated, not by convention); citations optional (additive-field discipline). Dashboard has a "Rapport" button per alert row, renders as text (no innerHTML). |
| Opt-in auth (v0.4 Track S) | `FENGARDE_API_KEY` shared-secret on the WS-3 triage + WS-6 inventory APIs (`services/shared/authz.py`); opt-in dashboard basic-auth via `infra/docker-compose.auth.yml` override; opt-in Redis `AUTH` via `REDIS_PASSWORD`. All default OFF (unset = fully open, matching v0.1-v0.3 behavior) — a real deployment opts in. OpenSearch/Redis/Dashboards ports now bound to `127.0.0.1` by default (were `0.0.0.0`); OpenSearch's own security plugin stays disabled (documented scope cut, see `SECURITY.md` §2). |
| Proven live | Full 7-workstream stack on real Docker/Redis/OpenSearch (not just zero-infra) — see build plan §"Docker — RESOLVED". **v0.4 S + R verified live 2026-07-10** (`38341ce`): with `FENGARDE_API_KEY` set, the pipeline produces alerts end-to-end; report generation through the dashboard nginx proxy → ws3 lands in `reports-*` with `status=draft`+disclaimer; ws3/ws6 return 401 without the key / 200 with it; nginx injects the key server-side. The container-to-container triage/report path is no longer config-review-only. That live run also caught + fixed two blockers the zero-infra gate can't see (a flow-style compose YAML break from the `${REDIS_PASSWORD}` interpolation, and ws2 missing PyYAML for the A5 enrichment import). |
| AI triage | Real Ollama integration + StubLLM fallback (`services/ws5-ai/llm_adapter.py::make_llm()`) |
| Hardening series (2026-07-14/15, post-rebrand) | Deep-audit P0/P1/P2 pass, all zero-infra-gated: **P0** (`9e2745b`) window-poisoning/NaN poison-pill fixes, memory-window redelivery dedup + idle-key eviction, parser registry routing rewrite (unreachable parsers fixed, ambiguous payloads dead-lettered), shared `status_from_outcome()`; **P1** (`c84c8f6`,`625f4f8`,`7e354bb`) `/health` 503-on-bus-deaf + compose healthchecks, slowloris timeouts, dashboard/inventory loopback binds, OpenSearch transient-retry, `timeutil.to_epoch_ms` (FILETIME/ISO), rule tuning + `tools/dlq_peek.py`; **P2** (`b645b13`,`7ea6010`) `in`/`contains` operators (fail-closed, no regex), IPv6/ASA-severity parser tail, anti-dormancy gate now per-event (group_by/distinct_field satisfiable on an event matching the rule's own selection). Rebrand ARGUS→FENGARDE (`717f4ed`); dashboard fully English (#1). |
| Open-core split | **Decided** (2026-07-01, via `/plan-ceo-review`): this repo stays fully open forever; FENGARDE-Sec (trained model + regulatory compliance) is the paid, closed layer in a separate repo. **v0.4 made this concrete**: `contracts/reporting.md` is the first real additive-field contract between the two repos (fengarde-sec's Track R implements the paid backend side against it). |
| Bus backend | Redis Streams (real) + in-memory (tests). **Kafka is NOT implemented** despite older docs mentioning it as a "prod backend" — see architecture review §3 R-A. |
| Security posture | Stored-XSS in dashboard: **fixed** (`35f80fc`). Poison-message DLQ, input validation, prompt bounds: **fixed** (`a60e6d4`). Opt-in auth (v0.4 Track S, see row above) — no auth is still the *default*, same trade-off as before, now with a real opt-in path. |
| Forward roadmap | **`docs/superpowers/specs/2026-07-15-fengarde-combined-plan.md`** — merges the owner's PLAN_A (90-day execution) + PLAN_C (engineering excellence) re-baselined against actual repo state; supersedes the v0.4 build plan as forward roadmap. Milestones M1-M7, status as of `8b3f450`: **M1 correctness gates — mostly done**, one real open item (`make chaos` is written and reviewed but genuinely NOT RUN — no Docker daemon in any environment this plan has executed in yet; do not treat it as proven until a real run's output lands in a PR). **M2 proof artifacts — mostly done** (bench numbers real and in README; supply-chain root-cause fix + Dependabot/SBOM/CodeQL/Scorecard wired; quality floor: ruff blocking, mypy informational, mutmut not started). **M3 product completeness — done** (the dashboard session-login UI + CSRF pass, previously the two real open items under this milestone, closed 2026-07-17 — see the new row below). **M4 MSP-grade (the launch gate) — done**: multi-tenancy, RBAC, versioned REST API + OpenAPI spec, HMAC-signed webhooks, entry-points plugin interface, ops lifecycle (schema migration, backup/restore, disk guardrails) — see the new summary rows below. **M5 NIS2 public template layer — done**: deterministic German/English generator, eval harness (72 drafts, CI-gated), dashboard button (browser-verified), `make nis2-demo`. **M6 LAUNCH — NOT executed, no posting of any kind has happened** (see §5 below for the honest launch-readiness assessment; M6 requires explicit human approval regardless of gate status, per standing instruction). Two locked decisions: NIS2 template layer is public in this repo (fengarde-sec keeps model/legal layer via the `contracts/reporting.md` seam); no posting before MSP readiness. v0.4 Track X carry-overs (B3 dual-backend test, B4 hot-reload, B5 HA design, C2 live dashboard updates, C3 MITRE heatmap, remaining A4 parsers — DNS/k8s/CEF/cloud, S7/PROFINET, periodicity primitive) are carried in that doc's deferred backlog — still not silently dropped. |
| MSP-grade (M4, done 2026-07-16) | Multi-tenancy (tenant-scoped indices, per-tenant rule enablement, `tools/test_multi_tenant_isolation.py`); RBAC (`FENGARDE_RBAC_DB` opt-in, SQLite users + scrypt hashing + sessions + roles, `services/shared/{users,sessions,rbac}.py`); versioned REST API (`contracts/triage-api.yaml`, `/api/v1/...` alongside the unchanged bare paths); outbound HMAC-signed webhooks (`contracts/webhooks/`, `services/ws3-indexer/webhooks.py`); entry-points parser/rule plugin interface (`docs/plugin-development.md`); ops lifecycle (`services/shared/users.py` schema migration via `PRAGMA user_version`, `tools/backup.py`/`restore.py`, `tools/migrate_opensearch.py`, `services/shared/diskguard.py`). **A real gap found and disclosed while building this, not hidden**: OpenSearch ILM/retention policies were never actually installable on a live cluster (schema mismatch, see §2 below) — everything else in M4 is real and tested, this one pre-existing issue surfaced during the "versioned index mappings" work. |
| NIS2 public template layer (M5, done 2026-07-16) | `contracts/nis2-de-schema.json` + `services/ws3-indexer/nis2_template.py` — deterministic German/English NIS2 Art. 23 / §32 BSIG draft generator, additive on the existing `/alerts/{id}/report` route (`?template=nis2`). States its own NIS2-vs-DORA scope caveat inline (financial entities are typically DORA-governed, not NIS2). Zero LLM, zero paid dependency — the paid, legally-validated layer stays `fengarde-sec`'s via the existing `REPORT_BACKEND=http` seam, untouched. `docs/nis2-report-generator.md` has the full honest scope/limits. |
| Adversarial repo-wide bug hunt (2026-07-16/17, `6e3fbe4`..`f7f6190`) | A dedicated review pass over the whole M4/M5 surface (not just a PR diff), owner-requested. **Method, honestly stated**: five parallel review subagents across two rounds all terminated early on a session/usage quota before returning verdicts — a real environment limitation, not a false-negative sweep — so every finding below was independently confirmed by direct code reading (parser source, callers, schema/validation, existing tests), not by trusting agent output. Found and fixed 6 real bugs, each with a regression test verified via a revert/run/restore cycle on the fix's own diff: **F1** (HIGH) cross-tenant pooling in WS-4's stateful window counter key; **F6** (MED/HIGH) `active_directory.py` skipping the M1 OCSF field-type guards every sibling parser already has; **F2** (MEDIUM) `GET /alerts/{id}/report` tenant-gate bypass when the alert doc is absent; **F5** (LOW/MED) `LoginRateLimiter` unbounded growth + missing lock; **F4** (MEDIUM) `tools/restore.py` symlink-escape via extract-before-verify; **F3** (MEDIUM) unvalidated `tenant_id` embedded in OpenSearch index names / config paths (reject-at-edge, per owner decision — never normalize, to avoid a *new* cross-tenant merge bug). **A dedicated follow-up review subagent on just the fix commit (`6e3fbe4`) then caught a real incompleteness in F1 itself** (`f7f6190`): the window *counter* key was tenant-namespaced, but `Rule.alert_key()` — the function that computes the actual `alert_id` persisted to storage and returned to API callers — still wasn't, so two tenants firing in the same window bucket on a shared group_by value got the IDENTICAL alert_id and `find_alert()`'s cross-index-by-id lookup could return the wrong tenant's doc; fixed and independently reverify-verified the same way. That follow-up review re-checked F2-F6 too and found no further issues. Full details, discarded false positives, and the "not yet reviewed" coverage-gap list (bus.py/runner.py redelivery, most parser test-coverage depth, diskguard.py, migrate_opensearch.py, chaos_test.py, generate_sbom.py --check, spool.py atomicity, users.py migrate downgrade) are in the review artifact this pass produced — those gaps are a real follow-up item, not silently dropped. `bash run_all_tests.sh` and `ruff check services/ tools/ eval/` are clean with all fixes applied together. |
| M3 remainder: dashboard session login + CSRF (done 2026-07-17) | `services/ws7-dashboard/index.html` gains a login form gating the app behind the M4.2 RBAC session API (`/auth/login`/`/auth/logout`/`/auth/me`, previously real and HTTP-tested but never called from the browser); new nginx proxy path `/api/auth/` (`services/ws7-dashboard/templates/default.conf.template`). **RBAC off (every existing deployment) is byte-for-byte unaffected** — `GET /auth/me` 404s, the login gate is skipped, same convention as every other opt-in auth layer. **CSRF protection** (`services/ws3-indexer/triage_api.py::_check_csrf`, `services/shared/sessions.py`'s new `csrf_token`) is a second, independent layer on top of the session cookie's existing `SameSite=Strict`: every session-authenticated POST must echo a per-login token back as `X-CSRF-Token` or get 403, a no-op when RBAC is off. **Two real bugs found and fixed via actual Playwright/Chromium browser testing, not just the static contract test**: a CSS-specificity trap (`#loginScreen`'s own ID-selector rule silently outranked the `hidden` attribute) and an inline-style `""` "unset" that fell back to a stylesheet `display:none` instead of becoming visible — the second one would have left the app permanently hidden for every RBAC-off deployment had it shipped. Both fixed by always setting an explicit `style.display` value. Verified end-to-end in a real browser: login → CSRF-protected write → reload persists; wrong token 403s; logout invalidates the session and re-locks the app; RBAC-off path confirmed to show the app immediately with no gate. |
| PR / merge status | **PR #2** (`github.com/supermhel/argiem/pull/2`, branch `claude/repo-status-plan-ehbr6k` → `main`) carries all of M1-M6 + the adversarial bug-hunt fixes above — 26 commits, 185 files. Description updated 2026-07-17 to describe the actual current diff (it was originally opened for just the roadmap-doc + rebrand commits, before 24 more commits landed on the same branch). **Not cleanly mergeable as of this writing** (`mergeable_state: dirty`): `main` picked up an unrelated 5-commit P2.x hardening series (cross-source severity rubric, backpressure metrics) since this branch diverged, touching the same files this branch's envelope-v1/F6 work touched — `Makefile`, `CHANGELOG.md`, `SSOT.md`, and 11 of the 13 files under `services/ws2-normalization/parsers/` (incl. `base.py`, `active_directory.py`). Conflict resolution needs semantic review (both sides changed real parser logic, not just formatting) and is explicitly deferred — owner's call, not attempted yet. |

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
| 3-tier edge/local/central deployment topology | **Design only** | `2026-06-27-fengarde-production-roadmap-design.md` — nothing built |
| Kafka as central-tier bus | **Design only, contradicted by code** | No `_KafkaBus` exists; docstring now corrected |
| Rule matching scales past ~50 rules | **Fixed (v0.3 B1)** | Detector buckets rules by class_uid equality selection, only candidate bucket evaluated per event (`services/ws4-detection/main.py`); byte-identical firing behavior verified |
| Every shipped rule has a real producer (no dormant rules) | **Proven** | `tools/check_rule_producers.py` in `run_all_tests.sh` — found and fixed `bank_db_priv_esc` dormancy (class 6005 had no emitting parser until the DB-audit parser) |
| Triage + report workflow works through the live Docker/nginx stack | **Proven (2026-07-10, `38341ce`)** | Live run on real Docker/Redis/OpenSearch/nginx: dashboard nginx `/api/triage` + `/api/report` proxy → `ws3-indexer:8013` works; report lands in `reports-*` (status=draft+disclaimer); auth 401/200 correct; nginx injects the key server-side. Still unproven at scale: the OCC/CAS multi-replica path (unit-tested against a fake transport only) and any high-concurrency behavior. |
| B2 backpressure protects Redis under a real flood | **Unit-tested, not load-tested** | Token-bucket shedding + spool replay have unit/integration tests (`test_syslog_udp.py`), but no real high-rate flood against a live Redis was run — the "protects against OOM" claim is by-design, not measured. Rate default (2000/s) and depth threshold (100k) are untuned guesses. |
| Open-core split (this repo free / fengarde-sec paid) | **Decided, not yet legally documented** | Decision made 2026-07-01; LICENSE/README don't yet state it explicitly (see §4 below) |
| ILM/retention policies actually enforced on a live OpenSearch cluster | **NOT implemented — discovered 2026-07-16 (M4.6)** | `contracts/opensearch-mappings/ilm-policies.json` is written in Elasticsearch ILM syntax (`phases`/`actions`/`min_age`), but this stack runs OpenSearch, whose Index State Management (ISM) plugin uses a different policy schema (`states`/`transitions`) at a different endpoint. `infra/provision.sh`'s ILM install loop was already an honest no-op placeholder (see its own comments) before this was investigated; every index template's `index.lifecycle.name` reference has therefore never actually attached a working policy on a live cluster. Index TEMPLATES (the mappings themselves) install correctly and are now versioned + diffable via `tools/migrate_opensearch.py`; the ILM/ISM policy schema rewrite is untouched, tracked as an open gap, not silently worked around — fixing it needs a live cluster to verify the real ISM policy bodies against. |
| `make chaos` (M1 gate: kill each service mid-replay, assert zero lost/dup alerts) | **Written and reviewed, NOT RUN** | `tools/chaos_test.py` + the `make chaos` target exist and are wired against `infra/docker-compose.yml`, but no environment this plan has executed in has had a Docker daemon available. This is the single most important open item before M6 can be called anything more than "gates believed green" — see §5. |
| RBAC (M4.2) session store at multi-replica scale | **Single-process only, by design, not yet HA** | `services/shared/sessions.py`'s `SessionStore` is in-memory; a real multi-replica RBAC deployment needs a shared session store (e.g. Redis-backed), tracked as a follow-up, not built since it needs a live Redis to test against. Every RBAC test (`test_rbac.py`, `test_rbac_api.py`) is genuinely real HTTP against a real `ThreadingHTTPServer`, just single-process. |
| Versioned OpenSearch index-template migration (`tools/migrate_opensearch.py`, M4.6) | **Wire-format tested only, not run against a live cluster** | Same standing caveat as the rest of `storage/opensearch.py` (the CAS path, the retry logic) — proven correct at the request-construction level via a fake transport (`tools/test_migrate_opensearch.py`), never exercised against real OpenSearch. |
| F1-F6 adversarial bug-hunt fixes (`6e3fbe4`) actually close the described holes | **Proven, zero-infra** | Each fix's regression test independently confirmed via `git apply -R`-then-run-then-restore against the fix's own diff: every test genuinely fails without its fix and passes with it restored (not just "passes today"). Full suite + ruff clean with all six applied together. Not yet run against a live Docker/Redis/OpenSearch stack — same standing zero-infra-only caveat as the rest of this table. |

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
| `docs/superpowers/specs/2026-06-27-fengarde-v0.1-build-plan.md` | v0.1 execution record | Historical — DONE, superseded by v0.2 but factually accurate for its era |
| `docs/superpowers/specs/2026-06-27-fengarde-production-roadmap-design.md` | 3-tier production vision + §9 open-core design | **Design/aspiration, not built** — don't read as current architecture |
| `docs/superpowers/specs/2026-06-28-T3-loop-ownership-decision.md` | Bus/runner design decision | Historical, now annotated RESOLVED (was marked unproven; gaps closed since — see file header) |
| `docs/superpowers/specs/2026-07-02-fengarde-architecture-review.md` | Cross-cutting architecture review (v0.2, current) | **Current** — the most up-to-date structural analysis; adversarially reviewed, claims confirmed against code |
| `docs/superpowers/specs/2026-07-02-fengarde-v0.3-improvement-plan.md` | v0.3 plan: more rules, robust rule logic, the rule-prefilter architecture fix, triage-first dashboard | **Executed (mostly), annotated** — header lists what landed vs. carried over; superseded as forward roadmap by the v0.4 plan |
| `docs/superpowers/specs/2026-07-10-fengarde-v0.4-build-plan.md` | v0.4 plan: auth, MCP/OT/n8n parser packs, incident-report hook (open half of the fengarde-sec split), quickstart + positioning | **Mostly executed** — Tracks 0/S/R/P1-P4/D1-D3 landed on `main`; Track X leftovers explicitly deferred to v0.5+ (see §1 forward-roadmap row) |
| `docs/superpowers/specs/2026-07-15-fengarde-combined-plan.md` | Combined forward roadmap: status re-baseline + merged PLAN_A/PLAN_C milestones M1-M7 (launch gated on MSP readiness) | **Current forward roadmap** — supersedes the v0.4 build plan for planning purposes |
| `contracts/reporting.md` | Frozen cross-repo contract: incident-report hook request/response schema, incl. M5's additive NIS2 template-mode query params | **Current** — the fengarde/fengarde-sec seam |
| `contracts/triage-api.yaml` | OpenAPI 3.1 spec for WS-3's versioned REST API (M4.3) | **Current** — spec-vs-code drift is CI-tested (`test_api_v1.py`) |
| `contracts/nis2-de-schema.json` | Field schema for the NIS2/§32 BSIG report generator (M5) | **Current** |
| `contracts/tenants/README.md`, `contracts/webhooks/README.md` | Config-file conventions for per-tenant rule enablement (M4.1) and outbound webhooks (M4.4); both ship empty | **Current** |
| `docs/ops-lifecycle.md` | M4.6: schema migration, backup/restore, disk guardrails | **Current** |
| `docs/plugin-development.md` | M4.5: writing an external parser/rule-pack plugin (entry points) | **Current** |
| `docs/webhooks.md` | M4.4: configuring + verifying outbound alert webhooks | **Current** |
| `docs/nis2-report-generator.md` | M5: NIS2 report generator scope/limits, leads with the NIS2-vs-DORA caveat | **Current** |
| `docs/posts/ocsf-native.md`, `opensearch-not-elastic.md`, `local-ai-triage.md` | v0.4 architecture write-ups (Track D3) | Draft, not published |
| `docs/posts/launch-checklist.md` | v0.4 launch sequencing (Track D3) | Current, publishing itself is a pending human action |
| `docs/posts/launch-drafts.md` | v0.1-era marketing draft | **Historical/stale facts** — annotated, points to the current write-ups above |
| `docs/adr/` (6 ADRs + index) | Architecture decision records: Redis bus, OCSF, OpenSearch, microservice split, fail-closed rules, local-LLM triage | Current (M2, backfilled 2026-07-16) — each cites the code/doc proving the decision is live, not aspirational |
| `AGENTS.md` | Imported cowork stub | Minimal, ignore |

## 4. Known doc debt (don't fix silently, flag before touching)

- ~~`services/ws2-normalization/INTERFACE.md` says "3 parsers"; code has 7.~~ **Fixed 2026-07-04** — now lists all 7.
- **Open-core decision isn't yet reflected in `README.md`/`LICENSE`/`SECURITY.md`.** The
  decision (§2 above) is real and made, but nothing in the public-facing docs *says* "this
  repo is free forever, there's a paid layer elsewhere." Worth a short README section once
  the FENGARDE-Sec product is closer to real (no rush — premature to advertise a product that's
  still Wave 0 corpus/tooling prep).
- **Production roadmap doc (`2026-06-27-...-design.md`) reads confidently** ("3-tier",
  "edge agents") but is 100% unbuilt design. A future reader skimming only that file would
  overestimate what exists. This SSOT file is the correction.

## 5. M6 launch readiness (as of `8b3f450`, 2026-07-16) — assessment only, NOT a launch

**No public post, PR-for-review-purposes-only exception aside, or announcement of any kind
has happened.** The combined plan's M6 milestone requires human approval regardless of gate
status (standing instruction: "no posting before MSP readiness," and more generally every
consequential/external action needs explicit sign-off). This section is an honest snapshot of
where the gate criteria actually stand, not a decision to launch.

**Gate criteria (combined plan, M6): M1 chaos gate + M2 bench/badges + M4 MSP-grade green.**

| Gate | Status | Why |
|---|---|---|
| M4 MSP-grade | **Green** | Multi-tenancy, RBAC, versioned API, webhooks, plugins, ops lifecycle all built and tested zero-infra (see §1's MSP-grade row). One real, disclosed gap (ILM/ISM policy schema, §2) doesn't block the gate — it was never part of M4's own scope, it's a pre-existing issue M4.6's work happened to surface. |
| M2 bench numbers | **Green** | Real, reproducible EPS/RSS numbers in README (`tools/fengarde_bench.py`), not fabricated. |
| M2 badges (CodeQL/Scorecard/Dependabot) | **Wired, not yet fired** | Workflows exist and are correctly configured; badges will reflect real values once each workflow's first run completes on `main` after this branch merges — today they read "unknown," honestly, not a pre-claimed score. |
| M1 `make chaos` | **RED — not run** | Written, reviewed, wired to `infra/docker-compose.yml`, but genuinely never executed against a live Docker daemon in any environment this plan has run in. This is real, unverified work, not a rubber-stamp gate. |

**Bottom line: three of four gate criteria are green; the fourth (`make chaos`) is the one
genuinely open item standing between "M4/M5 are done" and "the M6 gate criteria are fully
met."** Whether that blocks a launch decision, and what (if anything) happens next, is the
repo owner's call — this file states the facts, not the decision.

M5 (NIS2 template layer) is strongly preferred in the launch narrative per the plan but is
NOT a hard gate; it is also done (§1).

**Nothing in this session executed any part of `docs/posts/launch-checklist.md`.** That
remains exactly what it was: a written, unexecuted sequencing plan, pending explicit human
go-ahead.

---

*Update this file, don't create a new status doc, whenever a fact in §1/§2 changes. If a
new spec doc is added under `docs/superpowers/specs/`, add one line to §3 immediately.*
