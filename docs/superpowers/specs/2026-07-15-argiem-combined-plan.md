# ARGIEM Combined Execution Plan — status re-baseline + merged roadmap (v0.5 → launch)

*Merges two owner-supplied planning docs — PLAN_A ("90-Day Build Plan — Agent Execution Spec")
and PLAN_C ("Engineering Excellence Spec") — re-baselined against the repo as it actually is
on 2026-07-15 (commit `7ea6010`). Supersedes the v0.4 build plan
(`2026-07-10-argiem-v0.4-build-plan.md`) as the forward roadmap. Owner: Mel.*

**Status of this doc:** current forward roadmap. Everything in §C is **design/claim** (SSOT §2
sense) until its acceptance gate has actually run — a checked box requires evidence, not intent.

---

## Decisions locked at planning time (2026-07-15, by owner)

1. **NIS2 draft generator is a public template layer in this repo.** PLAN_A Phase 4 as written
   (field schema + deterministic German template + eval harness, disclaimer structurally
   enforced) lands here; `argiem-sec` keeps only the trained-model / legally-validated layer,
   plugged in through the existing `REPORT_BACKEND=http` seam frozen in `contracts/reporting.md`.
   This resolves the apparent conflict between PLAN_A Phase 4 and the v0.4 open-core split:
   the *seam* is unchanged, only "how good the free draft is" moves up.
2. **No launch or public posting of any kind before MSP readiness.** The launch wave
   (`docs/posts/launch-checklist.md` sequencing) fires only after the Tier-1 correctness gates,
   Tier-2 proof artifacts, **and Tier-3 MSP-grade features (multi-tenancy, RBAC, ops lifecycle)**
   are green. This is stricter than PLAN_C's own sequencing (which gated launch on Tier 2 only)
   and overrides PLAN_A's week-11/12 launch phase.

---

## §A Status baseline (as of 2026-07-15, commit `7ea6010`)

### The repo today, in one table

| Fact | Value | Evidence |
|---|---|---|
| Latest release | v0.3.0 (2026-07-10); v0.4 Tracks 0/S/R/P1–P4/D1–D3 on `main`, unreleased | `CHANGELOG.md`, SSOT §1 |
| Parsers | 10 (SSH, ASA, AD, vSphere, syslog, WinEventLog, DB-audit, MCP/agent, OPC UA, n8n) | `services/ws2-normalization/parsers/` |
| Detection rules | 17, all with anti-dormancy fixtures | `contracts/rules/`, `tools/check_rule_producers.py` |
| Bus delivery | Redis Streams + consumer groups + XAUTOCLAIM + DLQ — **proven live** | SSOT §2 |
| Auth | Opt-in: `ARGIEM_API_KEY`, dashboard basic-auth override, Redis AUTH; loopback binds by default | v0.4 Track S + P1 commit `c84c8f6` |
| Report hook | `POST/GET /alerts/{id}/report`, generic template + `REPORT_BACKEND=http` seam, draft+disclaimer structurally enforced | v0.4 Track R, `contracts/reporting.md` |
| Rebrand | ARGUS → ARGIEM done | `717f4ed` |

### Landed since SSOT §1's snapshot (`d404acf`) — the 2026-07-14/15 hardening series

A deep-audit P0/P1/P2 pass (numbering from that audit session, not a repo spec doc):

- **P0** (`9e2745b`): detection-trustworthiness fixes — window poisoning (far-future timestamps
  collapsing sliding thresholds), NaN/inf poison-pill redelivery loops, memory-window redelivery
  dedup + idle-key eviction, content-hash `alert_id` fallback; parser registry routing rewritten
  (source_type authoritative, unreachable parsers fixed, ambiguous payloads dead-lettered),
  shared `status_from_outcome()`, per-record parse isolation.
- **P1** (`c84c8f6`, `625f4f8`, `7e354bb`): `/health` flips 503 on bus-deaf workers + compose
  healthchecks, slowloris socket timeouts, dashboard/inventory loopback binds, OpenSearch
  transient-retry, shared `timeutil.to_epoch_ms` (FILETIME/ISO/epoch), operator rule-tuning
  (`service_accounts` allowlist, ships empty), `tools/dlq_peek.py` DLQ inspector.
- **P2** (`b645b13`, `7ea6010`): `in`/`contains` rule operators (fail-closed, no-regex → no
  ReDoS), IPv6 + full ASA severity in parser tail, anti-dormancy gate strengthened to prove
  `group_by`/`distinct_field` satisfiable *on an event matching the rule's own selection*.

### Open honesty flags carried forward (SSOT §2)

- B2 backpressure: unit-tested, **never load-tested** — thresholds are untuned guesses. (Closed by M2 bench.)
- OCC/CAS multi-replica triage: unit-tested against a fake transport only. (Exercised by M1 chaos + M4 upgrade tests.)
- Open-core split decided but not stated in README/LICENSE. (M3 repo hygiene.)
- OT fixtures are spec-derived, not field-validated. (Stays disclosed; design partner is the fix, not a doc edit.)

### Source-plan → reality map (what's already done vs. genuinely open)

| Source item | Reality (2026-07-15) | Open remainder |
|---|---|---|
| PLAN_A P0 audit | SSOT.md + this doc serve it | — |
| PLAN_A P1 auth & hardening | ~70%: opt-in API key/basic-auth/Redis AUTH, loopback binds, XSS fixed, gitleaks CI | Session login (argon2/bcrypt + rate limit), first-boot random credential, `docs/deployment.md` TLS/Caddy example, CSRF pass |
| PLAN_A P2 quickstart | ~80%: README quickstart, `make demo` + devkit-feeder, `docs/adding-a-parser.md`, 3 issue templates, `docs/argiem-demo.cast` | Clean-machine timed validation, new-rule issue template |
| PLAN_A P3 MCP/agent parser | Parser + 3 of 5 rules shipped (v0.4 P1) | R4 egress-allowlist rule, R5 destructive-command rule, `docs/agent-monitoring.md`, R1+R3 e2e fixture |
| PLAN_A P4 NIS2 generator | Seam + generic template shipped (Track R) | Everything NIS2-specific — now scoped public (decision 1), see M5 |
| PLAN_A P5 OT parser | Done — OPC UA chosen + shipped, 3 rules | Inventory-diff "new device on OT segment" rule, `docs/ot-monitoring.md` |
| PLAN_A P6 launch assets | ~60%: 3 write-ups + launch checklist drafted | `docs/vs.md`, agent/NIS2 posts, repo hygiene, v0.4+ release notes |
| PLAN_C T1.1 delivery semantics | Streams/groups/XAUTOCLAIM/DLQ done & proven; P0 window hardening | Envelope v1 (`schema_version`/`tenant_id`/`trace_id`), `make chaos` gate |
| PLAN_C T1.2 parser hardening | Substantially done (P0 routing + fail-closed, P2 no-regex operators, XSS fixed, schema validation in CI) | Hypothesis property tests, atheris fuzz nightly, ANSI/control-char strip test |
| PLAN_C T1.3 backpressure/outage | Partial: B2 shed+spool, OpenSearch retry, healthchecks | Degradation-matrix doc, chaos outage test |
| PLAN_C T2.1 bench | Not started | All of it (closes the B2 flag) |
| PLAN_C T2.2 supply chain | gitleaks only | Pinning+hashes, Dependabot, SBOM, signing, SLSA, CodeQL, Scorecard badges |
| PLAN_C T2.3 quality floor | Not started | ruff/black/mypy, pre-commit, coverage gate, mutmut, ADR backfill |
| PLAN_C T3 MSP features | Not started | All of it (M4) |
| PLAN_C T4 detection quality | Partial: per-event anti-dormancy (P2.7), FP-notes tuning (P1.7), `contracts/sigma-convention.md` | MITRE metadata, precision/recall eval, no-fire fixtures, Sigma import |
| PLAN_C T5 observability | Not started (DLQ visible via `dlq_peek.py` only) | Prometheus/Grafana, OTel traces |

---

## §B Corrections to the source plans (flagged, not silently resolved)

1. **Naming:** both plans say "ARGUS"; the project is **ARGIEM** (`supermhel/argiem`) since `717f4ed`.
2. **Workstream numbering:** PLAN_A's §0 has WS-3 = detection, WS-4 = indexing, WS-6 = dashboard,
   WS-7 = alerting. Reality: WS-3 **indexer**, WS-4 **detection**, WS-5 ai, WS-6 **inventory**,
   WS-7 **dashboard**; there is no alerting workstream (alerts are a bus topic + index). This doc
   and all future work use the repo numbering.
3. **PLAN_C 1.1 "migrate to Redis Streams + consumer groups"** — already done and proven live;
   restated here as "prove the effectively-once pair via `make chaos`".
4. **PLAN_C 2.3 shared pydantic schema package** conflicts with PLAN_A's stdlib-first dependency
   rule and the bus-only-coupling architecture (services deliberately don't share import graphs
   beyond `services/shared`). Decision deferred to the M2 PR that would introduce it; the
   contract-validator + envelope-v1 JSON schema may be sufficient without pydantic.
5. **PLAN_A Phases 3 and 5 assumed greenfield** — the MCP/agent and OT parsers already shipped
   in v0.4 (OPC UA was chosen exactly as PLAN_A 5.1 recommended). Only their remainders are open.
6. **PLAN_A's whole-plan definition of done** (stranger: `git clone` → firing detection + drafted
   German NIS2 early-warning in <10 min, auth on) is retained verbatim, but sits at the end of
   **M5**, not week 8.

---

## §C Combined roadmap

Launch is the FINAL milestone and is hard-gated on MSP readiness (decision 2). Every item keeps
an acceptance gate; "done" means the gate ran, not that code merged. Version targets:
**v0.5.0 = M1+M2+M3**, **v0.6.0 = M4**, **v0.7.0 = M5**.

### M1 — Correctness gates (PLAN_C Tier 1 remainder; ~2 weeks)

- **Envelope v1**: `schema_version`, `tenant_id`, `trace_id`, `event_time` vs `ingest_time`,
  documented dedup key. *Additive* fields on the existing bus payloads — but this is a bus-schema
  change, so per standing guardrail it needs explicit owner sign-off on the contract diff
  (`contracts/bus-topics.md`) before implementation.
- **`make chaos`**: docker-kill each service mid-load during a 10k-event replay, plus a 60s
  OpenSearch outage under load → zero lost alerts, zero duplicate alerts, asserted automatically.
- **Property-based tests** (Hypothesis) per parser: arbitrary/malformed input never crashes,
  never emits schema-invalid OCSF. **Fuzz** (atheris) nightly CI job for the top 3 parsers.
- **Log-injection test**: ANSI/control chars in log content stripped/encoded before storage &
  rendering (extends the existing no-innerHTML discipline with an explicit regression test).
- **Degradation matrix** doc: every dependency down → documented, tested behavior
  (LLM→stub and OpenSearch→retry+DLQ exist; complete the matrix).
- *Gate:* `make chaos` green in CI; fuzz corpus runs 10 min clean.

### M2 — Public proof artifacts (PLAN_C Tier 2; ~1.5 weeks)

- **`argiem-bench`**: in-repo reproducible load generator (syslog/Windows/agent events at
  configurable EPS). Publish sustained EPS, p50/p99 ingest→alert latency, resource footprint on
  a defined reference box in README, with methodology. Closes the "B2 never load-tested" flag —
  and re-tunes the guessed defaults (2000/s, 100k depth) with measured numbers.
- **Supply chain**: pinned deps with hashes, Dependabot, CycloneDX SBOM per release,
  cosign-signed releases, SLSA provenance via Actions, CodeQL + secret scanning,
  OpenSSF Scorecard ≥ 8.0 + Best Practices badge in README.
- **Quality floor**: ruff + black + mypy on all services, pre-commit; coverage gate (~85%) on
  WS-2/WS-3 core; **mutmut on the rule engine**; ADR backfill (`docs/adr/`) for the six standing
  decisions (Redis bus, OCSF, OpenSearch, microservice split, fail-closed rules, local-LLM
  triage — sources already exist in `docs/superpowers/specs/`).
- *Gate:* CI blocks on lint/types/coverage; bench numbers + badges live in README;
  mutation score reported.

### M3 — Product completeness (PLAN_A gaps; runs parallel to M1/M2)

- Agent rule pack completion: **R4** egress to non-allowlisted domain, **R5** destructive
  command via agent (reuse DC mass-delete logic); `docs/agent-monitoring.md` ("point Claude
  Code / an MCP server at ARGIEM in 5 minutes"); e2e fixture firing R1+R3 in `make e2e`.
- Dashboard **session login** (argon2/bcrypt hashed credentials, login rate-limit, first-boot
  random credential printed once — replaces "basic-auth override or nothing"); CSRF pass;
  `docs/deployment.md` with reverse-proxy TLS (sample Caddyfile).
- `docs/vs.md` (honest ARGIEM vs Wazuh vs Elastic vs Security Onion — generous to competitors);
  new-rule issue template; repo hygiene (topics, social preview, CoC, `good first issue` labels
  on deferred parsers, open-core statement in README per SSOT §4); release notes.
- Clean-machine timed quickstart validation (the unchecked launch-checklist prerequisite).
- **Cut v0.5.0** — signed, with SBOM. A release tag, not a promotion: no posting (decision 2).
- *Gate:* PLAN_A Phase 1/2/3 acceptance criteria all met; `make test` + both e2e paths green.

### M4 — MSP-grade (PLAN_C Tier 3; ~2–3 weeks; → v0.6.0) ← **the launch gate**

- **Multi-tenancy end-to-end**: `tenant_id` (from M1 envelope) threaded
  collector→rules→index→alert; per-tenant OpenSearch data streams + ILM retention; per-tenant
  rule enablement/allowlists. *Gate:* automated two-tenant isolation test — same stack,
  isolated data, isolated alerts.
- **RBAC + API surface**: admin/analyst/read-only scoped per tenant (builds on M3 session
  login); versioned REST API with published OpenAPI spec (alerts, event search, rule
  management, report generation); outbound webhooks with HMAC signing; entry-points-based
  parser/rule plugin interface ("parser dev kit" — installable from an external pip package
  without forking).
- **Ops lifecycle**: versioned index mappings + migration command (tested upgrade with data
  intact, in CI); scripted backup/restore (snapshots + SQLite + config); per-signal retention
  config + disk guardrails.
- *Gate:* two-tenant test green; OpenAPI published; upgrade test in CI.

### M5 — NIS2 public template layer (PLAN_A Phase 4 re-scoped per decision 1; ~3 weeks; → v0.7.0)

Can partially parallelize with M4 (different services: ws3 reporting vs. envelope/API work).

- `ws5/report/schema_nis2_de_v0.json` (or alongside `services/ws3-indexer/reporting.py` —
  decide at PR time): NIS2 Art. 23 / NIS2UmsuCG early-warning (24h) + notification (72h) fields
  from public sources, citations in comments. **DRAFT — not legal advice** banner structurally
  enforced, same mechanism as the existing report disclaimer.
- Deterministic layer: German template (English toggle) filling the schema from alert +
  inventory context, extending the existing builtin template backend. Markdown first; PDF
  (weasyprint) is a heavyweight-dep decision flagged for the owner.
- LLM enhancement stays optional and seam-shaped: free-text summarization/severity-suggestion
  via the existing WS-5 pattern or a `REPORT_BACKEND=http` backend (argiem-sec's slot).
  Structured fields stay deterministic; graceful degradation to pure template.
- `eval/report_generator/`: ≥10 synthetic incidents → drafts → checklist assertions (mandatory
  fields present, no facts absent from the alert, banner present). CI-runnable in template mode.
- Dashboard "Draft NIS2 notification" button on qualifying alerts (extends the Rapport button);
  `make demo` extension: bank-DB priv-esc (rule exists) → German draft, zero manual steps;
  `docs/nis2-report-generator.md` with honest scope/limits.
- *Gate:* PLAN_A Phase 4 acceptance verbatim + PLAN_A's whole-plan DoD (clone → firing
  detection + German draft <10 min, auth on).

### M6 — LAUNCH (single wave, LAST)

Fires only when **M1 chaos gate + M2 bench/badges + M4 MSP-grade** are green. M5 is strongly
preferred in the launch narrative (it's the README's Mittelstand/NIS2 headline) but M4 is the
hard gate. Human executes `docs/posts/launch-checklist.md` sequencing (r/netsec → r/selfhosted
→ Show HN → r/blueteamsec), including its prerequisites and "what NOT to do" list. Add M2's
bench numbers and badges to the posts. **No public posts of any kind before this milestone.**

### M7 — Continuous tracks (start whenever capacity allows; never block M1–M6)

- **Detection quality (Tier 4)**: MITRE ATT&CK + severity/confidence/FP-notes metadata on all
  rules, rendered in dashboard/docs; detection eval harness (labeled public corpora →
  per-rule precision/recall → `docs/detection-quality.md`); no-fire fixture sets per rule
  (regressions block CI); Sigma import layer (supported subset → ARGIEM grammar; ≥20 rules
  importable and passing anti-dormancy).
- **Self-observability (Tier 5)**: structured JSON logging, Prometheus metrics per WS
  (events in/out, lag, dead-letters, alerts), shipped Grafana dashboard, OTel traces via the
  M1 `trace_id` — `make demo` shows one event's full journey.
- **OT expansion**: inventory-diff "new device on OT segment" rule, `docs/ot-monitoring.md`,
  S7/PROFINET parser (deferred, named — needs obtainable real fixtures, else stays deferred).

### Deferred backlog (v0.4 Track X carry-overs — named, not dropped)

B3 dual-backend storage test, B4 rule hot-reload, B5 HA design, C2 live dashboard updates,
C3 MITRE heatmap (folds into M7 Tier 4 rendering), remaining A4 parsers (DNS/k8s/CEF/cloud —
`good first issue` candidates per M3), periodicity window primitive.

### Cut order under pressure (from PLAN_C, extended)

Tier 5 first, then Sigma import, then M7 OT expansion — **never Tier 1 (M1), never the
MSP-readiness launch gate (M4 before M6)**. If a milestone slips >30%: cut scope (fewer rules,
one fixture less), never tests or honesty docs.

---

## §D Standing guardrails (carried over from PLAN_A + repo conventions)

1. Contract-first: parsers in WS-2 pass `test_contract.py` without Docker; rules ship
   anti-dormancy fixtures; `make test` green before claiming done.
2. Honesty posture: README working-vs-planned and SSOT §1/§2 updated with every merge;
   no overclaiming — a gate that hasn't run is a claim, not a fact.
3. Fail-closed on malformed input; idempotency invariant (replay never double-alerts;
   `make e2e` may not break).
4. Ask the owner before: heavyweight dependencies (each new dep gets a one-line justification),
   bus message-schema changes (M1 envelope!), user-facing renames, licensing.
5. No proprietary/argiem-sec content here: regulatory *templates* with public-source citations
   OK; trained weights, corpora, legally-validated mappings NOT.
6. Never fabricate log formats, legal requirements, or benchmark numbers; cite sources.
   Keep PRs reviewable on a phone. Each milestone ends with tests green + CHANGELOG entry +
   a short devlog summary.
