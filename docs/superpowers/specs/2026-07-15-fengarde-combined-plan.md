# FENGARDE Combined Execution Plan — status re-baseline + merged roadmap (v0.5 → launch)

*Merges two owner-supplied planning docs — PLAN_A ("90-Day Build Plan — Agent Execution Spec")
and PLAN_C ("Engineering Excellence Spec") — re-baselined against the repo as it actually is
on 2026-07-15 (commit `7ea6010`). Supersedes the v0.4 build plan
(`2026-07-10-fengarde-v0.4-build-plan.md`) as the forward roadmap. Owner: Mel.*

**Status of this doc:** current forward roadmap. Everything in §C is **design/claim** (SSOT §2
sense) until its acceptance gate has actually run — a checked box requires evidence, not intent.

---

## Decisions locked at planning time (2026-07-15, by owner)

1. **NIS2 draft generator is a public template layer in this repo.** PLAN_A Phase 4 as written
   (field schema + deterministic German template + eval harness, disclaimer structurally
   enforced) lands here; `fengarde-sec` keeps only the trained-model / legally-validated layer,
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
| Auth | Opt-in: `FENGARDE_API_KEY`, dashboard basic-auth override, Redis AUTH; loopback binds by default | v0.4 Track S + P1 commit `c84c8f6` |
| Report hook | `POST/GET /alerts/{id}/report`, generic template + `REPORT_BACKEND=http` seam, draft+disclaimer structurally enforced | v0.4 Track R, `contracts/reporting.md` |
| Rebrand | ARGUS → FENGARDE done | `717f4ed` |

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
| PLAN_A P2 quickstart | ~80%: README quickstart, `make demo` + devkit-feeder, `docs/adding-a-parser.md`, 3 issue templates, `docs/fengarde-demo.cast` | Clean-machine timed validation, new-rule issue template |
| PLAN_A P3 MCP/agent parser | **Rule pack complete 2026-07-16**: all 5 rules (R1-R5) shipped, each proven firing on real mcp_agent parser output (`services/ws4-detection/test_v05_agent_rules.py`), including R1+R3 firing together on one session log (PLAN_A's original e2e-fixture ask, satisfied as a dedicated test rather than bolted onto the SSH-specific `make e2e`) | `docs/agent-monitoring.md` |
| PLAN_A P4 NIS2 generator | Seam + generic template shipped (Track R) | Everything NIS2-specific — now scoped public (decision 1), see M5 |
| PLAN_A P5 OT parser | Done — OPC UA chosen + shipped, 3 rules | Inventory-diff "new device on OT segment" rule, `docs/ot-monitoring.md` |
| PLAN_A P6 launch assets | ~60%: 3 write-ups + launch checklist drafted | `docs/vs.md`, agent/NIS2 posts, repo hygiene, v0.4+ release notes |
| PLAN_C T1.1 delivery semantics | Streams/groups/XAUTOCLAIM/DLQ done & proven; P0 window hardening | Envelope v1 (`schema_version`/`tenant_id`/`trace_id`), `make chaos` gate |
| PLAN_C T1.2 parser hardening | **Done** (P0 routing + fail-closed, P2 no-regex operators, XSS fixed, schema validation in CI, Hypothesis property tests + ANSI/control-char sanitize + atheris fuzz harnesses all landed 2026-07-16) | Nightly fuzz job needs to actually run in CI once merged (workflow exists, locally spot-verified only) |
| PLAN_C T1.3 backpressure/outage | Partial: B2 shed+spool, OpenSearch retry, healthchecks | Degradation-matrix doc, chaos outage test |
| PLAN_C T2.1 bench | Not started | All of it (closes the B2 flag) |
| PLAN_C T2.2 supply chain | gitleaks only | Pinning+hashes, Dependabot, SBOM, signing, SLSA, CodeQL, Scorecard badges |
| PLAN_C T2.3 quality floor | Not started | ruff/black/mypy, pre-commit, coverage gate, mutmut, ADR backfill |
| PLAN_C T3 MSP features | Not started | All of it (M4) |
| PLAN_C T4 detection quality | Partial: per-event anti-dormancy (P2.7), FP-notes tuning (P1.7), `contracts/sigma-convention.md` | MITRE metadata, precision/recall eval, no-fire fixtures, Sigma import |
| PLAN_C T5 observability | Not started (DLQ visible via `dlq_peek.py` only) | Prometheus/Grafana, OTel traces |

---

## §B Corrections to the source plans (flagged, not silently resolved)

1. **Naming:** both plans say "ARGUS"; the project is **FENGARDE** (`supermhel/argiem`) since `717f4ed`.
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
- **`make chaos`** — **started 2026-07-15**: `tools/chaos_test.py` + `make chaos` target land
  40 independent brute-force scenarios, kill each of ws1/ws2/ws3/ws4/ws5 mid-replay via
  `docker compose kill`, then assert every scenario's alert appears exactly once in
  `alerts-*`. Written against `infra/docker-compose.yml` and reviewed, but **not yet run** —
  no Docker daemon in the environment that authored it. Do not mark this gate closed in
  SSOT §2 until a real `make chaos` run's output lands in a PR. Still open: the 60s
  OpenSearch-outage-under-load variant.
- **Degradation matrix — done 2026-07-15**: `docs/degradation-matrix.md`, sourced from the
  actual fail-open/fail-closed code paths (Redis, OpenSearch write + OCC, Ollama,
  `fengarde-sec` backend, syslog spool, A5 enrichment, allowlists, poison events, parser
  crashes). Surfaces two open gaps: no documented Redis reconnect/backoff, and the OCC/CAS
  path is still unverified against a live cluster (exactly what `make chaos` needs to close).
- **Property-based tests — done 2026-07-16**: `services/ws2-normalization/parsers/test_property_hardening.py`
  (Hypothesis, added as a test-only dependency). One test per registered parser, 100
  generated examples each (recursive JSON-ish `raw`/`meta` shapes): asserts no crash and
  no schema-invalid OCSF emitted. All 10 parsers pass. Wired into `run_all_tests.sh` (+7s).
  **Fuzz — done 2026-07-16**: `tools/fuzz/{fuzz_linux_ssh,fuzz_cisco_asa,fuzz_windows_eventlog}.py`
  (atheris coverage-guided byte-level fuzzing, chosen as the top 3 by regex complexity +
  recent bug history) + `.github/workflows/fuzz.yml` (nightly, 10 min/target, corpus cached
  across runs). Locally verified (not just written): each ran 16s unseeded, 3-7 million
  execs, zero crashes, zero schema-invalid OCSF emitted -- real evidence, not a claim of
  the full nightly 10-min budget having run (that only happens in CI once merged).
- **Log-injection test — done 2026-07-16**: `services/shared/sanitize.py::strip_ansi_and_control()`
  strips ANSI CSI/OSC escapes (blocks OSC-52 clipboard injection and cursor-trick terminal
  spoofing when an analyst views raw event content) and C0/DEL control chars (blocks
  newline-based log forging), wired into `normalize_one()` (`services/ws2-normalization/main.py`)
  as a `parse -> sanitize -> enrich -> validate` stage — one choke point covering every
  parser's `message`/`actor.user.name`/`actor.process.name`/`src_endpoint.hostname`/
  `dst_endpoint.hostname` fields, not a per-parser change. Complements (doesn't replace) the
  dashboard's existing `esc()` HTML-escaping, which covers browser DOM XSS only, not
  terminal/log-sink injection. 7 tests in `services/ws2-normalization/test_sanitize.py`,
  including one driving a real parser end-to-end. Wired into `run_all_tests.sh`.
- **Degradation matrix — done 2026-07-15**: see M1's first bullet above (`docs/degradation-matrix.md`).
- *Gate:* `make chaos` green in CI (still open — no Docker daemon available where this pass
  ran, see the M1 bullet above); fuzz corpus runs 10 min clean (harnesses done + locally
  spot-verified, full nightly budget only runs once merged to `main` — see fuzz bullet above).

### M2 — Public proof artifacts (PLAN_C Tier 2; ~1.5 weeks)

- **`fengarde-bench` — partially done 2026-07-16**: `tools/fengarde_bench.py`, one command
  (`python tools/fengarde_bench.py --events 20000 --mixed`), no Docker required. Published in
  README: ~13,750 sustained EPS / ~84 MB peak RSS for a 20k-event mixed-source run, measured
  on this pass's 4 vCPU/15 GB sandbox host — real numbers, reproducible by a stranger. **Explicitly
  does NOT close the "B2 never load-tested" flag**: it's a zero-infra CPU-bound batch-processing
  baseline, not live Redis/OpenSearch throughput, and has no p50/p99 latency (batch processing
  has no queuing delay to measure). Still open: live-stack numbers on a defined reference box
  (needs Docker), re-tuning the B2 defaults (2000/s, 100k depth) from measured live numbers, and
  a before/after comparison for the rule prefilter.
- **Supply chain — mostly done 2026-07-16**: found and fixed a real root-cause gap while wiring
  this up: every service's `requirements.txt` was decorative prose (`#   redis>=5.0   # bus
  backend`), never actually installed from — each Dockerfile hardcoded its own unpinned inline
  `pip install redis PyYAML` (or similar). Rewrote all 6 as real, pinned manifests
  (`redis==5.0.8`, `PyYAML==6.0.2`) and switched every Dockerfile to
  `pip install -r requirements.txt`, dropping `pysnmp`/`scikit-learn` entirely (declared as
  "extras" but never actually imported anywhere — dead weight, not a real dependency). This is
  what makes Dependabot and the SBOM below meaningful instead of decorative themselves.
  `.github/dependabot.yml` (pip per-service + docker + github-actions ecosystems, weekly).
  `tools/generate_sbom.py` → `sbom.json` (CycloneDX, merged across services), wired into CI as a
  **blocking** freshness check (`--check` mode, compares declared components not the
  always-different `metadata.timestamp`) — verified to actually catch a staged staleness, not
  just pass trivially. `.github/workflows/codeql.yml` (Python, security-extended queries) +
  `.github/workflows/scorecard.yml` (weekly + on push) wired, badges live in README (read
  "unknown"/reflect-whatever-the-real-run-found until each workflow's first run on `main` —
  not a pre-claimed score). **Still open**: pinning with hashes (`--require-hashes`), cosign
  release signing, SLSA provenance, OpenSSF Best Practices badge, and CycloneDX-SBOM-per-release
  (today it's a repo-root snapshot kept fresh by CI, not yet tied to a release workflow — no
  release workflow exists yet).
- **Quality floor — mostly done 2026-07-16**: `pyproject.toml` (ruff/black/mypy/coverage config)
  + `.pre-commit-config.yaml`. **ruff**: 0 errors repo-wide, wired into CI as a **blocking**
  `quality` job (`.github/workflows/ci.yml`); E702 (semicolon one-liners) explicitly ignored as
  an established codebase idiom, not sloppiness — see the config's comment. **black**: configured
  but deliberately NOT applied repo-wide or wired into pre-commit — `black --check` flags 98/100
  files against this codebase's pre-existing compact style; forcing that now would be a 98-file
  mechanical reformat bundled into an unrelated PR, which CONTRIBUTING.md's own checklist forbids.
  Available for new code + the eventual deliberate full-reformat PR. **mypy**: informational only
  in CI (non-blocking) — honest baseline is 20 real findings across WS-1/2/3/4/5 (mostly legitimate
  `X | None` narrowing gaps), WS-6/shared/tools clean; flipping this to a blocking strict gate on a
  largely-unannotated codebase would train contributors to `--no-verify`, not raise quality.
  **Coverage**: `tools/coverage_gate.py`, wired into CI as **blocking**. WS-2 measured 90% (above
  the ~85% target); WS-3 measured 71% (below target — `main.py`'s run loop and
  `storage/opensearch.py`'s live-cluster paths are the gap). Gate blocks at measured-minus-buffer
  (88%/68%) as a regression guard, NOT at the unmet 85% for WS-3 — claiming that gate passed would
  be exactly the overclaiming SSOT.md §2 exists to prevent.
  Still open: **mutmut on the rule engine** (not started), **ADR backfill** (separate task, below).
- *Gate:* CI blocks on lint + coverage (both true now); types is informational, not blocking
  (honest deviation, documented above); bench numbers live in README (done); badges + mutation
  score still open.

### M3 — Product completeness (PLAN_A gaps; runs parallel to M1/M2)

- **Agent rule pack — done 2026-07-16**: **R4** (`agent_egress_non_allowlisted_domain.yml`) --
  mcp_agent parser gains `unmapped.mcp.egress_domain`/`is_egress_call` (parsed from a tool call's
  url/uri/endpoint argument), rule reuses the engine's existing `not_in`/Allowlist mechanism
  (`contracts/allowlists/agent_egress_domains.yml`, ships empty -> fires on everything until an
  operator populates it, fail-toward-visibility). **R5** (`agent_destructive_command.yml`) --
  `unmapped.mcp.destructive_command_indicator` (rm -rf/DROP TABLE/mkfs/fork-bomb patterns),
  single-shot severity (not a burst threshold like dc_mass_vm_delete.yml -- one destructive
  command from an agent is already the signal). All 19 rules (17 + these 2) pass the
  anti-dormancy gate. `services/ws4-detection/test_v05_agent_rules.py` proves all 5 agent
  rules (R1/R3/R4/R5, R2 already covered) fire on REAL mcp_agent parser output, including R1+R3
  firing together on one session log -- satisfies PLAN_A's original e2e-fixture ask as a
  dedicated test rather than bolted onto the SSH-specific `make e2e`. Also fixed a real bug
  found along the way (see the M1 property-fuzzing fix commit) in 6 parsers' unguarded
  IP/hostname/user field types. Still open: `docs/agent-monitoring.md` ("point Claude Code / an
  MCP server at FENGARDE in 5 minutes").
- Dashboard **session login** (argon2/bcrypt hashed credentials, login rate-limit, first-boot
  random credential printed once — replaces "basic-auth override or nothing"); CSRF pass;
  `docs/deployment.md` with reverse-proxy TLS (sample Caddyfile).
- `docs/vs.md` (honest FENGARDE vs Wazuh vs Elastic vs Security Onion — generous to competitors);
  new-rule issue template; repo hygiene (topics, social preview, CoC, `good first issue` labels
  on deferred parsers, open-core statement in README per SSOT §4); release notes.
- Clean-machine timed quickstart validation (the unchecked launch-checklist prerequisite).
- **Cut v0.5.0** — signed, with SBOM. A release tag, not a promotion: no posting (decision 2).
- *Gate:* PLAN_A Phase 1/2/3 acceptance criteria all met; `make test` + both e2e paths green.

### M4 — MSP-grade (PLAN_C Tier 3; ~2–3 weeks; → v0.6.0) ← **the launch gate**

- **Multi-tenancy end-to-end — done 2026-07-16**: `tenant_id` threaded collector(meta
  override)→WS-2(base_event)→WS-4(alerts, `main.py::make_alert`)→WS-3(`router.py`). Non-`default`
  tenants get their own `events-{family}-{tenant}-{date}` / `alerts-{tenant}-{date}` indices —
  ordering chosen so the EXISTING `events-common-*`/`alerts-*` OpenSearch index-template wildcards
  (`contracts/opensearch-mappings/*.json`) already match tenant-scoped names with zero template
  changes, and the `default` tenant (every pre-M4 deployment) keeps the exact old naming, zero
  migration. Per-tenant rule enablement: `contracts/tenants/<id>.yml` lists rule ids disabled for
  that tenant (`services/ws4-detection/tenants.py`), missing config/file = fail-open to full
  detection (same convention as `not_in` allowlists). **Gate passing**:
  `tools/test_multi_tenant_isolation.py`, wired into `run_all_tests.sh` — two tenants on one
  shared bus/store, proves separate event AND alert indices, correct `tenant_id` on alert docs,
  and that per-tenant rule disablement actually changes fired-vs-not behavior. Caught and fixed a
  test-authoring bug along the way (a fixed far-future timestamp tripped P0's clock-skew guard,
  unrelated to the tenancy logic itself — worth noting since it looked like a product bug first).
  **Explicitly NOT built**: true OpenSearch Data Streams API (this uses tenant-scoped regular
  indices + existing ILM policies, not the literal Data Streams feature) and PER-TENANT retention
  override (all tenants in a family currently share one ILM policy) — both real, open items, not
  silently dropped. Per-tenant *allowlist* customization (as opposed to rule enablement) also
  not built — a tenant that needs a different allowlist needs its own rule variant referencing a
  differently-named allowlist file, no engine change required but no dedicated mechanism either.
- **RBAC (M4.2) — done 2026-07-16**: real per-user identity/roles/tenant scoping, opt-in via
  `FENGARDE_RBAC_DB` (a SQLite path; unset = pre-M4.2 API-key-only behavior, `/auth/*` routes
  don't exist). `services/shared/users.py` — `UserStore` (SQLite), passwords hashed with
  `hashlib.scrypt` (stdlib, no new dependency — argon2/bcrypt considered and rejected per the
  no-new-heavyweight-deps guardrail), unique salt per hash, constant-time verify,
  fail-closed on a malformed/foreign stored hash. `services/shared/sessions.py` — in-memory
  `SessionStore`, 8h TTL, lazy expiry-on-resolve. `services/shared/rbac.py` —
  `role_at_least()` (three-tier `read_only < analyst < admin`, unrecognized role fails closed),
  `can_access_tenant()` (a non-default-tenant user can't reach an untenanted/pre-M4 resource
  either — treated as a different tenant, not a wildcard), `LoginRateLimiter` (5 failures / 5 min
  lockout per username). Wired into `services/ws3-indexer/triage_api.py`: `/auth/login`
  (sets an `HttpOnly`/`SameSite=Strict` session cookie), `/auth/logout`, `/auth/me`; role
  enforcement on the existing triage GET/POST routes (`read_only` blocked from writes);
  tenant-scoped access returns **404, never 403**, on a cross-tenant alert id, so an
  out-of-tenant caller can't even confirm the alert exists. First boot with an empty user DB
  auto-creates one `admin` account with a random password printed once to the service log —
  no `admin/admin` or any other default credential, ever
  (`services/shared/users.py::ensure_first_boot_admin`). **Gate passing**:
  `services/shared/test_rbac.py` (11 unit tests — hashing, sessions, role/tenant logic, rate
  limiter) + `services/ws3-indexer/test_rbac_api.py` (8 tests over a real `ThreadingHTTPServer`
  — login/logout/me, write-blocked-for-read-only, cross-tenant 404, admin bypass, RBAC-off
  default preserved), both wired into `run_all_tests.sh`. **Explicitly NOT built**: TLS
  anywhere (see `docs/deployment.md` for the reverse-proxy pattern), multi-replica session
  sharing (sessions are in-process; a real HA deployment needs a shared store — needs a live
  Redis to test against, not built), and WS-6 inventory API coverage (RBAC is wired into
  WS-3's triage/report routes only this pass; WS-6 stays `FENGARDE_API_KEY`-only). Documented
  in `SECURITY.md` §2 with the same "what this does NOT give you" honesty pattern used for
  every prior auth layer.
- **Versioned REST API + OpenAPI spec (M4.3) — done 2026-07-16**: `contracts/triage-api.yaml`
  (OpenAPI 3.1) is the published, canonical surface — every route is reachable both bare
  (`/alerts/...`, unchanged, what the dashboard's nginx proxy already targets) and under
  `/api/v1/...` (identical handler via `triage_api.py::_strip_api_v1`), so nothing existing
  broke to introduce versioning. Three new read endpoints close the "browse without a live
  OpenSearch Dashboards session" gap: `GET /api/v1/alerts` (newest-first, filter by
  `tenant_id`/`status`, `limit` clamped to 200), `GET /api/v1/events` (same shape, filter by
  `family`/`tenant_id`), `GET /api/v1/rules` (read-only summaries — id/title/level/sector/
  scoring/`enabled`-for-tenant — sourced directly from `contracts/rules/*.yml` +
  `contracts/tenants/<id>.yml` via a NEW, deliberately independent `services/ws3-indexer/
  rules_view.py`, not an import of `ws4-detection/engine.py`, honoring the "workstreams
  couple only through the bus" rule). **Two scoped-down-on-purpose decisions, stated not
  hidden:** (1) list endpoints are bounded/filtered, not free-text search — a real query DSL
  needs a live OpenSearch cluster this repo's zero-infra test path can't exercise; (2)
  `GET /rules` never returns a rule's raw `detection.condition` and there is no rule-write
  endpoint at all — SECURITY.md §3 treats rule files as code an operator must review, so an
  HTTP surface that could read or inject conditions would be a real regression of that
  boundary, not a feature. RBAC (M4.2) interaction: a non-admin caller's `tenant_id` on all
  three list endpoints is ALWAYS forced to their own session tenant — a `tenant_id` query
  param asking for another tenant is silently overridden, never honored, proven by
  `test_rbac_non_admin_tenant_forced_not_requested`. **Gate passing**:
  `services/ws3-indexer/test_api_v1.py` (real HTTP — filtering, limit validation, tenant
  scoping, and a spec-vs-code drift check that loads `contracts/triage-api.yaml` and confirms
  every documented GET path actually routes, not a 404 "no such path"), wired into
  `run_all_tests.sh`. `StorageAdapter.list_alerts`/`list_events` implemented in both
  `MemoryStore` (exercised by tests) and `OpenSearchStore` (same "correct request, unverified
  against a live cluster" status as the rest of that skeleton).
- **Outbound webhooks with HMAC signing (M4.4) — done 2026-07-16**: opt-in via
  `contracts/webhooks/*.yml` (ships empty — no files, no dispatcher thread starts, zero
  behavior change). `services/ws3-indexer/webhooks.py` dispatches the `alerts` bus topic
  under its OWN consumer group (`cg-webhook`), independent of WS-3's indexing group
  (`cg-index`) — a slow/down receiver can never delay or duplicate indexing, and vice versa
  (two Streams readers on one topic, the same pattern already used for `ai.requests`).
  Each delivery is HMAC-SHA256 signed (`X-Fengarde-Signature-256: sha256=<hex>`, GitHub's
  `X-Hub-Signature-256` convention, `hmac.compare_digest` on the verify side) and carries a
  `X-Fengarde-Delivery-Id` for receiver-side dedup (at-least-once, bounded retries: 4xx is
  permanent/no-retry, connection errors + 5xx get 3 attempts with backoff, mirroring
  `OpenSearchStore.index`'s policy). `secret_env` in a config names an ENVIRONMENT VARIABLE
  holding the real key — never the secret itself — so `contracts/webhooks/*.yml` stays safe
  to commit; an unset secret fails that one webhook closed without affecting others.
  Filtering: `tenant_id` (optional) and `min_score` (optional, default 0). **Gate passing**:
  `services/ws3-indexer/test_webhooks.py` — sign/verify roundtrip + tamper/wrong-secret
  rejection, config loading (valid + 3 kinds of malformed files skipped individually),
  tenant/score filtering, real HTTP delivery against a `ThreadingHTTPServer` receiver that
  independently verifies the signature, 4xx-no-retry vs 5xx-bounded-retry-then-succeed, and
  a bus-driven end-to-end test proving a two-tenant config only delivers the matching
  tenant's alert — wired into `run_all_tests.sh`. Documented in `SECURITY.md` §9 (new outbound
  egress path: operator-configured URL only, never derived from event content, so no SSRF
  surface from log content; HMAC gives authenticity, not confidentiality — use `https://` for
  anything beyond a trusted local network) and `docs/webhooks.md` (receiver-side verify
  example, honest "what this does NOT give you": no delivery UI, no dead-letter queue for
  exhausted retries yet, no mTLS/IP-allowlisting).
- **Entry-points-based parser/rule plugin interface (M4.5) — done 2026-07-16**: an external pip
  package can ship an additional WS-2 parser and/or WS-4 rule pack WITHOUT forking, via
  standard Python entry points — no new dependency, `importlib.metadata` is stdlib.
  `fengarde.parsers` entry points resolve to a `Parser` subclass
  (`services/ws2-normalization/parsers/plugins.py::discover_plugin_parsers`, wired into
  `parsers/__init__.py`); `fengarde.rule_packs` entry points resolve to a directory of rule
  YAML (`services/ws4-detection/plugins.py::discover_rule_pack_dirs`, wired into
  `Detector.__init__`). Both are purely ADDITIVE and collision-safe by construction: a
  plugin parser whose `SOURCE_TYPE` matches a built-in's is skipped (built-in wins); a
  plugin rule whose `id` matches an already-loaded rule (built-in or an earlier plugin) is
  skipped too — proven, not just asserted, by `test_colliding_rule_id_never_overrides_the_
  builtin` actually checking the built-in's title/score_weight survived untouched. **Gate
  passing**: `services/ws2-normalization/parsers/test_plugins.py` +
  `services/ws4-detection/test_plugins.py`, both using REAL `importlib.metadata.EntryPoint`
  objects (genuine `.load()` — real `import_module`+`getattr` against fixture modules under
  each service's `test_fixtures/`) rather than mocking the loading mechanism itself, only
  substituting where the entry-point LIST comes from. Covers: well-formed plugin
  discovered and its parser/rule actually runs (not just loads — the fixture rule fires on
  a real synthetic event through a real `Detector.process()`); a broken entry point (bad
  module, bad attribute, wrong type, non-directory target) is skipped individually without
  crashing discovery; and a sanity check that THIS repo's own real environment (zero
  installed plugins) round-trips to an empty plugin set, proving the "opt-in, zero behavior
  change" claim rather than assuming it. `docs/plugin-development.md` is the actual "parser
  dev kit" deliverable — a full worked example (`pyproject.toml` entry-point declarations,
  parser + rule pack source, `pip install -e`) plus an honest "what this does NOT give you"
  (no sandboxing — a plugin's code runs at full trust, same posture as SECURITY.md §3's
  existing "rule files are code, review before trusting"; no plugin marketplace; no
  versioned plugin ABI; anti-dormancy CI only covers `contracts/rules/*.yml`, not plugin
  rules — that's the plugin author's own responsibility).
- **Ops lifecycle (M4.6) — done 2026-07-16, all four items landed with an explicit new gap
  found and disclosed**:
  - **Schema migration**: `services/shared/users.py` (the RBAC DB, the one persistent local
    datastore in this system) now tracks schema via SQLite's `PRAGMA user_version` and
    migrates forward automatically on every open — a v1 `users.db` from an older release
    upgrades in place, existing accounts/roles/tenants/password hashes intact, proven by a
    real hand-built v1 DB round-tripped through migration in
    `services/shared/test_users_migration.py` (not simulated — actual SQL, actual file).
  - **Versioned index mappings + migration command**: every
    `contracts/opensearch-mappings/*.json` template now carries
    `template.mappings._meta.mapping_version` (5-file, 1-line-each surgical diff, not a
    reformat). `tools/migrate_opensearch.py` GETs what's installed, diffs against the
    file's version, and PUTs only what changed (plan-then-apply, idempotent) — replacing
    `infra/provision.sh`'s unconditional re-PUT-everything loop for a scripted upgrade path.
    Tested at the wire-format level against a fake transport
    (`tools/test_migrate_opensearch.py`), same standing "not exercised against a live
    cluster" caveat as the rest of `storage/opensearch.py`.
  - **A real gap found and disclosed, not silently worked around**: investigating "versioned
    index mappings" surfaced that ILM/retention policies were NEVER actually installable on
    a live OpenSearch cluster — `contracts/opensearch-mappings/ilm-policies.json` is written
    in Elasticsearch ILM syntax (`phases`/`actions`), but this stack runs OpenSearch, whose
    Index State Management (ISM) plugin uses a different schema (`states`/`transitions`) at
    a different endpoint. `infra/provision.sh`'s ILM loop was already an honest placeholder
    (its own prior comment said so); every template's `index.lifecycle.name` reference has
    therefore never attached a working policy. Documented in `SSOT.md` §2 (new table row) and
    `infra/provision.sh`'s comments, rather than left implicit or silently "fixed" with an
    unverifiable guess at the real ISM policy schema — closing it needs a live cluster this
    repo's test path can't stand up.
  - **Scripted backup/restore**: `tools/backup.py` bundles the RBAC SQLite DB (hot-copied via
    `sqlite3`'s `.backup()` API, safe against a live-open DB) + `contracts/` into one
    checksummed `.tar.gz` with a manifest; `tools/restore.py` verifies every file's sha256
    BEFORE writing anything, rejects path-traversal archive entries, and refuses to
    overwrite existing files without `--force`. **Explicitly NOT built**: OpenSearch index
    data (events/alerts/reports) backup — that needs OpenSearch's own native snapshot API
    against a live cluster, same reasoning as the ILM gap above; reimplementing it here would
    be an untested wrapper around a tool that already does this correctly. Proven end-to-end
    in `tools/test_backup_restore.py` against a REAL SQLite DB and this repo's REAL
    `contracts/` directory (not fixtures) — round-trip byte-identical, tampered-checksum
    rejection before any write, collision-requires-`--force`, path-traversal rejection.
  - **Disk guardrails**: `services/shared/diskguard.py::check_disk_headroom()` — a real
    `shutil.disk_usage()` check (absolute floor AND percentage floor, both must pass) — wired
    into `services/ws1-collectors/collectors/spool.py`'s `BoundedSpool.append()`, so the
    opt-in zero-loss syslog spool now refuses to grow once the underlying VOLUME (not just
    its own `max_bytes` cap) is critically low on free space. Tested against the real
    filesystem (`services/shared/test_diskguard.py`, `TestBoundedSpool.test_append_refuses_
    when_volume_is_below_the_disk_headroom_floor`) — thresholds set deliberately unreachable
    to prove the failure branch honestly, never a mocked `disk_usage` return value.
    **Explicitly NOT built**: per-tenant retention override (still M4.1's open item — one ILM
    policy per family, shared across tenants) and any guardrail on OpenSearch's own data
    volume (that's OpenSearch's own `disk.watermark.*` settings, a separate, mature
    mechanism).
  - `docs/ops-lifecycle.md` documents all four pieces with the same honest-scope pattern used
    throughout this plan.
- *Gate:* two-tenant test green (✅ done); RBAC gate green (✅ done); OpenAPI published
  (✅ done, `contracts/triage-api.yaml` + spec-vs-code test); webhook HMAC gate green
  (✅ done); plugin discovery gate green (✅ done); users.db migration gate green (✅ done);
  OpenSearch template migration gate green (✅ done, fake-transport level); backup/restore
  gate green (✅ done, real files); disk-headroom gate green (✅ done, real filesystem).
  **M4 (MSP-grade, the launch gate) is now fully done.**

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
  via the existing WS-5 pattern or a `REPORT_BACKEND=http` backend (fengarde-sec's slot).
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
  (regressions block CI); Sigma import layer (supported subset → FENGARDE grammar; ≥20 rules
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
5. No proprietary/fengarde-sec content here: regulatory *templates* with public-source citations
   OK; trained weights, corpora, legally-validated mappings NOT.
6. Never fabricate log formats, legal requirements, or benchmark numbers; cite sources.
   Keep PRs reviewable on a phone. Each milestone ends with tests green + CHANGELOG entry +
   a short devlog summary.
