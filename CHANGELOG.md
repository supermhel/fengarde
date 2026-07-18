# Changelog

All notable changes to FENGARDE will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (M3 remainder: dashboard session login + CSRF)

Closes two items the M3 milestone had left genuinely open (verified by grep before
starting, not assumed from the plan doc): the RBAC session API (`/auth/login`,
`/auth/logout`, `/auth/me`, M4.2) was real and tested at the HTTP level, but nothing
in `services/ws7-dashboard/` actually called it, and CSRF protection didn't exist.

- **Dashboard login UI** (`services/ws7-dashboard/index.html`) — a login form gates
  the app behind a real session when `FENGARDE_RBAC_DB` is set; a user badge
  (username + role + Sign out) replaces it once authenticated. Wired to a new nginx
  proxy path (`/api/auth/` → ws3-indexer's `/auth/*`, `services/ws7-dashboard/
  templates/default.conf.template`). **RBAC off (the default, every existing
  deployment) is byte-for-byte unaffected**: `GET /auth/me` 404s (no such route), the
  login gate is skipped entirely, and the app renders exactly as before — same
  "opt-in, zero behavior change" convention as every other auth layer in this
  project. Found and fixed two real bugs while browser-testing this (Playwright/
  Chromium, not just the static contract test): a CSS-specificity trap where
  `#loginScreen`'s own ID-selector rule silently outranked the `hidden` attribute
  (toggling `.hidden` in JS did nothing), and clearing an inline `style.display` with
  `""` fell back to a stylesheet rule that was still `none` instead of becoming
  visible — both fixed by always setting an explicit display value, documented
  inline where a future edit could easily reintroduce either trap.
- **CSRF protection** (`services/ws3-indexer/triage_api.py::_check_csrf`,
  `services/shared/sessions.py`) — a second, independent layer on top of the session
  cookie's existing `SameSite=Strict`: login now also mints a `csrf_token` (returned
  in the login/`. /auth/me` response body, never a cookie), and every state-changing
  (POST) request made with an active session must echo it back as `X-CSRF-Token` or
  get a 403 — enforced centrally in `do_POST`, a true no-op when RBAC is off or the
  request carries no session cookie at all (pure API-key callers are unaffected).
  Verified end-to-end in a real browser: login → write → reload persists; a wrong
  token 403s; logout invalidates the session and re-locks the app.

### Fixed (adversarial repo-wide bug hunt, post-M4/M5)

A repo-wide (not PR-only) reviewer/bug-hunter pass over the M4/M5 surface, each finding
adversarially verified against the real code path, each fix shipping a regression test
independently confirmed (via a revert/run/restore cycle on the fix's own diff) to fail
without the fix and pass with it restored. Full findings + severity ranking + discarded
false positives are in the review that produced this list; six real bugs were fixed:

- **F1 (HIGH)** — WS-4's stateful window rule counter (`engine.py`) keyed sliding-window
  state only on `f"{rule_id}:{group}"`, with no tenant component. Two tenants sharing a
  `group_by` value (e.g. overlapping RFC1918 IPs — the normal case for an MSP) had their
  event counts pooled in one shared window, letting one tenant's traffic trip another
  tenant's threshold and misattribute the resulting alert — a direct breach of the M4.1
  tenant-isolation guarantee. Fixed by namespacing the counter key on `siem.tenant`.
  **Follow-up caught by a dedicated review of this fix**: `Rule.alert_key()` — which
  computes the actual `alert_id` persisted to storage, separately from the counter key —
  was still unnamespaced, so two tenants firing in the same window bucket on a shared
  `group_by` value got the identical `alert_id` and WS-3's cross-index `find_alert()`
  lookup could return the wrong tenant's doc. Fixed the same way, with the same
  revert/run/restore-verified regression test discipline.
- **F6 (MEDIUM/HIGH)** — `active_directory.py` assigned raw, un-typechecked fields
  (`IpAddress`/`MacAddress`/`TargetUserSid`) straight into OCSF schema-constrained fields,
  unlike every sibling parser, which already goes through `shared/ocsf.py`'s
  `valid_ip`/`valid_mac`/`safe_str` guards. A malformed upstream field silently
  dead-lettered the whole event instead of just dropping the bad field, which can blind
  `common_bruteforce`/`common_password_spray`/`common_lateral_movement` on real AD
  authentication events.
- **F2 (MEDIUM)** — `GET /alerts/{id}/report` only applied the tenant gate when the
  backing alert doc was still present. Once the alert aged out (reports have independent
  retention), the gate was skipped and any authenticated caller could read another
  tenant's incident report. Now fails closed (404) for non-admins when the alert doc is
  absent.
- **F5 (LOW/MEDIUM)** — `LoginRateLimiter` (`rbac.py`) grew its per-username dict without
  bound and had no lock despite being mutated from multiple `ThreadingHTTPServer` handler
  threads — a memory-DoS risk on `/auth/login` plus dropped failure records under
  concurrency. Added a lock around all three methods plus a periodic sweep, mirroring the
  pattern `window.py` already uses for its own counters.
- **F4 (MEDIUM)** — `tools/restore.py` extracted the archive before verifying checksums,
  and its traversal guard only checked each member's *name* — not enough to stop a
  symlink member written "through" by a later member (the CVE-2007-4559 class). Switched
  to `tarfile.extractall(filter="data")` (PEP 706), which rejects symlinks, absolute
  paths, and `..` traversal before anything is written.
- **F3 (MEDIUM)** — `tenant_id` flowed unvalidated into an OpenSearch index name
  (`router.py`) and a `contracts/tenants/<id>.yml` path (`tenants.py`). An uppercase or
  space-containing tenant_id produced an OpenSearch-invalid index name that silently
  dead-lettered every event for that tenant; a path-traversal-shaped tenant_id could
  construct a config path outside `contracts/tenants/`. Added
  `shared/envelope.py::valid_tenant_id()` (DNS-label-style allowlist): `router.py` now
  rejects (never normalizes — normalizing "Acme"/"ACME" to the same slug would silently
  merge two tenants' data) an invalid tenant with a `ValueError` on both the alert and
  event branches; `tenants.py` fails open (no rules disabled, same as a missing config
  file) rather than ever constructing the unsafe path.

New/extended tests: `services/ws3-indexer/test_router.py`, `services/ws4-detection/test_tenants.py`,
`services/ws2-normalization/parsers/test_active_directory.py` (new files), plus extensions to
`tools/test_multi_tenant_isolation.py`, `services/ws3-indexer/test_reporting.py`,
`services/shared/test_rbac.py`, `tools/test_backup_restore.py`.

### Added (v0.5 M1 — correctness gates)

- **Envelope v1**: `schema_version`, `trace_id`, `tenant_id` (formalizes `siem.tenant`, declared since Phase 0 but never wired), documented `event_time`/`ingest_time`/dedup-key semantics. Additive bus-schema change to `contracts/bus-topics.md` + `contracts/ocsf-event.schema.json`, owner-authorized. `services/shared/envelope.py`; wired through all 10 parsers via `base_event(meta=...)` and all 4 live WS-1 collectors.
- **`make chaos`** (`tools/chaos_test.py`): kills each of ws1-ws5 mid-replay across 40 independent brute-force scenarios, asserts zero lost/duplicate alerts. Reviewed, not yet run against live Docker (unavailable in the authoring environment) — do not treat as a passed gate until a real run's output lands in a PR.
- **`docs/degradation-matrix.md`**: every dependency's down-behavior, sourced from the actual fail-open/fail-closed code paths.
- **Hypothesis property tests** (`parsers/test_property_hardening.py`): 100 generated examples per parser, all 10 pass. Found and fixed a real bug: 6 structured-record parsers (db_audit, mcp_agent, n8n_audit, opcua_audit, vmware_vsphere, windows_eventlog) assigned unguarded JSON-field values into schema-constrained `ip`/`mac`/hostname/name fields; `services/shared/ocsf.py` gains `valid_ip`/`valid_mac`/`safe_str` to fix all six.
- **Log-injection defense** (`services/shared/sanitize.py`): strips ANSI escapes (blocks terminal/OSC-52 injection when viewing raw event content) and C0/DEL control chars (blocks newline-based log forging), wired into `normalize_one()` as a new sanitize stage between parse and enrich.
- **atheris fuzz harnesses** for the top 3 parsers by regex complexity (linux_ssh, cisco_asa, windows_eventlog) + nightly CI job (`.github/workflows/fuzz.yml`). Locally spot-verified (millions of executions, zero crashes); full nightly budget runs only once merged to `main`.

### Added (v0.5 M2 — public proof artifacts)

- **`tools/fengarde_bench.py`**: one-command load generator, published real numbers in README (~13,750 EPS / ~84 MB peak RSS, zero-infra baseline — explicitly not a live-stack throughput claim).
- **Code quality floor**: `pyproject.toml` (ruff/black/mypy/coverage config), `.pre-commit-config.yaml`. ruff clean and CI-blocking; black configured but not force-applied (98/100 files would reformat against this codebase's established style — a deliberate, documented, separate decision); mypy informational-only (20 real findings, honest baseline, not a strict gate on a largely-unannotated codebase); coverage gate blocking at measured baseline (WS-2 90%, WS-3 71% — the latter below the ~85% target, documented as an open gap, not silently lowered).
- **ADR backfill** (`docs/adr/001-006`): Redis Streams, OCSF, OpenSearch, microservice split, fail-closed rules, local-first LLM triage.
- **Supply chain**: found and fixed every service's `requirements.txt` being decorative prose, never actually installed from (each Dockerfile hardcoded its own unpinned inline `pip install`). Rewrote all 6 as real pinned manifests, switched Dockerfiles to install from them, dropped two never-imported "extras" (pysnmp, scikit-learn). `.github/dependabot.yml`, `tools/generate_sbom.py` (CycloneDX, CI-blocking freshness check), `.github/workflows/codeql.yml`, `.github/workflows/scorecard.yml`, README badges.

### Added (v0.5 M3 — product completeness)

- **Agent rule pack complete**: R4 (`agent_egress_non_allowlisted_domain.yml`) and R5 (`agent_destructive_command.yml`) join R1-R3, reusing the engine's existing `not_in`/Allowlist mechanism (R4) and single-shot pattern-match (R5, not a burst threshold). All 5 rules proven firing on real `mcp_agent` parser output, including R1+R3 together on one session log (`services/ws4-detection/test_v05_agent_rules.py`).
- **`tools/agent_log_shipper.py`**: the missing real ingestion path for MCP/agent JSONL logs (file, `--follow`, or stdin) into `raw.events` — found while writing the doc below that this didn't exist yet. Proven end-to-end (`tools/test_agent_log_shipper.py`): a JSONL file with one malformed line ships, normalizes, fires R1+R3, and both alerts reach the index.
- **`docs/agent-monitoring.md`**, **`docs/deployment.md`** (reverse-proxy TLS via Caddy, documented not built), **`docs/vs.md`** (honest FENGARDE vs Wazuh/Elastic Security/Security Onion comparison), new-rule issue template.

### Changed — ARGIEM → FENGARDE rebrand

Second rename in two months (ARGUS → ARGIEM landed 2026-07-15, see below). Adopted
while merging the M1-M6 roadmap branch into `main`; branch-local env vars/identifiers
(`FENGARDE_API_KEY`, `FENGARDE_RBAC_DB`) already used the new name before the merge,
`main` did not — this merge is what makes the rename repo-wide. No functional change.

### Fixed / Added (deep-hardening pass — P0+P1+P2, 2026-07-16)

Full audit-and-fix pass across parser logic, the detection engine, and pipeline
robustness, ahead of public launch. Details and evidence in `SSOT.md` §1.

- **P0 (detection-integrity, `9e2745b`)**: window-poisoning (far-future/non-numeric
  `time`) now fails closed instead of collapsing sliding-window counts or crashing
  the daemon; memory-vs-Redis window counters now agree on redelivery dedup; idle
  window keys are evicted (bounded memory); parser registry routing rewritten
  (source_type-authoritative — fixes a bank DB privileged op being silently
  mis-parsed as a vSphere read, meaning `bank_db_priv_esc` could never fire);
  vmware port-crash guard + any raising parser now dead-letters one record instead
  of aborting the batch; out-of-range IP octets are dropped, not dead-lettered;
  `status_from_outcome()` shared helper (vmware/db/n8n no longer hardcode
  `"Success"`, masking failed logins from the brute-force rules); `alert_id` no
  longer collapses distinct no-ingest-id events onto one alert.
- **P1 (robustness, `c84c8f6`/`625f4f8`/`7e354bb`)**: `/health` probes the bus and
  returns 503 when degraded; compose healthchecks on ws1-5; `tools/dlq_peek.py`
  DLQ inspector/requeue tool; OpenSearch `index()` retries transient errors with
  backoff, surfaces 4xx immediately; HTTP servers get read timeouts (slowloris
  guard); dashboard (8080) + inventory (8000) bind to `127.0.0.1` by default
  (syslog 5514 stays open, must receive remote logs); shared `to_epoch_ms()`
  replaces 9 copy-pasted, FILETIME/ISO-mishandling time heuristics; rule tuning
  (service-account allowlist on after-hours-admin, documented brute-force/
  impossible-travel tradeoffs).
- **P2 (enhancements, `b645b13`..`2f807ec`)**: `in`/`contains` grammar operators;
  cross-source severity rubric (`SEV_BY_CATEGORY`) so the same action (e.g.
  delete) gets the same severity regardless of source; `siem.sector` override now
  validated + honored consistently across all 10 parsers; `/metrics` endpoint
  (per-topic acked/failed/deadlettered + ws1 ingest-edge counters); backpressure
  depth-watchdog on internal topics; IPv6 capture in ssh/ASA parsers + full 0-7
  ASA severity map; opt-in live Redis/OpenSearch test lane (`make test-live`);
  anti-dormancy CI gate now checks per-event satisfiability, not just "producible
  somewhere across all fixtures" (catches a rule that's dormant in practice
  because its group_by field is only ever produced by a different class).

### Changed — ARGUS → ARGIEM rebrand (`717f4ed`, 2026-07-15)

Renamed the project after a trademark/domain collision check on the prior name.
239 occurrences across 42 files, GitHub repo renamed (old clone URLs redirect),
`ARGUS_API_KEY` → `ARGIEM_API_KEY`. No functional change.

### Added (v0.4 Track S — opt-in auth)

- **`FENGARDE_API_KEY`** shared-secret auth on the WS-3 triage API and WS-6 inventory API (`X-Api-Key` header, constant-time compare). Unset (default) = every request allowed + a startup warning; set = 401 on missing/wrong key. `services/shared/authz.py` (ws3) + `services/ws6-inventory/authz.py` (ws6 doesn't bundle `shared`, so it gets its own copy).
- **Dashboard basic-auth**, opt-in via `infra/docker-compose.auth.yml` override (nginx `auth_basic` + htpasswd) — not baked into the main compose file, so `docker compose up` stays zero-prerequisite.
- **Redis `AUTH`**, opt-in via `REDIS_PASSWORD`, embedded in `REDIS_URL` for every service.
- Dashboard nginx converted to an envsubst template (`templates/default.conf.template`) so it can inject `X-Api-Key` server-side on the triage proxy — the browser never holds the key.
- OpenSearch/Redis/OpenSearch-Dashboards ports bound to `127.0.0.1` by default (were `0.0.0.0`). OpenSearch's security plugin stays disabled — a documented scope cut, not an oversight (`SECURITY.md` §2).

### Added (v0.4 Track R — incident-report hook)

- **`contracts/reporting.md`** — frozen cross-repo contract with `fengarde-sec`: `POST/GET /alerts/{id}/report` on the WS-3 triage port, `REPORT_BACKEND=template|http` seam, frozen response schema. Hard rules enforced structurally: `status` must be `"draft"`, `disclaimer` mandatory non-empty, `citations` optional (additive-field discipline) — a non-conforming backend response is rejected and WS-3 falls back to the builtin template (fail-open).
- **`services/ws3-indexer/reporting.py`** — generic markdown template renderer (rule/severity/timeline/source/actor/triage state, explicit `[ANALYST MUST PROVIDE]` blocks, zero regulatory claims), HTTP-backend caller + response validator, deterministic `report_id` (idempotent re-generation).
- Dashboard "Rapport" button per alert row; renders the draft as text (never `innerHTML`, same XSS discipline as the rest of the UI).

### Added (v0.4 Track P — niche parser packs)

- **MCP/AI-agent parser** (`mcp_agent`) — tool-call audit logs → OCSF API Activity (6003). Pattern classification (credential-path access, prompt-injection indicators) happens at parse time as documented heuristic booleans (`unmapped.mcp.*`), since the rule engine has no substring-match operator. Three rules: `agent_credential_file_access`, `agent_tool_call_burst`, `agent_prompt_injection_indicator`.
- **OPC UA/OT parser** (`opcua_audit`) — industrial control-system audit events (IEC 62541 Part 5) → OCSF Authentication (session/cert events) + API Activity (write/method-call events). First OT source chosen over S7/PROFINET because Part 5 is publicly documented and fixturable honestly; S7 deferred, named not dropped. Three rules: `ot_write_outside_maintenance` (reuses `outside_hours`), `ot_new_engineering_connection` (distinct source IP per PLC), `ot_config_change`.
- **n8n automation-platform parser** (`n8n_audit`) — workflow/webhook/credential/login events → OCSF. Two rules: `n8n_new_webhook_exposed`, `n8n_workflow_modified_after_hours`.
- **Impossible-travel rule** (`common_impossible_travel`) — the first rule consuming v0.3's A5 geo enrichment (`src_endpoint.location.country`, distinct-count, no engine change needed). `tools/check_rule_producers.py` updated to run each fixture through the real `enrich()` step too, mirroring the actual parse→enrich pipeline — otherwise this rule would have looked dormant by the tool's own standard.

### Fixed

- **Stateful rules pooled unattributable events under a shared "None" group** — an event whose `group_by` field was missing was counted under the literal string `"None"`, pooling unrelated actors toward one threshold (e.g. two sessionless agent streams summing into one burst). Worse, a missing `distinct_field` value diverged across backends: memory counted `None` as one distinct value, Redis turned every None-valued event into a *fresh* distinct member — N unenriched events alone could satisfy any distinct threshold (impossible-travel firing on 2 logins with no geo enrichment). `Rule.evaluate()` now fails closed: no group → no count; no distinct value → no count. Regression tests cover both paths; convention documented in `contracts/sigma-convention.md`.
- **Report route: body not drained on malformed Content-Length** — an unparseable `Content-Length` header on `POST /alerts/{id}/report` was silently zeroed, leaving stray body bytes buffered (keep-alive connection corruption risk). Now a 400, mirroring the triage route.
- **Cross-source rule-scoping bugs** — `agent_tool_call_burst`, `ot_write_outside_maintenance`, and `ot_new_engineering_connection` keyed only on `class_uid`/`activity_id` (or grouped on a field only one source sets). Landing a third `class_uid: 6003` producer (`n8n_audit`) alongside the existing `vmware_vsphere`/`mcp_agent`/`opcua_audit` surfaced the bug: another source's event could silently mis-fire the wrong rule or pool into a shared "None" counter bucket. All three now add an explicit `siem.source_type` selection. `contracts/detection-coverage.md` documents this as a standing lesson for the next shared-class producer — `check_rule_producers.py`'s satisfiability check does not catch this class of bug (it proves a rule *can* fire, not that it fires on the *right* source).

### Added (v0.4 Track D — distribution)

- **`make demo`** banner fixed to reflect reality — `devkit-feeder` already injects a real SSH brute-force burst on every `docker compose up`, but the Makefile still claimed the feeder wasn't built.
- README repositioned to the validated wedge ("the open-source SIEM for the European industrial Mittelstand"), new "Quickstart (10 minutes)" section, capability table refreshed (10 parsers / 17 rules).
- Three architecture write-ups (`docs/posts/ocsf-native.md`, `opensearch-not-elastic.md`, `local-ai-triage.md`) + a launch checklist (`docs/posts/launch-checklist.md`).

## [0.3.0] - 2026-07-10

### Added

- **DB-audit parser** (`db_audit`) — vendor-agnostic database audit logs → OCSF Datastore Activity (6005), activity_id 5 for GRANT/REVOKE/ALTER. Un-dormants the `bank_db_priv_esc` rule, which matched a class no parser emitted.
- **Windows account-change coverage** — `windows_eventlog` parser extended to EventIDs 4720/4722/4726/4728/4732 (Account Change, class 3003), with acting admin in `actor.user` and target account in `unmapped.target_user`.
- **Password-spray rule** (`common_password_spray.yml`) — one account failing auth from ≥8 distinct source IPs (inverse of brute-force).
- **Privileged-group grant rule** (`common_priv_grant.yml`) — single-shot on Account Change activity 5.
- **After-hours privileged-logon rule** (`common_after_hours_admin.yml`) — Windows 4672 special-privilege assignment (class 1002 activity 2) outside a configurable business-hours window.
- **Rule grammar: comparison operators + allowlists + time-of-day** — `gt/gte/lt/lte/ne` operators, a `not_in: <allowlist>` suppression clause (`contracts/allowlists/*.yml`, CIDR + exact match), and an `outside_hours` time-of-day/day-of-week predicate (with `tz_offset_minutes` and midnight-wrapping windows) in the boolean evaluator. Operators fail closed on malformed input; a missing/malformed allowlist *file* fails open on the rule (keeps firing) but closed on suppression (never suppresses). Grammar documented in `contracts/sigma-convention.md`.
- **Rule prefilter** — the detector buckets rules by their `class_uid` equality selection and only evaluates candidate rules per event, replacing the O(rules×events) linear scan. Alert-firing behavior verified byte-identical before/after.
- **Anti-dormancy guardrail** (`tools/check_rule_producers.py`, in `run_all_tests.sh`) — proves each rule's equality selections/`group_by`/`distinct_field` are satisfiable by an actual (path, value) pair some registered parser emits against a real fixture.
- **Detection coverage map** (`contracts/detection-coverage.md`) — ground truth of OCSF classes emitted by shipped parsers vs. rule coverage.
- **Triage workflow (v0.3 C1)** — status + analyst note per alert: new WS-3 triage HTTP API (`GET/POST /alerts/{id}/triage`, `TRIAGE_PORT` default 8013), `find_alert()` cross-index lookup in both storage backends, dashboard status dropdown + note field wired via a same-origin `/api/triage` nginx path. Triage field is OCSF-additive with tolerant-reader defaults.
- **RedisBus test parity** — `services/shared/test_runner.py` parametrized so the full MemoryBus behavioral suite also runs against RedisBus in CI's redis-integration job.

### Fixed

- **Prefilter mis-bucketing of multi-class rules** — the detector bucketed a rule under the *first* selection's `class_uid`, so a rule spanning classes (e.g. `(class 3002) OR (class 4001)`) was never evaluated for the second class's events: a silent missed detection. Bucketing now probes the condition with the real T4 parser and only buckets under X when class X is provably *necessary* for any match (`a and b` with classless `b` stays bucketed; `a or b`, multi-class OR, and negations fall back to the always-evaluated catch-all). All 8 shipped rules keep their exact buckets — no shipped rule was affected; the bug bit only contributor-style multi-class rules.
- **Triage API lost-update race (single-replica)** — concurrent `POST /alerts/{id}/triage` to the same alert could silently drop one update: the read-modify-write over `ThreadingHTTPServer`'s one-thread-per-request model had no lock. Serialized the critical section with a process-wide write lock (triage writes are rare/cheap; GETs and writes to other alerts are unaffected).
- **Triage API lost-update race (multi-replica)** — an in-process lock can't serialize two *separate* ws3 replicas racing on a shared OpenSearch cluster. Added a second OCC layer: `find_alert_versioned()` retrieves `_seq_no`/`_primary_term` from OpenSearch; `index_cas()` writes with `?if_seq_no=N&if_primary_term=M` — a stale write gets HTTP 409 → the retry loop re-reads the fresh doc and re-applies (bounded at `_CAS_MAX_RETRIES=5`; exhaustion surfaces as an honest 409 to the client, never a silent drop). CAS wire format unit-tested via fake transport (`test_storage_cas.py`); MemoryStore gets a matching real version counter so tests and single-replica use the same interface.
- **Triage API note-clearing bug** — a status-only update unconditionally overwrote `note` to `""`, silently wiping an existing analyst note. `note` is now a true partial update: absent from the body → preserved; present as `""` → deliberately cleared (a distinct, intentional action).
- **WS-6 inventory upsert race** — the `SELECT`-then-`INSERT` in `InventoryStore.upsert` was not atomic; two concurrent observations of the same new MAC both saw no row and both inserted, the second hitting the primary key with an `IntegrityError` surfaced as a 500. Serialized the read-modify-write with an in-process lock (concurrency regression test added).
- Dashboard `renderGlobal()` called async `getAlerts()` without `await`, so live-alert rendering operated on a Promise and threw in the browser — silently broken since live alerts shipped.
- `storage/opensearch.py` used `urllib.parse.quote()` without importing `urllib.parse` — the first real OpenSearch `index()` call would have raised `AttributeError`.
- `storage/opensearch.py::find_alert()` returned an empty dict on a hit with missing/empty `_source`; a triage update on such a hit re-indexed only the triage field and wiped the alert's original fields. Now returns `None` (treated as not-found).
- Runner worker called `bus.consume()` with the default 5 s Redis `block_ms`, leaving it deaf to a shutdown set mid-block so `serve()`'s worker join could time out (CI `redis-integration` hang). Now bounded by a `consume_block_ms` (default 1 s) so shutdown latency stays under the join timeout.

### CI

- Added `.gitleaks.toml` allowlisting canonical-UUID values so rule/entity identifiers (`contracts/rules/*.yml` ids and their test constants) don't trip the `generic-api-key` heuristic. Default ruleset otherwise unchanged; real (non-UUID-shaped) secrets are still detected.

### Added (v0.3 A5 — event enrichment)

- **Offline event enrichment** (`services/ws2-normalization/enrichment/`) — a WS-2 post-normalize stage that adds OCSF-additive context to events from local data files only (no external calls; air-gap-safe): `src_endpoint.reputation` (score + categories) from a local IOC list (`contracts/enrichment/ioc.yml`, exact-IP and CIDR, longest-prefix match) and `src_endpoint.location` (country) from a local CIDR→country map (`contracts/enrichment/geoip.yml`, a lightweight stand-in for a full GeoIP DB, with `INTERNAL` tagging for RFC1918). Additive and fail-open: it never overwrites a parser-set field, and a missing/malformed data file, bad IP, or any error leaves the event untouched and flowing — nothing hard-depends on these fields (tolerant readers). Enriched events still validate against Contract A. Wired into `normalize_one` (parse → enrich → validate). Enriched fields added to the OpenSearch event mappings (common/bank/dc) so they're queryable. Unblocks reputation- and geo-keyed detection rules (a follow-up; no rule consumes these fields yet, so alert behavior is unchanged). 12 unit tests.

### Added (v0.3 B4 — rule validation gate)

- **`tools/validate_rules.py`** — a contributor-facing static validator for `contracts/rules/*.yml`, wired into `run_all_tests.sh`/CI. Reuses the real WS-4 engine's tokenizer/parser and operator set (so "valid" means exactly "the runtime will evaluate this") to check: schema (title, canonical-UUID id, level enum, `siem.score_weight` bounds, stateful window/threshold pairing), that the `condition` parses under the T4 evaluator and references only defined selections, that every selection operator is one the engine implements (unknown operators rejected, not silently fail-closed at runtime), that `not_in` allowlists and `outside_hours` windows are well-formed and reference existing files, and that rule ids are unique. Complements the anti-dormancy `check_rule_producers.py`. 20 unit tests (`tools/test_validate_rules.py`) — every check has an adversarial reject case.

### Added (v0.3 B2 — backpressure)

- **Ingest-edge shedding** — `SyslogUDPServer` now sheds excess datagrams via a token bucket (`SYSLOG_MAX_EVENTS_PER_SEC`, default 2000/s) before they ever reach the bus, rather than letting an unbounded flood grow the Redis stream toward OOM. UDP is connectionless, so shedding (not blocking) is the only lever at this edge; the shed-warning log is itself throttled to 1/sec so a flood can't become a logging DoS.
- **Stream-depth monitoring** — `Bus.depth(topic)` on both backends; `services/ws1-collectors/main.py` runs a background watchdog logging a warning when `raw.events` depth crosses `RAW_EVENTS_DEPTH_WARN` (default 100000). Monitoring-only — the hard cap is the ingest-edge shedding above, not this watchdog.
- No mid-pipeline `MAXLEN` trimming was added or is planned — trimming would silently drop unconsumed events, an audit-completeness violation for a bank.
- **Zero-loss-under-flood fallback (opt-in)** — `services/ws1-collectors/collectors/spool.py`'s `BoundedSpool`: a FIFO, byte-capped, disk-backed JSONL queue. A shed or produce-failed datagram is spooled instead of lost when `SYSLOG_SPOOL_PATH` is set (`SYSLOG_SPOOL_MAX_BYTES`, default 64 MiB); a background thread replays it into the bus in order once capacity/connectivity returns. Still bounded — once the spool itself is full, the event is truly lost, but distinctly counted (`events_lost`) rather than silently merged into the plain shed counter. Disabled by default.

## [0.2.0] - 2026-07-01

### Added

- **Generic syslog parser** (`generic_syslog`) — RFC 3164 syslog lines (with or without `<PRI>`) → OCSF, with PRI-severity mapping. Covers sources that don't match a product-specific parser.
- **Windows Event Log parser** (`windows_eventlog`) — broad coverage of security-relevant EventIDs (4624 logon, 4634/4647 logoff, 4688 process creation, 4672 special privileges) → OCSF. Complements the existing Active Directory 4625 parser without overlap.
- **Port-scan detection rule** — fires when one source IP hits ≥15 distinct DENIED destination ports within 60s (OCSF Network Activity, activity_id 6). Restricted to denies for precision; open-port scans are intentionally out of scope.
- **Lateral-movement detection rule** — fires when one account successfully authenticates to ≥5 distinct destination hosts within 300s.
- **Distinct-count windowing** — new `hit_distinct()` on both the deque (single-replica) and Redis (multi-replica, sorted-set) window counters, so rules can threshold on the number of *distinct* field values in a window, not just the event count. Rules opt in via `siem.distinct_field` in YAML.
- **Real local-LLM triage (Ollama)** — WS-5 now calls a local Ollama model (`OLLAMA_URL`/`OLLAMA_MODEL`) for alert triage, returning a structured verdict, and degrades gracefully to the passthrough stub when Ollama is unset, unreachable, or returns malformed output. The acceptance test still runs stub-only with zero infra.
- **Real syslog UDP listener (WS-1)** — collectors now accept live syslog datagrams (`SYSLOG_UDP_HOST`/`SYSLOG_UDP_PORT`, default `0.0.0.0:5514`, now published in `docker-compose.yml`) and feed them into `raw.events` for the generic syslog parser, alongside the existing mock collection path.

### Fixed

- Windows parser mapped the logon source and destination host to the same field, leaving the lateral-movement rule unable to ever fire on real data; auth events now correctly split `src_endpoint` (logon origin) from `dst_endpoint.hostname` (target host).
- Cisco ASA parser dropped both endpoints on `denied from IP/port to IP/port`-style deny messages (106001/106006/106015), making the port-scan rule blind to that message family; endpoint extraction now covers `src/dst`, `for/to`, and `from/to` syntaxes.

### Security

- Documented the two new v0.2 attack surfaces in `SECURITY.md`: the syslog UDP listener is unauthenticated/spoofable by protocol design (keep it on a trusted network segment), and LLM triage output is advisory and enum-constrained but not immune to prompt injection.
- Capped the Ollama HTTP response read at 1 MiB to bound memory use against a runaway/hostile local response.

### Verified live (2026-07-01)

Full Docker stack (Docker Desktop 4.80.0 / engine 29.6.1): a real UDP syslog packet sent from the host to the newly-published `5514/udp` port was received by the container's live listener and indexed; 15 Cisco ASA denies to distinct ports fired the port-scan rule; 5 Windows 4624 logons to distinct hosts fired the lateral-movement rule; the existing brute-force rule fired unaffected. All three produced a rule alert AND a WS-5 AI triage verdict (`StubLLM`, since no `OLLAMA_URL` was configured for this run — confirming the documented fallback path), and all three rendered live in the dashboard via `GET /api/alerts`.

## [0.1.0] - 2026-06-30

### Added

- **Full detection pipeline** — end-to-end flow: collect → normalize (OCSF) → detect → index → dashboard. Every stage is independently testable and wired together in a single `docker compose up`.

- **4 log source parsers** — Linux SSH (`/var/log/auth.log`), Cisco ASA syslog, Windows Active Directory EventID 4625 (failed logon), and VMware vSphere. Each parser emits a typed OCSF `Authentication` event.

- **Brute-force detection rule** — fires when a single IP accumulates 10 failed authentications within a 60-second window. Threshold and window are YAML-configurable; no code change required to tune sensitivity.

- **Contract-first architecture** — 7 machine-readable contracts (OCSF event schemas, OpenAPI specs for internal HTTP surfaces, Sigma rule schema) committed alongside code. Contracts are the source of truth; implementations are verified against them in CI.

- **Shared message bus abstraction** — a single `Bus` interface with two concrete backends: an in-memory implementation for unit and acceptance tests (zero infrastructure), and a Redis Streams implementation for production. Services never import a backend directly.

- **Shared runner** — common event-loop component used by every service. Provides ack-after-handler semantics, configurable redelivery on failure, a dead-letter queue for poison messages, and a `/health` HTTP endpoint that CI and Docker health checks hit.

- **Deterministic alert IDs (T7)** — alert IDs are derived from a stable hash of the triggering evidence. Re-processing the same log stream produces identical IDs, making the pipeline idempotent under at-least-once delivery.

- **Global window counter (T6)** — sliding-window counts are stored in Redis sorted sets (`ZCOUNT`). All replicas share a single counter, so horizontal scaling does not split detection windows or cause missed alerts.

- **Zero-infrastructure acceptance test (`make e2e`)** — the full pipeline (parse → detect → index) runs in-process with the in-memory bus. No Docker, no Redis, no OpenSearch required locally. The same test is the CI gate.

- **Live dashboard** — a browser-based UI served by nginx, which also acts as a reverse proxy to OpenSearch. No CORS configuration needed; the browser talks only to nginx.

- **Auto-feeder (devkit-feeder)** — a companion container that injects a synthetic brute-force log sequence on `docker compose up`. A real alert appears in the dashboard within seconds of the stack starting, with no manual curl commands.

- **Secret scanning in CI** — gitleaks runs on every push and pull request. Any credential committed by mistake blocks the build before it reaches reviewers.

- **Apache-2.0 license** — permissive license; use in commercial products, fork freely.

[Unreleased]: https://github.com/supermhel/argiem/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/supermhel/argiem/releases/tag/v0.1.0
