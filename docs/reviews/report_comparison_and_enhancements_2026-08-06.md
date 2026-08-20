# FENGARDE — Report Comparison & Enhancement Roadmap

**Date:** 2026-08-06 · **HEAD:** `d701c2f`

---

## Part 1: Report Comparison — Prior Swarm vs My Independent Audit

### Methodology Differences

| Aspect | Prior Swarm (`swarm_review_report.md`) | My Audit (2 reports) |
|---|---|---|
| Subagents | 5 swarms, result summaries verified by orchestrator | 5 swarms dispatched in background + independent solo code reading |
| Docker live tests | None mentioned | Brought up full Docker stack, verified pipeline producing real alerts |
| CI/CD audit | Brief (4 HIGHs in code-quality section) | Dedicated full report: all 4 workflows, per-job grades, 16 checks |
| Verification depth | "Every flagship finding independently re-verified" | Same — file:line on both sides for all CRITICAL/HIGH |
| Empirical repro | Referenced by swarms | Attempted poison-pill inside container (blocked by path issue) |

### Severity Alignment

**10 core findings fully agree** (same finding, same or close severity):
- C1 (HA env-gate), H1 (poison-pill), H2 (GRANT SELECT), H3 (default-open), H6 (OpenSearch single-node), H7 (Redis CI-untested), H8 (coverage gaps), H9 (devkit-feeder)
- The medium findings on class_uid, not_in, LLM flood, Sigma, .lower() crash, time bypass, timeutil drift, racy counters, mypy, `|| true` all overlap

**4 severity disagreements:**

| Finding | Prior | Mine | Reasoning |
|---|---|---|---|
| Webhook redirect-following (SSRF) | MEDIUM | HIGH | Contradicts SECURITY.md's "No SSRF" claim — a doc overstatement is worse than a silent bug because operators trust the doc |
| Unsigned Redis sessions | MEDIUM | HIGH | SECURITY.md calls this a "security boundary" — a claimed boundary that isn't cryptographically enforced is a HIGH gap |
| Sanitize `unmapped.*` gap | MEDIUM | LOW | Blast radius bounded: LLM verdict enum-clamped + advisory-only. Input still reaches a human-readable log, not an execution path |
| Empty allowlists on shipped rules | MEDIUM | LOW | Documented as "live" noise, not a detection hole. Operator can populate allowlists; rules still fire correctly |

**4 findings the prior report caught that I missed:**
- Redis failover loses acked-but-unreplicated tail (no WAITAOF/MIN-REPLICAS) — I mentioned in passing, prior rated HIGH. Fair. ⚠️
- `not_in` allowlist fail-posture documented backwards (code says fail-closed, actually fail-open)
- Shipped rules with empty allowlists
- UDP ingest_id random UUID → deterministic dedup dead code

**10 net-new findings my swarm subagents found (beyond prior report):**
- Grafana default `admin`/`admin` password — undocumented in SECURITY.md (HIGH)
- linux_ssh IPv4-mapped IPv6 → dead-letter auth events (HIGH)
- inventory_diff epoch-seconds treated as ms (1000× off) (HIGH)
- VM.Undeploy misclassified as Create in vmware_vsphere (MEDIUM)
- OPC UA dotted eventType routing ambiguity (MEDIUM)
- `FENGARDE_API_KEY_PEPPER` defaults empty (MEDIUM)
- inventory_diff hostname unguarded → schema violation (MEDIUM)
- No API rate limiting on endpoints (LOW)
- `LoginRateLimiter` in-memory only (LOW)
- Webhook secrets from environment variables (LOW)

### What My Work Added That Neither Prior Report Had

1. **GitHub Actions / CI-CD audit** — 16 distinct checks across all 4 workflows, per-job grades, supply-chain maturity table, Scorecard/CodeQL/Dependabot analysis
2. **Docker live bring-up** — Real `docker compose up` with Redis PONG, OpenSearch health check, pipeline producing actual alerts
3. **Per-workflow CI grades** — `verify_action_pins.py` rated A+ (best-in-repo), actionlint coverage, SBOM freshness gate analysis
4. **CI/CD maturity comparison** — FENGARDE vs industry OSS median across 10 capabilities
5. **Broadened coverage** — 28 findings vs prior 23 (excluding INFOs), across more dimensions

---

## Part 2: Enhancement Possibilities — Security, Observability, Administration, UX

This section reviews what FENGARDE **could** add — forward-looking capabilities, not audit findings.

### Security Enhancements

#### S1: Refuse-to-start-without-credentials mode
**Current:** `authz.py:23-25` — unset `FENGARDE_API_KEY` → every request allowed, one warning.
**Gap:** `docker compose up` ships fully open. No enforcement.
**Enhancement:** `FENGARDE_REQUIRE_AUTH=1` — refuses startup if no API key, no RBAC DB, no Redis AUTH configured. Production deployments get a hard gate instead of a warning. Documented as opt-in (preserves zero-prereq quickstart).

#### S2: Redis session signing
**Current:** `sessions.py:132-143` — raw `HGETALL`, no server-side signature. Anyone who writes Redis forges sessions.
**Enhancement:** HMAC the session data with a server-side secret (`FENGARDE_SESSION_SECRET`). Store `data + signature` in Redis hash. `resolve()` verifies signature before returning. A Redis write without the secret can't forge a valid session. ~20 lines of code.

#### S3: Webhook redirect filter
**Current:** `webhooks.py:156` — `urlopen()` follows 30x by default.
**Enhancement:** Build a custom `OpenerDirector` without `HTTPRedirectHandler`. Or: resolve the initial URL, verify the host matches after each redirect. Same for `reporting.py:128` and `llm_adapter.py:150,173`.

#### S4: TLS between services (mutual TLS)
**Current:** All inter-service traffic is plaintext HTTP on the compose network. Documented as "TLS at reverse proxy only."
**Enhancement:** Add opt-in mTLS profile (`docker-compose.tls.yml`). Each service gets a cert. Shared `ca.crt` in the compose network. Small surface area (only 3 inter-service HTTP calls: ws3→OpenSearch, ws5→Ollama, ws7→ws3).

#### S5: Audit log for admin actions
**Current:** No record of who triaged what, who changed a rule, who provisioned a key.
**Enhancement:** `services/ws3-indexer/audit.py` — writes `audit.events` stream entries for: triage status changes, report generation, login/logout, key provisioning/revocation. Immutable append-only log. Queryable via API. Critical for MSSP compliance (who accessed which tenant's data?).

#### S6: MFA/TOTP for dashboard login
**Current:** Password-only auth via `FENGARDE_RBAC_DB`. Single factor.
**Enhancement:** Add TOTP as opt-in second factor. `users.py` gains `totp_secret` column. `POST /auth/login` accepts optional `totp_code`. Standard `pyotp` library (stdlib `hashlib` fallback possible). Per-user opt-in, not forced.

#### S7: Encrypted spool at rest
**Current:** `SYSLOG_SPOOL_PATH` JSONL is cleartext. Documented in SECURITY.md §8.
**Enhancement:** AES-256-GCM encrypt each spool entry with a key derived from `FENGARDE_SPOOL_KEY`. `BoundedSpool.append()` encrypts; replay decrypts. No key → spool is opaque. Small surface (one class, ~30 lines).

---

### Observability Enhancements

#### O1: OpenTelemetry tracing
**Current:** Prometheus metrics only (counters). No distributed tracing.
**Enhancement:** Add `opentelemetry-api` + `opentelemetry-exporter-otlp` as optional deps. Each service creates spans: `raw.events → normalize → index → detect → alert`. Trace context propagated via Redis Streams message headers. Single trace ID follows one syslog line through 5 services. Jaeger/Grafana Tempo as opt-in compose profile.

#### O2: Alert pipeline health dashboard
**Current:** Grafana dashboard shows throughput/DLQ depth. `rule_health_metrics()` exists but not live-verified in Grafana.
**Enhancement:** Complete the rule-health pipeline: verify `rule_last_fired` timestamps in Grafana, add per-rule firing rate, add "rules silent for >X hours" alert. The data is already collected; the panel just needs live verification.

#### O3: Detection coverage gap alerting
**Current:** `eval/attack/coverage_layer.py` builds ATT&CK Navigator layers. Manual inspection only.
**Enhancement:** Scheduled `check_rule_producers.py` run that POSTs to a `/metrics/coverage` endpoint. Grafana panel shows: techniques covered vs uncovered, rules with no recent fires. Operator knows their actual detection surface without running CLI tools.

#### O4: Syslog ingest metrics by source
**Current:** Aggregate counters (`events_produced`, `events_shed`, `events_dropped`). No per-source breakdown.
**Enhancement:** `SyslogUDPServer` tracks counters per source IP (bounded map, LRU eviction). Prometheus labels: `{source="10.0.1.5"}`. Operator sees which firewall stopped sending, which DC is flooding, which source is 100% shed.

#### O5: Alert volume anomaly detection
**Current:** Rules fire independently. No "this rule usually fires 3×/hour, now it's 300×/hour."
**Enhancement:** `Scorer` or a new `AnomalyDetector` tracks per-rule firing rate baseline (EMA). Alerts when a rule's rate exceeds 3σ of baseline. Catches: parser regression (rule suddenly silent), attack wave (rule suddenly hot), config change (rule suddenly noisy).

---

### Administration Enhancements

#### A1: Admin UI (rule/parser/tenant management)
**Current:** All administration is CLI-only: `manage_keys.py`, `validate_rules.py`, `backup.py`, `restore.py`, `migrate_opensearch.py`.
**Enhancement:** Add `/admin` routes to WS-3 (gated behind `role=admin`): list/enable/disable rules per tenant, view parser health, provision/revoke API keys, view audit log, trigger backup. The dashboard already has auth; extend it with admin panels. Single-page additions to `index.html`.

#### A2: Rule hot-reload via API (not just mtime poll)
**Current:** `RULES_RELOAD_INTERVAL_S` polls filesystem. Not wired for Docker (contracts baked into image).
**Enhancement:** `POST /admin/rules/reload` — triggers `Detector.reload()` via HTTP. Allows rules to be volume-mounted and reloaded without restart. Validate first (fail-closed: malformed rule → old rules kept, 400 response with error details).

#### A3: Tenant provisioning wizard
**Current:** Tenant setup requires hand-editing `FENGARDE_API_KEYS`, `contracts/tenants/*.yml`, running `manage_keys.py provision`.
**Enhancement:** `POST /admin/tenants` — creates tenant directory, provisions API key, creates RBAC user, creates tenant-scoped index template. Single API call or admin UI button. Returns: tenant_id, API key (shown once), admin credentials. ~200 lines.

#### A4: Scheduled backup with retention
**Current:** `tools/backup.py` + `tools/restore.py` are manual CLI tools.
**Enhancement:** Cron-scheduled backup service. `services/ws-admin/backup_scheduler.py` — runs `backup.py` on schedule, retains last N backups, prunes old ones. Backup to S3-compatible storage (MinIO in compose, or real S3). Status on `/health`.

#### A5: Rule import marketplace / SigmaHQ integration
**Current:** `tools/import_sigma_rules.py` does basic partial translation. Honest scope: "maybe 10-20% of real SigmaHQ constructs."
**Enhancement:** Extend the Sigma importer to cover: additional modifiers (`base64`, `utf16le`, `windash`), field references, `1 of them`/`all of sel*` aggregation, `near` temporal operator. Target: 60-80% of SigmaHQ rules importable with explicit warnings on the rest (not silent narrowing).

#### A6: Fleet management (multi-node deployment)
**Current:** Single-host Docker compose. HA profile is multi-container on one host.
**Enhancement:** Add a lightweight agent/collector that ships logs from remote hosts to the central bus. `fengarde-agent` — a single binary (Python or Go) that tails files, parses syslog, and produces to a remote Redis Streams bus. TLS between agent and bus. This is the "edge tier" of the 3-tier topology in the roadmap.

---

### User / UX Enhancements

#### U1: Alert correlation view
**Current:** Each rule fires independently. No "these 5 alerts are the same attacker" view. SSOT calls this the top remaining gap.
**Enhancement:** `GET /api/v1/alerts?actor=alice&src_ip=10.0.0.5` already exists. Build the UI: click an alert → "Show related" → lists all alerts for same actor/src_ip/dst_ip across time. Timeline visualization. Low-effort (backend already supports it), high analyst value.

#### U2: Alert lifecycle / playbooks
**Current:** Triage supports `status` (new/confirmed/false_positive) + `note`. No workflow.
**Enhancement:** Add status transitions: `new → investigating → contained → closed`. Add `playbook` field on rules — a markdown string shown to the analyst when the alert fires. E.g. brute-force alert shows: "1. Verify source IP in VPN logs. 2. Check if account is locked. 3. If confirmed, block IP at firewall." Rules carry operational knowledge.

#### U3: Saved searches / alert filters
**Current:** Dashboard shows all alerts, sorted by time. No persistent filters.
**Enhancement:** `GET /api/v1/alerts?severity=critical&status=new&rule_id=common_bruteforce` already works. Add "Save filter" button that stores the query in localStorage. Dashboard shows named saved searches. Analyst's personal watchlist.

#### U4: Dark mode + accessibility
**Current:** Dashboard is light-theme only, no accessibility attributes.
**Enhancement:** Add CSS custom properties for dark theme. `prefers-color-scheme: dark` media query. `aria-label` attributes on interactive elements. Keyboard navigation for triage actions. ~50 lines of CSS + a few HTML attributes.

#### U5: Mobile-responsive dashboard
**Current:** Dashboard is desktop-only layout.
**Enhancement:** CSS flexbox/grid with mobile breakpoints. Alert list stacks vertically. Triage actions become swipeable. Filter bar collapses to hamburger. Same HTML, just responsive CSS. Target: usable on a phone for on-call responders.

#### U6: Alert sound / desktop notification
**Current:** No audio or notification for new alerts.
**Enhancement:** Browser Notification API: `new Notification("FENGARDE: Critical alert", {body: "Brute-force from 10.0.0.5"})`. Opt-in per severity. Audio `ping` for critical. 10 lines of JS.

#### U7: Natural-language alert search
**Current:** API supports structured queries (`?actor=&src_ip=&severity=`). No free-text.
**Enhancement:** `GET /api/v1/alerts?q=admin+login+failed` — full-text search across alert fields using OpenSearch's built-in query-string search. Dashboard search bar. Backend: add a `q` parameter that builds an OpenSearch `query_string` query.

---

### Prioritized Enhancement Roadmap

Sorted by impact-to-effort ratio (highest ROI first):

| # | Enhancement | Effort | Impact | Category |
|---|---|---|---|---|
| 1 | Webhook redirect filter (S3) | 5 lines | Closes SSRF doc gap | Security |
| 2 | Redis session signing (S2) | 20 lines | Closes forgeable-session gap | Security |
| 3 | Refuse-to-start-without-credentials (S1) | 30 lines | Closes default-open risk | Security |
| 4 | Alert correlation view (U1) | Backend exists, UI only | Top analyst-requested feature | UX |
| 5 | Alert lifecycle + playbooks (U2) | ~100 lines | Operational maturity | UX |
| 6 | Saved searches (U3) | ~50 lines JS | Daily analyst workflow | UX |
| 7 | Admin UI (A1) | ~300 lines | Operator self-service | Admin |
| 8 | Audit log (S5) | ~150 lines | MSSP compliance requirement | Security |
| 9 | Grafana rule-health verification (O2) | Config only | Completes existing work | Observability |
| 10 | Rule hot-reload via API (A2) | ~40 lines | Closes Docker blind spot | Admin |
| 11 | Tenant provisioning wizard (A3) | ~200 lines | MSP onboarding | Admin |
| 12 | SigmaHQ import coverage (A5) | ~500 lines | Community adoption | Admin |
| 13 | Dark mode + accessibility (U4) | ~50 lines CSS | Broadens user base | UX |
| 14 | Desktop notifications (U6) | 10 lines JS | On-call responsiveness | UX |
| 15 | Per-source syslog metrics (O4) | ~80 lines | Operations visibility | Observability |
| 16 | OpenTelemetry tracing (O1) | ~300 lines + deps | Production debugging | Observability |
| 17 | Encrypted spool (S7) | ~30 lines | Data-at-rest compliance | Security |
| 18 | MFA/TOTP (S6) | ~100 lines + dep | Auth hardening | Security |
| 19 | Fleet agent (A6) | ~1000 lines | 3-tier topology | Admin |
| 20 | Scheduled backup (A4) | ~200 lines | Disaster recovery | Admin |

---

### What NOT to Build (or defer strongly)

- **Real-time WebSocket/SSE push** — polling every 10s is fine for a local SIEM. Adding a WebSocket server creates a new failure mode for negligible UX gain at this scale.
- **Elasticsearch backend** — ADR-003 already decided OpenSearch. Maintaining two storage backends doubles the test matrix for no architectural reason.
- **Kafka bus** — `contracts/bus-topics.md` already corrected this. Redis Streams is sufficient. Kafka adds operational complexity (ZooKeeper/KRaft, topic management) that contradicts the "single-host quickstart" value proposition.
- **Full SigmaHQ rule pack** — The import tool should improve, but shipping 1000+ community rules as defaults would create a false-positive flood that drowns the operator. Let the importer be a tool; don't bundle rules the project can't tune.

---

*Analysis performed 2026-08-06. Based on full codebase audit at `d701c2f`.*