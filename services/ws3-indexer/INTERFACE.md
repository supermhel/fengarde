# WS-3 Indexer — Interface Declaration

## Consumes
- Topics `normalized.events`, `scored.events`, `alerts`, `ai.results`,
  `incidents`, `entity.updates`, `incident.graph` (group `cg-index`). The
  last two are Phase 5 (2026-09-04) — see `contracts/bus-topics.md`, both
  existed on the bus since Phase 2/3 with WS-3 only reaper-trimming the
  stream, no real consumer, until this.
- Contracts: A (events), E (index templates / ILM), B (bus).

## Produces
- Writes to OpenSearch indices: `events-{bank|dc|common}-YYYY.MM.DD`,
  `alerts-YYYY.MM.DD` for the default tenant. A non-default `siem.tenant` (M4.1
  multi-tenancy) gets its own index per family: `events-{family}-{tenant}-
  YYYY.MM.DD`, `alerts-{tenant}-YYYY.MM.DD` (`router.py`, `tenant_id` validated
  and rejected — never normalized — before it reaches an index name).
- The other families (`router.py` `route()`): `incidents-YYYY.MM.DD` /
  `incidents-{tenant}-YYYY.MM.DD` (WS-8 incidents, dated by `first_seen`),
  and two flat, non-date-suffixed stores, `entities` / `entities-{tenant}`
  (WS-9 `entity.updates`) and `incident-graphs` / `incident-graphs-{tenant}`
  (WS-8 `incident.graph`). Generated reports (alert and incident) are written
  by the triage API to `reports-YYYY.MM.DD` (`reporting._report_index()`),
  pre-created at startup.

## Triage API — HTTP, separate listener (grown well past v0.3 C1; refreshed 2026-07-21)
- `TRIAGE_PORT` (default `8013`), on its own thread alongside the bus consumer.
- `GET /alerts/{id}/triage` → current `{status, note, updated_at}` (defaults to
  `status: "new"` for an alert with no triage yet — tolerant reader).
- `POST /alerts/{id}/triage` → `{status?, note?}`; partial update (an omitted field
  is preserved), status enum-validated, note length + body size capped,
  concurrent writes to one alert serialized (in-process) + OpenSearch optimistic
  concurrency (`find_alert_versioned`/`index_cas`) across replicas. Adds an
  OCSF-additive `triage` field to the existing alert doc.
- `GET/POST /alerts/{id}/report` (v0.4 Track R) — existing draft report, or
  generate one (`?template=nis2` for the M5 German/English NIS2 generator,
  otherwise the generic markdown backend). Every report is `status: "draft"` with
  a mandatory disclaimer.
- `GET /incidents` — newest-first (by `last_seen`) correlated-incident listing
  (WS-8 incidents), same bounded/filtered convention as `GET /alerts`.
- `GET /entities/{id}` (Phase 5, 2026-09-04) — a WS-9-resolved entity's
  current canonical state (`entity.updates` topic, indexed).
- `GET /incidents/{id}/graph` (Phase 5) — the typed causal DAG WS-8 emitted
  for this incident (`incident.graph` v2, indexed).
- `GET /incidents/{id}/evidence` (Phase 5) — builds, hash-verifies, and
  serves this incident's evidence package on demand
  (`evidence_package.py`'s first real HTTP consumer); 409 (never a silent
  200) if a freshly-built package fails `verify_evidence_package()`.
- `POST /incidents/{id}/report` — builds and verifies the incident's evidence
  package, then renders and stores an incident-level draft report from it
  (`route_post_incident_report`; the same draft/disclaimer rules as the alert report).
- `/api/v1/...` (M4.3) — versioned aliases for every route above (`/alerts`,
  `/incidents`, `/events`, `/rules`, `/audit`, `/auth/*`, the entity/graph/evidence
  and admin routes), alongside the unchanged bare paths. Spec-vs-code drift is
  CI-tested against `contracts/triage-api.yaml`.
- `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` (M4.2, RBAC — see
  Auth below) — session cookie + `csrf_token`. Every session-authenticated
  `POST` (including `/alerts/{id}/triage` and `/alerts/{id}/report`) must echo
  the token back as `X-CSRF-Token` or gets 403.
- `POST /auth/mfa/enable`, `POST /auth/mfa/verify` (E3, 2026-08-06, opt-in
  per-user TOTP) — both require the acting user's own current password in
  the body (session cookie alone is not sufficient to touch MFA config),
  rate-limited separately from login lockout, every outcome audited.
- `GET /audit` (E1, 2026-08-06, admin-only) — recent entries from the
  append-only, capacity-capped, fail-open audit log
  (`services/ws3-indexer/audit.py`); records login/triage/report events.
- **Admin routes (2026-10-15, RBAC mode only, role=admin; any other role gets
  404, no session 401; every write needs the session's `X-CSRF-Token`; every
  write is audited; none exist when RBAC is off).** Handlers live in
  `admin_api.py` and `inventory_write.py`; `do_PUT`/`do_PATCH` mirror `do_POST`.
  - `GET /users`, `POST /users {username,password,role,tenant_id?}`,
    `PATCH /users/{name} {role?,password?,disabled?}` — password min. 12
    characters (`shared/users.py password_problem`); a role change, reset or
    disable ends that user's live sessions; the last active admin cannot be
    demoted or disabled (409); `password_hash`/`totp_secret` never leave the
    store; the audit entry names the changed fields, never a password.
  - `GET /webhooks` — `contracts/webhooks/*.yml` reduced to scheme + host,
    `secret_env` (the variable NAME), `min_score`, `tenant_id`, and `enabled`
    (whether that variable is set in this process). Read-only.
  - `PUT /rules/{id}/enabled {enabled, tenant_id?}` — edits the tenant's
    `disabled_rules` in `contracts/tenants/<tenant>.yml` (atomic replace;
    never touches rule conditions). WS-4 re-reads a changed tenant file on the
    next event (no restart). In compose the file lives on the shared
    `tenants-config` volume (rw here, ro in ws4-detection).
  - `POST /inventory/assets {mac,hostname?,ip?,sector?,type?,tenant_id?}` —
    validates strictly, then calls WS-6 `POST /assets/upsert` server-side
    (`INVENTORY_URL`, optional `INVENTORY_API_KEY`); WS-6 400 is relayed, any
    other WS-6 failure is a 502. nginx's `/api/inventory/` stays GET-only.
- Outbound webhooks (M4.4, `services/ws3-indexer/webhooks.py`) run in a
  separate thread on their OWN consumer group (`cg-webhook`) on the `alerts`
  topic — a slow/down receiver can never delay or duplicate indexing itself.
  Opt-in via `contracts/webhooks/*.yml`; no configs = no thread started.
- **Auth is opt-in, not absent**: `FENGARDE_API_KEY` (shared-secret, `services/
  shared/authz.py`) gates the triage/report/webhooks-config surface;
  `FENGARDE_RBAC_DB` (SQLite users + scrypt + sessions + roles) additionally
  gates everything behind a real session when set. Both default OFF (every
  pre-M4 deployment stays fully open, unchanged) — "unauthenticated write
  surface" is the default state, not the only state; see SECURITY.md §7.

## Storage adapter (swappable)
- `MemoryStore` (default, tests) / `OpenSearchStore` (env `STORAGE_BACKEND=opensearch`).
  Request construction is unit-tested against a fake transport; live-verified against
  a real OpenSearch cluster (idempotent upsert, real 409 CAS conflict, transient-retry)
  via `services/ws3-indexer/storage/test_opensearch_live.py` (`make test-live` /
  CI's `redis-integration`-adjacent live lane).
- Idempotent on `siem.ingest_id` / `alert_id` (at-least-once delivery).

## Environment (read by `main.py` / `triage_api.py` / `audit.py` / `reporting.py`)
- `STORAGE_BACKEND` (`memory` default | `opensearch`) — which storage adapter `main.py` builds.
- `FENGARDE_OPT_IN_RULES` and `FENGARDE_PLUGIN_RULE_DIRS` — read by `rules_view.py` so
  `GET /rules` and the rule switch show what WS-4 actually evaluates (default-off rules
  opted in for every tenant; rules shipped in plugin packs). WS-4 reads the same two
  variables for detection itself; keep the values in sync across both services.
- `RATE_LIMIT_TRUST_PROXY_HEADER` (`1`/`true`/`yes`) — rate-limit per the client IP in the
  proxy's forwarded header instead of the socket peer (nginx reverse-proxy topology).
- `TRIAGE_PORT` (default `8013`) — HTTP listener port.
- `PORT` — alias read by the runner for the health/metrics listener host/port
  wiring (see `shared/runner.py`).
- `OPENSEARCH_URL` — storage endpoint (else `http://localhost:9200`); may be a
  comma-separated node list (multi-node write failover, FIX H6).
- `BUS_BACKEND` / `REDIS_URL` / `REDIS_PASSWORD` / `REDIS_SENTINEL_HOSTS` /
  `REDIS_SENTINEL_MASTER` — bus backend (memory / redis / redis-sentinel).
- `FENGARDE_API_KEY`, `FENGARDE_REQUIRE_AUTH`, `FENGARDE_RBAC_DB`,
  `FENGARDE_ADMIN_PASSWORD` — auth (see SECURITY.md §2).
- `FENGARDE_SESSION_BACKEND` (memory|redis) and `FENGARDE_SESSION_SECRET`
  (required non-empty for the redis session backend — signing).
- `INVENTORY_URL` (default `http://ws6-inventory:8000`), `INVENTORY_API_KEY` —
  target of the admin add-device route (`inventory_write.py`).
- Startup pre-creates today's `reports-*` index so the first report on a fresh
  stack does not pay OpenSearch's lazy index creation inside nginx's 5s timeout.
- `STREAM_REAP_INTERVAL_S` — acked-stream reaper cadence.
- `REPORT_BACKEND` (template|http), `REPORT_BACKEND_TIMEOUT`,
  `FENGARDE_SEC_REPORT_URL` — incident-report backend seam (`reporting.py`).
- `RATE_LIMIT_REQUESTS_PER_MIN` (default off / ≤0) — per-IP request rate cap.
- `FENGARDE_AUDIT_LOG` and `FENGARDE_AUDIT_MAX_ENTRIES` — audit JSONL path /
  capacity cap (`audit.py`; fail-open, never breaks a request).

## Contract tests
- `python test_contract.py`  (MemoryStore; routing + idempotency)

## Run locally
- `python main.py`  (memory store + memory bus by default)
