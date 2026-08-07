# WS-3 Indexer — Interface Declaration

## Consumes
- Topics `normalized.events`, `scored.events`, `alerts`, `ai.results` (group `cg-index`).
- Contracts: A (events), E (index templates / ILM), B (bus).

## Produces
- Writes to OpenSearch indices: `events-{bank|dc|common}-YYYY.MM.DD`,
  `alerts-YYYY.MM.DD` for the default tenant. A non-default `siem.tenant` (M4.1
  multi-tenancy) gets its own index per family: `events-{family}-{tenant}-
  YYYY.MM.DD`, `alerts-{tenant}-YYYY.MM.DD` (`router.py`, `tenant_id` validated
  and rejected — never normalized — before it reaches an index name).

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
- `/api/v1/...` (M4.3) — versioned aliases for `GET /alerts`, `GET /events`,
  `GET /rules`, alongside the unchanged bare paths. Spec-vs-code drift is
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
- `STREAM_REAP_INTERVAL_S` — acked-stream reaper cadence.
- `REPORT_BACKEND` (template|http), `REPORT_BACKEND_TIMEOUT`,
  `FENGARDE_SEC_REPORT_URL` — incident-report backend seam (`reporting.py`).
- `RATE_LIMIT_REQUESTS_PER_MIN` (default off / ≤0) — per-IP request rate cap.
- `FENGARDE_AUDIT_LOG` and `FENGARDE_AUDIT_LOG_MAX_ENTRIES` — audit JSONL path /
  capacity cap (`audit.py`; fail-open, never breaks a request).

## Contract tests
- `python test_contract.py`  (MemoryStore; routing + idempotency)

## Run locally
- `python main.py`  (memory store + memory bus by default)
