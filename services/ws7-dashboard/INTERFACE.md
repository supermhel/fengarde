# WS-7 Dashboard — Interface Declaration

## Consumes (via nginx same-origin proxies, `templates/default.conf.template`
## — envsubst'd at container start; replaces the older `nginx.conf`)
- `/api/alerts` → OpenSearch `alerts-*` (live alert list), polled every 10s when
  live + tab visible (C2, `document.hidden` guard, skips DOM rebuild when the
  fetched set is byte-identical — protects an in-progress triage-note edit).
- `/api/triage/` → WS-3 triage API (`ws3-indexer:8013`) — GET/POST forwarded,
  prefix stripped. The report feature (v0.4 Track R) has no separate `/api/report`
  location — it's reached through this same proxy at
  `/api/triage/alerts/{id}/report`, incl. the M5 `?template=nis2` NIS2/§32 BSIG
  draft option — "Rapport" button per alert row.
- `/api/rules` (C3, MITRE coverage heatmap) → WS-3's `/rules` read model
  (`list_rule_summaries`) — feeds the dashboard's "Coverage" view, shaded by real
  alert counts per tactic×technique.
- `/api/auth/` (M3 remainder) → WS-3's `/auth/{login,logout,me}`. Nginx injects
  `FENGARDE_API_KEY` server-side on the triage/report proxies — the browser
  never holds the key.
- `/api/inventory/` → WS-6 inventory API (`ws6-inventory:8000`), prefix
  stripped — `window.INVENTORY_API` now DEFAULTS to this (2026-08-20 fix: it
  previously had no default at all, unlike every other `*_API` constant, so
  the Inventory view showed mock data on every deployment). Fetches
  `/assets?limit=200` and `/keys` (key metadata, never material). Falls back
  to `mocks/mock_data.js` only if explicitly overridden with
  `window.INVENTORY_API = null`. `/assets/{mac}` (Phase 5, 2026-09-04) is now
  called too: clicking a device in the Inventory drill-in renders the list
  snapshot immediately, then refreshes with this authoritative single-device
  read once it resolves ("live device record" vs "list snapshot" badge shows
  which one is on screen; a failed/unavailable fetch just keeps the snapshot,
  never blanks the panel).
- `/api/incidents` → WS-3's `GET /incidents` (WS-8 correlation) — the "Incidents"
  nav view's list. `/api/incidents/{id}/graph` and `/api/incidents/{id}/evidence`
  (Phase 5, 2026-09-04, separate nginx `location /api/incidents/` block —
  prefix match, does not disturb the exact-match list route above) feed the
  incident detail panel's causal-graph SVG (rendered client-side, no chart
  library — a layered-DAG layout derived from the edges themselves) and its
  on-demand "Build + verify" evidence-package button. `/api/entities/{id}`
  exists (same pattern) but nothing calls it yet — `incident.graph`'s own
  nodes already carry `entity_type`/`entity_value`/`label` inline, so the
  causal graph doesn't need a per-node entity lookup; it's there for a
  possible future standalone entity-browser view.
- `/api/audit` (2026-08-20) → WS-3's `GET /audit`, admin-scoped by the backend's
  own session check — the "Audit" nav view.
- `/api/ops/{ws1,ws2,ws3,ws4,ws5,ws8}` (2026-08-20; `ws5` added later) → each workstream's own
  `GET /metrics` (`services/shared/runner.py`) — the "Ops" nav view. Gated by
  the same `FENGARDE_API_KEY` check `/api/alerts` uses, since these health
  ports were previously reachable only container-to-container.
- `/api/events` and `/api/ai-triage` → OpenSearch directly, not via WS-3
  (`events-*`, and `alerts-*` filtered to `alert_id` prefix `ai-`), both behind
  the nginx `X-Api-Key` check like `/api/alerts`. `/api/config.js` serves the
  browser runtime config (SECURITY.md explains why the key it carries is not an
  access-control boundary).

## Produces
- **The console (2026-10-15)** is a React + Vite + TypeScript app in `app/`,
  built in the Dockerfile's first stage and served at `/`. The old single-file
  UI at `/legacy/` was retired on 2026-10-20 (nginx location and file removed).
  Views, grouped:
  Detect (Overview, Alarms, Incidents), Investigate (Events log explorer,
  Coverage), Operate (Sources = how devices get connected, Inventory,
  Operations incl. System health from Prometheus, Audit, Settings), plus
  Account (MFA). Settings, the Inventory add-device form and the Coverage rule
  switch show for `role=admin` only and call WS-3's admin routes via
  `/api/triage/*` (see ws3-indexer/INTERFACE.md). DE/EN, light/dark, mobile.
  `/index.html` is `no-cache`, `/assets/*` immutable (hashed). `/api/prom/` is a
  read-only window onto Prometheus (`targets`, `query` only). The feature-by-
  feature status is `docs/console-feature-matrix.md`.
- **Demo build** (`npm run build:demo`, output `docs/demo/`): the same console with every `/api/*` call answered in the browser by `src/demo/adapter.ts` from `src/demo/fixtures.json`, a recording of a lab run made by `tools/console_e2e/record_fixtures.mjs`. Timestamps are shifted to now, writes are in-memory only, the attack is hidden until "Replay the attack", and the page that embeds it can start the replay and hears about alarms through `postMessage` (same origin). The normal build contains none of it (`import.meta.env.VITE_DEMO`). Details: `docs/console-demo.md`.
- Sign-in: username, password and an optional MFA code (the backend answers a missing or wrong code with the same 401 as a wrong password). The page shows the host, whether WS-3 answers, and a warning on plain HTTP away from localhost.
- The built bundle (`app/dist`, from `app/index.html`) is served as static files by nginx. No backend of its own.
- **Deep-linkable nav**: the URL hash (`#incidents`, `#audit`, ...) selects the active view
  on load and via `hashchange` (`app/src/App.tsx`) — bookmarkable/shareable links to one view;
  the routable ids are `overview`, `alarms`, `incidents`, `events`, `coverage`, `sources`,
  `inventory`, `operations`, `audit`, `account`, `settings` (see `tools/console_e2e/lib.mjs`).
  An unknown or empty hash falls back to Overview.
- Alert/triage/inventory/source-derived values are rendered through React, which escapes text
  by default; the source (`services/ws7-dashboard/app/src`) has no `dangerouslySetInnerHTML`,
  and the report view renders as text. (The `esc()` helper belonged to the retired single-file UI.)
- **Login gate** (M3 remainder, opt-in): when `FENGARDE_RBAC_DB` is set on WS-3,
  a login form gates the app behind a real session (username + role + Sign out
  badge once authenticated); every session-write echoes the CSRF token WS-3
  issued at login. `GET /auth/me` 404s when RBAC is off, so the gate is skipped
  and the app renders exactly as before — byte-for-byte unaffected for every
  pre-M3 deployment.

## Structure
- `app/` — the React + Vite + TypeScript console (`app/src/views/*.tsx` is one file per view
  plus the sign-in screen; `app/src/lib/i18n.ts` holds the German/English strings).
- `templates/default.conf.template` — nginx config, envsubst'd at container start.
- `Dockerfile` — two stages: Node builds `app/`, nginx serves the output.

## Contract tests
- `python test_contract.py`  (static checks of the Dockerfile and nginx proxy contract: the built
  bundle is copied in, no `/legacy/` UI or location remains, the `/api` proxies exist, the
  console source and lockfile are present)

## Run locally
- `docker compose -f infra/docker-compose.yml up ws7-dashboard` (nginx + the built console on :8080), or
  for console development `cd services/ws7-dashboard/app && npm run dev`.
