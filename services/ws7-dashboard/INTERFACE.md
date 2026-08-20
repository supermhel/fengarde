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
  `window.INVENTORY_API = null`. `/assets/{mac}` is still a WS-6 contract
  endpoint the dashboard doesn't currently call.
- `/api/audit` (2026-08-20) → WS-3's `GET /audit`, admin-scoped by the backend's
  own session check — the "Audit" nav view.
- `/api/ops/{ws1,ws2,ws3,ws4,ws8}` (2026-08-20) → each workstream's own
  `GET /metrics` (`services/shared/runner.py`) — the "Ops" nav view. Gated by
  the same `FENGARDE_API_KEY` check `/api/alerts` uses, since these health
  ports were previously reachable only container-to-container.

## Produces
- Static single-file UI (`index.html`) served by nginx. No backend of its own.
- **Deep-linkable nav** (2026-08-20): the URL hash (`#ops`, `#audit`, `#incidents`, ...)
  selects the active view on load and via `hashchange` — bookmarkable/shareable
  links to one tab, not just always-lands-on-Overview. Unknown/empty hash falls
  back to Overview rather than erroring (`selectView()`).
- All alert/triage/inventory/source-derived values are HTML-escaped via `esc()`
  before injection (stored-XSS discipline); the report view renders as text,
  never `innerHTML`.
- **Login gate** (M3 remainder, opt-in): when `FENGARDE_RBAC_DB` is set on WS-3,
  a login form gates the app behind a real session (username + role + Sign out
  badge once authenticated); every session-write echoes the CSRF token WS-3
  issued at login. `GET /auth/me` 404s when RBAC is off, so the gate is skipped
  and the app renders exactly as before — byte-for-byte unaffected for every
  pre-M3 deployment.

## Structure
- **Vue globale** — device counts, critical alerts.
- **Triage** — per-alert status dropdown + analyst note, wired to `/api/triage`;
  a "Rapport" button per row generates/fetches the incident report.
- **Inventaire** — search by IP or MAC → device detail with IP history.
- **Sources** — events per protocol/source.

## Contract tests
- `python test_contract.py`  (static checks: views present, API calls, mock shape)

## Run locally
- open `index.html`, or `docker compose up dashboard` (nginx).
