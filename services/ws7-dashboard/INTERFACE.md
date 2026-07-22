# WS-7 Dashboard — Interface Declaration

## Consumes (via nginx same-origin proxies, `templates/default.conf.template`
## — envsubst'd at container start; replaces the older `nginx.conf`)
- `/api/alerts` → OpenSearch `alerts-*` (live alert list), polled every 10s when
  live + tab visible (C2, `document.hidden` guard, skips DOM rebuild when the
  fetched set is byte-identical — protects an in-progress triage-note edit).
- `/api/triage` → WS-3 triage API (`ws3-indexer:8013`) — GET/POST forwarded.
- `/api/report` (v0.4 Track R) → WS-3's `/alerts/{id}/report`, incl. the M5
  `?template=nis2` NIS2/§32 BSIG draft option — "Rapport" button per alert row.
- `/api/auth/` (M3 remainder) → WS-3's `/auth/{login,logout,me}`. Nginx injects
  `FENGARDE_API_KEY` server-side on the triage/report proxies — the browser
  never holds the key.
- WS-6 inventory API (`GET /assets`, `/assets/{mac}`) — Contract C, via
  `window.INVENTORY_API`; falls back to `mocks/mock_data.js` when unset.

## Produces
- Static single-file UI (`index.html`) served by nginx. No backend of its own.
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
