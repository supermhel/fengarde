# WS-7 Dashboard — Interface Declaration

## Consumes (via nginx same-origin proxies, `nginx.conf`)
- `/api/alerts` → OpenSearch `alerts-*` (live alert list).
- `/api/triage` → WS-3 triage API (`ws3-indexer:8013`) — GET/POST forwarded.
- WS-6 inventory API (`GET /assets`, `/assets/{mac}`) — Contract C, via
  `window.INVENTORY_API`; falls back to `mocks/mock_data.js` when unset.

## Produces
- Static single-file UI (`index.html`) served by nginx. No backend of its own.
- All alert/triage/inventory/source-derived values are HTML-escaped via `esc()`
  before injection (stored-XSS discipline).

## Structure
- **Vue globale** — device counts, critical alerts.
- **Triage** — per-alert status dropdown + analyst note, wired to `/api/triage`
  (v0.3 C1).
- **Inventaire** — search by IP or MAC → device detail with IP history.
- **Sources** — events per protocol/source.

## Contract tests
- `python test_contract.py`  (static checks: views present, API calls, mock shape)

## Run locally
- open `index.html`, or `docker compose up dashboard` (nginx).
