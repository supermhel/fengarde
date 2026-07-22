# WS-6 Inventory — Interface Declaration

## Consumes
- Topic `assets.updates` (group `cg-inventory`) — `{mac, ip, hostname, seen_at}`.
- Contract C (this service IS the implementation).

## Produces
- HTTP API (Contract C): `GET /assets`, `GET /assets/resolve`, `GET /assets/{mac}`,
  `POST /assets/upsert`. Optionally consumed by WS-7 (dashboard, via the
  `INVENTORY_API` config). **Not consumed by WS-2**: `services/ws2-normalization/
  enrichment/` (A5) is local-file-only (an IOC list + a static CIDR→country map) —
  it never calls this API. This was previously documented as consumed by both;
  corrected 2026-07-21.

## Model
- MAC = primary key (stable). IP historised as intervals → `/assets/resolve?ip=&at=`
  is historically correct under DHCP churn. SQLite store, swappable to OpenSearch
  `assets` index (Contract E) later.

## Contract tests
- `python test_contract.py`  (in-memory SQLite + live stdlib HTTP server)

## Run locally
- `python app.py`  (serves on :8000)
