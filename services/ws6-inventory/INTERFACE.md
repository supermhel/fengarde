# WS-6 Inventory — Interface Declaration

**Re-synced 2026-08-06** — this file previously described only the basic
CRUD HTTP API; the auth model, MFA hosting, and bus-consumer half were all
undocumented. `services/ws6-inventory/` now has 8 substantive modules
(`app.py`, `authz.py`, `bus_consumer.py`, `keystore.py`, `manage_keys.py`,
`mfa.py`, `store.py`, plus tests) — everything below reflects the current
set.

## Consumes
- Topic `assets.updates` (opt-in, `BUS_BACKEND` set; `services/ws6-inventory/
  bus_consumer.py`) — `{mac, ip, hostname, seen_at}`. `redis` is only pulled
  into `sys.modules` when `BUS_BACKEND` is set, so the zero-infra HTTP-only
  path stays dependency-free.
- Contract C (this service IS the implementation).

## Produces
- HTTP API (Contract C): `GET /assets`, `GET /assets/resolve`, `GET /assets/{mac}`,
  `POST /assets/upsert`. Optionally consumed by WS-7 (dashboard, via the
  `INVENTORY_API` config). **Not consumed by WS-2**: `services/ws2-normalization/
  enrichment/` (A5) is local-file-only (an IOC list + a static CIDR→country map) —
  it never calls this API. This was previously documented as consumed by both;
  corrected 2026-07-21.
- **Topic `raw.events`** (M7 Track Y follow-up, 2026-08-05, `bus_consumer.py`):
  a first-ever sighting of a MAC per tenant, gated behind a per-tenant
  baseline window (`INVENTORY_BASELINE_SECONDS`, default 1h), republishes as
  a `source_type=inventory_diff` raw event — the producer side of
  `services/ws2-normalization/parsers/inventory_diff.py` and
  `contracts/rules/ot_new_device_on_segment.yml`. Was previously entirely
  undocumented in this file.

## Auth (`keystore.py` + `authz.py`, opt-in via `FENGARDE_API_KEYS`/`FENGARDE_API_KEY`)
- Per-tenant, independently-revocable API keys (`key_id` PK), HMAC-SHA256
  keyed by a server-side pepper (`FENGARDE_API_KEY_PEPPER`) — **not** scrypt;
  these are 256-bit random tokens, not low-entropy passwords, so a
  memory-hard KDF only bought a throughput ceiling and an unauth DoS lever.
  `read_only`/`read_write` scopes (a leaked read key can't poison inventory
  that feeds detection). First-boot migration
  (`ensure_legacy_keys_migrated()`) hashes any existing
  `FENGARDE_API_KEYS`/`FENGARDE_API_KEY` value once, so an operator's
  current credential keeps working unchanged after upgrading. `manage_keys.py`
  CLI for provisioning/rotation/revocation — a raw key is shown exactly once,
  never logged or stored. `app.py::_check_auth` is a single
  `TenantKeyStore.verify()` call. **Deliberately not built**: no cookie-session
  RBAC (login flow, roles, CSRF) — this is a headless service with no
  browser client; a static per-tenant secret was judged the right-sized
  control. See `SSOT.md`'s "WS-6 inventory: keystore hardened" rows for the
  full security history (this is the 3rd iteration after two earlier ones
  were found insufficient by independent review).

## MFA (`mfa.py` — hosted here, NOT wired into this service's own auth)
- Stdlib-only RFC 6238 TOTP primitive (`generate_secret`, `generate_code`,
  `verify_code`, `otpauth_uri`). Physically lives in this directory but is
  imported cross-service by `services/shared/users.py` (WS-3's RBAC session
  login) via a `sys.path` insert — WS-6's own API-key auth above does not
  itself gate anything behind MFA.

## Model
- MAC = primary key (stable), now scoped `(tenant_id, mac)` since the F1
  tenant-isolation fix. IP historised as intervals →
  `/assets/resolve?ip=&at=` is historically correct under DHCP churn. SQLite
  store, swappable to OpenSearch `assets` index (Contract E) later.
- **New-device diff** (`InventoryStore.upsert_with_diff()`): detects a
  first-ever sighting of a MAC per tenant, baseline-gated so standing the
  service up against an existing segment populates inventory instead of
  alerting on every device already present; durable in SQLite so a restart
  isn't mistaken for the segment reappearing. Surfaced as `new_device` on
  `POST /assets/upsert`'s response.

## Contract tests
- `python test_contract.py`  (in-memory SQLite + live stdlib HTTP server)
- `python test_keystore.py`, `test_auth.py` — auth/keystore scenarios
- `python test_tenant_isolation.py`, `test_new_device_diff.py` — tenant
  scoping and the baseline-gated new-device signal
- `python test_bus_consumer.py` — zero-infra round-trip of the
  `assets.updates` → `raw.events` producer path

## Run locally
- `python app.py`  (serves on :8000)
