"""F1 (2026-07-29 audit): WS-6 inventory tenant isolation.

Before this fix, `assets` had NO tenant column at all (`mac PRIMARY KEY`), so
two MSP customers sharing one ws6-inventory deployment whose devices happened
to share a MAC would silently overwrite each other's asset record, and any
caller could `GET /assets` and enumerate every tenant's entire inventory.

Proves, with zero infrastructure (in-memory SQLite + a live stdlib server):
  * the concrete failure scenario: two tenants observing the SAME MAC no
    longer collide -- each gets its own row, no overwrite,
  * every store method (get/list/resolve) is scoped to the caller's tenant_id,
  * a caller that never mentions tenant_id keeps the EXACT pre-fix,
    single-tenant behavior ("default" everywhere) -- no migration required,
  * a malformed tenant_id is rejected (400), never silently normalized/merged,
  * a pre-F1 on-disk DB (old schema, no tenant_id column) migrates in place,
    tagging all pre-existing rows "default" without losing any data,
  * the same isolation holds over real HTTP requests, not just the store API.
"""
from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from store import InventoryStore, InvalidTenantId  # noqa: E402
import app as ws6  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_same_mac_two_tenants_no_overwrite():
    """The concrete failure scenario Finding F1 describes: two tenants'
    devices share a MAC (plausible with locally-administered/randomized MACs
    or two customers on the same equipment vendor's OUI block)."""
    s = InventoryStore(":memory:")
    mac = "AA:BB:CC:00:11:99"
    s.upsert({"mac": mac, "ip": "10.0.0.5", "hostname": "acme-switch",
              "seen_at": "2026-06-16T08:00:00+00:00", "tenant_id": "acme"})
    s.upsert({"mac": mac, "ip": "10.0.0.5", "hostname": "globex-switch",
              "seen_at": "2026-06-16T08:00:00+00:00", "tenant_id": "globex"})

    acme_asset = s.get(mac, tenant_id="acme")
    globex_asset = s.get(mac, tenant_id="globex")
    check(acme_asset is not None and acme_asset["hostname"] == "acme-switch",
          f"acme's asset must survive the globex write, got {acme_asset}")
    check(globex_asset is not None and globex_asset["hostname"] == "globex-switch",
          f"globex's asset must be its own row, got {globex_asset}")
    check(acme_asset["hostname"] != globex_asset["hostname"],
          "the second tenant's upsert must NOT have overwritten the first tenant's record")


def test_list_never_leaks_across_tenants():
    """The enumeration half of Finding F1: GET /assets must not return another
    tenant's inventory, even though the deployment has only one API key."""
    s = InventoryStore(":memory:")
    s.upsert({"mac": "11:11:11:11:11:11", "ip": "10.0.0.1",
              "seen_at": "2026-06-16T08:00:00+00:00", "tenant_id": "acme"})
    s.upsert({"mac": "22:22:22:22:22:22", "ip": "10.0.0.2",
              "seen_at": "2026-06-16T08:00:00+00:00", "tenant_id": "globex"})

    acme_list = s.list(tenant_id="acme", limit=50)
    globex_list = s.list(tenant_id="globex", limit=50)
    check(len(acme_list) == 1 and acme_list[0]["mac"] == "11:11:11:11:11:11",
          f"acme's list must contain only acme's asset, got {acme_list}")
    check(len(globex_list) == 1 and globex_list[0]["mac"] == "22:22:22:22:22:22",
          f"globex's list must contain only globex's asset, got {globex_list}")


def test_resolve_scoped_per_tenant():
    """Two tenants both using the SAME (overlapping RFC1918) IP must not
    resolve into each other's asset."""
    s = InventoryStore(":memory:")
    s.upsert({"mac": "AA:AA:AA:AA:AA:01", "ip": "192.168.1.50",
              "seen_at": "2026-06-16T08:00:00+00:00", "tenant_id": "acme"})
    s.upsert({"mac": "BB:BB:BB:BB:BB:02", "ip": "192.168.1.50",
              "seen_at": "2026-06-16T08:00:00+00:00", "tenant_id": "globex"})

    acme_hit = s.resolve("192.168.1.50", "2026-06-16T09:00:00+00:00", tenant_id="acme")
    globex_hit = s.resolve("192.168.1.50", "2026-06-16T09:00:00+00:00", tenant_id="globex")
    check(acme_hit and acme_hit["mac"] == "AA:AA:AA:AA:AA:01",
          f"acme's resolve must find acme's MAC, got {acme_hit}")
    check(globex_hit and globex_hit["mac"] == "BB:BB:BB:BB:BB:02",
          f"globex's resolve must find globex's MAC, got {globex_hit}")


def test_default_tenant_backward_compatible():
    """A caller that never mentions tenant_id (every pre-F1 caller: WS-2
    enrichment, WS-7 dashboard, the existing test_contract.py suite) must see
    EXACTLY the old single-tenant behavior -- no migration, no new required
    parameter, no behavior change."""
    s = InventoryStore(":memory:")
    mac = "CC:CC:CC:CC:CC:CC"
    s.upsert({"mac": mac, "ip": "10.0.0.9", "seen_at": "2026-06-16T08:00:00+00:00"})
    asset = s.get(mac)  # no tenant_id kwarg at all
    check(asset is not None and asset["tenant_id"] == "default",
          f"an observation with no tenant_id must land in 'default', got {asset}")
    check(s.get(mac, tenant_id="default") == asset,
          "explicit tenant_id='default' must be identical to the omitted-kwarg default")


def test_malformed_tenant_id_rejected_not_normalized():
    """Same F3 convention as WS-3's router.py: reject, never lowercase/merge."""
    s = InventoryStore(":memory:")
    for bad in ("Acme", "ACME Corp", "-leading-hyphen", "trailing-hyphen-",
                "has a space", "semi;colon"):
        try:
            s.get("AA:AA:AA:AA:AA:AA", tenant_id=bad)
            check(False, f"tenant_id {bad!r} should have been rejected, was accepted")
        except InvalidTenantId:
            pass


def test_pre_tenant_schema_migrates_in_place():
    """A DB file created by the OLD code (no tenant_id column at all) must
    migrate cleanly on next open: every pre-existing row becomes 'default',
    no data lost, and the new (tenant_id, mac) key takes over going forward."""
    with tempfile.TemporaryDirectory() as td:
        db_path = str(Path(td) / "legacy.db")

        # Build a DB under the OLD (pre-F1) schema by hand, bypassing InventoryStore.
        legacy = sqlite3.connect(db_path)
        legacy.executescript(
            """
            CREATE TABLE assets (
              mac TEXT PRIMARY KEY,
              vendor TEXT, hostname TEXT, ip_current TEXT,
              sector TEXT, type TEXT, last_seen TEXT, status TEXT DEFAULT 'active'
            );
            CREATE TABLE ip_history (
              mac TEXT, ip TEXT, from_ts TEXT, to_ts TEXT
            );
            CREATE TABLE protocols (
              mac TEXT, protocol TEXT, UNIQUE(mac, protocol)
            );
            """
        )
        legacy.execute(
            "INSERT INTO assets(mac,hostname,ip_current,last_seen,status) VALUES (?,?,?,?,?)",
            ("DE:AD:BE:EF:00:00", "legacy-host", "10.0.0.42",
             "2026-06-01T00:00:00+00:00", "active"))
        legacy.execute(
            "INSERT INTO ip_history(mac,ip,from_ts,to_ts) VALUES (?,?,?,NULL)",
            ("DE:AD:BE:EF:00:00", "10.0.0.42", "2026-06-01T00:00:00+00:00"))
        legacy.execute(
            "INSERT INTO protocols(mac,protocol) VALUES (?,?)",
            ("DE:AD:BE:EF:00:00", "SNMP"))
        legacy.commit()
        legacy.close()

        # Opening it with the new InventoryStore must migrate, not crash or drop data.
        migrated = InventoryStore(db_path)
        asset = migrated.get("DE:AD:BE:EF:00:00")  # default tenant, as before
        check(asset is not None, "pre-existing asset must survive the migration")
        check(asset["tenant_id"] == "default",
              f"pre-existing row must be tagged 'default', got {asset.get('tenant_id')}")
        check(asset["hostname"] == "legacy-host", "hostname must survive the migration")
        check(asset["ip_current"] == "10.0.0.42", "ip_current must survive the migration")
        check(len(asset["ip_history"]) == 1, "ip_history must survive the migration")
        check("SNMP" in asset["protocols_seen"], "protocols must survive the migration")

        # New writes for a DIFFERENT tenant must not collide with the migrated row.
        migrated.upsert({"mac": "DE:AD:BE:EF:00:00", "ip": "10.0.0.42",
                         "hostname": "acme-host", "seen_at": "2026-07-01T00:00:00+00:00",
                         "tenant_id": "acme"})
        default_asset = migrated.get("DE:AD:BE:EF:00:00")
        acme_asset = migrated.get("DE:AD:BE:EF:00:00", tenant_id="acme")
        check(default_asset["hostname"] == "legacy-host",
              "the migrated 'default' row must be untouched by a new tenant's write")
        check(acme_asset["hostname"] == "acme-host",
              "the new tenant's write must land in its own row")

        # Re-opening the already-migrated DB must be a no-op (idempotent).
        reopened = InventoryStore(db_path)
        check(reopened.get("DE:AD:BE:EF:00:00")["hostname"] == "legacy-host",
              "re-opening an already-migrated DB must not re-run or corrupt the migration")
        # Windows holds an open file handle until the sqlite3 connection is
        # closed; without this the TemporaryDirectory cleanup above raises
        # PermissionError on __exit__.
        migrated.db.close()
        reopened.db.close()


def _http_get(base, path, headers=None):
    req = urllib.request.Request(base + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _http_post(base, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_http_layer_tenant_scoping():
    """Same isolation, proven over real HTTP requests (not just the store API),
    against the actual Handler used in production."""
    ws6.STORE = InventoryStore(":memory:")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), ws6.Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.1)
    base = f"http://127.0.0.1:{port}"
    try:
        st, _ = _http_post(base, "/assets/upsert",
                           {"mac": "FF:FF:FF:FF:FF:01", "ip": "10.9.9.1",
                            "hostname": "acme-box", "seen_at": "2026-06-16T10:00:00+00:00",
                            "tenant_id": "acme"})
        check(st == 200, f"acme upsert status {st}")
        st, _ = _http_post(base, "/assets/upsert",
                           {"mac": "FF:FF:FF:FF:FF:01", "ip": "10.9.9.1",
                            "hostname": "globex-box", "seen_at": "2026-06-16T10:00:00+00:00",
                            "tenant_id": "globex"})
        check(st == 200, f"globex upsert status {st}")

        st, acme_asset = _http_get(base, "/assets/FF:FF:FF:FF:FF:01?tenant_id=acme")
        check(st == 200 and acme_asset["hostname"] == "acme-box",
              f"GET /assets/{{mac}}?tenant_id=acme must return acme's row, got {acme_asset}")
        st, globex_asset = _http_get(base, "/assets/FF:FF:FF:FF:FF:01?tenant_id=globex")
        check(st == 200 and globex_asset["hostname"] == "globex-box",
              f"GET /assets/{{mac}}?tenant_id=globex must return globex's row, got {globex_asset}")

        st, acme_list = _http_get(base, "/assets?tenant_id=acme")
        check(st == 200 and len(acme_list) == 1 and acme_list[0]["hostname"] == "acme-box",
              f"GET /assets?tenant_id=acme must not leak globex's asset, got {acme_list}")

        st, err = _http_get(base, "/assets?tenant_id=ACME%20Corp")
        check(st == 400, f"a malformed tenant_id over HTTP must 400, got {st} {err}")

        # no tenant_id at all -> "default", not acme's or globex's data
        st, default_list = _http_get(base, "/assets")
        check(st == 200 and len(default_list) == 0,
              f"omitting tenant_id must scope to 'default' (empty here), not leak "
              f"tenant-scoped data, got {default_list}")
    finally:
        srv.shutdown(); srv.server_close()


def main():
    test_same_mac_two_tenants_no_overwrite()
    test_list_never_leaks_across_tenants()
    test_resolve_scoped_per_tenant()
    test_default_tenant_backward_compatible()
    test_malformed_tenant_id_rejected_not_normalized()
    test_pre_tenant_schema_migrates_in_place()
    test_http_layer_tenant_scoping()

    if FAILS:
        print(f"[FAIL] WS-6 tenant isolation (F1): {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-6 tenant isolation (F1): same-MAC collision, list/resolve scoping, "
          "default-tenant backward compatibility, malformed tenant_id rejection, "
          "pre-tenant DB migration, and HTTP-layer scoping all PASS")


if __name__ == "__main__":
    main()
