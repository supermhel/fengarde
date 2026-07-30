"""WS-6 contract test — zero infrastructure (in-memory SQLite + live stdlib server).

Asserts the Contract C behaviours:
  * upsert creates an asset keyed by MAC,
  * an IP change closes the old interval and opens a new one (ip_history),
  * /assets/resolve?ip=&at= returns the MAC that held the IP at that instant
    (historically correct across the DHCP change),
  * GET /assets/{mac} and search work over HTTP.
"""
from __future__ import annotations

import json
import sys
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import app as ws6  # noqa: E402
from store import InventoryStore  # noqa: E402

FAILS: list[str] = []


def check(c, m):
    if not c:
        FAILS.append(m)


def http_get(base, path):
    with urllib.request.urlopen(base + path) as r:
        return r.status, json.loads(r.read())


def http_post(base, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return r.status, json.loads(r.read())


def run():
    # --- store-level: IP history + resolve ---
    s = InventoryStore(":memory:")
    mac = "AA:BB:CC:00:11:01"
    s.upsert({"mac": mac, "ip": "10.0.0.50", "hostname": "sw-01",
              "protocol": "SNMP", "seen_at": "2026-06-16T08:00:00+00:00"})
    s.upsert({"mac": mac, "ip": "10.0.0.77",  # DHCP change
              "seen_at": "2026-06-16T12:00:00+00:00"})

    asset = s.get(mac)
    check(asset is not None, "asset not created")
    check(asset["ip_current"] == "10.0.0.77", f"ip_current {asset['ip_current']}")
    check(len(asset["ip_history"]) == 2, f"expected 2 ip intervals, got {len(asset['ip_history'])}")
    check("SNMP" in asset["protocols_seen"], "protocol not recorded")

    # historically correct resolution
    before = s.resolve("10.0.0.50", "2026-06-16T09:00:00+00:00")
    after = s.resolve("10.0.0.50", "2026-06-16T13:00:00+00:00")
    check(before and before["mac"] == mac, "resolve before change should find the MAC")
    check(after is None, "resolve after the IP was released should be None")
    now77 = s.resolve("10.0.0.77", "2026-06-16T13:00:00+00:00")
    check(now77 and now77["mac"] == mac, "resolve current IP should find the MAC")

    # --- H2 (2026-07-30 audit): a delayed/redelivered stale observation must
    # not regress ip_current/last_seen or invert an ip_history interval.
    stale_store = InventoryStore(":memory:")
    stale_mac = "AA:BB:CC:00:22:02"
    stale_store.upsert({"mac": stale_mac, "ip": "10.0.0.9",
                         "seen_at": "2026-06-16T12:05:00+00:00"})  # newer obs first
    stale_store.upsert({"mac": stale_mac, "ip": "10.0.0.5",
                         "seen_at": "2026-06-16T12:00:00+00:00"})  # stale redelivery after
    stale_asset = stale_store.get(stale_mac)
    check(stale_asset["ip_current"] == "10.0.0.9",
          f"stale observation regressed ip_current to {stale_asset['ip_current']}")
    check(stale_asset["last_seen"] == "2026-06-16T12:05:00+00:00",
          f"stale observation regressed last_seen to {stale_asset['last_seen']}")
    check(len(stale_asset["ip_history"]) == 1,
          f"stale observation must not open a second ip_history interval, "
          f"got {len(stale_asset['ip_history'])}")
    hist_entry = stale_asset["ip_history"][0]
    check(hist_entry["to"] is None,
          f"the only ip_history interval must still be open, got to={hist_entry['to']}")

    # --- M2 (2026-07-30 audit): WS-1 collectors (snmp_collector,
    # syslog_collector) emit seen_at as a raw epoch-seconds int, not an
    # ISO-8601 string. Must be normalized on ingest, not crash resolve().
    epoch_store = InventoryStore(":memory:")
    epoch_mac = "AA:BB:CC:00:33:03"
    epoch_store.upsert({"mac": epoch_mac, "ip": "10.0.0.20", "seen_at": 1750000000})
    epoch_asset = epoch_store.get(epoch_mac)
    check(epoch_asset is not None, "epoch seen_at upsert must not be silently dropped")
    try:
        resolved = epoch_store.resolve("10.0.0.20", "2025-06-15T15:30:00+00:00")
        check(resolved is not None and resolved["mac"] == epoch_mac,
              "resolve() must find the epoch-seen asset, not crash or miss it")
    except ValueError as e:
        FAILS.append(f"resolve() crashed on an epoch-normalized seen_at: {e}")
    # a later ISO-string observation must compare correctly against the
    # earlier epoch-normalized one (same on-disk shape, not string-typed
    # epoch digits that would sort/parse wrong)
    epoch_store.upsert({"mac": epoch_mac, "ip": "10.0.0.21",
                         "seen_at": "2025-06-15T16:00:00+00:00"})
    epoch_asset2 = epoch_store.get(epoch_mac)
    check(epoch_asset2["ip_current"] == "10.0.0.21",
          f"newer ISO seen_at after an epoch seen_at should win, got {epoch_asset2['ip_current']}")

    # --- HTTP layer ---
    srv = ThreadingHTTPServer(("127.0.0.1", 0), ws6.Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.1)
    base = f"http://127.0.0.1:{port}"
    try:
        st, _ = http_post(base, "/assets/upsert",
                          {"mac": "DE:AD:BE:EF:00:01", "ip": "192.168.1.5",
                           "hostname": "vm-01", "seen_at": "2026-06-16T10:00:00+00:00"})
        check(st == 200, f"upsert status {st}")
        st, got = http_get(base, "/assets/DE:AD:BE:EF:00:01")
        check(st == 200 and got["hostname"] == "vm-01", "GET /assets/{mac} failed")
        st, lst = http_get(base, "/assets?limit=10")
        check(st == 200 and isinstance(lst, list) and len(lst) >= 1, "GET /assets list failed")
        st, _ = http_get(base, "/assets/resolve?ip=192.168.1.5&at=2026-06-16T11:00:00%2B00:00")
        check(st == 200, f"resolve over HTTP status {st}")
    finally:
        srv.shutdown()

    # --- concurrency: many threads upserting the SAME new mac must not 500
    # (SELECT-then-INSERT race -> PRIMARY KEY IntegrityError). Found in review.
    cs = InventoryStore(":memory:")
    race_mac = "AA:BB:CC:DD:EE:FF"
    errors: list[str] = []
    barrier = threading.Barrier(12)

    def hammer(i):
        barrier.wait()
        try:
            cs.upsert({"mac": race_mac, "ip": f"10.1.0.{i}",
                       "seen_at": "2026-06-16T10:00:00+00:00"})
        except Exception as e:  # noqa: BLE001
            errors.append(repr(e))

    ts = [threading.Thread(target=hammer, args=(i,)) for i in range(12)]
    for th in ts:
        th.start()
    for th in ts:
        th.join(timeout=5)
    check(not errors, f"concurrent upsert of the same new mac raised: {errors[:2]}")
    check(cs.get(race_mac) is not None, "asset must exist after concurrent upserts")


def main():
    run()
    if FAILS:
        print(f"[FAIL] WS-6: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-6 contract test PASS")


if __name__ == "__main__":
    main()
