"""WS-6 contract test — zero infrastructure (in-memory SQLite + live stdlib server).

Asserts the Contract C behaviours:
  * upsert creates an asset keyed by MAC,
  * an IP change closes the old interval and opens a new one (ip_history),
  * /assets/resolve?ip=&at= returns the MAC that held the IP at that instant
    (historically correct across the DHCP change),
  * GET /assets/{mac} and search work over HTTP.
"""
from __future__ import annotations

import io
import json
import sys
import threading
import time
import urllib.error
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


def http_req(base, path, body=None):
    """Like http_get/http_post but returns (status, body) for ERROR responses
    too (urlopen raises HTTPError on >=400; the gap-hunt tests assert clean
    400/404/500 shapes, so they need the code + body instead of an exception)."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    req = urllib.request.Request(base + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


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

    # --- Gap-hunt #5: seen_at is validated at the write choke point -------
    # A well-formed ISO string still upserts; a NON-ISO string (e.g. epoch
    # digits stringified by a bad collector) is rejected at write time so it
    # can never be stored and later break resolve()/stale checks.
    try:
        epoch_store.upsert({"mac": "AA:BB:CC:00:44:04", "ip": "10.0.0.30",
                            "seen_at": "2026-06-16T10:00:00+00:00"})
        ok_iso = True
    except ValueError:
        ok_iso = False
    check(ok_iso, "a well-formed ISO seen_at must still upsert")
    for bad in ("1750000000", "not-a-date", "yesterday"):
        try:
            epoch_store.upsert({"mac": "AA:BB:CC:00:44:04", "ip": "10.0.0.31",
                                "seen_at": bad})
            check(False, f"non-ISO seen_at {bad!r} must be rejected at upsert")
        except ValueError as e:
            check("seen_at" in str(e), f"rejection message must name seen_at, got {e}")

    # A CORRUPT stored value (written before validation existed) must degrade
    # gracefully in resolve() -- treated as unknown, never a 400.
    corrupt = InventoryStore(":memory:")
    corrupt.db.execute(
        "INSERT INTO assets(tenant_id,mac,hostname,ip_current,last_seen,status) "
        "VALUES('default','AA:BB:CC:00:55:05','legacy-box','10.9.9.9','NOT-A-DATE','active')")
    corrupt.db.execute(
        "INSERT INTO ip_history(tenant_id,mac,ip,from_ts,to_ts) "
        "VALUES('default','AA:BB:CC:00:55:05','10.9.9.9','NOT-A-DATE',NULL)")
    corrupt.db.commit()
    resolved_corrupt = corrupt.resolve("10.9.9.9", "2026-06-16T09:00:00+00:00")
    check(resolved_corrupt is None,
          "resolve() must treat a corrupt stored timestamp as unknown (None), not raise")
    asset_corrupt = corrupt.get("AA:BB:CC:00:55:05")
    check(asset_corrupt is not None and asset_corrupt["mac"] == "AA:BB:CC:00:55:05",
          "get() must still return the corrupt-rowed asset without crashing")

    # --- Gap-hunt #6: ip_history / protocols_seen are bounded ------------
    cap_store = InventoryStore(":memory:")
    cap_mac = "AA:BB:CC:00:66:06"
    for i in range(150):  # 150 DHCP churns; monotonic seen_at
        m = i
        cap_store.upsert({"mac": cap_mac, "ip": f"10.99.0.{i}",
                          "seen_at": f"2026-06-16T{10 + m // 60:02d}:{m % 60:02d}:00+00:00"})
    hist_capped = cap_store.get(cap_mac)
    check(len(hist_capped["ip_history"]) <= 100,
          f"ip_history must be capped at 100 intervals per asset, got {len(hist_capped['ip_history'])}")
    check(hist_capped["ip_history"][-1]["ip"] == "10.99.0.149",
          "the most recent interval must be retained after capping")
    check(hist_capped["ip_history"][0]["ip"] == "10.99.0.50"
          or len(hist_capped["ip_history"]) < 100,
          "the OLDEST intervals must be the ones pruned")
    for i in range(80):  # 80 distinct protocols on the SAME asset
        cap_store.upsert({"mac": cap_mac, "ip": "10.99.5.5",
                          "protocol": f"PROTO-{i:02d}",
                          "seen_at": f"2026-06-17T{10 + i // 60:02d}:{i % 60:02d}:00+00:00"})
    protos_capped = cap_store.get(cap_mac)
    check(len(protos_capped["protocols_seen"]) <= 50,
          f"protocols_seen must be capped at 50 per asset, got {len(protos_capped['protocols_seen'])}")

    # --- Gap-hunt #7: mac/hostname/protocol validated on upsert -----------
    fstore = InventoryStore(":memory:")
    for bad_obs, label in (
        ({"mac": "A" * 100000, "ip": "10.0.0.99"}, "100,000-char mac"),
        ({"mac": "not-a-mac", "ip": "10.0.0.98"}, "malformed mac"),
        ({"mac": "AA:BB:CC:00:77:07", "ip": "10.0.0.97",
          "hostname": "h" * 300}, "300-char hostname"),
        ({"mac": "AA:BB:CC:00:77:07", "ip": "10.0.0.96",
          "protocol": "P" * 200}, "200-char protocol"),
    ):
        try:
            fstore.upsert({**bad_obs, "seen_at": "2026-06-16T10:00:00+00:00"})
            check(False, f"{label} must be rejected on upsert")
        except ValueError:
            pass
    ok_asset = fstore.upsert({"mac": "AA:BB:CC:00:77:07", "ip": "10.0.0.95",
                              "hostname": "sw-07", "protocol": "SNMP",
                              "seen_at": "2026-06-16T10:00:00+00:00"})
    check(ok_asset is not None and ok_asset["mac"] == "AA:BB:CC:00:77:07",
          "a well-formed observation (colon-hex mac, bounded hostname/protocol) must still upsert")

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

        # Gap-hunt #5/#7 over HTTP: invalid observation input is the CALLER'S
        # fault -> clean 400s naming the reason, never a 500.
        st, body = http_req(base, "/assets/upsert",
                            {"mac": "A" * 100000, "ip": "10.0.0.96",
                             "seen_at": "2026-06-16T10:00:00+00:00"})
        check(st == 400, f"upsert of a 100,000-char mac must be 400 over HTTP, got {st} {body}")
        st, body = http_req(base, "/assets/upsert",
                            {"mac": "AA:BB:CC:00:88:08", "ip": "10.0.0.95",
                             "seen_at": "garbage-not-iso"})
        check(st == 400 and "seen_at" in json.dumps(body),
              f"upsert of a non-ISO seen_at must be 400 naming seen_at, got {st} {body}")

        # A corrupt STORED timestamp must NOT 400 a well-formed resolve param:
        # /assets/resolve blames the caller's `at` only when `at` itself is
        # malformed; a corrupt DB row is the service's problem, answered 404.
        ws6.STORE.db.execute(
            "INSERT INTO assets(tenant_id,mac,hostname,ip_current,last_seen,status) "
            "VALUES('default','AA:BB:CC:00:99:09','legacy','10.9.9.9','NOT-A-DATE','active')")
        ws6.STORE.db.execute(
            "INSERT INTO ip_history(tenant_id,mac,ip,from_ts,to_ts) "
            "VALUES('default','AA:BB:CC:00:99:09','10.9.9.9','NOT-A-DATE',NULL)")
        ws6.STORE.db.commit()
        st, body = http_req(base, "/assets/resolve?ip=10.9.9.9&at=2026-06-16T09:00:00%2B00:00")
        check(st == 404,
              f"resolve over a corrupt stored timestamp must degrade to 404 (unknown), got {st} {body}")
        st, body = http_req(base, "/assets/resolve?ip=10.9.9.9&at=not-a-date")
        check(st == 400 and "at" in json.dumps(body),
              f"a MALFORMED caller `at` param must still be a 400 naming at, got {st} {body}")
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


def test_internal_error_is_logged():
    """Gap-hunt #2: both request dispatchers used to swallow every exception
    into a bare 500 with ZERO logging (log_message is a no-op), so a real
    backend break was invisible. Force an internal error in the GET path and
    assert the 500 is accompanied by a traceback log line on stdout."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), ws6.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    base = f"http://127.0.0.1:{port}"
    orig_list = ws6.STORE.list

    def _boom(*a, **k):
        raise RuntimeError("synthetic internal error")

    ws6.STORE.list = _boom
    buf = io.StringIO()
    try:
        old = sys.stdout
        sys.stdout = buf
        try:
            st, body = http_req(base, "/assets")
        finally:
            sys.stdout = old
        check(st == 500 and body.get("error") == "internal error",
              f"forced internal error should answer 500, got {st} {body}")
    finally:
        ws6.STORE.list = orig_list
        srv.shutdown()
        srv.server_close()
    out = buf.getvalue()
    check('"level": "error"' in out and "synthetic internal error" in out and "traceback" in out,
          f"the 500 must be logged with a traceback (not silent), got stdout={out!r}")


def main():
    run()
    test_internal_error_is_logged()
    if FAILS:
        print(f"[FAIL] WS-6: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-6 contract test PASS")


if __name__ == "__main__":
    main()
