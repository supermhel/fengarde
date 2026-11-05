"""Device identity on the HTTP/JSON ingest edge (review finding 9 on PR 142).

Behind a published Docker port or a relay every sender shares one TCP peer address, which used to be the rate-limit key AND the bus
partition key. A sender can now label the device with X-Fengarde-Source (or ?source=):
  1. the label becomes the bus partition key and meta.source; the TCP peer stays in meta.shipper_ip
  2. a per-source rate cap isolates one noisy device from another that shares the peer address
  3. without a label the TCP peer is used exactly as before
  4. a malformed label, or a header/query conflict, is a 400
  5. the per-source map is bounded

Zero-infra (memory bus, ephemeral loopback port). Run: python services/ws1-collectors/test_http_json_ingest_source_identity.py
"""
from __future__ import annotations

import http.client
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from shared.bus import Bus  # noqa: E402
from collectors import http_json_collector as mod  # noqa: E402
from collectors.http_json_collector import HttpJsonCollector  # noqa: E402

FAILS: list[str] = []
TOKEN = "test-ingest-token-000"
URL = "/v1/ingest?source_type=windows_eventlog"
REC = json.dumps({"EventID": 4625, "Computer": "WIN-DEV-01"})


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def post(port, path, body, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Authorization": f"Bearer {TOKEN}"}
    h.update(headers or {})
    try:
        conn.request("POST", path, body=body.encode(), headers=h)
        r = conn.getresponse()
        data = r.read()
        return r.status, (json.loads(data) if data else {})
    finally:
        conn.close()


def start(bus, **kw):
    c = HttpJsonCollector(bus, ingest_token=TOKEN, host="127.0.0.1", port=0, **kw)
    c.start()
    return c, c.port


def main() -> int:
    # 1 + 3. label -> partition key and meta; no label -> peer
    bus = Bus()
    c, port = start(bus)
    try:
        st, _ = post(port, URL, REC, {"X-Fengarde-Source": "plc-line-3"})
        check(st == 200, f"a labelled batch must be accepted, got {st}")
        st, _ = post(port, URL + "&source=gw-7", REC)
        check(st == 200, f"?source= must work, got {st}")
        st, _ = post(port, URL, REC)
        msgs = bus.drain("raw.events")
        check(len(msgs) == 3, f"3 events expected, got {len(msgs)}")
        keys = [m.key for m in msgs]
        check(keys == ["plc-line-3", "gw-7", "127.0.0.1"],
              f"partition keys must be the label, then the label, then the TCP peer, got {keys}")
        meta = [m.payload["meta"] for m in msgs]
        check(meta[0].get("source") == "plc-line-3" and meta[0].get("shipper_ip") == "127.0.0.1",
              f"meta must carry source and shipper_ip, got {meta[0]}")
        check("source" not in meta[2] and meta[2].get("shipper_ip") == "127.0.0.1",
              f"an unlabelled batch has shipper_ip but no source, got {meta[2]}")

        # 4. validation
        for bad in ("bad label", "x" * 129, "a;b", "../etc"):
            st, _ = post(port, URL, REC, {"X-Fengarde-Source": bad})
            check(st == 400, f"source {bad[:20]!r} must be a 400, got {st}")
        st, _ = post(port, URL + "&source=a", REC, {"X-Fengarde-Source": "b"})
        check(st == 400, f"conflicting header/query source must be a 400, got {st}")

        # 6. shipper self-label (X-Fengarde-Shipper / ?shipper=) -> meta.shipper
        st, _ = post(port, URL, REC, {"X-Fengarde-Shipper": "winlogbeat"})
        check(st == 200, f"a shipper-labelled batch must be accepted, got {st}")
        st, _ = post(port, URL + "&shipper=fluentbit-winevtlog", REC)
        check(st == 200, f"?shipper= must work, got {st}")
        st, _ = post(port, URL, REC)
        msgs = bus.drain("raw.events")
        meta6 = [m.payload["meta"] for m in msgs][-3:]  # drain is non-destructive
        check(meta6[0].get("shipper") == "winlogbeat"
              and meta6[1].get("shipper") == "fluentbit-winevtlog",
              f"meta.shipper must carry the label, got {[m.get('shipper') for m in meta6]}")
        check("shipper" not in meta6[2],
              f"an unlabelled batch must have no meta.shipper, got {meta6[2]}")
        for bad in ("bad shipper", "x" * 65, "a;b", "win log"):
            st, _ = post(port, URL, REC, {"X-Fengarde-Shipper": bad})
            check(st == 400, f"shipper {bad[:20]!r} must be a 400, got {st}")
        st, _ = post(port, URL + "&shipper=a", REC, {"X-Fengarde-Shipper": "b"})
        check(st == 400, f"conflicting header/query shipper must be a 400, got {st}")
    finally:
        c.stop()

    # 2. per-source isolation behind one peer address (tenant ceiling high, per-source cap 2 events/s)
    bus = Bus()
    c, port = start(bus, max_events_per_sec=1000, max_events_per_sec_per_source=2)
    try:
        batch = "\n".join([REC] * 3)
        st, body = post(port, URL, batch, {"X-Fengarde-Source": "noisy"})
        check(st == 429 and body.get("accepted") == 2,
              f"a source over its own cap is limited after 2 records, got {st} {body}")
        st, body = post(port, URL, "\n".join([REC] * 2), {"X-Fengarde-Source": "quiet"})
        check(st == 200 and body.get("accepted") == 2,
              f"another source behind the same peer address must be unaffected, got {st} {body}")
    finally:
        c.stop()

    # per-source cap off by default: same peer, no limit
    bus = Bus()
    c, port = start(bus, max_events_per_sec=1000)
    try:
        st, body = post(port, URL, "\n".join([REC] * 20), {"X-Fengarde-Source": "s"})
        check(st == 200 and body.get("accepted") == 20, f"no per-source cap by default, got {st} {body}")
    finally:
        c.stop()

    # 5. bounded map
    bus = Bus()
    c = HttpJsonCollector(bus, ingest_token=TOKEN, host="127.0.0.1", port=0, max_events_per_sec_per_source=5)
    for i in range(mod.DEFAULT_MAX_SOURCES + 50):
        c._take_source(f"dev-{i}")
    check(len(c._source_buckets) <= mod.DEFAULT_MAX_SOURCES,
          f"the per-source map must stay bounded, got {len(c._source_buckets)}")

    # 6. trusted-proxy client resolution (WP-3.1 review): XFF only from a trusted peer, last untrusted hop wins
    t = mod.parse_trusted_proxies("172.16.0.0/12, 10.0.0.0/8")
    r = mod.resolve_client_ip
    check(r("172.18.0.5", ["203.0.113.9"], t) == ("203.0.113.9", "172.18.0.5"), "trusted peer: client = XFF hop")
    check(r("172.18.0.5", ["1.1.1.1, 203.0.113.9"], t) == ("203.0.113.9", "172.18.0.5"),
          "spoofed leftmost hop must be ignored, last untrusted hop wins")
    check(r("172.18.0.5", ["198.51.100.7", "10.1.1.1, 203.0.113.9, 172.17.0.2"], t) == ("203.0.113.9", "172.18.0.5"),
          "trusted hops on the right are skipped, repeated headers are joined")
    check(r("172.18.0.5", ["10.1.1.1, 172.17.0.2"], t) == ("10.1.1.1", "172.18.0.5"),
          "all hops trusted-range (private client behind NAT): leftmost is the client")
    check(r("198.51.100.1", ["203.0.113.9"], t) == ("198.51.100.1", None), "untrusted peer: XFF ignored")
    check(r("172.18.0.5", [], t) == ("172.18.0.5", None), "no header: peer")
    check(r("172.18.0.5", ["not-an-ip"], t) == ("172.18.0.5", None), "garbage hop: fall back to peer")
    check(r("127.0.0.1", ["203.0.113.9"], ()) == ("127.0.0.1", None), "default (empty list): header never trusted")
    try:
        mod.parse_trusted_proxies("nonsense")
        check(False, "a bad CIDR must raise")
    except ValueError:
        pass

    # end to end: loopback peer trusted -> shipper_ip is the XFF client, proxy hop recorded, rate-limit key follows
    bus = Bus()
    c, port = start(bus, trusted_proxies="127.0.0.0/8")
    try:
        st, _ = post(port, URL, REC, {"X-Forwarded-For": "6.6.6.6, 203.0.113.9"})
        st2, _ = post(port, URL, REC, {"X-Forwarded-For": "203.0.113.10"})
        msgs = bus.drain("raw.events")
        check(st == 200 and st2 == 200 and [m.key for m in msgs] == ["203.0.113.9", "203.0.113.10"],
              f"keys must be the resolved client IPs, got {[m.key for m in msgs]}")
        m0 = msgs[0].payload["meta"]
        check(m0.get("shipper_ip") == "203.0.113.9" and m0.get("shipper_proxy_ip") == "127.0.0.1",
              f"meta must carry client and proxy hop separately, got {m0}")
    finally:
        c.stop()
    bus = Bus()
    c, port = start(bus)  # not trusted: a client-supplied XFF is ignored
    try:
        post(port, URL, REC, {"X-Forwarded-For": "203.0.113.9"})
        msgs = bus.drain("raw.events")
        check(msgs[0].key == "127.0.0.1" and "shipper_proxy_ip" not in msgs[0].payload["meta"],
              "an untrusted peer's X-Forwarded-For must be ignored")
    finally:
        c.stop()

    if FAILS:
        print(f"[FAIL] ws1 HTTP ingest source identity: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        return 1
    print("[OK] ws1 HTTP ingest source identity: label keys partition and meta, per-source cap isolates devices behind one peer, "
          "validation, bounded map")
    return 0


if __name__ == "__main__":
    sys.exit(main())
