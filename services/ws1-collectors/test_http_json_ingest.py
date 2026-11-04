"""WS-1 HTTP/JSON ingest contract test (WP-1.1) -- zero infrastructure.

Runs the real ``HttpJsonCollector`` (threaded server on 127.0.0.1:$EPHEMERAL)
against the in-memory bus (BUS_BACKEND=memory) and pins the acceptance
criteria from the roadmap:

  * auth: no token / wrong token -> 401, correct token -> 200;
    the listener REFUSES to construct without a token (unless the
    loopback-only dev switch is set);
  * unknown source_type -> 400 (server-side validation list cross-checked
    against ws2's parser registry -- drift fails THIS test, keeping the
    frozen REGISTERED_SOURCE_TYPES honest);
  * body size cap -> 413 (Content-Length and close-delimited paths);
  * per-source rate limit (reuses the syslog TenantTokenBuckets) -> 429;
  * malformed line -> counted + skipped, batch continues -> 200;
  * idempotent redelivery: same batch + same X-Fengarde-Idempotency-Key ->
    SAME ingest_ids; different keys -> different ids; identical lines inside
    one batch stay DISTINCT (no FIX-21 collapse);
  * bus down + spool -> 202; bus down + no spool -> 503;
  * partition key = client IP, meta.format stamped, stamp_meta fields present;
  * negative control: with the auth check neutered (dev_loopback), an
    unauthenticated batch is accepted -- proving the 401 test has teeth.
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent                       # .../services (for `shared`)
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"

import main as ws1  # noqa: E402  (imports the new collector too)
from shared.bus import Bus  # noqa: E402
from collectors.http_json_collector import (  # noqa: E402
    HttpJsonCollector, REGISTERED_SOURCE_TYPES)

FAILS: list[str] = []
_TOKEN = "test-ingest-token-000"
SAMPLE = {"EventID": 4625, "TimeCreated": "2026-11-04T12:00:00.000Z",
          "Computer": "WIN-DEV-01", "SubjectUserName": "svc_backup"}

RECORD_A = {"EventID": 4625, "TimeCreated": "2026-11-04T12:00:01.000Z"}
RECORD_B = {"EventID": 4634, "TimeCreated": "2026-11-04T12:00:02.000Z"}


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _start_collector(bus, **kw):
    """Start a collector on an ephemeral loopback port; returns (c, url)."""
    c = HttpJsonCollector(bus, ingest_token=_TOKEN, host="127.0.0.1", port=0,
                          **kw)
    c.start()
    return c, f"127.0.0.1:{c.port}"


def _post(hostport, path, body=b"", *, token=_TOKEN, headers=None):
    conn = http.client.HTTPConnection(hostport, timeout=10)
    hdrs = {"Authorization": f"Bearer {token}"}
    if headers:
        hdrs.update(headers)
    try:
        conn.request("POST", path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        parsed = {}
        try:
            parsed = json.loads(data) if data else {}
        except json.JSONDecodeError:
            parsed = {"_raw": data.decode("utf-8", "replace")}
        return resp.status, parsed, dict(resp.getheaders())
    finally:
        conn.close()


def _raw_socket_post(port, body: bytes):
    """Send a POST with NO Content-Length (close-delimited body)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    req = (b"POST /v1/ingest?source_type=windows_eventlog HTTP/1.1\r\n"
           b"Host: 127.0.0.1\r\n"
           b"Authorization: Bearer " + _TOKEN.encode() + b"\r\n"
           b"Connection: close\r\n\r\n")
    s.sendall(req)
    time.sleep(0.05)
    s.sendall(body)
    s.shutdown(socket.SHUT_WR)
    chunks = b""
    while True:
        data = s.recv(65536)
        if not data:
            break
        chunks += data
    s.close()
    status_line = chunks.split(b"\r\n", 1)[0]
    return int(status_line.split()[1])


class _FailingBus:
    """Memory-shaped bus whose produce always raises (Redis outage proxy)."""

    def __init__(self):
        self.produced = []
        self.drained = 0

    def produce(self, topic, key, payload):
        self.produced.append((topic, key, payload))
        raise RuntimeError("simulated bus outage")


def run():
    t0 = time.time()

    # -- auth ----------------------------------------------------------------
    bus = Bus()
    c, hp = _start_collector(bus)
    try:
        status, body, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog",
                                json.dumps(SAMPLE).encode(), token=None)
        check(status == 401, f"missing token must 401, got {status}")
        status, body, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog",
                                json.dumps(SAMPLE).encode(), token="wrong-token")
        check(status == 401, f"wrong token must 401, got {status}")
        status, body, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog",
                                json.dumps(SAMPLE).encode())
        check(status == 200, f"valid token must 200, got {status} ({body})")
        # wrong path / wrong method
        status, _, _ = _post(hp, "/v1/other", json.dumps(SAMPLE).encode())
        check(status == 404, f"unknown path must 404, got {status}")
        status, _, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog",
                             b"", headers={"X-Http-Method-Override": "GET"})
        # do_GET path
        import urllib.request
        try:
            urllib.request.urlopen(f"http://{hp}/v1/ingest", timeout=5)
            check(False, "GET /v1/ingest must not be accepted")
        except Exception:
            pass
        _ = status, body
    finally:
        c.stop()

    # -- refuse to start without a token --------------------------------------
    try:
        HttpJsonCollector(Bus(), ingest_token=None, host="127.0.0.1", port=0)
        check(False, "collector must refuse to start without a token")
    except ValueError:
        pass
    try:
        HttpJsonCollector(Bus(), ingest_token=None, dev_loopback=True,
                          host="127.0.0.1", port=0)
    except ValueError:
        check(False, "loopback dev switch must allow a missing token")

    # -- negative control: auth check is load-bearing --------------------------
    bus = Bus()
    dev = HttpJsonCollector(bus, ingest_token=None, dev_loopback=True,
                            host="127.0.0.1", port=0)
    dev.start()
    try:
        status, _, _ = _post(f"127.0.0.1:{dev.port}",
                             "/v1/ingest?source_type=windows_eventlog",
                             json.dumps(SAMPLE).encode(), token=None)
        # If a future change removes the token check, THIS becomes the behavior
        # of the production path too -- and the 401 assertion above would fail.
        # The control is that neutering the check changes the outcome:
        check(status == 200,
              "negative control broken: dev/neutered auth must accept, "
              f"got {status}")
    finally:
        dev.stop()

    # -- unknown source_type / format; missing / conflicting params ------------
    bus = Bus()
    c, hp = _start_collector(bus)
    try:
        status, body, _ = _post(hp, "/v1/ingest?source_type=not_a_parser",
                                json.dumps(SAMPLE).encode())
        check(status == 400, f"unknown source_type must 400, got {status}")
        check("registered" in json.dumps(body), "400 must name registered types")
        status, _, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog"
                                 "&format=bogus", json.dumps(SAMPLE).encode())
        check(status == 400, f"unknown format must 400, got {status}")
        status, _, _ = _post(hp, "/v1/ingest", json.dumps(SAMPLE).encode())
        check(status == 400, f"missing source_type must 400, got {status}")
        status, _, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog",
                             json.dumps(SAMPLE).encode(),
                             headers={"X-Fengarde-Source-Type": "sysmon"})
        check(status == 400,
              f"conflicting query/header source_type must 400, got {status}")
        # header-only source_type works
        status, _, _ = _post(hp, "/v1/ingest",
                             json.dumps(SAMPLE).encode(),
                             headers={"X-Fengarde-Source-Type": "sysmon"})
        check(status == 200, f"header source_type must 200, got {status}")
    finally:
        c.stop()

    # -- source_type validation snapshot matches ws2 registry -------------------
    try:
        sys.path.insert(0, str(SERVICES / "ws2-normalization"))
        import parsers as ws2_parsers  # type: ignore  # noqa: E402
        ws2_keys = set(ws2_parsers._REGISTRY.keys())
        check(ws2_keys == set(REGISTERED_SOURCE_TYPES),
              f"REGISTERED_SOURCE_TYPES drifted from ws2 registry: "
              f"only-ws2={sorted(ws2_keys - set(REGISTERED_SOURCE_TYPES))} "
              f"only-snapshot={sorted(set(REGISTERED_SOURCE_TYPES) - ws2_keys)}")
    except Exception as exc:  # noqa: BLE001
        check(False, f"could not cross-check ws2 registry: {exc}")

    # -- size cap: 413 ---------------------------------------------------------
    bus = Bus()
    c, hp = _start_collector(bus, max_body_bytes=1024)
    try:
        big = json.dumps({"EventID": 4625, "pad": "x" * 2048}).encode()
        status, body, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog",
                                big)
        check(status == 413, f"oversize Content-Length must 413, got {status}")
        ok_body = json.dumps({"EventID": 4625, "pad": "x" * 900}).encode()
        status, _, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog",
                             ok_body)
        check(status == 200, f"within-cap body must 200, got {status}")
        # close-delimited (no Content-Length): cap still enforced mid-transfer
        status = _raw_socket_post(c.port, big)
        check(status == 413, f"close-delimited oversize must 413, got {status}")
    finally:
        c.stop()

    # -- per-source rate limit: 429 ---------------------------------------------
    bus = Bus()
    c, hp = _start_collector(bus, max_events_per_sec=1)
    try:
        status, body, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog",
                                (json.dumps(RECORD_A) + "\n" +
                                 json.dumps(RECORD_B)).encode())
        check(status == 429, f"over-limit batch must 429, got {status}")
        check(body.get("rate_limited", 0) >= 1, "429 body must count rate_limited")
        check(body.get("accepted", 0) >= 1, "429 body must keep accepted count")
    finally:
        c.stop()

    # -- malformed line: counted + skipped, batch continues ----------------------
    bus = Bus()
    c, hp = _start_collector(bus)
    try:
        bad = b'{"EventID": 4625}\nnot-json-line\n{"EventID": 4634}\n\n'
        status, body, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog",
                                bad)
        check(status == 200, f"malformed-line batch must 200, got {status}")
        check(body.get("accepted") == 2, f"expected 2 accepted, got {body}")
        check(body.get("skipped") == 1, f"expected 1 skipped, got {body}")
        msgs = bus.drain("raw.events")
        check(len(msgs) == 2, f"expected 2 events on bus, got {len(msgs)}")
    finally:
        c.stop()

    # -- json-array format -------------------------------------------------------
    bus = Bus()
    c, hp = _start_collector(bus)
    try:
        arr = json.dumps([RECORD_A, RECORD_B, "not-a-dict"]).encode()
        status, body, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog"
                                 "&format=json-array", arr)
        check(status == 200, f"json-array must 200, got {status}")
        check(body.get("accepted") == 2 and body.get("skipped") == 1,
              f"json-array counts wrong: {body}")
        status, _, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog"
                                 "&format=json-array",
                             json.dumps({"EventID": 1}).encode())
        check(status == 400, "json-array with dict root must 400")
    finally:
        c.stop()

    # -- record shape: {source_type, raw, meta} on raw.events --------------------
    bus = Bus()
    c, hp = _start_collector(bus)
    try:
        status, _, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog",
                             json.dumps(SAMPLE).encode())
        check(status == 200, "shape probe must 200")
        msgs = bus.drain("raw.events")
        check(len(msgs) == 1, f"want 1 event, got {len(msgs)}")
        m = msgs[0]
        p = m.payload
        check(p["source_type"] == "windows_eventlog", "source_type stamped")
        check(p["raw"] == SAMPLE, "raw must be the wire record")
        check(m.key == "127.0.0.1", f"partition key must be peer IP, got {m.key}")
        meta = p["meta"]
        for field in ("received_at", "ingest_id", "format", "trace_id",
                      "tenant_id"):
            check(field in meta, f"meta missing {field}")
        check(meta["format"] == "ndjson", "meta.format must be ndjson")
        check(meta["tenant_id"] == "default", "meta.tenant_id default")
    finally:
        c.stop()

    # -- idempotent redelivery -----------------------------------------------------
    bus = Bus()
    c, hp = _start_collector(bus)
    payload = (json.dumps(RECORD_A) + "\n" + json.dumps(RECORD_B)).encode()
    try:
        status, _, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog",
                             payload, headers={"X-Fengarde-Idempotency-Key": "k1"})
        check(status == 200, f"idempotent first send must 200, got {status}")
        msgs = bus.drain("raw.events")
        ids_first = [m.payload["meta"]["ingest_id"] for m in msgs[:2]]
        # redeliver the SAME batch with the SAME key (bus accumulates; slice tail)
        status, _, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog",
                             payload, headers={"X-Fengarde-Idempotency-Key": "k1"})
        msgs = bus.drain("raw.events")
        ids_second = [m.payload["meta"]["ingest_id"] for m in msgs[2:]]
        check(ids_first == ids_second,
              f"same key + same batch must yield same ingest_ids: "
              f"{ids_first} vs {ids_second}")
        # different key -> different ids (distinct logical events)
        status, _, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog",
                             payload, headers={"X-Fengarde-Idempotency-Key": "k2"})
        msgs = bus.drain("raw.events")
        ids_third = [m.payload["meta"]["ingest_id"] for m in msgs[4:]]
        check(ids_first != ids_third, "different key must yield different ids")
        # identical lines INSIDE one batch stay distinct (no FIX-21 collapse)
        dup = (json.dumps(RECORD_A) + "\n" + json.dumps(RECORD_A)).encode()
        status, _, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog",
                             dup, headers={"X-Fengarde-Idempotency-Key": "k3"})
        msgs = bus.drain("raw.events")
        ids_dup = [m.payload["meta"]["ingest_id"] for m in msgs[6:]]
        check(len(set(ids_dup)) == 2,
              f"identical lines must stay distinct, got {ids_dup}")
    finally:
        c.stop()

    # -- bus down: spool -> 202, no spool -> 503 -----------------------------------
    with tempfile.TemporaryDirectory() as td:
        from collectors.spool import BoundedSpool  # noqa: E402
        failing = _FailingBus()
        spool = BoundedSpool(Path(td) / "spool.jsonl", max_bytes=1 << 20)
        c, hp = _start_collector(failing, spool=spool)
        try:
            status, body, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog",
                                    (json.dumps(RECORD_A) + "\n" +
                                     json.dumps(RECORD_B)).encode())
            check(status == 202, f"bus down + spool must 202, got {status}")
            check(body.get("spooled") == 2, f"expected 2 spooled, got {body}")
            check(spool.pending_count() == 2,
                  f"spool must hold 2 pending, got {spool.pending_count()}")
        finally:
            c.stop()

    bus = Bus()
    c, hp = _start_collector(_FailingBus())
    try:
        status, body, _ = _post(hp, "/v1/ingest?source_type=windows_eventlog",
                                json.dumps(RECORD_A).encode())
        check(status == 503, f"bus down + no spool must 503, got {status}")
    finally:
        c.stop()

    # -- /health + /metrics integration (main-level wiring) -------------------------
    c, hp = _start_collector(Bus())
    try:
        metrics = ws1._syslog_metrics(udp=None, http=c)
        check(metrics.get("http_events_accepted") is not None,
              "/metrics provider must expose http counters")

        class _FakeUDP:
            def is_running(self):
                return True

        health = ws1.build_health_handlers(udp=_FakeUDP(), http=c)
        handler = health[ws1._HEALTH_TOPIC][1]
        # handler raising means "not healthy"; it must NOT raise while running
        try:
            handler({"probe": 1})
        except RuntimeError:
            check(False, "health handler must pass while collector is running")
        # a stopped collector must flip /health to failure
        c.stop()
        try:
            handler({"probe": 1})
            check(False, "health handler must fail when collector is stopped")
        except RuntimeError:
            pass
        # http=None keeps the old UDP-only contract (no HTTP requirement)
        health = ws1.build_health_handlers(udp=_FakeUDP(), http=None)
        health[ws1._HEALTH_TOPIC][1]({"probe": 1})
    finally:
        c.stop()

    # -- run_all_tests wiring: this file must be referenced -------------------------
    gate = (SERVICES.parent / "run_all_tests.sh").read_text(encoding="utf-8")
    check("test_http_json_ingest.py" in gate,
          "test_http_json_ingest.py is not wired into run_all_tests.sh")

    print(f"ran in {time.time() - t0:.1f}s")
    if FAILS:
        print("[FAIL] ws1 HTTP/JSON ingest contract test")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] ws1 HTTP/JSON ingest contract test")


if __name__ == "__main__":
    run()
