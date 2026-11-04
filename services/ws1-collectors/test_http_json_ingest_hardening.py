"""Hardening tests for the HTTP/JSON ingest edge (review findings on PR 142).

Each case reproduces a defect found in review and pins the fix:
  1. a record with absurd nesting or a >4300-digit int is skipped, the batch survives (json-array: clean 400)
  2. Transfer-Encoding: chunked bodies are decoded (and still size-capped)
  3. a partial accept that a client may retry carries a note about the idempotency key
  4. a non-ASCII bearer token gets 401, not a dropped connection
  5. NDJSON splits on \\n only (a raw U+2028 inside a string stays one record)
  6. idle/slow connections cannot exceed the concurrency cap (extra ones get 503 at accept)
  7. extra (plugin) source types are accepted only when configured
  8. request counters stay exact under concurrent requests
  9. Bearer scheme is case-insensitive; query values are decoded once

Zero-infra (memory bus, ephemeral loopback port). Run: python services/ws1-collectors/test_http_json_ingest_hardening.py
"""
from __future__ import annotations

import http.client
import json
import socket
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from shared.bus import Bus  # noqa: E402
from collectors.http_json_collector import HttpJsonCollector  # noqa: E402

FAILS: list[str] = []
TOKEN = "test-ingest-token-000"
URL = "/v1/ingest?source_type=windows_eventlog"
REC = {"EventID": 4625, "Computer": "WIN-DEV-01"}


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def start(bus, **kw):
    c = HttpJsonCollector(bus, ingest_token=TOKEN, host="127.0.0.1", port=0, **kw)
    c.start()
    return c, c.port


def post(port, path, body=b"", headers=None, token=TOKEN, scheme="Bearer"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Authorization": f"{scheme} {token}"} if token is not None else {}
    h.update(headers or {})
    try:
        conn.request("POST", path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read()
        try:
            return r.status, json.loads(data) if data else {}
        except json.JSONDecodeError:
            return r.status, {"_raw": data.decode("utf-8", "replace")}
    finally:
        conn.close()


def raw(port, request: bytes, wait=True) -> bytes:
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(request)
    out = b""
    if wait:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    s.close()
    return out


def status_of(resp: bytes) -> int:
    return int(resp.split(b"\r\n", 1)[0].split()[1]) if resp else -1


def main() -> int:
    # 1. pathological JSON
    bus = Bus()
    c, port = start(bus)
    try:
        good = json.dumps(REC)
        deep = "[" * 200000
        huge = '{"EventID": ' + "9" * 5000 + "}"
        st, body = post(port, URL, f"{good}\n{deep}\n{huge}\n{good}".encode())
        check(st == 200 and body.get("accepted") == 2 and body.get("skipped") == 2,
              f"deep/huge-int lines must be skipped and the batch kept, got {st} {body}")
        st, body = post(port, URL + "&format=json-array", ("[" * 200000).encode())
        check(st == 400, f"json-array with absurd nesting must be a clean 400, got {st}")
        st, body = post(port, URL + "&format=json-array", ("[" + "9" * 5000 + "]").encode())
        check(st == 400, f"json-array with a >4300-digit int must be a clean 400, got {st}")

        # 2. chunked bodies
        payload = (json.dumps(REC) + "\n" + json.dumps(REC)).encode()
        half = len(payload) // 2
        chunked = (f"{half:x}\r\n".encode() + payload[:half] + b"\r\n" +
                   f"{len(payload) - half:x}\r\n".encode() + payload[half:] + b"\r\n0\r\n\r\n")
        req = (f"POST {URL} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {TOKEN}\r\n"
               "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n").encode() + chunked
        t0 = time.time()
        resp = raw(port, req)
        check(status_of(resp) == 200 and b'"accepted":2' in resp,
              f"chunked body must decode to 2 records, got {resp[:160]!r}")
        check(time.time() - t0 < 5, "a chunked request must not wait for the socket timeout")
        bad = (f"POST {URL} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {TOKEN}\r\n"
               "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\nzz\r\nabc\r\n0\r\n\r\n").encode()
        check(status_of(raw(port, bad)) == 400, "a malformed chunk size must be a 400")
    finally:
        c.stop()

    c, port = start(Bus(), max_body_bytes=64)
    try:
        big = b"A" * 200
        req = (f"POST {URL} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {TOKEN}\r\n"
               "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n").encode() + \
              f"{len(big):x}\r\n".encode() + big + b"\r\n0\r\n\r\n"
        check(status_of(raw(port, req)) == 413, "an oversized chunk must be refused with 413")
    finally:
        c.stop()

    # 3. partial accept note (rate limit after 1 record)
    c, port = start(Bus(), max_events_per_sec=1)
    try:
        body = (json.dumps(REC) + "\n" + json.dumps(REC) + "\n" + json.dumps(REC)).encode()
        st, resp = post(port, URL, body)
        check(st == 429 and resp.get("accepted", 0) >= 1 and "Idempotency-Key" in resp.get("note", ""),
              f"a partial accept must say how to retry safely, got {st} {resp}")
    finally:
        c.stop()

    # 4. non-ASCII token, 9. Bearer case + single decode
    c, port = start(Bus())
    try:
        req = (f"POST {URL} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer caf\xe9\r\n"
               "Content-Length: 0\r\nConnection: close\r\n\r\n").encode("latin-1")
        check(status_of(raw(port, req)) == 401, "a non-ASCII bearer token must get 401, not a dropped connection")
        st, _ = post(port, URL, json.dumps(REC).encode(), scheme="bearer")
        check(st == 200, f"lower-case 'bearer' scheme must be accepted, got {st}")
        st, resp = post(port, "/v1/ingest?source_type=%2577indows_eventlog", json.dumps(REC).encode())
        check(st == 400, f"query values must be decoded once (%2577 -> %77, not 'w'), got {st}")
        st, _ = post(port, "/v1/ingest?source_type=%77indows_eventlog", json.dumps(REC).encode())
        check(st == 200, f"a single percent-encoding must still work, got {st}")

        # 5. U+2028 inside a string
        bus5 = Bus()
    finally:
        c.stop()
    c, port = start(bus5)
    try:
        rec = {"EventID": 4625, "Message": "line one line two\u0085end"}
        st, resp = post(port, URL, (json.dumps(rec, ensure_ascii=False) + "\n").encode("utf-8"))
        msgs = bus5.drain("raw.events")
        check(st == 200 and resp.get("accepted") == 1 and resp.get("skipped") == 0 and len(msgs) == 1
              and msgs[0].payload["raw"]["Message"] == rec["Message"],
              f"a raw U+2028/U+0085 inside a JSON string must stay one record, got {st} {resp}")
    finally:
        c.stop()

    # 6. connection cap
    c, port = start(Bus(), max_concurrent=2)
    idle = []
    try:
        for _ in range(2):
            s = socket.create_connection(("127.0.0.1", port), timeout=10)
            idle.append(s)
        time.sleep(0.3)
        extra = raw(port, b"")
        check(status_of(extra) == 503, f"a connection over the cap must get 503 at accept, got {extra[:60]!r}")
    finally:
        for s in idle:
            s.close()
        c.stop()

    # 7. extra source types
    c, port = start(Bus(), extra_source_types=("acme_fw",))
    try:
        st, _ = post(port, "/v1/ingest?source_type=acme_fw", json.dumps(REC).encode())
        check(st == 200, f"a configured extra source type must be accepted, got {st}")
    finally:
        c.stop()
    c, port = start(Bus())
    try:
        st, _ = post(port, "/v1/ingest?source_type=acme_fw", json.dumps(REC).encode())
        check(st == 400, f"an unconfigured source type must be 400, got {st}")
    finally:
        c.stop()

    # 8. exact counters under concurrency
    c, port = start(Bus(), max_concurrent=64)
    try:
        def hammer():
            for _ in range(25):
                post(port, URL, b"{}", token="wrong")
        ts = [threading.Thread(target=hammer) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        check(c.metrics()["http_requests_4xx"] == 200,
              f"200 rejected requests must be counted exactly, got {c.metrics()['http_requests_4xx']}")
    finally:
        c.stop()

    if FAILS:
        print(f"[FAIL] ws1 HTTP ingest hardening: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        return 1
    print("[OK] ws1 HTTP ingest hardening: pathological JSON, chunked bodies, retry note, non-ASCII token, "
          "U+2028 records, connection cap, extra source types, exact counters, Bearer case, single decode")
    return 0


if __name__ == "__main__":
    sys.exit(main())
