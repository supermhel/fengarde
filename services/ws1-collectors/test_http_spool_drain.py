"""WS-1 HTTP ingest spool DRAIN test (2026-11-06) -- zero infrastructure.

The HTTP edges' BoundedSpool wrote spool files when the bus was down but,
unlike the UDP and TCP syslog loops, nothing ever replayed them: entries sat
in the spool forever (and, once the cap was reached, all further events were
dropped despite the spool being configured). This test proves the new
per-listener drain loop (`http-json-spool-drain` thread) mirrors the syslog
loops' contract:

  * bus down -> POST accepted with 202, events land in the spool, NOT the bus;
  * while the bus stays down, drain attempts fail and NOTHING is lost or
    duplicated (spool count unchanged);
  * bus comes back up -> the loop replays the spool into the bus;
  * each spooled event arrives EXACTLY ONCE (drain_into's FIFO rewrite is
    at-most-once; an extra wait proves no re-replay duplicates);
  * spool is empty afterwards, and stop() tears the drain thread down.

Runs the real HttpJsonCollector (threaded server on 127.0.0.1:$EPHEMERAL)
against a flappable in-memory bus stand-in; short drain interval (0.05s) so
the test is fast instead of waiting on the 5s production default.
"""
from __future__ import annotations

import http.client
import json
import os
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent                       # .../services (for `shared`)
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"

from collectors.http_json_collector import (  # noqa: E402
    HttpJsonCollector, REGISTERED_SOURCE_TYPES)
from collectors.spool import BoundedSpool  # noqa: E402

if "windows_eventlog" not in REGISTERED_SOURCE_TYPES:
    raise SystemExit("windows_eventlog must be a registered source type")

FAILS: list[str] = []
_TOKEN = "test-ingest-token-000"
RECORD_A = {"EventID": 4625, "TimeCreated": "2026-11-04T12:00:01.000Z"}
RECORD_B = {"EventID": 4634, "TimeCreated": "2026-11-04T12:00:02.000Z"}
_DRAIN_INTERVAL = 0.05


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _FlappableBus:
    """Memory-shaped bus with a produce() that fails while `down` is set.

    Records everything the collector successfully produced so the test can
    assert exact-once delivery.
    """

    def __init__(self):
        self.down = True
        self.produced: list[tuple] = []

    def produce(self, topic, key, payload):
        if self.down:
            raise RuntimeError("simulated bus outage")
        self.produced.append((topic, key, payload))


def _start_collector(bus, spool_dir):
    tmp = Path(spool_dir)
    spool = BoundedSpool(str(tmp / "http-spool.jsonl"))
    c = HttpJsonCollector(bus, ingest_token=_TOKEN, host="127.0.0.1", port=0,
                          spool=spool, spool_drain_interval_s=_DRAIN_INTERVAL)
    c.start()
    return c, f"127.0.0.1:{c.port}", spool


def _post(hostport, path, body=b"", *, token=_TOKEN):
    conn = http.client.HTTPConnection(hostport, timeout=10)
    try:
        conn.request("POST", path, body=body,
                     headers={"Authorization": f"Bearer {token}"})
        resp = conn.getresponse()
        data = resp.read()
        parsed = {}
        try:
            parsed = json.loads(data) if data else {}
        except json.JSONDecodeError:
            parsed = {"_raw": data.decode("utf-8", "replace")}
        return resp.status, parsed
    finally:
        conn.close()


def _ndjson(records):
    return "\n".join(json.dumps(r) for r in records).encode()


def _wait_for(pred, timeout_s=3.0, step=0.05):
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        if pred():
            return True
        time.sleep(step)
    return pred()


def test_bus_down_then_up_spooled_events_arrive_once():
    with tempfile.TemporaryDirectory() as td:
        bus = _FlappableBus()
        c, hp, spool = _start_collector(bus, td)
        try:
            # 1) bus down: the batch is accepted for later delivery
            status, body = _post(
                hp, "/v1/ingest?source_type=windows_eventlog&format=ndjson",
                _ndjson([RECORD_A, RECORD_B]))
            check(status == 202, f"bus down must 202 (spooled), got {status}")
            check(body.get("spooled") == 2, f"spooled count must be 2, got {body}")
            check(bus.produced == [], "bus down: nothing must reach the bus")
            check(spool.pending_count() == 2,
                  f"spool must hold 2 events, has {spool.pending_count()}")

            # 2) bus STILL down: drain attempts fail, nothing lost, nothing dupped
            time.sleep(_DRAIN_INTERVAL * 4)
            check(bus.produced == [],
                  "bus still down: drain attempts must not deliver events")
            check(spool.pending_count() == 2,
                  "bus still down: spool count must not change")

            # 3) bus up: the drain loop replays the spool, exactly once
            bus.down = False
            check(_wait_for(lambda: len(bus.produced) == 2),
                  f"bus up: both spooled events must arrive, got {len(bus.produced)}")
            topics = {t for t, _, _ in bus.produced}
            check(topics == {"raw.events"}, f"wrong topics: {topics}")
            keys = {k for _, k, _ in bus.produced}
            check(len(keys) == 1, "both events must share one partition key (the peer)")
            payloads = [p for _, _, p in bus.produced]
            check(all(p["source_type"] == "windows_eventlog" for p in payloads),
                  "replayed events must keep source_type")
            ids = {p["meta"]["ingest_id"] for p in payloads}
            check(len(ids) == 2, "replayed events must keep their distinct ingest_ids")
            check(spool.pending_count() == 0,
                  f"spool must be empty after drain, has {spool.pending_count()}")

            # 4) extra wait: no second replay (at-most-once)
            time.sleep(_DRAIN_INTERVAL * 4)
            check(len(bus.produced) == 2,
                  f"events must arrive EXACTLY once, got {len(bus.produced)} total")
            check(spool.pending_count() == 0,
                  "spool must stay empty after the replay")
        finally:
            c.stop()


def main():
    t0 = time.time()
    test_bus_down_then_up_spooled_events_arrive_once()
    if FAILS:
        print(f"[FAIL] ws1 http spool drain: {len(FAILS)} problem(s) "
              f"({time.time() - t0:.1f}s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print(f"[OK] WS-1 HTTP spool drain: bus down -> 202 spooled, bus up -> "
          f"replayed exactly once (at-most-once, spool empty) ({time.time() - t0:.1f}s)")


if __name__ == "__main__":
    main()