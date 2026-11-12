"""WS-1 HTTP ingest spool DRAIN test -- zero infrastructure.

The HTTP edge's BoundedSpool wrote spool files when the bus was down but,
unlike the UDP and TCP syslog loops, nothing ever replayed them. The
per-listener drain loop (`http-json-spool-drain` thread) fixes that. This test
pins the loop's contract, including the failure modes the PR #166 review found:

  1. bus down -> POST 202, events land in the spool, NOT the bus; drain
     attempts while the bus is down lose and duplicate nothing;
  2. bus up -> every spooled event is replayed and the spool empties;
  3. the drain INTERVAL IS HONORED (the first version waited on an already-set
     event and spun: thousands of passes per second, ~92% of a core);
  4. delivery is AT-LEAST-ONCE: a crash mid-drain replays events again, but
     checkpointing bounds that window to `checkpoint_every`, and nothing is lost;
  5. replayed duplicates collapse downstream: WS-2 keeps `meta.ingest_id` as
     `siem.ingest_id` and WS-3 indexes on it, so a replay stores ONE document;
  6. an event the bus keeps rejecting is dead-lettered instead of wedging the
     spool, while a plain outage is NOT mistaken for poison;
  7. a stuck spool is visible: failed-pass counter and spool gauges in metrics().

Runs the real HttpJsonCollector (threaded server on 127.0.0.1:$EPHEMERAL)
against a flappable in-memory bus stand-in.
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
os.environ["BUS_BACKEND"] = "memory"
# ws1 first, then ws3 / ws2: later inserts win, and WS-2's `main` must shadow
# WS-1's `main` for the dedupe test (the other modules do not collide).
for _p in (SERVICES, HERE, SERVICES / "ws3-indexer", SERVICES / "ws2-normalization"):
    sys.path.insert(0, str(_p))

from collectors.http_json_collector import (  # noqa: E402
    HttpJsonCollector, REGISTERED_SOURCE_TYPES)
from collectors.spool import BoundedSpool  # noqa: E402

if "windows_eventlog" not in REGISTERED_SOURCE_TYPES:
    raise SystemExit("windows_eventlog must be a registered source type")

FAILS: list[str] = []
_TOKEN = "test-ingest-token-000"
# EventID 4688 (process create) is owned by the windows_eventlog parser, so it
# normalizes to a real OCSF event for the downstream-dedupe test.
RECORD_A = {"EventID": 4688, "TimeCreated": 1750000000000,
            "Computer": "wks-jdoe", "SubjectUserName": "jdoe",
            "SubjectDomainName": "BANKCORP",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "NewProcessId": "0x1f4"}
RECORD_B = dict(RECORD_A, NewProcessId="0x2a0", TimeCreated=1750000001000)
_DRAIN_INTERVAL = 0.05


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _FlappableBus:
    """Memory-shaped bus whose produce() fails while `down` is set.

    `reject` (optional predicate on the payload) makes produce() fail for those
    payloads only, whatever `down` says: a deterministic poison event.
    """

    def __init__(self, down=True, reject=None):
        self.down = down
        self.reject = reject
        self.produced: list[tuple] = []
        self.attempts = 0

    def produce(self, topic, key, payload):
        self.attempts += 1
        if self.down:
            raise RuntimeError("simulated bus outage")
        if self.reject is not None and self.reject(payload):
            raise ValueError("simulated bus rejection of this payload")
        self.produced.append((topic, key, payload))


def _start_collector(bus, spool_dir, interval=_DRAIN_INTERVAL):
    spool = BoundedSpool(str(Path(spool_dir) / "http-spool.jsonl"))
    c = HttpJsonCollector(bus, ingest_token=_TOKEN, host="127.0.0.1", port=0,
                          spool=spool, spool_drain_interval_s=interval)
    c.start()
    return c, f"127.0.0.1:{c.port}", spool


def _post(hostport, path, body=b"", *, token=_TOKEN):
    conn = http.client.HTTPConnection(hostport, timeout=10)
    try:
        conn.request("POST", path, body=body,
                     headers={"Authorization": f"Bearer {token}"})
        resp = conn.getresponse()
        data = resp.read()
        try:
            parsed = json.loads(data) if data else {}
        except json.JSONDecodeError:
            parsed = {"_raw": data.decode("utf-8", "replace")}
        return resp.status, parsed
    finally:
        conn.close()


def _ndjson(records):
    return "\n".join(json.dumps(r) for r in records).encode()


def _wait_for(pred, timeout_s=3.0, step=0.02):
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        if pred():
            return True
        time.sleep(step)
    return pred()


_INGEST = "/v1/ingest?source_type=windows_eventlog&format=ndjson"


def test_bus_down_then_up_spooled_events_are_replayed():
    with tempfile.TemporaryDirectory() as td:
        bus = _FlappableBus()
        c, hp, spool = _start_collector(bus, td)
        try:
            status, body = _post(hp, _INGEST, _ndjson([RECORD_A, RECORD_B]))
            check(status == 202, f"bus down must 202 (spooled), got {status}")
            check(body.get("spooled") == 2, f"spooled count must be 2, got {body}")
            check(bus.produced == [], "bus down: nothing must reach the bus")
            check(spool.pending_count() == 2,
                  f"spool must hold 2 events, has {spool.pending_count()}")

            # bus STILL down: drain attempts fail, nothing lost, nothing dupped
            time.sleep(_DRAIN_INTERVAL * 4)
            check(bus.produced == [], "bus still down: no event may be delivered")
            check(spool.pending_count() == 2, "bus still down: spool must not change")
            check(spool.dead_lettered == 0,
                  "a plain outage must NOT dead-letter anything")
            check(c.metrics()["http_spool_drain_failed_passes"] >= 1,
                  "failed drain passes during an outage must be counted")

            bus.down = False
            check(_wait_for(lambda: len(bus.produced) == 2),
                  f"bus up: both events must arrive, got {len(bus.produced)}")
            check({t for t, _, _ in bus.produced} == {"raw.events"}, "wrong topic")
            check(len({k for _, k, _ in bus.produced}) == 1,
                  "both events must share one partition key (the peer)")
            payloads = [p for _, _, p in bus.produced]
            check(all(p["source_type"] == "windows_eventlog" for p in payloads),
                  "replayed events must keep source_type")
            check(len({p["meta"]["ingest_id"] for p in payloads}) == 2,
                  "replayed events must keep their distinct ingest_ids")
            check(_wait_for(lambda: spool.pending_count() == 0),
                  f"spool must be empty after drain, has {spool.pending_count()}")
            # an undisturbed run does not replay twice
            time.sleep(_DRAIN_INTERVAL * 4)
            check(len(bus.produced) == 2,
                  f"no re-replay in a clean run, got {len(bus.produced)} total")
            m = c.metrics()
            check(m["http_spool_replayed"] == 2, f"replayed gauge: {m}")
            check(m["http_spool_pending_bytes"] == 0, f"pending bytes gauge: {m}")
        finally:
            c.stop()
    # restart: stop() then start() must bring the drain thread back
    with tempfile.TemporaryDirectory() as td:
        bus = _FlappableBus(down=True)
        c, hp, spool = _start_collector(bus, td)
        try:
            c.stop()
            check(c._spool_thread is None, "stop() must tear the drain thread down")
            c.start()
            check(c._spool_thread is not None and c._spool_thread.is_alive(),
                  "start() after stop() must restart the drain thread")
            _post(f"127.0.0.1:{c.port}", _INGEST, _ndjson([RECORD_A]))
            bus.down = False
            check(_wait_for(lambda: len(bus.produced) == 1),
                  "restarted collector must drain its spool")
        finally:
            c.stop()


def test_drain_interval_is_honored():
    """Regression for F166-1: the loop waited on an already-set event, so it
    never slept (2216 passes in 2 s at a 5 s interval). With a 0.25 s interval
    a 1.2 s window allows ~5 passes; the old code did thousands."""
    with tempfile.TemporaryDirectory() as td:
        bus = _FlappableBus(down=True)
        c, hp, spool = _start_collector(bus, td, interval=0.25)
        try:
            _post(hp, _INGEST, _ndjson([RECORD_A]))
            p0, a0 = c.spool_drain_passes, bus.attempts
            time.sleep(1.2)
            passes, attempts = c.spool_drain_passes - p0, bus.attempts - a0
            check(passes <= 8, f"drain loop spinning: {passes} passes in 1.2 s "
                               f"at a 0.25 s interval")
            check(attempts <= 40, f"drain loop spinning: {attempts} produce "
                                  f"attempts in 1.2 s at a 0.25 s interval")
            t0 = time.time()
            c.stop()
            check(time.time() - t0 < 2.0,
                  "stop() must interrupt the interval sleep, not wait it out")
        finally:
            c.stop()


def test_crash_mid_drain_is_at_least_once_and_bounded():
    """F166-2: a hard crash replays already-delivered events (at-least-once).
    Without checkpointing the whole snapshot replays; with it, at most
    `checkpoint_every`. Nothing is ever lost."""
    total, crash_at = 300, 270

    def run(checkpoint_every):
        with tempfile.TemporaryDirectory() as td:
            sp = BoundedSpool(str(Path(td) / "s.jsonl"))
            for i in range(total):
                sp.append({"key": "k", "event": {"i": i}})
            first: list[int] = []

            def produce(item):
                if len(first) == crash_at:
                    # BaseException: stands in for SIGKILL -- no cleanup, no rewrite
                    raise SystemExit("simulated crash")
                first.append(item["event"]["i"])

            try:
                sp.drain_into(produce, checkpoint_every=checkpoint_every)
            except SystemExit:
                pass
            second: list[int] = []
            sp2 = BoundedSpool(str(Path(td) / "s.jsonl"))      # "restart"
            sp2.drain_into(lambda it: second.append(it["event"]["i"]),
                           checkpoint_every=checkpoint_every)
            return first, second, sp2.pending_count()

    first, second, pending = run(None)
    dups = len(set(first) & set(second))
    check(set(first) | set(second) == set(range(total)), "legacy drain lost events")
    check(dups == crash_at, f"unbounded drain: expected {crash_at} dups "
                            f"(documents the at-least-once window), got {dups}")
    check(pending == 0, "spool must be empty after the restart drain")

    first, second, pending = run(30)
    dups = len(set(first) & set(second))
    check(set(first) | set(second) == set(range(total)),
          "checkpointed drain lost events")
    check(dups <= 30, f"checkpoint_every=30 must bound duplicates to <=30, got {dups}")
    check(pending == 0, "spool must be empty after the restart drain")

    # appends racing the drain must survive a checkpoint rewrite
    with tempfile.TemporaryDirectory() as td:
        sp = BoundedSpool(str(Path(td) / "s.jsonl"))
        for i in range(10):
            sp.append({"key": "k", "event": {"i": i}})
        got: list[int] = []

        def produce2(item):
            got.append(item["event"]["i"])
            if len(got) == 3:       # an append lands mid-drain, before a checkpoint
                sp.append({"key": "k", "event": {"i": 99}})

        sp.drain_into(produce2, checkpoint_every=2)
        check(got[:10] == list(range(10)), f"FIFO order broken: {got}")
        check(99 not in got or sp.pending_count() == 0,
              "late append must be either delivered or still spooled")
        rest: list[int] = []
        sp.drain_into(lambda it: rest.append(it["event"]["i"]))
        check(sorted(set(got) | set(rest)) == list(range(10)) + [99],
              f"mid-drain append lost: got={got} rest={rest}")


def test_replayed_duplicates_collapse_downstream():
    """F166-2 data effect: WS-1 replay preserves meta.ingest_id, WS-2 turns it
    into siem.ingest_id, WS-3 routes on it. Replaying the same raw event
    stores exactly one document."""
    from main import normalize_one                  # WS-2 (see sys.path order)
    from router import route                        # WS-3
    from storage.memory import MemoryStore          # WS-3

    with tempfile.TemporaryDirectory() as td:
        bus = _FlappableBus(down=True)
        c, hp, spool = _start_collector(bus, td)
        try:
            _post(hp, _INGEST, _ndjson([RECORD_A, RECORD_B]))
            bus.down = False
            check(_wait_for(lambda: len(bus.produced) == 2), "setup: replay failed")
        finally:
            c.stop()
        raws = [p for _, _, p in bus.produced]

    store = MemoryStore()
    docs = 0
    for raw in raws + raws:           # every raw event delivered TWICE (a replay)
        event, errs = normalize_one(raw)
        check(event is not None and not errs, f"raw event must normalize: {errs}")
        if event is None:
            continue
        index, doc_id = route(event)
        store.index(index, doc_id, event)
        docs += 1
        check(doc_id == raw["meta"]["ingest_id"],
              "WS-3 doc id must be the replayed event's ingest_id")
    stored = sum(store.count(i) for i in store.indices())
    check(docs == 4, f"setup: expected 4 deliveries, got {docs}")
    check(stored == 2, f"replayed duplicates must collapse to 2 docs, got {stored}")


def test_poison_event_is_dead_lettered_but_outage_is_not():
    """F166-4: an event the bus rejects must not wedge the spool, and a bus
    that is merely down must never dead-letter anything."""
    with tempfile.TemporaryDirectory() as td:
        sp = BoundedSpool(str(Path(td) / "s.jsonl"))
        for i in range(6):
            sp.append({"key": "k", "event": {"i": i}})
        # outage: everything fails -> nothing dead-lettered, spool intact
        def down(_item):
            raise RuntimeError("bus down")
        replayed = sp.drain_into(down, skip_poison=True)
        check(replayed == 0, "outage: nothing may be replayed")
        check(sp.pending_count() == 6, "outage: spool must be intact")
        check(sp.dead_lettered == 0 and not sp.dead_letter_path.exists(),
              "outage must not dead-letter")
        check(sp.produce_failures >= 1 and sp.last_produce_error,
              "outage must be recorded in produce_failures/last_produce_error")

        # poison: event 2 is always rejected, the rest go through
        delivered: list[int] = []

        def picky(item):
            if item["event"]["i"] == 2:
                raise ValueError("bus rejects this payload")
            delivered.append(item["event"]["i"])

        replayed = sp.drain_into(picky, skip_poison=True)
        check(delivered == [0, 1, 3, 4, 5], f"all but the poison event: {delivered}")
        check(replayed == 5, f"replayed count: {replayed}")
        check(sp.pending_count() == 0, "spool must drain past the poison event")
        check(sp.dead_lettered == 1, f"one dead-letter expected: {sp.dead_lettered}")
        dead = [json.loads(x) for x in
                sp.dead_letter_path.read_text(encoding="utf-8").splitlines()]
        check(dead == [{"key": "k", "event": {"i": 2}}], f"dead-letter file: {dead}")

        # without skip_poison the legacy behaviour (stop at the head) is unchanged
        sp3 = BoundedSpool(str(Path(td) / "t.jsonl"))
        for i in range(3):
            sp3.append({"key": "k", "event": {"i": i}})
        seen: list[int] = []

        def picky0(item):
            if item["event"]["i"] == 0:
                raise ValueError("no")
            seen.append(item["event"]["i"])

        check(sp3.drain_into(picky0) == 0 and seen == [] and sp3.pending_count() == 3,
              "default drain_into must still stop at the first failure")


def test_poison_through_collector_end_to_end():
    with tempfile.TemporaryDirectory() as td:
        bus = _FlappableBus(
            down=True, reject=lambda p: p["raw"].get("NewProcessId") == "0x2a0")
        c, hp, spool = _start_collector(bus, td)
        try:
            _post(hp, _INGEST, _ndjson([RECORD_B, RECORD_A, RECORD_A]))
            bus.down = False
            check(_wait_for(lambda: spool.pending_count() == 0),
                  "spool must drain past the poison head")
            check(len(bus.produced) == 2, f"two good events expected: {len(bus.produced)}")
            m = c.metrics()
            check(m["http_spool_dead_lettered"] == 1, f"dead-letter metric: {m}")
        finally:
            c.stop()


def main():
    t0 = time.time()
    test_bus_down_then_up_spooled_events_are_replayed()
    test_drain_interval_is_honored()
    test_crash_mid_drain_is_at_least_once_and_bounded()
    test_replayed_duplicates_collapse_downstream()
    test_poison_event_is_dead_lettered_but_outage_is_not()
    test_poison_through_collector_end_to_end()
    if FAILS:
        print(f"[FAIL] ws1 http spool drain: {len(FAILS)} problem(s) "
              f"({time.time() - t0:.1f}s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print(f"[OK] WS-1 HTTP spool drain: replay on bus recovery, interval honored, "
          f"crash replay at-least-once and bounded, duplicates collapse on "
          f"ingest_id, poison dead-lettered, outage not ({time.time() - t0:.1f}s)")


if __name__ == "__main__":
    main()
