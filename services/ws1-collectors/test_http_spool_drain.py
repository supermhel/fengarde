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


def test_review_edge_cases():
    """Second PR #166 review: long poison runs, undecodable bytes, concurrent
    drains and a full disk must not wedge or lose spooled events."""
    import errno
    import threading
    with tempfile.TemporaryDirectory() as td:
        # 4 consecutive poison events ahead of good ones: the probe window widens.
        sp = BoundedSpool(str(Path(td) / "p.jsonl"))
        for i in range(6):
            sp.append({"key": "k", "event": {"i": i}})
        got: list[int] = []

        def picky(item):
            if item["event"]["i"] < 4:
                raise ValueError("poison")
            got.append(item["event"]["i"])

        for _ in range(4):
            sp.drain_into(picky, skip_poison=True)
        check(got == [4, 5] and sp.pending_count() == 0 and sp.dead_lettered == 4,
              f"4-poison run must not wedge: got={got} pending={sp.pending_count()} "
              f"dead={sp.dead_lettered}")

        # one invalid UTF-8 byte: skipped as corrupt, the rest drains
        bad = Path(td) / "u.jsonl"
        bad.write_bytes(b'{"key":"k","event":{"i":1}}\n\xff\xfe junk\n{"key":"k","event":{"i":2}}\n')
        sp2 = BoundedSpool(str(bad))
        seen: list[int] = []
        try:
            n = sp2.pending_count()
            sp2.drain_into(lambda it: seen.append(it["event"]["i"]))
        except Exception as exc:  # noqa: BLE001
            n = -1
            check(False, f"undecodable byte raised {type(exc).__name__}: {exc}")
        check(n == 3 and seen == [1, 2] and sp2.pending_count() == 0
              and sp2.corrupt_lines_skipped == 1,
              f"undecodable line: count={n} seen={seen} corrupt={sp2.corrupt_lines_skipped}")

        # concurrent drains while appending: nothing lost
        sp3 = BoundedSpool(str(Path(td) / "c.jsonl"))
        delivered: set[int] = set()
        lock = threading.Lock()

        def slow(item):
            time.sleep(0.001)
            with lock:
                delivered.add(item["event"]["i"])

        stop = threading.Event()

        def drainer():
            while not stop.is_set():
                sp3.drain_into(slow)

        ths = [threading.Thread(target=drainer) for _ in range(2)]
        for t in ths:
            t.start()
        for i in range(300):
            sp3.append({"key": "k", "event": {"i": i}})
        time.sleep(0.2)
        stop.set()
        for t in ths:
            t.join()
        sp3.drain_into(slow)
        check(delivered == set(range(300)) and sp3.pending_count() == 0,
              f"concurrent drains lost {300 - len(delivered)} event(s)")

        # full disk on rewrite: falls back to an in-place shrink, no re-delivery
        sp4 = BoundedSpool(str(Path(td) / "d.jsonl"))
        for i in range(5):
            sp4.append({"key": "k", "event": {"i": i}})

        def enospc(*_a, **_k):
            raise OSError(errno.ENOSPC, "No space left on device")

        import collectors.spool as spool_mod
        real_mkstemp = spool_mod.tempfile.mkstemp
        spool_mod.tempfile.mkstemp = enospc  # the temp copy can never be created
        out: list[int] = []
        try:
            for _ in range(2):
                try:
                    sp4.drain_into(lambda it: out.append(it["event"]["i"]), checkpoint_every=2)
                except OSError:
                    pass  # the collector loop swallows this and retries
            again = len(out) - 5
        finally:
            spool_mod.tempfile.mkstemp = real_mkstemp
        check(out == [0, 1, 2, 3, 4] and again == 0 and sp4.pending_count() == 0,
              f"disk-full rewrite must shrink the spool: out={out} again={again}")


def test_lone_poison_and_dead_letter_redrive():
    """A lone event the bus keeps refusing is parked after LONE_POISON_PASSES
    passes, and parked events are sent again once the bus takes them."""
    with tempfile.TemporaryDirectory() as td:
        sp = BoundedSpool(str(Path(td) / "l.jsonl"))
        sp.append({"key": "k", "event": {"i": 0}})

        def refuse(_item):
            raise RuntimeError("bus refuses")

        for _ in range(BoundedSpool.LONE_POISON_PASSES - 1):
            sp.drain_into(refuse, skip_poison=True)
        check(sp.pending_count() == 1 and sp.dead_lettered == 0,
              "lone event must not be parked before LONE_POISON_PASSES passes")
        sp.drain_into(refuse, skip_poison=True)
        check(sp.pending_count() == 0 and sp.dead_lettered == 1,
              f"lone poison must be parked: pending={sp.pending_count()} dead={sp.dead_lettered}")

        # redrive: the parked good event goes through, a real poison one stays
        sp.dead_letter_path.write_text(
            sp.dead_letter_path.read_text(encoding="utf-8") + '{"key":"k","event":{"i":99}}\n',
            encoding="utf-8")
        sent: list[int] = []

        def picky(item):
            if item["event"]["i"] == 99:
                raise ValueError("still poison")
            sent.append(item["event"]["i"])

        check(sp.redrive_dead_letter(refuse) == 0, "redrive with a refusing bus sends nothing")
        n = sp.redrive_dead_letter(picky)
        left = [json.loads(x)["event"]["i"]
                for x in sp.dead_letter_path.read_text(encoding="utf-8").splitlines()]
        check(n == 1 and sent == [0] and left == [99] and sp.dead_letter_redriven == 1,
              f"redrive: n={n} sent={sent} left={left}")
        sp.redrive_dead_letter(lambda it: sent.append(it["event"]["i"]))
        check(not sp.dead_letter_path.exists(), "empty .dead must be removed after full redrive")

    # end to end: the collector re-sends .dead after a clean pass
    with tempfile.TemporaryDirectory() as td:
        bus = _FlappableBus(down=False)
        spool_path = Path(td) / "http-spool.jsonl"
        spool_path.with_name(spool_path.name + ".dead").write_text(
            json.dumps({"key": "k", "event": {"raw": RECORD_A}}) + "\n", encoding="utf-8")
        spool = BoundedSpool(str(spool_path))
        c = HttpJsonCollector(bus, ingest_token=_TOKEN, host="127.0.0.1", port=0,
                              spool=spool, spool_drain_interval_s=_DRAIN_INTERVAL)
        c.dead_redrive_every_s = 0
        c.start()
        try:
            check(_wait_for(lambda: not spool.dead_letter_path.exists()
                            and c.metrics()["http_spool_dead_letter_redriven"] == 1),
                  "collector must re-send .dead once the bus is up")
            check(len(bus.produced) == 1 and c.metrics()["http_spool_dead_letter_redriven"] == 1,
                  f"redriven via collector: produced={len(bus.produced)} m={c.metrics()}")
        finally:
            c.stop()


def _seed(sp, n):
    for i in range(n):
        sp.append({"key": "k", "event": {"i": i}})


def _spool_ids(sp):
    return [json.loads(x)["event"]["i"]
            for x in sp.path.read_text(encoding="utf-8").splitlines() if x.strip()]


def _dead_ids(sp):
    if not sp.dead_letter_path.exists():
        return []
    return [json.loads(x)["event"]["i"]
            for x in sp.dead_letter_path.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_dead_letter_refusal_keeps_event_in_spool():
    """PR #166 re-review: a .dead write that fails (or hits the cap) must not
    delete the poison event from the spool: it stays, the pass stops, and it is
    parked once .dead accepts writes again."""
    def picky(got):
        def produce(item):
            if item["event"]["i"] < 2:
                raise ValueError("poison")
            got.append(item["event"]["i"])
        return produce

    # unwritable .dead (a directory squats on the path)
    with tempfile.TemporaryDirectory() as td:
        sp = BoundedSpool(str(Path(td) / "u.jsonl"))
        _seed(sp, 4)
        sp.dead_letter_path.mkdir()
        got: list[int] = []
        sp.drain_into(picky(got), skip_poison=True)
        left = _spool_ids(sp)
        check(0 in left and 1 in left, f"unwritable .dead: poison must stay in spool, left={left}")
        check(getattr(sp, "dead_letter_write_failures", 0) >= 1,
              f"unwritable .dead: failure must be counted: {sp.__dict__.get('dead_letter_write_failures')}")
        check(sorted(set(got) | {x for x in left if x >= 2}) == [2, 3],
              f"unwritable .dead: no good event lost: got={got} left={left}")
        sp.dead_letter_path.rmdir()
        for _ in range(3):
            sp.drain_into(picky(got), skip_poison=True)
        check(sorted(set(got)) == [2, 3] and _dead_ids(sp) == [0, 1] and _spool_ids(sp) == [],
              f"after .dead recovers: got={got} dead={_dead_ids(sp)} spool={_spool_ids(sp)}")

    # .dead at its cap
    with tempfile.TemporaryDirectory() as td:
        sp = BoundedSpool(str(Path(td) / "c.jsonl"), max_bytes=4000)
        _seed(sp, 4)
        sp.dead_letter_path.write_bytes(b"x" * 3990 + b"\n")
        got = []
        sp.drain_into(picky(got), skip_poison=True)
        left = _spool_ids(sp)
        check(0 in left and 1 in left,
              f"at-cap .dead: poison must stay in spool, left={left}")
        check(getattr(sp, "dead_letter_write_failures", 0) >= 1, "at-cap .dead: refusal must be counted")


def test_poison_run_longer_than_probe_cap_drains():
    """PR #166 re-review: 257+ consecutive poison events must still be passed
    (stateful probe cursor), within a bounded number of passes."""
    with tempfile.TemporaryDirectory() as td:
        sp = BoundedSpool(str(Path(td) / "r.jsonl"), max_bytes=10 * 1024 * 1024)
        _seed(sp, 301)
        got: list[int] = []

        def produce(item):
            if item["event"]["i"] < 300:
                raise ValueError("poison")
            got.append(item["event"]["i"])

        passes = 0
        while passes < 40 and not got:
            sp.drain_into(produce, skip_poison=True)
            passes += 1
        check(got == [300] and passes <= 20,
              f"300 poison then 1 good: got={got} passes={passes}")
        check(len(_dead_ids(sp)) == 300 and sp.pending_count() == 0,
              f"all 300 parked, spool empty: dead={len(_dead_ids(sp))} pending={sp.pending_count()}")

    # a real outage with a long backlog must NOT park anything
    with tempfile.TemporaryDirectory() as td:
        sp = BoundedSpool(str(Path(td) / "o.jsonl"), max_bytes=10 * 1024 * 1024)
        _seed(sp, 300)

        def down(_item):
            raise RuntimeError("bus down")

        for _ in range(30):
            sp.drain_into(down, skip_poison=True)
        check(sp.pending_count() == 300 and sp.dead_lettered == 0,
              f"outage parked events: pending={sp.pending_count()} dead={sp.dead_lettered}")


def test_redrive_disk_full_and_cap():
    """PR #166 re-review: redrive on a full disk must not re-send twice, and
    one call must attempt a bounded number of lines."""
    with tempfile.TemporaryDirectory() as td:
        sp = BoundedSpool(str(Path(td) / "d.jsonl"))
        sp.dead_letter_path.write_text(
            "".join(json.dumps({"key": "k", "event": {"i": i}}) + "\n" for i in range(4)),
            encoding="utf-8")
        real = sp._rewrite_atomic

        def full(lines, target=None):
            raise OSError(28, "No space left on device")

        sp._rewrite_atomic = full
        sent: list[int] = []

        def produce(item):
            if item["event"]["i"] == 3:
                raise ValueError("still poison")
            sent.append(item["event"]["i"])

        try:
            n = sp.redrive_dead_letter(produce)
        except OSError as exc:
            n = -1
            check(False, f"redrive raised on a full disk: {exc}")
        sp._rewrite_atomic = real
        sp.redrive_dead_letter(produce)
        check(n == 3 and sorted(sent) == [0, 1, 2] and _dead_ids(sp) == [3],
              f"redrive on full disk re-sent: n={n} sent={sent} dead={_dead_ids(sp)}")

    with tempfile.TemporaryDirectory() as td:
        sp = BoundedSpool(str(Path(td) / "k.jsonl"))
        sp.REDRIVE_MAX_LINES = 5
        sp.dead_letter_path.write_text(
            "".join(json.dumps({"key": "k", "event": {"i": i}}) + "\n" for i in range(13)),
            encoding="utf-8")
        attempts: list[int] = []
        sent = []

        def produce2(item):
            attempts.append(item["event"]["i"])
            if item["event"]["i"] < 12:
                raise ValueError("poison")
            sent.append(item["event"]["i"])

        sp.redrive_dead_letter(produce2)
        check(len(attempts) <= 5, f"one redrive call attempted {len(attempts)} lines (cap 5)")
        for _ in range(4):
            sp.redrive_dead_letter(produce2)
        check(sent == [12], f"capped redrive starved the tail: sent={sent}")
        check(sorted(_dead_ids(sp)) == list(range(12)),
              f"poison must remain parked: {_dead_ids(sp)}")


class _SlowDownBus:
    """produce() sleeps (client connect/retry timeout) then raises; counts attempts."""

    def __init__(self, delay=0.2):
        self.delay = delay
        self.attempts = 0

    def produce(self, topic, key, payload):
        self.attempts += 1
        time.sleep(self.delay)
        raise ConnectionError("simulated redis connection refused")


def test_bus_down_batch_spools_fast_and_flag_skips_bus():
    with tempfile.TemporaryDirectory() as td:
        bus = _SlowDownBus(delay=0.2)
        # no drain interference: interval far longer than the test
        c, hp, spool = _start_collector(bus, td, interval=3600)
        try:
            batch = _ndjson([dict(RECORD_A, NewProcessId=hex(i)) for i in range(50)])
            t0 = time.time()
            st, body = _post(hp, _INGEST, batch)
            took = time.time() - t0
            check(st == 202 and body.get("spooled") == 50,
                  f"50-event outage batch must 202 with all spooled: {st} {body}")
            check(took < 2.0, f"outage batch must not pay a timeout per event: {took:.1f}s")
            check(bus.attempts == 1,
                  f"only the first produce may touch the bus, got {bus.attempts}")
            st2, body2 = _post(hp, _INGEST, _ndjson([RECORD_A, RECORD_B]))
            check(st2 == 202 and body2.get("spooled") == 2 and bus.attempts == 1,
                  f"next batch must skip the bus while flagged: {st2} {body2} "
                  f"attempts={bus.attempts}")
            m = c.metrics()
            check(m["http_events_spooled"] == 52 and m["http_events_dropped"] == 0
                  and m["http_spool_pending_events"] == 52,
                  f"counters/gauge must match 52 spooled: {m}")
            # flag lapses -> the bus is tried again
            c._bus_down_until = 0.0
            _post(hp, _INGEST, _ndjson([RECORD_A]))
            check(bus.attempts == 2, f"after the hold lapses the bus is retried: {bus.attempts}")
        finally:
            c.stop()


def test_payload_rejection_does_not_flag_bus_down():
    with tempfile.TemporaryDirectory() as td:
        bus = _FlappableBus(down=False, reject=lambda p: p["raw"].get("NewProcessId") == "0xbad")
        c, hp, spool = _start_collector(bus, td, interval=3600)
        try:
            bad = dict(RECORD_A, NewProcessId="0xbad")
            st, body = _post(hp, _INGEST, _ndjson([bad, RECORD_A, RECORD_B]))
            m = c.metrics()
            check(m["http_events_spooled"] == 1 and m["http_events_accepted"] == 2,
                  f"one rejected payload spools, the rest go to the bus: {st} {body} {m}")
        finally:
            c.stop()


def test_pending_gauge_is_live_not_a_stale_snapshot():
    # PR #166 live run: http_spool_pending_events=14 while http_events_spooled=15. The gauge was the
    # line count at the END OF THE LAST DRAIN PASS; an event spooled after that pass was invisible
    # until the next pass. It is now counted live (non-blank lines).
    with tempfile.TemporaryDirectory() as td:
        bus = _FlappableBus(down=True)
        c, hp, spool = _start_collector(bus, td, interval=0.05)
        try:
            check(_wait_for(lambda: c.spool_drain_passes >= 1), "drain pass must run")
            c._spool_stop.set()        # freeze the loop: no further snapshot refresh
            time.sleep(0.2)
            _post(hp, _INGEST, _ndjson([RECORD_A, RECORD_B]))
            m = c.metrics()
            check(m["http_events_spooled"] == 2 and m["http_spool_pending_events"] == 2,
                  f"gauge must see events spooled after the last pass: {m}")
        finally:
            c.stop()


def main():
    t0 = time.time()
    test_bus_down_batch_spools_fast_and_flag_skips_bus()
    test_payload_rejection_does_not_flag_bus_down()
    test_pending_gauge_is_live_not_a_stale_snapshot()
    test_dead_letter_refusal_keeps_event_in_spool()
    test_poison_run_longer_than_probe_cap_drains()
    test_redrive_disk_full_and_cap()
    test_bus_down_then_up_spooled_events_are_replayed()
    test_drain_interval_is_honored()
    test_crash_mid_drain_is_at_least_once_and_bounded()
    test_replayed_duplicates_collapse_downstream()
    test_poison_event_is_dead_lettered_but_outage_is_not()
    test_poison_through_collector_end_to_end()
    test_review_edge_cases()
    test_lone_poison_and_dead_letter_redrive()
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
