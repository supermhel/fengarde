"""Tests for the real UDP syslog listener (stdlib unittest, zero infra).

Binds the listener to 127.0.0.1 on an ephemeral port, sends a real syslog
datagram over a UDP socket, and asserts a correctly-shaped raw event lands on
``raw.events`` of an in-memory bus. Deterministic: ephemeral port (0), and the
bus is polled with a short timeout instead of a fixed sleep.
"""
from __future__ import annotations

import os
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(HERE))
os.environ["BUS_BACKEND"] = "memory"

from shared.bus import Bus  # noqa: E402
from collectors.syslog_udp_server import (  # noqa: E402
    SyslogUDPServer, build_raw_event, _TokenBucket)
from collectors.spool import BoundedSpool  # noqa: E402

SYSLOG_LINE = "<34>Oct 11 22:14:15 myhost sshd[1234]: Failed password for root"


def _poll(predicate, timeout=2.0, interval=0.01):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(interval)
    return predicate()


class TestSyslogUDPServer(unittest.TestCase):
    def setUp(self):
        self.bus = Bus()
        # port 0 -> OS picks an ephemeral free port; .port reflects the real one
        self.server = SyslogUDPServer(
            self.bus, host="127.0.0.1", port=0, deterministic_id=True)
        self.server.start()

    def tearDown(self):
        self.server.stop()

    def test_datagram_becomes_raw_event(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(SYSLOG_LINE.encode("utf-8"),
                        ("127.0.0.1", self.server.port))
        finally:
            sock.close()

        msgs = _poll(lambda: self.bus.drain("raw.events"))
        self.assertTrue(msgs, "no raw event landed on raw.events")
        self.assertEqual(len(msgs), 1)

        msg = msgs[0]
        payload = msg.payload
        self.assertEqual(payload["source_type"], "generic_syslog")
        self.assertEqual(payload["raw"], SYSLOG_LINE)
        self.assertIn("meta", payload)
        self.assertIn("received_at", payload["meta"])
        self.assertIn("ingest_id", payload["meta"])
        self.assertEqual(msg.key, "127.0.0.1")  # peer IP is the partition key

    def test_build_raw_event_shape(self):
        evt = build_raw_event("hello", deterministic_id=True)
        self.assertEqual(evt["source_type"], "generic_syslog")
        self.assertEqual(evt["raw"], "hello")
        self.assertIsInstance(evt["meta"]["received_at"], int)
        # deterministic id is stable for the same line
        self.assertEqual(evt["meta"]["ingest_id"],
                         build_raw_event("hello", deterministic_id=True)["meta"]["ingest_id"])


class TestTokenBucket(unittest.TestCase):
    def test_zero_rate_disables_limiting(self):
        b = _TokenBucket(0)
        self.assertTrue(all(b.take() for _ in range(1000)))

    def test_negative_rate_disables_limiting(self):
        b = _TokenBucket(-5)
        self.assertTrue(all(b.take() for _ in range(100)))

    def test_burst_up_to_capacity_then_sheds(self):
        b = _TokenBucket(10)  # capacity == rate == 10
        allowed = [b.take() for _ in range(20)]
        self.assertEqual(sum(allowed), 10, "only `rate` tokens available instantly")
        self.assertTrue(all(allowed[:10]) and not any(allowed[10:]))

    def test_refills_over_time(self):
        b = _TokenBucket(100)  # 100/sec -> refills fast enough to observe
        for _ in range(100):
            b.take()
        self.assertFalse(b.take(), "bucket should be empty immediately after draining")
        time.sleep(0.05)  # ~5 tokens' worth at 100/sec
        self.assertTrue(b.take(), "bucket should have refilled some tokens after a delay")


class TestSyslogUDPServerShedding(unittest.TestCase):
    def test_rate_limit_sheds_excess_datagrams(self):
        bus = Bus()
        server = SyslogUDPServer(bus, host="127.0.0.1", port=0,
                                 deterministic_id=True, max_events_per_sec=5)
        server.start()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                for i in range(20):
                    sock.sendto(f"line {i}".encode(), ("127.0.0.1", server.port))
            finally:
                sock.close()

            _poll(lambda: len(bus.drain("raw.events")) + server.events_shed >= 20,
                  timeout=2.0)
            self.assertLessEqual(len(bus.drain("raw.events")), 5,
                                 "burst of 20 against a rate of 5 must be mostly shed")
            self.assertGreater(server.events_shed, 0,
                               "some datagrams must be recorded as shed")
            self.assertEqual(len(bus.drain("raw.events")) + server.events_shed, 20,
                             "every datagram is accounted for: produced or shed, never silently lost")
        finally:
            server.stop()

    def test_unlimited_by_default_matches_prior_behavior(self):
        bus = Bus()
        server = SyslogUDPServer(bus, host="127.0.0.1", port=0, deterministic_id=True)
        server.start()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                for i in range(50):
                    sock.sendto(f"line {i}".encode(), ("127.0.0.1", server.port))
            finally:
                sock.close()
            _poll(lambda: len(bus.drain("raw.events")) >= 50, timeout=2.0)
            self.assertEqual(len(bus.drain("raw.events")), 50)
            self.assertEqual(server.events_shed, 0)
        finally:
            server.stop()


class TestBusDepth(unittest.TestCase):
    def test_memory_bus_depth(self):
        bus = Bus()
        self.assertEqual(bus.depth("raw.events"), 0, "untouched topic reads depth 0")
        bus.produce("raw.events", key="k", payload={"n": 1})
        bus.produce("raw.events", key="k", payload={"n": 2})
        self.assertEqual(bus.depth("raw.events"), 2)
        list(bus.consume("raw.events"))  # drains
        self.assertEqual(bus.depth("raw.events"), 0)


class TestBoundedSpool(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "spool.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def test_append_and_pending_count(self):
        spool = BoundedSpool(self.path, max_bytes=1_000_000)
        self.assertEqual(spool.pending_count(), 0)
        self.assertTrue(spool.append({"a": 1}))
        self.assertTrue(spool.append({"a": 2}))
        self.assertEqual(spool.pending_count(), 2)
        self.assertGreater(spool.pending_bytes(), 0)

    def test_append_refuses_once_full(self):
        spool = BoundedSpool(self.path, max_bytes=50)  # tiny cap
        appended = 0
        for i in range(100):
            if spool.append({"i": i, "pad": "x" * 10}):
                appended += 1
        self.assertGreater(appended, 0)
        self.assertLess(appended, 100, "spool must refuse once at capacity")
        # further appends of a larger-than-remaining-space event keep failing,
        # never raise
        self.assertFalse(spool.append({"i": "overflow", "pad": "x" * 100}))

    def test_drain_replays_in_fifo_order_and_empties(self):
        spool = BoundedSpool(self.path, max_bytes=1_000_000)
        for i in range(5):
            spool.append({"i": i})
        replayed = []
        count = spool.drain_into(lambda ev: replayed.append(ev["i"]))
        self.assertEqual(count, 5)
        self.assertEqual(replayed, [0, 1, 2, 3, 4], "must replay in FIFO order")
        self.assertEqual(spool.pending_count(), 0)

    def test_drain_stops_at_first_failure_preserving_order(self):
        spool = BoundedSpool(self.path, max_bytes=1_000_000)
        for i in range(5):
            spool.append({"i": i})

        def flaky(ev):
            if ev["i"] == 2:
                raise RuntimeError("still down")
            flaky.seen.append(ev["i"])
        flaky.seen = []

        count = spool.drain_into(flaky)
        self.assertEqual(count, 2, "only the two entries before the failure replay")
        self.assertEqual(flaky.seen, [0, 1])
        self.assertEqual(spool.pending_count(), 3,
                         "the failed entry and everything after it must remain, in order")

        # a second drain (simulating the outage clearing) replays the rest
        count2 = spool.drain_into(lambda ev: flaky.seen.append(ev["i"]))
        self.assertEqual(count2, 3)
        self.assertEqual(flaky.seen, [0, 1, 2, 3, 4])
        self.assertEqual(spool.pending_count(), 0)

    def test_drain_skips_corrupt_lines_without_blocking_the_rest(self):
        spool = BoundedSpool(self.path, max_bytes=1_000_000)
        spool.append({"i": 0})
        with self.path.open("a", encoding="utf-8") as f:
            f.write("not valid json\n")
        spool.append({"i": 1})
        replayed = []
        count = spool.drain_into(lambda ev: replayed.append(ev["i"]))
        self.assertEqual(count, 2)
        self.assertEqual(replayed, [0, 1])

    def test_append_refuses_when_volume_is_below_the_disk_headroom_floor(self):
        # M4.6: an impossible free-space floor against the REAL filesystem
        # (never mocked) -- proves BoundedSpool actually consults
        # shared.diskguard.check_disk_headroom(), not just its own max_bytes
        # cap, and fails closed (no write, no raise) rather than crashing
        # the UDP listener thread over a disk problem.
        spool = BoundedSpool(self.path, max_bytes=1_000_000, min_free_bytes=10**18, min_free_pct=0.0)
        self.assertFalse(spool.append({"i": 0}), "must refuse when the volume fails the headroom floor")
        self.assertEqual(spool.pending_count(), 0, "a disk-headroom refusal must not partially write")

        # With a trivial floor (the default-ish, easily satisfied by any
        # real disk this test runs on), the same spool accepts normally.
        spool_ok = BoundedSpool(self.path.parent / "ok.jsonl", max_bytes=1_000_000,
                                min_free_bytes=1, min_free_pct=0.0)
        self.assertTrue(spool_ok.append({"i": 0}))


class TestSyslogUDPServerSpoolFallback(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.spool_path = Path(self._tmp.name) / "spool.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def test_shed_events_land_in_spool_not_lost(self):
        spool = BoundedSpool(self.spool_path, max_bytes=1_000_000)
        bus = Bus()
        # very slow drain interval so the test can inspect the spool before
        # the background thread empties it back into the bus
        server = SyslogUDPServer(bus, host="127.0.0.1", port=0, deterministic_id=True,
                                 max_events_per_sec=5, spool=spool,
                                 spool_drain_interval_s=60)
        server.start()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                for i in range(20):
                    sock.sendto(f"line {i}".encode(), ("127.0.0.1", server.port))
            finally:
                sock.close()

            _poll(lambda: server.events_spooled >= 15, timeout=2.0)
            self.assertEqual(server.events_shed, 0,
                             "with a spool configured, rate-limited events go to the "
                             "spool, not the shed-and-lose counter")
            self.assertGreater(server.events_spooled, 0)
            total_accounted = (len(bus.drain("raw.events")) + server.events_spooled
                               + server.events_shed + server.events_lost)
            self.assertEqual(total_accounted, 20,
                             "every datagram is accounted for: produced, spooled, "
                             "shed, or lost -- never silently vanished")
        finally:
            server.stop()

    def test_spooled_events_get_replayed_into_the_bus(self):
        spool = BoundedSpool(self.spool_path, max_bytes=1_000_000)
        bus = Bus()
        server = SyslogUDPServer(bus, host="127.0.0.1", port=0, deterministic_id=True,
                                 max_events_per_sec=3, spool=spool,
                                 spool_drain_interval_s=0.05)
        server.start()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                for i in range(10):
                    sock.sendto(f"line {i}".encode(), ("127.0.0.1", server.port))
            finally:
                sock.close()

            # eventually every datagram lands on the bus: some directly
            # (under the rate), the rest via the drain thread replaying the spool
            _poll(lambda: len(bus.drain("raw.events")) >= 10, timeout=3.0)
            self.assertEqual(len(bus.drain("raw.events")), 10,
                             "all 10 datagrams eventually reach the bus with zero loss")
            self.assertEqual(spool.pending_count(), 0, "spool must drain to empty")
        finally:
            server.stop()

    def test_full_spool_still_loses_events_but_counts_them_distinctly(self):
        spool = BoundedSpool(self.spool_path, max_bytes=10)  # tiny: fills almost instantly
        bus = Bus()
        server = SyslogUDPServer(bus, host="127.0.0.1", port=0, deterministic_id=True,
                                 max_events_per_sec=1, spool=spool,
                                 spool_drain_interval_s=60)
        server.start()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                for i in range(20):
                    sock.sendto(f"line {i}".encode(), ("127.0.0.1", server.port))
            finally:
                sock.close()

            _poll(lambda: server.events_lost > 0, timeout=2.0)
            self.assertGreater(server.events_lost, 0,
                               "once the spool itself is full, events are truly lost "
                               "-- but distinctly counted, not silently merged into "
                               "the plain shed counter")
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
