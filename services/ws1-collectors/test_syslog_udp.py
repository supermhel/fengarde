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


if __name__ == "__main__":
    unittest.main()
