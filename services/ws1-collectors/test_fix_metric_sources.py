"""FENGARDE E6: per-source syslog metrics (bounded per-IP produced/dropped/shed).

Covers the per-source breakdown added alongside the aggregate counters in
``collectors/syslog_udp_server.py`` (``_count_peer`` / ``per_source_metrics`` /
``_peer_metrics_max``). It drives ``SyslogUDPServer._handle_datagram`` directly
with a stub ``produce`` (no socket, no threads) so the per-IP accounting is
deterministic and fast, and asserts:

1. per-source counters increment correctly when datagrams arrive from
   different peer IPs;
2. the per-source map stays bounded (never exceeds the cap, and LRU-evicts
   the oldest entry when a new IP overflows it);
3. the aggregate counters still match the per-source sum when no eviction has
   occurred (the totals are authoritative, the map is a visibility partition).

No infra: this is a standalone ``check()``-style unittest script.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(HERE))
os.environ["BUS_BACKEND"] = "memory"

from collectors.syslog_udp_server import (  # noqa: E402
    SyslogUDPServer, DEFAULT_PEER_METRICS_MAX)


class _FakeBus:
    """Minimal stand-in for shared.bus.Bus: just records produces (or raises)."""

    def __init__(self, fail: bool = False):
        self.fail = fail
        self.produced = 0

    def produce(self, topic, key, payload) -> None:
        if self.fail:
            raise RuntimeError("bus down")
        self.produced += 1


def _make_server(self, bus, *, rate: float = 0,
                 peer_metrics_max: int = DEFAULT_PEER_METRICS_MAX):
    server = SyslogUDPServer(
        bus, host="127.0.0.1", port=0, deterministic_id=True,
        max_events_per_sec=rate, peer_metrics_max=peer_metrics_max)
    self.addCleanup(server.stop)  # closes the bound socket
    return server


class TestPerSourceMetrics(unittest.TestCase):
    def test_per_source_produced_increments_per_ip(self):
        bus = _FakeBus()
        server = _make_server(self, bus)  # rate 0: everything produced
        # 5 datagrams from A, 3 from B
        for i in range(5):
            server._handle_datagram(f"A line {i}".encode(), "10.0.0.1")
        for i in range(3):
            server._handle_datagram(f"B line {i}".encode(), "10.0.0.2")

        ps = server.per_source_metrics()
        self.assertEqual(ps["10.0.0.1"]["produced"], 5)
        self.assertEqual(ps["10.0.0.2"]["produced"], 3)
        self.assertEqual(ps["10.0.0.1"]["dropped"], 0)
        self.assertEqual(ps["10.0.0.2"]["shed"], 0)
        # aggregate totals the per-source produced
        self.assertEqual(server.events_produced, 8)
        self.assertEqual(bus.produced, 8)

    def test_per_source_shed_increments_per_ip(self):
        bus = _FakeBus()
        server = _make_server(self, bus, rate=5)  # burst of 5 allowed, rest shed
        # 20 from A, 10 from B -> 30 total, at most 10 produced
        for i in range(20):
            server._handle_datagram(f"A line {i}".encode(), "10.0.0.1")
        for i in range(10):
            server._handle_datagram(f"B line {i}".encode(), "10.0.0.2")

        ps = server.per_source_metrics()
        self.assertEqual(ps["10.0.0.1"]["produced"] + ps["10.0.0.1"]["shed"], 20,
                         "every A datagram is accounted for (produced or shed)")
        self.assertEqual(ps["10.0.0.2"]["produced"] + ps["10.0.0.2"]["shed"], 10,
                         "every B datagram is accounted for")
        # per-source shed must sum to the aggregate shed counter
        shed_sum = sum(m["shed"] for m in ps.values())
        self.assertEqual(shed_sum, server.events_shed)
        self.assertGreater(server.events_shed, 0, "rate limit must actually shed")

    def test_per_source_dropped_increments_per_ip(self):
        bus = _FakeBus(fail=True)  # produce raises -> dropped
        server = _make_server(self, bus)
        for i in range(4):
            server._handle_datagram(f"A line {i}".encode(), "10.0.0.1")
        for i in range(2):
            server._handle_datagram(f"B line {i}".encode(), "10.0.0.2")

        ps = server.per_source_metrics()
        self.assertEqual(ps["10.0.0.1"]["dropped"], 4)
        self.assertEqual(ps["10.0.0.2"]["dropped"], 2)
        drop_sum = sum(m["dropped"] for m in ps.values())
        self.assertEqual(drop_sum, server.events_dropped)
        self.assertEqual(server.events_dropped, 6)

    def test_map_stays_bounded_and_lru_evicts_oldest(self):
        bus = _FakeBus()
        server = _make_server(self, bus, peer_metrics_max=4)
        # 6 distinct IPs -> cap of 4 -> the two oldest must be evicted
        for i in range(6):
            server._handle_datagram(f"line {i}".encode(), f"10.0.{i // 255}.{i % 255}")

        ps = server.per_source_metrics()
        self.assertLessEqual(len(ps), 4, "bounded map must never exceed the cap")
        # the last 4 IPs survive; the first two are the LRU -> evicted
        surviving = {f"10.0.{i // 255}.{i % 255}" for i in (2, 3, 4, 5)}
        self.assertEqual(set(ps.keys()), surviving)
        # aggregates still count ALL 6 -- eviction is visibility-only
        self.assertEqual(server.events_produced, 6)
        self.assertEqual(bus.produced, 6)

    def test_lru_recency_update(self):
        # Touching an existing IP must refresh its recency so it is NOT the
        # next evicted -- proving true LRU, not plain cap-with-oldest-drop.
        bus = _FakeBus()
        server = _make_server(self, bus, peer_metrics_max=3)
        for i in range(3):
            server._handle_datagram(f"line {i}".encode(), f"10.0.0.{i + 1}")
        # refresh IP .2 (now most recent), then add a 4th IP -> evicts .1 (oldest)
        server._handle_datagram("more".encode(), "10.0.0.2")
        server._handle_datagram("new".encode(), "10.0.0.4")

        ps = server.per_source_metrics()
        self.assertNotIn("10.0.0.1", ps, "oldest (never re-touched) source evicted")
        self.assertIn("10.0.0.2", ps, "recently-touched source must survive")
        self.assertIn("10.0.0.4", ps)
        self.assertEqual(len(ps), 3)

    def test_aggregate_matches_per_source_sum(self):
        # Mixed produced/dropped/shed across several IPs, all within the cap,
        # so NO eviction: aggregate must exactly equal the per-source sum.
        bus = _FakeBus()  # drop none, shed some
        server = _make_server(self, bus, rate=5)
        for i in range(6):   # 5 produced + 1 shed
            server._handle_datagram(f"A {i}".encode(), "10.0.0.1")
        for i in range(3):   # 3 produced
            server._handle_datagram(f"B {i}".encode(), "10.0.0.2")
        for i in range(8):   # 5 produced + 3 shed
            server._handle_datagram(f"C {i}".encode(), "10.0.0.3")

        ps = server.per_source_metrics()
        self.assertEqual(
            server.events_produced, sum(m["produced"] for m in ps.values()))
        self.assertEqual(
            server.events_shed, sum(m["shed"] for m in ps.values()))
        self.assertEqual(
            server.events_dropped, sum(m["dropped"] for m in ps.values()))
        total = (server.events_produced + server.events_shed
                 + server.events_dropped)
        self.assertEqual(total, 17, "every datagram accounted for")


if __name__ == "__main__":
    unittest.main(verbosity=2)
