"""Regression tests for FIX 20 + FIX 21 (syslog UDP counters + deterministic id).

Covers the two infra/docs-agent fixes in ``collectors/syslog_udp_server.py``:

- FIX 20: the ``events_produced`` / ``events_spooled`` / ``events_dropped``
  increments in ``_handle_datagram`` are now taken under ``self._shed_lock`` so 4
  concurrent worker threads can't lose updates. Zero-infra, so we drive
  ``_handle_datagram`` directly with a fake bus from many threads and assert the
  counter exactly reflects every produced/spooled/dropped datagram.
- FIX 21 (reverted 2026-08-06): a prior version hardcoded
  ``deterministic_id=True`` in ``_handle_datagram`` regardless of the
  constructor flag, on the theory that "UDP retransmission is normal" (it
  isn't -- UDP has no retransmission mechanism). That collapsed N distinct
  repeated log lines (e.g. N separate brute-force attempts logging the exact
  same "Failed password" text) to ONE content-hash ``meta.ingest_id``, and
  WS-4's stateful window counters dedup by that id -- so the threshold rule
  silently never fired. ``_handle_datagram`` now honors ``self.deterministic_id``
  like every other ``build_raw_event`` caller; these tests assert the flag is
  RESPECTED, not that identical lines are forced to dedup.

``python services/ws1-collectors/test_fix_counters_deterministic.py``
"""
from __future__ import annotations

import os
import sys
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(HERE))
os.environ["BUS_BACKEND"] = "memory"

from collectors.syslog_udp_server import (  # noqa: E402
    SyslogUDPServer, build_raw_event)


class _FakeBus:
    """Records every produced payload; optionally raises to force the drop path."""

    def __init__(self, fail_produce=False):
        self.produced = []
        self.fail = fail_produce
        self._lock = threading.Lock()

    def produce(self, topic, key, payload):
        if self.fail:
            raise ConnectionError("redis unreachable (test)")
        with self._lock:
            self.produced.append(payload)


class _RecordingSpool:
    """A BoundedSpool stand-in whose append() always succeeds."""

    def __init__(self):
        self.items = []

    def append(self, item):
        self.items.append(item)
        return True

    def pending_count(self):
        return len(self.items)


class TestCountersUnderLock(unittest.TestCase):
    def _spawn_server(self, **kw):
        server = SyslogUDPServer(
            _FakeBus(), host="127.0.0.1", port=0, **kw)
        return server

    def _close(self, server):
        # Server never started; just release its bound socket to avoid a
        # ResourceWarning from the constructor's socket.
        try:
            server._sock.close()
        except OSError:
            pass

    def test_events_produced_reflects_every_produce(self):
        bus = _FakeBus()
        server = SyslogUDPServer(bus, host="127.0.0.1", port=0)
        # Direct-drive 4 "workers" like the real worker pool does.
        lines = [f"line-{i}" for i in range(200)]
        threads = []
        for t in range(4):
            def work(offset=t):
                for i in range(offset, len(lines), 4):
                    server._handle_datagram(lines[i].encode(), "10.0.0.1")
            th = threading.Thread(target=work)
            th.start()
            threads.append(th)
        for th in threads:
            th.join()
        self._close(server)
        self.assertEqual(server.events_produced, 200,
                         "every produced datagram must be counted exactly once")
        self.assertEqual(len(bus.produced), 200,
                         "bus must receive exactly one produce per datagram")
        self.assertEqual(server.events_dropped, 0)
        self.assertEqual(server.events_spooled, 0)

    def test_events_spooled_incremented_under_lock(self):
        bus = _FakeBus(fail_produce=True)  # produce always fails -> spool path
        spool = _RecordingSpool()
        server = SyslogUDPServer(bus, host="127.0.0.1", port=0, spool=spool)
        for i in range(50):
            server._handle_datagram(f"line-{i}".encode(), "10.0.0.1")
        self._close(server)
        self.assertEqual(server.events_spooled, 50)
        self.assertEqual(len(spool.items), 50)
        self.assertEqual(server.events_dropped, 0)

    def test_events_dropped_incremented_under_lock(self):
        bus = _FakeBus(fail_produce=True)
        server = SyslogUDPServer(bus, host="127.0.0.1", port=0, spool=None)
        for i in range(30):
            server._handle_datagram(f"line-{i}".encode(), "10.0.0.1")
        self._close(server)
        self.assertEqual(server.events_dropped, 30)
        self.assertEqual(server.events_produced, 0)
        self.assertEqual(server.events_spooled, 0)

    def test_counters_hold_lock_while_incrementing(self):
        # Structural: each increment is inside the shared _shed_lock context.
        # We assert the attribute exists (the real concurrency guarantee is
        # exercised above across 4 threads) and that a produce advances it.
        server = self._spawn_server()
        self.assertTrue(hasattr(server, "_shed_lock"))
        server._handle_datagram(b"hello world", "10.0.0.1")
        self.assertEqual(server.events_produced, 1)
        self._close(server)


class TestDeterministicUdpIngestId(unittest.TestCase):
    def test_build_raw_event_deterministic_stable(self):
        a = build_raw_event("same line", deterministic_id=True)
        b = build_raw_event("same line", deterministic_id=True)
        self.assertEqual(a["meta"]["ingest_id"], b["meta"]["ingest_id"])
        different = build_raw_event("different line", deterministic_id=True)
        self.assertNotEqual(a["meta"]["ingest_id"],
                            different["meta"]["ingest_id"])

    def test_handle_datagram_honors_deterministic_id_false(self):
        # FIX 21 (reverted): deterministic_id=False (the default) must give
        # every datagram its OWN random ingest_id, even when the line text is
        # byte-identical -- two separate "Failed password" attempts from an
        # attacker are two separate events, not one deduped event. This is
        # the property that keeps WS-4's stateful window counters (which dedup
        # by meta.ingest_id) able to count repeated identical log lines.
        bus = _FakeBus()
        server = SyslogUDPServer(bus, host="127.0.0.1", port=0,
                                 deterministic_id=False)
        for _ in range(5):
            server._handle_datagram(b"Failed password for admin from 1.2.3.4",
                                    "10.0.0.1")
        server._sock.close()
        self.assertEqual(len(bus.produced), 5)
        ids = {p["meta"]["ingest_id"] for p in bus.produced}
        self.assertEqual(len(ids), 5,
                         "identical-text datagrams must each get a distinct "
                         "ingest_id when deterministic_id=False, so a real "
                         "burst of repeated log lines is not silently "
                         "collapsed into one window-counter member")

    def test_handle_datagram_honors_deterministic_id_true(self):
        # Opt-in dedup: when a deployment explicitly wants content-hash
        # dedup (deterministic_id=True), identical lines DO share one id --
        # the flag is honored in both directions, never hardcoded.
        bus = _FakeBus()
        server = SyslogUDPServer(bus, host="127.0.0.1", port=0,
                                 deterministic_id=True)
        server._handle_datagram(b"same content", "10.0.0.1")
        server._handle_datagram(b"same content", "10.0.0.1")
        server._sock.close()
        ids = {p["meta"]["ingest_id"] for p in bus.produced}
        self.assertEqual(len(ids), 1,
                         "deterministic_id=True must still content-hash-dedup "
                         "when a deployment explicitly opts in")
        self.assertEqual(
            ids.pop(),
            build_raw_event("same content",
                            deterministic_id=True)["meta"]["ingest_id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
