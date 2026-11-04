"""WS-1 TCP syslog listener contract test (WP-1.2) -- zero infrastructure.

Drives the real ``SyslogTCPServer`` (ephemeral 127.0.0.1 port) against the
in-memory bus and pins the RFC 6587 acceptance criteria:

  * newline framing: whole frames, CRLF, frames split across reads, empty
    frames counted (not dropped-as-failed), oversize frame -> connection
    rejected + counted;
  * octet-counting framing: header + body arriving in any split, several
    frames per packet, tolerated trailing LF, non-digit / over-cap length ->
    rejected;
  * partial reads and slow clients: a connection that trickles bytes is
    served (no worker pinned -- per-connection thread + bounded slots), an
    idle connection is closed by timeout;
  * many concurrent connections; per-source rate limit shared with the UDP
    path (same dispatcher); spool fallback on bus failure; partition key and
    event shape identical to the UDP path.
"""
from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"

from shared.bus import Bus  # noqa: E402
from collectors.syslog_tcp_server import (  # noqa: E402
    SyslogTCPServer, FRAMING_NEWLINE, FRAMING_OCTET)
from collectors.spool import BoundedSpool  # noqa: E402


def _wait_for(cond, timeout_s=10.0, step=0.05):
    """Poll ``cond()`` until true; raise AssertionError on timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(step)
    raise AssertionError(f"condition not met within {timeout_s}s")


def _connect(port: int) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.settimeout(5)
    return s


class _FakeBusFail:
    def produce(self, topic, key, payload):
        raise ConnectionError("redis unreachable (test)")


class TestNewlineFraming(unittest.TestCase):
    def setUp(self):
        self.bus = Bus()
        self.server = SyslogTCPServer(self.bus, host="127.0.0.1", port=0,
                                      framing=FRAMING_NEWLINE,
                                      deterministic_id=True)
        self.server.start()
        self.addCleanup(self.server.stop)

    def _send(self, data: bytes):
        s = _connect(self.server.port)
        try:
            s.sendall(data)
        finally:
            s.close()

    def test_two_frames_in_one_write(self):
        self._send(b"line one\nline two\n")
        _wait_for(lambda: self.server.events_produced >= 2, timeout_s=10)
        msgs = self.bus.drain("raw.events")
        self.assertEqual(len(msgs), 2)
        self.assertEqual([m.payload["raw"] for m in msgs],
                         ["line one", "line two"])
        # partition key = peer IP, meta shape identical to the UDP path
        self.assertEqual(msgs[0].key, "127.0.0.1")
        self.assertEqual(msgs[0].payload["source_type"], "generic_syslog")
        self.assertIn("ingest_id", msgs[0].payload["meta"])
        self.assertIn("received_at", msgs[0].payload["meta"])

    def test_crlf_stripped(self):
        self._send(b"crlf line\r\n")
        _wait_for(lambda: self.server.events_produced >= 1, timeout_s=10)
        msgs = self.bus.drain("raw.events")
        self.assertEqual([m.payload["raw"] for m in msgs], ["crlf line"])

    def test_frame_split_across_reads(self):
        s = _connect(self.server.port)
        try:
            s.sendall(b"first half\nsec")
            time.sleep(0.2)
            s.sendall(b"ond half\n")
            _wait_for(lambda: self.server.events_produced >= 2,
                      timeout_s=10)
        finally:
            s.close()
        msgs = self.bus.drain("raw.events")
        self.assertEqual(sorted(m.payload["raw"] for m in msgs),
                         ["first half", "second half"])

    def test_byte_at_a_time_trickle(self):
        # A slow sender must not pin or starve the listener.
        s = _connect(self.server.port)
        try:
            for byte in b"trickle line\n":
                s.sendall(bytes([byte]))
                time.sleep(0.01)
            _wait_for(lambda: self.server.events_produced >= 1, timeout_s=10)
        finally:
            s.close()
        msgs = self.bus.drain("raw.events")
        self.assertEqual([m.payload["raw"] for m in msgs], ["trickle line"])

    def test_empty_frames_are_counted_not_failed(self):
        # Gap-hunt #81 semantics: empty payloads count events_empty, never
        # events_dropped (an empty line is not a bus outage).
        self._send(b"\n\n")
        _wait_for(lambda: self.server.events_empty >= 2, timeout_s=10)
        self.assertEqual(self.server.events_empty, 2)
        self.assertEqual(self.server.events_dropped, 0)

    def test_oversize_frame_rejects_connection(self):
        self.server = SyslogTCPServer(self.bus, host="127.0.0.1", port=0,
                                      framing=FRAMING_NEWLINE,
                                      max_frame_bytes=16)
        self.server.start()
        self.addCleanup(self.server.stop)
        big = b"x" * 100
        s = _connect(self.server.port)
        try:
            s.sendall(big)          # no newline yet, over the 16-byte cap
            _wait_for(lambda: self.server.events_frame_oversize >= 1,
                      timeout_s=10)
            # connection must be closed by the server
            self.assertEqual(s.recv(1), b"")
        finally:
            s.close()
        self.assertEqual(self.server.events_produced, 0)

    def test_oversize_frame_with_newline_rejects(self):
        self.server = SyslogTCPServer(self.bus, host="127.0.0.1", port=0,
                                      framing=FRAMING_NEWLINE,
                                      max_frame_bytes=16)
        self.server.start()
        self.addCleanup(self.server.stop)
        s = _connect(self.server.port)
        try:
            s.sendall(b"y" * 100 + b"\n")
            _wait_for(lambda: self.server.events_frame_oversize >= 1,
                      timeout_s=10)
        finally:
            s.close()
        self.assertEqual(self.server.events_produced, 0)

    def test_metrics_exposes_shared_event_counters(self):
        # /metrics must show the TCP transport's share of the SHARED dispatcher
        # counters (tcp_events_*) -- without them TCP-produced events are
        # invisible while flowing to the bus (live-verified bug).
        self._send(b"metric line\n")
        _wait_for(lambda: self.server.events_produced >= 1, timeout_s=10)
        m = self.server.metrics()
        self.assertEqual(m["tcp_events_produced"], 1)
        self.assertEqual(m["tcp_events_dropped"], 0)
        for key in ("tcp_syslog_conn_accepted", "tcp_syslog_conn_closed",
                    "tcp_events_empty"):
            self.assertIn(key, m)

    def test_rate_limit_sheds_without_breaking_connection(self):
        self.server = SyslogTCPServer(self.bus, host="127.0.0.1", port=0,
                                      framing=FRAMING_NEWLINE,
                                      max_events_per_sec=1,
                                      deterministic_id=True)
        self.server.start()
        self.addCleanup(self.server.stop)
        s = _connect(self.server.port)
        try:
            s.sendall(b"first\nsecond\n")
            _wait_for(lambda: self.server.events_shed >= 1, timeout_s=10)
            # connection still alive: one accepted, one shed, total accounted
            self.assertGreaterEqual(self.server.events_produced +
                                    self.server.events_shed, 2)
        finally:
            s.close()


class TestOctetCounting(unittest.TestCase):
    def setUp(self):
        self.bus = Bus()
        self.server = SyslogTCPServer(self.bus, host="127.0.0.1", port=0,
                                      framing=FRAMING_OCTET,
                                      deterministic_id=True)
        self.server.start()
        self.addCleanup(self.server.stop)

    def test_two_frames_in_one_packet(self):
        s = _connect(self.server.port)
        try:
            s.sendall(b"5 hello6 world2")
        finally:
            s.close()
        _wait_for(lambda: self.server.events_produced >= 2, timeout_s=10)
        msgs = self.bus.drain("raw.events")
        self.assertEqual(sorted(m.payload["raw"] for m in msgs),
                         ["hello", "world2"])

    def test_header_and_body_split_across_reads(self):
        s = _connect(self.server.port)
        try:
            s.sendall(b"10 abcdef")
            time.sleep(0.2)
            s.sendall(b"ghij")
            _wait_for(lambda: self.server.events_produced >= 1, timeout_s=10)
        finally:
            s.close()
        msgs = self.bus.drain("raw.events")
        self.assertEqual([m.payload["raw"] for m in msgs], ["abcdefghij"])

    def test_length_field_split_across_reads(self):
        s = _connect(self.server.port)
        try:
            s.sendall(b"1")
            time.sleep(0.2)
            s.sendall(b"5 xyz")
            time.sleep(0.2)
            s.sendall(b"0123456789ab")   # 15 chars after "15 "
            _wait_for(lambda: self.server.events_produced >= 1, timeout_s=10)
        finally:
            s.close()
        msgs = self.bus.drain("raw.events")
        self.assertEqual([m.payload["raw"] for m in msgs], ["xyz0123456789ab"])

    def test_trailing_newline_tolerated(self):
        s = _connect(self.server.port)
        try:
            s.sendall(b"4 abcd\n5 efghi")   # LF after first msg is interop
        finally:
            s.close()
        _wait_for(lambda: self.server.events_produced >= 2, timeout_s=10)
        msgs = self.bus.drain("raw.events")
        self.assertEqual(sorted(m.payload["raw"] for m in msgs), ["abcd", "efghi"])

    def test_oversize_length_rejects(self):
        s = _connect(self.server.port)
        try:
            s.sendall(b"999999 x")
            _wait_for(lambda: self.server.events_frame_oversize >= 1,
                      timeout_s=10)
        finally:
            s.close()

    def test_non_numeric_header_rejects(self):
        s = _connect(self.server.port)
        try:
            s.sendall(b"abc xyz")
            _wait_for(lambda: self.server.events_frame_oversize >= 1,
                      timeout_s=10)
        finally:
            s.close()


class TestConnections(unittest.TestCase):
    def test_many_concurrent_connections(self):
        bus = Bus()
        server = SyslogTCPServer(bus, host="127.0.0.1", port=0,
                                 max_connections=64)
        server.start()
        self.addCleanup(server.stop)
        errors = []

        def worker(n):
            try:
                s = _connect(server.port)
                try:
                    s.sendall(f"conn {n} line\n".encode())
                finally:
                    s.close()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
        _wait_for(lambda: server.events_produced >= 16, timeout_s=15)
        self.assertEqual(errors, [])
        self.assertEqual(server.events_produced, 16)

    def test_max_connections_refuses_excess(self):
        bus = Bus()
        server = SyslogTCPServer(bus, host="127.0.0.1", port=0,
                                 max_connections=1)
        server.start()
        self.addCleanup(server.stop)
        a = _connect(server.port)
        try:
            _wait_for(lambda: server.events_conn_accepted >= 1, timeout_s=10)
            b = _connect(server.port)   # must be refused (closed at accept)
            try:
                _wait_for(lambda: server.events_conn_refused >= 1, timeout_s=10)
                self.assertEqual(b.recv(1), b"", "refused conn must be closed")
            finally:
                b.close()
        finally:
            a.close()

    def test_idle_connection_closed_by_timeout(self):
        bus = Bus()
        server = SyslogTCPServer(bus, host="127.0.0.1", port=0,
                                 idle_timeout_s=0.3)
        server.start()
        self.addCleanup(server.stop)
        s = _connect(server.port)
        try:
            # send nothing; the server must close the idle connection
            _wait_for(lambda: server.events_idle_closed >= 1, timeout_s=10)
        finally:
            s.close()

    def test_spool_fallback_on_bus_failure(self):
        with tempfile.TemporaryDirectory() as td:
            spool = BoundedSpool(Path(td) / "spool.jsonl", max_bytes=1 << 20)
            server = SyslogTCPServer(_FakeBusFail(), host="127.0.0.1", port=0,
                                     spool=spool)
            server.start()
            try:
                s = _connect(server.port)
                try:
                    s.sendall(b"a\nb\n")
                finally:
                    s.close()
                _wait_for(lambda: server.events_spooled >= 2, timeout_s=10)
                self.assertEqual(server.events_dropped, 0)
                self.assertEqual(spool.pending_count(), 2)
            finally:
                server.stop()


if __name__ == "__main__":
    unittest.main(verbosity=1)