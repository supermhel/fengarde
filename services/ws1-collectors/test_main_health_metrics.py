"""WS-1 main.py health + metrics wiring regressions (gap-hunt round 4).

Covers the three main.py fixes:

- #70: main() used to call ``serve({}, ...)`` with an EMPTY handler map, so
  zero runner worker threads started and the runner's HealthState (only ever
  flipped by those workers) stayed permanently "ok" -- /health was a hardcoded
  200 forever, even with the bus unreachable and the UDP ingest daemon dead.
  Fix: WS-1 now passes a REAL handler map (``build_health_handlers``), so the
  runner starts a worker; a bus outage now reports 503. Tests assert the map is
  non-empty, and that serve() with a healthy bus reports 200 while a broken
  bus reports 503.
- #71/#76: ``_syslog_metrics`` nested everything under ``{"syslog_udp": {...}}``
  and render_prometheus only renders top-level NUMERIC leaves, so /metrics/prom
  emitted ZERO WS-1 gauges (structurally valid, simply empty). Fix: the metrics
  dict is now FLAT; tests assert the flat keys exist and that
  render_prometheus() emits real gauge lines for them.

Standalone unittest script, zero infra (memory bus), run from the service dir.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
import unittest
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(HERE))
os.environ["BUS_BACKEND"] = "memory"

import main as ws1  # noqa: E402
from shared.bus import Bus  # noqa: E402
from shared import runner  # noqa: E402


class _FakeUDP:
    """Minimal stand-in for SyslogUDPServer exposing just what
    build_health_handlers() / _syslog_metrics() touch."""

    def __init__(self, is_running=True):
        self._running = is_running
        self.events_produced = 10
        self.events_dropped = 2
        self.events_shed = 3
        self.events_spooled = 1
        self.events_lost = 0
        self.events_queue_full = 0
        self.events_empty = 4
        self.recv_oserror_total = 1

    def is_running(self):
        return self._running

    def per_source_metrics(self):
        return {"10.0.0.1": {"produced": 10, "dropped": 2, "shed": 3, "empty": 0}}

    def seconds_since_last_event(self):
        return 1.5


class TestBuildHealthHandlers(unittest.TestCase):
    """#70: WS-1 must hand the runner a REAL handler map, not serve({})."""

    def test_map_is_non_empty(self):
        handlers = ws1.build_health_handlers(_FakeUDP(is_running=True))
        self.assertTrue(handlers, "serve() must no longer be given an empty handler map")
        self.assertEqual(len(handlers), 1)
        topic, (group, handler) = next(iter(handlers.items()))
        self.assertEqual(group, ws1._HEALTH_GROUP)
        self.assertTrue(callable(handler))

    def test_handler_passes_when_udp_alive(self):
        _, (_, handler) = next(iter(ws1.build_health_handlers(_FakeUDP(is_running=True)).items()))
        self.assertIsNone(handler({"probe": 1}))

    def test_handler_raises_when_udp_down(self):
        _, (_, handler) = next(iter(ws1.build_health_handlers(_FakeUDP(is_running=False)).items()))
        with self.assertRaises(RuntimeError):
            handler({"probe": 1})

    def test_handler_raises_when_udp_none(self):
        _, (_, handler) = next(iter(ws1.build_health_handlers(None).items()))
        with self.assertRaises(RuntimeError):
            handler({"probe": 1})


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _run_serve(handlers, bus_factory):
    shutdown = threading.Event()
    port = _free_port()
    t = threading.Thread(
        target=runner.serve, args=(handlers,),
        kwargs=dict(health_port=port, shutdown=shutdown,
                    service_name="ws1-test", idle_sleep_s=0.05,
                    install_signal_handlers=False, bus_factory=bus_factory),
        daemon=True)
    t.start()
    return port, shutdown, t


def _http_status(url, timeout=3):
    import urllib.error
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception:
        return None, ""


def _poll_status(url, expect, timeout=4.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status, _ = _http_status(url)
        if status == expect:
            return status, True
        time.sleep(0.05)
    status, _ = _http_status(url)
    return status, status == expect


class TestServeHealthRealWorker(unittest.TestCase):
    """#70: with a REAL worker in the map, /health is driven by that worker's
    ability to reach the bus -- a broken bus now reports 503 instead of the old
    hardcoded 200 (which an empty handler map forced)."""

    def test_health_ok_on_healthy_bus(self):
        bus = Bus()
        port, shutdown, t = _run_serve(ws1.build_health_handlers(_FakeUDP(True)),
                                       lambda: bus)
        try:
            status, ok = _poll_status(f"http://127.0.0.1:{port}/health", 200)
            self.assertTrue(ok, f"healthy serve() should report 200, got {status}")
        finally:
            shutdown.set()
            t.join(timeout=5)

    def test_health_503_when_bus_unreachable(self):
        class _BrokenBus:
            def consume(self, *a, **k):
                raise RuntimeError("bus unreachable (test)")

            def claim_pending(self, *a, **k):
                raise RuntimeError("no bus")

            def depth(self, *a, **k):
                raise RuntimeError("no bus")

            def lag(self, *a, **k):
                raise RuntimeError("no bus")

        port, shutdown, t = _run_serve(ws1.build_health_handlers(_FakeUDP(True)),
                                       lambda: _BrokenBus())
        try:
            status, ok = _poll_status(f"http://127.0.0.1:{port}/health", 503)
            self.assertTrue(ok,
                            "a bus outage must now report 503 (not the old hardcoded "
                            f"200); got {status}")
        finally:
            shutdown.set()
            t.join(timeout=5)


class TestSyslogMetricsFlattened(unittest.TestCase):
    """#71/#76: _syslog_metrics must be FLAT so render_prometheus emits real
    gauges for the ingest-edge counters -- a nested {"syslog_udp": {...}}
    wrapper silenced them all (structurally valid, simply empty)."""

    def test_metrics_are_flat_not_nested(self):
        m = ws1._syslog_metrics(_FakeUDP())
        self.assertNotIn("syslog_udp", m,
                         "metrics must be flat, not wrapped under a syslog_udp "
                         "dict that render_prometheus skips")
        for key in ("events_produced", "events_dropped", "events_shed",
                    "events_spooled", "events_lost", "events_queue_full",
                    "events_empty", "recv_oserror_total",
                    "seconds_since_last_event"):
            self.assertIn(key, m, f"flat metric {key} missing")
        self.assertIsInstance(m["events_produced"], int)

    def test_udp_none_returns_empty(self):
        self.assertEqual(ws1._syslog_metrics(None), {})

    def test_render_prometheus_emits_gauges_for_flat_keys(self):
        m = ws1._syslog_metrics(_FakeUDP())
        text = runner.render_prometheus("ws1-collectors", {}, extra=m)
        for key in ("events_produced", "events_dropped", "events_shed",
                    "events_spooled", "events_lost", "events_queue_full",
                    "events_empty", "recv_oserror_total"):
            self.assertIn(f'field="{key}"', text,
                          f"render_prometheus must emit a gauge for flat key {key}")
            self.assertIn(f"fengarde_extra", text)
        # The per-source breakdown is a dict leaf -> intentionally NOT a gauge.
        self.assertNotIn('field="per_source"', text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
