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
    SyslogUDPServer, build_raw_event, _TokenBucket, TenantTokenBuckets,
    udp_rcvbuf_errors)
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


class TestTenantTokenBuckets(unittest.TestCase):
    def test_per_tenant_buckets_are_independent(self):
        buckets = TenantTokenBuckets(rate_per_sec=3)
        # acme drains its own bucket
        acme = [buckets.take("acme") for _ in range(6)]
        self.assertEqual(sum(acme), 3)
        # globex still has its full burst available
        globex = [buckets.take("globex") for _ in range(6)]
        self.assertEqual(sum(globex), 3)

    def test_missing_tenant_falls_back_to_shared_default(self):
        buckets = TenantTokenBuckets(rate_per_sec=2)
        self.assertTrue(buckets.take(""))
        self.assertTrue(buckets.take(""))
        self.assertFalse(buckets.take(""))
        # Explicit tenant should still have its own full bucket.
        self.assertTrue(buckets.take("acme"))
        self.assertTrue(buckets.take("acme"))
        self.assertFalse(buckets.take("acme"))

    def test_new_tenant_gets_own_capacity(self):
        buckets = TenantTokenBuckets(rate_per_sec=4)
        self.assertEqual(sum(buckets.take("acme") for _ in range(8)), 4)
        self.assertEqual(sum(buckets.take("globex") for _ in range(8)), 4)

    def test_unknown_tenant_bounded_even_when_map_is_full(self):
        buckets = TenantTokenBuckets(rate_per_sec=10)
        for i in range(4096):
            buckets.take(f"tenant-{i}")
        # The next distinct tenant should still be limited, not leak.
        self.assertEqual(sum(buckets.take("overflow-tenant") for _ in range(20)), 10)


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

    def test_per_tenant_token_bucket_isolates_at_edge(self):
        bus = Bus()
        server = SyslogUDPServer(bus, host="127.0.0.1", port=0,
                                 deterministic_id=True, max_events_per_sec=5)
        server.start()
        try:
            for i in range(20):
                os.environ["TENANT_ID"] = "acme"
                server._handle_datagram(f"acme line {i}".encode(), "127.0.0.1")
                os.environ["TENANT_ID"] = "globex"
                server._handle_datagram(f"globex line {i}".encode(), "127.0.0.1")
            self.assertEqual(len(bus.drain("raw.events")) + server.events_shed, 40,
                             "every datagram must be accounted for across both tenants")
            self.assertLessEqual(len(bus.drain("raw.events")), 10,
                                 "both tenants together should not exceed 2 * rate")
            self.assertGreaterEqual(server.events_shed, 30,
                                    "both tenants combined should shed most of the 40 datagrams")
        finally:
            os.environ.pop("TENANT_ID", None)
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

    def test_construction_refuses_a_directory_path(self):
        """Live-Docker-caught (2026-08-21): SYSLOG_SPOOL_PATH pointed at a
        named volume's mount point (a directory) used to be silently
        accepted -- every append()/drain_into() then hit IsADirectoryError,
        caught by their own broad except OSError, and no-op'd forever with
        zero error and zero log. A misconfigured zero-loss feature must fail
        loud at construction, not silently become its own opposite."""
        directory_path = Path(self._tmp.name)  # the tmpdir itself, not a file in it
        with self.assertRaises(IsADirectoryError):
            BoundedSpool(directory_path, max_bytes=1_000_000)

    def test_replay_survives_a_process_restart(self):
        """Ingestion-edge-redundancy design doc (fengarde-sec) step 1: "verify
        replay-on-boot." Every other spool test appends and drains on the SAME
        instance -- this is the one gap the design doc named: a NEW instance,
        pointed at the SAME path (simulating a container restart with the
        spool on a durable/named volume, per docker-compose.yml's ws1-collectors
        service), must pick up and replay whatever the OLD instance left
        on disk. Mechanically this should already work (BoundedSpool.__init__
        just opens whatever file exists), but nothing proved it until now.
        """
        old_process_spool = BoundedSpool(self.path, max_bytes=1_000_000)
        for i in range(5):
            self.assertTrue(old_process_spool.append({"i": i}))
        self.assertEqual(old_process_spool.pending_count(), 5)
        # No drain -- the process "dies" here with events still pending,
        # same as a container killed mid-flood before the drain loop caught up.
        del old_process_spool

        new_process_spool = BoundedSpool(self.path, max_bytes=1_000_000)
        self.assertEqual(new_process_spool.pending_count(), 5,
                         "a new instance pointed at the same path must see the "
                         "prior process's un-replayed events, not start empty")

        replayed_events = []
        replayed = new_process_spool.drain_into(replayed_events.append)
        self.assertEqual(replayed, 5)
        self.assertEqual([e["i"] for e in replayed_events], [0, 1, 2, 3, 4],
                         "replay-on-boot must preserve FIFO order across the restart")
        self.assertEqual(new_process_spool.pending_count(), 0)


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


class TestTenantTokenBucketDegradationLogging(unittest.TestCase):
    def test_tenant_map_full_logs_warning(self):
        log_records = []

        class FakeLog:
            def warn(self, msg, **kw):
                log_records.append((msg, kw))

        buckets = TenantTokenBuckets(rate_per_sec=0, logger=FakeLog())
        for i in range(4097):
            buckets.take(f"tenant-{i}", source_ip="10.0.0.1")
        self.assertTrue(any("tenant bucket map full" in r[0] for r in log_records),
                        "expected at least one tenant-map-full warning, got none")

    def test_source_map_full_logs_warning(self):
        log_records = []

        class FakeLog:
            def warn(self, msg, **kw):
                log_records.append((msg, kw))

        buckets = TenantTokenBuckets(rate_per_sec=0, logger=FakeLog())
        for i in range(4097):
            buckets.take("acme", source_ip=f"10.0.{i // 256}.{i % 256}")
        self.assertTrue(any("source bucket map full" in r[0] for r in log_records),
                        "expected at least one source-map-full warning, got none")

class TestIngestSilenceDetection(unittest.TestCase):
    """Ingestion-edge-redundancy design doc (fengarde-sec) step 2:
    seconds_since_last_event() -- the signal /health never had for
    "healthy but nothing is arriving"."""

    def test_starts_quiet_since_construction_not_silent_forever(self):
        bus = Bus()
        server = SyslogUDPServer(bus, host="127.0.0.1", port=0)
        try:
            # No datagrams sent, no start() even called -- a fresh server
            # reads as "quiet since just now", never a large/undefined number.
            self.assertLess(server.seconds_since_last_event(), 1.0,
                            "a freshly constructed server must read as recently "
                            "quiet (construction time), not silent forever")
        finally:
            # __init__ binds the socket eagerly (P0-4), before start() -- must
            # release it even though start()/stop() were never otherwise
            # called, or the bound socket leaks past this test.
            server.stop()

    def test_receiving_a_datagram_resets_the_silence_clock(self):
        bus = Bus()
        server = SyslogUDPServer(bus, host="127.0.0.1", port=0, deterministic_id=True)
        server.start()
        try:
            # Force the clock forward past what a real datagram should reset.
            server._last_received_ts -= 10.0
            self.assertGreaterEqual(server.seconds_since_last_event(), 10.0)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(SYSLOG_LINE.encode(), ("127.0.0.1", server.port))
            finally:
                sock.close()

            _poll(lambda: server.seconds_since_last_event() < 5.0, timeout=2.0)
            self.assertLess(server.seconds_since_last_event(), 5.0,
                            "a real received datagram must reset the silence clock")
        finally:
            server.stop()

    def test_watchdog_warns_once_then_stays_quiet_until_recovery(self):
        """The watchdog must not re-warn every tick for the duration of one
        outage (that would drown the one signal that matters in repeats of
        itself), but must warn again on a SECOND, separate silent period."""
        import threading
        sys.path.insert(0, str(HERE))
        from main import _start_ingest_silence_watchdog  # noqa: E402

        class _FakeUDP:
            def __init__(self):
                self.silent = False
            def seconds_since_last_event(self):
                return 999.0 if self.silent else 0.0

        class _FakeLog:
            def __init__(self):
                self.warnings = []
            def warn(self, msg, **kw):
                self.warnings.append((msg, kw))

        udp = _FakeUDP()
        log = _FakeLog()
        shutdown = threading.Event()
        os.environ["SYSLOG_SILENCE_WARN_S"] = "0.05"
        interval_s = 0.02
        try:
            t = _start_ingest_silence_watchdog(udp, log, shutdown, interval_s=interval_s)
            try:
                udp.silent = True
                _poll(lambda: len(log.warnings) >= 1, timeout=1.0)

                # Stay silent for several MORE ticks before recovering. This
                # is a genuinely unavoidable real wait, not flakiness of the
                # kind the polling changes elsewhere in this test fix: the
                # property under test is "no SECOND warning fires while
                # still silent," which is an absence-of-event-over-elapsed-
                # time claim -- there is no positive event to poll for, so
                # polling can't replace it. Too short a window and a broken
                # "warn every tick" implementation wouldn't get a second
                # tick to fire before recovery, passing by accident (caught
                # in review: an earlier version of this test raced exactly
                # that way and could not fail even when the guard was
                # deliberately removed).
                time.sleep(interval_s * 5)
                self.assertEqual(len(log.warnings), 1,
                                 "must warn exactly once per continuous outage, "
                                 "not once per watchdog tick")

                # Recovery: poll for elapsed time instead of a fixed sleep so
                # slow CI hosts get more slack before the second outage starts.
                udp.silent = False  # recovers
                recovery_start = time.monotonic()
                _poll(lambda: time.monotonic() - recovery_start >= interval_s * 2,
                      timeout=1.0)
                udp.silent = True  # goes silent again -- a NEW, separate outage
                _poll(lambda: len(log.warnings) >= 2, timeout=2.0)
                self.assertEqual(len(log.warnings), 2,
                                 "a second, separate silent period must warn again")
            finally:
                shutdown.set()
                t.join(timeout=2)
        finally:
            del os.environ["SYSLOG_SILENCE_WARN_S"]

    def test_udp_none_disables_the_watchdog(self):
        """A bind failure (main() logs and stays up for /health only) must not
        make the watchdog permanently, misleadingly report silence."""
        sys.path.insert(0, str(HERE))
        from main import _start_ingest_silence_watchdog  # noqa: E402
        import threading
        result = _start_ingest_silence_watchdog(None, None, threading.Event())
        self.assertIsNone(result, "udp=None must disable the watchdog, not crash or warn")


class TestEnvVarDegradation(unittest.TestCase):
    """Gap-hunt finding (2026-08-23): _int_env's own docstring documents
    "degrade to default (logged) on a malformed value instead of crashing
    startup" -- but zero test coverage existed for that claim (for ANY of
    its 4 original call sites), and it was applied to only 4 of the 8
    env-var-reading knobs in main.py, an inconsistency once _float_env
    closed the type gap. Proves the actual degrade behavior for both."""

    class _FakeLog:
        def __init__(self):
            self.warnings = []

        def warn(self, msg, **fields):
            self.warnings.append((msg, fields))

    def setUp(self):
        sys.path.insert(0, str(HERE))
        from main import _int_env, _float_env  # noqa: E402
        self._int_env = _int_env
        self._float_env = _float_env

    def test_int_env_missing_uses_default_silently(self):
        os.environ.pop("FENGARDE_TEST_INT", None)
        log = self._FakeLog()
        self.assertEqual(self._int_env("FENGARDE_TEST_INT", 7, log), 7)
        self.assertEqual(log.warnings, [], "an UNSET env var is not malformed, must not warn")

    def test_int_env_valid_value_parses(self):
        os.environ["FENGARDE_TEST_INT"] = "42"
        try:
            log = self._FakeLog()
            self.assertEqual(self._int_env("FENGARDE_TEST_INT", 7, log), 42)
            self.assertEqual(log.warnings, [])
        finally:
            del os.environ["FENGARDE_TEST_INT"]

    def test_int_env_malformed_degrades_and_warns(self):
        os.environ["FENGARDE_TEST_INT"] = "not-a-number"
        try:
            log = self._FakeLog()
            self.assertEqual(self._int_env("FENGARDE_TEST_INT", 7, log), 7)
            self.assertEqual(len(log.warnings), 1, "a malformed value must warn exactly once")
        finally:
            del os.environ["FENGARDE_TEST_INT"]

    def test_float_env_malformed_degrades_and_warns(self):
        os.environ["FENGARDE_TEST_FLOAT"] = "not-a-float"
        try:
            log = self._FakeLog()
            self.assertEqual(self._float_env("FENGARDE_TEST_FLOAT", 3.5, log), 3.5)
            self.assertEqual(len(log.warnings), 1, "a malformed value must warn exactly once")
        finally:
            del os.environ["FENGARDE_TEST_FLOAT"]

    def test_float_env_valid_value_parses(self):
        os.environ["FENGARDE_TEST_FLOAT"] = "12.5"
        try:
            log = self._FakeLog()
            self.assertEqual(self._float_env("FENGARDE_TEST_FLOAT", 3.5, log), 12.5)
            self.assertEqual(log.warnings, [])
        finally:
            del os.environ["FENGARDE_TEST_FLOAT"]


class TestUdpRcvbufErrors(unittest.TestCase):
    """Gap-hunt finding (2026-08-23): udp_rcvbuf_errors() -- the fix for the
    live-proven "healthy events_shed=0 events_dropped=0 while the kernel is
    silently dropping datagrams" blind spot -- had zero coverage of its own
    header/value-alignment parsing, only of the None-fallback path (no
    procfs / not Linux). ``path`` is test-only-injectable (see the
    function's docstring); production always uses the real default."""

    def _fixture(self, content: str) -> str:
        fd, path = tempfile.mkstemp()
        os.write(fd, content.encode("ascii"))
        os.close(fd)
        self.addCleanup(os.remove, path)
        return path

    def test_real_shaped_snmp_output_extracts_rcvbuf_errors(self):
        # Real /proc/net/snmp shape: Udp: header line, then Udp: value line,
        # interleaved with other protocols' Tcp:/Ip: blocks -- the parser
        # must skip those and find its OWN header/value pair.
        content = (
            "Ip: Forwarding DefaultTTL InReceives\n"
            "Ip: 1 64 12345\n"
            "Udp: InDatagrams NoPorts InErrors RcvbufErrors SndbufErrors\n"
            "Udp: 999 3 0 42 0\n"
        )
        self.assertEqual(udp_rcvbuf_errors(self._fixture(content)), 42)

    def test_rcvbuf_errors_is_zero_when_genuinely_zero(self):
        """0 is a real, meaningful value (no kernel drops) -- must not be
        confused with the None-means-unavailable sentinel."""
        content = ("Udp: InDatagrams NoPorts InErrors RcvbufErrors\n"
                   "Udp: 10 0 0 0\n")
        self.assertEqual(udp_rcvbuf_errors(self._fixture(content)), 0)

    def test_missing_rcvbuf_errors_column_returns_none(self):
        """An older/different kernel's Udp: header without this column must
        degrade to None, not crash or misindex into an adjacent column."""
        content = "Udp: InDatagrams NoPorts InErrors\nUdp: 10 0 0\n"
        self.assertIsNone(udp_rcvbuf_errors(self._fixture(content)))

    def test_missing_udp_value_line_returns_none(self):
        """A header with no matching value line (truncated/malformed procfs)
        must not raise -- IndexError-class failures are the exact thing this
        function's except clause exists to catch."""
        content = "Udp: InDatagrams NoPorts InErrors RcvbufErrors\n"
        self.assertIsNone(udp_rcvbuf_errors(self._fixture(content)))

    def test_no_udp_block_at_all_returns_none(self):
        content = "Ip: Forwarding DefaultTTL\nIp: 1 64\n"
        self.assertIsNone(udp_rcvbuf_errors(self._fixture(content)))

    def test_empty_file_returns_none(self):
        self.assertIsNone(udp_rcvbuf_errors(self._fixture("")))

    def test_nonexistent_path_returns_none_not_raise(self):
        """Off-Linux / no procfs: the documented None-fallback path."""
        self.assertIsNone(udp_rcvbuf_errors("/no/such/path/ever-9f3a2b"))

    def test_non_numeric_value_returns_none_not_raise(self):
        """A corrupted procfs line (non-numeric where a count is expected)
        must fail closed to None, not raise ValueError out of /metrics."""
        content = ("Udp: InDatagrams NoPorts InErrors RcvbufErrors\n"
                   "Udp: 10 0 0 not-a-number\n")
        self.assertIsNone(udp_rcvbuf_errors(self._fixture(content)))


if __name__ == "__main__":
    unittest.main()
