"""Real UDP syslog listener (live ingestion path for WS-1).

Binds a UDP socket and turns each received datagram into a raw event on the
``raw.events`` topic, shaped exactly like the other collectors' raw payloads so
it flows straight into the WS-2 ``generic_syslog`` parser::

    {"source_type": "generic_syslog",
     "raw": "<the raw syslog line>",
     "meta": {"received_at": <epoch_s>, "ingest_id": "<uuid|sha-derived>"}}

The source datagram's peer IP is used as the ``raw.events`` partition key so all
events from one device land on the same partition.

This complements (does not replace) the bundled mock collection in ``main.py``.
``main.py`` runs it as the daemon's real ingestion path alongside the runner's
/health endpoint.

Default bind port is 5514 (not the privileged 514) so it runs without elevation.
Binding to 514 requires root/admin (or CAP_NET_BIND_SERVICE on Linux).

P0-4 (2026-07-21 audit): this used to be a plain ``socketserver.UDPServer``,
whose default dispatch is single-threaded and serial -- one datagram's handler
(which does a blocking ``bus.produce`` Redis round-trip) had to finish before
the next `recvfrom` even happened. Live-proven on the real Docker stack: at
~7,350 EPS offered, the kernel silently dropped ~62,000 datagrams
(``/proc/net/snmp``'s ``Udp: RcvbufErrors``) while the app's own counters read
``events_shed=0 events_dropped=0`` -- the token bucket and spool fallback below
never even saw the traffic, because it never survived the recv queue. Fixed by
decoupling the two costs: a dedicated thread does nothing but a tight
``recvfrom`` loop (so the kernel's receive buffer drains as fast as possible),
handing datagrams to a bounded queue that a small worker pool drains at its own
pace running the existing token-bucket/spool/produce logic unchanged. A large
``SO_RCVBUF`` gives the kernel more slack while a burst is being drained, and
the real kernel-level drop counter is now surfaced via :func:`udp_rcvbuf_errors`
(exposed on ``/metrics`` by ``main.py``) so an operator sees loss below the
app, not just at it. The old per-datagram ``log.info`` (a JSON-dumps + stdout
flush syscall pair per event, roughly doubling per-event cost -- see
``shared/log.py``) is gone; ``events_produced`` already counts the same thing
on ``/metrics`` without the per-event I/O tax.
"""
from __future__ import annotations

import queue
import socket
import threading
import time
from typing import Optional

from .spool import BoundedSpool
from .syslog_dispatch import (  # noqa: F401  # re-exported for existing callers (tests import from this module)
    SyslogDispatcher, TenantTokenBuckets, _TokenBucket, build_raw_event,
    _deterministic_ingest_id,
)

# CodeQL py/bind-socket-all-network-interfaces (alert #63) flags this default.
# It is intentional, not an oversight: this is a syslog COLLECTOR whose entire
# purpose is receiving UDP datagrams from OTHER machines on the network
# (routers, firewalls, switches) -- binding it to 127.0.0.1 would make it
# unreachable from any real log source and defeat the service. The port is
# already published to the host's own interfaces in `infra/docker-compose.yml`
# (`ports: ["5514:5514/udp"]`, its own comment: "so devices ... can send to
# it"), so 0.0.0.0 here matches an already-deliberate, already-documented
# exposure decision one layer up, not a new one. Override via SYSLOG_UDP_HOST
# if a deployment needs to restrict ingestion to a specific NIC.
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5514
# B2 (backpressure decision, docs/superpowers/specs/2026-07-02-fengarde-v0.3-improvement-plan.md):
# shed at the ingest edge rather than trim mid-pipeline. UDP is connectionless
# -- there is no producer to apply backpressure to -- so the only real lever
# here is dropping excess datagrams before they ever reach bus.produce(),
# bounding stream growth at the source instead of an unbounded XADD flood that
# would otherwise grow Redis until OOM. 0/negative disables the limit.
DEFAULT_MAX_EVENTS_PER_SEC = 2000

# P0-4: recv/dispatch decoupling knobs. The recv thread's only job is
# `recvfrom` + `queue.put` -- no bus I/O, so it can drain the kernel buffer far
# faster than any single handler could. DEFAULT_WORKERS handlers pull from the
# queue and do the actual (token-bucket / spool / bus.produce) work in
# parallel. DEFAULT_QUEUE_MAXSIZE bounds memory if handlers fall behind a
# sustained flood; a full queue is a THIRD distinct drop reason (see
# events_queue_full below) -- distinguishable from a token-bucket shed (rate
# policy) or a kernel-level RcvbufErrors drop (never reached this process at
# all).
DEFAULT_WORKERS = 4
DEFAULT_QUEUE_MAXSIZE = 20000
# FENGARDE E6: the per-source (/metrics) breakdown is a bounded map -- cap on
# how many distinct peer IPs we retain per-source counters for, so a slow
# trickle of log sources plus a spike of novel/one-off senders can't grow the
# map without bound. When full, the least-recently-updated source is evicted
# (true LRU via dict insertion order + reinsert). This is inherently a
# visibility tradeoff: an operator sees the recent, active sources in detail
# and the aggregate counters still account for EVERY datagram, evicted or not.
DEFAULT_PEER_METRICS_MAX = 1024
# Best-effort kernel receive-buffer size (bytes). Linux typically caps this via
# net.core.rmem_max unless raised; setsockopt succeeding doesn't guarantee the
# full value was actually granted, but asking for headroom is still strictly
# better than leaving the OS default (often as low as 128KB) during a burst.
DEFAULT_SO_RCVBUF = 8 * 1024 * 1024
# Gap-hunt (2026-08-26) #79: a persistent recv-loop OSError is retried with
# this sleep between attempts so a wedged socket can't peg a core in a tight
# busyloop.
_RECV_OSERROR_BACKOFF_S = 0.1


def udp_rcvbuf_errors(path: str = "/proc/net/snmp") -> Optional[int]:
    """Cumulative kernel-level UDP receive-buffer-overflow count for this
    host/container, i.e. datagrams the OS dropped BEFORE any Python code ever
    saw them -- the exact loss class that reads as a healthy `events_shed=0
    events_dropped=0` at the app layer (live-proven, see the module
    docstring). Returns None off-Linux or if `/proc/net/snmp` isn't readable
    (never raises); the caller degrades to omitting the metric rather than
    crashing /metrics over an unavailable procfs.

    Cumulative since boot, not a rate -- a caller wanting a rate must diff two
    samples over a known interval, same convention as any other /proc counter.

    ``path`` defaults to the real procfs location; overridable ONLY so
    test_syslog_udp.py can drive the header/value-alignment parsing logic
    itself against a controlled fixture file -- this used to have zero
    coverage of anything but the None-fallback path (gap-hunt finding,
    2026-08-23), leaving the exact live-proven blind spot this function
    exists to close free to regress silently (e.g. a swapped header/value
    line order, or a shifted column index).
    """
    try:
        with open(path, "r", encoding="ascii") as f:
            header = value = None
            for line in f:
                if line.startswith("Udp:"):
                    if header is None:
                        header = line.split()
                    else:
                        value = line.split()
                        break
        if header is None or value is None:
            return None
        idx = header.index("RcvbufErrors")
        return int(value[idx])
    except (OSError, ValueError, IndexError):
        return None


class SyslogUDPServer:
    """Threaded UDP syslog server that produces raw events to ``raw.events``.

    :param bus: a ``shared.bus.Bus()`` with ``produce(topic, key, payload)``.
    :param host: bind host (env ``SYSLOG_UDP_HOST``, default ``0.0.0.0``).
    :param port: bind port (env ``SYSLOG_UDP_PORT``, default ``5514``). Pass 0
        to get an ephemeral port (tests). The actual bound port is exposed via
        :attr:`port` after construction.
    :param topic: bus topic to produce to (default ``raw.events``).
    :param deterministic_id: if True, derive ingest_id from the line (idempotent)
        instead of a random uuid4. Tests use this for determinism.
    :param max_events_per_sec: B2 ingest-edge shedding cap (env
        ``SYSLOG_MAX_EVENTS_PER_SEC``). 0/negative disables the limit
        (default for tests; ``main.py`` applies ``DEFAULT_MAX_EVENTS_PER_SEC``
        for real deployments).
    :param spool: an optional ``BoundedSpool`` (see ``spool.py``) for the
        zero-loss-under-flood fallback. When set, an event that would
        otherwise be shed (rate limit) or dropped (bus produce failed) is
        written to the spool instead and replayed later by a background
        drain thread. Still bounded: once the spool itself is full, the
        event is truly lost (counted in ``events_lost``), but that boundary
        is now an explicit, configurable byte cap instead of "everything
        over the rate limit, forever." None (default) preserves the plain
        shed-and-count behavior with no disk I/O.
    :param workers: P0-4: number of handler threads draining the internal
        queue (env ``SYSLOG_UDP_WORKERS``, default :data:`DEFAULT_WORKERS`).
        Decoupled from the single recv thread so a slow `bus.produce` never
        blocks the kernel-buffer drain.
    :param queue_maxsize: P0-4: bound on the internal recv-to-worker queue
        (env ``SYSLOG_UDP_QUEUE_MAXSIZE``, default
        :data:`DEFAULT_QUEUE_MAXSIZE`). A full queue means every worker is
        already saturated; the datagram is counted in ``events_queue_full``
        rather than blocking the recv thread (which would just push the
        kernel-drop problem back).
    :param so_rcvbuf: P0-4: requested kernel receive-buffer size in bytes
        (env ``SYSLOG_UDP_SO_RCVBUF``, default :data:`DEFAULT_SO_RCVBUF`).
        Best-effort (``setsockopt`` failures are swallowed) -- more headroom
        during a burst, not a correctness guarantee.
    :param peer_metrics_max: FENGARDE E6: max distinct peer IPs kept in the
        incremental per-source breakdown (``per_source_metrics()``); LRU-evicts
        the oldest when full. Default :data:`DEFAULT_PEER_METRICS_MAX`. The
        aggregate counters are never evicted -- every datagram stays counted.
    :param logger: optional shared.log Logger.
    """

    def __init__(self, bus, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 topic: str = "raw.events", deterministic_id: bool = False,
                 max_events_per_sec: float = 0,
                 spool: Optional[BoundedSpool] = None,
                 spool_drain_interval_s: float = 5.0, logger=None,
                 workers: int = DEFAULT_WORKERS,
                 queue_maxsize: int = DEFAULT_QUEUE_MAXSIZE,
                 so_rcvbuf: int = DEFAULT_SO_RCVBUF,
                 peer_metrics_max: int = DEFAULT_PEER_METRICS_MAX):
        self.bus = bus
        self.topic = topic
        self.deterministic_id = deterministic_id
        # WP-1.2: the dispatch core (token buckets, spool fallback, counters,
        # per-source breakdown, throttled shed/produce-failure logs) lives in a
        # protocol-agnostic SyslogDispatcher SHARED with the TCP listener. The
        # counters stay readable here through the properties below, so every
        # existing caller and the whole test_syslog_udp.py suite is unchanged.
        self._dispatcher = SyslogDispatcher(
            bus, topic=topic, max_events_per_sec=max_events_per_sec,
            spool=spool, deterministic_id=deterministic_id,
            peer_metrics_max=peer_metrics_max, logger=logger)
        self.events_queue_full = 0  # P0-4: worker pool saturated, queue.put_nowait refused
        self._queue_lock = threading.Lock()
        # Gap-hunt (2026-08-26) #79: a persistent (non-close) recv OSError is
        # no longer a bare `continue` inside the recv thread -- that could
        # become an unbounded tight busyloop pegging a core. Now counted and
        # logged, with a short backoff sleep between retries.
        self.recv_oserror_total = 0
        self._recv_oserror_backoff_s = _RECV_OSERROR_BACKOFF_S
        self._spool_drain_interval_s = spool_drain_interval_s
        self._spool_shutdown = threading.Event()
        self._spool_thread: Optional[threading.Thread] = None
        # Ingestion-edge-redundancy design doc (fengarde-sec, 2026-08-06),
        # step 2: "a healthy-but-silent ws1 with no sources looks fine" --
        # /health only ever probed the bus, never whether anything was
        # actually arriving on the socket. Stamped at recv time (_recv_loop),
        # deliberately NOT at produce/spool time, so this measures the thing
        # a dead/misdirected/firewalled source actually breaks: datagrams
        # reaching the kernel socket at all. Initialized to construction time
        # (not 0) so a freshly-started server with zero traffic yet reads as
        # "quiet since boot", not "silent forever" -- the watchdog's own
        # startup grace period is this value, for free, with no separate
        # boot-time tracking needed.
        # Gap-hunt (2026-08-26) #80: the silence watchdog now uses a monotonic
        # clock -- wall-clock time.time() made the elapsed-silence calculation go
        # NEGATIVE on an NTP step backward or a VM suspend/resume, silently
        # disabling the watchdog during the exact kind of event most likely to
        # accompany a real outage.
        self._last_received_ts = time.monotonic()

        # P0-4: raw socket, not socketserver.UDPServer -- gives us a tight
        # recv loop decoupled from per-datagram handling (see module
        # docstring) and a place to raise SO_RCVBUF before the first recv.
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, so_rcvbuf)
        except OSError:
            pass  # platform refused/capped it; proceed with whatever we got
        self._sock.bind((host, port))
        self.host, self.port = self._sock.getsockname()[0], self._sock.getsockname()[1]

        self._queue: "queue.Queue" = queue.Queue(maxsize=max(1, queue_maxsize))
        self._num_workers = max(1, workers)
        self._recv_thread: Optional[threading.Thread] = None
        self._worker_threads: list[threading.Thread] = []
        self._running = threading.Event()

    # -- WP-1.2: counters and per-source metrics delegate to the shared
    #    dispatcher (the TCP listener uses the same instance-level API, so
    #    /metrics and the tests read one source of truth for both transports)
    @property
    def log(self):
        # Forwarded so a caller may replace the logger AFTER construction
        # (test_syslog_udp.py does exactly that) -- the dispatcher must see it.
        return self._dispatcher.log

    @log.setter
    def log(self, value):
        self._dispatcher.log = value

    @property
    def events_produced(self) -> int:
        return self._dispatcher.events_produced

    @property
    def events_dropped(self) -> int:
        return self._dispatcher.events_dropped

    @property
    def events_shed(self) -> int:
        return self._dispatcher.events_shed

    @property
    def events_spooled(self) -> int:
        return self._dispatcher.events_spooled

    @property
    def events_lost(self) -> int:
        return self._dispatcher.events_lost

    @property
    def events_empty(self) -> int:
        return self._dispatcher.events_empty

    @property
    def _shed_lock(self):
        # Contract surface (test_fix_counters_deterministic asserts it): the
        # shared dispatch lock that serializes aggregate counter updates.
        return self._dispatcher._shed_lock  # noqa: SLF001 -- same family

    @property
    def _spool(self):
        # The spool-drain loop and main.py's metrics probe read this name.
        return self._dispatcher._spool  # noqa: SLF001 -- same family

    def per_source_metrics(self) -> dict:
        return self._dispatcher.per_source_metrics()

    def _handle_datagram(self, data: bytes, peer_ip: str) -> None:
        # WP-1.2: the whole dispatch decision (empty guard, token buckets,
        # spool fallback, produce, counters, per-source metrics) is in the
        # protocol-agnostic SyslogDispatcher shared with the TCP listener.
        line = data.decode("utf-8", errors="replace").rstrip("\r\n")
        self._dispatcher.handle_line(line, peer_ip)

    def _recv_queue_full(self) -> None:
        """Count a refused queue put (recv thread saturated; P0-4)."""
        with self._queue_lock:
            self.events_queue_full += 1

    def start(self) -> None:
        """Start serving on background daemon threads (non-blocking).

        P0-4: one recv thread (tight `recvfrom` + `queue.put_nowait` loop,
        never touches the bus) plus a fixed pool of worker threads draining
        the queue via `_handle_datagram` (the actual token-bucket/spool/
        `bus.produce` work). Decoupling these is the fix for the live-proven
        kernel-drop issue -- see the module docstring."""
        if self._running.is_set():
            return
        self._running.set()
        self._recv_thread = threading.Thread(
            target=self._recv_loop, name="syslog-udp-recv", daemon=True)
        self._recv_thread.start()
        for i in range(self._num_workers):
            t = threading.Thread(target=self._worker_loop,
                                 name=f"syslog-udp-worker-{i}", daemon=True)
            t.start()
            self._worker_threads.append(t)
        if self._spool is not None and self._spool_thread is None:
            self._spool_thread = threading.Thread(
                target=self._drain_spool_loop, name="syslog-spool-drain", daemon=True)
            self._spool_thread.start()
        if self.log is not None:
            self.log.info("syslog UDP listening", host=self.host, port=self.port,
                          workers=self._num_workers)

    def _recv_loop(self) -> None:
        """Tight loop: only `recvfrom` and a non-blocking queue put. No bus
        I/O here on purpose -- see the module docstring's P0-4 note. A full
        queue means every worker is already saturated; count it distinctly
        (events_queue_full) rather than blocking here, which would just
        re-create the exact coupling this fix removes."""
        while self._running.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
            except OSError:
                # stop() closed the socket -> _running is clear; exit instead
                # of spinning on a now-dead socket.
                if not self._running.is_set():
                    break
                # Gap-hunt (2026-08-26) #79: a PERSISTENT (non-close) recv
                # error was a bare `continue` -- an unbounded tight busyloop
                # pegging a core with no signal. Now counted + logged and
                # backed off briefly so a wedged socket burns one core's
                # fraction of a second, not 100%.
                self.recv_oserror_total += 1
                if self.log is not None:
                    self.log.warn("syslog udp recv error (backing off)",
                                  errors_total=self.recv_oserror_total,
                                  backoff_s=self._recv_oserror_backoff_s)
                time.sleep(self._recv_oserror_backoff_s)
                continue
            if not self._running.is_set():
                break
            # A single float write is atomic under CPython's GIL -- no lock
            # needed, same reasoning as every other lock-free counter this
            # module deliberately doesn't guard (queue_full is a single
            # increment, guarded against concurrent recv-loop writers only).
            self._last_received_ts = time.monotonic()
            try:
                self._queue.put_nowait((data, addr[0]))
            except queue.Full:
                self._recv_queue_full()

    def is_running(self) -> bool:
        """True while the recv + worker threads are live (start() called and
        stop() not yet). Exposed for the self-liveness wire-up in main.py's
        health worker (gap-hunt #70): a collector whose UDP ingest daemon is
        down must not report healthy."""
        return self._running.is_set()

    def seconds_since_last_event(self) -> float:
        """Monotonic seconds since the last datagram reached the socket.

        Measured at recv time, not produce/spool time -- this answers "is
        anything arriving at all", which is a different question from
        "is what arrives making it to the bus" (events_dropped/events_lost
        already answer that one). See the ingestion-edge-redundancy design
        doc (fengarde-sec) step 2 for why this didn't exist before.

        Gap-hunt (2026-08-26) #80: uses a monotonic clock, NOT wall-clock
        time.time() -- an NTP step backward or a VM suspend/resume used to
        make this go NEGATIVE, silently disabling the silence watchdog during
        the exact kind of event most likely to accompany a real outage.
        """
        return time.monotonic() - self._last_received_ts

    def _worker_loop(self) -> None:
        # R4-72 (gap-hunt 2026-08-26): keep working after stop() clears _running until the queue is
        # empty, so datagrams already accepted are handled, not discarded uncounted.
        while self._running.is_set() or not self._queue.empty():
            try:
                item = self._queue.get(timeout=0.5)
            except queue.Empty:
                if not self._running.is_set():
                    break
                continue
            if item is None:  # stop() sentinel
                break
            data, peer_ip = item
            try:
                self._handle_datagram(data, peer_ip)
            except Exception as exc:  # a handler bug must not kill the worker
                if self.log is not None:
                    self.log.warn("syslog datagram handler raised",
                                  src=peer_ip, error=str(exc))

    def _drain_spool_loop(self) -> None:
        """Periodically replay spooled events into the bus. Runs until stop()
        sets _spool_shutdown; a produce failure just means the flood/outage
        hasn't cleared yet, so drain_into() stops early and this loop retries
        next interval -- no busy-spinning, no event loss from a mid-drain
        failure (drain_into rewrites only the successfully-replayed prefix)."""
        while not self._spool_shutdown.is_set():
            spool = self._spool
            if spool is None:
                return
            try:
                drained = spool.drain_into(
                    lambda item: self.bus.produce(
                        self.topic, key=item["key"], payload=item["event"]))
                if drained and self.log is not None:
                    self.log.info("replayed spooled syslog events",
                                  count=drained,
                                  pending=spool.pending_count())
            except Exception as exc:  # never let the drain loop die silently
                if self.log is not None:
                    self.log.warn("spool drain failed", error=str(exc))
            self._spool_shutdown.wait(self._spool_drain_interval_s)

    def stop(self) -> None:
        """Stop serving and release the socket (graceful)."""
        self._running.clear()
        # Closing the socket unblocks the recv thread's blocking recvfrom()
        # (it raises OSError, caught in _recv_loop, which then re-checks
        # _running and exits).
        try:
            self._sock.close()
        except OSError:
            pass
        if self._recv_thread is not None:
            self._recv_thread.join(timeout=5)
            self._recv_thread = None
        # Wake every worker blocked in queue.get() so they notice _running is
        # clear promptly rather than waiting out their own 0.5s poll timeout.
        for _ in self._worker_threads:
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                pass
        for t in self._worker_threads:
            t.join(timeout=5)
        self._worker_threads = []
        # Anything the workers could not finish within the join timeout is lost: COUNT it.
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            if item is not None:
                with self._dispatcher._shed_lock:  # noqa: SLF001 -- same family
                    self._dispatcher.events_lost += 1
        self._spool_shutdown.set()
        if self._spool_thread is not None:
            self._spool_thread.join(timeout=5)
            self._spool_thread = None
        if self.log is not None:
            self.log.info("syslog UDP stopped", host=self.host, port=self.port)
