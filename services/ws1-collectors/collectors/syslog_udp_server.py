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

import hashlib
import queue
import socket
import threading
import time
import uuid
from typing import Optional

from .spool import BoundedSpool
from shared.envelope import stamp_meta

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
# Best-effort kernel receive-buffer size (bytes). Linux typically caps this via
# net.core.rmem_max unless raised; setsockopt succeeding doesn't guarantee the
# full value was actually granted, but asking for headroom is still strictly
# better than leaving the OS default (often as low as 128KB) during a burst.
DEFAULT_SO_RCVBUF = 8 * 1024 * 1024


def udp_rcvbuf_errors() -> Optional[int]:
    """Cumulative kernel-level UDP receive-buffer-overflow count for this
    host/container, i.e. datagrams the OS dropped BEFORE any Python code ever
    saw them -- the exact loss class that reads as a healthy `events_shed=0
    events_dropped=0` at the app layer (live-proven, see the module
    docstring). Returns None off-Linux or if `/proc/net/snmp` isn't readable
    (never raises); the caller degrades to omitting the metric rather than
    crashing /metrics over an unavailable procfs.

    Cumulative since boot, not a rate -- a caller wanting a rate must diff two
    samples over a known interval, same convention as any other /proc counter.
    """
    try:
        with open("/proc/net/snmp", "r", encoding="ascii") as f:
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


class _TokenBucket:
    """Token bucket: capacity == rate, refills continuously by elapsed time.

    A burst up to `rate` tokens is allowed instantly (a source flushing a
    small backlog shouldn't get throttled just for existing); sustained
    traffic above `rate`/sec sheds the excess. `rate <= 0` disables limiting
    (every take() succeeds) -- the default state for tests and any deployment
    that hasn't opted in yet.
    """

    def __init__(self, rate_per_sec: float):
        self.rate = rate_per_sec
        self.capacity = max(rate_per_sec, 0)
        self.tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def take(self) -> bool:
        if self.rate <= 0:
            return True
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False


def _deterministic_ingest_id(line: str) -> str:
    """SHA-256-derived UUID-like id (mirrors WS-2's generic_syslog parser)."""
    digest = hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()
    return f"{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def build_raw_event(line: str, *, deterministic_id: bool = False) -> dict:
    """Wrap a decoded syslog line into a WS-2-parseable raw event."""
    if deterministic_id:
        ingest_id = _deterministic_ingest_id(line)
    else:
        ingest_id = str(uuid.uuid4())
    return {
        "source_type": "generic_syslog",
        "raw": line,
        "meta": stamp_meta({
            "received_at": int(time.time()),
            "ingest_id": ingest_id,
        }),
    }


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
    :param logger: optional shared.log Logger.
    """

    def __init__(self, bus, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 topic: str = "raw.events", deterministic_id: bool = False,
                 max_events_per_sec: float = 0,
                 spool: Optional[BoundedSpool] = None,
                 spool_drain_interval_s: float = 5.0, logger=None,
                 workers: int = DEFAULT_WORKERS,
                 queue_maxsize: int = DEFAULT_QUEUE_MAXSIZE,
                 so_rcvbuf: int = DEFAULT_SO_RCVBUF):
        self.bus = bus
        self.topic = topic
        self.deterministic_id = deterministic_id
        self.log = logger
        self.events_produced = 0
        self.events_dropped = 0     # bus produce failed AND no spool (or spool full)
        self.events_shed = 0        # rate-limited AND no spool (or spool full)
        self.events_spooled = 0     # written to the fallback spool, pending replay
        self.events_lost = 0        # spool configured but itself at capacity
        self.events_queue_full = 0  # P0-4: worker pool saturated, queue.put_nowait refused
        self._bucket = _TokenBucket(max_events_per_sec)
        self._last_shed_log = 0.0   # throttles the shed-warning log itself: a
                                    # real flood must not turn into a log flood
        # P0-4: genuinely concurrent now (a fixed pool of worker threads all
        # call _handle_datagram), so this lock is load-bearing, not defensive.
        self._shed_lock = threading.Lock()
        self._spool = spool
        self._spool_drain_interval_s = spool_drain_interval_s
        self._spool_shutdown = threading.Event()
        self._spool_thread: Optional[threading.Thread] = None

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

    def _handle_datagram(self, data: bytes, peer_ip: str) -> None:
        line = data.decode("utf-8", errors="replace").rstrip("\r\n")
        if not line:
            return
        if not self._bucket.take():
            # B2: shed at the ingest edge rather than let an unbounded flood
            # grow the bus stream directly. If a spool is configured (the
            # zero-loss-under-flood opt-in, see spool.py), try there first --
            # only truly lost once the spool itself is full (or the spool
            # write itself unexpectedly errors -- _try_spool never raises).
            event = build_raw_event(line, deterministic_id=self.deterministic_id)
            if self._try_spool(peer_ip, event):
                self.events_spooled += 1
                return
            self._count_shed(peer_ip, lost_to_full_spool=self._spool is not None)
            return
        event = build_raw_event(line, deterministic_id=self.deterministic_id)
        try:
            self.bus.produce(self.topic, key=peer_ip, payload=event)
        except Exception as exc:  # bus/Redis unreachable -> try the spool before dropping
            if self._try_spool(peer_ip, event):
                self.events_spooled += 1
                return
            self.events_dropped += 1
            if self.log is not None:
                self.log.warn("dropped syslog datagram: bus produce failed",
                              src=peer_ip, error=str(exc),
                              spool_full=self._spool is not None)
            return
        self.events_produced += 1
        # P0-4: no per-datagram log here anymore -- a JSON-dumps + stdout
        # flush syscall pair per event roughly doubled per-event cost (see
        # shared/log.py) and turned line-rate ingest into a log flood.
        # events_produced already counts the same fact on /metrics.

    def _try_spool(self, peer_ip: str, event: dict) -> bool:
        """Best-effort spool write. False on no-spool-configured, spool-full,
        OR any unexpected error (BoundedSpool.append() already treats OSError
        as "not spooled", but this belt-and-suspenders catch means a bug in
        the spool itself degrades to "count as shed/dropped" rather than
        crashing the UDP handler and losing the datagram's accounting)."""
        if self._spool is None:
            return False
        try:
            return self._spool.append({"key": peer_ip, "event": event})
        except Exception as exc:
            if self.log is not None:
                self.log.warn("spool append failed unexpectedly", src=peer_ip,
                              error=str(exc))
            return False

    def _count_shed(self, peer_ip: str, *, lost_to_full_spool: bool) -> None:
        # Throttle the warning itself (at most once/sec) so a flood can't
        # turn into a logging DoS too. Locked so the counters and the
        # log-throttle timestamp stay correct even under concurrent handlers.
        should_log = False
        with self._shed_lock:
            if lost_to_full_spool:
                self.events_lost += 1
            else:
                self.events_shed += 1
            now = time.monotonic()
            if now - self._last_shed_log >= 1.0:
                self._last_shed_log = now
                should_log = True
            shed_total, lost_total = self.events_shed, self.events_lost
        if should_log and self.log is not None:
            self.log.warn(
                "shedding syslog datagrams: rate limit exceeded",
                src=peer_ip, events_shed_total=shed_total,
                events_lost_total=lost_total, spool_full=lost_to_full_spool)

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
                # socket closed (stop()) or a transient recv error; either
                # way, re-check _running rather than assuming shutdown.
                continue
            if not self._running.is_set():
                break
            try:
                self._queue.put_nowait((data, addr[0]))
            except queue.Full:
                with self._shed_lock:
                    self.events_queue_full += 1

    def _worker_loop(self) -> None:
        while self._running.is_set():
            try:
                item = self._queue.get(timeout=0.5)
            except queue.Empty:
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
        self._spool_shutdown.set()
        if self._spool_thread is not None:
            self._spool_thread.join(timeout=5)
            self._spool_thread = None
        if self.log is not None:
            self.log.info("syslog UDP stopped", host=self.host, port=self.port)
