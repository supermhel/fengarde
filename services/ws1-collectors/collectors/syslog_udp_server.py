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
It is stdlib-only: a ``socketserver.UDPServer`` running on its own thread, with a
graceful ``stop()``. ``main.py`` runs it as the daemon's real ingestion path
alongside the runner's /health endpoint.

Default bind port is 5514 (not the privileged 514) so it runs without elevation.
Binding to 514 requires root/admin (or CAP_NET_BIND_SERVICE on Linux).
"""
from __future__ import annotations

import hashlib
import socketserver
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
    :param logger: optional shared.log Logger.
    """

    def __init__(self, bus, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 topic: str = "raw.events", deterministic_id: bool = False,
                 max_events_per_sec: float = 0,
                 spool: Optional[BoundedSpool] = None,
                 spool_drain_interval_s: float = 5.0, logger=None):
        self.bus = bus
        self.topic = topic
        self.deterministic_id = deterministic_id
        self.log = logger
        self.events_produced = 0
        self.events_dropped = 0     # bus produce failed AND no spool (or spool full)
        self.events_shed = 0        # rate-limited AND no spool (or spool full)
        self.events_spooled = 0     # written to the fallback spool, pending replay
        self.events_lost = 0        # spool configured but itself at capacity
        self._bucket = _TokenBucket(max_events_per_sec)
        self._last_shed_log = 0.0   # throttles the shed-warning log itself: a
                                    # real flood must not turn into a log flood
        # UDPServer's default handler dispatch is single-threaded (one request
        # at a time), but this lock makes events_shed/_last_shed_log correct
        # even if a future ThreadingUDPServer swap makes handling concurrent.
        self._shed_lock = threading.Lock()
        self._spool = spool
        self._spool_drain_interval_s = spool_drain_interval_s
        self._spool_shutdown = threading.Event()
        self._spool_thread: Optional[threading.Thread] = None

        server = self  # capture for the handler closure

        class _Handler(socketserver.BaseRequestHandler):
            def handle(self):  # noqa: D401
                data, _sock = self.request
                peer_ip = self.client_address[0]
                server._handle_datagram(data, peer_ip)

        self._udp = socketserver.UDPServer((host, port), _Handler)
        # bound address (host, port) — port resolves the real one when 0 was asked
        self.host, self.port = self._udp.server_address[0], self._udp.server_address[1]
        self._thread: Optional[threading.Thread] = None

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
        if self.log is not None:
            self.log.info("syslog datagram", src=peer_ip,
                          ingest_id=event["meta"]["ingest_id"])

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
        """Start serving on a background daemon thread (non-blocking)."""
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._udp.serve_forever, name="syslog-udp", daemon=True)
        self._thread.start()
        if self._spool is not None and self._spool_thread is None:
            self._spool_thread = threading.Thread(
                target=self._drain_spool_loop, name="syslog-spool-drain", daemon=True)
            self._spool_thread.start()
        if self.log is not None:
            self.log.info("syslog UDP listening", host=self.host, port=self.port)

    def _drain_spool_loop(self) -> None:
        """Periodically replay spooled events into the bus. Runs until stop()
        sets _spool_shutdown; a produce failure just means the flood/outage
        hasn't cleared yet, so drain_into() stops early and this loop retries
        next interval -- no busy-spinning, no event loss from a mid-drain
        failure (drain_into rewrites only the successfully-replayed prefix)."""
        while not self._spool_shutdown.is_set():
            try:
                drained = self._spool.drain_into(
                    lambda item: self.bus.produce(
                        self.topic, key=item["key"], payload=item["event"]))
                if drained and self.log is not None:
                    self.log.info("replayed spooled syslog events",
                                  count=drained,
                                  pending=self._spool.pending_count())
            except Exception as exc:  # never let the drain loop die silently
                if self.log is not None:
                    self.log.warn("spool drain failed", error=str(exc))
            self._spool_shutdown.wait(self._spool_drain_interval_s)

    def stop(self) -> None:
        """Stop serving and release the socket (graceful)."""
        self._udp.shutdown()
        self._udp.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        self._spool_shutdown.set()
        if self._spool_thread is not None:
            self._spool_thread.join(timeout=5)
            self._spool_thread = None
        if self.log is not None:
            self.log.info("syslog UDP stopped", host=self.host, port=self.port)
