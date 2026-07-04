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

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5514
# B2 (backpressure decision, docs/superpowers/specs/2026-07-02-argus-v0.3-improvement-plan.md):
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
        "meta": {
            "received_at": int(time.time()),
            "ingest_id": ingest_id,
        },
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
    :param logger: optional shared.log Logger.
    """

    def __init__(self, bus, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 topic: str = "raw.events", deterministic_id: bool = False,
                 max_events_per_sec: float = 0, logger=None):
        self.bus = bus
        self.topic = topic
        self.deterministic_id = deterministic_id
        self.log = logger
        self.events_produced = 0
        self.events_dropped = 0     # datagrams lost because produce() failed
        self.events_shed = 0        # datagrams shed by the rate limiter (B2)
        self._bucket = _TokenBucket(max_events_per_sec)
        self._last_shed_log = 0.0   # throttles the shed-warning log itself: a
                                    # real flood must not turn into a log flood
        # UDPServer's default handler dispatch is single-threaded (one request
        # at a time), but this lock makes events_shed/_last_shed_log correct
        # even if a future ThreadingUDPServer swap makes handling concurrent.
        self._shed_lock = threading.Lock()

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
            # grow the bus stream. Throttle the warning itself (at most once/
            # sec) so the flood can't turn into a logging DoS too. Locked so
            # events_shed and the log-throttle timestamp stay correct even
            # under concurrent handlers.
            should_log = False
            with self._shed_lock:
                self.events_shed += 1
                now = time.monotonic()
                if now - self._last_shed_log >= 1.0:
                    self._last_shed_log = now
                    should_log = True
                total_shed = self.events_shed
            if should_log and self.log is not None:
                self.log.warn("shedding syslog datagrams: rate limit exceeded",
                              src=peer_ip, events_shed_total=total_shed)
            return
        event = build_raw_event(line, deterministic_id=self.deterministic_id)
        try:
            self.bus.produce(self.topic, key=peer_ip, payload=event)
        except Exception as exc:  # bus/Redis unreachable -> drop this datagram, keep serving
            self.events_dropped += 1
            if self.log is not None:
                self.log.warn("dropped syslog datagram: bus produce failed",
                              src=peer_ip, error=str(exc))
            return
        self.events_produced += 1
        if self.log is not None:
            self.log.info("syslog datagram", src=peer_ip,
                          ingest_id=event["meta"]["ingest_id"])

    def start(self) -> None:
        """Start serving on a background daemon thread (non-blocking)."""
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._udp.serve_forever, name="syslog-udp", daemon=True)
        self._thread.start()
        if self.log is not None:
            self.log.info("syslog UDP listening", host=self.host, port=self.port)

    def stop(self) -> None:
        """Stop serving and release the socket (graceful)."""
        self._udp.shutdown()
        self._udp.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self.log is not None:
            self.log.info("syslog UDP stopped", host=self.host, port=self.port)
