"""Real TCP syslog listener (WP-1.2) -- RFC 6587 framing, shared dispatch.

Adds live TCP syslog to WS-1 next to the UDP listener. Each decoded frame
becomes a ``raw.events`` message through the SAME ``SyslogDispatcher`` as
UDP (token buckets, bounded-spool fallback, counters, per-source metrics), so
the two transports are one ingest pipeline, not two.

Framing (RFC 6587):
  * ``newline`` (``SYSLOG_TCP_FRAMING=newline``, default): frames are
    terminated by LF; a trailing CR is stripped. A partial frame persists in
    the per-connection buffer until the LF arrives (no worker pinned by a
    slow sender -- each connection owns one thread, bounded by
    ``max_connections`` and an idle timeout).
  * ``octet-counting``: ``MSG-LEN SP SYSLOG-MSG`` where MSG-LEN is the
    decimal octet count of the message (RFC 6587 s3.4.1). The length field
    may arrive separately from the message; both are buffered across reads.
    One trailing LF after the message is tolerated for interop (some
    senders append it despite the RFC).

Failure modes (all counted, all on the connection that misbehaved):
  * frame longer than ``max_frame_bytes`` -> counted, connection closed
    (reject = reset, a loud signal the sender must fix its framing);
  * non-numeric or runaway length header (octet mode) -> same;
  * a connection that stays silent past ``idle_timeout_s`` is closed;
  * more than ``max_connections`` simultaneous peers -> newest connection
    refused (closed immediately, counted in ``events_conn_refused``).

TLS (RFC 5425) is deliberately NOT here: it is the follow-up PR per the
roadmap (cert/key env vars, refuse to start on unreadable files).
"""
from __future__ import annotations

import socket
import threading
import time
from typing import Optional

from .syslog_dispatch import SyslogDispatcher
from .spool import BoundedSpool

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5515
DEFAULT_MAX_FRAME_BYTES = 65536          # matches the UDP datagram budget
DEFAULT_MAX_CONNECTIONS = 64
DEFAULT_IDLE_TIMEOUT_S = 30
FRAMING_NEWLINE = "newline"
FRAMING_OCTET = "octet-counting"
FRAMINGS = (FRAMING_NEWLINE, FRAMING_OCTET)
# A length header or a delimiter gap longer than this is not a frame, it is
# garbage (prevents an unbounded buffer wait on a talker that never sends a
# space/newline). 16 bytes covers any sane MSG-LEN (<= 2^53 would be 17).
_MAX_HEADER_BYTES = 16
_RECV_CHUNK = 64 * 1024


class SyslogTCPServer:
    """Threaded TCP syslog listener sharing the UDP dispatcher.

    Mirrors SyslogUDPServer's lifecycle (``start()``/``stop()``/
    ``is_running()``) and counter style; the transport-specific counters
    (oversize frames, refused connections, idle closes) are added here, the
    event counters live in the shared dispatcher.
    """

    def __init__(self, bus, *, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 topic: str = "raw.events", framing: str = FRAMING_NEWLINE,
                 max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
                 max_events_per_sec: float = 0,
                 max_connections: int = DEFAULT_MAX_CONNECTIONS,
                 idle_timeout_s: float = DEFAULT_IDLE_TIMEOUT_S,
                 spool: Optional[BoundedSpool] = None,
                 deterministic_id: bool = False,
                 logger=None):
        if framing not in FRAMINGS:
            raise ValueError(f"SYSLOG_TCP_FRAMING must be one of {FRAMINGS}, "
                             f"got {framing!r}")
        if max_frame_bytes <= 0:
            raise ValueError("SYSLOG_TCP_MAX_FRAME_BYTES must be > 0")
        self.bus = bus
        self.host = host
        self.port = int(port)
        self.topic = topic
        self.framing = framing
        self.max_frame_bytes = int(max_frame_bytes)
        self.max_connections = max(1, int(max_connections))
        self.idle_timeout_s = float(idle_timeout_s)
        # Shared dispatch: same pipeline as the UDP listener. (No self.log =
        # here: ``log`` is a forwarded property; the dispatcher receives the
        # logger directly and the property setter serves post-construction
        # replacement, the pattern test_syslog_udp.py relies on.)
        self._dispatcher = SyslogDispatcher(
            bus, topic=topic, max_events_per_sec=max_events_per_sec,
            spool=spool, deterministic_id=deterministic_id, logger=logger)
        # Transport-specific counters.
        self.events_frame_oversize = 0
        self.events_conn_refused = 0     # at max_connections
        self.events_conn_errors = 0      # unexpected per-connection exceptions
        self.events_idle_closed = 0      # idle timeout closed the connection
        self.events_conn_closed = 0      # clean EOF
        self.events_conn_accepted = 0

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, self.port))
        self.host, self.port = self._sock.getsockname()[0], self._sock.getsockname()[1]
        # Backlog 128 mirrors the HTTP listener's hardening (default 5 refuses
        # legitimate connection bursts on some platforms).
        self._sock.listen(128)
        self._slots = threading.BoundedSemaphore(self.max_connections)
        self._conn_lock = threading.Lock()
        self._conns: set[socket.socket] = set()
        self._accept_thread: Optional[threading.Thread] = None
        self._running = threading.Event()

    # -- lifecycle ----------------------------------------------------------

    # WP-1.2: event counters live in the shared dispatcher (same pipeline as
    # UDP); these forwards keep the server object the one place tests and
    # callers read. The log forward preserves the replace-after-construction
    # pattern test_syslog_udp.py uses.
    @property
    def log(self):
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

    def start(self) -> None:
        if self._running.is_set():
            return
        self._running.set()
        self._accept_thread = threading.Thread(target=self._accept_loop,
                                               name="syslog-tcp-accept",
                                               daemon=True)
        self._accept_thread.start()
        if self.log is not None:
            self.log.info("syslog tcp listening", host=self.host, port=self.port,
                          framing=self.framing, max_frame_bytes=self.max_frame_bytes,
                          max_connections=self.max_connections,
                          idle_timeout_s=self.idle_timeout_s)

    def _accept_loop(self) -> None:
        while self._running.is_set():
            try:
                conn, addr = self._sock.accept()
            except OSError:
                if not self._running.is_set():
                    break
                time.sleep(0.1)   # transient accept error: back off, don't spin
                continue
            if not self._running.is_set():
                conn.close()
                break
            if not self._slots.acquire(blocking=False):
                conn.close()
                self.events_conn_refused += 1
                continue
            self.events_conn_accepted += 1
            with self._conn_lock:
                self._conns.add(conn)
            t = threading.Thread(target=self._conn_loop, args=(conn, addr[0]),
                                 name="syslog-tcp-conn", daemon=True)
            t.start()

    def _conn_loop(self, conn: socket.socket, peer_ip: str) -> None:
        buffer = b""
        try:
            conn.settimeout(self.idle_timeout_s)
            while self._running.is_set():
                try:
                    chunk = conn.recv(_RECV_CHUNK)
                except socket.timeout:
                    self.events_idle_closed += 1
                    break
                if not chunk:
                    self.events_conn_closed += 1
                    break
                buffer += chunk
                if self.framing == FRAMING_OCTET:
                    buffer = self._drain_octet(peer_ip, buffer)
                else:
                    buffer = self._drain_newline(peer_ip, buffer)
                if buffer is None:          # protocol violation -> reject
                    break
        except OSError:
            self.events_conn_errors += 1
        finally:
            try:
                conn.close()
            except OSError:
                pass
            with self._conn_lock:
                self._conns.discard(conn)
            self._slots.release()

    def _reject(self, peer_ip: str) -> None:
        """Count one framing-violation close (called when a drainer returns
        None). Throttled log: a talker sending garbage gets one warning per
        connection, then the reset."""
        self.events_frame_oversize += 1
        if self.log is not None:
            self.log.warn("closing tcp syslog connection: framing violation",
                          src=peer_ip, framing=self.framing,
                          max_frame_bytes=self.max_frame_bytes)

    def _drain_newline(self, peer_ip: str, buffer: bytes):
        while True:
            idx = buffer.find(b"\n")
            if idx < 0:
                # No terminator yet: an over-cap pending frame has nowhere to
                # go -- reject (the frame cannot complete within the cap).
                if len(buffer) > self.max_frame_bytes:
                    self._reject(peer_ip)
                    return None
                return buffer
            frame, buffer = buffer[:idx], buffer[idx + 1:]
            if len(frame) > self.max_frame_bytes:
                self._reject(peer_ip)
                return None
            line = frame.decode("utf-8", errors="replace").rstrip("\r")
            self._dispatcher.handle_line(line, peer_ip)

    def _drain_octet(self, peer_ip: str, buffer: bytes):
        while True:
            sp = buffer.find(b" ")
            if sp < 0:
                # No length header yet: either it is still arriving or the
                # peer is not speaking octet-counting at all.
                if len(buffer) > _MAX_HEADER_BYTES:
                    self._reject(peer_ip)
                    return None
                return buffer
            hdr = buffer[:sp]
            if sp > _MAX_HEADER_BYTES or not hdr.isdigit():
                self._reject(peer_ip)
                return None
            length = int(hdr)
            if length > self.max_frame_bytes:
                self._reject(peer_ip)
                return None
            need = sp + 1 + length
            if len(buffer) < need:
                if len(buffer) > self.max_frame_bytes + _MAX_HEADER_BYTES:
                    self._reject(peer_ip)  # belt: cannot make progress within the cap
                    return None
                return buffer
            msg = buffer[sp + 1:need]
            buffer = buffer[need:]
            # Interop: some senders append a newline after the message.
            if buffer.startswith(b"\n"):
                buffer = buffer[1:]
            line = msg.decode("utf-8", errors="replace").rstrip("\r")
            self._dispatcher.handle_line(line, peer_ip)

    # -- counters / metrics -------------------------------------------------

    def is_running(self) -> bool:
        return self._running.is_set() and bool(
            self._accept_thread and self._accept_thread.is_alive())

    def stop(self) -> None:
        self._running.clear()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=5)
            self._accept_thread = None
        with self._conn_lock:
            conns = list(self._conns)
            self._conns.clear()
        for conn in conns:
            try:
                conn.close()
            except OSError:
                pass
        # NOTE: the conn threads release() the semaphore themselves in their
        # finally -- replacing _slots here would double-release into a fresh
        # object (ValueError) and also loses the slot accounting.
        if self.log is not None:
            self.log.info("syslog tcp stopped", host=self.host, port=self.port)

    def metrics(self) -> dict:
        """Flat transport AND shared-dispatch counters for /metrics.

        The event counters (produced/dropped/shed/spooled/lost/empty) are the
        dispatcher's -- shared with UDP -- so they are exported here under the
        ``tcp_`` prefix, mirroring http_json_collector's ``http_events_*``.
        Without this the TCP-produced events were invisible on /metrics while
        flowing to the bus (live-verified)."""
        d = self._dispatcher
        return {
            "tcp_events_produced": d.events_produced,
            "tcp_events_dropped": d.events_dropped,
            "tcp_events_shed": d.events_shed,
            "tcp_events_spooled": d.events_spooled,
            "tcp_events_lost": d.events_lost,
            "tcp_events_empty": d.events_empty,
            "tcp_syslog_events_oversize": self.events_frame_oversize,
            "tcp_syslog_conn_refused": self.events_conn_refused,
            "tcp_syslog_conn_errors": self.events_conn_errors,
            "tcp_syslog_idle_closed": self.events_idle_closed,
            "tcp_syslog_conn_closed": self.events_conn_closed,
            "tcp_syslog_conn_accepted": self.events_conn_accepted,
        }