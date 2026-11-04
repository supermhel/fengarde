"""Real TCP syslog listener (WP-1.2) -- RFC 6587 framing, shared dispatch.

Adds live TCP syslog to WS-1 next to the UDP listener. Each decoded frame
becomes a ``raw.events`` message through the same dispatch CODE (``SyslogDispatcher``)
as UDP. Each listener owns its OWN dispatcher instance, so token buckets, counters, per-source metrics and
the spool are per listener, not pooled: the configured cap applies to UDP and to TCP separately.

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
DEFAULT_MAX_CONN_PER_PEER = 16           # one peer cannot hold every slot
DEFAULT_SPOOL_DRAIN_INTERVAL_S = 5.0
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
                 max_connections_per_peer: int = DEFAULT_MAX_CONN_PER_PEER,
                 spool: Optional[BoundedSpool] = None,
                 spool_drain_interval_s: float = DEFAULT_SPOOL_DRAIN_INTERVAL_S,
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
        self.max_connections_per_peer = max(1, int(max_connections_per_peer))
        self._spool_drain_interval_s = spool_drain_interval_s
        self._spool_shutdown = threading.Event()
        self._spool_thread: Optional[threading.Thread] = None
        self._stat_lock = threading.Lock()
        self._peer_conns: dict[str, int] = {}
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
        self.events_conn_refused_peer = 0   # per-peer connection cap
        self.events_truncated_frames = 0    # EOF mid-frame (octet mode)

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((host, self.port))
            self.host, self.port = self._sock.getsockname()[0], self._sock.getsockname()[1]
            # Backlog 128 mirrors the HTTP listener's hardening (default 5 refuses
            # legitimate connection bursts on some platforms).
            self._sock.listen(128)
        except OSError:
            self._sock.close()          # a failed start must not leak the descriptor
            raise
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

    @property
    def _spool(self):
        return self._dispatcher._spool  # noqa: SLF001 -- same family

    def _bump(self, name: str) -> None:
        """Thread-safe increment of a transport counter (connection threads share them)."""
        with self._stat_lock:
            setattr(self, name, getattr(self, name) + 1)

    def start(self) -> None:
        if self._running.is_set():
            return
        self._running.set()
        if self._spool is not None and self._spool_thread is None:
            # Review of PR 146: only the UDP server replayed its spool, so a TCP spool filled during a bus outage
            # was never drained. TCP now owns a drain loop for its own spool.
            self._spool_thread = threading.Thread(target=self._drain_spool_loop,
                                                  name="syslog-tcp-spool-drain", daemon=True)
            self._spool_thread.start()
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
            with self._conn_lock:
                over_peer = self._peer_conns.get(addr[0], 0) >= self.max_connections_per_peer
            if over_peer:
                conn.close()
                self._bump("events_conn_refused_peer")
                continue
            if not self._slots.acquire(blocking=False):
                conn.close()
                self._bump("events_conn_refused")
                continue
            self._bump("events_conn_accepted")
            with self._conn_lock:
                self._conns.add(conn)
                self._peer_conns[addr[0]] = self._peer_conns.get(addr[0], 0) + 1
            t = threading.Thread(target=self._conn_loop, args=(conn, addr[0]),
                                 name="syslog-tcp-conn", daemon=True)
            t.start()

    def _conn_loop(self, conn: socket.socket, peer_ip: str) -> None:
        buffer = b""
        state = {"lf": False}
        try:
            conn.settimeout(self.idle_timeout_s)
            while self._running.is_set():
                try:
                    chunk = conn.recv(_RECV_CHUNK)
                except socket.timeout:
                    self._bump("events_idle_closed")
                    break
                if not chunk:
                    self._bump("events_conn_closed")
                    # EOF: a final newline-framed message with no terminator is still a message (`printf msg | nc`);
                    # an unfinished octet-counted frame is counted, not silently dropped.
                    if buffer:
                        if self.framing == FRAMING_NEWLINE:
                            if len(buffer) <= self.max_frame_bytes:
                                self._dispatcher.handle_line(
                                    buffer.decode("utf-8", errors="replace").rstrip("\r"), peer_ip)
                        else:
                            self._bump("events_truncated_frames")
                    break
                buffer += chunk
                if self.framing == FRAMING_OCTET:
                    rest = self._drain_octet(peer_ip, buffer, state)
                else:
                    rest = self._drain_newline(peer_ip, buffer)
                if rest is None:            # protocol violation -> reject
                    break
                buffer = rest
        except OSError:
            self._bump("events_conn_errors")
        finally:
            try:
                conn.close()
            except OSError:
                pass
            with self._conn_lock:
                self._conns.discard(conn)
                n = self._peer_conns.get(peer_ip, 0) - 1
                if n > 0:
                    self._peer_conns[peer_ip] = n
                else:
                    self._peer_conns.pop(peer_ip, None)
            self._slots.release()

    def _reject(self, peer_ip: str) -> None:
        """Count one framing-violation close (called when a drainer returns
        None). Throttled log: a talker sending garbage gets one warning per
        connection, then the reset."""
        self._bump("events_frame_oversize")
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

    def _drain_octet(self, peer_ip: str, buffer: bytes, state: Optional[dict] = None):
        st = state if state is not None else {"lf": False}
        while True:
            if st["lf"] and buffer:
                # The optional LF after the previous message arrived in a LATER segment than the message itself.
                if buffer.startswith(b"\n"):
                    buffer = buffer[1:]
                st["lf"] = False
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
            # Interop: some senders append a newline after the message; it may not have arrived yet.
            if buffer.startswith(b"\n"):
                buffer = buffer[1:]
            elif not buffer:
                st["lf"] = True
            line = msg.decode("utf-8", errors="replace").rstrip("\r")
            self._dispatcher.handle_line(line, peer_ip)

    # -- counters / metrics -------------------------------------------------

    def is_running(self) -> bool:
        return self._running.is_set() and bool(
            self._accept_thread and self._accept_thread.is_alive())

    def _drain_spool_loop(self) -> None:
        """Replay this listener's spool into the bus until stop(); a produce failure just means the outage has not
        cleared, so drain_into() stops early and the loop retries next interval (same contract as the UDP loop)."""
        while not self._spool_shutdown.is_set():
            spool = self._spool
            if spool is None:
                return
            try:
                drained = spool.drain_into(
                    lambda item: self.bus.produce(self.topic, key=item["key"], payload=item["event"]))
                if drained and self.log is not None:
                    self.log.info("replayed spooled tcp syslog events", count=drained,
                                  pending=spool.pending_count())
            except Exception as exc:  # never let the drain loop die silently
                if self.log is not None:
                    self.log.warn("tcp spool drain failed", error=str(exc))
            self._spool_shutdown.wait(self._spool_drain_interval_s)

    def stop(self) -> None:
        self._running.clear()
        self._spool_shutdown.set()
        try:
            self._sock.shutdown(socket.SHUT_RDWR)   # wakes a blocked accept() on platforms where close() alone does not
        except OSError:
            pass
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
                conn.shutdown(socket.SHUT_RDWR)     # wake the connection thread's recv()
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
        if self._spool_thread is not None:
            self._spool_thread.join(timeout=5)
            self._spool_thread = None
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
            "tcp_syslog_conn_refused_peer": self.events_conn_refused_peer,
            "tcp_syslog_truncated_frames": self.events_truncated_frames,
            "tcp_syslog_conn_errors": self.events_conn_errors,
            "tcp_syslog_idle_closed": self.events_idle_closed,
            "tcp_syslog_conn_closed": self.events_conn_closed,
            "tcp_syslog_conn_accepted": self.events_conn_accepted,
        }