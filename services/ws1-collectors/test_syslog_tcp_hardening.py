"""Hardening tests for the TCP syslog listener (review findings on PR 146).

  1. a TCP spool is replayed into the bus once the bus recovers (only UDP used to drain its spool)
  2. an octet-counted message whose optional trailing LF arrives in a LATER segment does not kill the connection
  3. a final newline-framed message with no terminator is dispatched at EOF
  4. one peer cannot hold every connection slot (per-peer cap)
  5. stop() returns promptly with idle connections open and leaves no live listener threads
  6. transport counters stay exact under concurrent connections
  7. a failed bind does not leak the socket

Zero-infra (loopback, ephemeral port). Run: python services/ws1-collectors/test_syslog_tcp_hardening.py
"""
from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
os.environ["BUS_BACKEND"] = "memory"

from shared.bus import Bus  # noqa: E402
from collectors.spool import BoundedSpool  # noqa: E402
from collectors.syslog_tcp_server import SyslogTCPServer, FRAMING_OCTET  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def wait_for(cond, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def conn(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.settimeout(5)
    return s


class FlakyBus:
    """Fails produce() until .up is set; records what finally arrives."""

    def __init__(self):
        self.up = False
        self.got = []

    def produce(self, topic, key, payload):
        if not self.up:
            raise ConnectionError("bus down (test)")
        self.got.append(payload)


def main() -> int:
    # 1. TCP spool replay
    with tempfile.TemporaryDirectory() as td:
        bus = FlakyBus()
        spool = BoundedSpool(Path(td) / "tcp-spool.jsonl", max_bytes=1 << 20)
        srv = SyslogTCPServer(bus, host="127.0.0.1", port=0, spool=spool, spool_drain_interval_s=0.2)
        srv.start()
        try:
            s = conn(srv.port)
            s.sendall(b"one\ntwo\nthree\n")
            s.close()
            check(wait_for(lambda: srv.events_spooled >= 3), "events must be spooled while the bus is down")
            bus.up = True
            check(wait_for(lambda: len(bus.got) >= 3, 8),
                  f"spooled TCP events must be replayed once the bus recovers, got {len(bus.got)}")
            check(spool.pending_count() == 0, f"spool must be empty after replay, pending={spool.pending_count()}")
        finally:
            srv.stop()

    # 2. octet-counting: LF in a later segment
    bus = Bus()
    srv = SyslogTCPServer(bus, host="127.0.0.1", port=0, framing=FRAMING_OCTET)
    srv.start()
    try:
        s = conn(srv.port)
        s.sendall(b"5 hello")
        time.sleep(0.2)
        s.sendall(b"\n")
        time.sleep(0.2)
        s.sendall(b"5 world\n")
        check(wait_for(lambda: srv.events_produced >= 2),
              f"both octet frames must be produced when the trailing LF arrives late, got {srv.events_produced}")
        check(srv.events_frame_oversize == 0, "a late LF must not be counted as a framing violation")
        s.sendall(b"3 abc")
        check(wait_for(lambda: srv.events_produced >= 3), "the connection must still be usable after the late LF")
        s.close()
    finally:
        srv.stop()

    # 3. EOF without terminator
    bus = Bus()
    srv = SyslogTCPServer(bus, host="127.0.0.1", port=0)
    srv.start()
    try:
        s = conn(srv.port)
        s.sendall(b"complete\nlast-without-newline")
        s.shutdown(socket.SHUT_WR)
        s.close()
        check(wait_for(lambda: srv.events_produced >= 2),
              f"an unterminated final line must be dispatched at EOF, got {srv.events_produced}")
    finally:
        srv.stop()

    # 4. per-peer cap
    srv = SyslogTCPServer(Bus(), host="127.0.0.1", port=0, max_connections_per_peer=2, idle_timeout_s=30)
    srv.start()
    held = []
    try:
        for _ in range(2):
            held.append(conn(srv.port))
        time.sleep(0.3)
        extra = conn(srv.port)
        check(wait_for(lambda: srv.events_conn_refused_peer >= 1),
              "a third connection from one address must be refused by the per-peer cap")
        extra.close()
    finally:
        for h in held:
            h.close()
        srv.stop()

    # 5. stop() with idle connections
    srv = SyslogTCPServer(Bus(), host="127.0.0.1", port=0, idle_timeout_s=60)
    srv.start()
    idle = [conn(srv.port) for _ in range(3)]
    time.sleep(0.3)
    t0 = time.monotonic()
    srv.stop()
    elapsed = time.monotonic() - t0
    check(elapsed < 4.0, f"stop() must return promptly with idle connections open, took {elapsed:.1f}s")
    still = [t for t in threading.enumerate() if t.name.startswith("syslog-tcp") and t.is_alive()]
    check(wait_for(lambda: not [t for t in threading.enumerate() if t.name.startswith("syslog-tcp-conn")
                                and t.is_alive()], 5),
          f"connection threads must end after stop(), still alive: {[t.name for t in still]}")
    for s in idle:
        s.close()

    # 6. exact counters under concurrency
    srv = SyslogTCPServer(Bus(), host="127.0.0.1", port=0, max_connections=128, max_connections_per_peer=128)
    srv.start()
    try:
        def burst():
            for _ in range(20):
                s = conn(srv.port)
                s.sendall(b"x\n")
                s.close()
        ts = [threading.Thread(target=burst) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        check(wait_for(lambda: srv.events_conn_closed >= 160, 15),
              f"160 clean closes must be counted exactly, got {srv.events_conn_closed}")
        time.sleep(0.3)
        check(srv.events_conn_closed == 160, f"closes must not exceed or lose counts, got {srv.events_conn_closed}")
    finally:
        srv.stop()

    # 8. shared dispatcher: ONE rate cap, one counter set across UDP and TCP
    from collectors.syslog_udp_server import SyslogUDPServer
    ubus = Bus()
    udp = SyslogUDPServer(ubus, host="127.0.0.1", port=0, max_events_per_sec=2)
    tcp = SyslogTCPServer(ubus, host="127.0.0.1", port=0, dispatcher=udp.dispatcher)
    tcp.start()
    try:
        udp.dispatcher.handle_line("from-udp-1", "10.0.0.9")
        udp.dispatcher.handle_line("from-udp-2", "10.0.0.9")     # the 2/s cap is now used up
        s = conn(tcp.port)
        s.sendall(b"from-tcp-1\n")
        s.close()
        check(wait_for(lambda: udp.events_shed >= 1),
              f"the TCP line must be shed by the cap the UDP lines already consumed, shed={udp.events_shed}")
        check(udp.events_produced == 2, f"shared counters must show UDP's 2 produced, got {udp.events_produced}")
        check("tcp_events_produced" not in tcp.metrics(),
              "a TCP listener sharing the dispatcher must not re-export the event counters under tcp_")
    finally:
        tcp.stop()

    # 9. secure default bind
    from collectors import syslog_tcp_server as mod
    check(mod.DEFAULT_HOST == "127.0.0.1", f"the TCP listener must default to loopback, got {mod.DEFAULT_HOST}")

    # 10. throughput of the framing path (no per-frame re-copy): 20000 small frames in one buffer
    srv = SyslogTCPServer(Bus(), host="127.0.0.1", port=0)
    buf = bytearray(b"x" * 90 + b"\n") * 20000
    t0 = time.perf_counter()
    ok = srv._drain_newline("10.0.0.1", buf)
    dt = time.perf_counter() - t0
    check(ok and len(buf) == 0 and srv.events_produced == 20000, f"20000 frames must all be dispatched, got {srv.events_produced}")
    check(dt < 5.0, f"framing 20000 frames took {dt:.2f}s; the remainder is being re-copied per frame")
    srv.stop()

    # 7. failed bind closes the socket
    a = SyslogTCPServer(Bus(), host="127.0.0.1", port=0)
    try:
        before = len(os.listdir("/proc/self/fd")) if os.path.isdir("/proc/self/fd") else None
        raised = False
        try:
            SyslogTCPServer(Bus(), host="127.0.0.1", port=a.port)
        except OSError:
            raised = True
        check(raised or sys.platform == "win32", "binding an occupied port must raise OSError")
        if before is not None:
            check(len(os.listdir("/proc/self/fd")) <= before, "a failed bind must not leak a descriptor")
    finally:
        a.stop()

    if FAILS:
        print(f"[FAIL] ws1 TCP syslog hardening: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        return 1
    print("[OK] ws1 TCP syslog hardening: spool replay, late trailing LF, EOF tail, per-peer cap, prompt stop, "
          "exact counters, no socket leak on bind failure")
    return 0


if __name__ == "__main__":
    sys.exit(main())
