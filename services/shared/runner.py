"""Shared service runner (T3).

Owns the long-running consume loop ONCE for every bus-consuming service, so the
five batch services collapse to a single ``serve(...)`` call instead of each
hand-rolling a daemon + health endpoint + ack/DLQ logic.

Design (the parts the T3 Opus review flagged as unwritten):

1. **One thread PER topic** — not one thread iterating topics. WS-3 reads four
   topics; a single thread doing blocking reads would starve topics 2..N. Each
   topic gets its own worker thread that owns its own ``consume`` loop.

2. **Ack AFTER the handler returns** — ``bus.consume`` no longer auto-acks. The
   worker acks only once the handler returns without raising. A raising handler
   leaves the message unacked (in Redis it stays in the PEL for redelivery).

3. **Real redelivery + cap -> DLQ** — between new-message reads each worker calls
   ``bus.claim_pending(topic, group, min_idle_ms, max_redeliveries)``. For Redis
   that reclaims idle PEL entries via XAUTOCLAIM and reads the delivery count from
   XPENDING (``times_delivered``) — a Redis-side counter that survives a restart.
   When the count reaches ``max_redeliveries`` the message is produced to
   ``<topic>.deadletter`` and acked. (MemoryBus has no PEL; its redelivery path is
   exercised deterministically by ``test_runner.py`` via ``_process_message``.)

4. **Re-entry / daemon loop** — ``consume`` returns on the first empty read; the
   worker wraps it in ``while not shutdown.is_set()`` so the service stays up, and
   exits cleanly when the shutdown Event is set (SIGTERM is wired to set it).

Health: a stdlib ``ThreadingHTTPServer`` thread (mirrors ws6/app.py) answers
``GET /health`` with ``{"status":"ok","service":<name>}``.

Usage::

    from shared.runner import serve
    serve({"normalized.events": ("cg-detect", handler)}, health_port=8004)
"""
from __future__ import annotations

import json
import signal
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

# topic -> (consumer_group, handler).  handler(payload: dict) -> None; raise to fail.
Handlers = dict[str, "tuple[str, Callable[[dict], None]]"]


def _make_health_handler(service_name: str):
    class _HealthHandler(BaseHTTPRequestHandler):
        def _send(self, code: int, payload: dict):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802 (stdlib naming)
            if self.path.rstrip("/") in ("/health", ""):
                return self._send(200, {"status": "ok", "service": service_name})
            return self._send(404, {"error": "no such path"})

        def log_message(self, *_):  # quiet
            pass

    return _HealthHandler


def _process_message(bus, topic, group, msg, handler, max_redeliveries,
                     delivery_count):
    """Process one delivery of one message.

    ``delivery_count`` is how many times this message has now been delivered
    (1 on first delivery). Returns one of: "acked" (handler ok, acked),
    "deadlettered" (cap reached -> routed to <topic>.deadletter + acked),
    "failed" (handler raised, left unacked for redelivery).

    Factored out so the redelivery/DLQ decision is one testable function that
    both the live worker and the MemoryBus simulation in test_runner.py drive.
    """
    if delivery_count > max_redeliveries:
        # Exhausted: poison the message to the dead-letter topic and ack it so it
        # stops being redelivered.
        bus.produce(f"{topic}.deadletter", key=msg.key,
                    payload={"topic": topic, "group": group, "id": msg.id,
                             "delivery_count": delivery_count,
                             "payload": msg.payload})
        bus.ack(msg, group)
        return "deadlettered"
    try:
        from shared.log import set_trace_id  # noqa: E402
        set_trace_id(getattr(msg, "id", None))  # follow this event across services
        handler(msg.payload)
    except Exception:  # handler signalled failure -> do NOT ack; leave for redelivery
        traceback.print_exc()
        return "failed"
    bus.ack(msg, group)
    return "acked"


def _topic_worker(bus_factory, topic, group, handler, *, max_redeliveries,
                  shutdown, claim_idle_ms, idle_sleep_s, consume_block_ms,
                  service_name):
    """Own the consume loop for ONE topic until shutdown is set."""
    bus = bus_factory()
    while not shutdown.is_set():
        did_work = False

        # 1) Redeliveries first: reclaim idle PEL entries and apply the cap.
        try:
            for msg, times_delivered in bus.claim_pending(
                    topic, group, claim_idle_ms, max_redeliveries):
                did_work = True
                _process_message(bus, topic, group, msg, handler,
                                  max_redeliveries, times_delivered)
                if shutdown.is_set():
                    break
        except Exception:
            traceback.print_exc()

        # 2) New messages. Bound the blocking read (RedisBus.consume blocks up to
        # block_ms on XREADGROUP): a long block would leave the worker deaf to a
        # shutdown set mid-block, so serve()'s worker.join() could time out. A
        # short block keeps shutdown latency ~= consume_block_ms. MemoryBus
        # ignores block_ms (drains and returns), so this is Redis-only cost.
        try:
            for msg in bus.consume(topic, group=group, block_ms=consume_block_ms):
                did_work = True
                # First delivery == count 1 (the PEL/XPENDING counter starts at 1
                # once a message is read into a group). Redeliveries are handled by
                # the claim_pending branch above, which carries the real count.
                _process_message(bus, topic, group, msg, handler,
                                 max_redeliveries, 1)
                if shutdown.is_set():
                    break
        except Exception:
            traceback.print_exc()

        if not did_work:
            # consume() returned empty (MemoryBus drained, or Redis block expired
            # with nothing new). Sleep briefly so we don't busy-spin, but stay
            # responsive to shutdown.
            shutdown.wait(idle_sleep_s)


def serve(handlers: Handlers, *, health_port: int | None = None,
          max_redeliveries: int = 5, shutdown: threading.Event | None = None,
          service_name: str | None = None, claim_idle_ms: int = 60000,
          idle_sleep_s: float = 0.5, consume_block_ms: int = 1000,
          install_signal_handlers: bool = True,
          bus_factory: Callable | None = None) -> None:
    """Run the bus consume loop for every topic in ``handlers`` until shutdown.

    Args:
        handlers: topic -> (consumer_group, handler). handler(payload) -> None;
            raise to signal failure (message is not acked -> redelivered).
        health_port: if set, start a /health thread on this port.
        max_redeliveries: redeliver up to this many times, then DLQ to
            ``<topic>.deadletter``.
        shutdown: caller-supplied Event; created if None. SIGTERM/SIGINT set it.
        service_name: reported by /health; derived from the topics/groups if None.
        claim_idle_ms: how long a PEL entry must be idle before it is reclaimed.
        idle_sleep_s: pause between empty reads (keeps MemoryBus/Redis from spinning).
        consume_block_ms: max time a worker's RedisBus.consume() blocks on
            XREADGROUP before returning to re-check shutdown; bounds shutdown
            latency (MemoryBus ignores it). Keep < the worker.join() timeout.
        install_signal_handlers: wire SIGTERM/SIGINT to set shutdown (main thread).
        bus_factory: returns a Bus; defaults to shared.bus.Bus. Each worker gets
            its own Bus instance (Redis consumer-name isolation; thread-safety).
    """
    if shutdown is None:
        shutdown = threading.Event()
    if bus_factory is None:
        from shared.bus import Bus
        bus_factory = Bus
    if service_name is None:
        groups = sorted({g for g, _ in handlers.values()})
        service_name = (groups[0] if len(groups) == 1
                        else "+".join(sorted(handlers))) or "service"

    if install_signal_handlers:
        def _on_signal(_signum, _frame):
            shutdown.set()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, _on_signal)
            except (ValueError, OSError):
                # not on the main thread (e.g. under a test runner); skip silently
                pass

    # Health thread (stdlib ThreadingHTTPServer, mirrors ws6/app.py).
    health_srv = None
    health_thread = None
    if health_port is not None:
        health_srv = ThreadingHTTPServer(
            ("0.0.0.0", health_port), _make_health_handler(service_name))
        health_thread = threading.Thread(
            target=health_srv.serve_forever, name="health", daemon=True)
        health_thread.start()

    # One worker thread per topic.
    workers: list[threading.Thread] = []
    for topic, (group, handler) in handlers.items():
        t = threading.Thread(
            target=_topic_worker,
            args=(bus_factory, topic, group, handler),
            kwargs=dict(max_redeliveries=max_redeliveries, shutdown=shutdown,
                        claim_idle_ms=claim_idle_ms, idle_sleep_s=idle_sleep_s,
                        consume_block_ms=consume_block_ms,
                        service_name=service_name),
            name=f"consume:{topic}", daemon=True)
        t.start()
        workers.append(t)

    from shared.log import get_logger  # noqa: E402
    log = get_logger(service_name)
    log.info("serving", topics=list(handlers), health_port=health_port,
             max_redeliveries=max_redeliveries)

    # Block the main thread until shutdown, then drain workers.
    try:
        while not shutdown.is_set():
            shutdown.wait(0.25)
    finally:
        shutdown.set()
        for t in workers:
            t.join(timeout=5)
        if health_srv is not None:
            health_srv.shutdown()
            health_srv.server_close()
        log.info("shut down cleanly")


def run_once(bus, handlers: Handlers, *, max_redeliveries: int = 5) -> dict:
    """Single-pass drain of every topic (no threads, no daemon loop).

    Convenience for MemoryBus / tests and for services that want runner ack+DLQ
    semantics in a batch context. Returns per-topic counts of acked/failed/
    deadlettered messages. Mirrors the old per-service ``run()`` batch shape.
    """
    counts: dict[str, dict] = {}
    for topic, (group, handler) in handlers.items():
        c = {"acked": 0, "failed": 0, "deadlettered": 0}
        for msg in bus.consume(topic, group=group):
            result = _process_message(bus, topic, group, msg, handler,
                                      max_redeliveries, 1)
            c[result] += 1
        counts[topic] = c
    return counts
