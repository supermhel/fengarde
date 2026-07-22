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
import sys
import threading
import time
import traceback
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

# topic -> (consumer_group, handler).  handler(payload: dict) -> None; raise to fail.
Handlers = dict[str, "tuple[str, Callable[[dict], None]]"]

# P2-4 (2026-07-21 audit): a poison message redelivered in a tight loop used to
# call traceback.print_exc() on every single delivery -- turning one bad
# message into an unbounded stderr flood (and the syscall/format cost that
# goes with it) until it hit max_redeliveries. This throttles: print the full
# traceback at most once per _THROTTLE_WINDOW_S per (topic, exception type),
# with a count of how many were suppressed in between.
_THROTTLE_WINDOW_S = 30.0
_throttle_lock = threading.Lock()
_throttle_state: "dict[tuple[str, str], dict]" = {}


def _throttled_print_exc(topic: str, exc: BaseException) -> None:
    key = (topic, type(exc).__name__)
    now = time.monotonic()
    with _throttle_lock:
        st = _throttle_state.get(key)
        if st is None or now - st["last"] >= _THROTTLE_WINDOW_S:
            suppressed = st["suppressed"] if st else 0
            _throttle_state[key] = {"last": now, "suppressed": 0}
            emit = True
        else:
            st["suppressed"] += 1
            emit = False
            suppressed = 0
    if emit:
        if suppressed:
            print(f"[runner] {suppressed} more {type(exc).__name__} on topic "
                  f"'{topic}' suppressed in the last {_THROTTLE_WINDOW_S:.0f}s",
                  file=sys.stderr)
        traceback.print_exc()


class HealthState:
    """Shared liveness signal updated by the topic workers and read by /health.

    The old /health returned a static ``{"status":"ok"}`` even when a worker
    could not reach the bus -- a wedged/deaf service reported healthy, so nothing
    (orchestrator, compose healthcheck) ever restarted it. Workers now flip
    ``bus_ok`` on consume/claim exceptions and back on success; /health reports
    503 + ``status:"degraded"`` while the bus is unreachable so a healthcheck can
    act on it. Simple flag, no locking needed (single writer per worker, boolean
    store is atomic enough for a liveness hint)."""

    def __init__(self) -> None:
        self.bus_ok = True
        self.last_error = ""

    def mark_ok(self) -> None:
        self.bus_ok = True
        self.last_error = ""

    def mark_error(self, exc: BaseException) -> None:
        self.bus_ok = False
        self.last_error = f"{type(exc).__name__}: {exc}"


class Metrics:
    """Per-topic acked/failed/deadlettered counters (P2.3).

    The batch ``stats`` dicts only ever existed in ``run_once``/the old
    per-service batch ``run()``; the daemon path (``serve()``/``_topic_worker``)
    counted nothing, so an operator watching a production container had no way
    to see drops (redeliveries piling up, messages dead-lettering) short of
    reading raw logs. One counter per (topic, result), exported on ``/metrics``.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: "dict[str, dict[str, int]]" = defaultdict(lambda: defaultdict(int))

    def incr(self, topic: str, result: str) -> None:
        with self._lock:
            self._counts[topic][result] += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {topic: dict(results) for topic, results in self._counts.items()}


# Socket read timeout (seconds) for the stdlib health/API servers. Without it a
# slow client that opens a connection and dribbles/withholds bytes pins a worker
# thread indefinitely (slowloris). BaseHTTPRequestHandler.timeout is honored by
# StreamRequestHandler's socket setup.
HTTP_TIMEOUT_S = 15


def _make_health_handler(service_name: str, state: "HealthState | None" = None,
                         metrics: "Metrics | None" = None,
                         extra_metrics_fn: "Callable[[], dict] | None" = None):
    class _HealthHandler(BaseHTTPRequestHandler):
        timeout = HTTP_TIMEOUT_S

        def _send(self, code: int, payload: dict):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802 (stdlib naming)
            path = self.path.rstrip("/")
            if path in ("/health", ""):
                if state is not None and not state.bus_ok:
                    return self._send(503, {"status": "degraded", "service": service_name,
                                            "error": state.last_error or "bus unreachable"})
                return self._send(200, {"status": "ok", "service": service_name})
            if path == "/metrics":
                payload = {"service": service_name,
                          "topics": metrics.snapshot() if metrics is not None else {}}
                if extra_metrics_fn is not None:
                    try:
                        payload["extra"] = extra_metrics_fn()
                    except Exception as exc:  # a broken provider must not break /metrics
                        payload["extra_error"] = str(exc)
                return self._send(200, payload)
            return self._send(404, {"error": "no such path"})

        def log_message(self, *_):  # quiet
            pass

    return _HealthHandler


def _process_message(bus, topic, group, msg, handler, max_redeliveries,
                     delivery_count, metrics: "Metrics | None" = None):
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
        if metrics is not None:
            metrics.incr(topic, "deadlettered")
        return "deadlettered"
    try:
        from shared.log import set_trace_id  # noqa: E402
        set_trace_id(getattr(msg, "id", None))  # follow this event across services
        handler(msg.payload)
    except Exception as exc:  # handler signalled failure -> do NOT ack; leave for redelivery
        _throttled_print_exc(topic, exc)
        if metrics is not None:
            metrics.incr(topic, "failed")
        return "failed"
    bus.ack(msg, group)
    if metrics is not None:
        metrics.incr(topic, "acked")
    return "acked"


def _topic_worker(bus_factory, topic, group, handler, *, max_redeliveries,
                  shutdown, claim_idle_ms, idle_sleep_s, consume_block_ms,
                  service_name, state=None, metrics=None):
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
                                  max_redeliveries, times_delivered, metrics)
                if shutdown.is_set():
                    break
            if state is not None:
                state.mark_ok()
        except Exception as exc:
            if state is not None:
                state.mark_error(exc)  # bus unreachable -> /health reports degraded
            _throttled_print_exc(topic, exc)

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
                                 max_redeliveries, 1, metrics)
                if shutdown.is_set():
                    break
            if state is not None:
                state.mark_ok()
        except Exception as exc:
            if state is not None:
                state.mark_error(exc)
            _throttled_print_exc(topic, exc)

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
          bus_factory: Callable | None = None,
          metrics_provider: "Callable[[], dict] | None" = None) -> None:
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
        metrics_provider: optional zero-arg callable returning a JSON-able dict
            merged into ``/metrics`` under ``"extra"`` (e.g. an ingest-edge
            server's produced/dropped/shed counters) alongside the per-topic
            acked/failed/deadlettered counts this runner tracks itself.
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

    state = HealthState()
    metrics = Metrics()

    # Health thread (stdlib ThreadingHTTPServer, mirrors ws6/app.py).
    health_srv = None
    health_thread = None
    if health_port is not None:
        health_srv = ThreadingHTTPServer(
            ("0.0.0.0", health_port),
            _make_health_handler(service_name, state, metrics, metrics_provider))
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
                        service_name=service_name, state=state, metrics=metrics),
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


def start_depth_watchdog(bus, log, shutdown: threading.Event, topics: "list[str]",
                         *, warn_at: int = 100000, interval_s: float = 30.0
                         ) -> "threading.Thread | None":
    """P2.4: periodically sample ``topics``' real consumer BACKLOG and log a
    warning when any crosses ``warn_at``, so an operator sees a backpressure
    buildup before it OOMs Redis. Signal only, never a fix: internal topics
    (normalized.events/scored.events/ai.requests) are deliberately never
    MAXLEN-trimmed on the unconsumed side -- see ``bus.py``'s
    ``_RedisBus.depth()`` docstring -- trimming an unconsumed bank audit event
    is a completeness violation a SIEM cannot make silently. The only real
    shedding lever is the ingest edge (``SyslogUDPServer``'s token bucket).
    ``warn_at<=0`` disables. Originally ws1-only (``raw.events``); shared here
    so ws2/ws4 can watch their own produced topics too.

    P1-7 (2026-07-21 audit): uses ``bus.lag()`` (true per-group backlog), not
    ``bus.depth()``/XLEN. Before this fix, XLEN only ever grew (nothing
    trimmed acked history), so once a topic's LIFETIME volume alone passed
    ``warn_at`` this warned on every single check forever, whether or not any
    consumer was actually behind -- pure noise, real lag was never measured.
    P0-5's reaper narrows that gap for depth() too now, but lag() is still the
    correct signal: it reflects backlog, not retained-history size.
    """
    if warn_at <= 0 or not topics:
        return None

    def _loop():
        while not shutdown.is_set():
            for topic in topics:
                try:
                    backlog = bus.lag(topic)
                    if backlog >= warn_at:
                        log.warn("topic backlog crossed warning threshold",
                                topic=topic, backlog=backlog, threshold=warn_at)
                except Exception as exc:
                    log.warn("depth watchdog check failed", topic=topic, error=str(exc))
            shutdown.wait(interval_s)

    t = threading.Thread(target=_loop, name="depth-watchdog", daemon=True)
    t.start()
    return t


def start_stream_reaper(bus, log, shutdown: threading.Event, topics: "list[str]",
                        *, interval_s: float = 300.0
                        ) -> "threading.Thread | None":
    """P0-5 (2026-07-21 audit): periodically call ``bus.trim_acked(topic)`` on
    each of ``topics`` so entries every consumer group has finished with don't
    accumulate in Redis forever.

    This is a DIFFERENT operation from the "no MAXLEN trim" decision documented
    on ``start_depth_watchdog``/``_RedisBus.depth()`` -- that decision is about
    never dropping an UNCONSUMED event (an audit-completeness violation).
    ``trim_acked`` only ever removes entries every registered consumer group has
    already consumed AND acknowledged (see its docstring for the exact safety
    proof); a topic no group has ever consumed is left untouched.

    ``.deadletter`` topics are excluded here -- they're an operator-facing
    inspection queue (``tools/dlq_peek.py``), not a normal processing topic, and
    should be cleared deliberately, not swept on a timer.

    Any one service can run this for a topic; correctness doesn't depend on
    which service calls it (``trim_acked`` queries Redis directly via
    ``XINFO GROUPS``/``XPENDING``, a global view of every consumer group on the
    stream, not just the caller's own). Safe to run redundantly from multiple
    services on overlapping topic lists.

    MemoryBus's ``trim_acked`` is a no-op (see its docstring), so this is a
    harmless no-op loop under BUS_BACKEND=memory -- callers don't need to
    special-case it. ``interval_s<=0`` disables."""
    if interval_s <= 0 or not topics:
        return None
    reap_topics = [t for t in topics if not t.endswith(".deadletter")]
    if not reap_topics:
        return None

    def _loop():
        while not shutdown.is_set():
            for topic in reap_topics:
                try:
                    trimmed = bus.trim_acked(topic)
                    if trimmed:
                        log.info("trimmed acked stream entries",
                                topic=topic, trimmed=trimmed)
                except Exception as exc:
                    log.warn("stream reaper failed", topic=topic, error=str(exc))
            shutdown.wait(interval_s)

    t = threading.Thread(target=_loop, name="stream-reaper", daemon=True)
    t.start()
    return t


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
