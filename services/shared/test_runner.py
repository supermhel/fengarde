"""Shared-runner unit tests — MemoryBus (always) + RedisBus (when reachable).

Proves the four mechanisms the T3 Opus review said were unwritten:

  1. handler called once per queued message (dispatch + ack-on-success);
  2. a raising handler leaves the message UNACKED, and after max_redeliveries the
     message is routed to <topic>.deadletter and acked;
  3. multi-topic dispatch routes each topic to its own handler;
  4. the threaded serve() loop processes a queued message, runs a /health endpoint,
     and exits cleanly when the shutdown Event is set.

Each of these test bodies is parametrized over a bus-factory: MemoryBus always
runs (zero infra); RedisBus runs too when BUS_BACKEND=redis and a broker is
reachable (e.g. the redis-integration CI job's redis:7 service container), and
is cleanly SKIPPED (not silently, not a failure) otherwise — same gate that
`test_redis_redelivery_and_dlq` used before this refactor.

On MemoryBus, redelivery/DLQ is exercised deterministically via a re-produce /
_process_message loop (MemoryBus has no persistent PEL to replay). On RedisBus,
the same test body drives the real PEL: consume() (no auto-ack) then
claim_pending() (XAUTOCLAIM + XPENDING.times_delivered) until the cap is hit.
"""
from __future__ import annotations

import os
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))
os.environ.setdefault("BUS_BACKEND", "memory")

from shared.bus import _MemoryBus, Message  # noqa: E402
from shared import runner  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


# --------------------------------------------------------------------------- #
# Backend parametrization helpers
# --------------------------------------------------------------------------- #
def _redis_reachable():
    if os.getenv("BUS_BACKEND", "memory").lower() != "redis":
        return False
    try:
        import redis  # type: ignore
        r = redis.Redis.from_url(
            os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            decode_responses=True, socket_connect_timeout=1)
        r.ping()
        return True
    except Exception:
        return False


def _make_redis_bus():
    from shared.bus import _RedisBus
    url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    return _RedisBus(url)


def _unique_topic(base):
    # Redis streams/groups persist across runs; keep each run's topics disjoint.
    return f"{base}.{int(time.time()*1000)}.{os.getpid()}"


# Backends to parametrize over: (label, bus_factory or None).
# bus_factory is None for the redis entry when redis isn't reachable here — the
# runner below turns that into a clean [SKIP] line instead of calling the test.
_BACKENDS = [("memory", _MemoryBus)]
if _redis_reachable():
    _BACKENDS.append(("redis", _make_redis_bus))
else:
    _BACKENDS.append(("redis", None))


def _redis_cleanup(bus, *topics):
    """Best-effort delete of the streams/DLQs a Redis-backed test created."""
    if bus is None:
        return
    try:
        bus.r.delete(*topics)
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# 1. handler called once per queued message
# --------------------------------------------------------------------------- #
def _body_handler_called_once_per_message(make_bus, unique):
    bus = make_bus()
    topic = unique("t.in")
    seen = []
    for i in range(3):
        bus.produce(topic, key=str(i), payload={"n": i})

    counts = runner.run_once(bus, {topic: ("cg-t", lambda p: seen.append(p["n"]))})

    check(seen == [0, 1, 2], f"handler order/count wrong: {seen}")
    check(counts[topic]["acked"] == 3, f"expected 3 acked, got {counts[topic]}")
    # Both backends should have nothing left queued/pending after a full drain+ack.
    check(bus.drain(topic) == [] if hasattr(bus, "drain") else True,
          "messages should be drained after run_once")
    return bus, [topic]


# --------------------------------------------------------------------------- #
# 2. raising handler -> not acked -> DLQ after max_redeliveries
# --------------------------------------------------------------------------- #
def _body_raising_handler_not_acked(make_bus, unique):
    """A single delivery of a raising handler must NOT ack and must NOT DLQ."""
    bus = make_bus()
    topic = unique("t.fail")
    dlq = f"{topic}.deadletter"
    bus.produce(topic, key="k", payload={"x": 1})

    acked = {"n": 0}
    orig_ack = bus.ack
    bus.ack = lambda m, g=None: (acked.__setitem__("n", acked["n"] + 1), orig_ack(m, g))[1]

    def boom(_payload):
        raise RuntimeError("handler failure")

    counts = runner.run_once(bus, {topic: ("cg-f", boom)}, max_redeliveries=5)

    check(counts[topic]["failed"] == 1, f"expected 1 failed, got {counts[topic]}")
    check(acked["n"] == 0, "a failed handler must NOT ack its message")
    if hasattr(bus, "drain"):
        check(bus.drain(dlq) == [],
              "must NOT dead-letter on a single failure (cap not reached)")
    bus.ack = orig_ack
    return bus, [topic, dlq]


def _body_redelivery_then_deadletter(make_bus, unique):
    """Assert the message is DLQ'd exactly when delivery count exceeds the cap.

    On MemoryBus (no PEL) we re-create the same Message and drive
    runner._process_message with an incrementing delivery_count directly. On
    RedisBus we drive the real PEL: consume() once (leaves it unacked/pending),
    then repeatedly claim_pending() (XAUTOCLAIM + XPENDING) until DLQ'd — this is
    exactly what the standalone test_redis_redelivery_and_dlq used to do alone.
    """
    bus = make_bus()
    topic = unique("t.poison")
    group = "cg-p"
    dlq = f"{topic}.deadletter"
    max_redeliveries = 3

    def boom(_payload):
        raise RuntimeError("always fails")

    results = []
    if isinstance(bus, _MemoryBus):
        msg = Message(topic, "k", {"x": 1}, "1-0")
        # delivery_count climbs 1,2,3 (all fail) then 4 (> max -> DLQ).
        for delivery_count in range(1, max_redeliveries + 2):
            r = runner._process_message(
                bus, topic, group, msg, boom,
                max_redeliveries=max_redeliveries, delivery_count=delivery_count)
            results.append(r)
    else:
        bus.produce(topic, key="k", payload={"x": 1})
        for msg in bus.consume(topic, group=group):
            results.append(runner._process_message(
                bus, topic, group, msg, boom,
                max_redeliveries=max_redeliveries, delivery_count=1))
        for _ in range(10):
            if results and results[-1] == "deadlettered":
                break
            for msg, times in bus.claim_pending(topic, group, 0, max_redeliveries):
                results.append(runner._process_message(
                    bus, topic, group, msg, boom,
                    max_redeliveries=max_redeliveries, delivery_count=times))

    check(results and results[-1] == "deadlettered" and
          all(r == "failed" for r in results[:-1]),
          f"redelivery sequence wrong: {results}")
    dlq_msgs = bus.drain(dlq) if hasattr(bus, "drain") else None
    if dlq_msgs is None:
        dlq_msgs = [Message(dlq, m.get("key"), m, "?")
                    for m in ([bus.r.xrange(dlq)] if False else [])]
        # RedisBus has no .drain(); read the DLQ stream directly instead.
        entries = bus.r.xrange(dlq)
        import json as _json
        dlq_msgs = [_json.loads(fields["payload"]) for _eid, fields in entries]
        check(len(dlq_msgs) == 1, f"expected exactly 1 DLQ message, got {len(dlq_msgs)}")
        if dlq_msgs:
            dl = dlq_msgs[0]
            check(dl["topic"] == topic, f"DLQ wrong topic: {dl}")
            check(dl["delivery_count"] == 4, f"DLQ wrong delivery_count: {dl}")
            check(dl["payload"] == {"x": 1}, f"DLQ lost original payload: {dl}")
    else:
        check(len(dlq_msgs) == 1, f"expected exactly 1 DLQ message, got {len(dlq_msgs)}")
        if dlq_msgs:
            dl = dlq_msgs[0].payload
            check(dl["topic"] == topic, f"DLQ wrong topic: {dl}")
            check(dl["delivery_count"] == 4, f"DLQ wrong delivery_count: {dl}")
            check(dl["payload"] == {"x": 1}, f"DLQ lost original payload: {dl}")
    return bus, [topic, dlq]


def _body_handler_eventually_succeeds(make_bus, unique):
    """If a redelivered message finally succeeds before the cap, it is acked and
    never dead-lettered."""
    bus = make_bus()
    topic = unique("t.flaky")
    group = "cg-fl"
    dlq = f"{topic}.deadletter"
    attempts = {"n": 0}

    def flaky(_payload):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise RuntimeError("transient")

    results = []
    if isinstance(bus, _MemoryBus):
        msg = Message(topic, "k", {"x": 1}, "1-0")
        for delivery_count in range(1, 6):
            r = runner._process_message(bus, topic, group, msg, flaky,
                                        max_redeliveries=5,
                                        delivery_count=delivery_count)
            results.append(r)
            if r == "acked":
                break
    else:
        bus.produce(topic, key="k", payload={"x": 1})
        for msg in bus.consume(topic, group=group):
            results.append(runner._process_message(
                bus, topic, group, msg, flaky, max_redeliveries=5,
                delivery_count=1))
        for _ in range(10):
            if results and results[-1] == "acked":
                break
            for msg, times in bus.claim_pending(topic, group, 0, 5):
                results.append(runner._process_message(
                    bus, topic, group, msg, flaky, max_redeliveries=5,
                    delivery_count=times))
                if results[-1] == "acked":
                    break

    check(results == ["failed", "failed", "acked"], f"flaky sequence wrong: {results}")
    if hasattr(bus, "drain"):
        check(bus.drain(dlq) == [],
              "must not DLQ a message that eventually succeeded")
    else:
        entries = bus.r.xrange(dlq)
        check(len(entries) == 0,
              "must not DLQ a message that eventually succeeded")
    return bus, [topic, dlq]


# --------------------------------------------------------------------------- #
# 3. multi-topic dispatch routes to the right handler
# --------------------------------------------------------------------------- #
def _body_multi_topic_dispatch(make_bus, unique):
    bus = make_bus()
    topic_a = unique("topic.a")
    topic_b = unique("topic.b")
    bus.produce(topic_a, key="a", payload={"who": "a"})
    bus.produce(topic_b, key="b", payload={"who": "b"})
    bus.produce(topic_b, key="b2", payload={"who": "b"})

    got = {"a": [], "b": []}
    counts = runner.run_once(bus, {
        topic_a: ("cg-a", lambda p: got["a"].append(p["who"])),
        topic_b: ("cg-b", lambda p: got["b"].append(p["who"])),
    })

    check(got["a"] == ["a"], f"topic.a handler wrong: {got['a']}")
    check(got["b"] == ["b", "b"], f"topic.b handler wrong: {got['b']}")
    check(counts[topic_a]["acked"] == 1 and counts[topic_b]["acked"] == 2,
          f"per-topic counts wrong: {counts}")
    return bus, [topic_a, topic_b]


# --------------------------------------------------------------------------- #
# 4. threaded serve(): processes a message, /health works, exits on shutdown
# --------------------------------------------------------------------------- #
def _body_serve_threaded_and_health_and_shutdown(make_bus, unique, health_port):
    # Each worker calls bus_factory() for its own Bus; share ONE bus instance so
    # the test can pre-load it and read results back.
    shared_bus = make_bus()
    topic = unique("live.in")
    shared_bus.produce(topic, key="k", payload={"n": 42})

    seen = []
    done = threading.Event()

    def handler(payload):
        seen.append(payload["n"])
        done.set()

    shutdown = threading.Event()

    serve_thread = threading.Thread(
        target=runner.serve,
        args=({topic: ("cg-live", handler)},),
        kwargs=dict(health_port=health_port, shutdown=shutdown,
                    service_name="test-svc", idle_sleep_s=0.05,
                    install_signal_handlers=False,
                    bus_factory=lambda: shared_bus),
        daemon=True)
    serve_thread.start()

    processed = done.wait(timeout=5)
    check(processed, "serve() did not process the queued message within 5s")
    check(seen == [42], f"serve() handler saw wrong payloads: {seen}")

    # /health
    health_ok = False
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{health_port}/health", timeout=3) as resp:
            import json
            body = json.loads(resp.read().decode())
            health_ok = (body == {"status": "ok", "service": "test-svc"})
    except Exception as e:  # pragma: no cover - diagnostic
        FAILS.append(f"/health request failed: {e!r}")
    check(health_ok, "/health did not return {'status':'ok','service':'test-svc'}")

    # /metrics (P2.3): the daemon path must count the message it just acked.
    metrics_ok = False
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{health_port}/metrics", timeout=3) as resp:
            import json
            body = json.loads(resp.read().decode())
            metrics_ok = (body.get("service") == "test-svc" and
                         body.get("topics", {}).get(topic, {}).get("acked") == 1)
    except Exception as e:  # pragma: no cover - diagnostic
        FAILS.append(f"/metrics request failed: {e!r}")
    check(metrics_ok, f"/metrics did not report 1 acked for {topic}")

    # clean shutdown
    shutdown.set()
    serve_thread.join(timeout=5)
    check(not serve_thread.is_alive(), "serve() did not exit after shutdown.set()")
    return shared_bus, [topic]


# --------------------------------------------------------------------------- #
# Parametrized-test registry: each entry runs once per backend in _BACKENDS.
# health_port is bumped per-backend run since serve() binds a real socket.
# --------------------------------------------------------------------------- #
_HEALTH_PORT_COUNTER = {"n": 8099}


def _next_health_port():
    p = _HEALTH_PORT_COUNTER["n"]
    _HEALTH_PORT_COUNTER["n"] += 1
    return p


def _run_parametrized(name, body, needs_health_port=False):
    """Run ``body(make_bus, unique[, health_port])`` once per entry in
    _BACKENDS. Prints ``  . name[backend]`` on pass, ``[SKIP] name[backend] ...``
    when the backend factory is None (Redis unreachable here), and records
    failures into FAILS with a backend-qualified test name.
    """
    any_ran = False
    for backend_label, make_bus in _BACKENDS:
        qualified = f"{name}[{backend_label}]"
        if make_bus is None:
            print(f"  [SKIP] {qualified} (no reachable Redis / BUS_BACKEND!=redis)")
            continue
        bus = None
        topics = []
        try:
            unique = lambda base: _unique_topic(base)  # noqa: E731
            if needs_health_port:
                bus, topics = body(make_bus, unique, _next_health_port())
            else:
                bus, topics = body(make_bus, unique)
            print(f"  . {qualified}")
            any_ran = True
        except Exception as e:
            FAILS.append(f"{qualified} raised: {e!r}")
            print(f"  X {qualified}: {e!r}")
        finally:
            if backend_label == "redis" and bus is not None and topics:
                _redis_cleanup(bus, *topics)
    return any_ran


# --------------------------------------------------------------------------- #
# P1.1: /health reports 503 "degraded" when a worker can't reach the bus, so a
# compose healthcheck / orchestrator can restart a wedged-but-alive service.
def _test_health_degraded():
    from http.server import ThreadingHTTPServer
    state = runner.HealthState()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), runner._make_health_handler("t", state))
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        # healthy -> 200
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=3) as r:
            check(r.status == 200, "healthy /health should be 200")
        # bus error -> 503 degraded
        state.mark_error(RuntimeError("redis down"))
        code = None
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=3)
        except urllib.error.HTTPError as e:
            code = e.code
        check(code == 503, f"degraded /health should be 503, got {code}")
        # recovery -> 200 again
        state.mark_ok()
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=3) as r:
            check(r.status == 200, "recovered /health should be 200 again")
    finally:
        srv.shutdown()
        srv.server_close()


# --------------------------------------------------------------------------- #
# P2.3: Metrics counts _process_message outcomes per topic, snapshot() is a
# plain dict (JSON-able for /metrics).
def _test_metrics_counts_outcomes():
    bus = _MemoryBus()
    topic = _unique_topic("t.metrics")
    m = runner.Metrics()

    bus.produce(topic, key="1", payload={"x": 1})
    msg = next(iter(bus.consume(topic, group="cg-m")))
    runner._process_message(bus, topic, "cg-m", msg, lambda p: None,
                            max_redeliveries=5, delivery_count=1, metrics=m)

    def boom(_p):
        raise RuntimeError("always fails")
    bus.produce(topic, key="2", payload={"x": 2})
    msg2 = next(iter(bus.consume(topic, group="cg-m")))
    runner._process_message(bus, topic, "cg-m", msg2, boom,
                            max_redeliveries=5, delivery_count=1, metrics=m)

    snap = m.snapshot()
    check(snap[topic]["acked"] == 1, f"expected 1 acked, got {snap}")
    check(snap[topic]["failed"] == 1, f"expected 1 failed, got {snap}")


def _test_prometheus_metrics_endpoint():
    # M7 observability (2026-07-22): render_prometheus() is the hand-rolled
    # exposition-format renderer behind the new /metrics/prom route -- same
    # per-topic counts as the JSON /metrics route, plus numeric `extra`
    # fields as gauges.
    topics = {"normalized.events": {"acked": 3, "failed": 1}}
    text = runner.render_prometheus("ws4-detection", topics, {"queue_depth": 7, "note": "skip-me"})
    check("fengarde_topic_events_total" in text, f"missing counter family: {text!r}")
    check('service="ws4-detection"' in text, f"missing service label: {text!r}")
    check('topic="normalized.events"' in text, f"missing topic label: {text!r}")
    check('result="acked"} 3' in text, f"acked count wrong: {text!r}")
    check('result="failed"} 1' in text, f"failed count wrong: {text!r}")
    check('field="queue_depth"} 7' in text, f"missing numeric extra gauge: {text!r}")
    check("note" not in text, f"non-numeric extra field must not render as a gauge: {text!r}")

    # A label value containing a quote/backslash/newline must not break the
    # exposition format for every OTHER metric on the same scrape: exactly
    # one metric line (plus 2 HELP/TYPE header lines) must come out, not
    # more, which is what a raw unescaped "\n" inside a label would produce.
    hostile = runner.render_prometheus('svc"x\\y\nz', {"t\"opic": {"acked": 1}}, None)
    lines = [ln for ln in hostile.split("\n") if ln]
    check(len(lines) == 3, f"a hostile label value must not inject extra lines: {lines!r}")
    check("\\n" in hostile, f"the raw newline must be escaped to the literal chars \\n: {hostile!r}")


# --------------------------------------------------------------------------- #
# P2.4: start_depth_watchdog logs when a topic's backlog crosses warn_at, and
# warn_at<=0 disables it (returns None, spawns no thread).
# P1-7 (2026-07-21 audit): the watchdog now samples bus.lag() (true consumer
# backlog), not bus.depth()/XLEN -- on MemoryBus the two are numerically
# identical (lag() just reuses depth(), see bus.py), so this test's assertion
# only needed the log kwarg renamed (depth= -> backlog=) to match the fix.
def _test_depth_watchdog():
    bus = _MemoryBus()
    topic = _unique_topic("t.depth")
    for i in range(5):
        bus.produce(topic, key=str(i), payload={"n": i})

    warned = []

    class _FakeLog:
        def warn(self, msg, **kw):
            warned.append((msg, kw))

    shutdown = threading.Event()
    t = runner.start_depth_watchdog(bus, _FakeLog(), shutdown, [topic],
                                    warn_at=3, interval_s=0.05)
    check(t is not None, "watchdog thread should start when warn_at > 0")
    time.sleep(0.2)
    shutdown.set()
    t.join(timeout=2)
    check(any(kw.get("topic") == topic and kw.get("backlog") == 5 for _m, kw in warned),
          f"watchdog did not warn on backlog 5 >= warn_at 3: {warned}")

    disabled = runner.start_depth_watchdog(bus, _FakeLog(), threading.Event(),
                                           [topic], warn_at=0)
    check(disabled is None, "warn_at<=0 must disable the watchdog (no thread)")


# --------------------------------------------------------------------------- #
def main():
    _test_health_degraded()
    _test_metrics_counts_outcomes()
    _test_prometheus_metrics_endpoint()
    _test_depth_watchdog()
    parametrized = [
        ("test_handler_called_once_per_message",
         _body_handler_called_once_per_message, False),
        ("test_raising_handler_not_acked",
         _body_raising_handler_not_acked, False),
        ("test_redelivery_then_deadletter",
         _body_redelivery_then_deadletter, False),
        ("test_handler_that_eventually_succeeds_is_acked_not_dlqd",
         _body_handler_eventually_succeeds, False),
        ("test_multi_topic_dispatch",
         _body_multi_topic_dispatch, False),
        ("test_serve_threaded_and_health_and_shutdown",
         _body_serve_threaded_and_health_and_shutdown, True),
    ]
    for name, body, needs_port in parametrized:
        _run_parametrized(name, body, needs_health_port=needs_port)

    if FAILS:
        print(f"\n[FAIL] runner: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("\n[OK] runner unit tests PASS")


if __name__ == "__main__":
    main()
