"""_RedisSentinelBus failover coverage — zero infrastructure (fakes, no Redis).

Guards the bug that made the HA profile's failover useless for every
long-running service (2026-08-05):

    _RedisBus.consume and _RedisBus.claim_pending are GENERATOR functions, so
    calling them builds a generator and performs no I/O. _with_failover's
    try/except therefore could never fire for them, _refresh_master() was never
    called on the consume path, and a service stayed pinned to the dead primary
    forever after a failover.

Found only by killing the primary under the FULL HA stack: Redis-side failover
completed in 1.2s while ws2/ws3/ws4/ws5 sat unhealthy on
"ConnectionError: Error 113 connecting to <old primary>:6379" with messages
stranded at lag=12 on the new primary. A produce-only test client recovered in
the same scenario, which is precisely why this stayed hidden -- produce/ack/
depth/lag/trim_acked are ordinary functions and were genuinely covered.

These tests use fake buses rather than real Redis so they run in the normal
zero-infra gate, and they assert on WHEN rediscovery happens, which is the part
that was broken -- not merely that a call eventually succeeds.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
os.environ.setdefault("BUS_BACKEND", "memory")

from shared import bus as busmod  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _DeadBus:
    """Stands in for a _RedisBus pointed at a primary that just died.

    Mirrors the real shapes: consume/claim_pending are generator functions that
    raise on ITERATION (not on call), everything else raises on call.
    """

    def __init__(self):
        self.r = None

    def produce(self, topic, key, payload):
        raise ConnectionError("Error 113 connecting to dead-primary:6379")

    def ack(self, msg, group="cg-default"):
        raise ConnectionError("Error 113 connecting to dead-primary:6379")

    def depth(self, topic):
        raise ConnectionError("Error 113 connecting to dead-primary:6379")

    def consume(self, topic, group="cg-default", block_ms=5000):
        raise ConnectionError("Error 113 connecting to dead-primary:6379")
        yield  # pragma: no cover -- makes this a generator function

    def claim_pending(self, topic, group="cg-default", min_idle_ms=60000,
                      max_redeliveries=5):
        raise ConnectionError("Error 113 connecting to dead-primary:6379")
        yield  # pragma: no cover -- makes this a generator function


class _LiveBus:
    """The promoted replica."""

    def __init__(self):
        self.r = object()
        self.produced = []

    def produce(self, topic, key, payload):
        self.produced.append((topic, key, payload))
        return "1-0"

    def ack(self, msg, group="cg-default"):
        return 1

    def depth(self, topic):
        return 7

    def consume(self, topic, group="cg-default", block_ms=5000):
        yield f"msg-from-new-primary:{topic}"

    def claim_pending(self, topic, group="cg-default", min_idle_ms=60000,
                      max_redeliveries=5):
        yield f"claimed-from-new-primary:{topic}"


def _make_bus():
    """A _RedisSentinelBus wired to a dead primary, whose _refresh_master()
    swaps in the promoted one — the shape a real Sentinel failover produces."""
    sb = object.__new__(busmod._RedisSentinelBus)
    sb._url = "redis://dead-primary:6379/0"
    sb._password = ""
    sb._sentinel = None
    sb._master_name = "mymaster"
    sb._bus = _DeadBus()
    sb.refreshes = 0
    live = _LiveBus()

    def _refresh():
        sb.refreshes += 1
        sb._bus = live
        sb._url = "redis://new-primary:6379/0"

    sb._refresh_master = _refresh
    return sb, live


def test_consume_rediscovers_master_on_failover():
    """THE regression. Before the fix this yielded nothing and never refreshed:
    the generator was constructed without touching the connection, so the
    wrapper's except never ran."""
    sb, _ = _make_bus()
    got = list(sb.consume("raw.events", group="cg-normalize"))

    check(sb.refreshes == 1,
          f"consume() must trigger exactly one master rediscovery, got {sb.refreshes}")
    check(got == ["msg-from-new-primary:raw.events"],
          f"consume() must deliver from the promoted primary, got {got!r}")


def test_claim_pending_rediscovers_master_on_failover():
    """Same defect, same shape — claim_pending is also a generator function."""
    sb, _ = _make_bus()
    got = list(sb.claim_pending("raw.events", group="cg-normalize"))

    check(sb.refreshes == 1,
          f"claim_pending() must trigger one rediscovery, got {sb.refreshes}")
    check(got == ["claimed-from-new-primary:raw.events"],
          f"claim_pending() must deliver from the promoted primary, got {got!r}")


def test_consume_refreshes_on_iteration_not_on_call():
    """Pins the actual mechanism. Merely CALLING consume() must not be treated
    as success: the I/O (and so the failure, and so the rediscovery) happens
    when the caller iterates. A future refactor that eagerly returns a list, or
    re-wraps these in _with_failover, breaks here."""
    sb, _ = _make_bus()
    gen = sb.consume("raw.events")
    check(sb.refreshes == 0,
          "no rediscovery should happen before the generator is iterated")
    next(gen, None)
    check(sb.refreshes == 1,
          "rediscovery must happen once the generator is actually iterated")


def test_plain_methods_still_failover():
    """produce/ack/depth were always covered; make sure the split didn't
    regress them."""
    sb, live = _make_bus()
    sb.produce("raw.events", key="k", payload={"a": 1})
    check(sb.refreshes == 1, f"produce() should rediscover once, got {sb.refreshes}")
    check(live.produced == [("raw.events", "k", {"a": 1})],
          f"produce() must land on the promoted primary, got {live.produced!r}")

    sb2, _ = _make_bus()
    check(sb2.depth("raw.events") == 7, "depth() must failover and return the new value")


def test_generator_methods_are_routed_through_the_iter_wrapper():
    """Structural guard: whichever _RedisBus methods are generator functions
    MUST be the ones _RedisSentinelBus routes through _iter_with_failover. If
    someone later makes another method a generator, this fails loudly instead
    of silently losing its failover the way consume did."""
    import inspect

    # Note _RedisSentinelBus.consume is NOT itself a generator function -- it is
    # a plain function that RETURNS the _iter_with_failover generator. So the
    # check has to be on the returned object, not on the method.
    sample_args = {
        "produce": ("t", "k", {}),
        "consume": ("t",),
        "ack": ("m",),
        "claim_pending": ("t",),
        "depth": ("t",),
        "lag": ("t",),
        "trim_acked": ("t",),
    }
    for name, args in sample_args.items():
        underlying_is_gen = inspect.isgeneratorfunction(
            getattr(busmod._RedisBus, name)
        )
        if not underlying_is_gen:
            continue
        sb, _ = _make_bus()
        returned = getattr(sb, name)(*args)
        check(
            inspect.isgenerator(returned),
            f"_RedisBus.{name} is a generator function, so _RedisSentinelBus"
            f".{name} must return a generator from _iter_with_failover; got "
            f"{type(returned).__name__}. Routing it through _with_failover "
            f"instead silently drops its failover.",
        )
        check(
            sb.refreshes == 0,
            f"{name}() must not have done I/O at call time (that is what made "
            f"the original bug invisible); refreshes={sb.refreshes}",
        )


def main():
    for fn in [
        test_consume_rediscovers_master_on_failover,
        test_claim_pending_rediscovers_master_on_failover,
        test_consume_refreshes_on_iteration_not_on_call,
        test_plain_methods_still_failover,
        test_generator_methods_are_routed_through_the_iter_wrapper,
    ]:
        fn()

    if FAILS:
        print(f"[FAIL] sentinel failover: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] _RedisSentinelBus failover: consume/claim_pending rediscover the "
          "promoted primary on iteration (not just on call), plain methods "
          "unaffected, generator methods structurally pinned to the iter wrapper")


if __name__ == "__main__":
    main()
