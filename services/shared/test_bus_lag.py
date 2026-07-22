"""P1-7 (2026-07-21 audit fix plan): _RedisBus.lag() unit tests.

Live-proven bug this closes: the depth watchdog used bus.depth()/XLEN, which
(before P0-5's reaper existed) only ever grew -- once a topic's LIFETIME
volume passed warn_at, every check warned forever regardless of whether any
consumer was actually behind. lag() must report near-zero once a group has
caught up, even though the stream's total historical volume is large.

Same real-Redis-required, cleanly-SKIPPED-otherwise convention as
test_runner.py / test_bus_trim_acked.py.

Run: BUS_BACKEND=redis python services/shared/test_bus_lag.py
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))
os.environ.setdefault("BUS_BACKEND", "memory")

from shared.bus import _MemoryBus  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


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
    return f"{base}.{int(time.time() * 1000)}.{os.getpid()}"


def _drain_all(bus, topic, group, block_ms=200):
    """_RedisBus.consume() reads ONE XREADGROUP batch (count=10) per call --
    it is NOT a full drain (that's the real worker's job, via runner.py's
    `while not shutdown.is_set()` loop re-calling consume() each pass). A
    test with more than 10 entries must loop the same way, or it silently
    only sees the first batch."""
    msgs = []
    while True:
        batch = list(bus.consume(topic, group=group, block_ms=block_ms))
        if not batch:
            return msgs
        msgs.extend(batch)


def test_memory_bus_lag_equals_depth():
    bus = _MemoryBus()
    bus.produce("t", key=None, payload={"i": 1})
    check(bus.lag("t") == bus.depth("t") == 1,
          "MemoryBus.lag must equal depth (no PEL/retained history to diverge)")


def test_no_groups_lag_equals_total_length():
    """Nobody has ever consumed -> the whole stream length IS the backlog."""
    bus = _make_redis_bus()
    topic = _unique_topic("p17.nogroup")
    for i in range(4):
        bus.produce(topic, key=None, payload={"i": i})
    check(bus.lag(topic) == 4, "lag with zero consumer groups must equal total length")


def test_caught_up_group_reports_near_zero_lag_despite_large_lifetime_volume():
    """The core P1-7 bug: a topic with a LARGE total historical volume
    (everything already consumed and acked) must report LOW lag, not the
    huge lifetime total -- unlike the old XLEN-based check, which (absent
    P0-5's reaper) would warn forever past that volume regardless of the
    real backlog."""
    bus = _make_redis_bus()
    topic = _unique_topic("p17.caughtup")
    n = 500  # "large" relative to a tiny warn_at, to prove the point
    for i in range(n):
        bus.produce(topic, key=None, payload={"i": i})
    caughtup_msgs = _drain_all(bus, topic, "cg-caughtup")
    check(len(caughtup_msgs) == n, f"sanity: cg-caughtup read all {n}, got {len(caughtup_msgs)}")
    for msg in caughtup_msgs:
        bus.ack(msg, "cg-caughtup")

    lag = bus.lag(topic)
    depth = bus.depth(topic)
    check(depth == n, f"sanity: depth/XLEN still reflects the full {n} lifetime "
                       f"entries (nothing trims retained-but-acked history until "
                       f"trim_acked runs), got {depth}")
    check(lag <= 5, f"a fully-caught-up group must report near-zero lag "
                    f"(got {lag}), even though depth()/XLEN is {depth} -- "
                    f"this is the exact false-positive the old watchdog had")


def test_group_with_real_pending_backlog_reports_it():
    """A group that has fallen genuinely behind (consumed but not acked, or
    simply hasn't read yet) must show real, non-zero lag -- the fix must not
    swing to "always report near-zero" and hide a genuine backlog."""
    bus = _make_redis_bus()
    topic = _unique_topic("p17.behind")
    n = 30
    for i in range(n):
        bus.produce(topic, key=None, payload={"i": i})

    # cg-behind reads all of them but acks NONE -- fully pending, genuinely behind.
    behind_msgs = _drain_all(bus, topic, "cg-behind")
    check(len(behind_msgs) == n, f"sanity: cg-behind read all {n}, got {len(behind_msgs)}")

    lag = bus.lag(topic)
    check(lag >= n - 2,  # allow a small tolerance for native-lag vs pending-count rounding
          f"a group with {n} unacked pending entries must report real lag "
          f"close to {n}, got {lag} -- the fix must not mask a genuine backlog")

    for msg in behind_msgs:  # cleanup
        bus.ack(msg, "cg-behind")


def main():
    test_memory_bus_lag_equals_depth()

    if not _redis_reachable():
        print("[SKIP] test_bus_lag: BUS_BACKEND=redis + a reachable broker "
              "required for the RedisBus lag tests (MemoryBus test above still ran)")
        return

    test_no_groups_lag_equals_total_length()
    test_caught_up_group_reports_near_zero_lag_despite_large_lifetime_volume()
    test_group_with_real_pending_backlog_reports_it()

    if FAILS:
        print(f"\n[FAIL] bus lag: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] bus lag (P1-7) tests PASS")


if __name__ == "__main__":
    main()
