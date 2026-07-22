"""P0-5 (2026-07-21 audit fix plan): _RedisBus.trim_acked() unit tests.

Live-proven root cause this closes: after a full send-then-drain cycle on the
real Docker stack, `raw.events` XLEN stayed frozen (7968) even though every
entry had been consumed AND acked by every group -- nothing ever called
XTRIM, so Redis memory grows monotonically forever.

Same real-Redis-required, cleanly-SKIPPED-otherwise convention as
test_runner.py's RedisBus parametrization (BUS_BACKEND=redis + a reachable
broker, e.g. the redis-integration CI job's redis:7 service container, or
this repo's own `make up` Docker stack). MemoryBus's no-op trim_acked() is
covered inline below too (deterministic, no infra).

Run: BUS_BACKEND=redis python services/shared/test_bus_trim_acked.py
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


def test_memory_bus_trim_acked_is_noop():
    """MemoryBus removes entries on yield -- nothing for a reaper to find."""
    bus = _MemoryBus()
    bus.produce("t", key=None, payload={"i": 1})
    check(bus.trim_acked("t") == 0, "MemoryBus.trim_acked must be a no-op (0)")
    check(bus.depth("t") == 1,
          "MemoryBus.trim_acked must not touch depth() (still 1, unconsumed)")


def test_no_groups_never_trims():
    """A topic nobody has ever consumed must be left completely alone."""
    bus = _make_redis_bus()
    topic = _unique_topic("p05.nogroup")
    for i in range(5):
        bus.produce(topic, key=None, payload={"i": i})
    check(bus.depth(topic) == 5, "sanity: 5 entries produced")
    trimmed = bus.trim_acked(topic)
    check(trimmed == 0, "a topic with zero consumer groups must never be trimmed")
    check(bus.depth(topic) == 5, "depth must be unchanged when nothing was trimmed")


def test_fully_acked_by_all_groups_trims_everything():
    """Every group has consumed AND acked every entry -> safe to trim it all."""
    bus = _make_redis_bus()
    topic = _unique_topic("p05.fullyacked")
    for i in range(6):
        bus.produce(topic, key=None, payload={"i": i})

    for group in ("cg-a", "cg-b"):
        for msg in bus.consume(topic, group=group, block_ms=100):
            bus.ack(msg, group)

    check(bus.depth(topic) == 6,
          "sanity: acking doesn't remove entries from the stream itself, "
          "only from the PEL -- depth stays 6 until trim_acked runs")
    trimmed = bus.trim_acked(topic)
    check(trimmed == 6, f"all 6 entries acked by both groups must be trimmed, got {trimmed}")
    check(bus.depth(topic) == 0, "depth must be 0 after trimming everything acked")


def test_partially_acked_group_blocks_trim_past_its_pending_entries():
    """One group has acked everything; another has UNACKED entries still
    pending -- trim must never remove those, even though the first group
    is done. This is the core safety property: the min-across-all-groups
    boundary, not "trim whatever the fastest group finished with"."""
    bus = _make_redis_bus()
    topic = _unique_topic("p05.partial")
    for i in range(8):
        bus.produce(topic, key=None, payload={"i": i})

    # cg-fast: reads and acks ALL 8.
    fast_msgs = list(bus.consume(topic, group="cg-fast", block_ms=100))
    check(len(fast_msgs) == 8, "sanity: cg-fast read all 8")
    for msg in fast_msgs:
        bus.ack(msg, "cg-fast")

    # cg-slow: reads all 8 but only acks the first 3 -- entries 4..8 stay
    # pending (crashed-mid-batch simulation).
    slow_msgs = list(bus.consume(topic, group="cg-slow", block_ms=100))
    check(len(slow_msgs) == 8, "sanity: cg-slow read all 8 too")
    for msg in slow_msgs[:3]:
        bus.ack(msg, "cg-slow")
    still_pending_id = slow_msgs[3].id  # the 4th entry: delivered, never acked

    trimmed = bus.trim_acked(topic)
    remaining = bus.depth(topic)
    check(trimmed == 3,
          f"only the first 3 entries (acked by BOTH groups) may be trimmed, got {trimmed}")
    check(remaining == 5,
          f"the 5 entries cg-slow hasn't acked yet must survive, got depth={remaining}")

    # The specific still-pending entry must still be claimable/redeliverable --
    # i.e. genuinely present, not silently dropped.
    reclaimed_ids = {m.id for m, _times in bus.claim_pending(
        topic, group="cg-slow", min_idle_ms=0, max_redeliveries=5)}
    check(still_pending_id in reclaimed_ids,
          "the entry cg-slow never acked must still be present and reclaimable "
          "after trim_acked -- proves trim never touched anything a group still needs")
    for msg in bus.claim_pending(topic, group="cg-slow", min_idle_ms=0, max_redeliveries=5):
        bus.ack(msg[0], "cg-slow")  # cleanup


def test_deadletter_topics_are_never_swept_by_the_generic_call():
    """trim_acked() is a generic per-topic primitive; the caller (the
    reaper in runner.py) is responsible for excluding .deadletter topics.
    Sanity-check here that trim_acked() itself has no special-casing that
    would silently make a .deadletter topic behave differently -- i.e. the
    exclusion is a policy decision at the call site, not hidden magic."""
    bus = _make_redis_bus()
    topic = _unique_topic("p05.src") + ".deadletter"
    bus.produce(topic, key=None, payload={"poison": True})
    for msg in bus.consume(topic, group="cg-dlq", block_ms=100):
        bus.ack(msg, "cg-dlq")
    trimmed = bus.trim_acked(topic)
    check(trimmed == 1,
          "trim_acked() itself doesn't know about .deadletter -- callers must "
          "exclude those topics explicitly (see start_stream_reaper)")


def main():
    test_memory_bus_trim_acked_is_noop()

    if not _redis_reachable():
        print("[SKIP] test_bus_trim_acked: BUS_BACKEND=redis + a reachable broker "
              "required for the RedisBus trim_acked tests (MemoryBus no-op test above still ran)")
        return

    test_no_groups_never_trims()
    test_fully_acked_by_all_groups_trims_everything()
    test_partially_acked_group_blocks_trim_past_its_pending_entries()
    test_deadletter_topics_are_never_swept_by_the_generic_call()

    if FAILS:
        print(f"\n[FAIL] bus trim_acked: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] bus trim_acked (P0-5) tests PASS")


if __name__ == "__main__":
    main()
