"""P1-8 (2026-07-21 audit fix plan): _RedisBus XREADGROUP batch-size tunable.

Live-proven win: 250 messages drained in 4 XREADGROUP calls at count=100,
vs >=25 calls at the old hardcoded count=10 -- a ~6x reduction in read-RTT
overhead at real production message volumes.

Same real-Redis-required, cleanly-SKIPPED-otherwise convention as the other
_RedisBus-specific test files this session (test_bus_trim_acked.py,
test_bus_lag.py).

Run: BUS_BACKEND=redis python services/shared/test_bus_read_count.py
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))

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


def _unique_topic(base):
    return f"{base}.{int(time.time() * 1000)}.{os.getpid()}"


def test_default_read_count_is_100():
    from shared.bus import _RedisBus
    bus = _RedisBus(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    check(bus._read_count == 100, f"expected default 100, got {bus._read_count}")


def test_env_override_respected():
    old = os.environ.get("BUS_XREADGROUP_COUNT")
    os.environ["BUS_XREADGROUP_COUNT"] = "37"
    try:
        from shared.bus import _RedisBus
        bus = _RedisBus(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        check(bus._read_count == 37, f"expected env override 37, got {bus._read_count}")
    finally:
        if old is None:
            os.environ.pop("BUS_XREADGROUP_COUNT", None)
        else:
            os.environ["BUS_XREADGROUP_COUNT"] = old


def test_batch_size_reduces_read_calls():
    """The actual live win: drain N messages in far fewer XREADGROUP calls
    than the old hardcoded count=10 would have needed."""
    from shared.bus import _RedisBus
    bus = _RedisBus(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    topic = _unique_topic("p18.readcount")
    n = 250
    for i in range(n):
        bus.produce(topic, key=None, payload={"i": i})

    orig = bus.r.xreadgroup
    calls = [0]

    def counting(*a, **k):
        calls[0] += 1
        return orig(*a, **k)
    bus.r.xreadgroup = counting

    total = 0
    while True:
        batch = list(bus.consume(topic, group="cg-p18test", block_ms=200))
        if not batch:
            break
        total += len(batch)
        for m in batch:
            bus.ack(m, "cg-p18test")

    check(total == n, f"sanity: must drain all {n} messages, got {total}")
    old_count_minimum_calls = n // 10  # what count=10 would have needed, at least
    check(calls[0] < old_count_minimum_calls,
          f"expected far fewer than {old_count_minimum_calls} XREADGROUP calls "
          f"(the old count=10 baseline), got {calls[0]}")


def main():
    if not _redis_reachable():
        print("[SKIP] test_bus_read_count: BUS_BACKEND=redis + a reachable "
              "broker required")
        return

    test_default_read_count_is_100()
    test_env_override_respected()
    test_batch_size_reduces_read_calls()

    if FAILS:
        print(f"\n[FAIL] bus read count (P1-8): {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] bus read count (P1-8) tests PASS")


if __name__ == "__main__":
    main()
