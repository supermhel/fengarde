"""Tests for the v0.5 A3 periodicity/beaconing window primitive
(``hit_periodic`` on both DequeWindowCounter and RedisWindowCounter).

Proves: both backends agree on count AND coefficient-of-variation for the
same event sequence; a regular-interval sequence has low CV; a bursty/
irregular sequence has high CV; fewer than 3 in-window events returns
cv=None (not enough data to judge regularity, never fabricated as 0).

Run: python services/ws4-detection/test_window_periodic.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from window import DequeWindowCounter, RedisWindowCounter  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _FakeRedis:
    """Same minimal ZADD/ZREMRANGEBYSCORE/ZCARD/EXPIRE fake as test_window.py,
    plus ZRANGE(key, 0, -1, withscores=True) which hit_periodic() needs."""

    def __init__(self):
        self.store: dict[str, dict] = {}

    def pipeline(self):
        return _FakePipe(self.store)

    def zrange(self, key, start, stop, withscores=False):
        d = self.store.get(key, {})
        items = sorted(d.items(), key=lambda kv: kv[1])
        if stop == -1:
            stop = len(items) - 1
        sliced = items[start:stop + 1]
        return sliced if withscores else [m for m, _ in sliced]


class _FakePipe:
    def __init__(self, store):
        self.store = store
        self.ops = []

    def zadd(self, key, mapping):
        self.ops.append(("zadd", key, mapping)); return self

    def zremrangebyscore(self, key, lo, hi):
        self.ops.append(("zrem", key, lo, hi)); return self

    def zcard(self, key):
        self.ops.append(("zcard", key)); return self

    def expire(self, key, secs):
        self.ops.append(("expire", key, secs)); return self

    def execute(self):
        res = []
        for op in self.ops:
            if op[0] == "zadd":
                _, k, mapping = op
                d = self.store.setdefault(k, {})
                added = sum(1 for m in mapping if m not in d)
                d.update(mapping)
                res.append(added)
            elif op[0] == "zrem":
                _, k, lo, hi = op
                d = self.store.get(k, {})
                dead = [m for m, sc in d.items() if lo <= sc <= hi]
                for m in dead:
                    del d[m]
                res.append(len(dead))
            elif op[0] == "zcard":
                _, k = op
                res.append(len(self.store.get(k, {})))
            elif op[0] == "expire":
                res.append(1)
        self.ops = []
        return res


def _feed_regular(counter, key, base, n, interval_ms, window_ms=3_600_000):
    result = None
    for i in range(n):
        result = counter.hit_periodic(key, base + i * interval_ms, window_ms,
                                      member=f"e{i}")
    return result


def run():
    base = 1_750_000_000_000

    # --- both backends agree: regular 60s cadence -> low CV ---
    for name, c in [("deque", DequeWindowCounter()),
                    ("redis-fake", RedisWindowCounter(_FakeRedis()))]:
        count, cv = _feed_regular(c, "beacon:10.0.0.5", base, 6, 60_000)
        check(count == 6, f"{name}: count should be 6, got {count}")
        check(cv is not None and cv < 0.05,
              f"{name}: perfectly regular 60s cadence should have near-zero CV, got {cv}")

    # --- both backends agree: irregular/bursty cadence -> high CV ---
    for name, c in [("deque", DequeWindowCounter()),
                    ("redis-fake", RedisWindowCounter(_FakeRedis()))]:
        c2 = c
        deltas = [1000, 45000, 2000, 90000, 1500]  # wildly irregular
        t = base
        count = cv = None
        for i, d in enumerate([0] + deltas):
            t += d
            count, cv = c2.hit_periodic("bursty:10.0.0.6", t, 3_600_000, member=f"b{i}")
        check(cv is not None and cv > 0.5,
              f"{name}: bursty/irregular cadence should have high CV, got {cv}")

    # --- fewer than 3 events -> cv is None, not fabricated as 0 ---
    for name, c in [("deque", DequeWindowCounter()),
                    ("redis-fake", RedisWindowCounter(_FakeRedis()))]:
        count1, cv1 = c.hit_periodic("k1", base, 3_600_000, member="a")
        check(cv1 is None, f"{name}: 1 event -> cv must be None, got {cv1}")
        count2, cv2 = c.hit_periodic("k1", base + 1000, 3_600_000, member="b")
        check(cv2 is None, f"{name}: 2 events (1 delta) -> cv must be None, got {cv2}")
        count3, cv3 = c.hit_periodic("k1", base + 2000, 3_600_000, member="c")
        check(cv3 is not None, f"{name}: 3 events (2 deltas) -> cv must be computable, got {cv3}")

    # --- stale events age out of the window, same as hit()/hit_distinct() ---
    dc = DequeWindowCounter()
    dc.hit_periodic("aging", base, 60_000, member="old1")
    dc.hit_periodic("aging", base + 1000, 60_000, member="old2")
    count, cv = dc.hit_periodic("aging", base + 10_000_000, 60_000, member="new")
    check(count == 1, f"stale events must be trimmed from hit_periodic, got count={count}")
    check(cv is None, "a single surviving event after trim must report cv=None")


if __name__ == "__main__":
    run()
    if FAILS:
        print(f"[FAIL] window periodicity: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] periodicity primitive: deque + redis-fake agree on count and CV, "
          "regular cadence -> low CV, bursty cadence -> high CV, <3 events -> cv=None, "
          "stale events trimmed same as hit()/hit_distinct()")
