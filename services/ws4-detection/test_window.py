"""Tests for the T6 sliding-window counters.

Proves the windowing algorithm for BOTH backends with zero infrastructure:
  - DequeWindowCounter (in-process)
  - RedisWindowCounter driven by a minimal in-memory fake sorted set, so the
    ZADD/ZREMRANGEBYSCORE/ZCARD math is exercised without a live Redis.

Both must agree, and both must (a) fire at the threshold inside the window and
(b) drop stale events that age out of the window.

Run: C:/Python313/python.exe services/ws4-detection/test_window.py
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


# --- minimal in-memory fake of the redis-py pipeline subset we use ----------
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


class _FakeRedis:
    def __init__(self):
        self.store = {}

    def pipeline(self):
        return _FakePipe(self.store)


def _drive(counter, key="bf:1.2.3.4", window_ms=60_000):
    """10 events 1s apart all inside the window -> counts 1..10."""
    base = 1_750_000_000_000
    counts = [counter.hit(key, base + i * 1000, window_ms, member=f"e{i}")
              for i in range(10)]
    return base, counts


def run():
    # --- both backends: count climbs 1..10 within the window ---
    for name, c in [("deque", DequeWindowCounter()),
                    ("redis-fake", RedisWindowCounter(_FakeRedis()))]:
        base, counts = _drive(c)
        check(counts == list(range(1, 11)), f"{name}: counts should be 1..10, got {counts}")
        check(counts[-1] == 10, f"{name}: 10th event in window -> count 10 (fires at threshold)")

        # an event far in the future ages out all 10 prior -> count resets to 1
        far = c.hit("bf:1.2.3.4", base + 10_000_000, 60_000, member="late")
        check(far == 1, f"{name}: stale events trimmed; lone late event -> count 1, got {far}")

    # --- unique-member requirement: same member must not double-count (redis) ---
    rc = RedisWindowCounter(_FakeRedis())
    base = 1_750_000_000_000
    rc.hit("k", base, 60_000, member="dup")
    again = rc.hit("k", base + 1000, 60_000, member="dup")
    check(again == 1, f"redis: same member id must not double-count, got {again}")

    # --- P0.2: the DEQUE backend must dedup by member too (redelivery parity) ---
    # Previously the deque ignored `member` and appended blindly, so a redelivered
    # event double-counted on memory but not on Redis; thresholds tripped early.
    dc = DequeWindowCounter()
    dc.hit("k", base, 60_000, member="dup")
    dagain = dc.hit("k", base + 1000, 60_000, member="dup")
    check(dagain == 1, f"deque: same member id must not double-count, got {dagain}")
    # distinct members still climb
    dc.hit("k", base + 2000, 60_000, member="x")
    d3 = dc.hit("k", base + 3000, 60_000, member="y")
    check(d3 == 3, f"deque: distinct members still counted (dup,x,y -> 3), got {d3}")

    # --- P0.3: idle group keys must be evicted (no unbounded growth / OOM) ---
    ev = DequeWindowCounter()
    # spray many one-shot groups, each far apart so every prior group is idle
    for i in range(1000):
        ev.hit(f"g{i}", base + i * 10_000_000, 60_000, member=f"m{i}")
    # after the sweep, only recently-touched keys survive -- not one-per-group-ever
    live_keys = len(ev._w) + len(ev._dw)
    check(live_keys < 300,
          f"deque: idle group keys should be swept, {live_keys} still resident (>=300 = leak)")

    # --- the two backends agree on a mixed sequence ---
    d, r = DequeWindowCounter(), RedisWindowCounter(_FakeRedis())
    seq = [(0, "a"), (1000, "b"), (2000, "c"), (70_000, "d")]  # 'd' ages a,b,c out
    base = 1_750_000_000_000
    dd = [d.hit("g", base + t, 60_000, member=m) for t, m in seq]
    rr = [r.hit("g", base + t, 60_000, member=m) for t, m in seq]
    check(dd == rr, f"backends disagree: deque={dd} redis={rr}")
    check(dd[-1] == 1, f"after gap, only the latest event is in-window, got {dd[-1]}")


def main():
    run()
    if FAILS:
        print(f"[FAIL] window counters: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] window counters (deque + redis-fake) PASS")


if __name__ == "__main__":
    main()
