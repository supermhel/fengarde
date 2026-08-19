"""Tests for the distinct-count sliding window (port scan / lateral movement).

Mirrors test_window.py: proves hit_distinct() for BOTH backends with zero infra,
reusing the same in-memory fake of the redis-py pipeline subset. Both backends
must agree, and both must (a) count DISTINCT values (repeats don't inflate),
(b) fire at the threshold, and (c) drop values that age out of the window.

Run: C:/Python313/python.exe services/ws4-detection/test_window_distinct.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.window import DequeWindowCounter, RedisWindowCounter  # noqa: E402
from test_window import _FakeRedis  # reuse the fake redis pipeline  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _backends():
    return [("deque", DequeWindowCounter()),
            ("redis-fake", RedisWindowCounter(_FakeRedis()))]


def run():
    base = 1_750_000_000_000

    # --- distinct climbs as new values appear ---
    for name, c in _backends():
        counts = [c.hit_distinct("ps:1.2.3.4", base + i * 1000, 60_000,
                                 value=1000 + i, member=f"e{i}")
                  for i in range(15)]
        check(counts == list(range(1, 16)),
              f"{name}: 15 distinct ports -> counts 1..15, got {counts}")
        check(counts[-1] == 15, f"{name}: 15th distinct value fires at threshold")

    # --- repeats of the SAME value do not inflate the distinct count ---
    for name, c in _backends():
        seq = [c.hit_distinct("ps:dup", base + i * 1000, 60_000,
                              value=22, member=f"e{i}") for i in range(30)]
        check(all(x == 1 for x in seq),
              f"{name}: 30 hits on ONE port -> distinct stays 1, got {set(seq)}")

    # --- values age out of the window ---
    for name, c in _backends():
        c.hit_distinct("ps:age", base, 60_000, value=80, member="a")
        c.hit_distinct("ps:age", base + 1000, 60_000, value=443, member="b")
        # far-future event ages out the first two distinct values
        late = c.hit_distinct("ps:age", base + 10_000_000, 60_000,
                              value=8080, member="c")
        check(late == 1, f"{name}: stale distinct values trimmed -> 1, got {late}")

    # --- both backends agree on a mixed sequence (repeats + new + aging) ---
    d, r = DequeWindowCounter(), RedisWindowCounter(_FakeRedis())
    seq = [(0, "h1"), (1000, "h2"), (2000, "h2"), (3000, "h3"), (400_000, "h9")]
    dd = [d.hit_distinct("g", base + t, 300_000, value=v, member=f"m{i}")
          for i, (t, v) in enumerate(seq)]
    rr = [r.hit_distinct("g", base + t, 300_000, value=v, member=f"m{i}")
          for i, (t, v) in enumerate(seq)]
    check(dd == rr, f"backends disagree: deque={dd} redis={rr}")
    check(dd == [1, 2, 2, 3, 1],
          f"distinct over mixed/aging sequence wrong: {dd}")

    # --- count and distinct windows are independent (separate namespaces) ---
    c = DequeWindowCounter()
    c.hit("k", base, 60_000, member="x")
    dist = c.hit_distinct("k", base, 60_000, value="v", member="y")
    check(dist == 1, f"distinct window must not see count window, got {dist}")

    # --- C1 (2026-07-29 audit): out-of-order arrivals must not wedge a stale
    # distinct value behind a not-yet-expired later one forever. Reproduces
    # the exact scenario from the audit report (grouped by actor.user.name,
    # as common_password_spray.yml/common_impossible_travel.yml do).
    for name, c in _backends():
        seq = [(0, "ip1"), (299_000, "ip2"), (5_000, "ip3"),  # ip3 arrives late
               (302_000, "ip4"), (310_000, "ip5")]
        counts = [c.hit_distinct("alice", base + t, 300_000, value=v, member=f"m{i}")
                  for i, (t, v) in enumerate(seq)]
        check(counts == [1, 2, 3, 3, 3],
              f"{name}: out-of-order hit_distinct() sequence wrong, got {counts} "
              f"(expected [1, 2, 3, 3, 3])")


def main():
    run()
    if FAILS:
        print(f"[FAIL] distinct window: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] distinct-count window (deque + redis-fake) PASS")


if __name__ == "__main__":
    main()
