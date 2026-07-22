"""P1-5 (2026-07-21 audit fix plan): DequeWindowCounter.hit() dedup performance.

Live-proven finding: the member-dedup check was `any(m == member for _, m in w)`,
an O(window-size) scan per call. A single-source burst -- the EXACT traffic
common_bruteforce.yml targets -- drove that window's size up linearly with the
burst, making the whole burst O(n^2). At ~1k EPS into a 60s window that's
~60,000 comparisons for the LAST event alone.

Fixed by mirroring live (non-None) members in a `set` alongside the deque
(O(1) membership + O(1) discard-on-evict). This test proves the fix
empirically: a burst large enough to make the OLD O(n^2) scan clearly
noticeable (tens of thousands of unique members into one group) must complete
near-linearly, not take seconds.

Run: python services/ws4-detection/test_window_perf.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from window import DequeWindowCounter  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_large_single_group_burst_stays_near_linear():
    """20k unique-member hits into ONE group, all within the window (so
    nothing evicts, worst case for the dedup scan). A quadratic
    implementation of this exact shape was empirically ~seconds+; the O(1)
    fix completes in well under a second even with generous CI-machine
    slack. This is a regression trip-wire, not a micro-benchmark -- the
    bound is deliberately loose (10s) so it never flakes on a slow runner,
    while still catching a reintroduced O(n^2) scan (which would take far
    longer than 10s at this N)."""
    n = 20_000
    counter = DequeWindowCounter()
    t0 = time.perf_counter()
    for i in range(n):
        result = counter.hit("burst-group", i, 600_000, member=f"id-{i}")
    elapsed = time.perf_counter() - t0
    check(result == n, f"all {n} unique members must be counted, got {result}")
    check(elapsed < 10.0,
          f"{n} unique-member hits into one group took {elapsed:.2f}s -- "
          f"a reintroduced O(n^2) dedup scan would take far longer than this "
          f"at n={n} (this is a regression trip-wire, not a strict perf SLA)")


def test_redelivered_member_still_dedups_correctly_at_scale():
    """The O(1) fix must not have traded correctness for speed: a member
    already live in the window must still count once, even deep into a
    large burst."""
    n = 5_000
    counter = DequeWindowCounter()
    for i in range(n):
        counter.hit("g", i, 600_000, member=f"id-{i}")
    # Redeliver an early member (still within the window) -- count must NOT increase.
    before = counter.hit("g", n, 600_000, member="id-1")
    after = counter.hit("g", n + 1, 600_000, member="id-1")
    check(before == after,
          f"redelivering a member already live in the window must not "
          f"increase the count (got {before} then {after})")


def test_eviction_correctly_frees_the_member_set():
    """The member-mirroring set must track evictions (popleft on window
    slide), not just leak forever: a member that ages OUT of the window
    must be re-countable as a "new" hit if it reappears later, and the
    internal set must not grow unboundedly across many distinct short-lived
    groups (mirrors the existing idle-key-sweep test in test_window.py, but
    specifically for the new _live_members structure)."""
    counter = DequeWindowCounter()
    window_ms = 1000
    counter.hit("g", 0, window_ms, member="m1")
    # advance well past the window -- "m1" ages out
    result = counter.hit("g", 5000, window_ms, member="m1")
    check(result == 1,
          f"a member that aged OUT of the window must count again on "
          f"reappearance (fresh hit, not blocked by a stale dedup entry), got {result}")

    # idle-key sweep must also clear _live_members, not just _w/_dw (mirrors
    # test_window.py's existing "idle group keys should be swept" check).
    base = 1_750_000_000_000
    for i in range(1000):
        counter.hit(f"g{i}", base + i * 10_000_000, 60_000, member=f"m{i}")
    live_member_keys = len(counter._live_members)
    check(live_member_keys < 300,
          f"_live_members must be swept alongside _w/_dw for idle groups, "
          f"{live_member_keys} still resident (>=300 = leak)")


def main():
    test_large_single_group_burst_stays_near_linear()
    test_redelivered_member_still_dedups_correctly_at_scale()
    test_eviction_correctly_frees_the_member_set()

    if FAILS:
        print(f"\n[FAIL] window perf (P1-5): {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] window perf (P1-5) tests PASS")


if __name__ == "__main__":
    main()
