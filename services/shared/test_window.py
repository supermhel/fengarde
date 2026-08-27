"""R3-#61 (2026-08-27): deque/Redis window-count parity on redelivery.

RedisWindowCounter's ZADD refreshes an already-present member's score (so a
member that keeps appearing stays in-window). DequeWindowCounter used to
SKIP an already-live member entirely, leaving its original (older) timestamp
in place -- so a member redelivered just inside the window still aged out at
the window boundary on the deque backend while the Redis backend kept it
alive. Fix: the deque backend also refreshes the member's timestamp on
redelivery.

Run: python services/shared/test_window.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))

from shared.window import DequeWindowCounter  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_redelivered_member_refreshes_timestamp():
    """A member already alive in the window counts once, but its timestamp is
    refreshed to the redelivery time -- parity with Redis ZADD updating the
    member's score."""
    c = DequeWindowCounter()
    # first 'a' at t=100
    check(c.hit("k", 100, 1000, member="a") == 1,
          "first hit of a new member must count it once")
    # redelivery of the already-live 'a' at t=200 -> still one entry, but its
    # timestamp is refreshed to 200
    check(c.hit("k", 200, 1000, member="a") == 1,
          "redelivering a live member must not double count")
    # observer at t=1200 (window 1000 -> horizon 200): a refreshed 'a'
    # (t=200) is still in-window, plus the new 'b' -> count 2. WITHOUT the
    # refresh, 'a' would sit at t=100 (evicted at horizon 200) -> count 1.
    check(c.hit("k", 1200, 1000, member="b") == 2,
          f"redelivered member must be refreshed so it survives the window "
          f"boundary, got {c.hit('k', 1200, 1000, member='b')}")

    # members() should also agree: both 'a' and 'b' alive at t=1200.
    check(sorted(c.members("k")) == ["a", "b"],
          f"members() must include the refreshed 'a' and 'b', got {sorted(c.members('k'))}")


def test_member_without_redelivery_ages_out_normally():
    """Sanity: without a refresh, an idle member still ages out at the window
    boundary -- the refresh only applies to an actual redelivery."""
    c = DequeWindowCounter()
    check(c.hit("k", 100, 1000, member="a") == 1, "hit once")
    # a new member at t=1200 (horizon 200): 'a' at t=100 was NOT refreshed,
    # so it is evicted -> only 'b' survives.
    check(c.hit("k", 1200, 1000, member="b") == 1,
          f"an un-refreshed member must age out at the window boundary, got "
          f"{c.hit('k', 1200, 1000, member='b')}")


def test_distinct_count_path_still_refreshes_value():
    """hit_distinct keeps one entry per distinct value; re-seeing a value
    must refresh its timestamp the same way (ZADD parity)."""
    c = DequeWindowCounter()
    check(c.hit_distinct("k", 100, 1000, value=443) == 1, "port 443 first seen")
    check(c.hit_distinct("k", 200, 1000, value=443) == 1, "port 443 re-seen stays 1 distinct")
    # observer at t=1200 (horizon 200): refreshed 443 (t=200) + new 80 -> 2
    check(c.hit_distinct("k", 1200, 1000, value=80) == 2,
          f"refreshed distinct value must survive the window boundary, got "
          f"{c.hit_distinct('k', 1200, 1000, value=80)}")


def main():
    test_redelivered_member_refreshes_timestamp()
    test_member_without_redelivery_ages_out_normally()
    test_distinct_count_path_still_refreshes_value()

    if FAILS:
        print(f"[FAIL] window parity: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] R3-#61: deque window counter refreshes a redelivered member's "
          "timestamp (parity with Redis ZADD); idle members still age out")


if __name__ == "__main__":
    main()
