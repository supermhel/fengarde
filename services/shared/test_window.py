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


def _drive_sweep(c, t_ms, window_ms, prefix="noise"):
    """Send hits on OTHER keys until the counter's next sweep tick has run (the
    cadence is read from the module, never hard-coded)."""
    from shared import window as w
    for i in range(w._SWEEP_EVERY):
        c.hit(f"{prefix}-{i}", t_ms, window_ms, member=f"{prefix}-m{i}")


def test_sweep_evicts_each_key_by_its_own_window():
    """F1 (2026-10-02, adaptive-evasion lane): the idle-key sweep used the window of
    the hit that TRIGGERED it, so benign noise on a 60 s rule wiped the live state
    of every longer-window rule. Every key must be evicted by ITS OWN window only.
    Positive control: the 60 s noise keys ARE reclaimed. Negative control: a key
    idle for less than its own window survives."""
    t0 = 1_000_000
    # --- hit(): 300 s key, last hit 100 s before the sweep ----------------------
    c = DequeWindowCounter()
    c.hit("long", t0, 300_000, member="a")
    _drive_sweep(c, t0 + 100_000, 60_000)
    check("long" in c._w and "long" in c._last,
          "a 300 s key idle for 100 s must survive a sweep triggered by 60 s noise (F1)")
    check(c.hit("long", t0 + 100_001, 300_000, member="b") == 2,
          "the long-window count must still be 2 after the noise (state not swept)")
    check("noise-0" in c._w, "noise keys are not yet past their own 60 s window (still live)")
    # --- positive control: a key idle past ITS OWN window is reclaimed ----------
    c2 = DequeWindowCounter()
    c2.hit("short", t0, 60_000, member="a")
    _drive_sweep(c2, t0 + 100_000, 60_000)
    check("short" not in c2._w and "short" not in c2._last and "short" not in c2._live_members,
          "a 60 s key idle for 100 s must still be reclaimed by the sweep (memory bound)")
    # --- negative control: a long key idle past ITS window is also reclaimed ----
    c3 = DequeWindowCounter()
    c3.hit("long", t0, 300_000, member="a")
    _drive_sweep(c3, t0 + 400_000, 60_000)
    check("long" not in c3._w, "a 300 s key idle for 400 s is past its own window and must be reclaimed")
    # --- hit_distinct(): the same property --------------------------------------
    c4 = DequeWindowCounter()
    c4.hit_distinct("dlong", t0, 300_000, value="p1")
    _drive_sweep(c4, t0 + 100_000, 60_000)
    check(c4.hit_distinct("dlong", t0 + 100_001, 300_000, value="p2") == 2,
          "hit_distinct state of a 300 s key must survive 60 s noise (F1, distinct path)")
    c5 = DequeWindowCounter()
    c5.hit_distinct("dshort", t0, 60_000, value="p1")
    _drive_sweep(c5, t0 + 100_000, 60_000)
    check("dshort" not in c5._dw and "dshort" not in c5._last,
          "an idle 60 s distinct key is still reclaimed (memory bound)")


def test_sweep_per_key_window_is_the_latest_seen_for_that_key():
    """A key whose window changes between hits (rule reload) is judged by the window
    of its LAST hit, and the sidecar map never outlives the key."""
    t0 = 1_000_000
    c = DequeWindowCounter()
    c.hit("k", t0, 300_000, member="a")
    c.hit("k", t0 + 1, 10_000, member="b")        # reloaded with a shorter window
    _drive_sweep(c, t0 + 50_000, 60_000)
    check("k" not in c._w, "after the window shrank to 10 s the key is idle past it and is reclaimed")
    check("k" not in getattr(c, "_exp", {}), "the per-key deadline record must be dropped with the key")


def main():
    test_redelivered_member_refreshes_timestamp()
    test_member_without_redelivery_ages_out_normally()
    test_distinct_count_path_still_refreshes_value()
    test_sweep_evicts_each_key_by_its_own_window()
    test_sweep_per_key_window_is_the_latest_seen_for_that_key()

    if FAILS:
        print(f"[FAIL] window parity: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] R3-#61: deque window counter refreshes a redelivered member's "
          "timestamp (parity with Redis ZADD); idle members still age out")


if __name__ == "__main__":
    main()
