"""P1-6 (2026-07-21 audit fix plan): BoundedSpool.drain_into() perf + locking.

Two fixes proven here:
  1. O(n) instead of O(n^2): drain_into() used to do `remaining = remaining[1:]`
     once per line -- a full list reallocation per iteration.
  2. The lock is no longer held across produce() (network I/O in the real
     SyslogUDPServer path). A slow/blocking produce() must not starve a
     concurrent append() -- that stall is exactly what re-created kernel-level
     UDP drops (P0-4) via a different path.

Run: python services/ws1-collectors/test_spool_perf.py
"""
from __future__ import annotations

import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))  # for `shared`
sys.path.insert(0, str(HERE))

from collectors.spool import BoundedSpool  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_large_drain_stays_near_linear():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "spool.jsonl"
        spool = BoundedSpool(path, max_bytes=200_000_000)
        n = 20_000
        for i in range(n):
            spool.append({"i": i})

        replayed = []
        t0 = time.perf_counter()
        count = spool.drain_into(lambda ev: replayed.append(ev["i"]))
        elapsed = time.perf_counter() - t0

        check(count == n, f"all {n} entries must replay, got {count}")
        check(replayed == list(range(n)), "must replay in exact FIFO order")
        check(spool.pending_count() == 0, "spool must drain to empty")
        # Regression trip-wire (loose bound, same rationale as
        # test_window_perf.py): a reintroduced O(n^2) reslice would take far
        # longer than this at n=20,000.
        check(elapsed < 10.0,
              f"draining {n} entries took {elapsed:.2f}s -- a reintroduced "
              f"O(n^2) remaining-list reslice would take far longer at this n")


def test_produce_does_not_hold_the_lock_append_can_proceed_concurrently():
    """The core P1-6 safety property: while drain_into() is calling a SLOW
    produce() (simulating a real bus.produce() network round-trip), a
    concurrent append() (simulating the UDP handler's _try_spool()) must not
    block for the whole drain duration -- it must complete almost
    immediately, proving produce() runs outside the lock."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "spool.jsonl"
        spool = BoundedSpool(path, max_bytes=10_000_000)
        for i in range(5):
            spool.append({"i": i})

        produce_started = threading.Event()
        release_produce = threading.Event()

        def slow_produce(event):
            produce_started.set()
            release_produce.wait(timeout=5)  # simulate a slow network call

        drain_thread = threading.Thread(
            target=lambda: spool.drain_into(slow_produce), daemon=True)
        drain_thread.start()
        check(produce_started.wait(timeout=2),
              "drain_into must reach produce() promptly")

        # While produce() is deliberately blocked (lock must be free by now),
        # append() must complete quickly -- NOT wait for the whole drain.
        t0 = time.perf_counter()
        ok = spool.append({"i": "concurrent"})
        append_elapsed = time.perf_counter() - t0
        check(ok, "append() during a slow drain must still succeed")
        check(append_elapsed < 1.0,
              f"append() took {append_elapsed:.2f}s while produce() was "
              f"blocked -- the lock must be released during produce(), not "
              f"held for the whole drain (the exact P0-4-adjacent stall this "
              f"fix closes)")

        release_produce.set()
        drain_thread.join(timeout=5)
        check(not drain_thread.is_alive(), "drain thread must finish")


def test_concurrent_append_during_drain_is_not_lost():
    """The lock-release must not silently drop an event appended WHILE the
    drain is in flight -- it must survive into the post-drain remainder (or
    be picked up by a subsequent drain), never vanish."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "spool.jsonl"
        spool = BoundedSpool(path, max_bytes=10_000_000)
        for i in range(3):
            spool.append({"i": i})

        appended_during_drain = threading.Event()

        def produce_then_append_concurrently(event):
            if event["i"] == 1 and not appended_during_drain.is_set():
                # append a NEW event while this drain is still in flight
                spool.append({"i": "late-arrival"})
                appended_during_drain.set()

        replayed = []
        spool.drain_into(lambda ev: replayed.append(ev) or
                         produce_then_append_concurrently(ev))

        check(appended_during_drain.is_set(), "sanity: the concurrent append happened")
        # The late arrival must show up eventually -- either replayed in this
        # same drain pass (if it landed before drain_into's final re-read) or
        # preserved in the remainder for the next one. Either way, it must
        # never be silently lost.
        seen_ids = {e["i"] for e in replayed}
        still_pending = spool.pending_count() > 0
        check("late-arrival" in seen_ids or still_pending,
              "an event appended DURING a drain must not be silently lost -- "
              "either replayed in this pass or preserved for the next")


def test_torn_tail_from_crash_is_repaired_not_corrupted():
    """Gap-hunt (2026-08-26) #73: a crash mid-append can leave a partial,
    non-newline-terminated record at the spool's tail. The next append() must
    write the new record on a line of its OWN (a terminator newline first),
    never concatenate onto the partial record -- a concatenation would silently
    corrupt the new AND the old record into one unparseable line, then
    drain_into()'s corrupt-line skip would silently delete both with no log."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "spool.jsonl"
        # Simulate the torn state: a complete record, then a partial one
        # truncated mid-JSON by a crash (no trailing newline).
        path.write_text('{"i": 0}\n{"i": 1', encoding="utf-8")

        spool = BoundedSpool(path, max_bytes=10_000_000)
        check(not spool._tail_known_good,
              "torn-tail spool must be detected as not known-good at construction")
        ok = spool.append({"i": 2})
        check(ok, "append after a torn tail must succeed")

        replayed = []
        spool.drain_into(lambda ev: replayed.append(ev["i"]))
        # The complete record survives; the torn partial is dropped as corrupt
        # (documented behavior), and the NEW record is intact on its own line.
        check(0 in replayed, f"complete record must survive the torn tail, got {replayed}")
        check(2 in replayed, f"post-torn append must survive intact, got {replayed}")
        check(spool._tail_known_good, "after the repair the tail is known-good")
        # No garbage remains: the spool drains clean to empty.
        check(spool.pending_count() == 0, "spool must drain to empty after repair")


def test_torn_tail_append_keeps_new_record_on_its_own_line():
    """The repair property that actually matters (before any drain): the new
    record must NOT be concatenated onto the torn partial record."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "spool.jsonl"
        path.write_text('{"i": 0}\n{"i": 1', encoding="utf-8")

        spool = BoundedSpool(path, max_bytes=10_000_000)
        check(spool.append({"i": 2}), "append after a torn tail must succeed")
        raw = path.read_bytes()
        check(raw.endswith(b"\n"), "spool file must be newline-terminated after the append")
        # Lines: {"i": 0}, the (corrupt) torn partial, {"i": 2} -- the new
        # record is exactly one well-formed JSON line of its own, never fused
        # with the partial above it.
        lines = raw.decode("utf-8").splitlines()
        check(lines[-1] == '{"i": 2}',
              f"new record must be its own final line, got {lines[-1:]!r}")
        check(len(lines) == 3, f"expected 3 lines (good, torn, new), got {lines}")


def main():
    test_large_drain_stays_near_linear()
    test_produce_does_not_hold_the_lock_append_can_proceed_concurrently()
    test_concurrent_append_during_drain_is_not_lost()
    test_torn_tail_from_crash_is_repaired_not_corrupted()
    test_torn_tail_append_keeps_new_record_on_its_own_line()

    if FAILS:
        print(f"\n[FAIL] spool perf/locking (P1-6): {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] spool perf/locking (P1-6) tests PASS")


if __name__ == "__main__":
    main()
