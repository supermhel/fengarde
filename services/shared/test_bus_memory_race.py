"""L1 (2026-07-30 audit): _MemoryBus.produce()'s `self._seq += 1` was an
unsynchronized read-modify-write. deque.append() is atomic in CPython so no
message was ever lost, but the counter wasn't -- concurrent produce() calls
on one shared _MemoryBus instance (e.g. SyslogUDPServer's worker-thread pool)
could hand two different messages the same `Message.id`.

Under real CPython scheduling this race is rare (a plain `int += 1` is a
handful of bytecodes, rarely preempted) -- exactly why it shipped unnoticed.
To make the test deterministic rather than relying on timing luck, `_seq` is
swapped for a `SlowInt` whose `__add__` sleeps before returning, then two
threads are released at a `Barrier` to force both to read the same pre-
increment value before either writes back -- the exact interleaving the
audit described. Verified by hand against the pre-fix code (bare
`self._seq += 1`, no lock): this technique reliably reproduces the
duplicate-id bug there, and the fix below (locking the whole read-modify-
write) makes it disappear even under this widened window.

Run: python services/shared/test_bus_memory_race.py
"""
from __future__ import annotations

import sys
import threading
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))

from shared.bus import _MemoryBus  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class SlowInt(int):
    """Widens the race window: __add__ sleeps before returning, so two
    threads both computing `self._seq + 1` overlap deterministically instead
    of by scheduling luck."""
    def __add__(self, other):
        time.sleep(0.05)
        return SlowInt(int(self) + other)


def run_consume_concurrency():
    """L2 (Task H): _MemoryBus.consume()'s check-and-pop was NOT atomic. Two
    concurrent consumers could both pass the `while q:` check before either
    popped, then double-deliver the last message (or IndexError on an emptied
    deque), and a consumer could interleave with a concurrent produce(). Fix:
    consume() snapshots-and-clears under _seq_lock so 'is there a message?' +
    'pop it' is a single atomic step.

    N > M so multiple consumers are guaranteed to contend over the tail of the
    queue, and the consumers each fully drain -- but the assertion doesn't lean
    on any particular interleaving: with the lock, every consumer always sees a
    distinct message. Under the pre-fix unlocked `while q: popleft()`, N>1
    consumers on a single message reliably double-popleft (IndexError / double
    delivery), so this test goes red there and green here.
    """
    N = 64  # concurrent consumers
    M = 64  # produced messages
    bus = _MemoryBus()
    for m in range(M):
        bus.produce("ct", key=None, payload={"m": m})

    results: list[int] = []
    results_lock = threading.Lock()

    def consumer():
        for msg in bus.consume("ct"):
            with results_lock:
                results.append(msg.payload["m"])

    threads = [threading.Thread(target=consumer) for _ in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    check(bus.depth("ct") == 0,
          f"bus depth should be 0 after all consumers finish, got "
          f"{bus.depth('ct')} (unconsumed messages left on the bus)")
    check(len(results) == M,
          f"expected exactly M={M} total messages consumed, got {len(results)} "
          f"(duplicates, drops, or stray yields on a drained bus)")
    counts = Counter(results)
    missing = [m for m in range(M) if counts.get(m, 0) == 0]
    dupes = {m: c for m, c in counts.items() if c > 1}
    check(not missing,
          f"messages dropped by concurrent consumers: {missing}")
    check(not dupes,
          f"messages consumed MORE than once by concurrent consumers: {dupes}")


def run():
    bus = _MemoryBus()
    bus._seq = SlowInt(0)  # force the widened window on the real class
    barrier = threading.Barrier(2)

    def hammer():
        barrier.wait()  # both threads enter produce() at the same instant
        bus.produce("t", key=None, payload={})

    t1 = threading.Thread(target=hammer)
    t2 = threading.Thread(target=hammer)
    t1.start(); t2.start()
    t1.join(timeout=5); t2.join(timeout=5)

    msgs = bus.drain("t")
    check(len(msgs) == 2, f"expected 2 messages, got {len(msgs)}")
    ids = [m.id for m in msgs]
    check(len(set(ids)) == 2,
          f"two concurrent produce() calls got the same Message.id under a "
          f"forced widened race window: {ids} -- the read-modify-write on "
          f"_seq is not properly locked")
    check(sorted(ids) == ["1", "2"], f"expected ids ['1','2'], got {sorted(ids)}")


def main():
    run()
    run_consume_concurrency()
    if FAILS:
        print(f"[FAIL] bus memory race: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] _MemoryBus.produce() and consume() are race-free under forced "
          "concurrent interleavings")


if __name__ == "__main__":
    main()
