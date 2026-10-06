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
from collections import Counter, deque
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

    All M messages are produced before any consumer thread starts, so with the
    fix in place whichever consumer wins the `_seq_lock` race takes the ENTIRE
    batch in one snapshot-and-clear and every other consumer sees an empty
    queue -- the split across N threads is all-or-nothing per consume() call,
    not one-message-each. The assertions therefore don't lean on any
    particular split between threads, only on the aggregate: every message
    delivered exactly once, none dropped, none duplicated, regardless of which
    thread(s) happened to win. N > M just gives the lock genuine contention
    (many threads racing to claim a batch, not just two). Under the pre-fix
    unlocked `while q: popleft()`, N>1 consumers draining the SAME queue
    concurrently reliably double-popleft (IndexError / double delivery) before
    it empties, so this test goes red there and green here.
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


class _RacingDeque(deque):
    """Makes the produce-vs-read race DETERMINISTIC. A producer thread is parked INSIDE its
    ``append`` (it has already allocated its id; exactly the reviewer's "taken its seq and is
    about to append" window) until a reader has created its iterator over this stream, then the
    producer is let go and given 0.3s to land its append.

    A bus whose produce() appends WITHOUT the lock its readers hold lets that append complete
    mid-iteration, and CPython raises ``RuntimeError: deque mutated during iteration`` in the
    reader. A bus that appends under the same lock the readers take can never have the append land
    inside a snapshot: the reader waits for the lock (the producer's park simply times out)."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.park_next_append = False
        self.parked = threading.Event()        # a producer is inside append()
        self.reader_ready = threading.Event()  # a reader holds a live iterator
        self.producer = None
        self.race_armed = 0

    def append(self, entry):
        if self.park_next_append:
            self.park_next_append = False
            self.race_armed += 1
            self.parked.set()
            self.reader_ready.wait(timeout=0.5)
        super().append(entry)

    def _reader_iter(self, it):
        self.reader_ready.set()                # the real deque iterator exists BEFORE the append lands
        if self.producer is not None:
            self.producer.join(timeout=0.3)
        yield from it                          # a mid-iteration mutation is detected here

    def __iter__(self):
        return self._reader_iter(super().__iter__())

    def __reversed__(self):
        return self._reader_iter(super().__reversed__())


def run_produce_vs_read_race():
    """A produce() racing consume()/drain() must never kill the reader (islice over a live deque
    raised RuntimeError) and must neither lose nor duplicate the racing message."""
    for reader in ("consume", "drain"):
        bus = _MemoryBus()
        q = _RacingDeque()
        bus._streams["rt"] = q
        for i in range(5):
            bus.produce("rt", None, {"i": i})
        q.park_next_append = True
        q.producer = threading.Thread(target=lambda: bus.produce("rt", None, {"late": True}), daemon=True)
        q.producer.start()
        q.parked.wait(timeout=2)
        read = (lambda: [m.payload for m in bus.consume("rt", group="g")]) if reader == "consume" \
            else (lambda: [m.payload for m in bus.drain("rt")])
        try:
            first = read()
        except RuntimeError as exc:
            check(False, f"{reader}() raised while a producer appended concurrently: {exc}")
            q.producer.join(timeout=5)
            continue
        q.producer.join(timeout=5)
        check(q.race_armed == 1, f"{reader}: the race was not armed (positive control)")
        check(first[:5] == [{"i": i} for i in range(5)],
              f"{reader}(): must return the 5 messages produced before it started, got {first}")
        if reader == "consume":      # cursor advanced: the racer arrives exactly once, now or next
            late = first[5:] + read()
            check(late == [{"late": True}],
                  f"consume(): the racing message must arrive exactly once, got {late}")
        else:                        # drain() does not advance anything: the next read has all six
            again = read()
            check(again == [{"i": i} for i in range(5)] + [{"late": True}],
                  f"drain(): the racing message must be visible on the next read, got {again}")


class _CountingDeque(deque):
    """Counts every element a reader walks past (forward or reversed iteration)."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.walked = 0

    def __iter__(self):
        for e in super().__iter__():
            self.walked += 1
            yield e

    def __reversed__(self):
        for e in super().__reversed__():
            self.walked += 1
            yield e


def run_tail_read_cost():
    """consume()/drain() must cost O(undelivered tail), not O(stream length). A lockstep
    produce-1/consume-1/ack run over a never-trimmed stream walked the whole already-consumed
    prefix on every call (islice(q, cursor, None)): quadratic. Counted in elements walked, so
    deterministic (no timing)."""
    n = 1500
    bus = _MemoryBus()
    q = _CountingDeque()
    bus._streams["lock"] = q
    for i in range(n):
        bus.produce("lock", "k", {"i": i})
        got = [m.payload["i"] for m in bus.consume("lock", group="g")]
        if got != [i]:
            check(False, f"lockstep delivery wrong at {i}: {got}")
            break
    check(q.walked <= 3 * n,
          f"consume() walked {q.walked} stream entries for {n} one-message polls "
          f"(~{n} expected; the quadratic pattern is ~{n * n // 2})")
    q.walked = 0
    for i in range(n):
        bus.produce("lock", "k", {"i": n + i})
        d = bus.drain("lock")
        if len(d) != 1:
            check(False, f"drain() must return exactly the undelivered tail, got {len(d)} at {i}")
            break
        list(bus.consume("lock", group="g"))
    check(q.walked <= 6 * n,
          f"drain()+consume() walked {q.walked} entries for {n} rounds (~{2 * n} expected)")


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
    run_produce_vs_read_race()
    run_tail_read_cost()
    if FAILS:
        print(f"[FAIL] bus memory race: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] _MemoryBus.produce() and consume() are race-free under forced "
          "concurrent interleavings")


if __name__ == "__main__":
    main()
