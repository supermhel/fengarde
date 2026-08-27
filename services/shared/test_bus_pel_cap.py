"""Gap-hunt #1 (2026-08-27): _MemoryBus's bounded-PEL eviction must never
evict an entry from the batch about to be yielded.

Before this fix, consume() added the whole batch to the PEL and then ran
oldest-eviction while len(pel) > cap -- with a small cap and a large batch,
that eviction loop deleted entries that were IN the batch being returned.
The caller received those messages via the iterator, but claim_pending()
could no longer see them, so a handler crash on one of them lost it forever:
an at-least-once violation.

Run: python services/shared/test_bus_pel_cap.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))

from shared.bus import _MemoryBus  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_pel_cap_never_evicts_in_flight_batch():
    """THE regression: a batch larger than the cap must still be fully
    reclaimable via claim_pending after it is yielded -- nothing handed to
    the caller may be dropped by the cap."""
    bus = _MemoryBus()
    bus._pel_cap = 3  # force the cap far below the batch size
    N = 10
    for i in range(N):
        bus.produce("t", key=None, payload={"n": i})

    yielded = list(bus.consume("t"))
    check(len(yielded) == N,
          f"consume() must yield all {N} messages, got {len(yielded)}")

    # At-least-once contract: every yielded id must still be reclaimable via
    # claim_pending. Before the fix, the cap evicted 7 of the 10 in-flight
    # entries and claim_pending saw only 3.
    claimed = {m.id for m, _times in bus.claim_pending("t", min_idle_ms=0)}
    check(claimed == {m.id for m in yielded},
          f"every yielded message must still be claimable via claim_pending; "
          f"missing={ {m.id for m in yielded} - claimed }")

    # And nothing was evicted at all: the only over-cap entries were
    # in-flight, which the fix refuses to drop.
    check(bus.pel_evicted("t") == 0,
          f"no in-flight entry may be evicted by the cap, got {bus.pel_evicted('t')} evicted")


def test_pel_cap_still_evicts_prior_batches():
    """The cap must still bound memory for a never-acking consumer: entries
    from PRIOR batches (already yielded, still unacked) are fair game."""
    bus = _MemoryBus()
    bus._pel_cap = 2
    for i in range(4):
        bus.produce("t", key=None, payload={"n": i})
    first = list(bus.consume("t"))  # batch of 4 -> all in-flight, none evictable
    check(bus.pel_evicted("t") == 0, "an in-flight batch must not be evicted")

    # a second batch: the first batch's entries are now PRIOR (yielded) work
    for i in range(4, 6):
        bus.produce("t", key=None, payload={"n": i})
    second = list(bus.consume("t"))
    check(len(second) == 2, f"second batch must yield all 2, got {len(second)}")

    # cap=2, 6 pending, 2 in-flight protected -> the 4 prior entries evicted
    check(bus.pel_evicted("t") == 4,
          f"prior-batch entries must be evicted down to the cap, got {bus.pel_evicted('t')}")
    claimed = {m.id for m, _times in bus.claim_pending("t", min_idle_ms=0)}
    check(claimed == {m.id for m in second},
          f"the in-flight (second) batch must still be fully claimable, got "
          f"claimed={len(claimed)} expected={len(second)}")


def main():
    test_pel_cap_never_evicts_in_flight_batch()
    test_pel_cap_still_evicts_prior_batches()

    if FAILS:
        print(f"[FAIL] bus PEL cap: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] gap-hunt #1: _MemoryBus PEL-cap eviction never drops in-flight "
          "batch entries (at-least-once preserved); prior-batch eviction still "
          "bounds the never-acking consumer")


if __name__ == "__main__":
    main()
