"""Fan-out pin: with N consumer groups on ONE topic, EVERY group receives
EVERY message, and one group's ack does NOT cancel another's.

Closes the per-group fan-out guarantee (gap-hunt #50/#52, 2026-08-26): the
old one-deque-per-topic design let the first group to consume wipe the topic
for everyone else. The other bus tests cover lag()/PEL semantics broadly, but
the multi-group INDEPENDENCE property -- every group gets a full copy, and
acking in group A never affects the PEL/cursor of groups B/C -- deserves a
direct pin (the real 3-way `alerts` fan-out cg-index/cg-webhook/cg-correlate
depends on exactly this).

Same zero-infra convention as every other `services/shared/test_*.py`: runs on
the in-memory backend, no Redis required. Plain `unittest` so it also
assembles under `python -m unittest discover`; `if __name__ == "__main__"`
makes it self-running too.

Run: python services/shared/test_bus_groups.py
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))
os.environ.setdefault("BUS_BACKEND", "memory")

from shared.bus import _MemoryBus  # noqa: E402


def _produce(bus, topic, n):
    for i in range(n):
        bus.produce(topic, key=str(i), payload={"n": i})


class BusFanOutTest(unittest.TestCase):
    def test_every_group_receives_every_message(self):
        """3 groups on one topic: each sees the full, identical stream."""
        bus = _MemoryBus()
        topic = "fanout.every"
        n = 20
        _produce(bus, topic, n)

        groups = ["cg-a", "cg-b", "cg-c"]
        seen: dict[str, list] = {}
        for g in groups:
            seen[g] = list(bus.consume(topic, group=g))

        # Every group got every message (a true fan-out) -- and the *same*
        # stream ids, not N independently-numbered copies.
        first_ids = [m.id for m in seen[groups[0]]]
        for g in groups:
            self.assertEqual(len(seen[g]), n,
                             f"{g} must receive all {n} messages")
            self.assertEqual(sorted(m.payload["n"] for m in seen[g]),
                             list(range(n)),
                             f"{g} must see payloads 0..{n - 1}")
            self.assertEqual(sorted(m.id for m in seen[g]), sorted(first_ids),
                             f"{g} must see the SAME stream ids as the others")

    def test_one_groups_ack_does_not_cancel_another(self):
        """Acking group A leaves group B/C's PEL (and redelivery) intact."""
        bus = _MemoryBus()
        topic = "fanout.independent"
        n = 8
        _produce(bus, topic, n)

        msgs: dict[str, list] = {}
        for g in ["cg-a", "cg-b", "cg-c"]:
            msgs[g] = list(bus.consume(topic, group=g))

        # Ack ONLY group A. Its PEL must fully clear...
        for m in msgs["cg-a"]:
            bus.ack(m, "cg-a")
        claimed_a = list(bus.claim_pending(topic, group="cg-a", min_idle_ms=0))
        self.assertEqual(claimed_a, [],
                         "acking group A must fully clear A's own PEL")

        # ...but B and C still hold every message -- A's ack must NOT reach
        # across and cancel them.
        for g in ("cg-b", "cg-c"):
            claimed = list(bus.claim_pending(topic, group=g, min_idle_ms=0))
            self.assertEqual(
                len(claimed), n,
                f"group {g} must still hold all {n} messages for redelivery "
                f"after group A's ack")
            self.assertEqual(sorted(m.payload["n"] for m, _ in claimed),
                             sorted(range(n)))
            # First redelivery of the oldest {g} message carries count 2.
            self.assertEqual(claimed[0][1], 2,
                             f"oldest {g} message reclaim must be delivery #2")
            self.assertEqual(claimed[0][0].id, msgs[g][0].id,
                             "reclaimed ids must match what the group consumed")
            for m, _ in claimed:
                bus.ack(m, g)

    def test_lag_tracks_the_worst_group_not_the_acked_one(self):
        """lag() must reflect the furthest-behind group, so one group acking
        everything does not hide another group that read but never acked."""
        bus = _MemoryBus()
        topic = "fanout.lag"
        n = 5
        _produce(bus, topic, n)

        fast = list(bus.consume(topic, group="cg-fast"))
        _ = list(bus.consume(topic, group="cg-slow"))

        # cg-fast acks everything; cg-slow acks nothing.
        for m in fast:
            bus.ack(m, "cg-fast")

        self.assertEqual(bus.depth(topic), 0,
                         "everything is delivered (past every cursor) -> depth 0")
        self.assertEqual(bus.lag(topic), n,
                         "lag must report cg-slow's {n} unacked pending, not "
                         "cg-fast's clean slate")


if __name__ == "__main__":
    unittest.main(verbosity=2)