"""P1-8 remainder: XACK batching in `_topic_worker`'s real consume loop.

2026-07-21 audit found `bus.py`'s ack path issued one XACK round-trip per
message, no pipelining -- deferred at the time because batching safely
across `_process_message`'s three call sites (live daemon, claim_pending
redelivery, run_once()) needed a place to accumulate acks first.

This proves the actual wiring in `runner.py::_topic_worker`, not just that
`Bus.ack_batch()` exists in isolation: a spy bus counts real `ack()` vs
`ack_batch()` calls while `_topic_worker` runs its real consume loop, so
these assertions go RED if `_topic_worker` reverts to acking immediately per
message instead of batching at the end of each consume() pass.

Also covers the correctness property that matters more than the perf win:
a handler failure mid-batch must NOT batch-ack the message that failed --
only messages whose handler actually succeeded get into the flushed batch.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))
os.environ.setdefault("BUS_BACKEND", "memory")

from shared.bus import _MemoryBus  # noqa: E402
from shared import runner  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _SpyBus:
    """Wraps a real _MemoryBus, counting ack() vs ack_batch() calls/sizes."""

    def __init__(self):
        self._inner = _MemoryBus()
        self.ack_calls = 0          # single-message ack() invocations
        self.ack_batch_calls = 0    # ack_batch() invocations
        self.ack_batch_sizes: list[int] = []
        self.total_acked_ids: list[str] = []

    def produce(self, topic, key, payload):
        return self._inner.produce(topic, key, payload)

    def consume(self, topic, group=None, block_ms=0):
        return self._inner.consume(topic, group=group, block_ms=block_ms)

    def claim_pending(self, topic, group=None, min_idle_ms=0, max_redeliveries=5):
        return self._inner.claim_pending(
            topic, group=group, min_idle_ms=min_idle_ms,
            max_redeliveries=max_redeliveries)

    def ack(self, msg, group=None):
        self.ack_calls += 1
        self.total_acked_ids.append(msg.id)
        return self._inner.ack(msg, group)

    def ack_batch(self, msgs, group=None):
        self.ack_batch_calls += 1
        self.ack_batch_sizes.append(len(msgs))
        self.total_acked_ids.extend(m.id for m in msgs)
        return self._inner.ack_batch(msgs, group)


def _run_topic_worker_briefly(spy, topic, handler, *, run_ms=300):
    shutdown = threading.Event()
    t = threading.Thread(
        target=runner._topic_worker,
        args=(lambda: spy, topic, "cg-test", handler),
        kwargs=dict(max_redeliveries=5, shutdown=shutdown,
                    claim_idle_ms=60_000, idle_sleep_s=0.02,
                    consume_block_ms=50, service_name="test-ack-batching"),
        daemon=True,
    )
    t.start()
    time.sleep(run_ms / 1000)
    shutdown.set()
    t.join(timeout=2)
    check(not t.is_alive(), "_topic_worker did not shut down in time")


def test_successful_batch_is_acked_via_one_ack_batch_call():
    spy = _SpyBus()
    topic = "ack-batch-test.ok"
    for i in range(10):
        spy.produce(topic, key=str(i), payload={"n": i})

    seen = []

    def handler(payload):
        seen.append(payload["n"])

    _run_topic_worker_briefly(spy, topic, handler)

    check(sorted(seen) == list(range(10)),
          f"handler should see all 10 payloads exactly once, got {sorted(seen)}")
    check(spy.ack_calls == 0,
          f"expected the batched path to never call single-message ack(), "
          f"got {spy.ack_calls} -- _topic_worker may have reverted to "
          f"immediate per-message acking")
    check(spy.ack_batch_calls >= 1,
          "expected at least one ack_batch() flush")
    check(sum(spy.ack_batch_sizes) == 10,
          f"expected 10 total messages acked across batch(es), "
          f"got {sum(spy.ack_batch_sizes)}")

    # And the messages are genuinely gone from the PEL -- not just "counted
    # as acked" by the spy without the real ack happening underneath.
    remaining = list(spy._inner._pel.get(topic, {}))
    check(remaining == [], f"PEL should be empty after ack_batch, still has {remaining}")


def test_failed_handler_is_not_batch_acked():
    """A message whose handler raises must be excluded from the flushed
    batch -- proving ack_fn only accumulates messages _process_message
    actually decided to ack, not every message the loop saw."""
    spy = _SpyBus()
    topic = "ack-batch-test.partial-fail"
    for i in range(5):
        spy.produce(topic, key=str(i), payload={"n": i})

    def handler(payload):
        if payload["n"] == 2:
            raise RuntimeError("boom on 2")

    _run_topic_worker_briefly(spy, topic, handler)

    # 4 of 5 succeed and get acked; #2 stays in the PEL for redelivery.
    check(sum(spy.ack_batch_sizes) == 4,
          f"expected exactly 4 messages batch-acked (the ones whose handler "
          f"succeeded), got {sum(spy.ack_batch_sizes)}")
    remaining = list(spy._inner._pel.get(topic, {}).values())
    check(len(remaining) == 1 and remaining[0][0].payload["n"] == 2,
          f"expected exactly the failed message (n=2) to remain in the PEL "
          f"unacked, got {[m.payload for m, *_ in remaining]}")


def test_ack_batch_flush_failure_leaves_messages_for_redelivery():
    """If the pipeline flush itself raises, already-processed messages must
    NOT be silently treated as acked -- they simply stay in the PEL, same
    as any other failed flush (ack_batch's own docstring contract)."""

    class _FlushExplodes(_SpyBus):
        def ack_batch(self, msgs, group=None):
            self.ack_batch_calls += 1
            self.ack_batch_sizes.append(len(msgs))
            raise ConnectionError("simulated pipeline flush failure")

    spy = _FlushExplodes()
    topic = "ack-batch-test.flush-fail"
    for i in range(3):
        spy.produce(topic, key=str(i), payload={"n": i})

    seen = []
    _run_topic_worker_briefly(spy, topic, seen.append)

    check(len(seen) == 3, f"handler should still run for all 3, got {len(seen)}")
    remaining = list(spy._inner._pel.get(topic, {}))
    check(len(remaining) == 3,
          f"a failed flush must leave every processed-but-unflushed message "
          f"in the PEL for redelivery, found {len(remaining)} of 3 still "
          f"there")


def run_all() -> None:
    tests = [
        test_successful_batch_is_acked_via_one_ack_batch_call,
        test_failed_handler_is_not_batch_acked,
        test_ack_batch_flush_failure_leaves_messages_for_redelivery,
    ]
    for t in tests:
        t()
    if FAILS:
        for f in FAILS:
            print(f"  FAIL: {f}")
        raise SystemExit(f"[FAIL] {len(FAILS)} ack-batching assertion(s) failed")
    print(f"[OK] shared ack-batching (P1-8 remainder) PASS ({len(tests)} scenarios)")


if __name__ == "__main__":
    run_all()
