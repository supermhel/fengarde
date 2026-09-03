"""WS-5 WP-3-D concurrency test -- standalone script.

Validates the bounded LLM pool in ``AiWorker``:

(a) N concurrent LLM-tier ``handle()`` calls across N threads actually OVERLAP
    in the LLM (fake LLM blocks on a ``threading.Barrier``; with
    ``max_workers >= 2`` two calls must be in flight simultaneously; assert
    via a shared counter that the barrier was reached). Also asserts the pool
    is wired (mutation-soundness: deleting the pool wiring makes (a) fail).

(b) boundedness: submitting N much-larger-than-cap requests does not blow
    memory and the admission control rejects/backs up beyond the bound (assert
    in-flight count never exceeds the cap via an instrumented llm).

(c) concurrent redelivery dedup: two threads handling the SAME event id
    yield exactly ONE ``llm.analyze`` call and identical results.

(d) ordering/determinism: same request handled twice sequentially returns
    identical result dicts.

(e) existing ws5 tests stay green.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"
os.environ.pop("OLLAMA_URL", None)  # force StubLLM

import main as ws5  # noqa: E402

FAILS: list[str] = []


def check(c, m):
    if not c:
        FAILS.append(m)


def _ai_request(ingest_id="test-1", tier="llm"):
    return {
        "event_id": ingest_id,
        "reason": ["Privileged database operation on a banking DB"],
        "event": {
            "class_uid": 6005, "activity_id": 5, "severity_id": 4,
            "time": 1750000000000,
            "siem": {"sector": "bank", "ingest_id": ingest_id, "score": 85},
        },
    }


# ---------------------------------------------------------------------------
# (a) concurrent overlap with DIFFERENT event ids
# ---------------------------------------------------------------------------
class BarrierLLM:
    """Fake LLM that blocks on a barrier so we can observe concurrency."""

    def __init__(self, barrier: threading.Barrier, counter: list):
        self._barrier = barrier
        self._counter = counter

    def analyze(self, event, reasons):
        self._counter[0] += 1
        self._barrier.wait()
        return {"verdict": "malicious", "summary": "s", "level": "critical"}


def test_concurrent_overlap():
    worker = ws5.AiWorker(max_workers=2)
    check(isinstance(worker._pool, ThreadPoolExecutor),
          "AiWorker must own a ThreadPoolExecutor")
    check(worker._pool._max_workers >= 2,
          f"pool max_workers must be >= 2 for overlap test, got {worker._pool._max_workers}")

    n = 2
    barrier = threading.Barrier(n)
    counter = [0]
    worker.llm = BarrierLLM(barrier, counter)

    results = [None] * n
    errors = [None] * n

    def run_handle(idx):
        try:
            results[idx] = worker.handle(_ai_request(f"overlap-{idx}"))
        except Exception as exc:
            errors[idx] = exc

    threads = [threading.Thread(target=run_handle, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    check(counter[0] == n,
          f"concurrent overlap: analyze called {counter[0]}x, want {n}")
    check(all(e is None for e in errors),
          f"concurrent handle() raised: {errors}")
    check(all(r is not None for r in results),
          "concurrent handle() returned None")


# ---------------------------------------------------------------------------
# (b) boundedness / admission control
# ---------------------------------------------------------------------------
class ConcurrencyCountingLLM:
    """LLM stub that tracks how many analyze() calls are active at once."""

    def __init__(self):
        self.active = 0
        self.peak = 0
        self.total_calls = 0
        self._lock = threading.Lock()
        self._block = threading.Event()

    def analyze(self, event, reasons):
        with self._lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.total_calls += 1
        self._block.wait()
        with self._lock:
            self.active -= 1
        return {"verdict": "malicious", "summary": "s", "level": "critical"}


def test_boundedness():
    worker = ws5.AiWorker(max_workers=2, queue_cap=2)
    llm = ConcurrencyCountingLLM()
    worker.llm = llm

    req = _ai_request("bound-1")
    # Submit 6 requests: max_workers=2, queue_cap=2, total_cap=4.
    # The 5th and 6th should block on the semaphore.
    futures = []
    start_lock = threading.Lock()
    started = [0]

    def submit_one():
        with start_lock:
            started[0] += 1
        return worker.handle(req)

    threads = []
    for _ in range(6):
        t = threading.Thread(target=lambda: futures.append(submit_one()))
        threads.append(t)
        t.start()

    # Wait until at least 4 have started their LLM calls (acquired semaphore)
    while started[0] < 4:
        threading.Event().wait(0.05)

    check(llm.peak <= 2,
          f"in-flight LLM calls exceeded max_workers: peak={llm.peak}, want <= 2")

    # Unblock all LLM calls.
    llm._block.set()

    for t in threads:
        t.join(timeout=15)

    check(len(futures) == 6,
          f"expected 6 completed submissions, got {len(futures)}")
    check(all(f is not None for f in futures),
          "not all bounded submissions completed")
    check(llm.peak <= 2,
          f"peak in-flight exceeded cap after full run: {llm.peak}")


# ---------------------------------------------------------------------------
# (c) concurrent redelivery dedup with the SAME event id
# ---------------------------------------------------------------------------
class CountingLLM:
    def __init__(self, counter: list):
        self._counter = counter

    def analyze(self, event, reasons):
        self._counter[0] += 1
        return {"verdict": "malicious", "summary": "s", "level": "critical"}


def test_concurrent_redelivery_dedup():
    worker = ws5.AiWorker(max_workers=2)
    counter = [0]
    worker.llm = CountingLLM(counter)

    req = _ai_request("dedup-1")
    results = [None, None]
    errors = [None, None]

    # Synchronize both threads so they call handle() concurrently.
    barrier = threading.Barrier(2)

    def run_handle(idx):
        barrier.wait()
        try:
            results[idx] = worker.handle(req)
        except Exception as exc:
            errors[idx] = exc

    threads = [
        threading.Thread(target=run_handle, args=(0,)),
        threading.Thread(target=run_handle, args=(1,)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    check(counter[0] == 1,
          f"concurrent redelivery dedup: analyze called {counter[0]}x, want 1")
    check(errors[0] is None and errors[1] is None,
          f"concurrent dedup handle() raised: {errors[0]}, {errors[1]}")
    check(results[0] is not None and results[1] is not None,
          "concurrent dedup handle() returned None")
    check(results[0] == results[1],
          "concurrent dedup results must be identical")


# ---------------------------------------------------------------------------
# (d) ordering / determinism
# ---------------------------------------------------------------------------
def test_determinism():
    worker = ws5.AiWorker()
    req = _ai_request("det-1")
    r1 = worker.handle(req)
    r2 = worker.handle(req)
    check(r1 == r2, "sequential same-request results must be identical")
    check(r1 is not r2, "results must be defensive copies, not the same object")


# ---------------------------------------------------------------------------
# (e) existing tests stay green
# ---------------------------------------------------------------------------
EXISTING_TESTS = [
    "test_contract.py",
    "test_ai_engine_metrics.py",
    "test_fix_llm_dedup.py",
    "test_fix_ws5_gap_hunt.py",
    "test_llm_adapter.py",
]


def test_existing_green():
    python = sys.executable
    for script in EXISTING_TESTS:
        proc = subprocess.run(
            [python, str(HERE / script)],
            capture_output=True,
            text=True,
            cwd=str(SERVICES),
            env={**os.environ, "BUS_BACKEND": "memory"},
        )
        ok = proc.returncode == 0
        check(ok, f"{script} failed (rc={proc.returncode}):\n{proc.stdout}\n{proc.stderr}")


def main():
    test_concurrent_overlap()
    test_boundedness()
    test_concurrent_redelivery_dedup()
    test_determinism()
    test_existing_green()

    if FAILS:
        print(f"[FAIL] WS-5 concurrency: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-5 concurrency test PASS")


if __name__ == "__main__":
    main()
