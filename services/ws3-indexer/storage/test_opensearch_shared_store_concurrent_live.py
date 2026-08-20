"""ONE shared OpenSearchStore instance survives real concurrent request/
response cycles from multiple threads -- LIVE (2026-08-19).

This is the exact shape `services/ws3-indexer/main.py`'s real daemon uses in
production: ``store = make_store()`` is constructed ONCE and handed to one
worker thread PER topic (module docstring, "the store is shared across the
4 topic threads"). `test_opensearch_cas_concurrency_live.py` deliberately
gives each of ITS writer threads its own store -- correct for what it's
proving (OCC/CAS holds under real concurrent writers), but its own docstring
notes in passing that a SHARED store "raises URLError(Idle) under real
contention" without that claim ever having its own dedicated proof. This
test is that proof, for the opposite reason: NOT to demonstrate the bug (the
production code no longer has it, see below) but to pin the fix.

Found live (2026-08-19) via `tools/fengarde_bench_live.py` pushing several
thousand events through the real Docker stack: ws3-indexer's log filled with
``http.client.ResponseNotReady: Idle`` / ``urllib.error.URLError: <urlopen
error Idle>`` on `scored.events`, because multiple topic-consumer threads
were racing ``.request()``/``.getresponse()`` on the SAME
``http.client.HTTPConnection`` -- a socket that cannot serve two concurrent
request/response cycles at once, no matter how much bookkeeping around it is
locked. `storage/opensearch.py`'s ``_node_lock`` only ever guarded node
SELECTION, never the connection's actual I/O (deliberately, per its own
comment, "so concurrent requests aren't needlessly serialized on the
network round-trip") -- so this was never actually prevented, only masked by
every prior live-Docker check using low-volume single-feeder-burst traffic
that rarely produced true concurrent hits on ws3's own multi-thread daemon.

Fixed by giving each thread its own connection via ``threading.local()``
(see `OpenSearchStore.__init__`/`_connection()`'s 2026-08-19 FIX comment) --
node-selection state stays shared and lock-guarded; only the raw socket,
the part that genuinely cannot be shared, is now per-thread.

Skips cleanly when no live cluster is reachable. Run with the stack up:

    OPENSEARCH_URL=http://localhost:9200 \\
        python services/ws3-indexer/storage/test_opensearch_shared_store_concurrent_live.py
"""
from __future__ import annotations

import os
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from storage.opensearch import OpenSearchStore  # noqa: E402

FAILS: list[str] = []

_THREADS = 8
_DOCS_PER_THREAD = 15


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _first_url() -> str:
    raw = os.getenv("OPENSEARCH_URL", "http://localhost:9200")
    return [p.strip() for p in raw.split(",") if p.strip()][0]


def _reachable(url: str) -> bool:
    try:
        with urllib.request.urlopen(f"{url}/_cluster/health", timeout=3):
            return True
    except Exception:  # noqa: BLE001
        return False


def main() -> int:
    url = _first_url()
    if not _reachable(url):
        print(f"[SKIP] shared-store concurrency: no live OpenSearch at {url} "
              f"(bring up the stack, or set OPENSEARCH_URL).")
        return 0

    # ONE store, shared across every thread -- the exact shape main.py uses,
    # deliberately NOT one-store-per-thread like the CAS concurrency test.
    store = OpenSearchStore(url)
    index = "events-sharedstoretest"
    run_id = uuid.uuid4().hex[:8]
    errors: dict[str, Exception] = {}
    lock = threading.Lock()
    start = threading.Barrier(_THREADS)

    # Defense in depth against a PRIOR run's leftovers: this test hangs, by
    # design, exactly when the bug it's checking for is present (a thread
    # wedged on ResponseNotReady never returns), so a killed-not-crashed
    # prior run can skip its own `finally`/DELETE entirely and leave stray
    # docs behind -- found live doing exactly this while pinning the fix
    # (a reverted-code run got SIGKILLed mid-hang, and the next run's count
    # check silently summed the leftover docs with its own). Best-effort:
    # a failure here must not block the real test from running.
    try:
        store._request("DELETE", f"/{index}")
    except Exception:  # noqa: BLE001
        pass

    def worker(thread_idx: int) -> None:
        start.wait()  # maximize real overlap, not staggered by spawn time
        for i in range(_DOCS_PER_THREAD):
            doc_id = f"{run_id}-t{thread_idx}-{i}"
            try:
                store.index(index, doc_id, {"ingest_id": doc_id, "run_id": run_id,
                                             "thread": thread_idx})
            except Exception as exc:  # noqa: BLE001
                with lock:
                    errors[doc_id] = exc

    try:
        threads = [threading.Thread(target=worker, args=(t,), daemon=True)
                   for t in range(_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        check(not errors,
              f"{len(errors)} of {_THREADS * _DOCS_PER_THREAD} shared-store writes raised "
              f"(the exact ResponseNotReady/URLError(Idle) class this test exists to catch): "
              f"{ {k: f'{type(v).__name__}: {v}' for k, v in list(errors.items())[:5]} }")

        store._request("POST", f"/{index}/_refresh")
        # Scoped to THIS run's run_id, never a bare index-wide count -- a
        # leftover doc from a killed prior run (see the pre-cleanup above)
        # must not silently inflate this run's own pass/fail verdict.
        count = store._request(
            "GET", f"/{index}/_count?q={urllib.parse.quote(f'run_id:{run_id}')}"
        ).get("count", 0)
        expected = _THREADS * _DOCS_PER_THREAD
        check(count == expected,
              f"expected {expected} docs indexed via the shared store for run "
              f"{run_id}, found {count} -- a doc silently failed to land even "
              f"though no exception surfaced")
    finally:
        try:
            store._request("DELETE", f"/{index}")
        except Exception:  # noqa: BLE001
            print(f"[warn] could not delete test index {index} -- remove it by hand")

    if FAILS:
        print(f"[FAIL] OpenSearch shared-store concurrency: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        return 1
    print(f"[OK] OpenSearch shared-store concurrency PASS -- {_THREADS} threads x "
          f"{_DOCS_PER_THREAD} docs through ONE OpenSearchStore instance (main.py's "
          f"real daemon shape), zero ResponseNotReady/URLError(Idle)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
