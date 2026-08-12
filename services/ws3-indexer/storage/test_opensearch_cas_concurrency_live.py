"""Optimistic-concurrency (OCC/CAS) holds under REAL concurrent writers -- LIVE.

Closes the gap SSOT.md §2 records against the triage row: the CAS wire format
was verified against a fake transport (`test_storage_cas.py`) and a real 409 was
observed in `test_opensearch_live.py`, but the property those exist to protect
-- that two analysts triaging one alert cannot silently clobber each other --
was never exercised with actual concurrent writers against a real cluster.

The defect this catches is a LOST UPDATE, and the reason it needs real
concurrency is that a lost update is invisible to a serial test: each write
succeeds, the final document is well-formed, and only a marker that should be
there and isn't reveals the loss. Every writer here appends its own unique
marker under read-modify-write with a bounded retry on 409, so the pass
condition is exact and total: after N concurrent writers, all N markers are
present. Drop the `if_seq_no`/`if_primary_term` guard from `index_cas` and this
test fails -- interleaved writers overwrite each other's appends.

Note what this does NOT claim: it exercises `find_alert_versioned` + `index_cas`
directly, so it proves the storage layer's concurrency control, not the triage
HTTP endpoint's end-to-end behavior under load (that path adds an in-process
lock the storage layer knows nothing about).

Skips cleanly when no live cluster is reachable -- same convention as the other
live lanes. Run with the stack up:

    OPENSEARCH_URL=http://localhost:9201 \\
        python services/ws3-indexer/storage/test_opensearch_cas_concurrency_live.py
"""
from __future__ import annotations

import os
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from storage.opensearch import OpenSearchStore  # noqa: E402

FAILS: list[str] = []

_WRITERS = 8
_MAX_RETRIES = 50


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


def _writer(store: OpenSearchStore, alert_id: str, marker: str,
            results: dict, lock: threading.Lock) -> None:
    """One analyst: read the alert, append a marker, CAS it back.

    A 409 means someone else committed in between -- re-read and retry, which
    is exactly what the production triage path does. Retries are bounded so a
    livelock fails the test instead of hanging it.

    Each writer gets its OWN store (see main()): `OpenSearchStore` holds a
    urllib opener that is not thread-safe, and sharing one across threads
    raises `URLError(Idle)` under real contention -- which surfaces here as
    every note "lost" and reads exactly like an OCC failure. Separate clients
    are also the honest shape of the scenario being modelled: two analysts on
    two replicas, not two threads sharing a connection.
    """
    for attempt in range(_MAX_RETRIES):
        found = store.find_alert_versioned(alert_id)
        if found is None:
            with lock:
                results[marker] = f"alert not found on attempt {attempt}"
            return
        index, doc, version = found
        notes = list(doc.get("triage_notes") or [])
        notes.append(marker)
        doc["triage_notes"] = notes
        try:
            if store.index_cas(index, alert_id, doc, version):
                with lock:
                    results[marker] = "ok"
                return
        except Exception as exc:  # noqa: BLE001
            with lock:
                results[marker] = f"raised {type(exc).__name__}: {exc}"
            return
        # CAS rejected (409): someone committed in between. Re-read and retry.
        #
        # The refresh is REQUIRED, not a politeness. `find_alert_versioned`
        # locates the doc with `/alerts-*/_search` (the caller holds only an
        # alert_id, not the index name), and search only sees REFRESHED
        # segments -- default `index.refresh_interval` is 1s. Without an
        # explicit refresh the retry loop re-reads the same stale version it
        # just failed on, burns every attempt inside one refresh window, and
        # gives up. Measured 2026-08-11 on the single-node stack: 3 of 8
        # writers exhausted 50 retries this way while the 3-node HA cluster
        # happened to pass. That is a real property of the production triage
        # path too, not a test artifact -- its CAS loop is refresh-bound for
        # exactly the same reason. Recorded in SSOT.md.
        try:
            store._request("POST", f"/{index}/_refresh")
        except Exception:  # noqa: BLE001 - refresh is best-effort
            pass
        time.sleep(0.02 * (attempt % 5 + 1))
    with lock:
        # Distinct from a lost update, and the distinction matters: this writer
        # never committed at all, which means OCC did its job (it refused every
        # stale write) and the CALLER ran out of patience. Reporting it as a
        # clobber would blame the concurrency control for the opposite of what
        # it did.
        results[marker] = f"never committed: gave up after {_MAX_RETRIES} CAS retries"


def main() -> int:
    url = _first_url()
    if not _reachable(url):
        print(f"[SKIP] CAS concurrency: no live OpenSearch at {url} "
              f"(bring up the stack, or set OPENSEARCH_URL).")
        return 0

    store = OpenSearchStore(url)
    alert_id = f"cas-concurrency-{uuid.uuid4()}"
    index = "alerts-castest"

    # Everything that touches the index runs under try/finally so the teardown
    # below ALWAYS runs. This matters more than usual here: `alerts-castest`
    # matches the `alerts-*` pattern `_search_alert` queries, so an index left
    # behind by an early return or a raised request does not merely waste disk
    # -- it becomes a stray document that later runs of this test, and any other
    # test counting or searching `alerts-*`, will see. Found in review (the
    # original had two leak paths: the seed-failure `return 1`, and any raise
    # from the post-write refresh/read).
    try:
        # Seed one alert, then make it visible to _search (find_alert_versioned
        # goes through /alerts-*/_search, which only sees refreshed segments).
        store.index(index, alert_id, {"alert_id": alert_id, "score": 50,
                                      "triage_notes": []})
        store._request("POST", f"/{index}/_refresh")

        seeded = store.find_alert_versioned(alert_id)
        check(seeded is not None,
              f"seed alert {alert_id} not retrievable -- nothing below is meaningful")
        if seeded is None:
            print(f"[FAIL] CAS concurrency: {FAILS[-1]}")
            return 1
        check(seeded[2] is not None,
              "seed alert returned version=None -- the cluster did not supply "
              "_seq_no/_primary_term, so index_cas would degrade to unconditional "
              "writes and this test would prove nothing about OCC")

        # Fire all writers at once against the same document.
        results: dict[str, str] = {}
        lock = threading.Lock()
        start = threading.Barrier(_WRITERS)
        markers = [f"note-{i}-{uuid.uuid4().hex[:6]}" for i in range(_WRITERS)]

        def run(marker: str) -> None:
            writer_store = OpenSearchStore(url)  # per-thread client, see _writer
            start.wait()  # maximize real overlap rather than stagger by spawn time
            _writer(writer_store, alert_id, marker, results, lock)

        threads = [threading.Thread(target=run, args=(m,), daemon=True)
                   for m in markers]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)

        failed = {m: r for m, r in results.items() if r != "ok"}
        check(not failed, f"writer(s) did not commit: {failed}")
        check(len(results) == _WRITERS,
              f"only {len(results)} of {_WRITERS} writers reported a result "
              f"(a thread hung or died silently)")

        # The actual assertion: every marker survived. A lost update shows up
        # here and nowhere else -- each individual write succeeded.
        store._request("POST", f"/{index}/_refresh")
        final = store.find_alert_versioned(alert_id)
        check(final is not None, "alert vanished after the concurrent writes")
        if final is not None:
            notes = list(final[1].get("triage_notes") or [])
            # THE correctness assertion, scoped precisely: a writer whose CAS
            # RETURNED TRUE committed, so its note must be present. A writer
            # that never committed is a separate outcome (reported by the
            # `failed` check above) and asserting its note here would blame OCC
            # for a caller that gave up -- the opposite of what happened.
            committed = [m for m in markers if results.get(m) == "ok"]
            lost = [m for m in committed if m not in notes]
            check(not lost,
                  f"{len(lost)} note(s) whose CAS reported SUCCESS are missing "
                  f"from the final document -- a genuine lost update, OCC did "
                  f"not hold: {lost}")
            check(len(notes) == len(committed),
                  f"document holds {len(notes)} notes but {len(committed)} "
                  f"writers committed: {notes}")
    finally:
        # Test-only index, never a real alerts-YYYY.MM.DD one. Catches broadly
        # on purpose: a cleanup that itself raises (connection dropped, cluster
        # going away mid-teardown) must not replace the real verdict above with
        # an unrelated traceback.
        try:
            store._request("DELETE", f"/{index}")
        except Exception:  # noqa: BLE001
            print(f"[warn] could not delete test index {index} -- it matches "
                  f"alerts-* and may pollute later searches; remove it by hand")

    if FAILS:
        print(f"[FAIL] OpenSearch CAS concurrency: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        return 1
    print(f"[OK] OpenSearch OCC/CAS concurrency PASS -- {_WRITERS} concurrent "
          f"read-modify-write triage updates against a real cluster, all "
          f"{_WRITERS} notes preserved, zero lost updates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
