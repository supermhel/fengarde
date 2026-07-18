"""P2.6 opt-in LIVE OpenSearch integration lane.

``test_opensearch_retry.py`` proves the retry/backoff/permanent-vs-transient
logic against a FAKE transport (no network). This file drives the real HTTP
wire format against a REAL OpenSearch cluster -- the exact surface the fake
transport cannot prove: that the request actually round-trips, that an
explicit ``_id`` PUT really is an idempotent upsert (not a duplicate), and
that OpenSearch's optimistic-concurrency 409 really fires on a stale
``if_seq_no``/``if_primary_term`` write. None of this runs in the default
zero-infra gate (``run_all_tests.sh`` / ``make test``); it is SKIPPED cleanly
here unless ``OPENSEARCH_URL`` is set and the cluster is reachable, and is
invoked separately via ``make test-live`` (see Makefile / README) with a real
OpenSearch container up (``make up`` or a redis+opensearch-only compose).

Run: OPENSEARCH_URL=http://localhost:9200 python services/ws3-indexer/storage/test_opensearch_live.py
"""
from __future__ import annotations

import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # for `storage`

from storage.opensearch import OpenSearchStore  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _reachable(url: str) -> bool:
    try:
        with urllib.request.urlopen(f"{url}/", timeout=2):
            return True
    except Exception:
        return False


def _test_index_is_idempotent_upsert(store: OpenSearchStore, index: str):
    doc_id = f"live-{uuid.uuid4()}"
    doc = {"n": 1, "msg": "first"}
    created = store.index(index, doc_id, doc)
    check(created is True, f"first index() of a new doc should report created=True, got {created}")
    check(store.count(index) >= 1, "count() should see the just-indexed doc")

    # Re-index the SAME id with different content: must UPDATE in place, not
    # duplicate -- this is the entire idempotency contract StorageAdapter
    # documents, and the fake-transport test can only assert the wire format,
    # not that OpenSearch itself honors it.
    doc2 = {"n": 2, "msg": "second"}
    store.index(index, doc_id, doc2)
    got = store._request("GET", f"/{index}/_doc/{doc_id}")
    check(got.get("_source", {}).get("n") == 2,
          f"re-index of the same _id must update in place, got {got}")


def _test_cas_conflict_on_stale_version(store: OpenSearchStore, index: str = "alerts-livetest"):
    alert_id = f"live-alert-{uuid.uuid4()}"
    store.index(index, alert_id, {"alert_id": alert_id, "status": "open"})
    time.sleep(0.2)  # let the refresh-on-read window settle (default 1s refresh_interval)
    store._request("POST", f"/{index}/_refresh")

    found = store.find_alert_versioned(alert_id)
    check(found is not None, "find_alert_versioned should locate the just-indexed alert")
    if found is None:
        return
    idx, doc, version = found
    check(version is not None, "a live cluster must return (_seq_no, _primary_term)")

    # A write using the correct (now-current) version succeeds.
    ok = store.index_cas(idx, alert_id, {"alert_id": alert_id, "status": "closed"}, version)
    check(ok is True, "CAS write at the correct version should succeed")

    # Reusing the SAME (now-stale) version must be rejected with a 409 -> False.
    stale_ok = store.index_cas(idx, alert_id, {"alert_id": alert_id, "status": "reopened"}, version)
    check(stale_ok is False, "CAS write reusing a stale version must be rejected (409 -> False)")


def _test_permanent_error_not_retried(store: OpenSearchStore):
    # A malformed document ID / index name combination that OpenSearch's URL
    # rules will reject outright should raise immediately (not silently swallow).
    try:
        store._request("GET", "/_this_path_does_not_exist_at_all")
        check(False, "expected an HTTPError for a nonexistent path")
    except urllib.error.HTTPError as exc:
        check(400 <= exc.code < 500, f"expected a 4xx, got {exc.code}")


def main() -> None:
    url = os.getenv("OPENSEARCH_URL", "http://localhost:9200")
    if not _reachable(url):
        print(f"[SKIP] test_opensearch_live: OpenSearch not reachable at {url} "
              "(set OPENSEARCH_URL and bring up a real cluster to run this lane)")
        return

    store = OpenSearchStore(url=url)
    index = "events-livetest"
    _test_index_is_idempotent_upsert(store, index)
    _test_cas_conflict_on_stale_version(store)
    _test_permanent_error_not_retried(store)

    if FAILS:
        print(f"\n[FAIL] opensearch live: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("\n[OK] opensearch live integration PASS")


if __name__ == "__main__":
    main()
