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
    # P1-4 (2026-07-21 audit): count() hits _count, which only sees REFRESHED
    # segments (OpenSearch's default refresh_interval is ~1s) -- this check
    # had no settle wait at all before the persistent-connection rewrite
    # made the round-trip fast enough to reliably race it. Explicit refresh,
    # same pattern already used later in this file.
    store._request("POST", f"/{index}/_refresh")
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


def _load_json(path: Path) -> dict:
    import json
    return json.loads(path.read_text(encoding="utf-8"))


_ROOT = HERE.parents[2]  # repo root (parents: ws3-indexer, services, root)
_MAPPINGS = _ROOT / "contracts" / "opensearch-mappings"


def _put_ism_policy(store: OpenSearchStore, name: str, body: dict) -> None:
    """Idempotent ISM policy install: create-PUT, or update-PUT with the
    stored _seq_no/_primary_term when it already exists (ISM's required
    update handshake) -- same flow infra/provision.sh runs with curl."""
    try:
        store._request("PUT", f"/_plugins/_ism/policies/{name}", body)
    except urllib.error.HTTPError as exc:
        if exc.code not in (409, 400):
            raise
        meta = store._request("GET", f"/_plugins/_ism/policies/{name}")
        seq, prim = meta.get("_seq_no"), meta.get("_primary_term")
        store._request(
            "PUT",
            f"/_plugins/_ism/policies/{name}?if_seq_no={seq}&if_primary_term={prim}",
            body)


def _test_ism_policies_install_and_attach(store: OpenSearchStore):
    """The M4.6 gap-closer: prove the ism-*.json bodies are ACCEPTED by a real
    OpenSearch ISM plugin (schema-valid), round-trip on GET, and that the
    ism_template block really auto-attaches the policy to a new index matching
    its pattern -- the exact thing the old Elasticsearch-syntax file could
    never do."""
    policies = sorted(_MAPPINGS.glob("ism-*.json"))
    check(len(policies) == 4, f"expected 4 ism-*.json policy files, found {len(policies)}")
    for path in policies:
        name = path.stem.removeprefix("ism-")
        _put_ism_policy(store, name, _load_json(path))
        got = store._request("GET", f"/_plugins/_ism/policies/{name}")
        states = got.get("policy", {}).get("states", [])
        check(any(s.get("name") == "delete" for s in states),
              f"policy {name} must round-trip with its delete state, got {got.get('policy', {}).keys()}")

    # ism_template attach check: create a fresh index matching events-common-*
    # and confirm ISM marks it managed by the events-30d policy.
    idx = f"events-common-livetest-{uuid.uuid4().hex[:8]}"
    store._request("PUT", f"/{idx}", {})
    try:
        attached = None
        for _ in range(20):  # attach is asynchronous; poll up to ~10s
            explain = store._request("GET", f"/_plugins/_ism/explain/{idx}")
            info = explain.get(idx, {}) or {}
            attached = (info.get("index.plugins.index_state_management.policy_id")
                        or info.get("policy_id"))
            if attached:
                break
            time.sleep(0.5)
        check(attached == "events-30d",
              f"new index {idx} must auto-attach policy events-30d via ism_template, got {attached!r}")
    finally:
        try:
            store._request("DELETE", f"/{idx}")
        except Exception:
            pass


def _test_migrate_live(store: OpenSearchStore):
    """Run the real tools/migrate_opensearch.py plan/apply cycle against the
    live cluster -- the standing 'wire-format tested only' caveat closer:
    real 2.13 accepts the template PUTs, GET /_index_template returns the
    shape the parser expects, mapping_version round-trips, and a second
    plan() reports zero drift."""
    sys.path.insert(0, str(_ROOT / "tools"))
    sys.path.insert(0, str(_ROOT / "services"))
    import migrate_opensearch as mig

    steps = mig.plan(store)
    applied = mig.apply(store, steps)
    # After apply, every template must be installed at its file version.
    steps2 = mig.plan(store)
    check(all(s["action"] == "skip" for s in steps2),
          f"second plan() after apply must report zero drift, got {steps2}")
    check(all(s["installed_version"] == s["desired_version"] for s in steps2),
          f"mapping_version must round-trip through the live cluster, got {steps2}")
    print(f"  migrate live: applied={applied or '(already current)'}")


def _test_permanent_error_not_retried(store: OpenSearchStore):
    # A malformed document ID / index name combination that OpenSearch's URL
    # rules will reject outright should raise immediately (not silently swallow).
    try:
        store._request("GET", "/_this_path_does_not_exist_at_all")
        check(False, "expected an HTTPError for a nonexistent path")
    except urllib.error.HTTPError as exc:
        check(400 <= exc.code < 500, f"expected a 4xx, got {exc.code}")


def _test_bulk_index_round_trips(store: OpenSearchStore, index: str = "events-bulktest"):
    """P1-4 (2026-07-21 audit): the real /_bulk NDJSON path against a live
    cluster -- the fake-transport unit test (test_opensearch_retry.py) can
    only prove the request is CONSTRUCTED correctly, not that OpenSearch
    actually indexes every item and reports per-item status the way
    bulk_index()'s result-parsing expects."""
    n = 25
    items = [(index, f"bulk-{uuid.uuid4()}", {"n": i, "msg": f"bulk item {i}"})
            for i in range(n)]
    result = store.bulk_index(items)
    check(result["indexed"] == n,
          f"bulk_index should report all {n} items indexed, got {result}")
    check(result["errors"] == [], f"no items should error, got {result['errors']}")

    store._request("POST", f"/{index}/_refresh")
    check(store.count(index) >= n,
          f"count() should see all {n} bulk-indexed docs, got {store.count(index)}")

    check(store.bulk_index([]) == {"indexed": 0, "errors": []},
          "bulk_index([]) must be a safe zero-op, not an HTTP call")

    # Persistent-connection reuse (the other half of P1-4): the same
    # connection object must survive across an index() call, a bulk_index()
    # call, and a count() call -- i.e. it's genuinely being reused, not
    # silently reconnecting every time (which would still pass functionally
    # but defeat the point of this fix).
    conn_before = store._conn
    store.index(index, f"single-{uuid.uuid4()}", {"n": 999})
    check(store._conn is conn_before,
          "the HTTP connection must be REUSED across calls, not reopened each time")


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
    _test_migrate_live(store)
    _test_ism_policies_install_and_attach(store)
    _test_bulk_index_round_trips(store)

    if FAILS:
        print(f"\n[FAIL] opensearch live: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("\n[OK] opensearch live integration PASS")


if __name__ == "__main__":
    main()
