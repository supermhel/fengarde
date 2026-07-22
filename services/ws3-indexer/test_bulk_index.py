"""P1-4 (2026-07-21 audit fix plan): OpenSearchStore.bulk_index() unit tests.

Zero-infra: a fake http.client connection object stands in for the real
socket, proving bulk_index() constructs the correct NDJSON request and
parses OpenSearch's per-item /_bulk response shape correctly (including
partial failure -- some items indexed, some errored, in one response).
The live round-trip against a REAL cluster is in
storage/test_opensearch_live.py's _test_bulk_index_round_trips (opt-in,
make test-live) -- that one proves OpenSearch itself accepts the wire
format; this one proves bulk_index()'s own request/response handling.

Run: python services/ws3-indexer/test_bulk_index.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from storage.opensearch import OpenSearchStore  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _FakeResponse:
    def __init__(self, status, body: dict):
        self.status = status
        self.reason = "OK" if status < 400 else "error"
        self._body = json.dumps(body).encode("utf-8")

    def read(self):
        return self._body


class _FakeConnection:
    """Records the request it was given; returns a pre-set response."""

    def __init__(self, response: _FakeResponse):
        self._response = response
        self.requests: list[dict] = []

    def request(self, method, path, body=None, headers=None):
        self.requests.append({"method": method, "path": path,
                              "body": body, "headers": headers})

    def getresponse(self):
        return self._response

    def close(self):
        pass


def _store_with_fake_connection(response: _FakeResponse) -> tuple[OpenSearchStore, _FakeConnection]:
    store = OpenSearchStore(url="http://fake:9200")
    fake = _FakeConnection(response)
    store._connection = lambda: fake  # patch the connection seam
    return store, fake


def test_empty_items_is_a_safe_zero_op():
    store, fake = _store_with_fake_connection(_FakeResponse(200, {"items": []}))
    result = store.bulk_index([])
    check(result == {"indexed": 0, "errors": []}, f"got {result}")
    check(fake.requests == [], "bulk_index([]) must not make any HTTP call at all")


def test_all_items_succeed():
    store, fake = _store_with_fake_connection(_FakeResponse(200, {
        "items": [
            {"index": {"_id": "a", "status": 201}},
            {"index": {"_id": "b", "status": 200}},
        ]
    }))
    result = store.bulk_index([("events-x", "a", {"n": 1}), ("events-x", "b", {"n": 2})])
    check(result["indexed"] == 2, f"got {result}")
    check(result["errors"] == [], f"got {result}")


def test_ndjson_request_body_is_action_then_doc_per_item():
    store, fake = _store_with_fake_connection(_FakeResponse(200, {"items": [
        {"index": {"_id": "a", "status": 201}},
    ]}))
    store.bulk_index([("events-x", "a", {"n": 1})])
    check(len(fake.requests) == 1, "must be exactly one HTTP call for the whole batch")
    req = fake.requests[0]
    check(req["method"] == "POST", f"got {req['method']}")
    check(req["path"] == "/_bulk", f"got {req['path']}")
    check(req["headers"]["Content-Type"] == "application/x-ndjson",
          f"got {req['headers']}")
    lines = req["body"].decode("utf-8").strip("\n").split("\n")
    check(len(lines) == 2, f"one action line + one doc line per item, got {lines}")
    action = json.loads(lines[0])
    check(action == {"index": {"_index": "events-x", "_id": "a"}}, f"got {action}")
    doc = json.loads(lines[1])
    check(doc == {"n": 1}, f"got {doc}")


def test_partial_failure_reports_both_indexed_and_errors():
    """The core correctness property: /_bulk returns 200 even when SOME
    items failed (e.g. a mapping conflict on one doc) -- indexed/errors
    must be split correctly from the per-item status codes, not treated as
    all-or-nothing."""
    store, fake = _store_with_fake_connection(_FakeResponse(200, {
        "items": [
            {"index": {"_id": "a", "status": 201}},
            {"index": {"_id": "b", "status": 400, "error": {"type": "mapper_parsing_exception"}}},
            {"index": {"_id": "c", "status": 201}},
        ]
    }))
    result = store.bulk_index([
        ("events-x", "a", {"n": 1}), ("events-x", "b", {"n": "bad"}), ("events-x", "c", {"n": 3}),
    ])
    check(result["indexed"] == 2, f"got {result}")
    check(len(result["errors"]) == 1, f"got {result}")
    check(result["errors"][0]["_id"] == "b", f"got {result['errors']}")


def test_bulk_http_level_5xx_raises():
    store, fake = _store_with_fake_connection(_FakeResponse(503, {"error": "unavailable"}))
    try:
        store.bulk_index([("events-x", "a", {"n": 1})])
        FAILS.append("a 503 at the HTTP level (not per-item) must raise, not silently return")
    except Exception as exc:  # noqa: BLE001
        check(getattr(exc, "code", None) == 503, f"expected code=503, got {exc!r}")


def main():
    test_empty_items_is_a_safe_zero_op()
    test_all_items_succeed()
    test_ndjson_request_body_is_action_then_doc_per_item()
    test_partial_failure_reports_both_indexed_and_errors()
    test_bulk_http_level_5xx_raises()

    if FAILS:
        print(f"\n[FAIL] bulk_index (P1-4): {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] bulk_index (P1-4) unit tests PASS")


if __name__ == "__main__":
    main()
