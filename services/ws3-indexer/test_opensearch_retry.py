"""P1.3: OpenSearchStore.index() retries transient failures, surfaces permanent.

A brief OpenSearch outage (connection refused / 5xx) must be absorbed inside one
bus delivery via bounded retry, so a transient blip doesn't silently bleed events
into the dead-letter topic. A permanent 4xx (bad mapping/document) must NOT be
retried -- it can only ever fail.

Run: C:/Python313/python.exe services/ws3-indexer/test_opensearch_retry.py
"""
from __future__ import annotations

import sys
import urllib.error
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from storage import opensearch  # noqa: E402
from storage.opensearch import OpenSearchStore  # noqa: E402

opensearch.time.sleep = lambda *_a, **_k: None  # no real backoff waits in tests

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _url_error():
    return urllib.error.URLError("connection refused")


def _http_error(code):
    return urllib.error.HTTPError("http://x", code, "boom", None, None)


class _FlakyStore(OpenSearchStore):
    """Overrides _request to fail `fails` times with `exc`, then succeed."""
    def __init__(self, fails, exc):
        super().__init__(url="http://fake:9200")
        self._left = fails
        self._exc = exc
        self.calls = 0

    def _request(self, method, path, body=None):
        self.calls += 1
        if self._left > 0:
            self._left -= 1
            raise self._exc
        return {"result": "created"}


def run():
    # transient URLError twice, then success -> index() returns True after 3 calls
    s = _FlakyStore(2, _url_error())
    check(s.index("events", "id1", {"x": 1}) is True, "transient URLError should retry to success")
    check(s.calls == 3, f"expected 3 attempts, got {s.calls}")

    # transient 5xx twice, then success
    s2 = _FlakyStore(2, _http_error(503))
    check(s2.index("events", "id2", {"x": 1}) is True, "transient 503 should retry to success")

    # permanent 4xx -> raised immediately, NOT retried
    s3 = _FlakyStore(99, _http_error(400))
    try:
        s3.index("events", "id3", {"x": 1})
        FAILS.append("permanent 400 must raise, not silently pass")
    except urllib.error.HTTPError:
        check(s3.calls == 1, f"400 must not be retried, got {s3.calls} calls")

    # exhausted transient -> raises after _INDEX_RETRIES attempts (message stays
    # unacked -> redelivered by the runner, not silently dropped)
    s4 = _FlakyStore(99, _url_error())
    try:
        s4.index("events", "id4", {"x": 1})
        FAILS.append("exhausted transient must raise")
    except urllib.error.URLError:
        check(s4.calls == opensearch._INDEX_RETRIES,
              f"expected {opensearch._INDEX_RETRIES} attempts, got {s4.calls}")


def main():
    run()
    if FAILS:
        print(f"[FAIL] opensearch retry: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] opensearch index() transient-retry / permanent-surface PASS")


if __name__ == "__main__":
    main()
