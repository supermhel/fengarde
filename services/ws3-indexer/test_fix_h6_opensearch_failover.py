"""FIX H6 regression: OpenSearch multi-node writer failover (2026-08-06).

A 3-node HA cluster whose writer pins to a single URL ("opensearch-1") has
*zero* write failover -- losing that node stalls all writes while cluster
health is green. FIX H6 makes OpenSearchStore accept a comma-separated node
list and rotate to the next node on a connection-level failure.

This test asserts the rotation seam (the node-switch and connection-reset
behaviour) independently of a live cluster, via a fake connection that fails
only for the first node.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "services" / "ws3-indexer"))

from storage.opensearch import OpenSearchStore  # noqa: E402

_failures = 0
_results: list[int] = []


class _FakeConnection:
    """Connection that fails to request on the FIRST host only, then succeeds."""

    def __init__(self, host, port=None, **kw):  # noqa: N803
        self._host = host
        self.closed = False

    def request(self, *a, **kw):
        global _failures
        if self._host == "node-a" and _results[0] == 0:
            _results[0] = 1
            _failures += 1
            raise ConnectionRefusedError("node-a down")
        # otherwise succeed like a healthy OpenSearch node
        self.status = 200
        self.body = b'{"hits":{"total":0}}'

    def getresponse(self):
        return self

    def read(self):
        return self.body

    def close(self):
        self.closed = True


def _check_node_rotation_to_surviving_node():
    global _failures, _results
    _failures = 0
    _results = [0]
    store = OpenSearchStore(url="http://node-a:9200,http://node-b:9200")
    # Patch the connection factory so _connection() returns our fake for the
    # CURRENT node, and record which node got used after rotation.
    def fake_conn():
        return _FakeConnection(store._host)

    store._connection = fake_conn  # type: ignore[method-assign,assignment]
    store._request("GET", "/")  # real request path: node-a fails -> rotate -> node-b
    # After node-a's connection-refused, rotation must land on node-b.
    assert store._host == "node-b", f"expected rotation to node-b, got {store._host}"
    assert _failures == 1, f"expected exactly 1 failed attempt (node-a), got {_failures}"


def main():
    try:
        _check_node_rotation_to_surviving_node()
        print("[OK] FIX H6: OpenSearchStore rotates to the surviving node on "
              "a connection-level failure (multi-node failover)")
    except AssertionError as e:
        print(f"[FAIL] FIX H6: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
