"""Design-C (2026-07-29 audit): list_alerts()'s actor/src_ip filters --
the manual cross-alert correlation query (see storage/opensearch.py's
list_alerts docstring and SSOT.md for why this is scoped down from a full
correlation engine).

Proves the OpenSearchStore wire format (fake transport, no live cluster):
actor/src_ip become term filters in the query DSL, composing correctly with
tenant_id/status, and are omitted from the query entirely when not
requested (so an unfiltered call's query shape is unchanged from before this
field existed).

Run: python services/ws3-indexer/test_list_alerts_correlation.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from storage.opensearch import OpenSearchStore  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _FakeTransport:
    def __init__(self, response):
        self.response = response
        self.calls: list[tuple[str, str, dict | None]] = []

    def __call__(self, method, path, body=None):
        self.calls.append((method, path, body))
        return self.response


def _empty_hits():
    return {"hits": {"hits": []}}


def test_actor_and_src_ip_become_term_filters():
    store = OpenSearchStore(url="http://fake:9200")
    fake = _FakeTransport(_empty_hits())
    store._request = fake

    store.list_alerts(tenant_id="acme", actor="jdoe", src_ip="203.0.113.5", limit=25)
    _, path, body = fake.calls[0]
    check(path == "/alerts-*/_search", f"must search the alerts-* pattern, got {path}")
    must = body["query"]["bool"]["must"]
    check({"term": {"tenant_id": "acme"}} in must, f"tenant_id filter missing: {must}")
    check({"term": {"actor.user.name": "jdoe"}} in must, f"actor filter missing: {must}")
    check({"term": {"src_endpoint.ip": "203.0.113.5"}} in must, f"src_ip filter missing: {must}")
    check(body["size"] == 25, f"limit must pass through as size, got {body['size']}")


def test_actor_and_src_ip_omitted_when_not_requested():
    """An unfiltered call's query shape must be unchanged from before this
    field existed -- no stray {"term": {"actor.user.name": None}} garbage."""
    store = OpenSearchStore(url="http://fake:9200")
    fake = _FakeTransport(_empty_hits())
    store._request = fake

    store.list_alerts(tenant_id="acme", limit=10)
    _, _, body = fake.calls[0]
    must = body["query"]["bool"]["must"]
    check(len(must) == 1 and must[0] == {"term": {"tenant_id": "acme"}},
          f"unfiltered actor/src_ip must not appear in the query at all, got {must}")


def test_status_and_actor_compose():
    store = OpenSearchStore(url="http://fake:9200")
    fake = _FakeTransport(_empty_hits())
    store._request = fake

    store.list_alerts(status="closed", actor="jdoe")
    _, _, body = fake.calls[0]
    must = body["query"]["bool"]["must"]
    check({"term": {"triage.status": "closed"}} in must, f"status filter missing: {must}")
    check({"term": {"actor.user.name": "jdoe"}} in must, f"actor filter missing: {must}")


def main():
    test_actor_and_src_ip_become_term_filters()
    test_actor_and_src_ip_omitted_when_not_requested()
    test_status_and_actor_compose()
    if FAILS:
        print(f"[FAIL] list_alerts correlation filters: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] Design-C: list_alerts() actor/src_ip term filters wire-format correct, "
          "compose with tenant_id/status, omitted when not requested")


if __name__ == "__main__":
    main()
