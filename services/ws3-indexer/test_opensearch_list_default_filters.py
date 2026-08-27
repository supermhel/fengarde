"""Gap-hunt (2026-08-27) read-plane #WS3-1: OpenSearchStore.list_events and
list_incidents must apply the same default-tenant default_filters fix that
list_alerts already had.

MemoryStore materializes the default tenant for a doc whose tenant field is
absent ((d.get("tenant_id") or "default") / ((d.get("siem") or {}).get("tenant")
or "default")); OpenSearch may STORE it absent, so a bare
{"term": {"tenant_id": "default"}} query would match nothing. The _list()
default_filters machinery emits a bool-should clause that matches docs
carrying the explicit value OR docs that never set the field.

These are wire-format tests against a fake transport (no live cluster needed
-- matches test_ws8_incidents_routing.py's pattern).

Run: python services/ws3-indexer/test_opensearch_list_default_filters.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from storage.opensearch import OpenSearchStore  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _FakeTransport:
    def __init__(self):
        self.calls = []

    def __call__(self, method, path, body=None):
        self.calls.append((method, path, body))
        return {"hits": {"hits": []}}


def _make_store():
    store = OpenSearchStore.__new__(OpenSearchStore)  # bypass __init__'s real HTTP setup
    store._request = _FakeTransport()
    return store


def _must_clauses(store):
    return store._request.calls[0][2]["query"]["bool"]["must"]


def _expects_default_should_clause(term_field, store):
    """True if some must-clause for `term_field` is the default-filter
    bool-should: {should: [{term: {f: v}}, {bool: {must_not: [{exists: {f}}]}}]}
    -- the MemoryStore-equivalent fallback for docs that never set the field."""
    for clause in _must_clauses(store):
        should = (clause.get("bool") or {}).get("should", [])
        if len(should) != 2:
            continue
        has_term = any(isinstance(s, dict) and term_field in s.get("term", {})
                       for s in should)
        has_must_not_exists = any(
            (s.get("bool") or {}).get("must_not")
            and any((e or {}).get("exists", {}).get("field") == term_field
                    for e in s["bool"]["must_not"])
            for s in should)
        if has_term and has_must_not_exists:
            return True
    return False


def test_list_incidents_default_tenant_gets_should_clause():
    store = _make_store()
    store.list_incidents(tenant_id="default", limit=10)
    check(len(store._request.calls) == 1, "list_incidents must issue one search")
    check(store._request.calls[0][1] == "/incidents-*/_search", "must search incidents-*")
    check(_expects_default_should_clause("tenant_id", store),
          "tenant_id=default must emit bool-should(term | must_not exists tenant_id) "
          "-- docs stored WITHOUT tenant_id must still match")


def test_list_events_default_tenant_gets_should_clause():
    store = _make_store()
    store.list_events(tenant_id="default", limit=10)
    check(len(store._request.calls) == 1, "list_events must issue one search")
    check(store._request.calls[0][1] == "/events-*/_search", "must search events-*")
    check(_expects_default_should_clause("siem.tenant", store),
          "events tenant_id=default must emit bool-should(term | must_not exists siem.tenant)")


def test_list_events_scoped_tenant_uses_plain_term():
    """A NON-default tenant must stay a plain term (no exists fallback -- an
    event without siem.tenant is not a scoped-tenant event)."""
    store = _make_store()
    store.list_events(tenant_id="acme", limit=10)
    clauses = _must_clauses(store)
    check(len(clauses) == 1, f"expected one filter clause, got {clauses}")
    check(clauses[0] == {"term": {"siem.tenant": "acme"}},
          f"a scoped tenant must be a plain term, got {clauses[0]}")


def test_list_alerts_still_has_default_filters():
    """Sanity: list_alerts keeps its existing default tenant + triage.status
    should-clauses (the read-plane fix must not regress it)."""
    store = _make_store()
    store.list_alerts(tenant_id="default", limit=10)
    check(_expects_default_should_clause("tenant_id", store),
          "list_alerts must still emit the default-tenant should-clause")


def main():
    test_list_incidents_default_tenant_gets_should_clause()
    test_list_events_default_tenant_gets_should_clause()
    test_list_events_scoped_tenant_uses_plain_term()
    test_list_alerts_still_has_default_filters()

    if FAILS:
        print(f"[FAIL] OpenSearch read-plane default filters: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] read-plane #WS3-1: list_incidents/list_events emit the default-tenant "
          "bool-should should-clause (parity with list_alerts); scoped tenants stay plain terms")


if __name__ == "__main__":
    main()