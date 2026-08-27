"""WS-3 side of WS-8 correlation (2026-08-18): incident routing + storage.

Proves:
  - router.route() recognizes an incident doc (incident_id key), scopes it
    per-tenant like alerts, and suffixes by first_seen (not last_seen/time)
    so a re-emitted (grown) incident's day-index assignment never drifts.
  - template_for() maps incidents-* -> "incidents".
  - MemoryStore.list_incidents() round-trips and filters by tenant_id/
    entity_type/entity_value, newest-first by last_seen.
  - OpenSearchStore.list_incidents() wire format (fake transport): queries
    incidents-*, sorts by last_seen (not the alerts/events default "time").

Run: python services/ws3-indexer/test_ws8_incidents_routing.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from router import route, template_for  # noqa: E402
from storage.memory import MemoryStore  # noqa: E402
from storage.opensearch import OpenSearchStore  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _incident(incident_id, tenant="default", first_seen=0, last_seen=0, entity_type="actor",
              entity_value="alice"):
    return {"incident_id": incident_id, "tenant_id": tenant, "entity_type": entity_type,
            "entity_value": entity_value, "first_seen": first_seen, "last_seen": last_seen,
            "tactics": ["TA0001", "TA0002"], "member_alert_ids": ["a1", "a2"],
            "member_count": 2, "severity": 20, "truncated": False}


def test_route_default_tenant():
    index, doc_id = route(_incident("default:actor:alice:19700", first_seen=1000))
    check(index == "incidents-1970.01.01", f"default-tenant incident routed to {index!r}")
    check(doc_id == "default:actor:alice:19700", "doc_id must be the incident_id")
    check(template_for(index) == "incidents", "template_for must recognize incidents-*")


def test_route_scoped_tenant():
    index, _ = route(_incident("acme:actor:alice:19700", tenant="acme", first_seen=1000))
    check(index == "incidents-acme-1970.01.01",
          f"tenant-scoped incident routed to {index!r}")


def test_route_stable_across_growth_day_boundary():
    """A re-emitted incident's day-index must stay STABLE even if last_seen
    has since crossed a day boundary -- routing must key off first_seen."""
    day0_ms = 1000
    day1_ms = day0_ms + 2 * 24 * 3600 * 1000  # two days later
    first, _ = route(_incident("default:actor:alice:19700", first_seen=day0_ms, last_seen=day0_ms))
    grown, _ = route(_incident("default:actor:alice:19700", first_seen=day0_ms, last_seen=day1_ms))
    check(first == grown,
          f"same incident_id must route to the SAME index across growth: {first!r} vs {grown!r}")


def test_route_invalid_tenant_rejected():
    try:
        route(_incident("x", tenant="Not Valid!"))
        check(False, "an invalid tenant_id must raise, never be silently normalized")
    except ValueError:
        pass


def _store_incident(store, **kwargs):
    doc = _incident(**kwargs)
    index, doc_id = route(doc)
    store.index(index, doc_id, doc)


def test_memory_store_list_incidents_round_trip_and_filters():
    store = MemoryStore()
    _store_incident(store, incident_id="i1", tenant="default", entity_type="actor",
                     entity_value="alice", last_seen=200)
    _store_incident(store, incident_id="i2", tenant="default", entity_type="ip",
                     entity_value="203.0.113.5", last_seen=100)
    _store_incident(store, incident_id="i3", tenant="acme", entity_type="actor",
                     entity_value="alice", last_seen=300)

    all_default = store.list_incidents(tenant_id="default")
    check(len(all_default) == 2, f"tenant filter must exclude acme's incident: got {len(all_default)}")
    check(all_default[0]["incident_id"] == "i1",
          "newest-first by last_seen: i1 (last_seen=200) must precede i2 (last_seen=100)")

    by_entity = store.list_incidents(entity_type="ip")
    check(len(by_entity) == 1 and by_entity[0]["incident_id"] == "i2",
          "entity_type filter must isolate the ip: incident")

    by_value = store.list_incidents(entity_value="alice")
    check({d["incident_id"] for d in by_value} == {"i1", "i3"},
          "entity_value filter must match across tenants when tenant_id is not also given")


def test_opensearch_store_list_incidents_wire_format():
    calls = []

    class _FakeTransport:
        def __call__(self, method, path, body=None):
            calls.append((method, path, body))
            return {"hits": {"hits": []}}

    store = OpenSearchStore.__new__(OpenSearchStore)  # bypass __init__'s real HTTP setup
    store._request = _FakeTransport()
    store.list_incidents(tenant_id="acme", entity_type="actor", limit=10)

    check(len(calls) == 1, "list_incidents must issue exactly one search request")
    method, path, body = calls[0]
    check(path == "/incidents-*/_search", f"must search incidents-*, got {path!r}")
    check(body["sort"] == [{"last_seen": {"order": "desc", "unmapped_type": "long"}}],
          f"incidents must sort by last_seen, not the alerts/events default 'time': {body['sort']!r}")
    terms = {list(clause["term"].keys())[0]: list(clause["term"].values())[0]
             for clause in body["query"]["bool"]["must"]}
    check(terms == {"tenant_id": "acme", "entity_type": "actor"},
          f"unexpected term filters: {terms!r}")


def test_incidents_mapping_declares_entity_value_full():
    """Gap-hunt #WS3-5: ws8-correlation/correlator.py writes `entity_value_full`
    (the untruncated attacker-controlled value) onto the incident, but the
    incidents mapping is dynamic:false -- an undeclared field is SILENTLY
    dropped at index time. The mapping must declare it as keyword."""
    import json
    mapping_path = (HERE.parent.parent / "contracts" / "opensearch-mappings"
                    / "incidents.json")
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    props = mapping["template"]["mappings"]["properties"]
    check(props.get("entity_value_full") is not None
          and props["entity_value_full"].get("type") == "keyword",
          f"incidents.json (dynamic:false) must declare entity_value_full as "
          f"keyword, got {props.get('entity_value_full')!r}")

    # Every structure the WS-8 correlator emits must be declared (dynamic:false
    # silently drops anything missing). This is the field the fix added.
    check("truncated" in props and "member_alert_ids" in props
          and "tactics" in props and "severity" in props,
          "sanity: the other incident fields must still be declared")


def run_all():
    test_route_default_tenant()
    test_route_scoped_tenant()
    test_route_stable_across_growth_day_boundary()
    test_route_invalid_tenant_rejected()
    test_memory_store_list_incidents_round_trip_and_filters()
    test_opensearch_store_list_incidents_wire_format()
    test_incidents_mapping_declares_entity_value_full()


if __name__ == "__main__":
    run_all()
    if FAILS:
        print(f"[FAIL] WS-3 incidents routing: {len(FAILS)} problem(s)")
        for f in FAILS:
            print(f"  - {f}")
        sys.exit(1)
    print("[OK] WS-3 incidents routing: route()/template_for(), MemoryStore round-trip + "
          "filters, OpenSearchStore wire format (sort by last_seen, tenant-scoped index)")
