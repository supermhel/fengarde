"""F3 (adversarial repo-wide bug hunt, 2026-07-16) — tenant_id validation
in router.py's index-name construction.

Before this fix, `tenant` flowed straight from `doc.get("tenant_id")` /
`siem.get("tenant")` into f"alerts-{tenant}-..." / f"events-{family}-{tenant}-..."
with no validation. An uppercase or space-containing tenant_id (e.g. an MSP
onboarding "Acme" or "ACME Corp") produces an OpenSearch-INVALID index name;
OpenSearchStore.index() treats the resulting 4xx as permanent, so the
document is silently dead-lettered -- that tenant gets zero detections.
This asserts route() now rejects (never normalizes) a malformed tenant_id
loudly, at the point of use, and that valid tenants (including the
"default" sentinel) are unaffected.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from router import route  # noqa: E402

FAILS: list[str] = []


def check(c, m):
    if not c:
        FAILS.append(m)


def _raises_value_error(doc: dict) -> bool:
    try:
        route(doc)
    except ValueError:
        return True
    return False


def test_invalid_tenant_rejected_on_alert_branch():
    # Note: "" is deliberately excluded -- `doc.get("tenant_id") or DEFAULT_TENANT`
    # treats an empty string the same as absent, falling through to "default"
    # (the same "missing -> default" convention documented across the codebase),
    # not a value _validated_tenant ever sees.
    for bad in ("Acme", "ACME Corp", "has space", "UPPER", "-leading-hyphen", "trailing-hyphen-"):
        alert = {"alert_id": "a-1", "time": 1750000000000, "level": "high", "tenant_id": bad}
        check(_raises_value_error(alert), f"alert with tenant_id={bad!r} should raise ValueError, didn't")


def test_invalid_tenant_rejected_on_event_branch():
    for bad in ("Acme", "ACME Corp", "has space", "UPPER"):
        event = {
            "siem": {"sector": "common", "tenant": bad, "ingest_id": "i-1"},
            "time": 1750000000000,
        }
        check(_raises_value_error(event), f"event with siem.tenant={bad!r} should raise ValueError, didn't")


def test_valid_tenants_still_route():
    # "default" sentinel -> unchanged pre-M4 naming, no tenant segment at all.
    alert = {"alert_id": "a-2", "time": 1750000000000, "level": "high", "tenant_id": "default"}
    index, doc_id = route(alert)
    check(index.startswith("alerts-") and "default" not in index,
          f"default-tenant alert must use pre-M4 naming, got {index}")

    # A normal lowercase-hyphenated tenant id -> tenant-scoped index.
    alert2 = {"alert_id": "a-3", "time": 1750000000000, "level": "high", "tenant_id": "acme-corp"}
    index2, doc_id2 = route(alert2)
    check(index2.startswith("alerts-acme-corp-"), f"tenant-scoped alert routed to {index2}")

    event = {
        "siem": {"sector": "bank", "tenant": "acme-corp", "ingest_id": "i-2"},
        "time": 1750000000000,
    }
    eidx, eid = route(event)
    check(eidx.startswith("events-bank-acme-corp-"), f"tenant-scoped event routed to {eidx}")

    # tenant_id/siem.tenant absent entirely -> defaults to "default", still routes.
    alert3 = {"alert_id": "a-4", "time": 1750000000000, "level": "high"}
    index3, _ = route(alert3)
    check(index3.startswith("alerts-") and "None" not in index3, f"missing tenant_id alert routed to {index3}")


def test_shape_dispatch_order_is_collision_free():
    """Review-fix (2026-09-04): route() dispatches by structural key-
    sniffing, not an explicit type discriminator -- flagged in review as
    fragile. This locks the branch order down as a tested contract: every
    current producer shape routes to its own index, AND the specific near-
    future shape review named (a flattened single graph node -- carrying
    entity_id+entity_type but none of incident.graph's other keys) is
    proven to route as an entity deliberately, not by accident. Any new
    branch added to route() must extend this test."""
    graph_v2 = {"incident_id": "inc-1", "tenant_id": "default", "version": 2,
                "nodes": [{"entity_id": "e1", "entity_type": "actor",
                           "entity_value": "admin", "label": "admin"}],
                "edges": [], "tactic_sources": {}}
    idx, doc_id = route(graph_v2)
    check(idx == "incident-graphs" and doc_id == "inc-1",
          f"a nodes+incident_id doc must route to incident-graphs, got {idx}/{doc_id}")

    entity = {"entity_id": "e1", "entity_type": "actor", "entity_value": "admin",
              "tenant_id": "default"}
    idx2, doc_id2 = route(entity)
    check(idx2 == "entities" and doc_id2 == "e1",
          f"an entity_id+entity_type doc must route to entities, got {idx2}/{doc_id2}")

    # The near-future shape review flagged: the SAME entity_id+entity_type
    # pair a graph's nodes[] carries, but as its own top-level message (no
    # "nodes", no "incident_id") -- e.g. a hypothetical per-node live-update
    # message. Must NOT collide with the incident-graph branch (it has none
    # of that branch's keys) and must land as an entity, on purpose.
    flattened_node = {"entity_id": "e1", "entity_type": "actor",
                       "entity_value": "admin", "label": "admin", "tenant_id": "default"}
    idx3, doc_id3 = route(flattened_node)
    check(idx3 == "entities" and doc_id3 == "e1",
          f"a flattened graph-node-shaped doc must route to entities (a lone "
          f"entity_id+entity_type IS entity-shaped, regardless of origin), "
          f"got {idx3}/{doc_id3}")

    incident = {"incident_id": "inc-2", "tenant_id": "default", "first_seen": 1750000000000,
                "member_alert_ids": ["a-1"]}
    idx4, doc_id4 = route(incident)
    check(idx4.startswith("incidents-") and doc_id4 == "inc-2",
          f"an incident_id-only doc (no nodes) must route to incidents, got {idx4}/{doc_id4}")

    alert = {"alert_id": "a-5", "time": 1750000000000, "level": "high", "tenant_id": "default"}
    idx5, doc_id5 = route(alert)
    check(idx5.startswith("alerts-") and doc_id5 == "a-5",
          f"an alert_id-only doc must route to alerts, got {idx5}/{doc_id5}")


def run():
    test_invalid_tenant_rejected_on_alert_branch()
    test_invalid_tenant_rejected_on_event_branch()
    test_valid_tenants_still_route()
    test_shape_dispatch_order_is_collision_free()


def main():
    run()
    if FAILS:
        print(f"[FAIL] router tenant validation: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] F3: router.route() rejects malformed tenant_id (never normalizes) on both "
          "alert and event branches; valid/default tenants route unaffected")


if __name__ == "__main__":
    main()
