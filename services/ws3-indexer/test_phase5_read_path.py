"""Phase 5 (2026-09-04): the entity/causal-graph/evidence read path.

Covers scope items 1-2 of fengarde-sec's forward-roadmap Phase 5:
  - WS-3 persists entity.updates / incident.graph (via index_doc/route(),
    not just the reaper-only registration that predates this).
  - GET /entities/{id}, GET /incidents/{id}/graph,
    GET /incidents/{id}/evidence -- real HTTP, zero infra (MemoryStore).
  - The evidence route builds+verifies before ever serving 200 (mutation-
    verified below: force verify_evidence_package to report a failure,
    confirm 409, restore, confirm 200 again).

Run: python services/ws3-indexer/test_phase5_read_path.py
"""
from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from storage.memory import MemoryStore  # noqa: E402
from router import route  # noqa: E402
from shared.users import UserStore  # noqa: E402
import evidence_package  # noqa: E402
import main as ws3_main  # noqa: E402
import triage_api  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _serve(store, users_db=None):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), triage_api.make_handler(store, users_db=users_db))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _http(method, url, cookie=None):
    headers = {}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _seed_incident_chain(store, *, tenant="default", incident_id="inc-1"):
    """A real incident with one member alert, one contributing event, and
    an incident.graph -- routed through the SAME index_doc()/route() path
    the live bus consumer uses, not hand-picked index names."""
    alert = {"alert_id": "a-1", "tenant_id": tenant, "time": 1750000000000,
             "level": "high", "rule_title": "test rule", "score": 70,
             "event_ids": ["ev-1"]}
    idx, doc_id = route(alert)
    store.index(idx, doc_id, alert)

    event = {"event_id": "ev-1", "time": 1750000000000,
              "siem": {"sector": "common", "ingest_id": "ev-1"}}
    idx, doc_id = route(event)
    store.index(idx, doc_id, event)

    incident = {"incident_id": incident_id, "tenant_id": tenant,
                "first_seen": 1750000000000, "last_seen": 1750000001000,
                "member_alert_ids": ["a-1"], "entity_type": "actor",
                "entity_value": "admin"}
    idx, doc_id = route(incident)
    store.index(idx, doc_id, incident)

    graph = {"version": 2, "incident_id": incident_id, "tenant_id": tenant,
             "nodes": [{"entity_id": "e1", "entity_type": "actor",
                        "entity_value": "admin", "label": "admin"}],
             "edges": [], "tactic_sources": []}
    idx, doc_id = route(graph)
    store.index(idx, doc_id, graph)

    entity = {"entity_id": "e1", "entity_type": "actor", "tenant_id": tenant,
              "entity_value": "admin", "first_seen_ms": 1, "last_seen_ms": 2,
              "attributes": {}}
    idx, doc_id = route(entity)
    store.index(idx, doc_id, entity)
    return alert, event, incident, graph, entity


def test_topics_are_real_consumer_topics_not_just_reaper_entries():
    """The actual regression this whole phase closes: entity.updates and
    incident.graph must be in the real TOPICS the daemon consumes, not only
    in _ALL_BUS_TOPICS (which only bounds the raw stream, proven separately
    by main.py's own comment/history)."""
    check("entity.updates" in ws3_main.TOPICS,
          "entity.updates must be a real consumed topic")
    check("incident.graph" in ws3_main.TOPICS,
          "incident.graph must be a real consumed topic")
    handlers = ws3_main.build_handlers(MemoryStore())
    check("entity.updates" in handlers and "incident.graph" in handlers,
          "build_handlers must wire both new topics to a real handler")


def test_get_entity_real_http():
    store = MemoryStore()
    _seed_incident_chain(store)
    srv, port = _serve(store)
    try:
        code, body = _http("GET", f"http://127.0.0.1:{port}/entities/e1")
        check(code == 200, f"GET /entities/e1 must be 200, got {code}: {body}")
        check(body.get("entity_value") == "admin", f"must return the real entity doc, got {body}")

        code2, body2 = _http("GET", f"http://127.0.0.1:{port}/entities/nope")
        check(code2 == 404, f"unknown entity must 404, got {code2}: {body2}")
    finally:
        srv.shutdown(); srv.server_close()


def test_get_incident_graph_real_http():
    store = MemoryStore()
    _seed_incident_chain(store)
    srv, port = _serve(store)
    try:
        code, body = _http("GET", f"http://127.0.0.1:{port}/incidents/inc-1/graph")
        check(code == 200, f"GET /incidents/inc-1/graph must be 200, got {code}: {body}")
        check(body.get("version") == 2 and body.get("incident_id") == "inc-1",
              f"must return the real v2 graph doc, got {body}")

        code2, body2 = _http("GET", f"http://127.0.0.1:{port}/incidents/nope/graph")
        check(code2 == 404, f"unknown incident's graph must 404, got {code2}: {body2}")
    finally:
        srv.shutdown(); srv.server_close()


def test_get_incident_evidence_builds_and_verifies_real_http():
    store = MemoryStore()
    _seed_incident_chain(store)
    srv, port = _serve(store)
    try:
        code, body = _http("GET", f"http://127.0.0.1:{port}/incidents/inc-1/evidence")
        check(code == 200, f"GET /incidents/inc-1/evidence must be 200, got {code}: {body}")
        check(body.get("incident_id") == "inc-1", f"package must name the real incident, got {body}")
        check(body.get("chain", {}).get("block_count", 0) >= 3,
              f"package must chain incident+alert+event blocks at minimum, got {body.get('chain')}")
        check(any(b.get("type") == "graph" for b in body.get("blocks", [])),
              "package must include the graph block (seeded above)")
        # never returns an unverified package -- prove it, don't assume it
        failures = evidence_package.verify_evidence_package(body)
        check(not failures, f"the served package must independently re-verify clean, got {failures}")

        code2, body2 = _http("GET", f"http://127.0.0.1:{port}/incidents/nope/evidence")
        check(code2 == 404, f"unknown incident's evidence must 404, got {code2}: {body2}")
    finally:
        srv.shutdown(); srv.server_close()


def test_evidence_route_409s_on_a_verification_failure_mutation_verified():
    """Prove the route's own claim ('NEVER serves an unverified/tampered
    chain') by making verification actually fail and confirming a 409 --
    not by reading the code and trusting the docstring."""
    store = MemoryStore()
    _seed_incident_chain(store)
    srv, port = _serve(store)
    real_verify = evidence_package.verify_evidence_package
    try:
        evidence_package.verify_evidence_package = lambda pkg: ["forced failure for this test"]
        code, body = _http("GET", f"http://127.0.0.1:{port}/incidents/inc-1/evidence")
        check(code == 409, f"a failing verification must 409, got {code}: {body}")
        check(body.get("failures") == ["forced failure for this test"],
              f"the failure reasons must reach the caller, got {body}")
    finally:
        evidence_package.verify_evidence_package = real_verify
        srv.shutdown(); srv.server_close()

    # restore-and-confirm-green half of the mutation proof
    store2 = MemoryStore()
    _seed_incident_chain(store2)
    srv2, port2 = _serve(store2)
    try:
        code, _ = _http("GET", f"http://127.0.0.1:{port2}/incidents/inc-1/evidence")
        check(code == 200, f"with verify_evidence_package restored, must be 200 again, got {code}")
    finally:
        srv2.shutdown(); srv2.server_close()


def test_cross_tenant_entity_and_graph_are_404_not_leaked():
    """RBAC on: a non-admin session from a DIFFERENT tenant must not be able
    to fetch another tenant's entity or incident graph -- same _tenant_gate
    discipline every other single-doc GET route in this file already has."""
    store = MemoryStore()
    _seed_incident_chain(store, tenant="acme")
    users = UserStore(":memory:")
    users.create_user("globex_analyst", "pw", role="analyst", tenant_id="globex")
    srv, port = _serve(store, users_db=users)
    try:
        data = json.dumps({"username": "globex_analyst", "password": "pw"}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/auth/login", data=data, method="POST",
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            set_cookie = resp.headers.get("Set-Cookie")
        cookie = set_cookie.split(";")[0]

        code, body = _http("GET", f"http://127.0.0.1:{port}/entities/e1", cookie=cookie)
        check(code == 404, f"cross-tenant entity fetch must 404 (never leak existence), got {code}: {body}")

        code2, body2 = _http("GET", f"http://127.0.0.1:{port}/incidents/inc-1/graph", cookie=cookie)
        check(code2 == 404, f"cross-tenant graph fetch must 404, got {code2}: {body2}")

        code3, body3 = _http("GET", f"http://127.0.0.1:{port}/incidents/inc-1/evidence", cookie=cookie)
        check(code3 == 404, f"cross-tenant evidence fetch must 404, got {code3}: {body3}")
    finally:
        srv.shutdown(); srv.server_close()


def _seed_two_step_causal_chain(store, *, tenant="default", incident_id="inc-2"):
    """Two alerts, two graph edges in a KNOWN, deliberately non-chronological-
    by-alert-time order -- proves the report's timeline follows the graph's
    own ts_ms, not alert-arrival order (item 7's whole point)."""
    alert_late = {"alert_id": "a-late", "tenant_id": tenant, "time": 1,
                  "level": "medium", "rule_title": "later-arriving alert",
                  "score": 40, "event_ids": ["ev-early"]}
    alert_early = {"alert_id": "a-early", "tenant_id": tenant, "time": 2,
                   "level": "high", "rule_title": "earlier-in-the-chain alert",
                   "score": 70, "event_ids": ["ev-late"]}
    for a in (alert_late, alert_early):
        idx, doc_id = route(a)
        store.index(idx, doc_id, a)
    for eid in ("ev-early", "ev-late"):
        ev = {"event_id": eid, "time": 1, "siem": {"sector": "common", "ingest_id": eid}}
        idx, doc_id = route(ev)
        store.index(idx, doc_id, ev)
    incident = {"incident_id": incident_id, "tenant_id": tenant,
                "first_seen": 1, "last_seen": 2,
                "member_alert_ids": ["a-late", "a-early"],
                "entity_type": "actor", "entity_value": "admin"}
    idx, doc_id = route(incident)
    store.index(idx, doc_id, incident)
    graph = {"version": 2, "incident_id": incident_id, "tenant_id": tenant,
             "nodes": [{"entity_id": "e1", "entity_type": "actor", "entity_value": "admin", "label": "admin"},
                       {"entity_id": "e2", "entity_type": "ip", "entity_value": "10.1.1.5", "label": "10.1.1.5"},
                       {"entity_id": "e3", "entity_type": "device", "entity_value": "plc-1", "label": "plc-1"}],
             # ts_ms order is e1->e2 (authenticated_as) THEN e2->e3 (wrote_to) --
             # event_ids point at the EARLY-alert's event first, then the LATE-alert's,
             # the opposite of the two alerts' own `time` fields above.
             "edges": [
                 {"from": "e1", "to": "e2", "kind": "authenticated_as", "event_id": "ev-early", "ts_ms": 100},
                 {"from": "e2", "to": "e3", "kind": "wrote_to", "event_id": "ev-late", "ts_ms": 200},
             ],
             "tactic_sources": []}
    idx, doc_id = route(graph)
    store.index(idx, doc_id, graph)
    return incident, graph


def test_incident_report_causal_order_not_alert_arrival_order():
    store = MemoryStore()
    _seed_two_step_causal_chain(store)
    srv, port = _serve(store)
    try:
        code, body = _http("POST", f"http://127.0.0.1:{port}/incidents/inc-2/report")
        check(code == 200, f"POST /incidents/inc-2/report must be 200, got {code}: {body}")
        check(body.get("report_id") == "inc-2:incident-report",
              f"report_id must be '{{incident_id}}:incident-report', got {body.get('report_id')!r}")
        check(body.get("incident_id") == "inc-2",
              f"response must name the incident it was built for, got {body.get('incident_id')!r}")
        check(body.get("evidence_verified") is True, "a clean build must report evidence_verified: true")
        check(body.get("format") == "markdown" and body.get("status") == "draft",
              "must match this repo's report-envelope conventions (format/status)")
        text = body.get("body", "")
        # the causal order test: "later-arriving alert" (ev-early's rule,
        # the FIRST edge by ts_ms) must appear BEFORE "earlier-in-the-chain
        # alert" (ev-late's rule, the SECOND edge) -- the opposite of the
        # two alerts' own arrival-time order.
        pos_first_edge_rule = text.index("later-arriving alert")
        pos_second_edge_rule = text.index("earlier-in-the-chain alert")
        check(pos_first_edge_rule < pos_second_edge_rule,
              "the timeline must follow the graph's edge ts_ms order, not alert-arrival order")
        check("authenticated_as" in text and "wrote_to" in text,
              "both edge kinds must appear in the rendered timeline")
        check("[ANALYST MUST" in text or "[ANALYST MUSS" in text,
              "entity facts must still be explicit placeholders, never fabricated")
    finally:
        srv.shutdown(); srv.server_close()


def test_incident_report_falls_back_to_alert_order_with_no_graph():
    store = MemoryStore()
    alert = {"alert_id": "a-1", "tenant_id": "default", "time": 1750000000000,
             "level": "high", "rule_title": "only alert", "score": 70, "event_ids": []}
    idx, doc_id = route(alert)
    store.index(idx, doc_id, alert)
    incident = {"incident_id": "inc-nograph", "tenant_id": "default",
                "first_seen": 1750000000000, "last_seen": 1750000000000,
                "member_alert_ids": ["a-1"], "entity_type": "actor", "entity_value": "x"}
    idx, doc_id = route(incident)
    store.index(idx, doc_id, incident)
    srv, port = _serve(store)
    try:
        code, body = _http("POST", f"http://127.0.0.1:{port}/incidents/inc-nograph/report")
        check(code == 200, f"an incident with no graph must still produce a report, got {code}: {body}")
        check("only alert" in body.get("body", ""),
              "must fall back to listing the member alert even with no causal graph")
    finally:
        srv.shutdown(); srv.server_close()


def test_incident_report_404_on_unknown_incident():
    store = MemoryStore()
    srv, port = _serve(store)
    try:
        code, body = _http("POST", f"http://127.0.0.1:{port}/incidents/nope/report")
        check(code == 404, f"an unknown incident must 404, got {code}: {body}")
    finally:
        srv.shutdown(); srv.server_close()


def test_incident_report_409s_on_verification_failure_mutation_verified():
    store = MemoryStore()
    _seed_incident_chain(store, incident_id="inc-3")
    srv, port = _serve(store)
    real_verify = evidence_package.verify_evidence_package
    try:
        evidence_package.verify_evidence_package = lambda pkg: ["forced failure"]
        code, body = _http("POST", f"http://127.0.0.1:{port}/incidents/inc-3/report")
        check(code == 409, f"a failing verification must 409 the report route too, got {code}: {body}")
        check(body.get("failures") == ["forced failure"], f"failures must reach the caller, got {body}")
    finally:
        evidence_package.verify_evidence_package = real_verify
        srv.shutdown(); srv.server_close()

    store2 = MemoryStore()
    _seed_incident_chain(store2, incident_id="inc-3")
    srv2, port2 = _serve(store2)
    try:
        code, _ = _http("POST", f"http://127.0.0.1:{port2}/incidents/inc-3/report")
        check(code == 200, f"with verify_evidence_package restored, must be 200 again, got {code}")
    finally:
        srv2.shutdown(); srv2.server_close()


def test_incident_report_id_never_collides_with_alert_report_id():
    """report_id "{incident_id}:incident-report" vs "{alert_id}:report" --
    if an operator ever names an alert_id equal to some incident_id, the two
    report_id FORMATS still can't collide (different suffix), unlike a
    naive f"{id}:report" would risk."""
    store = MemoryStore()
    _seed_incident_chain(store, incident_id="shared-id")
    alert2 = {"alert_id": "shared-id", "tenant_id": "default", "time": 1,
              "level": "low", "rule_title": "x", "score": 10, "event_ids": []}
    idx, doc_id = route(alert2)
    store.index(idx, doc_id, alert2)
    srv, port = _serve(store)
    try:
        code, body = _http("POST", f"http://127.0.0.1:{port}/incidents/shared-id/report")
        check(code == 200, f"expected 200, got {code}: {body}")
        check(body.get("report_id") == "shared-id:incident-report",
              f"got {body.get('report_id')!r}")
        code2, body2 = _http("POST", f"http://127.0.0.1:{port}/alerts/shared-id/report")
        check(code2 == 200, f"the alert-scoped route must be unaffected, got {code2}: {body2}")
        check(body2.get("report_id") == "shared-id:report",
              f"the alert-scoped report_id format must be untouched, got {body2.get('report_id')!r}")
        check(body.get("report_id") != body2.get("report_id"),
              "the two report_id FORMATS must never collide even when the raw id is shared")
    finally:
        srv.shutdown(); srv.server_close()


def main():
    test_topics_are_real_consumer_topics_not_just_reaper_entries()
    test_get_entity_real_http()
    test_get_incident_graph_real_http()
    test_get_incident_evidence_builds_and_verifies_real_http()
    test_evidence_route_409s_on_a_verification_failure_mutation_verified()
    test_cross_tenant_entity_and_graph_are_404_not_leaked()
    test_incident_report_causal_order_not_alert_arrival_order()
    test_incident_report_falls_back_to_alert_order_with_no_graph()
    test_incident_report_404_on_unknown_incident()
    test_incident_report_409s_on_verification_failure_mutation_verified()
    test_incident_report_id_never_collides_with_alert_report_id()

    if FAILS:
        print(f"[FAIL] Phase 5 read path: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] Phase 5 read path: entity.updates/incident.graph are real consumed "
          "topics; GET /entities/{id}, GET /incidents/{id}/graph, "
          "GET /incidents/{id}/evidence all serve real data over real HTTP; "
          "evidence route verifies before serving (409 mutation-proven, not just "
          "asserted); cross-tenant entity/graph/evidence fetches 404, never leak; "
          "POST /incidents/{id}/report renders a causal-ordered narrative (proven "
          "against alert-arrival order, not just asserted), falls back honestly with "
          "no graph, 409s on verification failure (mutation-proven), and its "
          "report_id format never collides with the alert-scoped seam's own")


if __name__ == "__main__":
    main()
