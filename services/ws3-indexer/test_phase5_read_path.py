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


def main():
    test_topics_are_real_consumer_topics_not_just_reaper_entries()
    test_get_entity_real_http()
    test_get_incident_graph_real_http()
    test_get_incident_evidence_builds_and_verifies_real_http()
    test_evidence_route_409s_on_a_verification_failure_mutation_verified()
    test_cross_tenant_entity_and_graph_are_404_not_leaked()

    if FAILS:
        print(f"[FAIL] Phase 5 read path: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] Phase 5 read path: entity.updates/incident.graph are real consumed "
          "topics; GET /entities/{id}, GET /incidents/{id}/graph, "
          "GET /incidents/{id}/evidence all serve real data over real HTTP; "
          "evidence route verifies before serving (409 mutation-proven, not just "
          "asserted); cross-tenant entity/graph/evidence fetches 404, never leak")


if __name__ == "__main__":
    main()
