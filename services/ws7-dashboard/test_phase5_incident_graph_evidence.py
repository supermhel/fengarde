"""Phase 5 (2026-09-04) item 3: incident detail renders the typed causal DAG
and an evidence-package panel alongside -- not instead of -- the existing
member-alert list (static, no browser needed -- test_contract.py's node
--check is the syntax gate; this proves the specific shape).

Browser-verified separately this session (not re-asserted here): a real
3-node/2-edge graph rendered as an SVG with the right box/edge-label counts;
the evidence panel's three states (verified, tampered/409, unavailable) all
rendered their distinct real content with zero console errors.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAILS: list[str] = []


def check(c, m):
    if not c:
        FAILS.append(m)


def run():
    html = (HERE / "index.html").read_text(encoding="utf-8")
    tpl = (HERE / "templates" / "default.conf.template").read_text(encoding="utf-8")

    # ---- fetch functions hit the real Phase 5 routes ----
    gs = html.index("async function getIncidentGraph(incidentId){")
    ge = html.index("async function getIncidentEvidence(incidentId){")
    graph_fn = html[gs:ge]
    check("/graph" in graph_fn, "getIncidentGraph() must call GET .../graph")
    check("return null;" in graph_fn, "getIncidentGraph() must return null on failure, never fabricate")

    es = html.index("async function getIncidentEvidence(incidentId){")
    ee = html.index("function _graphLayers(")
    evidence_fn = html[es:ee]
    check("/evidence" in evidence_fn, "getIncidentEvidence() must call GET .../evidence")
    check('r.status === 409' in evidence_fn,
          "getIncidentEvidence() must specifically handle the route's documented 409 "
          "(verification failure), not just treat it as a generic non-2xx failure")
    check("_verification_failed" in evidence_fn,
          "a 409 must be surfaced as a distinct state, not silently merged with 'unavailable'")

    # ---- the layout is a real DAG layering, not force-directed / a library ----
    check("function _graphLayers(" in html, "must have a real layering function")
    check("marker-end=\"url(#phase5arrow)\"" in html, "edges must render as directed arrows")
    for lib in ("d3.", "cytoscape", "chart.js", "vis-network"):
        check(lib not in html.lower(), f"must not pull in a chart/graph library ({lib}) -- "
              "this project's own '0 stock chart libraries' line")

    # ---- showIncident actually wires the graph + evidence UI, not just defines it ----
    ss = html.index("function showIncident(inc){")
    se = html.index("// ---- LEVEL 2: inventory ----")
    showincident_body = html[ss:se]
    check('id="incidentGraph"' in showincident_body, "showIncident() must render an incidentGraph container")
    check('id="evidencePanel"' in showincident_body, "showIncident() must render an evidencePanel container")
    check("getIncidentGraph(incidentId)" in showincident_body,
          "showIncident() must actually call getIncidentGraph() -- the wiring, not just a container div")
    check('id="evidenceBtn"' in showincident_body and "showEvidencePanel" in showincident_body,
          "showIncident() must wire a button that calls showEvidencePanel() -- evidence is on-demand, "
          "never fetched eagerly for every row in a list (build_evidence_package() does real work)")
    # the original member-alert list must still be there -- ALONGSIDE, not replaced
    check("Member alerts (" in showincident_body,
          "the existing member-alert list must stay -- roadmap item 3 says 'alongside, not instead of'")

    # ---- nginx: the new sub-path routes exist as their OWN blocks, not merged
    # into the exact-match list route (which would break /api/incidents itself) ----
    check("location /api/incidents/ {" in tpl, "must add a prefix-match block for incident sub-paths")
    check("location /api/incidents {" in tpl, "the original exact-match list route must still exist unchanged")
    check("location /api/entities/ {" in tpl, "must add a block for the entities route")
    check(r"rewrite ^/api/incidents/(.*)$ /incidents/$1 break;" in tpl,
          "the incidents sub-path rewrite must preserve the id/resource segments")
    check(r"rewrite ^/api/entities/(.*)$ /entities/$1 break;" in tpl,
          "the entities rewrite must preserve the id segment")

    if FAILS:
        print(f"[FAIL] Phase 5 item 3 (incident graph + evidence): {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] Phase 5 item 3: getIncidentGraph()/getIncidentEvidence() call the real routes "
          "with never-fabricate failure handling and distinct 409/tampered surfacing; the causal "
          "graph renders as a layered-DAG SVG (no chart library); showIncident() wires both the "
          "graph (eager) and evidence (on-demand, via a button) alongside -- not instead of -- the "
          "existing member-alert list; the nginx sub-path routes are separate blocks that don't "
          "disturb the existing exact-match list route")


if __name__ == "__main__":
    run()
