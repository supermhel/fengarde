"""The 10s poll refresh must not reset an open incident (static, no browser
needed -- test_contract.py's node --check is the syntax gate; this proves the
specific shape).

Bug: the setInterval at the end of index.html re-runs renderIncidents(),
which ended in showIncident(sorted[0]) -- so an analyst who opened an
incident and clicked "Build + verify" saw #evidencePanel reset to "Not
requested yet." (and #incidentGraph blank back to "Loading...") within
POLL_INTERVAL_MS, and was bounced back to the newest incident.

Fix shape asserted here: renderIncidents() re-selects _selectedIncidentId;
showIncident() skips the rebuild when the incident's data signature is
unchanged and the pane is still mounted; a changed signature (new
members / last_seen / severity ...) still rebuilds, since a built evidence
package would then be stale.
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

    # ---- the poll really does re-run renderIncidents() (the premise) ----
    poll = html[html.rindex("setInterval(() => {"):]
    check("renderIncidents()" in poll, "premise: the poll interval must still call renderIncidents()")

    # ---- renderIncidents() keeps the selected incident, not always sorted[0] ----
    rs = html.index("async function renderIncidents(){")
    re_ = html.index("// ---- Phase 5 (2026-09-04): causal graph")
    render_body = html[rs:re_]
    check("_selectedIncidentId" in render_body,
          "renderIncidents() must consult _selectedIncidentId so a refresh keeps the open incident")
    check("find(i => i.incident_id === _selectedIncidentId)" in render_body,
          "renderIncidents() must look the selected incident up by incident_id in the refreshed list")
    check("|| sorted[0]" in render_body,
          "renderIncidents() must still fall back to the newest incident (first render / selection aged out)")
    check("showIncident(sorted[0]);" not in render_body,
          "renderIncidents() must not unconditionally re-show sorted[0] -- that is the reset bug")

    # ---- showIncident() skips the rebuild on an unchanged, still-mounted pane ----
    ss = html.index("function showIncident(inc){")
    se = html.index("// ---- LEVEL 2: inventory ----")
    show_body = html[ss:se]
    guard = show_body.split("detail.innerHTML = `", 1)[0]  # everything before the first rebuild
    check("_incidentSig(inc)" in guard and "_shownIncidentSig" in guard,
          "showIncident() must compare a data signature against the one the pane was built from")
    check('document.getElementById("evidencePanel")' in guard,
          "the skip must also require the pane to still be mounted (#evidencePanel present)")
    check("return;" in guard.split("_shownIncidentSig = sig;")[0],
          "an unchanged incident must early-return BEFORE detail.innerHTML is rebuilt")
    check("_shownIncidentSig = sig;" in guard,
          "a rebuild must record the new signature, so the next poll can tell 'unchanged' from 'changed'")
    check("_shownIncidentSig = null" in guard,
          "clearing the pane (showIncident(null)) must reset the signature")

    # ---- the signature covers the fields that make a built package stale ----
    ssig = html.index("function _incidentSig(inc){")
    sig_body = html[ssig:html.index("async function getIncidentGraph")]
    for field in ("incident_id", "last_seen", "member_count", "severity", "member_alert_ids"):
        check(f"inc.{field}" in sig_body, f"_incidentSig() must include {field} -- a change there must rebuild")

    # ---- a graph that hadn't loaded is retried on refresh, without a rebuild ----
    check('_graphState === "empty"' in guard and "loadIncidentGraph(" in guard,
          "an unchanged refresh must retry a graph that came back empty, without rebuilding the pane")
    check("function loadIncidentGraph(" in show_body,
          "graph loading must be its own function so the refresh path can re-run it alone")
    check("incidentId !== _selectedIncidentId" in show_body.split("function loadIncidentGraph(")[1],
          "the stale-fetch guard (Phase 5 review-fix) must survive the refactor")

    if FAILS:
        print(f"[FAIL] incident poll-refresh keeps selection: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] incident poll refresh: renderIncidents() re-selects the open incident by id; "
          "showIncident() skips the rebuild when the incident's data signature is unchanged and "
          "the pane is mounted (so a built evidence package/graph survives the 10s poll), still "
          "rebuilds when members/last_seen/severity change, and retries an empty graph in place")


if __name__ == "__main__":
    run()
