"""WS-7 read-plane gap-hunt regression test (static, no browser needed).

Covers four verified findings fixed 2026-08-27:

  * R4-#65            getAlerts() no longer mutates the shared global `LIVE`
                      as a side effect; it now returns {alerts, live} and the
                      RENDER path (renderGlobal / renderMonitoring) owns the
                      global badge state.
  * read-plane #3     `live` is derived from nginx's
                      `_fengarde_proxy:"opensearch_unavailable"` outage marker
                      (default.conf.template @alerts_unavailable), NOT from
                      empty hits -- so a healthy-but-empty time range reads as
                      LIVE, never as a mock/outage state.
  * read-plane #6     the /api/config.js API-key bootstrap is served only to
                      same-origin browser subresource fetches (Sec-Fetch-Site:
                      same-origin, GET/HEAD only) as defense-in-depth against
                      non-browser key-minting clients, and the residual
                      exposure is documented loudly.
  * R4-#91            the badge/posture copy no longer claims "mock data" /
                      "mock mode" (the outage path shows an honest empty state,
                      not mock data).

Substring assertions plus a node --check syntax gate (test_contract.py) are the
static contract; this test proves the specific returns that the greps cannot.
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

    # ---- R4-#65: getAlerts() is a pure read; the render path owns LIVE ----
    gs = html.index("async function getAlerts(){")
    ge = html.index("async function getEvents(){")
    getalerts_body = html[gs:ge]
    check("LIVE = " not in getalerts_body,
          "getAlerts() still writes the shared global LIVE as a side effect (R4-#65)")
    check("return {alerts, live:true};" in getalerts_body,
          "getAlerts() no longer reports a live backend on a non-outage 200 (read-plane #3)")
    check("return {alerts:[], live:false};" in getalerts_body,
          "getAlerts() no longer returns the {alerts, live:false} outage shape")
    # render path writes LIVE (renderGlobal + renderMonitoring), not the fetch.
    check("LIVE = live;" in html,
          "renderGlobal() no longer owns LIVE, so the render path lost the badge state (R4-#65)")
    check("LIVE = f.live;" in html,
          "renderMonitoring() no longer sets LIVE from its own fetch (R4-#65)")

    # ---- read-plane #3: outage = the nginx marker, NOT empty hits ----
    check('data._fengarde_proxy === "opensearch_unavailable"' in html,
          "read-plane #3: getAlerts() does not key liveness off the nginx opensearch_unavailable marker")
    check("_fengarde_proxy" in html and "opensearch_unavailable" in html,
          "read-plane #3: the outage-marker string is not referenced in index.html")
    check("hits.length" in html,
          "read-plane #3: cannot confirm live is decoupled from hits.length")

    # ---- R4-#91: honest badge/posture copy, no "mock data"/"mock mode" ----
    check(">data unavailable<" in html,
          "R4-#91: initial status pill still shows the stale 'mock data' copy")
    check('? "live data" : "data unavailable"' in html,
          "R4-#91: renderGlobal badge still shows the stale 'mock data' copy")
    check('value: LIVE ? "connected" : "unavailable"' in html,
          "R4-#91: posture 'Live pipeline data' still shows the stale 'mock mode' copy")
    check('backend reachable":"backend unreachable"' in html,
          "R4-#91: Monitoring 'Live data' card still shows the stale '/ mock' copy")
    check('? "live data" : "mock data"' not in html,
          "R4-#91: stale renderGlobal 'mock data' badge expression still present")
    check('value: LIVE ? "connected" : "mock mode"' not in html,
          "R4-#91: stale 'mock mode' posture expression still present")
    check("backend unreachable / mock" not in html,
          "R4-#91: stale 'backend unreachable / mock' card copy still present")

    # ---- read-plane #6: config.js served only to same-origin browser fetches ----
    cfg = tpl[tpl.index("location = /api/config.js"):]
    check("$http_sec_fetch_site" in cfg,
          "read-plane #6: config.js location does not gate on Sec-Fetch-Site")
    check('$http_sec_fetch_site = "same-origin"' in cfg,
          "read-plane #6: config.js does not require Sec-Fetch-Site: same-origin")
    check("limit_except GET HEAD" in cfg,
          "read-plane #6: config.js location does not restrict to GET/HEAD")
    check("fengarde_cfg_ok" in cfg,
          "read-plane #6: config.js same-origin gate is missing the allow flag")
    check("read-plane #6" in tpl,
          "read-plane #6: the residual-exposure tradeoff is not documented loudly in the template")


def main():
    run()
    if FAILS:
        print(f"[FAIL] WS-7 read-plane regression: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-7 read-plane regression PASS")


if __name__ == "__main__":
    main()
