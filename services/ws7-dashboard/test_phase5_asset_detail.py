"""Phase 5 (2026-09-04) item 4: GET /assets/{mac} wired into the Inventory
drill-in (static, no browser needed -- test_contract.py's node --check is
the syntax gate; this proves the specific shape).

Browser-verified separately this session (not re-asserted here): the
fallback path (fetch fails/unreachable -> "list snapshot" badge, original
row data kept) and the success path ("live device record" badge, fresh data
replaces stale) were both exercised live in a real page load with no
console errors.
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
    interface = (HERE / "INTERFACE.md").read_text(encoding="utf-8")

    gs = html.index("async function getAsset(mac){")
    ge = html.index("async function getKeys(){")
    getasset_body = html[gs:ge]
    check("/assets/${encodeURIComponent(mac)}" in getasset_body,
          "getAsset() must call the real WS-6 /assets/{mac} contract endpoint")
    check("return null;" in getasset_body,
          "getAsset() must return null (never fabricate) on any failure")
    check("if(!r.ok) return null;" in getasset_body,
          "getAsset() must treat a non-2xx response as failure, not data "
          "(same discipline as getAssets()'s own r.ok check)")

    ss = html.index("async function showAsset(a){")
    se = html.index("function applyFilter(){")
    showasset_body = html[ss:se]
    check("_renderAssetDetail(a, undefined);" in showasset_body,
          "showAsset() must render the list snapshot immediately (no blank/loading flash)")
    check("await getAsset(a.mac);" in showasset_body,
          "showAsset() must actually call getAsset() -- this is the wiring the "
          "roadmap item asks for, not just a function existing unused")
    check("_renderAssetDetail(fresh || a, !!fresh);" in showasset_body,
          "showAsset() must fall back to the snapshot `a` when the fresh read fails, "
          "never blank the panel on a transient failure")

    check("live device record" in html and "list snapshot" in html,
          "the detail panel must visibly distinguish a live read from the list snapshot "
          "-- an analyst must be able to tell which one they're looking at")

    check("/assets/{mac}` (Phase 5, 2026-09-04) is now" in interface,
          "INTERFACE.md's stale 'dashboard doesn't currently call it' claim must be corrected")

    if FAILS:
        print(f"[FAIL] Phase 5 item 4 (asset detail live read): {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] Phase 5 item 4: getAsset() calls the real WS-6 /assets/{mac} contract "
          "endpoint with never-fabricate failure handling; showAsset() renders the list "
          "snapshot instantly then refreshes with the live read, falling back to the "
          "snapshot (never blank) on failure; the live/snapshot state is visibly "
          "distinguished; INTERFACE.md corrected")


if __name__ == "__main__":
    run()
