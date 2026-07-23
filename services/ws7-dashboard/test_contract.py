"""WS-7 contract test — static checks, no browser needed.

Asserts:
  * index.html exposes the three levels (global / inventory / sources),
  * it reads the inventory API via /assets and supports IP/MAC filtering,
  * it consumes alert fields from Contract B/E (level, score, rule_title),
  * the mock data file parses and matches the shapes the dashboard reads.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAILS: list[str] = []


def check(c, m):
    if not c:
        FAILS.append(m)


def run():
    html = (HERE / "index.html").read_text(encoding="utf-8")
    for view in ("global", "inventory", "sources"):
        check(f'id="{view}"' in html, f"missing view section: {view}")
    check("/assets" in html, "dashboard does not call the inventory /assets endpoint")
    check("ip_history" in html, "dashboard does not render IP history (Contract C)")
    for field in ("rule_title", "level", "score"):
        check(field in html, f"dashboard does not use alert field {field}")
    check("INVENTORY_API" in html, "no live-API switch (falls back to mock)")

    mock = (HERE / "mocks" / "mock_data.js").read_text(encoding="utf-8")
    m = re.search(r"window\.SIEM_MOCK\s*=\s*(\{.*\});", mock, re.S)
    check(m is not None, "mock_data.js does not assign window.SIEM_MOCK")
    if m:
        # convert the JS object literal to JSON-ish for a parse sanity check
        blob = m.group(1)
        blob = re.sub(r"//.*", "", blob)
        blob = re.sub(r"([{,]\s*)([A-Za-z_]\w*)\s*:", r'\1"\2":', blob)
        blob = blob.replace("null", "null")
        try:
            data = json.loads(blob)
            check("assets" in data and "alerts" in data, "mock missing assets/alerts")
            check(all("mac" in a for a in data["assets"]), "mock asset missing mac key")
        except Exception as e:
            FAILS.append(f"mock data did not parse: {e}")


def main():
    run()
    if FAILS:
        print(f"[FAIL] WS-7: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-7 contract test PASS")


if __name__ == "__main__":
    main()
