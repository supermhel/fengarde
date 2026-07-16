"""WS-3 contract test — zero infrastructure (MemoryStore).

Asserts:
  * the three OCSF fixtures route to events-bank-*, events-dc-*, events-common-*,
  * an alert routes to alerts-*,
  * re-indexing the same ingest_id is idempotent (count stays 1),
  * template_for() picks the right Contract E template.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
ROOT = SERVICES.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from router import route, template_for  # noqa: E402
from storage.memory import MemoryStore  # noqa: E402

FAILS = []


def check(c, m):
    if not c:
        FAILS.append(m)


def load_fixture(name):
    return json.loads((ROOT / "fixtures" / name).read_text())


def run():
    store = MemoryStore()

    cases = [
        ("bank_auth_valid.json", "events-bank-", "events-bank"),
        ("dc_api_valid.json", "events-dc-", "events-dc"),
        ("common_net_valid.json", "events-common-", "events-common"),
    ]
    for fname, prefix, tmpl in cases:
        doc = load_fixture(fname)
        index, doc_id = route(doc)
        check(index.startswith(prefix), f"{fname}: routed to {index}, expected {prefix}*")
        check(template_for(index) == tmpl, f"{fname}: template {template_for(index)} != {tmpl}")
        created = store.index(index, doc_id, doc)
        check(created, f"{fname}: first index should be new")

    # alert routing
    alert = {"alert_id": "a-1", "time": 1750000000000, "level": "high", "sector": "bank"}
    aidx, aid = route(alert)
    check(aidx.startswith("alerts-"), f"alert routed to {aidx}")
    store.index(aidx, aid, alert)
    check(template_for(aidx) == "alerts", "alert template mismatch")

    # idempotency: re-index the bank fixture
    doc = load_fixture("bank_auth_valid.json")
    index, doc_id = route(doc)
    before = store.count(index)
    created_again = store.index(index, doc_id, doc)
    after = store.count(index)
    check(not created_again, "duplicate ingest_id should not be 'created'")
    check(before == after, f"idempotency broken: count {before} -> {after}")


def main():
    run()
    if FAILS:
        print(f"[FAIL] WS-3: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-3 contract test PASS")


if __name__ == "__main__":
    main()
