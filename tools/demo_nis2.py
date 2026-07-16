"""M5 demo: bank-DB privilege escalation -> a real alert -> a German NIS2
notification draft. Zero infra (no Docker, no Redis, no OpenSearch, no
LLM) -- same in-process pipeline-wiring style as tools/demo_e2e.py.

A single privileged database GRANT on a banking-sector host fires
contracts/rules/bank_db_priv_esc.yml (PCI-DSS access-control monitoring),
reaches the indexer as a real alert, and the NIS2 public template layer
(services/ws3-indexer/nis2_template.py) turns that alert into a
deterministic German-language NIS2/§32 BSIG notification draft --
exercising the exact code path the dashboard's "NIS2 (DE)" button and the
POST /alerts/{id}/report?template=nis2 API call use.

Run:  python tools/demo_nis2.py
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
os.environ["BUS_BACKEND"] = "memory"

sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(SERVICES / "ws3-indexer"))
from shared.bus import Bus  # noqa: E402

RULE_TITLE = "Privileged database operation outside maintenance window"


def _import(ws_dir, mod="main"):
    """Import a service module with its own dir winning on sys.path (mirrors
    tools/demo_e2e.py -- several services share module names like `main`)."""
    p = str(SERVICES / ws_dir)
    while p in sys.path:
        sys.path.remove(p)
    sys.path.insert(0, p)
    return importlib.import_module(mod)


def db_grant_event() -> dict:
    """The exact shape services/ws2-normalization/parsers/test_db_audit.py
    proves fires bank_db_priv_esc.yml: class 6005, activity_id 5, sector
    bank (a privileged GRANT on a banking database, outside any allowlisted
    maintenance window)."""
    return {
        "source_type": "db_audit",
        "raw": {
            "operation": "GRANT", "object": "customers", "user": "dba_svc",
            "host": "db-prod-01", "ipAddress": "10.4.4.9", "timestamp": 1752000100000,
        },
        "meta": {"ingest_id": "db-grant-demo-1"},
    }


def _fresh(*mods):
    for m in mods:
        sys.modules.pop(m, None)


def main() -> None:
    fails: list[str] = []
    bus = Bus()

    print("# A privileged GRANT on a banking database (host=db-prod-01, user=dba_svc)")
    print("# fires contracts/rules/bank_db_priv_esc.yml -- zero infra, in-process.\n")

    bus.produce("raw.events", key="10.4.4.9", payload=db_grant_event())

    _fresh("main", "parsers")
    ws2 = _import("ws2-normalization")
    c2 = ws2.run(bus)

    _fresh("main", "engine", "scoring", "tenants", "plugins")
    ws4 = _import("ws4-detection")
    det = ws4.Detector()
    c4 = ws4.run(bus, det)

    _fresh("main", "router")
    ws3 = _import("ws3-indexer")
    store = ws3.make_store()
    c3 = ws3.run(bus, store)

    print(f"WS-2 normalized={c2['normalized']} dropped={c2['dropped']}")
    print(f"WS-4 scored={c4['scored']} alerts={c4['alerts']}")
    print(f"WS-3 indexed={c3['indexed']} dup={c3['duplicates']} unroutable={c3['unroutable']}")

    alert_indices = [i for i in store.indices() if i.startswith("alerts-")]
    priv_alerts = [d for idx in alert_indices for d in store.all_docs(idx)
                   if d.get("rule_title") == RULE_TITLE]
    if not priv_alerts:
        fails.append("no bank_db_priv_esc alert reached the alerts-* index")
        print("\n[FAIL] demo nis2:", *fails, sep="\n  - ")
        sys.exit(1)

    alert = priv_alerts[0]
    print(f"\n  ALERT: {alert.get('rule_title')} host=db-prod-01 user=dba_svc "
          f"score={alert.get('score')} id={alert.get('alert_id')}")

    import nis2_template  # noqa: E402
    triage = {"status": "new", "note": ""}
    report = nis2_template.build_report(alert, triage, stage="notification", lang="de")

    print("\n" + "=" * 70)
    print(report["body"])
    print("=" * 70 + "\n")

    if report["status"] != "draft":
        fails.append(f"NIS2 report status must be draft, got {report['status']!r}")
    if "DORA" not in report["body"]:
        fails.append("NIS2 report must carry the NIS2-vs-DORA scope caveat")
    if RULE_TITLE not in report["body"]:
        fails.append("NIS2 report must reflect the triggering rule's title")
    if not report["citations"]:
        fails.append("NIS2 report must cite its public sources")

    if fails:
        print("[FAIL] demo nis2:", *fails, sep="\n  - ")
        sys.exit(1)
    print("[OK] FENGARDE M5: bank-DB privilege escalation -> real alert -> "
          "German NIS2 notification draft. Zero infra, zero manual steps.")


if __name__ == "__main__":
    main()
