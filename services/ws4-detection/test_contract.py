"""WS-4 contract test — zero infrastructure.

Asserts:
  * the bank DB priv-esc fixture fires bank_db_priv_esc (critical) and scores >=80 -> llm,
  * the DC mass-VM-delete rule fires only after threshold within the window (stateful),
  * brute-force fires only on the 10th failed auth from one IP (stateful),
  * a benign event scores 0 -> store,
  * scored.events / alerts / ai.requests are produced through the bus.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
ROOT = SERVICES.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"

from shared.bus import Bus  # noqa: E402
from engine import load_rules  # noqa: E402
from scoring import Scorer  # noqa: E402
import main as ws4  # noqa: E402

FAILS = []


def check(c, m):
    if not c:
        FAILS.append(m)


def bank_priv_op(t=1750000000000):
    return {
        "class_uid": 6005, "category_uid": 6, "activity_id": 5, "type_uid": 600505,
        "severity_id": 4, "time": t, "status": "Success",
        "actor": {"user": {"name": "dba1"}},
        "dst_endpoint": {"hostname": "ora-core-01"},
        "siem": {"sector": "bank", "source_type": "oracle_db", "ingest_id": f"b-{t}"},
    }


def failed_auth(ip, t):
    return {
        "class_uid": 3002, "category_uid": 3, "activity_id": 4, "type_uid": 300204,
        "severity_id": 4, "time": t, "status": "Failure",
        "src_endpoint": {"ip": ip}, "actor": {"user": {"name": "jdoe"}},
        "siem": {"sector": "common", "source_type": "active_directory", "ingest_id": f"f-{ip}-{t}"},
    }


def vm_delete(user, t):
    return {
        "class_uid": 6003, "category_uid": 6, "activity_id": 4, "type_uid": 600304,
        "severity_id": 5, "time": t, "status": "Success",
        "src_endpoint": {"ip": "172.16.5.9"}, "actor": {"user": {"name": user}},
        "siem": {"sector": "datacenter", "source_type": "vmware_vsphere", "ingest_id": f"v-{t}"},
    }


def benign():
    return {
        "class_uid": 4001, "category_uid": 4, "activity_id": 7, "type_uid": 400107,
        "severity_id": 1, "time": 1750000000000, "status": "Success",
        "src_endpoint": {"ip": "10.0.0.5"},
        "siem": {"sector": "common", "source_type": "cisco_asa", "ingest_id": "ok-1"},
    }


def run():
    rules = load_rules(ROOT / "contracts" / "rules")
    check(len(rules) >= 3, f"expected >=3 rules loaded, got {len(rules)}")
    Scorer(ROOT / "contracts" / "scoring.yaml")  # constructing it validates scoring.yaml parses

    # --- bank priv-esc: single event, critical ---
    det = ws4.Detector()
    ev, matched, action = det.process(bank_priv_op())
    titles = [r.title for r in matched]
    check(any("Privileged database" in t for t in titles), f"bank rule did not fire: {titles}")
    check(ev["siem"]["score"] >= 80, f"bank score {ev['siem']['score']} < 80")
    check(action == "llm", f"bank action {action} != llm")

    # --- benign: no match, store ---
    det2 = ws4.Detector()
    ev2, matched2, action2 = det2.process(benign())
    check(matched2 == [], "benign event should not match")
    check(ev2["siem"]["score"] == 0, f"benign score {ev2['siem']['score']} != 0")
    check(action2 == "store", f"benign action {action2} != store")

    # --- brute force: stateful, fires on the 10th ---
    det3 = ws4.Detector()
    fired = None
    for i in range(10):
        _, m, _ = det3.process(failed_auth("203.0.113.5", 1750000000000 + i * 1000))
        if any("brute-force" in r.title for r in m):
            fired = i
            break
    check(fired == 9, f"brute-force fired at attempt {None if fired is None else fired+1}, expected 10th")

    # --- mass VM delete: stateful, fires on 5th within 120s ---
    det4 = ws4.Detector()
    fired_vm = None
    for i in range(5):
        _, m, _ = det4.process(vm_delete("svc_orchestrator", 1750000000000 + i * 1000))
        if any("Mass VM" in r.title for r in m):
            fired_vm = i
            break
    check(fired_vm == 4, f"mass-vm-delete fired at {None if fired_vm is None else fired_vm+1}, expected 5th")

    # --- full bus loop produces scored.events + alerts + ai.requests ---
    bus = Bus()
    bus.produce("normalized.events", key="ora", payload=bank_priv_op())
    det5 = ws4.Detector()
    stats = ws4.run(bus, det5)
    check(stats["scored"] == 1, "expected 1 scored event")
    check(stats["alerts"] >= 1, "expected >=1 alert")
    check(stats["ai_enqueued"] == 1, "expected bank critical to enqueue to ai.requests")
    check(len(bus.drain("scored.events")) == 1, "scored.events not produced")
    check(len(bus.drain("ai.requests")) == 1, "ai.requests not produced")


def main():
    run()
    if FAILS:
        print(f"[FAIL] WS-4: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-4 contract test PASS")


if __name__ == "__main__":
    main()
