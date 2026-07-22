"""v0.5 A3 new-rule firing test: common_beaconing.yml (periodicity primitive).

Loads the REAL rule YAML and feeds it events shaped exactly as the REAL
cisco_asa parser emits ("Built outbound TCP connection" -> accept, activity
7). Proves: a REGULAR cadence fires, an IRREGULAR cadence of the same count
does not, and fewer than 3 events never fires (not enough data to judge
periodicity, never fabricated). Zero infra.

Run: python services/ws4-detection/test_v05_beaconing.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "services" / "ws2-normalization"))

from engine import load_rules  # noqa: E402
from parsers.cisco_asa import CiscoAsaParser  # noqa: E402

RULES_DIR = ROOT / "contracts" / "rules"
BEACONING_ID = "f6071829-a3b4-4c53-9d6e-7f8091a2b526"
FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def rule_by_id(rules, rid):
    for r in rules:
        if r.id == rid:
            return r
    raise AssertionError(f"rule {rid} not loaded")


def _built(i: int, base_s: int):
    line = (f"%ASA-6-302013: Built outbound TCP connection {i} for "
            f"outside:203.0.113.5/51000 (203.0.113.5/51000) to "
            f"inside:10.0.0.10/22 (10.0.0.10/22)")
    return {"raw": line, "meta": {"received_at": base_s + i, "ingest_id": f"beacon{i}"}}


def run():
    asa = CiscoAsaParser()
    base = 1_750_000_000

    rules = load_rules(RULES_DIR)
    rule = rule_by_id(rules, BEACONING_ID)
    check(rule.stateful and rule.periodicity == {"max_cv": 0.25},
          "beaconing rule should be stateful with periodicity.max_cv=0.25")

    # --- regular 60s cadence: 6 events -> should fire on the 6th ---
    fired = False
    for i in range(6):
        ev = asa.parse(_built(i, base + i * 60))
        ev["siem"]["ingest_id"] = f"reg{i}"
        fired = rule.evaluate(ev)
    check(fired is True, "6 events at a perfectly regular 60s cadence must fire")

    # --- irregular cadence: 6 events, same count, wildly uneven spacing ---
    rule2 = rule_by_id(load_rules(RULES_DIR), BEACONING_ID)
    deltas = [0, 5, 300, 12, 900, 40]  # seconds, deliberately erratic
    t = base + 100000  # different src-independent time range, same src IP though
    fired2 = False
    for i, d in enumerate(deltas):
        t += d
        ev = asa.parse(_built(100 + i, t))
        ev["siem"]["ingest_id"] = f"irr{i}"
        fired2 = rule2.evaluate(ev)
    check(fired2 is False, "6 events at an irregular cadence must NOT fire (high CV)")

    # --- fewer than 3 events: never fires, regardless of threshold ---
    rule3 = rule_by_id(load_rules(RULES_DIR), BEACONING_ID)
    ev1 = asa.parse(_built(200, base + 200000))
    ev1["siem"]["ingest_id"] = "few1"
    ev2 = asa.parse(_built(201, base + 200060))
    ev2["siem"]["ingest_id"] = "few2"
    check(rule3.evaluate(ev1) is False, "1 event must never fire")
    check(rule3.evaluate(ev2) is False,
          "2 events (1 delta, cv=None) must never fire even though count would reach 2")


def main():
    run()
    if FAILS:
        print(f"[FAIL] v0.5 beaconing: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] v0.5 A3 common_beaconing.yml: fires on REAL cisco_asa parser output "
          "at a regular cadence, does not fire on an irregular cadence of the same "
          "count, and never fires on fewer than 3 events (not enough data for cv)")


if __name__ == "__main__":
    main()
