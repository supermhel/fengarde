"""OT inventory-diff rule firing test: new OT device on segment.

Loads the REAL rule YAML and feeds it a synthetic OCSF event shaped like
an inventory-diff worker's notification. The repo does not yet ship an
inventory_diff parser/service, so this test proves the rule's contract in
isolation, the same way `test_v04_new_rules.py` does for impossible-travel.

Run: python services/ws4-detection/test_ot_inventory_diff_rule.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "services"))

from engine import load_rules  # noqa: E402

RULES_DIR = ROOT / "contracts" / "rules"
RULE_ID = "7f8091a2-b3c4-4d53-9e6f-1a2b3c4d5e6f"
FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def rule_by_id(rules, rid):
    for r in rules:
        if r.id == rid:
            return r
    raise AssertionError(f"rule {rid} not loaded")


def _ot_event(*, source_type="inventory_diff", sector="datacenter",
              ot_sector="ot", device_type="plc", activity_id=1):
    return {
        "class_uid": 4001,
        "activity_id": activity_id,
        "time": 1_751_500_000_000,
        "src_endpoint": {"ip": "10.20.0.77", "mac": "AA:BB:CC:DD:EE:FF"},
        "siem": {
            "source_type": source_type,
            "sector": sector,
        },
        "unmapped": {
            "ot": {
                "sector": ot_sector,
                "device_type": device_type,
                "vendor": "generic-plc",
                "hostname": "plc-line4",
            }
        },
    }


def run():
    rules = load_rules(RULES_DIR)
    rule = rule_by_id(rules, RULE_ID)

    check(rule.id == RULE_ID, "loaded rule id mismatch")
    check(rule.title == "New OT device appeared on the OT inventory segment",
          "unexpected rule title")
    check(rule.level == "high", "level should be high")
    check(rule.stateful is False, "inventory-diff rule must be single-shot")
    check(rule.sector == "datacenter", "rule sector should be datacenter")
    check(rule.score_weight == 55, "score_weight should be 55")

    # A brand-new OT device inventory notification MUST fire.
    new_device = _ot_event()
    check(rule.evaluate(new_device) is True,
          "a new inventory-diff OT device event MUST fire")

    # This rule is intentionally non-stateful: a non-stateful rule matches
    # purely from event shape, so the same event matches on every evaluation.
    # The "single-shot" behavior noted in the rule description is operational
    # (fire once per new device per deployment), not a grammar constraint.
    check(rule.evaluate(new_device) is True,
          "non-stateful rule must still match the same synthetic event")

    # Missing the OT-sector marker means this isn't scoped to OT inventory.
    non_ot = _ot_event(ot_sector="it")
    check(rule.evaluate(non_ot) is False,
          "a non-OT sector inventory event must not fire")

    # A different source type (e.g. generic syslog) must not match.
    other_source = _ot_event(source_type="generic_syslog")
    check(rule.evaluate(other_source) is False,
          "a different source_type must not match")

    # A non-open network activity (activity_id 6 Traffic) must not match.
    traffic_event = _ot_event(activity_id=6)
    check(rule.evaluate(traffic_event) is False,
          "a non-Open Network Activity event must not match")

    # An empty device_type should still fire because the rule only keys on
    # source_type/sector/OT-sector and activity, not on device_type.
    empty_type = _ot_event(device_type="")
    check(rule.evaluate(empty_type) is True,
          "empty device_type should still satisfy the rule")


def main():
    run()
    if FAILS:
        print(f"[FAIL] OT inventory-diff rule: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] OT inventory-diff rule fires correctly")


if __name__ == "__main__":
    main()
