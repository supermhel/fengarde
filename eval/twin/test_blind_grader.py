"""P4: the technique-level blind-oracle grader -- positive and negative controls.

Run: python eval/twin/test_blind_grader.py
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

TWIN = Path(__file__).resolve().parent
sys.path.insert(0, str(TWIN))

import blind_grader as bg  # noqa: E402

FAILS: list = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        FAILS.append(name)


def main() -> int:
    res = bg.run()
    again = bg.run()
    check("deterministic: two runs give the identical register", res == again)
    g = res["phishing_bec"]
    rows = {r["step"]: r for r in g["rows"]}
    check("every committed step is graded", g["steps"] == 8, str(g["steps"]))
    check("the benign victim session is CONTEXT on both sides (not a gap disagreement)",
          rows["victim_session"]["verdict"] == "agree" and rows["victim_session"]["committed_class"] == "context")
    check("user_execution is the recorded disagreement: blind says detectable, the product has no rule",
          rows["user_execution"]["verdict"] == "disagree" and "user_execution" in g["open_disagreements"])
    check("owner decisions are read from the file (Q15 on c2_beacon), absent rows read OPEN",
          rows["c2_beacon"]["owner_decision"].startswith("Q15") and rows["user_execution"]["owner_decision"] == "OPEN")
    check("technique parent match: T1071 (rule) vs T1071.001 (blind)", rows["c2_beacon"]["technique"] == "parent")

    # NEGATIVE controls on the pure function
    import scenario_registry as reg  # noqa: PLC0415
    import yaml  # noqa: PLC0415
    blind = yaml.safe_load((bg.ROOT / bg.BLIND_ORACLES["phishing_bec"]).read_text(encoding="utf-8"))
    committed = reg.load_oracle(reg.get("phishing_bec"))
    tech = bg._rule_techniques()
    flipped = copy.deepcopy(blind)
    flipped["detection_points"]["proxy_pool_logins"]["gap"] = True
    flipped["detection_points"]["proxy_pool_logins"]["detectable_in_principle"] = False
    r = {x["step"]: x for x in bg.grade(flipped, committed, tech)["rows"]}
    check("NEGATIVE: a blind gap flag flipped on a detected step becomes a disagreement",
          r["proxy_pool_logins"]["verdict"] == "disagree")
    other = copy.deepcopy(blind)
    other["detection_points"]["foreign_login"]["attack_technique"] = "T1059"
    r = {x["step"]: x for x in bg.grade(other, committed, tech)["rows"]}
    check("NEGATIVE: a different technique family is a disagreement even when the class agrees",
          r["foreign_login"]["verdict"] == "disagree" and r["foreign_login"]["technique"] == "differ")
    missing = copy.deepcopy(blind)
    del missing["detection_points"]["inbox_rule"]
    r = {x["step"]: x for x in bg.grade(missing, committed, tech)["rows"]}
    check("NEGATIVE: a step absent on one side is a disagreement, never skipped",
          r["inbox_rule"]["verdict"] == "disagree")
    check("technique_match table", (bg.technique_match({"T1110.004"}, {"T1110.003", "T1110.004"}),
                                   bg.technique_match({"T1110"}, {"T1110.004"}),
                                   bg.technique_match(set(), {"T1"})) == ("exact", "parent", "n/a"))
    if FAILS:
        print(f"[FAIL] {len(FAILS)} check(s) failed")
        return 1
    print("[OK] blind grader: technique-level register, owner-decision column, controls go red")
    return 0


if __name__ == "__main__":
    sys.exit(main())
