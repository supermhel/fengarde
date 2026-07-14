"""v0.3 (A3) rule grammar tests: comparison operators + allowlist (`not_in`).

Adversarial: this is a security-sensitive surface (T4 -- no eval(), rule files
are contributor-supplied). Every case here proves a malformed/edge-case
operator FAILS CLOSED (returns False) rather than raising past evaluate().

Run: C:/Python313/python.exe services/ws4-detection/test_v03_rule_grammar.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from engine import Rule, load_allowlist, Allowlist  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def make_rule(detection: dict, allowlists_dir=None) -> Rule:
    return Rule({
        "id": "t", "title": "test", "level": "high",
        "detection": detection, "siem": {"score_weight": 10},
    }, allowlists_dir=allowlists_dir)


def run():
    # --- comparison operators: correctness ---
    r = make_rule({"sel": {"score": {"gt": 60}}, "condition": "sel"})
    check(r.evaluate({"score": 61}) is True, "gt: 61 > 60 must match")
    check(r.evaluate({"score": 60}) is False, "gt: 60 > 60 must NOT match")
    check(r.evaluate({"score": 59}) is False, "gt: 59 > 60 must NOT match")

    r = make_rule({"sel": {"score": {"gte": 60}}, "condition": "sel"})
    check(r.evaluate({"score": 60}) is True, "gte: 60 >= 60 must match")

    r = make_rule({"sel": {"score": {"lt": 10}}, "condition": "sel"})
    check(r.evaluate({"score": 9}) is True, "lt: 9 < 10 must match")
    check(r.evaluate({"score": 10}) is False, "lt: 10 < 10 must NOT match")

    r = make_rule({"sel": {"score": {"lte": 10}}, "condition": "sel"})
    check(r.evaluate({"score": 10}) is True, "lte: 10 <= 10 must match")

    r = make_rule({"sel": {"score": {"ne": 0}}, "condition": "sel"})
    check(r.evaluate({"score": 5}) is True, "ne: 5 != 0 must match")
    check(r.evaluate({"score": 0}) is False, "ne: 0 != 0 must NOT match")

    # --- comparison operators: fail-closed on malformed/non-numeric input ---
    r = make_rule({"sel": {"score": {"gt": 60}}, "condition": "sel"})
    check(r.evaluate({"score": "not a number"}) is False,
          "gt against a non-numeric field must fail closed, not raise")
    check(r.evaluate({}) is False,
          "gt against a MISSING field must fail closed, not raise")
    check(r.evaluate({"score": None}) is False,
          "gt against a None field must fail closed, not raise")

    r = make_rule({"sel": {"score": {"gt": "not a number"}}, "condition": "sel"})
    check(r.evaluate({"score": 100}) is False,
          "gt with a non-numeric COMPARAND must fail closed, not raise")

    r = make_rule({"sel": {"score": {"gt": True}}, "condition": "sel"})
    check(r.evaluate({"score": 100}) is False,
          "gt with a bool comparand must fail closed (bool excluded on purpose)")

    r = make_rule({"sel": {"score": {"bogus_op": 1}}, "condition": "sel"})
    check(r.evaluate({"score": 100}) is False,
          "unknown operator must fail closed, not raise")

    r = make_rule({"sel": {"score": {}}, "condition": "sel"})
    check(r.evaluate({"score": 100}) is False,
          "empty operator dict must fail closed")

    # --- allowlist: correctness ---
    with tempfile.TemporaryDirectory() as tmp:
        allow_dir = Path(tmp)
        (allow_dir / "test_allow.yml").write_text(
            'entries:\n  - "10.0.0.0/8"\n  - "known-good-host"\n', encoding="utf-8")

        r = make_rule({"sel": {"src_endpoint.ip": {"not_in": "test_allow"}},
                      "condition": "sel"}, allowlists_dir=allow_dir)
        check(r.evaluate({"src_endpoint": {"ip": "10.1.2.3"}}) is False,
              "not_in: an IP inside the CIDR range must be SUPPRESSED (no match)")
        check(r.evaluate({"src_endpoint": {"ip": "203.0.113.5"}}) is True,
              "not_in: an IP outside the range must still match")

        r2 = make_rule({"sel": {"hostname": {"not_in": "test_allow"}},
                       "condition": "sel"}, allowlists_dir=allow_dir)
        check(r2.evaluate({"hostname": "known-good-host"}) is False,
              "not_in: exact-string allowlist entry must be SUPPRESSED")
        check(r2.evaluate({"hostname": "other-host"}) is True,
              "not_in: a non-matching string must still match")

    # --- allowlist: broken file -> suppression never triggers -> RULE STILL
    # FIRES (the safe default for a SIEM: a config bug in a suppression list
    # must never silently make monitoring go blind). "Fail closed" here means
    # the ALLOWLIST closes (never suppresses), which makes the RULE fail open
    # (still alerts) -- confirmed via engine.py's Allowlist.matches: ok=False
    # -> always returns False -> not_in's suppression branch never triggers.
    with tempfile.TemporaryDirectory() as tmp:
        empty_dir = Path(tmp)
        r = make_rule({"sel": {"src_endpoint.ip": {"not_in": "does_not_exist"}},
                      "condition": "sel"}, allowlists_dir=empty_dir)
        check(r.evaluate({"src_endpoint": {"ip": "1.2.3.4"}}) is True,
              "not_in referencing a MISSING allowlist file must NOT crash the "
              "rule, and must not silently suppress -- the rule keeps firing")

        (empty_dir / "malformed.yml").write_text("not: a valid\n- shape at all",
                                                  encoding="utf-8")
        r2 = make_rule({"sel": {"src_endpoint.ip": {"not_in": "malformed"}},
                       "condition": "sel"}, allowlists_dir=empty_dir)
        check(r2.evaluate({"src_endpoint": {"ip": "1.2.3.4"}}) is True,
              "not_in referencing a MALFORMED allowlist file must not crash "
              "and must not silently suppress")

    r = make_rule({"sel": {"src_endpoint.ip": {"not_in": 123}}, "condition": "sel"})
    check(r.evaluate({"src_endpoint": {"ip": "1.2.3.4"}}) is False,
          "not_in with a non-string allowlist NAME is a malformed selection "
          "itself -- THIS fails closed (no match at all), unlike a "
          "missing/malformed FILE which fails open. Different failure classes: "
          "a bad rule author input vs. a bad ops-owned data file.")

    # --- v0.4 (P2.1): `in` (list membership) ---
    r = make_rule({"sel": {"activity_id": {"in": [1, 3]}}, "condition": "sel"})
    check(r.evaluate({"activity_id": 1}) is True, "in: 1 in [1,3] matches")
    check(r.evaluate({"activity_id": 3}) is True, "in: 3 in [1,3] matches")
    check(r.evaluate({"activity_id": 2}) is False, "in: 2 not in [1,3]")
    check(r.evaluate({"activity_id": True}) is False,
          "in: bool True must NOT match numeric 1 (bool/int distinction)")
    check(r.evaluate({}) is False, "in: missing field fails closed")
    r = make_rule({"sel": {"x": {"in": "notalist"}}, "condition": "sel"})
    check(r.evaluate({"x": "n"}) is False, "in: non-list arg fails closed")

    # --- v0.4 (P2.1): `contains` (bounded substring, no regex) ---
    r = make_rule({"sel": {"api.operation": {"contains": "credentials."}},
                   "condition": "sel"})
    check(r.evaluate({"api": {"operation": "credentials.accessed"}}) is True,
          "contains: substring present matches")
    check(r.evaluate({"api": {"operation": "workflow.created"}}) is False,
          "contains: substring absent does not match")
    check(r.evaluate({"api": {"operation": 123}}) is False,
          "contains: non-string actual fails closed")
    r = make_rule({"sel": {"x": {"contains": ["not", "a", "string"]}}, "condition": "sel"})
    check(r.evaluate({"x": "abc"}) is False, "contains: non-string needle fails closed")

    # --- allowlist direct unit: an entry is ALWAYS exact-matchable even when
    # it's also CIDR-shaped-but-invalid (exact.add happens unconditionally in
    # Allowlist.__init__, independent of whether ip_network() parses it) ---
    al = Allowlist(["not-a-cidr-or-anything/999"], ok=True)
    check(al.matches("not-a-cidr-or-anything/999") is True,
          "an entry that fails CIDR parsing still works as an exact string match")
    check(al.matches("something-else") is False,
          "a non-matching value against the same allowlist must not match")

    # --- B1 interaction sanity: class_uid bucketing doesn't break equality still ---
    r = make_rule({"sel": {"class_uid": 3002, "score": {"gte": 50}}, "condition": "sel"})
    check(r.class_uid == 3002, "class_uid bucketing key must still be captured "
                               "when the selection has OTHER operator clauses too")
    check(r.evaluate({"class_uid": 3002, "score": 50}) is True,
          "mixed equality + operator selection must still evaluate correctly")

    # --- B1 bucketing safety (review fix): bucket only when the class is provably
    # NECESSARY for a match; anything that can fire on another class -> catch-all.
    # A multi-class OR rule must NOT be bucketed under its first class (the old
    # first-selection-wins heuristic silently skipped the second class's events).
    r = make_rule({"a": {"class_uid": 3002, "activity_id": 4},
                   "b": {"class_uid": 4001, "activity_id": 6},
                   "condition": "a or b"})
    check(r.class_uid is None, "multi-class OR rule must land in the catch-all bucket")
    check(r.evaluate({"class_uid": 4001, "activity_id": 6}) is True,
          "multi-class OR rule must fire on its SECOND class too")

    # A negated selection can match events of other classes -> catch-all.
    r = make_rule({"a": {"class_uid": 3002}, "condition": "not a"})
    check(r.class_uid is None, "'not a' can match any class; must not be bucketed")
    check(r.evaluate({"class_uid": 4001}) is True,
          "'not a' fires on a non-3002 event, so bucketing under 3002 would lose it")

    # 'a and b' where b is classless: class 3002 is still necessary -> bucketed.
    # (This is the shipped bank_db_priv_esc / dc_mass_vm_delete shape.)
    r = make_rule({"a": {"class_uid": 6005, "activity_id": 5},
                   "b": {"siem.sector": "bank"}, "condition": "a and b"})
    check(r.class_uid == 6005, "'a and b' with classless b must stay bucketed (a is required)")

    # 'a or b' where b is classless: b alone can satisfy -> catch-all.
    r = make_rule({"a": {"class_uid": 3002}, "b": {"siem.sector": "bank"},
                   "condition": "a or b"})
    check(r.class_uid is None, "'a or b' with classless b can match any class")

    # Operator-shaped class_uid ({ne: ...}) is not an equality -> catch-all.
    r = make_rule({"sel": {"class_uid": {"ne": 3002}}, "condition": "sel"})
    check(r.class_uid is None, "operator class_uid must not be used as a bucket key")

    # End-to-end through the Detector: the multi-class rule must be evaluated
    # for BOTH classes (the old heuristic dropped the second).
    sys.path.insert(0, str(HERE))
    import importlib
    det_main = importlib.import_module("main")
    det = det_main.Detector.__new__(det_main.Detector)
    det.rules = [make_rule({"a": {"class_uid": 3002, "activity_id": 4},
                            "b": {"class_uid": 4001, "activity_id": 6},
                            "condition": "a or b"})]
    det._by_class_uid = {None: []}
    for rr in det.rules:
        det._by_class_uid.setdefault(rr.class_uid, []).append(rr)
    from scoring import Scorer
    det.scorer = Scorer(det_main.SCORING_YAML)
    for cls, act in ((3002, 4), (4001, 6)):
        _ev, matched, _action = det.process({"class_uid": cls, "activity_id": act,
                                             "siem": {"ingest_id": f"t{cls}"}})
        check(len(matched) == 1,
              f"Detector must evaluate the multi-class rule for class {cls}")


def main():
    run()
    if FAILS:
        print(f"[FAIL] v0.3 rule grammar: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] comparison operators + allowlist (not_in) all fail closed, "
          "and match correctly on well-formed input")


if __name__ == "__main__":
    main()
