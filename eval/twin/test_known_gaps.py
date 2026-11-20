"""Acceptance test for oracle-declared gaps (known_gaps, 2026-11-20).

Standalone (NOT pytest): ``[OK]``/``[FAIL]`` lines, exit 0 only when every check passes. Run:

    python eval/twin/test_known_gaps.py

Every guard that reads declarations is shown to go RED for each failure mode, on a copy of a shipped
oracle (nothing on disk is written):

  (a) UNDECLARED   a real disagreement whose declaration was removed
  (b) WRONG KIND   a declaration that mislabels what is observed (a different finding kind at the same
                   identity; an order_blind_join for a pair an explicit step edge claims)
  (c) STALE        a declaration that no longer reproduces
  (d) SCHEMA       a malformed block raises instead of being ignored
  (e) PLUMBING     the mutation probe skips known_gaps (declarations are not oracle semantics); the
                   legacy name-keyed tables are gone; the shipped oracles migrated every legacy entry
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
for _p in (str(TWIN), str(SERVICES), str(ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import report  # noqa: E402  (first: pins ws4's `main` before anything imports one)

import known_gaps as kg  # noqa: E402
import oracle_consistency as oc  # noqa: E402
import oracle_derive as od  # noqa: E402
import oracle_mutate as om  # noqa: E402
import scenario_registry as reg  # noqa: E402

FAILURES: list = []
IT = reg.BY_NAME["it_intrusion"]
PH = reg.BY_NAME["phishing_bec"]


def _check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def _oracle(sdef) -> dict:
    return yaml.safe_load(Path(sdef.oracle_path).read_text(encoding="utf-8"))


def _raises(fn) -> bool:
    try:
        fn()
    except kg.KnownGapsError:
        return True
    return False


def _gap(**kw) -> dict:
    return {"since": "2026-11-20", "reason": "synthetic declaration used by the negative test", **kw}


def test_schema() -> None:
    base = _oracle(IT)
    _check("SCHEMA the shipped it_intrusion block loads", len(kg.load(base, "it_intrusion")) == 12)
    _check("SCHEMA an oracle without known_gaps has none", kg.load({}, "x") == [])

    def bad(entry):
        o = {"known_gaps": [entry]}
        return _raises(lambda: kg.load(o, "x"))
    _check("SCHEMA an unknown kind raises", bad(_gap(kind="nope")))
    _check("SCHEMA a missing field raises", bad(_gap(kind="order_blind_join", **{"from": "a"})))
    _check("SCHEMA an unknown field raises", bad(_gap(kind="gap_technique_waiver", step="s", extra=1)))
    _check("SCHEMA a malformed date raises", bad({**_gap(kind="gap_technique_waiver", step="s"), "since": "20-11-2026"}))
    _check("SCHEMA an impossible date raises", bad({**_gap(kind="gap_technique_waiver", step="s"), "since": "2026-13-40"}))
    _check("SCHEMA an empty reason raises", bad({**_gap(kind="gap_technique_waiver", step="s"), "reason": " "}))
    _check("SCHEMA a forbidden pair cannot hide in accepted_disagreement",
           bad(_gap(kind="accepted_disagreement", finding="forbidden", step="a", rule_id="b")))
    _check("SCHEMA a non-positive cap raises", bad(_gap(kind="f2_cap", max=0)))
    twice = {"known_gaps": [_gap(kind="gap_technique_waiver", step="s")] * 2}
    _check("SCHEMA a duplicate declaration raises", _raises(lambda: kg.load(twice, "x")))
    mal = copy.deepcopy(base)
    mal["known_gaps"][0]["kind"] = "typo"
    _check("SCHEMA a malformed block turns reconcile / run_checks RED (raises), never silently ignored",
           _raises(lambda: oc.reconcile(7, IT, oracle=mal, grade={}))
           and _raises(lambda: od.run_checks(IT, 7, oracle=mal)))


def test_consistency() -> None:
    oracle = _oracle(IT)
    grade = report._grade_chain(reg.run(IT, 7), oracle)
    ok = oc.reconcile(7, IT, oracle=oracle, grade=grade)
    n_ob = len(kg.of_kind(kg.load(oracle, IT.name), "order_blind_join"))
    _check("CONSISTENCY shipped it_intrusion: nothing new, nothing stale, every forbidden join accepted",
           not ok["new"] and not ok["stale_allowlist_entries"] and ok["accepted_count"] == n_ob == 2,
           f"new={ok['new']} stale={ok['stale_allowlist_entries']} accepted={ok['accepted_count']}")
    # (a) undeclared
    o = copy.deepcopy(oracle)
    dropped = o["known_gaps"].pop(next(i for i, g in enumerate(o["known_gaps"]) if g["kind"] == "order_blind_join"))
    f = oc.reconcile(7, IT, oracle=o, grade=grade)
    _check("CONSISTENCY (a) UNDECLARED: removing an order_blind_join declaration makes the join a NEW drift (red)",
           [(n["kind"], n["from"], n["to"]) for n in f["new"]] == [("forbidden", dropped["from"], dropped["to"])]
           and f["accepted_count"] == n_ob - 1 and oc._report_one(f, False) == 1)
    # (c) stale
    o = copy.deepcopy(oracle)
    o["known_gaps"].append(_gap(kind="order_blind_join", **{"from": "recon_port_scan", "to": "priv_grant"}))
    f = oc.reconcile(7, IT, oracle=o, grade=grade)
    _check("CONSISTENCY (c) STALE: an order_blind_join for a pair that is not a joined forbidden pair is red",
           len(f["stale_allowlist_entries"]) == 1 and not f["new"] and oc._report_one(f, False) == 1)
    o = copy.deepcopy(oracle)
    o["known_gaps"].append(_gap(kind="gap_technique_waiver", step="priv_grant"))
    f = oc.reconcile(7, IT, oracle=o, grade=grade)
    _check("CONSISTENCY (c) STALE: a gap_technique_waiver for a step that is not an untagged gap is red",
           [e["key"][0] for e in f["stale_allowlist_entries"]] == ["gap_technique_waiver"])
    o = copy.deepcopy(oracle)
    o["known_gaps"].append(_gap(kind="accepted_disagreement", finding="decorative", step="priv_grant",
                                rule_id="00000000-0000-4000-8000-000000000000"))
    f = oc.reconcile(7, IT, oracle=o, grade=grade)
    _check("CONSISTENCY (c) STALE: an accepted_disagreement that does not occur is red",
           len(f["stale_allowlist_entries"]) == 1 and oc._report_one(f, False) == 1)
    # (b) wrong kind: same identity, other finding kind
    o = copy.deepcopy(oracle)
    g = next(g for g in o["known_gaps"] if g["kind"] == "order_blind_join")
    o["known_gaps"].remove(g)
    o["known_gaps"].append(_gap(kind="accepted_disagreement", finding="unexpected", step=g["from"], rule_id=g["to"]))
    f = oc.reconcile(7, IT, oracle=o, grade=grade)
    _check("CONSISTENCY (b) WRONG KIND: the pair declared as another finding kind is red twice (undeclared + stale "
           "with why=kind_mismatch)",
           len(f["new"]) == 1 and len(f["stale_allowlist_entries"]) == 1
           and "kind_mismatch" in f["stale_allowlist_entries"][0].get("why", ""))
    # (b) wrong kind: the pair is claimed by an explicit step edge, not only through entities
    g2 = copy.deepcopy(grade)
    for pf in g2["per_forbidden_pair"]:
        pf["joined"] = False
    pair = (g["from"], g["to"])
    g2["graph_edges"] = list(g2.get("graph_edges") or []) + [{"from_step": pair[0], "to_step": pair[1]}]
    f = oc.reconcile(7, IT, oracle=oracle, grade=g2)
    kinds = [e.get("why", "") for e in f["stale_allowlist_entries"] if e["key"][2:] == list(pair)]
    _check("CONSISTENCY (b) WRONG KIND: an order_blind_join for a pair claimed by an explicit step edge is red",
           any("explicit step edge" in k for k in kinds) and any(n.get("basis") == "edge from_step/to_step"
                                                                     for n in f["new"]))
    # triangulation declarations
    t0 = oc.triangulate(7, IT, oracle=oracle, grade=grade)
    o = copy.deepcopy(oracle)
    o["known_gaps"].append(_gap(kind="triangulation_difference", step="priv_grant",
                                rule_id="00000000-0000-4000-8000-000000000000"))
    t1 = oc.triangulate(7, IT, oracle=o, grade=grade)
    _check("CONSISTENCY (c) STALE: a triangulation_difference that does not occur is red; shipped oracle is clean",
           t0["ok"] and not t1["ok"] and len(t1["stale_waivers"]) == 1)


def test_derive() -> None:
    oracle = _oracle(IT)
    derived = od.derive(IT, 7)
    run = lambda o: od.run_checks(IT, 7, oracle=o, derived=derived)  # noqa: E731
    good = run(oracle)
    _check("DERIVE shipped it_intrusion is green with its declared F14", good["ok"])
    o = copy.deepcopy(oracle)
    o["known_gaps"] = [g for g in o["known_gaps"] if g["kind"] != "derive_waiver"]
    r = run(o)
    _check("DERIVE (a) UNDECLARED: without its derive_waiver the F14 is an unwaived FAIL",
           [f["kind"] for f in r["unwaived"]] == ["F14"] and not r["ok"])
    o = copy.deepcopy(oracle)
    o["known_gaps"].append(_gap(kind="derive_waiver", finding="F1", step="x", item="y"))
    r = run(o)
    _check("DERIVE (c) STALE: a derive_waiver that does not reproduce is red", not r["ok"] and len(r["stale_waivers"]) == 1)
    o = copy.deepcopy(oracle)
    for g in o["known_gaps"]:
        if g["kind"] == "derive_waiver":
            g["finding"] = "F13"
    r = run(o)
    _check("DERIVE (b) WRONG KIND: the right (step, item) declared under another F-code is reported as a kind "
           "mismatch AND leaves the real finding unwaived",
           not r["ok"] and len(r["kind_mismatches"]) == 1 and r["kind_mismatches"][0]["observed_kind"] == "F14"
           and [f["kind"] for f in r["unwaived"]] == ["F14"])
    o = copy.deepcopy(oracle)
    o["known_gaps"].append(_gap(kind="f2_cap", max=1))
    r = run(o)
    _check("DERIVE (c) STALE: an f2_cap above the undecidable count is red", not r["ok"] and r["stale_f2_cap"])
    ph = _oracle(PH)
    rp = od.run_checks(PH, 7, oracle=ph)
    _check("DERIVE phishing_bec's declared f2_cap == its one undecided step", rp["ok"] and rp["f2_count"] == 1)
    o = copy.deepcopy(ph)
    o["known_gaps"] = [g for g in o["known_gaps"] if g["kind"] != "f2_cap"]
    rp = od.run_checks(PH, 7, oracle=o)
    _check("DERIVE (a) UNDECLARED: without the declared f2_cap the undecidable rule fails the gate",
           not rp["ok"] and rp["f2_over_cap"])


def test_mutate() -> None:
    reason = "2026-10-02 this class of mutant is unobservable by construction in this synthetic test"
    rows = [("a1", "op", "WRONG", "SURVIVED"), ("a2", "op", "WRONG", "SURVIVED")]
    run = {"scenario": "s", "rows": [{"id": i, "operator": op, "kind": k, "outcome": out} for i, op, k, out in rows]}
    ev = om.evaluate(run, equivalent={})
    _check("MUTATE (a) UNDECLARED: a survivor class with no declaration is red", not ev["ok"] and len(ev["unwaived"]) == 1)
    ev = om.evaluate(run, equivalent={("s", "op", "IMPROVED"): {"max": 2, "reason": reason}})
    _check("MUTATE (b) WRONG KIND: a class declared IMPROVED that is observed SURVIVED is reported as a kind "
           "mismatch (and stale, and the survivors stay undeclared)",
           not ev["ok"] and ev["kind_mismatches"] == [{"class": ["s", "op", "IMPROVED"], "observed": ["SURVIVED"]}]
           and len(ev["unwaived"]) == 1)
    ev = om.evaluate(run, equivalent={("s", "op", "SURVIVED"): {"max": 2, "reason": reason},
                                      ("s", "gone", "SURVIVED"): {"max": 1, "reason": reason}})
    _check("MUTATE (c) STALE: a declared class that no longer occurs is red (and is not a kind mismatch)",
           ev["stale_waivers"] == [["s", "gone", "SURVIVED"]] and not ev["kind_mismatches"] and not ev["ok"])
    # the shipped declarations are what evaluate() reads when no table is injected
    sd = reg.BY_NAME["ransomware"]
    want = kg.mutant_map(kg.load(_oracle(sd), sd.name), sd.name)
    only = {"scenario": sd.name, "rows": [{"id": "z", "operator": "drop_expected_rule", "kind": "WRONG",
                                          "outcome": "SURVIVED"}]}
    ev = om.evaluate(only)
    _check("MUTATE evaluate() with no injected table reads the storyline oracle's declarations (every other "
           "declared class is then stale)",
           ev["ok"] is False and len(ev["stale_waivers"]) == len(want) - 1 and not ev["unwaived"])


def test_plumbing() -> None:
    for name in ("_ACCEPTED", "_GAP_TECHNIQUE_WAIVED", "_TRIANGULATION_WAIVED", "_ORDER_BLIND"):
        _check(f"PLUMBING the name-keyed table oracle_consistency.{name} is gone", not hasattr(oc, name))
    for name in ("_WAIVED", "_F2_CAP"):
        _check(f"PLUMBING the name-keyed table oracle_derive.{name} is gone", not hasattr(od, name))
    _check("PLUMBING the name-keyed table oracle_mutate._EQUIVALENT is gone", not hasattr(om, "_EQUIVALENT"))
    for sd in reg.ALL:
        o = _oracle(sd)
        gaps = kg.load(o, sd.name)
        _check(f"PLUMBING {sd.name}: known_gaps parses and every entry is dated", all(g["since"] for g in gaps))
        paths = {om.normalise_path(p) for p, _ in om._leaves(kg.strip(o))}
        _check(f"PLUMBING {sd.name}: the mutation probe sees no known_gaps key (not oracle semantics)",
               not any(p.startswith("known_gaps") for p in paths) and "known_gaps" in o or not gaps)
    n = sum(len(kg.load(_oracle(sd), sd.name)) for sd in reg.ALL)
    _check("PLUMBING all 74 legacy table entries live in the oracles", n == 74, f"{n}")


def main() -> int:
    test_schema()
    test_consistency()
    test_derive()
    test_mutate()
    test_plumbing()
    if FAILURES:
        print(f"\n[FAIL] {len(FAILURES)} check(s) failed:")
        for f in FAILURES:
            print(f"   - {f}")
        return 1
    print("\n[OK] known_gaps: undeclared, wrong-kind and stale declarations each turn their guard red.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
