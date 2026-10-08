"""Acceptance test for the ATT&CK technique matrix and its gate (2026-10-03).

Standalone (NOT pytest): ``[OK]``/``[FAIL]`` lines, exit 0 only when every check passes. Run:

    python eval/adversarial/test_technique_matrix.py

The gate logic is proven on a SYNTHETIC world (a temporary rules directory, a hand-written
artefact and oracle) so every branch can be driven to red; one integration check then builds the
matrix from a REAL scenario_matrix result for the phishing_bec storyline to prove the plumbing
reads real data.

  (a) cells      survive / evaded_declared / evaded_unexpected are classified from the rule's own YAML;
                 loss of the rule's OWN step or its CONTEXT step, and variants that changed nothing, are
                 excluded; a companion is exercised through a variant
  (b) gate       POSITIVE: the synthetic world passes with its (dated) waivers
                 NEGATIVE: a rule with a technique no storyline exercises; a rule with no mitre block
                 and no waiver; a stale waiver; a malformed/undated waiver; a waiver for a rule that
                 does not exist; an artefact for another seed, another scenario list or another tree
  (c) determinism the canonical JSON is byte-identical across two builds
  (d) surfaced   the matrix reports where the observed baseline disagrees with the oracle (it does not
                 simply echo the oracle)
  (e) real data  phishing_bec built from an actual scenario_matrix run
  (f) register   the missing-rule block in contracts/detection-coverage.md is generated from the oracles'
                 tagged gaps; a stale or absent block FAILS the gate, a regenerated one passes
"""
from __future__ import annotations

import copy
import shutil
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ADVERSARIAL = Path(__file__).resolve().parent
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
for _p in (str(ADVERSARIAL), str(TWIN), str(SERVICES)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import layer_a  # noqa: E402,F401  (import order: report.py collision guard, as test_scenario_harness)
import scenario_matrix  # noqa: E402
import scenario_registry as reg  # noqa: E402
import technique_matrix as tm  # noqa: E402

_FAILURES: list = []


def _check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        _FAILURES.append(name)


# ---------------------------------------------------------------------------
# the synthetic world
# ---------------------------------------------------------------------------
ID_COUNT, ID_COMP, ID_TIME, ID_STATELESS, ID_NOTECH = (f"00000000-0000-4000-8000-00000000000{i}" for i in range(1, 6))


def _write_rules(d: Path, extra: dict | None = None) -> None:
    rules = {
        "r_count": {"title": "count", "id": ID_COUNT, "description": "x", "detection": {"s": {"class_uid": 3002}},
                    "siem": {"threshold": 5, "window_seconds": 60, "group_by": "src_endpoint.ip"},
                    "mitre": {"tactic": "TA0006", "technique": "T1110"}},
        "r_comp": {"title": "companion", "id": ID_COMP, "description": "x", "detection": {"s": {"class_uid": 3002}},
                   "siem": {"threshold": 5, "window_seconds": 60, "group_by": "actor.user.name", "companion_of": ID_COUNT},
                   "mitre": {"tactic": "TA0006", "technique": "T1110"}},
        "r_time": {"title": "time", "id": ID_TIME, "description": "x",
                   "detection": {"s": {"time": {"outside_hours": {"start": "08:00", "end": "18:00"}}}},
                   "siem": {}, "mitre": {"tactic": "TA0004", "technique": "T1078"}},
        "r_stateless": {"title": "stateless", "id": ID_STATELESS, "description": "x",
                        "detection": {"s": {"class_uid": 6003}}, "siem": {},
                        "mitre": {"tactic": "TA0040", "technique": "T1485"}},
        "r_notech": {"title": "notech", "id": ID_NOTECH, "description": "x",
                     "detection": {"s": {"class_uid": 6003}}, "siem": {}},
    }
    rules.update(extra or {})
    for stem, body in rules.items():
        (d / f"{stem}.yml").write_text(yaml.safe_dump(body), encoding="utf-8")


def _oracle() -> dict:
    return {
        "expected_sequence": ["a", "b", "c"],
        "step_dependencies": {"c": ["b"]},
        "detection_points": {
            "a": {"expected_rules": [{"rule_id": ID_COUNT}], "gap": {"no_rule_exists": False}},
            "b": {"expected_rules": [{"rule_id": ID_TIME}], "gap": {"no_rule_exists": False}},
            "c": {"expected_rules": [{"rule_id": ID_STATELESS}], "gap": {"no_rule_exists": False}},
            "d": {"expected_rules": [], "gap": {"no_rule_exists": True, "attack_technique": "T1566.001",
                                                 "reason": "no mail parser"}},
            "ctx": {"expected_rules": [], "context": True, "gap": {"no_rule_exists": True, "reason": "benign"}},
        },
    }


def _row(axis, variant, pairs, applicable=True):
    if not applicable:
        return {"axis": axis, "variant": variant, "applicable": False, "changed_events": 0, "pass": None}
    return {"axis": axis, "variant": variant, "applicable": True, "changed_events": 3,
            "fired_pairs": [list(p) for p in pairs]}


def _artefact() -> dict:
    base = [("a", ID_COUNT), ("b", ID_TIME), ("c", ID_STATELESS)]
    rows = [
        _row("volume", "thin_25pct", [("b", ID_TIME), ("c", ID_STATELESS)]),                 # r_count evaded (declared)
        _row("distribution", "ip_rotate_2", [("a", ID_COMP), ("b", ID_TIME), ("c", ID_STATELESS)]),   # companion fires
        _row("loss", "drop_a", [("b", ID_TIME), ("c", ID_STATELESS)]),                       # own step of r_count: excluded
        _row("loss", "drop_b", [("a", ID_COUNT)]),                       # r_time own step; r_stateless context
        _row("loss", "drop_c", [("a", ID_COUNT), ("b", ID_TIME)]),       # r_stateless own step: excluded
        # r_stateless displaced onto its context step b
        _row("delivery", "reverse_arrival", [("a", ID_COUNT), ("b", ID_STATELESS)]),
        # r_stateless evaded (unexpected); r_time ok
        _row("delivery", "shuffle_arrival", [("a", ID_COUNT), ("b", ID_TIME)]),
        _row("timing", "to_business_hours", [("a", ID_COUNT), ("c", ID_STATELESS)]),   # r_time evaded (declared)
        _row("pacing", "stretch_2x", [], applicable=False),                                  # changed nothing: excluded
    ]
    return {"seed": 7, "scenario_list": ["s1"], "inputs_fingerprint": "fp-1",
            "scenarios": {"s1": {"baseline": {"fired_pairs": [list(p) for p in base]}, "rows": rows}}}


def _waivers() -> dict:
    return {"unexercised": {}, "no_technique": {"r_notech": "2026-10-03 deliberately no technique (synthetic)"}}


def _build(tmp: Path, artefact=None, oracle=None):
    return tm.build(artefact or _artefact(), tm.load_rule_infos(tmp), {"s1": oracle or _oracle()})


def _gate(matrix, waivers=None, **kw):
    return tm.gate(matrix, waivers or _waivers(), registry_names=kw.pop("registry_names", ["s1"]),
                   fingerprint=kw.pop("fingerprint", "fp-1"), **kw)


# ---------------------------------------------------------------------------
def test_cells(tmp: Path) -> None:
    m = _build(tmp)
    rc = m["rules"]["r_count"]["survives_mutation"]["s1"]
    _check("(a) a threshold rule thinned out of firing is evaded_declared (its own threshold predicts it); "
           "rotating the source address it is keyed on likewise",
           [e["variant"] for e in rc["evaded_declared"]] == ["volume/thin_25pct", "distribution/ip_rotate_2"],
           str(rc["evaded_declared"]))
    _check("(a) loss/drop_<its own step> is EXCLUDED from r_count's cells (the lane's negative control, "
           "not an evasion)", "loss/drop_a" in rc["excluded"] and "loss/drop_a" not in
           [e["variant"] for e in rc["evaded_unexpected"] + rc["evaded_declared"]], str(rc["excluded"]))
    _check("(a) ...and a loss of ANOTHER step that leaves r_count firing is a survival",
           "loss/drop_b" in rc["survived"] and "loss/drop_c" in rc["survived"])
    rt = m["rules"]["r_time"]["survives_mutation"]["s1"]
    _check("(a) an outside_hours rule moved into business hours is evaded_declared",
           [e["variant"] for e in rt["evaded_declared"]] == ["timing/to_business_hours"], str(rt))
    rs = m["rules"]["r_stateless"]["survives_mutation"]["s1"]
    _check("(a) a stateless rule that stops firing under a delivery shuffle is evaded_UNEXPECTED (nothing in its "
           "YAML predicts it)", [e["variant"] for e in rs["evaded_unexpected"]] == ["delivery/shuffle_arrival"],
           str(rs))
    _check("(a) dropping the rule's CONTEXT step is excluded, not scored as an evasion",
           "loss/drop_b" in rs["excluded"] and "loss/drop_c" in rs["excluded"], str(rs["excluded"]))
    _check("(a) a rule re-attributed to its context step (it fires one step away when delivery is reversed) "
           "SURVIVES: the step and its dependency form one group", "delivery/reverse_arrival" in rs["survived"],
           str(rs["survived"]))
    allcells = [v for r in m["rules"].values() for c in r["survives_mutation"].values() for k in c.values()
                for v in k]
    _check("(a) a variant that changed no event (applicable=False) appears in NO cell",
           not any("stretch_2x" in str(v) for v in allcells))
    comp = m["rules"]["r_comp"]
    _check("(a) a companion is silent at baseline by design and EXERCISED through the variant it fires in",
           comp["fires_on_storyline"] == {} and comp["fires_in_variants"] == {"s1": ["distribution/ip_rotate_2"]}
           and comp["exercised"] is True and comp["exercised_via"] == "companion_variant")
    _check("(a) a NON-companion rule that never fires at baseline is NOT exercised by a variant alone",
           not m["rules"]["r_notech"]["exercised"])
    _check("(a) the demonstrated-but-undetected table lists the oracle's tagged gap and skips the context step",
           [(u["technique"], u["step"]) for u in m["demonstrated_but_undetected"]] == [("T1566.001", "d")],
           str(m["demonstrated_but_undetected"]))


def test_gate(tmp: Path) -> None:
    m = _build(tmp)
    # r_notech is the only rule with no baseline fire; waive it as unexercised
    w = _waivers()
    w["unexercised"]["r_notech"] = "2026-10-03 not exercised yet (synthetic)"
    _check("(b) POSITIVE: the synthetic world passes with its dated waivers", _gate(m, w) == [], str(_gate(m, w)))

    probs = _gate(m, _waivers())
    _check("(b) NEGATIVE: a rule no storyline exercises and nobody waived -> G2 names it",
           any(p.startswith("G2") and "r_notech" in p for p in probs), str(probs))

    d2 = tmp.parent / "rules_neg"
    shutil.rmtree(d2, ignore_errors=True)
    d2.mkdir()
    _write_rules(d2, {"r_t9999": {"title": "ghost", "id": "00000000-0000-4000-8000-0000000000ff", "description": "x",
                                  "detection": {"s": {"class_uid": 1}}, "siem": {},
                                  "mitre": {"tactic": "TA0001", "technique": "T9999"}}})
    m2 = tm.build(_artefact(), tm.load_rule_infos(d2), {"s1": _oracle()})
    probs = _gate(m2, w)
    _check("(b) NEGATIVE: a rule declaring technique T9999 that no storyline exercises turns the gate red "
           "(rule AND technique)", any(p.startswith("G2") and "T9999" in p for p in probs)
           and any(p.startswith("G3") and "T9999" in p for p in probs), str(probs))

    d3 = tmp.parent / "rules_notech"
    shutil.rmtree(d3, ignore_errors=True)
    d3.mkdir()
    _write_rules(d3, {"r_bare": {"title": "bare", "id": "00000000-0000-4000-8000-0000000000fe", "description": "x",
                                 "detection": {"s": {"class_uid": 1}}, "siem": {}}})
    m3 = tm.build(_artefact(), tm.load_rule_infos(d3), {"s1": _oracle()})
    w3 = copy.deepcopy(w)
    w3["unexercised"]["r_bare"] = "2026-10-03 not exercised yet (synthetic)"
    probs = _gate(m3, w3)
    _check("(b) NEGATIVE: a rule with no mitre block and no no-technique waiver -> G4",
           any(p.startswith("G4") and "r_bare" in p for p in probs), str(probs))

    w4 = copy.deepcopy(w)
    w4["unexercised"]["r_count"] = "2026-10-03 pretend it is not exercised (synthetic)"
    probs = _gate(m, w4)
    _check("(b) NEGATIVE: a waiver for a rule that IS exercised is STALE and fails",
           any(p.startswith("G5 stale waiver") and "r_count" in p for p in probs), str(probs))

    w5 = copy.deepcopy(w)
    w5["unexercised"]["r_missing"] = "2026-10-03 names a rule that does not exist"
    w5["unexercised"]["r_notech"] = "no date at all"
    probs = _gate(m, w5)
    _check("(b) NEGATIVE: a waiver for a rule that does not exist, and an undated waiver, both fail",
           any("r_missing" in p for p in probs) and any("needs 'YYYY-MM-DD" in p for p in probs), str(probs))

    w6 = copy.deepcopy(w)
    w6["no_technique"]["r_count"] = "2026-10-03 but it has a technique"
    _check("(b) NEGATIVE: a no-technique waiver for a rule that now HAS a technique is stale",
           any("stale no-technique" in p for p in _gate(m, w6)))

    bad = _artefact()
    bad["seed"] = 11
    _check("(b) NEGATIVE: an artefact written by `--seed 11` is refused (same default path as seed 7)",
           any(p.startswith("G1") and "seed" in p for p in _gate(_build(tmp, bad), w)))
    _check("(b) NEGATIVE: an artefact covering a subset of the registry is refused",
           any(p.startswith("G1") and "registry" in p for p in _gate(m, w, registry_names=["s1", "s2"])))
    _check("(b) NEGATIVE: an artefact whose input fingerprint differs from the live tree is refused as stale",
           any(p.startswith("G1") and "fingerprint" in p for p in _gate(m, w, fingerprint="fp-2")))


def test_determinism_and_surfacing(tmp: Path) -> None:
    a, b = tm.canonical(_build(tmp)), tm.canonical(_build(tmp))
    _check("(c) two builds of the same inputs are byte-identical (sorted keys, no timestamps)", a == b)
    # (d) the matrix does not echo the oracle: make the oracle expect a rule the baseline never fires
    o = _oracle()
    o["detection_points"]["a"]["expected_rules"].append({"rule_id": ID_TIME})
    m = _build(tmp, oracle=o)
    _check("(d) an oracle expectation the observed baseline does not meet is SURFACED "
           "(oracle_expects_but_baseline_silent)",
           {"scenario": "s1", "step": "a", "rule": "r_time", "kind": "oracle_expects_but_baseline_silent"}
           in m["observed_vs_oracle"], str(m["observed_vs_oracle"]))
    art = _artefact()
    art["scenarios"]["s1"]["baseline"]["fired_pairs"].append(["a", ID_STATELESS])
    m = _build(tmp, artefact=art)
    _check("(d) a rule that fires where the oracle does not declare it is SURFACED too",
           any(d["kind"] == "baseline_fires_but_oracle_does_not_declare" and d["rule"] == "r_stateless"
               for d in m["observed_vs_oracle"]))
    _check("(d) the unmodified synthetic world has no disagreement", _build(tmp)["observed_vs_oracle"] == [])


def test_real_data() -> None:
    sd = reg.get("phishing_bec")
    res = scenario_matrix.run_scenario(sd, 7)
    artefact = {"seed": 7, "scenario_list": ["phishing_bec"], "inputs_fingerprint": scenario_matrix.inputs_fingerprint(),
                "scenarios": {"phishing_bec": res}}
    m = tm.build(artefact, tm.load_rule_infos(), {"phishing_bec": reg.load_oracle(sd)})
    r = m["rules"]
    _check("(e) the three rules phishing_bec exercises fire at the oracle's steps, OBSERVED from the baseline grade",
           r["common_beaconing"]["fires_on_storyline"] == {"phishing_bec": ["c2_beacon"]}
           and r["common_password_spray"]["fires_on_storyline"] == {"phishing_bec": ["proxy_pool_logins"]}
           and r["common_impossible_travel"]["fires_on_storyline"] == {"phishing_bec": ["foreign_login"]},
           str({k: r[k]["fires_on_storyline"] for k in ("common_beaconing", "common_password_spray",
                                                         "common_impossible_travel")}))
    it = r["common_impossible_travel"]["survives_mutation"]["phishing_bec"]
    _check("(e) dropping the victim's login (the context step) is EXCLUDED from impossible travel's cells, "
           "not scored as an evasion", "loss/drop_victim_session" in it["excluded"]
           and "loss/drop_foreign_login" in it["excluded"], str(it["excluded"]))
    _check("(e) reverse arrival moves the impossible-travel alert onto its context step and still counts as "
           "SURVIVED", "delivery/reverse_arrival" in it["survived"], str(it))
    bc = r["common_beaconing"]["survives_mutation"]["phishing_bec"]
    _check("(e) the periodic rule is evaded_declared by jitter_100pct and by thinning (its own text says so)",
           {"pacing/jitter_100pct", "volume/thin_25pct"} <= {e["variant"] for e in bc["evaded_declared"]},
           str([e["variant"] for e in bc["evaded_declared"]]))
    _check("(e) duplicate_all on the beacon is an evaded_unexpected cell carrying its KNOWN CAUSE note "
           "(the harness stamps a fresh ingest_id per copy)",
           any(e["variant"] == "delivery/duplicate_all" and "known_cause" in e for e in bc["evaded_unexpected"]),
           str(bc["evaded_unexpected"]))
    _check("(e) the register lists the four phishing_bec techniques with no rule, and not the context step",
           sorted(u["technique"] for u in m["demonstrated_but_undetected"])
           == ["T1114.003", "T1204.002", "T1565.001", "T1566.001"], str(m["demonstrated_but_undetected"]))
    _check("(e) the real matrix has no observed-vs-oracle disagreement on this storyline",
           m["observed_vs_oracle"] == [], str(m["observed_vs_oracle"]))


def test_register() -> None:
    o = _oracle()
    rows = tm.register_rows({"s1": o})
    _check("(f) the register lists the oracle's tagged gap and skips the context step and untagged steps",
           [(r["technique"], r["scenario"], r["step"]) for r in rows] == [("T1566.001", "s1", "d")], str(rows))
    block = tm.render_register(rows)
    doc = "# doc\n\nbefore\n\n" + block + "\n\nafter\n"
    _check("(f) POSITIVE: a document carrying the freshly rendered block has no register problem",
           tm.register_problems(rows, doc) == [])
    more = rows + [{"technique": "T1486", "scenario": "s2", "step": "x", "reason": "no rule"}]
    probs = tm.register_problems(more, doc)
    _check("(f) NEGATIVE: a new storyline gap not yet in the document -> G6 (stale), so it cannot go unlisted",
           len(probs) == 1 and probs[0].startswith("G6") and "STALE" in probs[0], str(probs))
    fixed = tm.splice_register(doc, tm.render_register(more))
    _check("(f) regenerating splices ONLY the block (text around it is untouched) and clears the problem",
           tm.register_problems(more, fixed) == [] and fixed.startswith("# doc\n\nbefore\n\n")
           and fixed.endswith("\n\nafter\n"))
    _check("(f) NEGATIVE: a document with no register block -> G6",
           tm.register_problems(rows, "# nothing\n")[0].startswith("G6"))
    _check("(f) the rendered table header is NOT '| Rule |' (check_lane_coverage would read it as the rule "
           "scorecard)", not any(line.startswith("| Rule |") for line in block.splitlines()))
    real = {s.name: reg.load_oracle(s) for s in reg.ALL}
    text = tm.COVERAGE_DOC.read_text(encoding="utf-8")
    problems = tm.register_problems(tm.register_rows(real), text)
    _check("(f) the committed contracts/detection-coverage.md block equals the live oracles' tagged gaps",
           problems == [], str(problems))
    _check("(f) every technique id the oracles tag has the ATT&CK id shape",
           all(tm._TECH_SHAPE.match(r["technique"]) for r in tm.register_rows(real)))


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="techmatrix_")) / "rules"
    tmp.mkdir()
    try:
        _write_rules(tmp)
        test_cells(tmp)
        test_gate(tmp)
        test_determinism_and_surfacing(tmp)
    finally:
        shutil.rmtree(tmp.parent, ignore_errors=True)
    test_register()
    test_real_data()
    if _FAILURES:
        print(f"\n[FAIL] {len(_FAILURES)} check(s) failed:")
        for f in _FAILURES:
            print(f"   - {f}")
        return 1
    print("\n[OK] technique matrix: every cell class and every gate branch passed its positive AND negative control.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
