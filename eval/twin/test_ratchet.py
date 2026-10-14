"""Phase 6 ratchet acceptance tests; executable without pytest."""
from __future__ import annotations

import copy
import json
import os
import shutil
import tempfile
import hashlib
from pathlib import Path
import sys

import ratchet
import ratchet_measure
from fingerprint import system_fingerprint


ROOT = Path(__file__).resolve().parents[2]


def _check(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"{label}: {detail}")
    print(f"[OK] {label}")


def _report(result):
    return {"status": result.status, "failures": result.failures}


def test_atom_direction_and_masking() -> None:
    base = {
        "scn/demo/mut/volume/a": "fail",
        "scn/demo/mut/volume/b": "pass",
        "scn/demo/base/tpr": 1.0,
        "scn/demo/base/mttd_seconds": 10.0,
        "scn/demo/base/fired_alerts": 5,
    }
    current = copy.deepcopy(base)
    current["scn/demo/mut/volume/a"] = "pass"
    current["scn/demo/mut/volume/b"] = "fail"
    current["scn/demo/base/tpr"] = 0.9
    current["scn/demo/base/mttd_seconds"] = 11.0
    current["scn/demo/base/fired_alerts"] = 3
    out = ratchet.compare(base, current, {"waivers": []}, today="2026-10-14")
    ids = {x.atom for x in out.failures}
    _check("atom masking catches the newly failed variant", "scn/demo/mut/volume/b" in ids)
    _check("higher-is-better regression is named", "scn/demo/base/tpr" in ids)
    _check("lower-is-better regression is named", "scn/demo/base/mttd_seconds" in ids)
    _check("pinned change is named", "scn/demo/base/fired_alerts" in ids)


def test_null_and_improvement() -> None:
    base = {"scn/demo/base/tpr": 1.0, "scn/demo/base/incident_membership_ok": False}
    current = {"scn/demo/base/tpr": None, "scn/demo/base/incident_membership_ok": True}
    out = ratchet.compare(base, current, {"waivers": []}, today="2026-10-14")
    _check("numeric to null is regression", any(x.atom.endswith("/tpr") for x in out.failures))
    _check("improvement is unrecorded", any(x.kind == "IMPROVED-UNRECORDED" for x in out.failures))


def test_waiver_validation() -> None:
    base = {"scn/demo/base/tpr": 1.0}
    current = {"scn/demo/base/tpr": 0.9}
    valid = {"waivers": [{
        "id": "w1", "scope": "scn/demo/base/tpr", "floor": 0.9,
        "opened": "2026-10-01", "expires": "2026-10-30", "owner": "owner",
        "reason": "temporary approved detector migration evidence",
        "evidence": "https://github.com/supermhel/fengarde/issues/1",
    }]}
    out = ratchet.compare(base, current, valid, today="2026-10-14")
    _check("valid waiver clears regression", not out.failures and out.waived == ["scn/demo/base/tpr"])
    expired = copy.deepcopy(valid)
    expired["waivers"][0]["expires"] = "2026-10-13"
    _check("expired waiver fails", bool(ratchet.compare(base, current, expired, today="2026-10-14").failures))


def test_fingerprint_is_stable_and_sensitive() -> None:
    first = system_fingerprint(ROOT)
    second = system_fingerprint(ROOT)
    _check("fingerprint is deterministic", first == second)
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td) / "repo"
        shutil.copytree(ROOT, tmp, ignore=shutil.ignore_patterns(".git", "__pycache__", ".venv"))
        target = tmp / "contracts" / "rules" / "dc_mass_vm_delete.yml"
        target.write_bytes(target.read_bytes() + b"\n")
        _check("rule edit changes fingerprint", first != system_fingerprint(tmp))


def test_direction_table_completeness() -> None:
    atoms = {
        "scn/demo/base/tpr": 1.0,
        "scn/demo/mut/volume/a": "pass",
        "lane_a/base/chain_fidelity": 0.6,
        "tech/attack:T1485/cell/demo/step/base": "detected",
        "quality/macro_f1": 0.875,
    }
    _check("all synthetic committed families have explicit directions",
           not ratchet.unmatched_direction_atoms(atoms))
    _check("unknown families default to pinned",
           ratchet.direction_for("future/family/atom") == "pinned")


def test_technique_mapping_controls() -> None:
    oracle = {"detection_points": {
        "step": {"expected_rules": [{"rule_id": "r1"}, {"rule_id": "r2"}]},
        "gap": {"expected_rules": [], "gap": {"no_rule_exists": True, "attack_technique": "T9999"}},
    }}
    rows = [{"axis": "volume", "variant": "thin", "applicable": True,
             "steps_lost": [], "tactic_lost": [], "expected_rule_lost_steps": [],
             "fired_pairs": [["step", "r1"], ["step", "r2"]]},
            {"axis": "loss", "variant": "drop_step", "applicable": True,
             "steps_lost": ["step"], "tactic_lost": ["step"],
             "expected_rule_lost_steps": ["step"], "fired_pairs": []}]
    catalogue = {"r1": {"framework": "attack", "technique": "T1", "stem": "r1"},
                 "r2": {"framework": "attack", "technique": "T2", "stem": "r2"}}
    cells = ratchet_measure.technique_cells("demo", oracle, {"tpr": 1.0,
        "tactic_covered_steps": ["step"], "fired_pairs": [["step", "r1"], ["step", "r2"]]}, rows, catalogue)
    _check("multi-rule step credits both techniques", all(
        cells[f"tech/attack:T{n}/cell/demo/step/base/expected_rule_fired"] is True for n in (1, 2)))
    _check("drop own step is excluded", not any("drop_step" in k for k in cells))
    _check("gap creates a gap cell", cells["tech/attack:T9999/cell/demo/gap/base"] == "gap")


def test_trend_is_advisory() -> None:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "trend.jsonl"
        path.write_text("# seed\n" + json.dumps({"_schema": "layer-c-trend-v1", "producer": "stub",
            "comparable": True, "system_fingerprint": "x", "ratchet_snapshot": {"pooled": 1}}) + "\n" +
            json.dumps({"_schema": "layer-c-trend-v1", "producer": "stub", "comparable": True,
            "system_fingerprint": "x", "ratchet_snapshot": {"pooled": 0}}) + "\n", encoding="utf-8")
        rc = ratchet.trend_diff(path, summary_path=None)
        _check("trend diff remains advisory", rc == 0)


def test_guard_controls() -> None:
    base = {"schema": "fengarde-scenario-ratchet-v1", "seed": 7,
            "atoms": {"scn/demo/base/tpr": 1.0}, "retired": []}
    lowered = {**base, "atoms": {"scn/demo/base/tpr": 0.9}}
    _check("guard rejects an unexplained lower", bool(ratchet.guard_compare(
        base, lowered, [], [], {"waivers": []}, today="2026-10-14")))
    waiver = {"waivers": [{
        "id": "w1", "scope": "scn/demo/base/tpr", "floor": 0.9,
        "opened": "2026-10-01", "expires": "2026-10-30", "owner": "owner",
        "reason": "temporary approved detector migration evidence",
        "evidence": "https://github.com/supermhel/fengarde/issues/1",
    }]}
    _check("guard accepts an unexpired waiver", not ratchet.guard_compare(
        base, lowered, [], [], waiver, today="2026-10-14"))
    history = [{"kind": "refresh", "lowered": [{"atom": "scn/demo/base/tpr",
        "reason": "documented change with evidence for review", "evidence": "https://github.com/supermhel/fengarde/issues/2"}]}]
    _check("guard accepts an evidenced lowered entry", not ratchet.guard_compare(
        base, lowered, [], history, {"waivers": []}, today="2026-10-14"))
    _check("guard rejects a truncated history", any("history" in item for item in ratchet.guard_compare(
        base, base, [{"kind": "old"}], [], {"waivers": []}, today="2026-10-14")))
    _check("guard rejects a deleted baseline atom", bool(ratchet.guard_compare(
        base, {**base, "atoms": {}}, [], [], {"waivers": []}, today="2026-10-14")))
    _check("guard accepts an introducing baseline", not ratchet.guard_compare(
        None, lowered, [], [], {"waivers": []}, today="2026-10-14"))


def test_weakened_rule_mutation_proof() -> None:
    """The stock slice is the proof baseline; the temp tree must turn RED."""
    # These imports are deliberately inside the live proof: the stdlib ratchet
    # guard remains usable without importing the production detector cascade.
    sys.path[:0] = [str(ROOT / "eval" / "adversarial"), str(ROOT / "services")]
    import layer_a
    import mutate_generic
    import report
    import scenario_registry as registry

    rules = ROOT / "contracts" / "rules"
    def tree_hash(path: Path) -> str:
        h = hashlib.sha256()
        for item in sorted(path.glob("*.yml")):
            h.update(item.name.encode())
            h.update(item.read_bytes())
        return h.hexdigest()

    before = tree_hash(rules)
    sdef = registry.get("infra_takeover")
    payloads = sdef.build(7)[0]
    mutated, changed = mutate_generic.apply(payloads, "volume", "thin_25pct", seed=7, sdef=sdef)
    def source(_seed):
        return mutated, {}, {}, None

    stock_base = registry.grade(sdef, 7)
    stock_mut = registry.grade(sdef, 7, payload_source=source, strict=False)
    stock_base["fired_pairs"] = [[a.get("step"), a.get("rule_id")] for a in stock_base.get("fired", [])]
    stock_row = layer_a.cmp_result("volume", "thin_25pct", stock_base, stock_mut)
    stock_row["applicable"] = True
    _check("stock mutation proof control is applicable", changed > 0 and stock_row["pass"] is True)

    with tempfile.TemporaryDirectory() as td:
        temp_rules = Path(td) / "rules"
        shutil.copytree(rules, temp_rules)
        for filename in ("dc_mass_vm_delete.yml", "dc_mass_vm_delete_by_source.yml"):
            path = temp_rules / filename
            path.write_text(path.read_text(encoding="utf-8").replace("threshold: 5", "threshold: 7"), encoding="utf-8")
        original_rules_dir = report._WS4_MOD.RULES_DIR
        report._WS4_MOD.RULES_DIR = temp_rules
        try:
            weak_base = registry.grade(sdef, 7)
            weak_mut = registry.grade(sdef, 7, payload_source=source, strict=False)
            weak_base["fired_pairs"] = [[a.get("step"), a.get("rule_id")] for a in weak_base.get("fired", [])]
            weak_row = layer_a.cmp_result("volume", "thin_25pct", weak_base, weak_mut)
            weak_row["applicable"] = True
            oracle = registry.load_oracle(sdef)
            catalogue = ratchet_measure._rule_catalogue()
            base_cells = ratchet_measure.technique_cells(
                sdef.name, oracle, stock_base, [stock_row], catalogue)
            weak_cells = ratchet_measure.technique_cells(
                sdef.name, oracle, weak_base, [weak_row], catalogue)
            named = "scn/infra_takeover/mut/volume/thin_25pct"
            tech = "tech/attack:T1485/cell/infra_takeover/mass_vm_delete/volume/thin_25pct"
            _check("weakened base TPR remains 1.0", weak_base.get("tpr") == 1.0)
            _check("weakened base pinned fired_alerts changes explicitly",
                   stock_base.get("fired_alerts") == 5 and weak_base.get("fired_alerts") == 3)
            _check("weakened mutation is RED", weak_row["pass"] is False and "mass_vm_delete" in weak_row["steps_lost"])
            _check("named scenario atom is represented", named.endswith("thin_25pct"))
            weakened_atoms = ratchet.compare(
                {named: "pass", tech: "retained"},
                {named: "fail", tech: "lost"}, {"waivers": []}, today="2026-10-14")
            _check("ratchet names weakened scenario and technique atoms",
                   {named, tech} <= {finding.atom for finding in weakened_atoms.failures})
            _check("named technique atom detects the weakened rule",
                   base_cells.get(tech) == "retained" and weak_cells.get(tech) == "lost")
        finally:
            report._WS4_MOD.RULES_DIR = original_rules_dir
    _check("weakened-rule proof leaves contracts/rules unchanged", before == tree_hash(rules))


def main() -> int:
    tests = [
        test_atom_direction_and_masking, test_null_and_improvement, test_waiver_validation,
        test_fingerprint_is_stable_and_sensitive, test_direction_table_completeness,
        test_technique_mapping_controls, test_trend_is_advisory,
        test_guard_controls,
        test_weakened_rule_mutation_proof,
    ]
    for test in tests:
        test()
    print(f"[OK] {len(tests)} ratchet acceptance controls")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
