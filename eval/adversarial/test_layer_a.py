"""WP-4-A: Layer A acceptance test -- the DETERMINISTIC BLOCKING mutation
lane is real, sensitive, and safe to block on.

Standalone (NOT pytest), matching the repo twin-test style: ``if __name__``
guard, ``[OK]``/``[FAIL]`` lines, exit 0 only when every check passes.

Run:  python eval/adversarial/test_layer_a.py

Checks (all against REAL pipeline numbers -- nothing hand-picked):
  (a) catalogue coverage: the matrix grades EVERY variant_specs entry (a
      silent skip would make the lane incomplete) and the self-check floor
      holds (baseline TPR==1.0, fidelity/FCR non-None; no row is both pass
      and causal_join_broken).
  (b) DETERMINISM (the property that licenses BLOCKING): two fresh
      run_matrix(seed) calls produce byte-identical matrices. Without this
      the lane must not gate; with it, a green run is reproducible.
  (c) sensitivity both ways: a mutation known to EVADE (unicode_confusables)
      is graded detection_retained=False (the lane CAN go red on a real
      evasion), and a mutation known to preserve detection (case_flip) is
      graded detection_retained=True (positive control -- the grader is not
      pathologically pessimistic).
  (d) the causal-join-break class: the segment_ips mutation keeps detection
      (rules key on arguments, not identity) but drops chain_fidelity -- the
      grader MUST record causal_join_broken=True and pass=False, proving the
      roadmap's "alert kept but join broken = FAILURE" rule is surfaced, not
      folded into a pass.
  (e) weakened-rule probe (roadmap verify: "a deliberately weakened rule
      shows a measurable drop"): load the REAL agent_prompt_injection_
      indicator rule from a temp rules dir with its condition weakened to
      never-match, detect the base chain's mcp event with the REAL detector,
      and assert the injection rule's fire DROPS while the STOCK detector
      still fires it -- the lane is sensitive to rule weakening.

Like the twin tests, importing layer_a pre-seeds the same module-collision
discipline (report.py's ws4-main pre-seed / lazy WS-8), so this module must
be imported as a standalone script, never under pytest.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
ADVERSARIAL = Path(__file__).resolve().parent
for p in (str(TWIN), str(SERVICES)):
    if p not in sys.path:
        sys.path.insert(0, p)

import mutate  # noqa: E402
import layer_a  # noqa: E402
import report  # noqa: E402
import scenario  # noqa: E402

SEED = 7
_INJECTION_RULE_ID = "3c4d5e6f-7081-48a9-9b1c-3d4e5f6a7b8d"
_FAILURES: list[str] = []


def _check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        _FAILURES.append(name)


def _grade_one(axis: str, variant: str) -> dict:
    """Grade ONE mutation (base vs mutated) with Layer A's REAL grader."""
    oracle = report._load_oracle()
    base = layer_a._baseline_grade(SEED, oracle)
    base_build = scenario._build_chain_payloads(SEED)
    mutated = mutate.apply_mutation(base_build[0], axis, variant, SEED)
    mut_grade = layer_a._grade_variant(mutated, SEED, oracle)
    return layer_a._cmp(axis, variant, base, mut_grade)


def _test_coverage(matrix: dict) -> None:
    cata = mutate.variant_specs(SEED)
    graded = matrix["overall"]["total_variants"]
    _check("(a) matrix grades the full catalogue (no silent skip)",
           graded == len(cata), f"graded={graded} catalogue={len(cata)}")
    base = matrix["baseline"]
    _check("(a) baseline is real (TPR=1.0, fidelity/FCR non-None)",
           base["tpr"] == 1.0 and base["chain_fidelity"] is not None
           and base["false_correlation_rate"] is not None,
           f"tpr={base['tpr']} fid={base['chain_fidelity']} fcr={base['false_correlation_rate']}")
    bad = [r for r in matrix["rows"] if r["pass"] and r["causal_join_broken"]]
    _check("(a) no row is both pass AND causal_join_broken",
           not bad, f"bad_rows={[r['variant'] for r in bad]}")


def _test_determinism(m1: dict) -> None:
    """Compare ``m1`` (the caller's already-computed matrix) against ONE
    fresh run_matrix(SEED) call -- two independent computations total (the
    determinism license), not three: main() no longer discards its own
    matrix just to recompute two more from scratch."""
    m2 = layer_a.run_matrix(SEED)
    d1 = json.dumps(m1, sort_keys=True)
    d2 = json.dumps(m2, sort_keys=True)
    same = d1 == d2
    _check("(b) matrix is byte-deterministic across two full runs (the license to block)",
           same,
           f"sha={hashlib.sha256(d1.encode()).hexdigest()[:12]} "
           f"rows={m1['overall']['total_variants']}")


def _test_sensitivity() -> None:
    ev = _grade_one("prompt", "unicode_confusables")
    _check("(c) evasion variant is graded detection_retained=False (can go red)",
           ev["detection_retained"] is False,
           f"det={ev['detection_retained']} tpr={ev['tpr']} fid={ev['chain_fidelity']}")
    ok_row = _grade_one("prompt", "case_flip")
    _check("(c) surviving variant is graded detection_retained=True (positive control)",
           ok_row["detection_retained"] is True,
           f"det={ok_row['detection_retained']} tpr={ok_row['tpr']}")


def _test_causal_join_break() -> None:
    row = _grade_one("network", "segment_ips")
    _check("(d) segment_ips keeps detection but drops chain_fidelity (0.6 -> lower)",
           row["detection_retained"] is True and row["chain_fidelity"] is not None
           and row["chain_fidelity"] < 0.6,
           f"det={row['detection_retained']} fid={row['chain_fidelity']} (base=0.6)")
    _check("(d) causal_join_broken=True AND pass=False (reported as FAILURE, never folded)",
           row["causal_join_broken"] is True and row["pass"] is False,
           f"join_broken={row['causal_join_broken']} pass={row['pass']}")


def _base_mcp_event() -> dict:
    """The REAL parsed OCSF event of the chain's agent_mcp_tool_call step."""
    chain = scenario.run_chain(SEED, strict=True)
    ev = next(e for e in chain.events if e.step == "agent_mcp_tool_call")
    event = copy.deepcopy(ev.event or {})
    siem = event.setdefault("siem", {})
    siem.update({"tenant": report._CHAIN_TENANT, "ingest_id": "twin:agent_mcp_tool_call"})
    return event


def _test_weakened_rule_drop() -> None:
    """(e) A deliberately weakened rule shows a measurable drop."""
    event = _base_mcp_event()

    stock = report._WS4_MOD.Detector(plugin_rule_dirs=[])
    _ev, stock_matched, _a = stock.process(copy.deepcopy(event))
    stock_ids = {r.id for r in stock_matched}
    _check("(e) STOCK detector fires the injection rule on the base mcp event",
           _INJECTION_RULE_ID in stock_ids,
           f"stock fired={sorted(stock_ids)}")

    rule_path = (ROOT / "contracts" / "rules" / "agent_prompt_injection_indicator.yml")
    if not rule_path.exists():
        _check("(e) rule file present for weakening", False, str(rule_path))
        return
    import yaml  # noqa: PLC0415

    # Weaken ONLY the injection rule in a full copy of the rules dir: its
    # condition is pointed at a class_uid the chain never produces, so the
    # rule can never fire while every other rule stays unchanged.
    with tempfile.TemporaryDirectory() as td:
        weak_dir = Path(td)
        for src in rule_path.parent.glob("*.yml"):
            if src.name != rule_path.name:
                dst = weak_dir / src.name
                dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
                continue
            rule = yaml.safe_load(src.read_text(encoding="utf-8"))
            rule["detection"]["condition"] = "never_fires"
            rule["detection"]["never_fires"] = {"class_uid": 9999}
            dst = weak_dir / src.name
            dst.write_text(yaml.safe_dump(rule, sort_keys=False), encoding="utf-8")
        weak_det = report._WS4_MOD.Detector(rules_dir=weak_dir, plugin_rule_dirs=[])
        _wev, weak_matched, _wa = weak_det.process(copy.deepcopy(event))
        weak_ids = {r.id for r in weak_matched}

    dropped = _INJECTION_RULE_ID not in weak_ids
    _check("(e) weakened rule drops the fire (measurable drop)",
           dropped and _INJECTION_RULE_ID in stock_ids,
           f"stock={_INJECTION_RULE_ID in stock_ids} weak={sorted(weak_ids)}")


def main() -> int:
    print(f"== Phase 4 Layer A acceptance test (seed={SEED}) ==")
    matrix = layer_a.run_matrix(SEED)  # one full real-pipeline matrix
    _test_coverage(matrix)
    _test_determinism(matrix)  # + one more fresh run = two independent runs
    _test_sensitivity()
    _test_causal_join_break()
    _test_weakened_rule_drop()

    print()
    if _FAILURES:
        for f in _FAILURES:
            print(f"  [FAIL] {f}")
        print(f"[FAIL] {len(_FAILURES)} Layer A check(s) failed")
        return 1
    print(f"[OK] all Layer A acceptance checks passed (seed={SEED})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())