"""layer_a -- WP-4-A LAYER A: the DETERMINISTIC, BLOCKING mutation lane.

Phase 4 success criterion, per mutation (roadmap + execution-breakdown):
    detection retained  AND  chain fidelity retained  AND  false-correlation
    rate unchanged.
    A mutation that KEEPS the alert but BREAKS the causal join is a FAILURE,
    not a pass -- that distinction is the whole reason Phase 4 sits after
    Phase 3 (the causal graph exists to grade it).

LAYER A'S CONTRACT (the property that makes it safe to BLOCK on)
    Everything is a pure function of ``seed``: same seed -> same variant set
    (eval/adversarial/mutate.py::variant_specs) -> same mutated payload
    bytes -> same graded matrix JSON. There is NO wall-clock, NO stochastic
    model, NO network in this lane. Because it is deterministic it can be a
    blocking CI lane: a nondeterministic lane would flake the gate, so the
    determinism assertion below is not cosmetic -- it is what licenses the
    lane's existence.

WHAT IT DOES (real pipeline, nothing stubbed)
    For every variant in the catalogue:
      1. apply_mutation(base_payloads, ...) -> mutated RAW payload list
      2. scenario.run_chain(seed, payload_source=...) -> the REAL WS-2 parse
         path on the mutated raw records (type_uid derived by the real
         parser; dead-letter behavior identical to the base chain)
      3. report._grade_chain -> the REAL detection run (WS-2 -> WS-4) + the
         REAL WS-8 correlator v2-graph grading (chain_fidelity, FCR,
         incident membership) -- the same functions the twin scorecard uses.
    Each variant's grade is compared against the UNMUTATED baseline grade:

      detection_retained  = oracle-expected rules that fired on the base
                            ALSO fired on the mutated chain at the same
                            steps (per-step attribution); TPR equal to base.
      fidelity_retained   = chain_fidelity(mutated) == chain_fidelity(base)
                            (a mutation must not degrade the causal join).
      fcr_unchanged       = false_correlation_rate(mutated) == FCR(base).
      PASS  = all three.
      causal_join_broken  = detection retained (alerts still fire) BUT
                            fidelity dropped -- THE failure this phase exists
                            to catch: the alert lured past the join. NEVER
                            folded into a pass. Usually produced by a
                            composition (identity.split + network.segment_ips
                            removes the shared entity bridge).

OUTPUT
    Matrix JSON (deterministic; written to --out, default
    eval/adversarial/out/matrix.latest.json -- GITIGNORED, same convention as
    eval/twin/report.latest.json). Plus a per-axis + per-composition summary.

    mutation_robustness = pass/total per axis AND overall -- the number Phase
    4 exists to publish (basis: harness-measured), computed from REAL grades.

BLOCKING FLOOR (main returns 1 when any fails):
    - the matrix covers EVERY catalogue variant (no silent skip);
    - determinism: two same-seed runs produce byte-identical matrices
      (proven inside test_layer_a.py too; here asserted for the written file
      shape: no wall-clock fields at all);
    - the baseline itself is real (TPR==1.0 for seed 7, fidelity 0.6, FCR
      1.0) -- a mutated matrix graded against a broken baseline is a lie;
    - causal-join-break rows are recorded as FAILURE, never pass.

STDLIB ONLY. This module performs NO stochastic sampling -- determinism is
the entire point (Layer C owns the adaptive adversary; it NEVER runs here).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADVERSARIAL = Path(__file__).resolve().parent
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"

for p in (str(TWIN), str(SERVICES)):
    if p not in sys.path:
        sys.path.insert(0, p)

import mutate  # noqa: E402  (the mutation engine; same dir as this module)
import report  # noqa: E402  (the twin scorecard machinery: _grade_chain etc.)
import scenario  # noqa: E402  (via report; kept explicit for run_chain)

OUT_DIR = ADVERSARIAL / "out"
DEFAULT_OUT = OUT_DIR / "matrix.latest.json"


# ---------------------------------------------------------------------------
# Grading
# ---------------------------------------------------------------------------
def _grade_variant(mutated: list, seed: int, oracle: dict) -> dict:
    """Run ONE mutated payload list through the REAL WS-2->WS-4->WS-8 path
    and grade it exactly like the twin scorecard does."""
    base_build = scenario._build_chain_payloads(seed)

    def _source(seed_ignored: int):
        return mutated, base_build[1], base_build[2], base_build[3]

    result = scenario.run_chain(seed, payload_source=_source, strict=False)
    return report._grade_chain(result, oracle)


def _baseline_grade(seed: int, oracle: dict) -> dict:
    return report._grade_chain(scenario.run_chain(seed, strict=True), oracle)


def _cmp(axis: str, variant: str, base: dict, mut: dict) -> dict:
    """Compare a mutated grade against the baseline grade; emit the three
    success criteria + the causal-join-break verdict."""
    b_tpr = base.get("tpr")
    m_tpr = mut.get("tpr")

    # detection retained: the mutated chain still fires every oracle-expected
    # rule at the same step (TPR identical), AND the alert SET is not missing
    # a step the base detected (alert_count identical). TPR equality alone
    # can hide a swap (one step lost, another gained); the count equality
    # closes that.
    b_fired_steps = {(a.get("step"), a.get("rule_id")) for a in base.get("fired", [])}
    m_fired_steps = {(a.get("step"), a.get("rule_id")) for a in mut.get("fired", [])}
    detection_retained = (
        b_tpr == m_tpr
        and b_fired_steps == m_fired_steps
        and len(base.get("fired", [])) == len(mut.get("fired", []))
    )

    b_fid, m_fid = base.get("chain_fidelity"), mut.get("chain_fidelity")
    fidelity_retained = (b_fid is not None and b_fid == m_fid)

    b_fcr, m_fcr = base.get("false_correlation_rate"), mut.get("false_correlation_rate")
    fcr_unchanged = (b_fcr is not None and b_fcr == m_fcr)

    passed = bool(detection_retained and fidelity_retained and fcr_unchanged)

    # THE failure class: alert kept but causal join broken.
    causal_join_broken = bool(
        detection_retained and (b_fid is not None) and (m_fid is not None)
        and m_fid < b_fid
    )

    return {
        "axis": axis,
        "variant": variant,
        "tpr": m_tpr,
        "chain_fidelity": m_fid,
        "false_correlation_rate": m_fcr,
        "fired_count": len(mut.get("fired", [])),
        "incident_count": mut.get("incident_count"),
        "incident_membership_ok": mut.get("incident_membership_ok"),
        "detection_retained": detection_retained,
        "fidelity_retained": fidelity_retained,
        "fcr_unchanged": fcr_unchanged,
        "pass": passed,
        "causal_join_broken": causal_join_broken,
    }


# ---------------------------------------------------------------------------
# Matrix
# ---------------------------------------------------------------------------
def run_matrix(seed: int = 7, out: Path = DEFAULT_OUT) -> dict:
    """Evaluate the WHOLE deterministic variant catalogue against the real
    pipeline; write + return the matrix dict (no wall-clock anywhere)."""
    oracle = report._load_oracle()
    base = _baseline_grade(seed, oracle)
    base_build = scenario._build_chain_payloads(seed)
    base_payloads = base_build[0]

    rows: list[dict] = []
    for spec in mutate.variant_specs(seed):
        mutated = mutate.apply_mutation(
            base_payloads, spec["axis"], spec["variant"], seed,
            composition=spec.get("composition"))
        m_grade = _grade_variant(mutated, seed, oracle)
        rows.append(_cmp(spec["axis"], spec["variant"], base, m_grade))

    # per-axis summary (composition is its own bucket)
    axes = sorted({r["axis"] for r in rows})
    per_axis: dict[str, dict] = {}
    for ax in axes:
        rs = [r for r in rows if r["axis"] == ax]
        per_axis[ax] = {
            "variants": len(rs),
            "pass": sum(1 for r in rs if r["pass"]),
            "causal_join_broken": sum(1 for r in rs if r["causal_join_broken"]),
            "detection_retained": sum(1 for r in rs if r["detection_retained"]),
            "fidelity_retained": sum(1 for r in rs if r["fidelity_retained"]),
            "fcr_unchanged": sum(1 for r in rs if r["fcr_unchanged"]),
            "robustness": round(sum(1 for r in rs if r["pass"]) / len(rs), 4) if rs else None,
        }

    total = len(rows)
    passed = sum(1 for r in rows if r["pass"])
    matrix = {
        "seed": seed,
        "basis": "harness-measured",
        "lanes": ["A"],
        "baseline": {
            "tpr": base.get("tpr"),
            "chain_fidelity": base.get("chain_fidelity"),
            "false_correlation_rate": base.get("false_correlation_rate"),
            "fired_count": len(base.get("fired", [])),
            "incident_count": base.get("incident_count"),
        },
        "rows": rows,
        "per_axis": per_axis,
        "overall": {
            "total_variants": total,
            "passed": passed,
            "mutation_robustness": round(passed / total, 4) if total else None,
        },
    }

    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(matrix, fh, indent=2)
    return matrix


_ROW_KEYS = frozenset({
    "axis", "variant", "tpr", "chain_fidelity", "false_correlation_rate",
    "fired_count", "incident_count", "incident_membership_ok",
    "detection_retained", "fidelity_retained", "fcr_unchanged",
    "pass", "causal_join_broken",
})


def _selfcheck(matrix: dict) -> bool:
    """Layer A's own blocking floor, checked on the returned matrix."""
    ok = True
    total = matrix["overall"]["total_variants"]
    catalogue = len(mutate.variant_specs(matrix["seed"]))
    if total != catalogue:
        print(f"[FAIL] matrix covers {total} variants, catalogue has {catalogue}")
        ok = False
    base = matrix["baseline"]
    if base["tpr"] != 1.0:
        print(f"[FAIL] baseline tpr == {base['tpr']!r}, expected 1.0 (broken baseline -> matrix is a lie)")
        ok = False
    if base["chain_fidelity"] is None or base["false_correlation_rate"] is None:
        print("[FAIL] baseline fidelity/FCR is None -- cannot grade mutations against it")
        ok = False
    # causal-join-break rows must be recorded as failures, never passes
    for r in matrix["rows"]:
        if r["causal_join_broken"] and r["pass"]:
            print(f"[FAIL] {r['axis']}:{r['variant']} is BOTH pass and causal_join_broken -- impossible")
            ok = False
        # Strict key-shape whitelist: the matrix must not ACCIDENTALLY grow a
        # wall-clock/nondeterministic field (a lazy heuristic substring scan
        # false-positives on words like "incidenTS"; a whitelist cannot).
        extra = set(r) - _ROW_KEYS
        if extra:
            print(f"[FAIL] row {r['axis']}:{r['variant']} has unexpected keys {sorted(extra)} "
                  "-- wall-clock fields would violate the lane's determinism license")
            ok = False
    return ok


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="layer_a", description="FENGARDE Phase-4 Layer A: deterministic blocking mutation lane")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    print(f"== Phase 4 Layer A: deterministic blocking mutation lane (seed={args.seed}) ==")
    matrix = run_matrix(seed=args.seed, out=args.out)

    m, o = matrix["overall"], matrix["per_axis"]
    print(f"baseline: TPR={matrix['baseline']['tpr']} fidelity={matrix['baseline']['chain_fidelity']} "
          f"FCR={matrix['baseline']['false_correlation_rate']}")
    print(f"variants graded: {m['total_variants']}  passed: {m['passed']}  "
          f"mutation_robustness={m['mutation_robustness']}")
    for ax in sorted(o):
        s = o[ax]
        print(f"  {ax:<12} pass={s['pass']}/{s['variants']} robustness={s['robustness']} "
              f"join_broken={s['causal_join_broken']} det={s['detection_retained']} "
              f"fid={s['fidelity_retained']} fcr={s['fcr_unchanged']}")

    ok = _selfcheck(matrix)
    if not ok:
        print("[FAIL] Layer A self-check failed -- see messages above.")
        return 1
    print(f"[OK] Layer A matrix written to {args.out} -- deterministic, all {m['total_variants']} "
          f"catalogue variants graded against the real WS-2->WS-4->WS-8 path.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())