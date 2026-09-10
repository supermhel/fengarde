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
def _grade_variant(mutated: list, seed: int, oracle: dict,
                    base_build: tuple | None = None) -> dict:
    """Run ONE mutated payload list through the REAL WS-2->WS-4->WS-8 path
    and grade it exactly like the twin scorecard does.

    ``base_build`` lets a caller iterating many variants (run_matrix) pass in
    its own already-computed scenario._build_chain_payloads(seed) result so
    this isn't rebuilt from scratch on every call -- it defaults to None
    (rebuild) so standalone callers (test_layer_a.py, adversary_c.py) keep
    working unchanged."""
    if base_build is None:
        base_build = scenario._build_chain_payloads(seed)

    def _source(seed_ignored: int):
        return mutated, base_build[1], base_build[2], base_build[3]

    result = scenario.run_chain(seed, payload_source=_source, strict=False)
    return report._grade_chain(result, oracle)


def _baseline_grade(seed: int, oracle: dict) -> dict:
    return report._grade_chain(scenario.run_chain(seed, strict=True), oracle)


# ---------------------------------------------------------------------------
# Public grading surface (review-fix, 2026-09-04)
#
# Layer C (adversary_c.py) grades single ad-hoc compositions through this
# same machinery and used to call _grade_variant/_baseline_grade/_cmp (and
# even layer_a.report._load_oracle(), two hops into another module's own
# private function) directly -- underscore-prefixed internals reached across
# a module boundary with no contract, untested by test_layer_a.py, breakable
# by any internal refactor with only a nightly-workflow failure to notice.
# These wrappers ARE that contract: a stable, tested surface for any caller
# outside this module. run_matrix/_selfcheck above keep using the private
# names directly (same module, no boundary to name); everything crossing
# the module boundary should go through these instead.
# ---------------------------------------------------------------------------

def load_oracle() -> dict:
    """Public one-hop re-export of report._load_oracle()."""
    return report._load_oracle()


def baseline_grade(seed: int, oracle: dict) -> dict:
    """Public wrapper for _baseline_grade -- see module note above."""
    return _baseline_grade(seed, oracle)


def grade_variant(mutated: list, seed: int, oracle: dict,
                   base_build: tuple | None = None) -> dict:
    """Public wrapper for _grade_variant -- see module note above."""
    return _grade_variant(mutated, seed, oracle, base_build=base_build)


def cmp_result(axis: str, variant: str, base: dict, mut: dict) -> dict:
    """Public wrapper for _cmp -- see module note above."""
    return _cmp(axis, variant, base, mut)


def _cmp(axis: str, variant: str, base: dict, mut: dict) -> dict:
    """Compare a mutated grade against the baseline grade; emit the three
    success criteria + the causal-join-break verdict.

    DETECTION SEMANTICS (rewritten 2026-09-10 after a review found the old
    definition measuring the wrong thing).

    The old test was fingerprint equality: the mutated run had to fire the
    IDENTICAL ``(step, rule_id)`` set AND the identical alert COUNT. Both
    halves conflated "the attack stopped being caught" with "the attack got
    caught differently", and the harness's own catalogue contains mutations
    that CANNOT preserve either by construction:

      - ``protocol/opcua_path`` re-shapes an OT write from Modbus to OPC UA.
        A different protocol is parsed by a different parser and can only
        ever fire a different rule id. Under fingerprint equality that is
        an automatic "evasion" even in the counterfactual where an OPC UA
        rule caught it perfectly.
      - ``telemetry/duplicate`` delivers each event twice. Every step is
        still caught, twice; the count doubles. Under count equality that
        is an automatic "evasion" even though nothing evaded -- and the
        only way to make it "pass" would be re-adding content-hash event
        dedup, which this project deliberately reverted (FIX 21, SSOT.md)
        because it collapsed genuinely-repeated real attacks.

    So the criterion is now the actual security question: **is every attack
    step the baseline caught still caught?** A step going dark is the
    failure. Which rule caught it, and how many alerts it produced, are
    recorded as SEPARATE INFORMATIONAL fields (``rule_identity_changed``,
    ``alert_volume_ratio``) so a protocol swap or a duplicate delivery is
    visible in the matrix without being mislabeled an evasion.

    ``steps_lost`` names exactly which steps went dark, so a failure is
    actionable instead of a bare False.
    """
    b_tpr = base.get("tpr")
    m_tpr = mut.get("tpr")

    b_fired, m_fired = base.get("fired", []), mut.get("fired", [])
    b_steps = {a.get("step") for a in b_fired}
    m_steps = {a.get("step") for a in m_fired}
    steps_lost = sorted(s for s in (b_steps - m_steps) if s is not None)

    detection_retained = (
        b_tpr is not None
        and b_tpr == m_tpr
        and not steps_lost
    )

    # Informational only -- NEVER part of pass/fail. A mutation that keeps
    # every step covered but by a different rule, or with a different alert
    # volume, is a real observation worth publishing, not a failure.
    b_pairs = {(a.get("step"), a.get("rule_id")) for a in b_fired}
    m_pairs = {(a.get("step"), a.get("rule_id")) for a in m_fired}
    rule_identity_changed = bool(b_pairs != m_pairs)
    alert_volume_ratio = (round(len(m_fired) / len(b_fired), 4)
                           if b_fired else None)

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
        "fired_count": len(m_fired),
        "incident_count": mut.get("incident_count"),
        "incident_membership_ok": mut.get("incident_membership_ok"),
        "detection_retained": detection_retained,
        "steps_lost": steps_lost,
        "rule_identity_changed": rule_identity_changed,
        "alert_volume_ratio": alert_volume_ratio,
        "fidelity_retained": fidelity_retained,
        "fcr_unchanged": fcr_unchanged,
        "pass": passed,
        "causal_join_broken": causal_join_broken,
    }


# ---------------------------------------------------------------------------
# Baseline quality
# ---------------------------------------------------------------------------
# mutation_robustness is a RELATIVE measure: every row is graded against the
# unmutated baseline's own numbers. That makes the headline meaningless --
# actively misleading -- without the baseline's quality stated next to it. A
# baseline that already fails to reconstruct 40% of the causal chain, and
# already joins every relationship the oracle forbids, will happily report a
# high "robustness" simply because a mutation cannot degrade what was never
# there. Added 2026-09-10 after a review pointed out the harness was being
# quoted as "0.86 robust" with these two numbers buried one line above.
_FIDELITY_FLOOR = 0.8   # below this, the causal join is materially incomplete
_FCR_CEILING = 0.25     # above this, forbidden pairs are being joined freely


def _baseline_quality(base: dict) -> dict:
    """Assess the reference the whole matrix is graded against, and say
    plainly when it is too weak to carry a robustness claim."""
    fid = base.get("chain_fidelity")
    fcr = base.get("false_correlation_rate")
    caveats = []
    if fid is not None and fid < _FIDELITY_FLOOR:
        caveats.append(
            f"chain_fidelity={fid} (< {_FIDELITY_FLOOR}): the UNMUTATED chain already fails to "
            f"reconstruct {round((1 - fid) * 100)}% of its own causal links, so "
            "'fidelity_retained' can only ever mean 'no WORSE than an already-incomplete join'")
    if fcr is not None and fcr > _FCR_CEILING:
        caveats.append(
            f"false_correlation_rate={fcr} (> {_FCR_CEILING}): the UNMUTATED chain already joins "
            "relationships the oracle explicitly forbids, so 'fcr_unchanged' cannot "
            "distinguish a mutation that induces false correlation from one that "
            "merely fails to make an already-saturated number worse")
    return {
        "chain_fidelity": fid,
        "false_correlation_rate": fcr,
        "fidelity_floor": _FIDELITY_FLOOR,
        "fcr_ceiling": _FCR_CEILING,
        "sound_reference": not caveats,
        "caveats": caveats,
        "interpretation": (
            "mutation_robustness is measured RELATIVE to this baseline. With the caveats "
            "above outstanding it is a regression signal (did THIS change make things "
            "worse?), NOT an absolute claim about robustness against real adversaries."
            if caveats else
            "baseline is sound on both axes; mutation_robustness carries its plain meaning."
        ),
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
        m_grade = _grade_variant(mutated, seed, oracle, base_build=base_build)
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
        "baseline_quality": _baseline_quality(base),
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


def run_multi_seed(seeds: list, out_dir: Path = OUT_DIR) -> dict:
    """Run the full catalogue across SEVERAL seeds and report the spread.

    Why (2026-09-10): the blocking lane runs one seed, which is the right
    call for a gate (fast, byte-deterministic). But a single seed is a
    single POINT -- quoting it as "mutation_robustness" implies a
    population estimate the harness never measured. This mode makes the
    spread explicit and, more importantly, separates:

      seed_stable   -- a variant that passes (or fails) on EVERY seed. A
                       stable failure is a real, reproducible gap; a stable
                       pass is real coverage.
      seed_dependent -- a variant whose verdict CHANGES with the seed. Its
                       single-seed verdict was luck in either direction,
                       and any claim resting on it is unsupported.

    Determinism is preserved: each seed's matrix is byte-deterministic and
    the seed list is explicit, so this whole aggregate is reproducible.

    MEASURED LIMITATION, stated here because the output is otherwise
    actively misleading (2026-09-10, found by running this mode the day it
    was written): across seeds 7/11/13/17 every verdict is IDENTICAL, and
    that is not evidence of robustness. ``scenario._build_chain_payloads``
    derives only IDENTIFIERS and sensor values from the seed (session id,
    ingest/trace ids, PLCSim readings, account choice). The attack
    STRUCTURE is hardcoded: the same 7 steps in the same order, a module-
    constant ``_ATTACKER_IP``, the same tool names, the same injection
    phrase, the same out-of-range Modbus address -- so the same rules fire
    over the same causal topology every time. Grading depends on exactly
    those things, so the seed CANNOT move a grade.

    Therefore: a flat spread here means "the seed is not a source of
    variation", NOT "the result generalizes". Real generality needs
    SCENARIO diversity -- additional attack shapes (lateral movement,
    staged exfil, insider misuse) with their own oracles -- which this
    harness does not yet have. Do not quote a flat multi-seed spread as
    evidence of anything.
    """
    per_seed = {}
    for s in seeds:
        per_seed[s] = run_matrix(seed=s, out=out_dir / f"matrix.seed{s}.json")

    verdicts: dict = {}
    for s, m in per_seed.items():
        for r in m["rows"]:
            verdicts.setdefault(f"{r['axis']}/{r['variant']}", {})[s] = r["pass"]

    seed_stable_pass, seed_stable_fail, seed_dependent = [], [], []
    for key, by_seed in sorted(verdicts.items()):
        results = set(by_seed.values())
        if results == {True}:
            seed_stable_pass.append(key)
        elif results == {False}:
            seed_stable_fail.append(key)
        else:
            seed_dependent.append({
                "variant": key,
                "passed_on": sorted(s for s, ok in by_seed.items() if ok),
                "failed_on": sorted(s for s, ok in by_seed.items() if not ok),
            })

    scores = [m["overall"]["mutation_robustness"] for m in per_seed.values()]
    return {
        "basis": "harness-measured",
        "seeds": list(seeds),
        "per_seed_robustness": {s: m["overall"]["mutation_robustness"]
                                 for s, m in per_seed.items()},
        "robustness_min": min(scores) if scores else None,
        "robustness_max": max(scores) if scores else None,
        "robustness_mean": round(sum(scores) / len(scores), 4) if scores else None,
        "seed_stable_pass": seed_stable_pass,
        "seed_stable_fail": seed_stable_fail,
        "seed_dependent": seed_dependent,
        "baseline_quality": {s: m["baseline_quality"]["sound_reference"]
                              for s, m in per_seed.items()},
        "seed_varies": "identifiers + sensor values only (session/ingest/trace ids, PLCSim "
                        "readings, account choice) -- NOT attack structure",
        "seed_does_not_vary": "step count/order, attacker IP (module constant), tool names, "
                               "injection phrase, Modbus address, which rules fire, causal topology",
        "interpretation": (
            "A seed_stable_fail is a reproducible gap worth fixing. A seed_dependent row means "
            "the single-seed verdict was luck -- do not quote it either way. CRITICAL CAVEAT: "
            "the seed varies only identifiers and sensor values, never attack structure, so a "
            "FLAT spread across seeds is the expected result and is NOT evidence of robustness "
            "or generality. Real generality requires additional SCENARIO shapes with their own "
            "oracles, which this harness does not yet have."
        ),
    }


_ROW_KEYS = frozenset({
    "axis", "variant", "tpr", "chain_fidelity", "false_correlation_rate",
    "fired_count", "incident_count", "incident_membership_ok",
    "detection_retained", "steps_lost", "rule_identity_changed",
    "alert_volume_ratio", "fidelity_retained", "fcr_unchanged",
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
    ap.add_argument("--seeds", type=str, default=None,
                     help="comma-separated seeds; runs the spread analysis instead of the "
                          "single-seed gate (e.g. --seeds 7,11,13,17)")
    args = ap.parse_args(argv)

    if args.seeds:
        seeds = [int(s) for s in args.seeds.split(",") if s.strip()]
        print(f"== Phase 4 Layer A: multi-seed spread (seeds={seeds}) ==")
        agg = run_multi_seed(seeds)
        out_path = OUT_DIR / "matrix.multiseed.json"
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(agg, fh, indent=2)
        print(f"robustness per seed: {agg['per_seed_robustness']}")
        print(f"range: [{agg['robustness_min']}, {agg['robustness_max']}]  "
              f"mean={agg['robustness_mean']}")
        print(f"seed-stable passes: {len(agg['seed_stable_pass'])}")
        print(f"seed-stable FAILURES ({len(agg['seed_stable_fail'])}) -- reproducible gaps:")
        for v in agg["seed_stable_fail"]:
            print(f"  - {v}")
        if agg["seed_dependent"]:
            print(f"SEED-DEPENDENT ({len(agg['seed_dependent'])}) -- single-seed verdict was luck, "
                  "do not quote either way:")
            for d in agg["seed_dependent"]:
                print(f"  - {d['variant']}: passed on {d['passed_on']}, failed on {d['failed_on']}")
        else:
            print("SEED-DEPENDENT (0) -- every verdict reproduced across all seeds")
            print("  NOTE: this is the EXPECTED result and is NOT evidence of robustness.")
            print(f"  seed varies:      {agg['seed_varies']}")
            print(f"  seed does NOT vary: {agg['seed_does_not_vary']}")
            print("  => a flat spread means the seed cannot move a grade. Generality needs")
            print("     additional SCENARIO shapes, not more seeds. Not yet built.")
        print(f"=> {agg['interpretation']}")
        print(f"[OK] multi-seed spread written to {out_path}")
        return 0

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

    # Failures name the step that went dark, so a red row is actionable
    # rather than a bare False.
    for r in matrix["rows"]:
        if r["steps_lost"]:
            print(f"  [DARK] {r['axis']}/{r['variant']}: steps no longer detected: "
                  f"{', '.join(r['steps_lost'])}")
        elif r["causal_join_broken"]:
            print(f"  [JOIN] {r['axis']}/{r['variant']}: every step still detected, causal join "
                  f"broke ({matrix['baseline']['chain_fidelity']} -> {r['chain_fidelity']})")

    # The headline is relative; print what it is relative TO, loudly.
    bq = matrix["baseline_quality"]
    if not bq["sound_reference"]:
        print("\n[BASELINE TOO WEAK TO CARRY AN ABSOLUTE ROBUSTNESS CLAIM]")
        for c in bq["caveats"]:
            print(f"  - {c}")
        print(f"  => {bq['interpretation']}")

    ok = _selfcheck(matrix)
    if not ok:
        print("[FAIL] Layer A self-check failed -- see messages above.")
        return 1
    print(f"[OK] Layer A matrix written to {args.out} -- deterministic, all {m['total_variants']} "
          f"catalogue variants graded against the real WS-2->WS-4->WS-8 path.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())