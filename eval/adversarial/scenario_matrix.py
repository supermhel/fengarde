"""scenario_matrix -- the Phase-4 mutation lane run over EVERY attack storyline.

WHY THIS EXISTS (2026-10-01)
    ``layer_a.py`` grades a 36-variant catalogue against one chain. Whatever it
    reports is a statement about that chain. This module runs the same
    criterion -- detection retained, chain fidelity retained, false-correlation
    unchanged, now also *order retained* and *decoys not absorbed* -- over each
    storyline in ``eval/twin/scenario_registry`` with scenario-agnostic
    operators (``mutate_generic``), so a weakness that only exists on one attack
    shape cannot hide behind a pass on another, and a pass that only exists on
    one shape cannot be quoted as general.

WHAT IT DELIBERATELY DOES NOT DO
    It does not replace layer_a's AI-to-OT-specific catalogue (those operators
    encode domain knowledge -- homoglyph folds, OPC UA re-shaping -- that has no
    analogue elsewhere). It adds the dimension that catalogue could not:
    other attack shapes, and the volume/window/pivot evasions that need them.

HONESTY RULES
    * A variant that changes no event is ``applicable=False`` and is excluded
      from every pass rate. "Mutated nothing" never grades as a pass.
    * Pass rates are reported PER SCENARIO. The pooled number is printed last
      and labelled as a pooled number; it is not the headline.
    * A scenario whose own baseline is weak (see ``_scenario_baseline_quality``)
      says so next to its numbers.

BLOCKING FLOOR (``main`` returns 1 on any failure)
    - every scenario's baseline TPR is 1.0 (a matrix over a broken baseline lies);
    - two same-seed runs are byte-identical (the lane is deterministic);
    - positive control: ``timing/shift_1h`` (a pure replay offset) PASSES on
      every scenario -- the lane can say yes;
    - negative control: dropping a detected step turns that step DARK on every
      scenario -- the lane can say no;
    - every scenario has at least one applicable variant per axis it claims.

METRIC CONTROLS (2026-10-02) -- a SEPARATE section, never pooled
    ``order_controls`` replays each storyline time-MIRRORED (the attack happens
    backwards) and checks that the order metrics say no while the legacy join
    metrics -- which never read a clock -- do not move. That is a control for the
    INSTRUMENT, so it is printed beside the product rows under ``metric_controls``
    and is never counted in a pass rate or in ``mutation_robustness`` (an earlier
    time-rewriting ``swap_first_two_steps`` variant was removed from the product
    catalogue because failing it said nothing about the product). Its self-check
    fails the lane when the control cannot say yes or cannot say no.

STDLIB ONLY. Deterministic: no wall clock, no network, no sampling.
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
for _p in (str(ADVERSARIAL), str(TWIN), str(SERVICES)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import layer_a  # noqa: E402
import mutate_generic  # noqa: E402
import scenario_registry as reg  # noqa: E402

OUT_DIR = ADVERSARIAL / "out"
DEFAULT_OUT = OUT_DIR / "scenario_matrix.latest.json"

_FIDELITY_FLOOR = layer_a._FIDELITY_FLOOR
_FCR_CEILING = layer_a._FCR_CEILING


# Everything whose change can change a matrix cell. ``technique_matrix`` refuses an artefact whose
# fingerprint differs from the live tree: ``out/`` is gitignored, so without this a stale file from an
# earlier checkout (or a run restricted to one scenario / another seed) would be read as current.
_FINGERPRINT_GLOBS = (
    "contracts/rules/*.yml", "contracts/allowlists/*", "contracts/enrichment/*", "contracts/scoring.yaml",
    "eval/twin/*.py", "eval/twin/*.yaml",
    "eval/adversarial/mutate_generic.py", "eval/adversarial/scenario_matrix.py",
    "eval/adversarial/layer_a.py", "eval/adversarial/probe_session.py",
    "services/ws2-normalization/*.py", "services/ws2-normalization/parsers/*.py",
    "services/ws2-normalization/enrichment/*.py",
    "services/ws4-detection/*.py", "services/shared/*.py", "services/ws8-correlation/*.py",
)


def inputs_fingerprint(root: Path = ROOT) -> str:
    """sha256 over the files in ``_FINGERPRINT_GLOBS`` (path + content, CRLF folded to LF so a
    Windows checkout and a Linux one agree). Test files are excluded: editing a test cannot change
    what the matrix measures."""
    import hashlib  # noqa: PLC0415
    h = hashlib.sha256()
    files: set = set()
    for pattern in _FINGERPRINT_GLOBS:
        files.update(p for p in root.glob(pattern) if p.is_file())
    for p in sorted(files):
        rel = p.relative_to(root).as_posix()
        if "/__pycache__/" in rel or p.name.startswith("test_") or p.suffix in (".pyc", ".json"):
            continue
        h.update(rel.encode())
        h.update(b"\0")
        h.update(p.read_bytes().replace(b"\r\n", b"\n"))
        h.update(b"\0")
    return h.hexdigest()


def _fired_pairs(grade: dict) -> list:
    """Sorted ``[step, rule_id]`` pairs the run fired (the unit the technique matrix reads)."""
    return sorted({(a.get("step"), a.get("rule_id")) for a in grade.get("fired", [])})


def _dependents(oracle: dict, step: str) -> set:
    """Steps whose detection legitimately depends on ``step``'s telemetry (oracle
    ``step_dependencies``: ``{dependent: [context steps]}``). Dropping a context step blinds its
    dependents by design (no victim login, no impossible travel), which is the lane's negative
    control for the CONTEXT step, not collateral damage."""
    deps = oracle.get("step_dependencies") or {}
    return {dep for dep, needs in deps.items() if step in (needs or [])}


def _reattribute_displaced(row: dict, oracle: dict, base: dict, grade: dict) -> None:
    """A detection that needs TWO steps' telemetry fires on whichever event arrives (or sorts) LAST.

    Impossible travel is the case: the alert is raised by the second country's login. Deliver the
    stream backwards and the second country is the account's own earlier session, so the same
    rule fires, on the same account, one step away -- on the CONTEXT step the oracle declares in
    ``step_dependencies``. ``layer_a.cmp_result`` reads "no alert at the step's own events" as
    "step lost", which would score a still-working detection as a failure of the product.

    For a step the oracle says depends on context steps, an expected rule that fired at a
    DEPENDENCY step of the mutated run counts as the step's detection (reported in
    ``steps_displaced``, never silent). ``steps_lost`` / ``tactic_lost`` / ``detection_retained`` /
    ``pass`` are recomputed from that. A storyline with no ``step_dependencies`` never reaches this
    code, so every pre-existing number is untouched."""
    deps_of = oracle.get("step_dependencies") or {}
    if not deps_of or not row.get("steps_lost"):
        return
    dp = oracle.get("detection_points") or {}
    displaced = []
    for step in list(row["steps_lost"]):
        deps = set(deps_of.get(step) or [])
        exp = {r.get("rule_id") for r in ((dp.get(step) or {}).get("expected_rules") or [])}
        if deps and any(a.get("step") in deps and a.get("rule_id") in exp for a in grade.get("fired", [])):
            displaced.append(step)
    if not displaced:
        return
    row["steps_displaced"] = sorted(displaced)
    row["steps_lost"] = [s for s in row["steps_lost"] if s not in displaced]
    row["tactic_lost"] = [s for s in row.get("tactic_lost", []) if s not in displaced]
    row["expected_rule_lost_steps"] = [s for s in row.get("expected_rule_lost_steps", []) if s not in displaced]
    b_cov = set(base.get("tactic_covered_steps") or [])
    coverage_ok = (not row["tactic_lost"]) if b_cov else (base.get("tpr") == row.get("tpr"))
    row["detection_retained"] = bool(base.get("tpr") is not None and coverage_ok and not row["steps_lost"])
    row["pass"] = bool(row["detection_retained"] and row["fidelity_retained"] and row["fcr_unchanged"]
                       and row["order_retained"] and row["decoy_clean"])
    row["causal_join_broken"] = bool(
        row["detection_retained"] and base.get("chain_fidelity") is not None
        and row.get("chain_fidelity") is not None and row["chain_fidelity"] < base["chain_fidelity"])


def _scenario_baseline_quality(base: dict) -> dict:
    """Same standard as layer_a._baseline_quality, applied per scenario."""
    return layer_a._baseline_quality(base)


def _expected_lost(oracle: dict, base: dict, mut: dict) -> list:
    """Steps whose ORACLE-EXPECTED rule fired on the baseline but no longer
    fires -- even if some other rule still alerts at that step. (``steps_lost``
    only sees a step with NO alert at all, so a step that goes from its
    intended detection to an incidental one looked fine.)"""
    dp = oracle.get("detection_points") or {}
    lost = []
    for step, pt in dp.items():
        exp = {r.get("rule_id") for r in (pt.get("expected_rules") or [])}
        if not exp:
            continue
        b = {a["rule_id"] for a in base.get("fired", []) if a.get("step") == step} & exp
        m = {a["rule_id"] for a in mut.get("fired", []) if a.get("step") == step} & exp
        if b and not m:
            lost.append(step)
    return sorted(lost)


def run_negative_twins(sdef, seed: int = 7) -> list:
    """Run every ``NegativeTwin`` the storyline declares (detection leg only: WS-2 -> WS-4 through
    ``probe_session.FastProbe``, whose parity with the slow path is proven in ``probe_session``).

    For each twin the SAME builder is run twice: ``restored=False`` (one attribute just below what
    the rule needs -- the rules in ``rule_ids`` must stay SILENT at the twin's step) and
    ``restored=True`` (the attribute put back -- they must FIRE). The pair is the control: a
    silent negative means something only because its restored twin is seen to fire, so a deaf
    harness cannot pass. ``ok`` needs both halves."""
    import probe_session  # noqa: PLC0415 - imports the engine; keep it off module import
    probe = probe_session.default_probe()
    out = []
    for tw in sdef.negatives:
        fired: dict = {}
        for restored in (False, True):
            payloads = tw.build(seed, restored)[0]
            alerts = probe.detect(probe_session.payloads_to_pairs(payloads))
            fired[restored] = sorted({a["rule_id"] for a in alerts if a.get("step") == tw.step}
                                     & set(tw.rule_ids))
        out.append({
            "name": tw.name, "step": tw.step, "attribute": tw.attribute,
            "rule_ids": sorted(tw.rule_ids),
            "negative_fired": fired[False], "restored_fired": fired[True],
            "negative_silent": not fired[False],
            "restored_fires": set(fired[True]) == set(tw.rule_ids),
            "ok": (not fired[False]) and set(fired[True]) == set(tw.rule_ids),
        })
    return out


def run_scenario(sdef, seed: int = 7) -> dict:
    """Grade the full generic variant list against ONE storyline."""
    oracle = reg.load_oracle(sdef)
    base = reg.grade(sdef, seed)
    base_payloads = sdef.build(seed)[0]
    rows: list = []
    for axis, variant in mutate_generic.variants_for(sdef):
        mutated, changed = mutate_generic.apply(
            base_payloads, axis, variant, seed=seed, sdef=sdef)
        if changed == 0:
            rows.append({"axis": axis, "variant": variant, "applicable": False,
                         "changed_events": 0, "pass": None})
            continue

        def _src(_seed, mutated=mutated):
            return mutated, {}, {}, None

        grade = reg.grade(sdef, seed, payload_source=_src, strict=False)
        row = layer_a.cmp_result(axis, variant, base, grade)
        row["applicable"] = True
        row["changed_events"] = changed
        row["expected_rule_lost_steps"] = _expected_lost(oracle, base, grade)
        row["fired_pairs"] = [list(p) for p in _fired_pairs(grade)]
        _reattribute_displaced(row, oracle, base, grade)
        if axis == "loss":
            # A log source going dark cannot be "detected through", so losing
            # the dropped step's own detection is not a product failure -- it
            # is the lane's NEGATIVE CONTROL. What IS a failure is COLLATERAL:
            # any OTHER step going dark because one source vanished. A step that
            # DEPENDS on the dropped one by the oracle's own declaration
            # (``step_dependencies``: impossible travel needs the victim's earlier
            # login) goes dark with it by design, so it is not collateral either.
            dropped = variant[len("drop_"):]
            expected_dark = {dropped} | _dependents(oracle, dropped)
            row["collateral_lost_steps"] = [s for s in row["steps_lost"] if s not in expected_dark]
            row["pass"] = bool(not row["collateral_lost_steps"]
                               and row["order_retained"] and row["decoy_clean"])
        rows.append(row)

    applicable = [r for r in rows if r["applicable"]]
    per_axis: dict = {}
    for ax in sorted({r["axis"] for r in rows}):
        rs = [r for r in rows if r["axis"] == ax]
        ap = [r for r in rs if r["applicable"]]
        per_axis[ax] = {
            "variants": len(rs),
            "applicable": len(ap),
            "pass": sum(1 for r in ap if r["pass"]),
            "robustness": round(sum(1 for r in ap if r["pass"]) / len(ap), 4) if ap else None,
        }
    passed = sum(1 for r in applicable if r["pass"])
    return {
        "scenario": sdef.name,
        "summary": sdef.summary,
        "seed": seed,
        "baseline": {
            "tpr": base.get("tpr"),
            "chain_fidelity": base.get("chain_fidelity"),
            "false_correlation_rate": base.get("false_correlation_rate"),
            "directional_discrimination": base.get("directional_discrimination"),
            "alert_order_ok": base.get("alert_order_ok"),
            "incident_count": base.get("incident_count"),
            "incident_membership_ok": base.get("incident_membership_ok"),
            "fired_alerts": base.get("fired_alerts"),
            "mttd_seconds": base.get("mttd_seconds"),
            "campaign_count": base.get("campaign_count"),
            "campaign_full_coverage": base.get("campaign_full_coverage"),
            "fired_pairs": [list(p) for p in _fired_pairs(base)],
        },
        "baseline_quality": _scenario_baseline_quality(base),
        "negative_twins": run_negative_twins(sdef, seed),
        "rows": rows,
        "per_axis": per_axis,
        "overall": {
            "variants": len(rows),
            "applicable": len(applicable),
            "not_applicable": len(rows) - len(applicable),
            "passed": passed,
            "mutation_robustness": round(passed / len(applicable), 4) if applicable else None,
        },
    }


def run_all(seed: int = 7, scenarios: list | None = None) -> dict:
    sdefs = [reg.get(n) for n in scenarios] if scenarios else list(reg.ALL)
    per = {s.name: run_scenario(s, seed) for s in sdefs}
    tot_ap = sum(m["overall"]["applicable"] for m in per.values())
    tot_pass = sum(m["overall"]["passed"] for m in per.values())
    return {
        "seed": seed,
        "basis": "harness-measured",
        # What this artefact covers. ``technique_matrix`` asserts seed == 7 and
        # scenario_list == the whole registry: ``--scenario X`` and ``--seed 11`` write the same
        # default path, and ``out/`` is gitignored, so the file alone cannot say what it is.
        "scenario_list": [s.name for s in sdefs],
        "inputs_fingerprint": inputs_fingerprint(),
        "scenarios": per,
        "pooled": {
            "applicable": tot_ap,
            "passed": tot_pass,
            "mutation_robustness": round(tot_pass / tot_ap, 4) if tot_ap else None,
            "note": "pooled across storylines for convenience only; the per-scenario "
                    "numbers are the result, and a pooled pass rate hides which attack "
                    "shape fails",
        },
    }


def run_multi_seed(seeds: list, scenarios: list | None = None) -> dict:
    """Per-scenario spread across seeds. Unlike layer_a's multi-seed mode, the
    seed here varies attack STRUCTURE (attacker address, burst sizes, account
    and host names), so a flat spread is a weak claim and a moving one is real
    information."""
    per_seed = {s: run_all(s, scenarios) for s in seeds}
    out: dict = {"seeds": list(seeds), "scenarios": {}}
    for name in next(iter(per_seed.values()))["scenarios"]:
        verdicts: dict = {}
        for s, m in per_seed.items():
            for r in m["scenarios"][name]["rows"]:
                if r["applicable"]:
                    verdicts.setdefault(f"{r['axis']}/{r['variant']}", {})[s] = r["pass"]
        stable_pass = sorted(k for k, v in verdicts.items() if set(v.values()) == {True})
        stable_fail = sorted(k for k, v in verdicts.items() if set(v.values()) == {False})
        dependent = sorted(k for k, v in verdicts.items() if len(set(v.values())) > 1)
        out["scenarios"][name] = {
            "per_seed_robustness": {s: per_seed[s]["scenarios"][name]["overall"]["mutation_robustness"]
                                    for s in seeds},
            "stable_pass": stable_pass,
            "stable_fail": stable_fail,
            "seed_dependent": dependent,
        }
    return out


def run_metric_controls(seed: int = 7, scenarios: list | None = None) -> dict:
    """The reversed-order control table per storyline (see the module docstring). Kept OUT of
    ``run_all`` so the per-scenario rows, the pooled number and every existing artefact are
    byte-for-byte what they were."""
    import order_controls  # noqa: PLC0415  (imports the harness; keep it off module import)
    sdefs = [reg.get(n) for n in scenarios] if scenarios else list(reg.ALL)
    return {
        "note": "metric controls for the order metrics; NOT product mutations, never pooled into "
                "a pass rate or mutation_robustness",
        "scenarios": {s.name: order_controls.run_order_controls(s, seed) for s in sdefs},
    }


def _selfcheck(result: dict) -> bool:
    ok = True
    if "metric_controls" in result:
        import order_controls  # noqa: PLC0415
        for name, ctl in result["metric_controls"]["scenarios"].items():
            for problem in order_controls.controls_ok(ctl):
                print(f"[FAIL] metric control: {problem}")
                ok = False
    for name, m in result["scenarios"].items():
        if m["baseline"]["tpr"] != 1.0:
            print(f"[FAIL] {name}: baseline tpr={m['baseline']['tpr']!r}, expected 1.0 "
                  "(a matrix over a broken baseline is a lie)")
            ok = False
        rows = {(r["axis"], r["variant"]): r for r in m["rows"]}
        pos = rows.get(("timing", "shift_1h"))
        if not pos or not pos["applicable"] or not pos["pass"]:
            print(f"[FAIL] {name}: positive control timing/shift_1h did not PASS "
                  f"({pos!r}) -- the lane cannot say yes")
            ok = False
        # negative control: dropping a step that raised an alert must make that
        # step dark. Without this the lane could report "graceful degradation"
        # simply because it never removed anything it was detecting.
        dark_seen = any(r["applicable"] and r.get("steps_lost") and r["axis"] == "loss"
                        for r in m["rows"])
        if not dark_seen:
            print(f"[FAIL] {name}: no loss/drop_<step> variant turned a step DARK -- "
                  "the lane cannot say no")
            ok = False
        if m["overall"]["applicable"] == 0:
            print(f"[FAIL] {name}: zero applicable variants -- nothing was tested")
            ok = False
        for tw in m.get("negative_twins", []):
            if not tw["negative_silent"]:
                print(f"[FAIL] {name}: negative twin {tw['name']!r} ({tw['attribute']}) fired "
                      f"{tw['negative_fired']} at {tw['step']} -- the boundary is not where the oracle says")
                ok = False
            if not tw["restored_fires"]:
                print(f"[FAIL] {name}: positive twin of {tw['name']!r} (attribute restored) fired "
                      f"{tw['restored_fired']} at {tw['step']}, wanted {tw['rule_ids']} -- the harness "
                      "is deaf to this rule, so the silent negative twin proves nothing")
                ok = False
    return ok


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(prog="scenario_matrix")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--seeds", type=str, default=None,
                    help="comma-separated seeds: per-scenario spread instead of the gate")
    ap.add_argument("--scenario", action="append", default=None,
                    help="restrict to one registered scenario (repeatable)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    if args.seeds:
        seeds = [int(x) for x in args.seeds.split(",") if x.strip()]
        agg = run_multi_seed(seeds, args.scenario)
        print(f"== scenario matrix: per-scenario spread over seeds {seeds} ==")
        for name, m in agg["scenarios"].items():
            print(f"  {name}: robustness per seed {m['per_seed_robustness']}")
            for k in m["stable_fail"]:
                print(f"      stable FAIL   {k}")
            for k in m["seed_dependent"]:
                print(f"      SEED-DEPENDENT {k}  (single-seed verdict was luck)")
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with open(OUT_DIR / "scenario_matrix.multiseed.json", "w", encoding="utf-8") as fh:
            json.dump(agg, fh, indent=2)
        return 0

    print(f"== Phase 4: mutation lane over every attack storyline (seed={args.seed}) ==")
    result = run_all(args.seed, args.scenario)
    for name, m in result["scenarios"].items():
        b, o = m["baseline"], m["overall"]
        print(f"\n[{name}] {m['summary']}")
        print(f"  baseline: TPR={b['tpr']} fidelity={b['chain_fidelity']} FCR={b['false_correlation_rate']} "
              f"order_ok={b['alert_order_ok']} incidents={b['incident_count']} "
              f"membership_ok={b['incident_membership_ok']} MTTD={b['mttd_seconds']}s")
        print(f"  variants: {o['variants']}  applicable: {o['applicable']}  "
              f"not-applicable: {o['not_applicable']}  passed: {o['passed']}  "
              f"robustness={o['mutation_robustness']}")
        for ax, s in m["per_axis"].items():
            print(f"    {ax:<13} pass={s['pass']}/{s['applicable']} (of {s['variants']} variants)")
        for r in m["rows"]:
            if not r["applicable"]:
                print(f"    [N/A ] {r['axis']}/{r['variant']}: changed no event in this storyline")
            elif r["steps_lost"] and r["axis"] != "loss":
                print(f"    [DARK] {r['axis']}/{r['variant']}: steps no longer detected: "
                      f"{', '.join(r['steps_lost'])}")
            elif not r["pass"]:
                why = [k for k, v in (("detection", r["detection_retained"]),
                                       ("fidelity", r["fidelity_retained"]), ("fcr", r["fcr_unchanged"]),
                                       ("order", r["order_retained"]), ("decoys", r["decoy_clean"])) if not v]
                extra = ""
                if r.get("expected_rule_lost_steps"):
                    extra = f" (intended rule lost at: {', '.join(r['expected_rule_lost_steps'])})"
                if r.get("collateral_lost_steps"):
                    extra += f" (COLLATERAL steps lost: {', '.join(r['collateral_lost_steps'])})"
                print(f"    [FAIL] {r['axis']}/{r['variant']}: failed on {', '.join(why) or 'collateral loss'}{extra}")
        for tw in m.get("negative_twins", []):
            print(f"    [{'OK' if tw['ok'] else 'FAIL'}] negative twin {tw['name']} @ {tw['step']}: "
                  f"{tw['attribute']} -> fired {tw['negative_fired'] or 'nothing'}; restored -> "
                  f"fired {len(tw['restored_fired'])}/{len(tw['rule_ids'])} of its rules")
        bq = m["baseline_quality"]
        if not bq["sound_reference"]:
            print("  [BASELINE CAVEATS]")
            for c in bq["caveats"]:
                print(f"    - {c}")

    p = result["pooled"]
    print(f"\npooled (convenience only, hides per-shape failures): "
          f"{p['passed']}/{p['applicable']} = {p['mutation_robustness']}")

    result["metric_controls"] = run_metric_controls(args.seed, args.scenario)
    print("\nmetric_controls (instrument controls for the ORDER metrics -- not mutations, "
          "never pooled above; order_concordance is a timestamp invariant):")
    for name, ctl in result["metric_controls"]["scenarios"].items():
        r = ctl["rows"]
        print(f"  [{name}] true chain: order_concordance={r['identity']['order_concordance']} "
              f"causal_order_fidelity={r['identity']['causal_order_fidelity']} | "
              f"MIRRORED: order_concordance={r['mirror']['order_concordance']} "
              f"causal_order_fidelity={r['mirror']['causal_order_fidelity']} "
              f"alert_order_ok={r['mirror']['alert_order_ok']} | legacy chain_fidelity "
              f"{r['identity']['chain_fidelity']} -> {r['mirror']['chain_fidelity']}, FCR "
              f"{r['identity']['false_correlation_rate']} -> {r['mirror']['false_correlation_rate']} "
              f"(legacy join metrics equal under mirror: {ctl['legacy_equal_under_mirror']})")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    if not _selfcheck(result):
        print("[FAIL] scenario matrix self-check failed -- see above.")
        return 1
    print(f"[OK] scenario matrix written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
