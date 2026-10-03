"""Acceptance test for the reversed-order METRIC CONTROL (eval/adversarial/order_controls.py).

Standalone (NOT pytest), same style as test_scenario_harness.py: ``[OK]``/``[FAIL]``
lines, exit 0 only when every check passes. Run:

    python eval/adversarial/test_order_controls.py

The finding this guards (measured 2026-10-02, seed 7, all three registered storylines):
a time-MIRRORED copy of the attack scores the same as the true chain on every legacy
join metric (tpr, chain_fidelity, false_correlation_rate, directional_discrimination,
incident_count, incident_membership_ok) and only the order metrics move. A metric that
claims to grade order must therefore be shown to say NO on the reversed chain and YES
on the true one -- and the legacy pair must be shown NOT to.

  (a) mirror_event_time / swap_adjacent_steps  pure, never mutate the input, do what
                                               they say, involution on the clock
  (b) per storyline, mirrored chain            order_concordance 0.0, causal_order_fidelity
                                               0.0, alert_order_ok False, forbidden order
                                               realised 1.0, WS-3 story order False ...
                                               while every LEGACY key EQUALS the identity
                                               run (the half that makes the finding)
  (c) per storyline, identity / shift_1h       the instrument says YES: concordance 1.0,
                                               and a pure replay offset moves nothing
  (d) graded intermediate                      swapping two adjacent steps lands strictly
                                               between 0 and 1, equal to an independent
                                               reference (a metric, not a coin flip)
  (e) the control can fail                     a mirror that moves nothing, a span past the
                                               correlator horizon, a pipeline whose incident
                                               count moved, a metric that cannot say no -- each
                                               is reported as a problem, never a silent pass
  (f) policy                                   the control is NOT in mutate_generic's product
                                               catalogue and never enters mutation_robustness
  (g) determinism                              two runs are byte-identical
  (h) Stage 1 wiring                           layer_a._cmp RECORDS causal_order_fidelity /
                                               causal_order_retained without changing `pass`;
                                               the row whitelist accepts them; scenario_matrix
                                               prints the control in a separate section, never
                                               pooled, and its self-check fails a broken control
"""
from __future__ import annotations

import copy
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

import report  # noqa: E402,F401  (pre-seeds sys.modules['main']; must precede the harness imports)
import layer_a  # noqa: E402
import mutate_generic as mg  # noqa: E402
import order_controls as oc  # noqa: E402
import scenario_matrix  # noqa: E402
import scenario_registry as reg  # noqa: E402

SEED = 7
_FAILURES: list = []

#: Legacy values measured on the identity AND mirrored chain, 2026-10-02, seed 7. The
#: test asserts mirror == identity (the finding) and, separately, that identity still has
#: these numbers, so a drifting baseline is noticed rather than silently re-blessed.
LEGACY_EXPECT = {
    "ai_to_ot": {"tpr": 1.0, "chain_fidelity": 0.6, "false_correlation_rate": 1.0,
                 "directional_discrimination": 0.0, "incident_count": 2},
    "it_intrusion": {"tpr": 1.0, "chain_fidelity": 0.5, "false_correlation_rate": 1.0,
                     "directional_discrimination": 0.0, "incident_count": 3},
    "infra_takeover": {"tpr": 1.0, "chain_fidelity": 0.5, "false_correlation_rate": 1.0,
                       "directional_discrimination": 0.0, "incident_count": 1},
    # 2026-10-03: measured on the first run of the 4th storyline
    "phishing_bec": {"tpr": 1.0, "chain_fidelity": 0.5, "false_correlation_rate": 1.0,
                     "directional_discrimination": 0.0, "incident_count": 1},
}


def _mirror_displaced(sdef) -> list:
    """Steps whose expected rule still fires in the TIME-MIRRORED run, but at a CONTEXT step the oracle
    declares in ``step_dependencies`` (impossible travel is raised by whichever of the two logins sorts
    last, and mirrored the account's own earlier login is the last one)."""
    oracle = reg.load_oracle(sdef)
    deps = oracle.get("step_dependencies") or {}
    mirrored, _ = oc.mirror_event_time(sdef.build(SEED)[0])
    g = oc._grade(sdef, SEED, mirrored)
    out = []
    for step, needs in deps.items():
        exp = {r["rule_id"] for r in oracle["detection_points"][step].get("expected_rules") or []}
        at_step = any(a["step"] == step and a["rule_id"] in exp for a in g["fired"])
        at_dep = any(a["step"] in needs and a["rule_id"] in exp for a in g["fired"])
        if at_dep and not at_step:
            out.append(step)
    return sorted(out)


def _check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        _FAILURES.append(name)


def _first_times(payloads: list) -> dict:
    out: dict = {}
    for spec, p in payloads:
        t = mg.get_time(p)
        if t is not None:
            out[spec.label] = min(out.get(spec.label, t), t)
    return out


# --------------------------------------------------------------------------
def test_pure_helpers() -> None:
    sdef = reg.get("ai_to_ot")
    base = sdef.build(SEED)[0]
    frozen = copy.deepcopy(base)
    mirrored, changed = oc.mirror_event_time(base)
    _check("(a) mirror_event_time never mutates its input", base == frozen)
    ts = [mg.get_time(p) for _s, p in base if mg.get_time(p) is not None]
    lo, hi = min(ts), max(ts)
    mts = sorted(mg.get_time(p) for _s, p in mirrored if mg.get_time(p) is not None)
    _check("(a) mirror maps every timed event to lo+hi-t (same multiset of reflected times) and "
           "reports how many it changed",
           mts == sorted(lo + hi - t for t in ts) and changed > 0 and changed <= len(base),
           f"changed={changed}/{len(base)}")
    _check("(a) delivery follows the logs: the mirrored list is sorted by its new times",
           [mg.get_time(p) for _s, p in mirrored if mg.get_time(p) is not None]
           == sorted(mg.get_time(p) for _s, p in mirrored if mg.get_time(p) is not None))
    twice, _ = oc.mirror_event_time(mirrored)
    _check("(a) mirroring twice restores the original clock (involution)",
           sorted((s.label, mg.get_time(p)) for s, p in twice)
           == sorted((s.label, mg.get_time(p)) for s, p in base))
    empty, n = oc.mirror_event_time([])
    _check("(a) nothing to mirror -> (copy, 0), not a crash", empty == [] and n == 0)

    labels = [s.label for s in sdef.steps]
    a, b = labels[1], labels[2]
    before = _first_times(base)
    swapped, sc = oc.swap_adjacent_steps(base, a, b)
    after = _first_times(swapped)
    _check("(a) swap_adjacent_steps exchanges the two steps' start times, leaves the rest, never "
           "mutates its input",
           base == frozen and sc > 0 and after[a] == before[b] and after[b] == before[a]
           and all(after[s] == before[s] for s in before if s not in (a, b)),
           f"{a}:{before[a]}->{after[a]} {b}:{before[b]}->{after[b]}")
    nope, n0 = oc.swap_adjacent_steps(base, a, "no_such_step")
    _check("(a) swapping a step that does not exist changes nothing", n0 == 0 and nope == base)


def test_storylines() -> dict:
    tables = {}
    for sdef in reg.ALL:
        ctl = oc.run_order_controls(sdef, SEED)
        tables[sdef.name] = ctl
        r = ctl["rows"]
        ident, mir, sh = r["identity"], r["mirror"], r["shift_1h"]
        _check(f"(b) {sdef.name}: the mirror is a VALID control (moved events, span far below the horizon, "
               "incident count unchanged)", ctl["mirror_valid"] is True, str(ctl["mirror_invalid_reason"]))
        _check(f"(b) {sdef.name}: mirrored chain -> order_concordance 0.0, causal_order_fidelity 0.0, "
               "alert_order_ok False, forbidden order realised 1.0, temporal_discrimination 0.0, "
               "WS-3 story order False",
               mir["order_concordance"] == 0.0 and mir["causal_order_fidelity"] == 0.0
               and mir["alert_order_ok"] is False and mir["forbidden_order_realised_rate"] == 1.0
               and mir["temporal_discrimination"] == 0.0 and mir["story_order_ok"] is False,
               str({k: mir[k] for k in oc.ORDER_KEYS}))
        diff = {k: (ident[k], mir[k]) for k in oc.LEGACY_KEYS if ident[k] != mir[k]}
        if not reg.load_oracle(sdef).get("step_dependencies"):
            _check(f"(b) {sdef.name}: LEGACY join metrics on the mirrored chain EQUAL the identity run "
                   "(tpr, chain_fidelity, FCR, directional_discrimination, incident_count, incident_membership_ok)",
                   not diff and ctl["legacy_equal_under_mirror"] is True, f"differences: {diff}")
        else:
            # FINDING (2026-10-03, phishing_bec): the legacy metrics are order-blind only while each
            # step's detection is independent of the ORDER of other steps. Impossible travel is raised by
            # the second country's login, so mirrored the alert moves to the account's own (context) step
            # and the dependent step reads as lost: tpr (and with it the graph) changes. The difference is
            # therefore REQUIRED to be explained by displacement, not waved through.
            displaced = _mirror_displaced(sdef)
            _check(f"(b) {sdef.name}: legacy metrics on the mirrored chain differ ONLY because a dependent "
                   "step's detection is displaced onto its context step (an explained difference, not an "
                   "order-sensitive metric)",
                   bool(diff) and bool(displaced) and ctl["legacy_equal_under_mirror"] is False,
                   f"displaced={displaced} differences={diff}")
        _check(f"(b) {sdef.name}: legacy identity values are the measured ones "
               f"{LEGACY_EXPECT[sdef.name]}",
               all(ident[k] == v for k, v in LEGACY_EXPECT[sdef.name].items()),
               str({k: ident[k] for k in LEGACY_EXPECT[sdef.name]}))
        _check(f"(c) {sdef.name}: identity says YES (concordance 1.0, alert_order_ok True, forbidden "
               "order realised 0.0, story order True)",
               ident["order_concordance"] == 1.0 and ident["alert_order_ok"] is True
               and ident["forbidden_order_realised_rate"] == 0.0 and ident["story_order_ok"] is True)
        _check(f"(c) {sdef.name}: positive control shift_1h (pure replay offset) moves no order metric",
               all(sh[k] == ident[k] for k in oc.ORDER_KEYS + ("forbidden_order_realised_rate",
                                                               "temporal_discrimination", "story_order_ok"))
               and sh["changed_events"] > 0, f"changed={sh['changed_events']}")
        _check(f"(c) {sdef.name}: controls_ok() reports no problem", oc.controls_ok(ctl) == [],
               str(oc.controls_ok(ctl)))
    return tables


def test_graded_swap(tables: dict) -> None:
    """Independent reference for the swap row: the fraction of graded allowed pairs whose
    FROM step still starts no later than its TO step, computed from the swapped payloads'
    own clocks (not from causal_order.py)."""
    for sdef in reg.ALL:
        ctl = tables[sdef.name]
        pair = ctl["swap_pair"]
        ident_grade = reg.grade(sdef, SEED)
        graded = [(r["from"], r["to"]) for r in ident_grade["causal_order"]["per_pair"] if r.get("graded")]
        swapped, _n = oc.swap_adjacent_steps(sdef.build(SEED)[0], *pair)
        first = _first_times(swapped)
        ok_pairs = sum(1 for f, t in graded if first[f] <= first[t])
        ref = round(ok_pairs / len(graded), 4)
        got = ctl["rows"]["swap"]["order_concordance"]
        _check(f"(d) {sdef.name}: swapping {pair[0]}/{pair[1]} gives a GRADED concordance strictly between "
               "0 and 1, equal to an independent reference",
               0.0 < got < 1.0 and got == ref and ctl["rows"]["swap"]["alert_order_ok"] is False,
               f"module={got} reference={ref} ({ok_pairs}/{len(graded)})")


def test_control_can_fail(tables: dict) -> None:
    # validity_reason: one branch each, plus the pass case.
    h = oc.HORIZON_MS
    _check("(e) validity_reason: nothing moved -> invalid",
           "no event" in (oc.validity_reason(0, 1000, 2, 2) or ""))
    _check("(e) validity_reason: span at the horizon -> invalid",
           "horizon" in (oc.validity_reason(5, h // 4, 2, 2) or "")
           and "horizon" in (oc.validity_reason(5, None, 2, 2) or ""))
    _check("(e) validity_reason: the pipeline's incident count moved -> invalid",
           "pipeline" in (oc.validity_reason(5, 1000, 2, 3) or ""))
    _check("(e) validity_reason: a sound mirror -> None", oc.validity_reason(5, 1000, 2, 2) is None)

    good = tables["ai_to_ot"]
    for label, tweak, needle in (
        ("an invalid mirror", lambda c: c.update(mirror_valid=False, mirror_invalid_reason="x"), "invalid"),
        ("a metric that cannot say yes", lambda c: c["rows"]["identity"].update(order_concordance=0.5),
         "cannot say yes"),
        ("a metric that cannot say no", lambda c: c["rows"]["mirror"].update(order_concordance=1.0),
         "cannot say no"),
        ("a mirror that still looks in order", lambda c: c["rows"]["mirror"].update(alert_order_ok=True),
         "alert_order_ok"),
        ("a positive control that moved a metric", lambda c: c["rows"]["shift_1h"].update(order_concordance=0.0),
         "shift_1h"),
    ):
        bad = copy.deepcopy(good)
        tweak(bad)
        problems = oc.controls_ok(bad)
        _check(f"(e) controls_ok flags {label}", any(needle in p for p in problems), str(problems))

    # End to end: if the mirror silently stops moving anything, the lane must FAIL, not pass.
    real_set_time = mg.set_time
    mg.set_time = lambda p, ts: False  # a broken set_time: the 'mirror' is the identity
    try:
        ctl = oc.run_order_controls(reg.get("ai_to_ot"), SEED)
    finally:
        mg.set_time = real_set_time
    problems = oc.controls_ok(ctl)
    _check("(e) a mirror that moves nothing is reported (mirror_valid False, problems non-empty), "
           "never a silent pass",
           ctl["mirror_valid"] is False and len(problems) >= 2, str(problems[:2]))


def test_policy_and_determinism(tables: dict) -> None:
    catalogue = {name for name in getattr(mg, "_STATIC", {})}
    _check("(f) the control is NOT in mutate_generic's product catalogue (it would say nothing about "
           "the product)",
           not any("mirror" in str(k) or "order_control" in str(k) for k in catalogue), str(sorted(map(str, catalogue))))
    src = Path(oc.__file__).read_text(encoding="utf-8")
    _check("(f) order_controls does not import layer_a (it cannot feed mutation_robustness)",
           "import layer_a" not in src and "from layer_a" not in src)
    again = {s.name: oc.run_order_controls(s, SEED) for s in reg.ALL}
    _check("(g) two runs give byte-identical control tables",
           json.dumps(again, sort_keys=True) == json.dumps(tables, sort_keys=True))
    _check("(g) no wall-clock field in the tables",
           "elapsed" not in json.dumps(tables) and "date" not in json.dumps(tables))


def test_stage1_wiring(tables: dict) -> None:
    base = reg.grade(reg.get("ai_to_ot"), SEED)
    same = layer_a._cmp("ax", "va", base, dict(base))
    _check("(h) _cmp on an unchanged grade: causal_order_retained True and pass True (the flag does not "
           "make a clean row fail)", same["causal_order_retained"] is True and same["pass"] is True,
           f"cof={same['causal_order_fidelity']}")
    worse = layer_a._cmp("ax", "va", base, dict(base, causal_order_fidelity=0.5))
    gone = layer_a._cmp("ax", "va", base, dict(base, causal_order_fidelity=None))
    _check("(h) a lower or vanished causal_order_fidelity flips causal_order_retained to False but NOT `pass` "
           "(Stage 1: recorded, not gating -- Stage 2 is owner-gated)",
           worse["causal_order_retained"] is False and gone["causal_order_retained"] is False
           and worse["pass"] is True and gone["pass"] is True)
    nobase = layer_a._cmp("ax", "va", dict(base, causal_order_fidelity=None),
                          dict(base, causal_order_fidelity=0.0))
    better = layer_a._cmp("ax", "va", dict(base, causal_order_fidelity=0.5), dict(base, causal_order_fidelity=1.0))
    _check("(h) nothing to lose when the baseline had no graded fidelity; an improvement is retained",
           nobase["causal_order_retained"] is True and better["causal_order_retained"] is True)
    _check("(h) the strict row-key whitelist accepts exactly the new keys (and still rejects strangers)",
           {"causal_order_fidelity", "causal_order_retained"} <= layer_a._ROW_KEYS
           and set(same) <= layer_a._ROW_KEYS and "wall_clock" not in layer_a._ROW_KEYS)
    _check("(h) layer_a's baseline-quality caveat still names directional_discrimination and now points at the "
           "order metrics",
           any("directional_discrimination" in c and "causal_order_fidelity" in c
               for c in layer_a._baseline_quality(base)["caveats"]))

    mc = scenario_matrix.run_metric_controls(SEED, ["ai_to_ot"])
    _check("(h) scenario_matrix.run_metric_controls returns the control table under its own key and run_all "
           "does not carry it (never pooled)",
           set(mc["scenarios"]) == {"ai_to_ot"} and mc["scenarios"]["ai_to_ot"]["mirror_valid"] is True
           and "metric_controls" not in scenario_matrix.run_all(SEED, ["ai_to_ot"]))
    good = {"scenarios": {}, "metric_controls": {"scenarios": {"ai_to_ot": tables["ai_to_ot"]}}}
    bad_ctl = copy.deepcopy(tables["ai_to_ot"])
    bad_ctl["rows"]["mirror"]["order_concordance"] = 1.0
    bad = {"scenarios": {}, "metric_controls": {"scenarios": {"ai_to_ot": bad_ctl}}}
    _check("(h) scenario_matrix._selfcheck passes a sound control and FAILS one that cannot say no",
           scenario_matrix._selfcheck(good) is True and scenario_matrix._selfcheck(bad) is False)


def main() -> int:
    print("== FENGARDE adversarial: reversed-order metric control ==")
    test_pure_helpers()
    tables = test_storylines()
    test_graded_swap(tables)
    test_control_can_fail(tables)
    test_policy_and_determinism(tables)
    test_stage1_wiring(tables)
    print("-" * 60)
    if _FAILURES:
        print(f"[FAIL] {len(_FAILURES)} check(s) failed: {', '.join(_FAILURES)}")
        return 1
    print("[OK] all order-control checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
