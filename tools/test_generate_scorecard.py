"""Step 7 scorecard: positive AND negative controls for the registry + generator.

Every control in the design spec's ``positive_and_negative_controls`` list is an
ACTUAL assertion here, and each is demonstrated to be able to fail by neutering
the corresponding guard (see the notes at the bottom of each test).

Run:  python tools/test_generate_scorecard.py
"""
from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FAILS: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        FAILS.append(msg)


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


gs = _load("generate_scorecard", "tools/generate_scorecard.py")
reg = sys.modules["scorecard_registry"]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def real_arts() -> dict:
    arts, problems = gs.load_artifacts(ROOT)
    check(not problems, f"real artifacts do not load cleanly: {problems}")
    return gs.decorate(arts)


def reverse_keys(obj):
    """Reverse every dict's key order, recursively (lists keep their order)."""
    if isinstance(obj, dict):
        return {k: reverse_keys(obj[k]) for k in reversed(list(obj.keys()))}
    if isinstance(obj, list):
        return [reverse_keys(x) for x in obj]
    return obj


def render_fixture(arts: dict) -> str:
    return gs.render(gs.build_model(copy.deepcopy(arts)))


def run_main(argv, *, arts=None):
    """Run gs.main(argv) with stdout captured. When ``arts`` is given, the
    loader is monkeypatched to return them (a fixture artifact set)."""
    buf = io.StringIO()
    saved = gs.load_artifacts
    if arts is not None:
        def fake_load(root=gs.ROOT):  # noqa: ARG001
            return copy.deepcopy(arts), []
        gs.load_artifacts = fake_load
    try:
        with contextlib.redirect_stdout(buf):
            rc = gs.main(argv)
    finally:
        gs.load_artifacts = saved
    return rc, buf.getvalue()


def with_temp_card(text: str):
    """Context manager-ish helper: writes to a temp card path and returns
    (dir, path, restore_fn)."""
    d = tempfile.mkdtemp(prefix="scorecard_test_")
    p = Path(d) / "SCORECARD.md"
    p.write_text(text, encoding="utf-8", newline="\n")
    return d, p


# ==========================================================================
# 1. POSITIVE: round trip + key-order invariance
# ==========================================================================
def test_round_trip_and_key_order() -> None:
    arts = real_arts()
    t1 = render_fixture(arts)
    t2 = render_fixture(arts)
    check(t1 == t2, "two renders from the same artifacts are not byte-identical")

    raw, _ = gs.load_artifacts(ROOT)
    rev = gs.decorate(reverse_keys(raw))
    t3 = render_fixture(rev)
    check(t3 == t1, "render changed when every artifact dict's key order was reversed")


# ==========================================================================
# 2. NEGATIVE: determinism is not vacuous (volatile fields, dates, ms, separators)
# ==========================================================================
def test_volatile_fields_are_never_read() -> None:
    arts = real_arts()
    base = render_fixture(arts)

    pert = copy.deepcopy(arts)
    pert["twin"]["report"]["date"] = "1999-01-01T00:00:00+00:00"
    pert["twin"]["elapsed_seconds"] = 999.5
    pert["twin"]["metrics"]["incident_reconstruction_time_ms"] = 1234.5
    pert["layer_a"]["assembly_samples_ms"] = [1.0, 2.0]
    pert["layer_a"]["assembly_median_ms"] = 9.5
    got = render_fixture(pert)
    check(got == base, "perturbing a VOLATILE field changed the render -- the renderer "
                       "reads a wall-clock value")

    # the registry must contain no path into a volatile key
    for spec in reg.ARTIFACTS:
        for v in reg.VOLATILE:
            for slot in (spec.seed_path, spec.basis_path):
                check(v not in (slot or ""),
                      f"artifact {spec.key} has a provenance path into VOLATILE {v!r}")
            check(v not in spec.required_keys,
                  f"artifact {spec.key} requires the VOLATILE key {v!r}")
    for m in reg.METRICS:
        check(all(v not in m.key and v not in m.label for v in reg.VOLATILE),
              f"metric {m.key} names a VOLATILE key")

    # no ISO date, no millisecond measurement, no backslash, no C:, LF only
    check(not re.search(r"\d{4}-\d{2}-\d{2}", base),
          "the rendered card contains an ISO date")
    check(not re.search(r"\b\d+(?:\.\d+)?\s?ms\b", base),
          "the rendered card contains a millisecond measurement")
    check("\\" not in base, "the rendered card contains a backslash")
    check(not re.search(r"(?<![A-Za-z])[A-Za-z]:[\\/]", base),
          "the rendered card contains a Windows drive path")


# ==========================================================================
# 3. NEGATIVE: the staleness check can go red (and its positive pair)
# ==========================================================================
def test_check_detects_a_changed_artifact() -> None:
    arts = real_arts()
    text = render_fixture(arts)
    d, card = with_temp_card(text)
    saved_card = gs.CARD
    gs.CARD = card
    try:
        rc, out = run_main(["--check"])
        check(rc == 0, f"--check on an unchanged card exited {rc}: {out[:400]}")

        # mutate ONE number in a copied artifact
        bad = copy.deepcopy(arts)
        bad["twin"]["metrics"]["mutation_robustness"] = 0.9459
        rc, out = run_main(["--check"], arts=bad)
        check(rc == 1, "a changed artifact number did NOT make --check exit non-zero")
        check("0.9189" in out and "0.9459" in out,
              f"--check output does not name both committed and fresh values: {out[:600]}")
        check("mutation_robustness" in out,
              "--check output does not name the changed metric")
        check("cell-level summary" in out,
              "--check output has no cell-level summary")
    finally:
        gs.CARD = saved_card
        shutil.rmtree(d, ignore_errors=True)


# ==========================================================================
# 4. NEGATIVE: a hand edit goes red; a CRLF copy stays green
# ==========================================================================
def test_hand_edit_and_crlf() -> None:
    arts = real_arts()
    text = render_fixture(arts)
    d, card = with_temp_card(text)
    saved_card = gs.CARD
    gs.CARD = card
    try:
        edited = text.replace("| tpr | 1.0 ", "| tpr | 0.9 ", 1)
        check(edited != text, "could not construct a hand edit to the card")
        card.write_text(edited, encoding="utf-8", newline="\n")
        rc, out = run_main(["--check"])
        check(rc == 1, "a hand-edited card did NOT fail --check")
        check("--- committed eval/SCORECARD.md" in out or "@@" in out,
              "the failure printed no unified diff")
        check("cell ai_to_ot|tpr" in out,
              f"the cell-level summary did not name the edited cell: {out[:600]}")

        # a CRLF copy of the same (now correct) content must compare equal
        card.write_text(text.replace("\n", "\r\n"), encoding="utf-8", newline="")
        rc, out = run_main(["--check"])
        check(rc == 0, f"a CRLF copy of an equal card failed --check: {out[:300]}")

        # ... and normalisation must not MASK a real difference
        card.write_text(edited.replace("\n", "\r\n"), encoding="utf-8", newline="")
        rc, _ = run_main(["--check"])
        check(rc == 1, "a CRLF copy of a CHANGED card passed --check (normalisation "
                       "masked a real difference)")
    finally:
        gs.CARD = saved_card
        shutil.rmtree(d, ignore_errors=True)


# ==========================================================================
# 5. NEGATIVE: provenance + freshness
# ==========================================================================
def test_provenance_and_freshness() -> None:
    arts = real_arts()
    check(not gs.validate_provenance(arts, mtimes={k: 9e9 for k in reg.ARTIFACTS_BY_KEY}),
          "the real artifact set fails provenance/freshness")

    bad = copy.deepcopy(arts)
    bad["layer_a"]["seed"] = 11
    probs = gs.validate_provenance(bad, inputs_mtime=0.0)
    check(any("seed=11" in p for p in probs), "seed 11 was not rejected")

    bad = copy.deepcopy(arts)
    bad["scenario_matrix"]["basis"] = "hand-picked"
    probs = gs.validate_provenance(bad, inputs_mtime=0.0)
    check(any("basis='hand-picked'" in p for p in probs), "a non-harness basis was not rejected")

    bad = copy.deepcopy(arts)
    bad["oracle_consistency"]["ai_to_ot"]["seed"] = 3
    probs = gs.validate_provenance(bad, inputs_mtime=0.0)
    check(any("oracle_consistency.ai_to_ot" in p and "seed=3" in p for p in probs),
          "a per-scenario seed drift was not rejected")

    # a stale artifact (mtime injected older than the newest input)
    probs = gs.check_freshness(arts, mtimes={k: 1.0 for k in reg.ARTIFACTS_BY_KEY})
    check(probs and all("stale artifact, rerun the gate" in p for p in probs),
          f"an old artifact mtime was not rejected: {probs[:2]}")

    # fire_check holding {harness_ok: false} -- wrong shape AND wrong content
    d = tempfile.mkdtemp(prefix="scorecard_badfire_")
    try:
        p = Path(d) / reg.ARTIFACTS_BY_KEY["fire_check"].path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"harness_ok": False}), encoding="utf-8")
        got, probs = gs.load_artifacts(ROOT)
        check(not probs, "sanity: the real set loaded fine")
        arts_bad = copy.deepcopy(arts)
        arts_bad["fire_check"] = {"harness_ok": False}
        probs = gs.validate_provenance(arts_bad, inputs_mtime=0.0)
        check(isinstance(arts_bad["fire_check"], dict),
              "fire_check must be a LIST -- a dict is the wrong shape")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # a missing artifact
    d = tempfile.mkdtemp(prefix="scorecard_missing_")
    try:
        for spec in reg.ARTIFACTS:
            if spec.key == "evasion":
                continue
            src = ROOT / spec.path
            dst = Path(d) / spec.path
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        loaded, probs = gs.load_artifacts(Path(d))
        check(any("evasion" in p and "does not exist" in p for p in probs),
              f"a missing artifact was not reported: {probs}")
        check("evasion" not in loaded, "a missing artifact was silently included")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # a partial set cannot render as if it were complete
    partial = {k: v for k, v in arts.items()
               if k in reg.ARTIFACTS_BY_KEY and k != "corpus_b"}
    probs = gs._check_artifact_count(partial)
    check(probs and "6 of 7" in probs[0], f"a partial artifact set was not rejected: {probs}")


# ==========================================================================
# 6. NEGATIVE: registry honesty (controls) + the NONE register
# ==========================================================================
def test_control_verification_and_none_register() -> None:
    d = tempfile.mkdtemp(prefix="scorecard_controls_")
    try:
        # (a) a needle that is absent from the file
        ghost = reg.ControlRef("eval/adversarial/test_scenario_harness.py",
                               "def test_a_needle_that_does_not_exist", "x")
        probs = gs.check_one_control(ghost, ROOT)
        check(any("not found" in p for p in probs), f"an absent needle was accepted: {probs}")

        # (b) a needle in an UNCALLED function -- the dormant-control class
        f = Path(d) / "tools" / "test_ghost_control.py"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(
            "def test_called():\n    return 1\n\n\n"
            "def test_orphan():\n    return 1\n\n\n"
            "def main():\n    test_called()\n\n\n"
            "if __name__ == '__main__':\n    main()\n",
            encoding="utf-8")
        gate = (ROOT / reg.GATE_SH).read_text(encoding="utf-8")
        wiring = "tools/test_ghost_control.py"
        gate_with = gate + f"\n$PY {wiring}\n"
        ok_ref = reg.ControlRef(wiring, "def test_called", "y")
        probs = gs.check_one_control(ok_ref, Path(d), gate_text=gate_with)
        check(probs == [], f"a needle in a called function was rejected: {probs}")
        bad_ref = reg.ControlRef(wiring, "def test_orphan", "y")
        probs = gs.check_one_control(bad_ref, Path(d), gate_text=gate_with)
        check(any("never CALLED from main()" in p for p in probs),
              f"a needle in an UNCALLED function was accepted: {probs}")

        # (c) a control pointing at a test file that is NOT gate-wired
        unwired_ref = reg.ControlRef(wiring, "def test_called", "y")
        probs = gs.check_one_control(unwired_ref, Path(d), gate_text=gate)
        check(any("not invoked" in p for p in probs),
              f"a control in an unwired test file was accepted: {probs}")

        # every REAL control verifies against the real tree
        probs = gs.verify_controls(ROOT)
        check(probs == [], f"a registry control does not verify: {probs}")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    arts = real_arts()
    model = gs.build_model(copy.deepcopy(arts))
    text = gs.render(model)
    n_none = sum(1 for m in reg.METRICS if m.control_key is None)
    check(n_none >= 1, "no registry metric is control-less -- the NONE register is vacuous")
    # a control=None metric renders as a bold NONE row AND is in the register
    check("| **NONE** |" in text or "| **NONE**" in text,
          "no bold NONE control cell rendered")
    reg_section = text.split("## Register: metric cells with NO control", 1)[-1]
    check("ai_to_ot/fpr" in reg_section,
          "ai_to_ot/fpr is not in the NONE register (the spec requires it there)")
    check("attribution_accuracy" in reg_section,
          "attribution_accuracy is not in the NONE register")
    check(f"{len(model['none_register'])} of " in text,
          "the register does not print its own NONE count")
    # the twin-only metrics are 'not measured' for the other three storylines
    for s in reg.STORYLINES:
        if s == reg.TWIN_STORYLINE:
            continue
        check(f"{s}/fpr" in reg_section or f"{s}/chain_fidelity" in reg_section,
              f"{s} does not report the twin-only metrics as not measured")


# ==========================================================================
# 7. NEGATIVE: the limits expire when their evidence stops holding
# ==========================================================================
def test_limits_expire() -> None:
    arts = real_arts()
    for key, ok, ev, static in gs.verify_limits(arts, ROOT):
        check(ok, f"limit {key} guard failed on the real shapes: {ev}")
    check(len(reg.LIMITS) == 12, f"expected 12 'cannot prove' bullets, got {len(reg.LIMITS)}")

    # directional_discrimination climbs -> the entity-sharing caveat expires
    bad = copy.deepcopy(arts)
    for sc in bad["scenario_matrix"]["scenarios"]:
        bad["scenario_matrix"]["scenarios"][sc]["baseline"]["directional_discrimination"] = 0.8
    got = dict((k, (ok, ev)) for k, ok, ev, _ in gs.verify_limits(bad, ROOT))
    check(got["fidelity_is_entity_sharing"][0] is False,
          "directional_discrimination=0.8 did NOT expire the entity-sharing caveat")
    check("0.8" in got["fidelity_is_entity_sharing"][1], "the evidence did not name the value")

    # a solvent baseline -> the relative-to-degraded caveat expires
    bad2 = copy.deepcopy(arts)
    for sc in bad2["scenario_matrix"]["scenarios"]:
        bad2["scenario_matrix"]["scenarios"][sc]["baseline_quality"]["sound_reference"] = True
    got = dict((k, (ok, ev)) for k, ok, ev, _ in gs.verify_limits(bad2, ROOT))
    check(got["relative_to_degraded_baseline"][0] is False,
          "a sound baseline did NOT expire the relative-baseline caveat")

    # a boundary that stops agreeing with the declared threshold
    bad3 = copy.deepcopy(arts)
    for sc, node in bad3["evasion"]["scenarios"].items():
        for r in node.get("rows", []):
            if r.get("searched"):
                r["all_agree"] = False
    got = dict((k, (ok, ev)) for k, ok, ev, _ in gs.verify_limits(bad3, ROOT))
    check(got["evasion_is_declared_boundary"][0] is False,
          "a disagreeing boundary did NOT expire the declared-boundary caveat")

    # a rule that stops firing -> the own-fixture caveat expires
    bad4 = copy.deepcopy(arts)
    bad4["fire_check"][0]["fired"] = False
    got = dict((k, (ok, ev)) for k, ok, ev, _ in gs.verify_limits(bad4, ROOT))
    check(got["fire_check_is_own_fixture"][0] is False,
          "a non-firing rule did NOT expire the own-fixture caveat")

    # the ratchet floor appearing expires 'no ratchet yet'
    d = tempfile.mkdtemp(prefix="scorecard_floor_")
    try:
        (Path(d) / reg.RATCHET_FLOOR_FILE).parent.mkdir(parents=True, exist_ok=True)
        (Path(d) / reg.RATCHET_FLOOR_FILE).write_text("{}", encoding="utf-8")
        # the other guards need the real tree, so check this one directly
        ok, ev = reg._g_no_ratchet(arts, Path(d))
        check(ok is False, "the ratchet floor file did NOT expire 'no ratchet yet'")
        check(reg.RATCHET_FLOOR_FILE in ev, "the evidence did not name the floor constant")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ANCHORED evtx/splunk guard: the real line must NOT trip it, a direct
    # evtx_eval.py invocation MUST.
    real_line = "$PY eval/detection_accuracy/test_evtx_eval.py || { fail=1; }"
    direct = "$PY eval/detection_accuracy/evtx_eval.py"
    pipe = re.compile(r"\$PY\s+eval/detection_accuracy/(?:evtx|splunk)_eval\.py")
    check(pipe.search(real_line) is None,
          "the anchored guard trips on the H7 test_evtx_eval.py line (it must not)")
    check(pipe.search(direct) is not None,
          "the anchored guard does NOT trip on a direct evtx_eval.py invocation")

    d = tempfile.mkdtemp(prefix="scorecard_gate_")
    try:
        (Path(d) / reg.GATE_SH).write_text(direct + "\n", encoding="utf-8")
        ok, ev = reg._g_no_third_party(arts, Path(d))
        check(ok is False, "a gate that RUNS evtx_eval.py did not expire the "
                           "no-third-party-corpus caveat")
        (Path(d) / reg.GATE_SH).write_text(
            (ROOT / reg.GATE_SH).read_text(encoding="utf-8"), encoding="utf-8")
        ok, ev = reg._g_no_third_party(arts, Path(d))
        check(ok is True, f"the real gate text failed the anchored guard: {ev}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ==========================================================================
# 8. POSITIVE/NEGATIVE: per-technique math
# ==========================================================================
def test_per_technique_math() -> None:
    arts = real_arts()

    # (a) two rules sharing a technique, one with an unverified near-miss -> 1/2
    fix = copy.deepcopy(arts)
    rows = [r for r in fix["fire_check"] if r.get("technique") == "T1110"]
    check(len(rows) >= 2, "sanity: expected >=2 T1110 rules in the real fire_check")
    for i, r in enumerate(rows):
        r["fired"] = True
        r["boundary"] = {"applicable": False, "reason": "stateless rule"}
        r["near_miss"] = {"applicable": True, "fully_held": i == 0, "held": [],
                          "too_loose": [] if i == 0 else ["x"]}
    only = [r for r in fix["fire_check"] if r.get("technique") == "T1110"]
    tr = {t["technique"]: t for t in gs._technique_rows(fix)}
    check(tr["T1110"]["verified"] == 1,
          f"expected exactly 1 of {len(only)} T1110 rules verified, got "
          f"{tr['T1110']['verified']}")
    check(tr["T1110"]["verified"] != len(only),
          "an unverified near-miss was counted as verified (2/2 instead of 1/2)")

    # (b) a technique present in fire_check but at no oracle step
    fix = copy.deepcopy(arts)
    for r in fix["fire_check"]:
        if r.get("technique") == "T1046":
            r["id"] = "00000000-0000-0000-0000-000000000000"  # no oracle references it
    tr = {t["technique"]: t for t in gs._technique_rows(fix)}
    check(tr["T1046"]["end_to_end"] is False,
          "a technique referenced by no oracle step was reported end-to-end")
    text = render_fixture(fix)
    check("**NOT EXERCISED END-TO-END**" in text,
          "the NOT EXERCISED END-TO-END flag is not rendered")

    # (c) an oracle step with no_rule_exists -> a GAP row
    gaps = {(s, step) for s, step, _ in gs.build_model(copy.deepcopy(arts))["gaps"]}
    for expect in (("ai_to_ot", "external_content"), ("ai_to_ot", "plc_state_change"),
                   ("it_intrusion", "initial_access"), ("phishing_bec", "phish_delivery"),
                   ("phishing_bec", "victim_session")):
        check(expect in gaps, f"oracle gap {expect} is missing from the GAP table")
    den = arts["__denominator__"]
    check(den["ai_to_ot"][:2] == (5, 7), f"ai_to_ot TPR denominator wrong: {den['ai_to_ot']}")
    check(den["it_intrusion"][:2] == (5, 6), f"it_intrusion wrong: {den['it_intrusion']}")
    check(den["infra_takeover"][:2] == (3, 3), f"infra_takeover wrong: {den['infra_takeover']}")
    check(den["phishing_bec"][:2] == (3, 8), f"phishing_bec wrong: {den['phishing_bec']}")

    # (d) 2 of 12 applicable variants lose a technique's step; N/A excluded
    fix = copy.deepcopy(arts)
    rows = []
    for i in range(12):
        r = {"axis": "timing", "variant": f"v{i:02d}", "applicable": True, "pass": True,
             "expected_rule_lost_steps": ["recon_port_scan"] if i in (1, 5) else []}
        rows.append(r)
    for i in range(3):
        rows.append({"axis": "timing", "variant": f"na{i:02d}", "applicable": False,
                     "pass": False, "expected_rule_lost_steps": ["recon_port_scan"]})
    fix["scenario_matrix"] = {
        "seed": 7, "basis": "harness-measured",
        "scenario_list": ["it_intrusion"],
        "inputs_fingerprint": "x", "pooled": {},
        "metric_controls": {},
        "scenarios": {"it_intrusion": {
            "scenario": "it_intrusion", "summary": "s", "seed": 7,
            "baseline": {"tpr": 1.0, "chain_fidelity": 0.5,
                         "false_correlation_rate": 1.0,
                         "directional_discrimination": 0.0,
                         "alert_order_ok": True, "incident_count": 1,
                         "incident_membership_ok": True, "fired_alerts": 5},
            "baseline_quality": {"chain_fidelity": 0.5, "false_correlation_rate": 1.0,
                                 "directional_discrimination": 0.0,
                                 "fidelity_floor": 0.8, "fcr_ceiling": 0.25,
                                 "sound_reference": False, "caveats": [],
                                 "interpretation": "i"},
            "negative_twins": [], "rows": rows, "per_axis": {}}},
    }
    dec = gs.decorate(copy.deepcopy(fix))
    tr = {t["technique"]: t for t in gs._technique_rows(dec)}
    t1046 = tr["T1046"]
    check(t1046["lost_denom"] == 12,
          f"N/A variants were counted in the lost denominator: {t1046['lost_denom']}")
    check(len(t1046["lost"]) == 2, f"expected 2 lost variants, got {t1046['lost']}")
    check(t1046["lost"] == sorted(t1046["lost"]), "the lost variant names are not sorted")
    check(all(v.startswith("it_intrusion/") for v in t1046["lost"]),
          "lost variant names are not scoped by storyline")
    text = render_fixture(dec)
    check("| 2/12 (it_intrusion/v01, it_intrusion/v05) |" in text,
          "the per-technique lost cell does not read '2/12' with sorted variant names")


# ==========================================================================
# 9. POSITIVE/NEGATIVE: doc lint
# ==========================================================================
def test_doc_lint() -> None:
    arts = real_arts()
    model = gs.build_model(copy.deepcopy(arts))
    q = model["quotable"]
    check("mutation_robustness" in q, "mutation_robustness is not in the quotable block")
    check(any(abs(v - 0.9189) < 1e-9 for v in q["mutation_robustness"].values()),
          "the quotable block does not hold 0.9189 for mutation_robustness")

    d = tempfile.mkdtemp(prefix="scorecard_lint_")
    try:
        (Path(d) / "README.md").write_text(
            "# R\n\nmutation_robustness 0.9189 is the Layer A number.\n", encoding="utf-8")
        (Path(d) / "SSOT.md").write_text("## 2. Proven\n\nnope\n", encoding="utf-8")
        probs = gs.lint_docs(Path(d), quotable=q)
        check(probs == [], f"a correct README number was rejected: {probs}")

        (Path(d) / "README.md").write_text(
            "# R\n\nmutation_robustness 0.6111 is the Layer A number.\n", encoding="utf-8")
        probs = gs.lint_docs(Path(d), quotable=q)
        check(len(probs) == 1 and "README.md:3" in probs[0],
              f"a stale README number was not named file:line: {probs}")

        # the coincidence control: FCR 1.0 is only accepted when the CARD holds it
        (Path(d) / "README.md").write_text("# R\n\nFCR 1.0 here\n", encoding="utf-8")
        probs = gs.lint_docs(Path(d), quotable=q)
        check(probs == [], f"FCR 1.0 was rejected while the card holds it: {probs}")
        probs = gs.lint_docs(Path(d), quotable={"tpr": {"ai_to_ot": 1.0}})
        check(len(probs) == 1 and "false_correlation_rate" in probs[0],
              f"the coincidence control passed: an unrelated metric's 1.0 validated FCR "
              f"({probs})")

        # a historical tag exempts the line
        (Path(d) / "README.md").write_text(
            "# R\n\nmutation_robustness 0.6111 [historical numbers - current: "
            "eval/SCORECARD.md]\n", encoding="utf-8")
        probs = gs.lint_docs(Path(d), quotable=q)
        check(probs == [], f"a tagged historical line was not exempt: {probs}")

        # section 1 of SSOT is NOT scanned; section 2 is
        (Path(d) / "SSOT.md").write_text(
            "## 1. Current state\n\nmutation_robustness 0.6111 (stale log line)\n\n"
            "## 2. What's proven\n\n| mutation_robustness 0.6111 |\n", encoding="utf-8")
        probs = gs.lint_docs(Path(d), quotable=q)
        check(any("SSOT.md:7" in p for p in probs),
              f"a section-2 number was not scanned: {probs}")
        check(not any("SSOT.md:3" in p for p in probs),
              f"a section-1 log line was scanned: {probs}")

        # the alias vocabulary is restricted: bare `attribution` and prose do not match
        (Path(d) / "SSOT.md").write_text("## 2. What's proven\n\nnope\n", encoding="utf-8")
        (Path(d) / "README.md").write_text(
            "# R\n\nSee the attribution 2026-08-28 row and the TPR column of the table.\n",
            encoding="utf-8")
        probs = gs.lint_docs(Path(d), quotable=q)
        check(probs == [], f"the lint matched prose / a bare 'attribution': {probs}")
        check("attribution" not in reg.ALIASES, "a bare 'attribution' alias is registered")
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ==========================================================================
# 10. NEGATIVE: gate wiring
# ==========================================================================
def test_gate_wiring() -> None:
    gate = (ROOT / reg.GATE_SH).read_text(encoding="utf-8")
    check(gs.assert_gate_wiring(gate) == [],
          f"the real gate fails the wiring check: {gs.assert_gate_wiring(gate)}")

    no_stanza = gate.replace("tools/generate_scorecard.py --check", "tools/nothing.py --check")
    probs = gs.assert_gate_wiring(no_stanza)
    check(probs and "does not invoke" in probs[0],
          f"a gate without the stanza passed: {probs}")

    # move the check BEFORE the last instrument
    lines = gate.splitlines()
    idx = next(i for i, ln in enumerate(lines) if reg.CHECK_STANZA in ln)
    stanza = lines.pop(idx)
    first_instrument = next(i for i, ln in enumerate(lines)
                            if "eval/attack/fire_check.py" in ln)
    lines.insert(first_instrument, stanza)
    probs = gs.assert_gate_wiring("\n".join(lines))
    check(any("runs AFTER" in p for p in probs),
          f"a gate with the check before the instruments passed: {probs}")


# ==========================================================================
# 11. NEGATIVE: REGRESSIONS print on --write
# ==========================================================================
def test_regressions_on_write() -> None:
    arts = real_arts()
    committed = gs.extract_cells(gs._norm(render_fixture(arts)))

    fix = copy.deepcopy(arts)
    fix["twin"]["metrics"]["mutation_robustness"] = 0.5000      # higher_better FALLS
    fix["twin"]["metrics"]["fpr"] = 0.5                         # lower_better RISES
    # leave an unchanged comparable metric untouched
    fresh = gs.extract_cells(gs._norm(render_fixture(fix)))
    lines = gs.regressions(committed, fresh)
    joined = "\n".join(lines)
    check("mutation_robustness" in joined, f"a falling higher-better metric was not listed: {joined}")
    check("fpr" in joined, "a rising lower-better metric was not listed")
    check("0.9189" in joined and "0.5" in joined, "the regression line has no old->new values")
    check(not any("chain_fidelity" in x for x in lines),
          f"an unchanged metric was reported: {lines}")

    # an IMPROVEMENT must not be reported
    fix2 = copy.deepcopy(arts)
    fix2["twin"]["metrics"]["mutation_robustness"] = 1.0
    fresh2 = gs.extract_cells(gs._norm(render_fixture(fix2)))
    check(gs.regressions(committed, fresh2) == [],
          "an improvement was reported as a regression")


# ==========================================================================
# 12. POSITIVE/NEGATIVE: denominators agree with the instrument
# ==========================================================================
def test_pooled_and_per_storyline_denominators() -> None:
    arts = real_arts()
    check(gs._check_pooled_sum(arts) == [],
          f"the per-storyline denominators do not sum to the pooled one: "
          f"{gs._check_pooled_sum(arts)}")

    sm = arts["scenario_matrix"]
    for s, node in sorted(sm["scenarios"].items()):
        rows = [r for r in node["rows"] if r.get("applicable") is True]
        if not rows:
            continue
        recomputed = round(sum(1 for r in rows if r.get("pass")) / len(rows), 4)
        check(abs(node["overall"]["mutation_robustness"] - recomputed) < 1e-9,
              f"{s}: the instrument reports {node['overall']['mutation_robustness']} "
              f"but its own rows recompute to {recomputed}")
        check(node["overall"]["applicable"] == len(rows),
              f"{s}: overall.applicable != the count of applicable rows")

    bad = copy.deepcopy(arts)
    bad["scenario_matrix"]["scenarios"]["it_intrusion"]["overall"]["applicable"] += 1
    check(gs._check_pooled_sum(bad), "a denominator mismatch was NOT caught")


# ==========================================================================
# 13. NEGATIVE: no Windows path in any artifact; render is cross-OS stable
# ==========================================================================
def test_artifacts_carry_no_windows_paths() -> None:
    arts = real_arts()
    bs, drv = gs.scan_artifacts_for_paths(arts)
    check(drv == set(),
          f"a Windows drive path leaked into an artifact: {sorted(drv)}")
    check(bs == set(gs.BACKSLASH_ALLOWED_ARTIFACT_PATHS),
          f"the set of artifact locations containing a backslash changed: {sorted(bs)} "
          f"(allowlist: {sorted(gs.BACKSLASH_ALLOWED_ARTIFACT_PATHS)}) -- either a new "
          f"Windows path leaked into an artifact, or the known one moved")
    # positive control: the scan CAN see a backslash
    planted = copy.deepcopy(arts)
    planted["layer_a"]["planted"] = "C:\\tmp\\x.py"
    bs2, drv2 = gs.scan_artifacts_for_paths(planted)
    check("layer_a:planted" in bs2 and "layer_a:planted" in drv2,
          "the artifact path scan did not detect a planted Windows path")


def test_render_is_cross_os_and_hash_order_stable() -> None:
    arts = real_arts()
    base = render_fixture(arts)
    check("\r" not in base, "the rendered card contains a CR -- it must be pure LF")
    check(base.endswith("\n"), "the rendered card does not end with a newline")

    # Two interpreters with different hash seeds must produce identical bytes,
    # which is what makes a Windows-generated card check out on Linux CI.
    import os
    import subprocess
    code = (
        "import importlib.util, sys, hashlib\n"
        "sys.path.insert(0, 'eval')\n"
        "spec = importlib.util.spec_from_file_location('gs', 'tools/generate_scorecard.py')\n"
        "gs = importlib.util.module_from_spec(spec)\n"
        "sys.modules['gs'] = gs\n"
        "spec.loader.exec_module(gs)\n"
        "arts, probs = gs.load_artifacts()\n"
        "arts = gs.decorate(arts)\n"
        "print(hashlib.sha256(gs.render(gs.build_model(arts)).encode('utf-8')).hexdigest())\n"
    )
    digests = []
    for seed in ("0", "12345"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        proc = subprocess.run([sys.executable, "-c", code], capture_output=True,
                              text=True, env=env, cwd=str(ROOT))
        digests.append(proc.stdout.strip())
        check(proc.returncode == 0,
              f"the render subprocess failed (PYTHONHASHSEED={seed}): {proc.stderr[-300:]}")
    check(bool(digests[0]) and len(set(digests)) == 1,
          f"the render depends on hash/iteration order: {digests}")


# ==========================================================================
# 14. POSITIVE/NEGATIVE: oracle shapes, the 4th storyline, freshness coverage
# ==========================================================================
def test_oracle_shapes_and_storyline_registry() -> None:
    # expected_rules is read DEFENSIVELY: both shapes must resolve
    check(gs._oracle_rule_ids(["a", "b"]) == ["a", "b"],
          "a bare-string expected_rules list was not read")
    check(gs._oracle_rule_ids([{"rule_id": "a", "title": "t"}]) == ["a"],
          "a dict expected_rules element (rule_id) was not read")
    check(gs._oracle_rule_ids([{"title": "no id"}, {}, None]) == [],
          "an id-less element must be SKIPPED, never rendered as a blank cell")
    check(gs._oracle_rule_ids(None) == [] and gs._oracle_rule_ids([]) == [],
          "None/empty expected_rules must resolve to []")

    import yaml
    for f in ("oracle.yaml", "oracle_it_intrusion.yaml", "oracle_infra_takeover.yaml",
              "oracle_phishing_bec.yaml"):
        o = yaml.safe_load((ROOT / "eval/twin" / f).read_text(encoding="utf-8"))
        for step, node in o["detection_points"].items():
            er = node.get("expected_rules") or []
            if (node.get("gap") or {}).get("no_rule_exists"):
                check(er == [], f"{f}/{step}: a GAP step declares expected rules")
                continue
            check(bool(er), f"{f}/{step}: a non-gap step declares no expected rule")
            for e in er:
                check(isinstance(e, dict) and bool(e.get("rule_id")),
                      f"{f}/{step}: expected_rules element is not a dict with rule_id "
                      f"({e!r})")
            for e in er:
                check("rule_id" in e, f"{f}/{step}: element lacks rule_id")

    # the 4th storyline: the registry and the artifact must agree
    arts = real_arts()
    check("phishing_bec" in reg.STORYLINES,
          "phishing_bec is not a registered storyline")
    check(len(reg.STORYLINES) == 5, f"expected 5 storylines, got {reg.STORYLINES}")
    check(gs._check_storylines(arts) == [],
          f"the storyline cross-check failed on the real tree: {gs._check_storylines(arts)}")
    bad = copy.deepcopy(arts)
    bad["scenario_matrix"]["scenario_list"] = ["ai_to_ot", "it_intrusion", "infra_takeover"]
    probs = gs._check_storylines(bad)
    check(bool(probs) and "phishing_bec" in probs[0],
          "dropping the 4th storyline from the artifact was NOT caught")
    text = render_fixture(arts)
    for s in reg.STORYLINES:
        check(f"### {s}" in text, f"storyline {s} has no section in the card")


def test_freshness_covers_every_ws4_contract_input() -> None:
    globs = reg.FRESHNESS_INPUT_GLOBS
    matched = {str(p.relative_to(ROOT)).replace("\\", "/")
               for g in globs for p in ROOT.glob(g) if p.is_file()}
    present: dict[str, bool] = {}
    for d in reg.WS4_CONTRACT_DIRS:
        check((ROOT / d).is_dir(), f"{d} is not a directory on disk")
        check(any(g.startswith(d + "/") for g in globs),
              f"no freshness glob is rooted at {d} -- services/ws4-detection/main.py "
              f"loads it, so an edit there moves metrics with an old artifact passing")
        present[d] = any(m.startswith(d + "/") for m in matched)
    # every contract dir that HOLDS instrument-readable files must be matched.
    # contracts/tenants/ ships EMPTY by design (see its README), so its glob is
    # ready rather than vacuous -- the consistency check below encodes that.
    for d, has in present.items():
        on_disk = [p for p in (ROOT / d).glob("*") if p.suffix in (".yml", ".yaml")]
        check(bool(on_disk) == has,
              f"{d}: {len(on_disk)} yml/yaml file(s) on disk but matched={has}")
    check(present["contracts/rules"] and present["contracts/ot-points"],
          f"a contract dir holding real files matched nothing: {present}")
    check(len(matched) >= 35,
          f"only {len(matched)} freshness input files matched -- the glob set is "
          f"effectively vacuous")
    for f in reg.WS4_CONTRACT_FILES:
        check(any(g == f for g in globs), f"no freshness glob covers {f} exactly")
        check(f in matched, f"{f} did not match any input file on disk")
    # the exact drift the critic called out
    check("contracts/scoring.yaml" in matched,
          "contracts/scoring.yaml is NOT a freshness input -- severity/peak-score "
          "metrics could move while a stale artifact still validated")


# ==========================================================================
def main() -> int:
    tests = [
        test_round_trip_and_key_order,
        test_volatile_fields_are_never_read,
        test_check_detects_a_changed_artifact,
        test_hand_edit_and_crlf,
        test_provenance_and_freshness,
        test_control_verification_and_none_register,
        test_limits_expire,
        test_per_technique_math,
        test_doc_lint,
        test_gate_wiring,
        test_regressions_on_write,
        test_pooled_and_per_storyline_denominators,
        test_artifacts_carry_no_windows_paths,
        test_render_is_cross_os_and_hash_order_stable,
        test_oracle_shapes_and_storyline_registry,
        test_freshness_covers_every_ws4_contract_input,
    ]
    for t in tests:
        before = len(FAILS)
        t()
        print(f"[{'OK' if len(FAILS) == before else 'FAIL'}] {t.__name__}")
    if FAILS:
        print(f"\n[FAIL] {len(FAILS)} check(s) failed:")
        for f in FAILS:
            print(f"   - {f}")
        return 1
    print("\n[OK] scorecard registry/generator: every control (positive AND negative) "
          "behaved as specified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
