"""Design-B (2026-07-29 audit): `siem.llm_gate: false` decouples funnel
routing from `severity_floor`, without touching the analyst-facing score.

Before this fix, `severity_floor.high` (70) and `.critical` (80) were both
>= `llm_min` (60), so ANY matched high/critical rule always routed to the
LLM tier -- tuning `score_weight` down did nothing, the floor always won.
Several shipped rules document themselves as noisy before an operator tunes
them (agent_credential_file_access.yml, ot_config_change.yml,
bank_mass_card_read.yml, common_after_hours_admin.yml) with no lever to say
"stay high severity for the analyst UI, but don't burn an LLM call yet".

Proves:
  * default behavior (llm_gate unset) is BYTE-FOR-BYTE unchanged: a matched
    high/critical rule still floors routing_score >= llm_min, same as score.
  * llm_gate: false excludes ONLY that rule's floor from routing_score --
    score_weight still counts, and the analyst-facing score()/level are
    completely unaffected.
  * end-to-end through Detector.process(): the funnel action actually
    changes while event["siem"]["score"] stays floor-inclusive.
  * validate_rules.py rejects a non-bool llm_gate (fails closed at
    validate-time, not silently at runtime).
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
ROOT = SERVICES.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(ROOT / "tools"))

from engine import Rule  # noqa: E402
from scoring import Scorer  # noqa: E402
import main as ws4  # noqa: E402
import validate_rules  # noqa: E402

SCORING_YAML = ROOT / "contracts" / "scoring.yaml"

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _rule(level="high", score_weight=45, llm_gate=None):
    siem = {"sector": "common", "score_weight": score_weight}
    if llm_gate is not None:
        siem["llm_gate"] = llm_gate
    return Rule({"id": "r1", "title": "t", "level": level,
                "detection": {"sel": {"class_uid": 1}, "condition": "sel"},
                "siem": siem})


def test_default_llm_gate_is_true_unchanged_behavior():
    r = _rule(level="high", score_weight=45)  # llm_gate unset
    check(r.llm_gate is True, "llm_gate must default to True")
    scorer = Scorer(SCORING_YAML)
    score = scorer.score([r])
    routing = scorer.routing_score([r])
    check(score == routing == 70,
          f"unset llm_gate: score and routing_score must be identical and "
          f"floor-driven (70 for high), got score={score} routing={routing}")
    check(scorer.route(routing) == "llm",
          f"unset llm_gate: a matched high rule must still route to llm, "
          f"got {scorer.route(routing)}")


def test_llm_gate_false_excludes_floor_from_routing_only():
    r = _rule(level="high", score_weight=45, llm_gate=False)
    check(r.llm_gate is False, "llm_gate: false must be read as False")
    scorer = Scorer(SCORING_YAML)
    score = scorer.score([r])
    routing = scorer.routing_score([r])
    check(score == 70,
          f"llm_gate:false must NOT change the analyst-facing score (still "
          f"floor-inclusive), got {score}")
    check(routing == 45,
          f"llm_gate:false must exclude the floor from routing_score, "
          f"leaving only score_weight (45), got {routing}")
    check(scorer.route(routing) == "classifier",
          f"with the floor excluded, 45 is below llm_min (60) -- routing "
          f"must fall to 'classifier', got {scorer.route(routing)}")
    check(scorer.route(score) == "llm",
          "sanity: routing off the OLD (floor-inclusive) score would still "
          "say llm -- confirms routing_score is the thing that changed, not "
          "the thresholds")


def test_malformed_llm_gate_fails_closed_to_gate_on():
    """A non-bool value (e.g. a typo'd quoted "false" string) must not
    silently disable the gate via Python truthiness (`bool("false") is
    True`) -- only a literal `False` disables it; anything else keeps the
    safe default (gate ON, more triage rather than less)."""
    r = _rule(level="high", score_weight=45, llm_gate="false")
    check(r.llm_gate is True,
          f"a non-bool llm_gate must fail closed to True (gate stays on), "
          f"got {r.llm_gate!r}")


def test_multiple_matched_rules_only_gated_ones_excluded():
    """One gated + one ungated high rule matching the same event: the
    ungated rule's floor still applies to routing (fail-safe -- one rule
    opting out must not silently suppress triage for a DIFFERENT rule that
    didn't)."""
    gated = _rule(level="high", score_weight=10, llm_gate=False)
    ungated = _rule(level="high", score_weight=10, llm_gate=None)
    scorer = Scorer(SCORING_YAML)
    routing = scorer.routing_score([gated, ungated])
    check(routing == 70,
          f"the ungated rule's floor must still drive routing even though "
          f"a different matched rule opted out, got {routing}")


def test_validate_rules_rejects_non_bool_llm_gate():
    rule = {
        "title": "t", "id": "11111111-1111-1111-1111-111111111111",
        "status": "stable", "level": "high",
        "logsource": {"category": "authentication"},
        "detection": {"sel": {"class_uid": 3002}, "condition": "sel"},
        "siem": {"sector": "common", "score_weight": 40, "llm_gate": "false"},
    }
    errors = validate_rules.validate_rule(rule)
    check(any("llm_gate" in e for e in errors),
          f"a string 'false' for llm_gate must be rejected at validate-time, "
          f"got errors={errors}")

    rule["siem"]["llm_gate"] = False
    errors2 = validate_rules.validate_rule(rule)
    check(not any("llm_gate" in e for e in errors2),
          f"a real bool False must be accepted, got errors={errors2}")


def _with_tmp_rules_dir(fn):
    """Same knob test_hot_reload.py uses: point ws4.RULES_DIR/ALLOWLISTS_DIR
    at a fresh tmpdir so Detector loads ONLY a synthetic rule, then restore."""
    orig_rules, orig_allow = ws4.RULES_DIR, ws4.ALLOWLISTS_DIR
    tmp = Path(tempfile.mkdtemp(prefix="fengarde-llmgate-"))
    try:
        ws4.RULES_DIR = tmp
        ws4.ALLOWLISTS_DIR = tmp / "allowlists"
        fn(tmp)
    finally:
        ws4.RULES_DIR, ws4.ALLOWLISTS_DIR = orig_rules, orig_allow
        shutil.rmtree(tmp, ignore_errors=True)


_RULE_TMPL = """\
title: gated high rule
id: 22222222-2222-2222-2222-222222222222
status: stable
level: high
logsource:
  category: authentication
detection:
  sel:
    class_uid: 3002
  condition: sel
siem:
  sector: common
  score_weight: 45
  llm_gate: {gate}
"""


def test_end_to_end_detector_routes_differently_score_unchanged():
    def body(tmp):
        (tmp / "r.yml").write_text(_RULE_TMPL.format(gate="false"), encoding="utf-8")
        detector = ws4.Detector(plugin_rule_dirs=[])
        event = {"class_uid": 3002, "time": 1750000000000,
                 "siem": {"sector": "common", "ingest_id": "e1"}}
        scored_event, matched, action = detector.process(event)
        check(len(matched) == 1, f"the gated rule must still match, got {matched}")
        check(scored_event["siem"]["score"] == 70,
              f"stored/displayed score must stay floor-inclusive (70), "
              f"got {scored_event['siem']['score']}")
        check(action == "classifier",
              f"with llm_gate:false and score_weight=45 < llm_min, funnel "
              f"action must be 'classifier', got {action!r}")
    _with_tmp_rules_dir(body)

    def body_ungated(tmp):
        (tmp / "r.yml").write_text(_RULE_TMPL.format(gate="true"), encoding="utf-8")
        detector = ws4.Detector(plugin_rule_dirs=[])
        event = {"class_uid": 3002, "time": 1750000000000,
                 "siem": {"sector": "common", "ingest_id": "e2"}}
        scored_event, matched, action = detector.process(event)
        check(scored_event["siem"]["score"] == 70,
              f"score unchanged regardless of gate, got {scored_event['siem']['score']}")
        check(action == "llm",
              f"llm_gate:true (explicit) must behave exactly like the "
              f"pre-Design-B default -- still routes to llm, got {action!r}")
    _with_tmp_rules_dir(body_ungated)


def main():
    test_default_llm_gate_is_true_unchanged_behavior()
    test_llm_gate_false_excludes_floor_from_routing_only()
    test_malformed_llm_gate_fails_closed_to_gate_on()
    test_multiple_matched_rules_only_gated_ones_excluded()
    test_validate_rules_rejects_non_bool_llm_gate()
    test_end_to_end_detector_routes_differently_score_unchanged()

    if FAILS:
        print(f"[FAIL] Design-B llm_gate: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] Design-B: llm_gate decouples funnel routing from severity_floor "
          "without changing the analyst-facing score, defaults preserve exact "
          "pre-fix behavior, malformed values fail closed")


if __name__ == "__main__":
    main()
