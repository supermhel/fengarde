"""WP-2-F (roadmap finding S5) + Phase 5 (2026-09-04): the `exposure`
extension to scoring.yaml -- was schema-additive and provably inert, is now
PARTIALLY wired (asset_criticality is real; internet_exposure/tenant_tier
stay inert -- see scoring.yaml's own comment for why).

This proves:
  1. scoring.yaml still parses with `exposure` present alongside every
     existing block.
  2. The existing load-bearing keys -- `version`, `thresholds`,
     `severity_floor`, `clamp` -- are unchanged; Scorer still constructs and
     routes identically for the two still-inert factors' own schema shape.
  3. `enabled` is now True (was False pre-Phase-5) -- this file's own
     original claim that it was inert is now the wrong claim to make; a
     regression back to `enabled: false` would silently un-wire OT
     criticality scoring with zero test signal if this assertion still said
     False.
  4. NEW, real wiring tests: an OT event whose `unmapped.ot.address` matches
     a criticality-tagged ot-points point scores measurably higher than the
     identical event at an address with no ot-points entry -- the exact
     roadmap Phase 5 Verify criterion ("an OT alert on a critical point
     measurably outranks the same rule firing on an unmarked point"), plus a
     mutation check (force `enabled: false` at the Scorer level, confirm the
     gap disappears, confirming this is really the exposure path and not
     some other confound).

Run: python test_exposure_scoring.py   (from inside services/ws4-detection)
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml  # noqa: E402

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
ROOT = SERVICES.parent
sys.path.insert(0, str(HERE))

from scoring import Scorer, load_ot_criticality  # noqa: E402

SCORING_YAML = ROOT / "contracts" / "scoring.yaml"
OT_POINTS_DIR = ROOT / "contracts" / "ot-points"

# The pre-existing (load-bearing) facts this file must NOT have changed.
EXPECTED_VERSION = 1
EXPECTED_THRESHOLDS = {"classifier_min": 20, "llm_min": 60}
EXPECTED_FLOOR = {"informational": 0, "low": 10, "medium": 40, "high": 70, "critical": 80}
EXPECTED_CLAMP = {"min": 0, "max": 100}

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_schema_shape_and_load_bearing_keys_unchanged():
    # --- 1. The extension is schema-additive: the whole file still parses. ---
    cfg = yaml.safe_load(Path(SCORING_YAML).read_text(encoding="utf-8"))
    check(isinstance(cfg, dict), "scoring.yaml did not parse to a mapping")

    # --- 2a. Existing load-bearing keys are unchanged. ---
    check(cfg.get("version") == EXPECTED_VERSION,
          f"version must stay {EXPECTED_VERSION} (an inert additive section must "
          f"not bump it and trip Scorer's R4-24 warn path), got {cfg.get('version')!r}")
    check(cfg.get("thresholds") == EXPECTED_THRESHOLDS,
          f"thresholds changed: {cfg.get('thresholds')!r}")
    check(cfg.get("severity_floor") == EXPECTED_FLOOR,
          f"severity_floor changed: {cfg.get('severity_floor')!r}")
    check(cfg.get("clamp") == EXPECTED_CLAMP,
          f"clamp changed: {cfg.get('clamp')!r}")

    # --- 2b. The loader is undisturbed: Scorer still constructs (this runs the
    # exact-key severity_floor validation -- proving `exposure` did not sneak a
    # foreign key under severity_floor) and routes identically. ---
    scorer = Scorer(SCORING_YAML)
    check(scorer.route(60) == "llm", f"route(60) must be 'llm', got {scorer.route(60)!r}")
    check(scorer.route(50) == "classifier",
          f"route(50) must be 'classifier', got {scorer.route(50)!r}")
    check(scorer.route(10) == "store", f"route(10) must be 'store', got {scorer.route(10)!r}")

    # Funnel- and severity-floor math unchanged: critical floors to 80, medium
    # rule with a 30 weight floors to max(30, 40) = 40.
    crit = scorer._floor_for("critical")
    check(crit == 80, f"severity_floor.critical should floor to 80, got {crit}")
    med = scorer._floor_for("medium")
    check(med == 40, f"severity_floor.medium should floor to 40, got {med}")

    # --- 3. The extension itself is present, ON (Phase 5), and self-consistent. ---
    ex = cfg.get("exposure")
    check(isinstance(ex, dict), "no `exposure` section present")
    check(ex.get("enabled") is True,
          f"exposure.enabled must be True as of Phase 5 (2026-09-04) -- "
          f"asset_criticality has a real reader now, got {ex.get('enabled')!r}")

    if isinstance(ex, dict):
        factors = ex.get("factors", {})
        check(isinstance(factors, dict), "exposure.factors must be a mapping")
        # Every tier-table absolute add is >= 0 and within the clamp band.
        for factor, table in (("asset_criticality", factors.get("asset_criticality", {}).get("tiers", {})),
                              ("tenant_tier", factors.get("tenant_tier", {}).get("tiers", {}))):
            for tier, pts in table.items():
                check(isinstance(pts, int) and 0 <= pts <= EXPECTED_CLAMP["max"],
                      f"{factor}.tiers[{tier}] must be an int in [0, clamp.max], got {pts!r}")
        # Every exposure multiplier is positive (neutral is 1.0).
        levels = factors.get("internet_exposure", {}).get("levels", {})
        for lvl, mult in levels.items():
            check(isinstance(mult, (int, float)) and mult > 0,
                  f"internet_exposure.levels[{lvl}] must be a positive number, got {mult!r}")
        check(levels.get("internal_only") == 1.0,
              f"internal_only must be the neutral multiplier 1.0, got {levels.get('internal_only')!r}")
        # The cap keeps any future-adjusted score inside the existing clamp band.
        ceiling = ex.get("cap", {}).get("ceiling")
        check(isinstance(ceiling, int) and EXPECTED_CLAMP["min"] <= ceiling <= EXPECTED_CLAMP["max"],
              f"exposure.cap.ceiling must be within [clamp.min, clamp.max], got {ceiling!r}")

        # Structural smoke of the documented formula on a concrete sample:
        # base 40 (a floor-driven medium) + crown_jewel(15) + premium(10) with an
        # internet_facing multiplier (1.25) must stay <= clamp.max.
        add = factors.get("asset_criticality", {}).get("tiers", {}).get("crown_jewel", 0) \
            + factors.get("tenant_tier", {}).get("tiers", {}).get("premium", 0)
        mult = levels.get("internet_facing", 1.0)
        base = 40
        adjusted = base + add + round(base * (mult - 1))
        # Compare the RAW (unclamped) formula output to the band -- NOT
        # adjust(adjusted) (2026-09-02 review): adjust() unconditionally
        # clamps its input into [min, max], so wrapping `adjusted` in it
        # before this comparison made the check tautologically true for any
        # tier/multiplier values, silently defeating its purpose of catching
        # a documented-formula regression that overflows the clamp band.
        check(EXPECTED_CLAMP["min"] <= adjusted <= EXPECTED_CLAMP["max"],
              f"documented exposure formula over base {base} gives {adjusted}, "
              f"outside clamp band {EXPECTED_CLAMP}")


class _FakeRule:
    def __init__(self, score_weight=30, level="medium", llm_gate=True, exposure_gate=True):
        self.score_weight = score_weight
        self.level = level
        self.llm_gate = llm_gate
        self.exposure_gate = exposure_gate


def test_load_ot_criticality_reads_the_real_sample():
    """load_ot_criticality() against the real contracts/ot-points/ directory
    -- not a synthetic fixture -- must find the real plc-line3.yml sample
    point and skip writer-categories.yml/README.md without erroring."""
    table = load_ot_criticality(OT_POINTS_DIR)
    check(table.get(40001) == "high",
          f"the real plc-line3.yml sample's setpoint point (wire_address "
          f"40001, criticality: high) must be loaded, got {table.get(40001)!r}")


def test_load_ot_criticality_missing_dir_is_empty_not_an_error():
    table = load_ot_criticality(ROOT / "contracts" / "does-not-exist")
    check(table == {}, f"a missing ot-points dir must return {{}}, got {table}")


def test_ot_alert_on_a_criticality_tagged_point_measurably_outranks_an_unmarked_one():
    """The roadmap Phase 5 Verify criterion, proven directly: identical
    matched rules, identical base score -- the ONLY difference is the OT
    event's address. A critical/high-tagged point must score strictly
    higher than one no ot-points file mentions."""
    scorer = Scorer(SCORING_YAML, ot_points_dir=OT_POINTS_DIR)
    rule = _FakeRule(score_weight=30, level="medium")

    tagged_event = {"unmapped": {"ot": {"address": 40001}}}  # real sample: criticality high -> +10
    unmarked_event = {"unmapped": {"ot": {"address": 59999}}}  # not in any ot-points file

    tagged_score = scorer.score([rule], tagged_event)
    unmarked_score = scorer.score([rule], unmarked_event)
    check(tagged_score > unmarked_score,
          f"a high-criticality OT point must score higher than an unmarked one, "
          f"got tagged={tagged_score} unmarked={unmarked_score}")
    check(tagged_score - unmarked_score == 10,
          f"the gap must be exactly the 'high' tier's +10 (scoring.yaml), "
          f"got a gap of {tagged_score - unmarked_score}")

    # Same proof for routing_score() -- the funnel-deciding value, not just
    # the analyst-facing one.
    tagged_routing = scorer.routing_score([rule], tagged_event)
    unmarked_routing = scorer.routing_score([rule], unmarked_event)
    check(tagged_routing > unmarked_routing,
          f"routing_score must show the same gap, got tagged={tagged_routing} "
          f"unmarked={unmarked_routing}")


def test_exposure_gap_disappears_when_disabled_mutation_verified():
    """Mutation proof that the gap above really comes from the exposure
    path, not some other confound: force enabled=False on the SAME scorer
    instance's already-loaded config and confirm the two scores converge."""
    scorer = Scorer(SCORING_YAML, ot_points_dir=OT_POINTS_DIR)
    rule = _FakeRule(score_weight=30, level="medium")
    tagged_event = {"unmapped": {"ot": {"address": 40001}}}
    unmarked_event = {"unmapped": {"ot": {"address": 59999}}}

    scorer._exposure["enabled"] = False
    tagged_score = scorer.score([rule], tagged_event)
    unmarked_score = scorer.score([rule], unmarked_event)
    check(tagged_score == unmarked_score,
          f"with exposure disabled, the two must score identically, got "
          f"tagged={tagged_score} unmarked={unmarked_score}")


def test_event_with_no_ot_address_is_unaffected():
    """A normal (non-OT) event with no unmapped.ot.address at all must score
    exactly as it would with exposure off -- the OT-only signal never
    silently touches an unrelated alert."""
    scorer = Scorer(SCORING_YAML, ot_points_dir=OT_POINTS_DIR)
    rule = _FakeRule(score_weight=30, level="medium")
    check(scorer.score([rule], {}) == scorer.score([rule], None) == 40,
          "a non-OT event (or none at all) must floor to medium=40 with no "
          "exposure adjustment")


def test_exposure_gate_false_excludes_routing_but_not_score():
    """Review-fix (2026-09-04): a rule with exposure_gate=False must not let
    exposure's point-add cross it into a higher funnel tier via
    routing_score(), while score() (the analyst-facing value) still shows
    the full exposure-adjusted severity. Reproduces the exact regression
    found in review: a low-scored, ticketed rule (base 10, under
    classifier_min=20) on a 'critical' tier OT point (+20) must NOT reach
    the classifier funnel, even though its true severity (score()) does
    reflect the critical asset."""
    scorer = Scorer(SCORING_YAML, ot_points_dir=OT_POINTS_DIR)
    gated_rule = _FakeRule(score_weight=10, level="low", exposure_gate=False)
    ungated_rule = _FakeRule(score_weight=10, level="low", exposure_gate=True)
    critical_event = {"unmapped": {"ot": {"address": 1}}}  # plc-line3.yml: criticality critical -> +20

    gated_score = scorer.score([gated_rule], critical_event)
    gated_routing = scorer.routing_score([gated_rule], critical_event)
    ungated_score = scorer.score([ungated_rule], critical_event)
    ungated_routing = scorer.routing_score([ungated_rule], critical_event)

    check(gated_score == ungated_score == 30,
          f"score() must show full exposure-adjusted severity regardless of "
          f"exposure_gate (both must be base 10 + critical tier 20 = 30), "
          f"got gated={gated_score} ungated={ungated_score}")
    check(gated_routing == 10,
          f"routing_score() with exposure_gate=False must stay at the base "
          f"score (10), unaffected by exposure, got {gated_routing}")
    check(ungated_routing == 30,
          f"routing_score() with exposure_gate=True (default) must include "
          f"exposure same as score(), got {ungated_routing}")

    from scoring import Scorer as _S  # local import, avoids polluting module scope
    t = _S(SCORING_YAML).t
    check(gated_routing < t["classifier_min"],
          f"the whole point of exposure_gate=False: gated routing_score "
          f"({gated_routing}) must stay under classifier_min "
          f"({t['classifier_min']}) -- this is the ticketed-OT-write "
          f"regression this test exists to prevent")
    check(ungated_routing >= t["classifier_min"],
          f"sanity: without the gate, the same event WOULD cross into the "
          f"classifier funnel (got {ungated_routing} vs classifier_min "
          f"{t['classifier_min']}), confirming the gate is what's doing the work")


def test_exposure_gate_mixed_co_fire_does_not_suppress_the_ungated_rule():
    """Review-fix (2026-09-04, round 2): matched_rules can contain BOTH a
    gated and an ungated rule at once -- several shipped rules share
    class_uid 4001 with the ticketed OT-write rule (common_port_scan.yml,
    ot_new_device_on_segment.yml, common_beaconing.yml), so a burst of OT
    traffic could plausibly trip one of those on the SAME event a ticketed
    write also matches. The OLD 'any rule opts out -> skip exposure for
    the whole alert' logic silently suppressed exposure for the UNGATED
    rule too in that case. This proves the fix: an ungated rule co-firing
    with a gated one still gets its exposure boost, while the gated rule's
    own baseline still acts as a floor (never scores below its no-exposure
    value just because it's mixed in)."""
    scorer = Scorer(SCORING_YAML, ot_points_dir=OT_POINTS_DIR)
    gated_rule = _FakeRule(score_weight=5, level="low", exposure_gate=False)
    ungated_rule = _FakeRule(score_weight=5, level="low", exposure_gate=True)
    critical_event = {"unmapped": {"ot": {"address": 1}}}  # criticality critical -> +20

    mixed_routing = scorer.routing_score([gated_rule, ungated_rule], critical_event)
    gated_alone_routing = scorer.routing_score([gated_rule], critical_event)
    classifier_min = scorer.t["classifier_min"]

    check(mixed_routing >= classifier_min,
          f"the ungated rule's exposure eligibility must survive an unrelated "
          f"gated rule co-firing on the same event -- got mixed routing_score="
          f"{mixed_routing}, classifier_min={classifier_min}")
    check(mixed_routing >= gated_alone_routing,
          f"mixing in an ungated rule must never make the routing score LOWER "
          f"than the gated rule scores alone -- got mixed={mixed_routing} "
          f"alone={gated_alone_routing}")

    mixed_score = scorer.score([gated_rule, ungated_rule], critical_event)
    check(mixed_score == 30,
          f"score() (analyst-facing) is untouched by this fix -- still weight_sum(10) "
          f"+ critical tier(20) = 30 regardless of either rule's exposure_gate, "
          f"got {mixed_score}")


def test_ticketed_ot_write_rule_ships_with_exposure_gate_set():
    """Regression guard: the real rule this bug was found against
    (contracts/rules/ot_modbus_unauthorized_write_ticketed.yml) must
    actually carry exposure_gate: false, not just a synthetic fixture --
    otherwise this whole fix is unverified against the rule it was written
    for."""
    rule_path = ROOT / "contracts" / "rules" / "ot_modbus_unauthorized_write_ticketed.yml"
    raw = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    siem = raw.get("siem", {})
    check(siem.get("exposure_gate") is False,
          f"ot_modbus_unauthorized_write_ticketed.yml must set "
          f"siem.exposure_gate: false, got {siem.get('exposure_gate')!r}")

    import sys as _sys
    _sys.path.insert(0, str(SERVICES / "ws4-detection"))
    from engine import Rule
    rule = Rule(raw)
    check(rule.exposure_gate is False,
          f"engine.Rule must parse siem.exposure_gate into rule.exposure_gate, "
          f"got {rule.exposure_gate!r}")

    scorer = Scorer(SCORING_YAML, ot_points_dir=OT_POINTS_DIR)
    critical_event = {"unmapped": {"ot": {"address": 1}}}
    routing = scorer.routing_score([rule], critical_event)
    check(routing < scorer.t["classifier_min"],
          f"the real shipped rule, on a real critical-tier OT point, must "
          f"still route to 'store' not 'classifier' -- got routing_score="
          f"{routing} vs classifier_min={scorer.t['classifier_min']}")


def main():
    test_schema_shape_and_load_bearing_keys_unchanged()
    test_load_ot_criticality_reads_the_real_sample()
    test_load_ot_criticality_missing_dir_is_empty_not_an_error()
    test_ot_alert_on_a_criticality_tagged_point_measurably_outranks_an_unmarked_one()
    test_exposure_gap_disappears_when_disabled_mutation_verified()
    test_event_with_no_ot_address_is_unaffected()
    test_exposure_gate_false_excludes_routing_but_not_score()
    test_exposure_gate_mixed_co_fire_does_not_suppress_the_ungated_rule()
    test_ticketed_ot_write_rule_ships_with_exposure_gate_set()

    if FAILS:
        print(f"[FAIL] WP-2-F exposure scoring extension: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WP-2-F/Phase 5: `exposure` parses alongside the unchanged version/"
          "thresholds/severity_floor/clamp; Scorer still constructs and routes "
          "identically for the two still-inert factors; asset_criticality is now "
          "REAL and wired -- an OT alert on a real ot-points criticality-tagged "
          "address measurably outranks (by exactly its tier's points) the same "
          "rule on an unmarked address, on both score() and routing_score(), "
          "mutation-verified (disabling exposure collapses the gap), and a "
          "non-OT event is provably unaffected")


if __name__ == "__main__":
    main()
