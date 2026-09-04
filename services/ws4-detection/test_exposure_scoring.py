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
    def __init__(self, score_weight=30, level="medium", llm_gate=True):
        self.score_weight = score_weight
        self.level = level
        self.llm_gate = llm_gate


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


def main():
    test_schema_shape_and_load_bearing_keys_unchanged()
    test_load_ot_criticality_reads_the_real_sample()
    test_load_ot_criticality_missing_dir_is_empty_not_an_error()
    test_ot_alert_on_a_criticality_tagged_point_measurably_outranks_an_unmarked_one()
    test_exposure_gap_disappears_when_disabled_mutation_verified()
    test_event_with_no_ot_address_is_unaffected()

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
