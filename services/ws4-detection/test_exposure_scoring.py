"""WP-2-F (roadmap finding S5): the `exposure` extension to scoring.yaml is
schema-additive and provably inert.

This proves three things, all structurally (no scorer wiring -- that is a
later package and explicitly out of scope):
  1. scoring.yaml still parses with the new top-level `exposure` section
     present alongside every existing block (yaml.safe_load).
  2. The existing load-bearing keys -- `version`, `thresholds`,
     `severity_floor`, `clamp` -- are byte-for-byte unchanged by the addition,
     and Scorer still constructs from them and routes identically (so the new
     section disturbs nothing it claims not to).
  3. The `exposure` section is DEFAULT-OFF (`enabled: false`), reads nothing,
     and its own schema is self-consistent: every tier add is >= 0 and within
     the clamp band, every multiplier is > 0, and the documented cap keeps any
     future-adjusted score inside [clamp.min, clamp.max].

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

from scoring import Scorer  # noqa: E402  (validates severity_floor keys on construct)

SCORING_YAML = ROOT / "contracts" / "scoring.yaml"

# The pre-existing (load-bearing) facts this file must NOT have changed.
EXPECTED_VERSION = 1
EXPECTED_THRESHOLDS = {"classifier_min": 20, "llm_min": 60}
EXPECTED_FLOOR = {"informational": 0, "low": 10, "medium": 40, "high": 70, "critical": 80}
EXPECTED_CLAMP = {"min": 0, "max": 100}

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def main():
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

    # --- 3. The extension itself is present, DEFAULT-OFF, and self-consistent. ---
    ex = cfg.get("exposure")
    check(isinstance(ex, dict), "no `exposure` section present")
    check(ex.get("enabled") is False,
          f"exposure.enabled must default to False (inert until a reader exists), "
          f"got {ex.get('enabled')!r}")

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

    if FAILS:
        print(f"[FAIL] WP-2-F exposure scoring extension: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WP-2-F: `exposure` extension is schema-additive and inert -- it parses "
          "alongside the unchanged version/thresholds/severity_floor/clamp, Scorer still "
          "constructs and routes identically, and the section defaults to enabled:false "
          "with a self-consistent cap inside the existing clamp band")


if __name__ == "__main__":
    main()
