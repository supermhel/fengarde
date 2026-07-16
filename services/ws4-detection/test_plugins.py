"""M4.5 rule-pack plugin discovery + Detector merge tests.

Uses REAL importlib.metadata.EntryPoint objects pointing at
test_fixtures/example_rule_pack/ (a fixture standing in for a third-party
pip package's rule pack) instead of requiring an actual `pip install`.
EntryPoint.load() still does a genuine import_module + getattr; only the
source of the entry-point list is substituted.

Run: python services/ws4-detection/test_plugins.py
"""
from __future__ import annotations

import sys
from importlib.metadata import EntryPoint
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from plugins import discover_rule_pack_dirs  # noqa: E402
from main import Detector, RULES_DIR, ALLOWLISTS_DIR  # noqa: E402
from engine import load_rules  # noqa: E402

FAILS: list[str] = []

EXAMPLE_PACK_DIR = HERE / "test_fixtures" / "example_rule_pack"
COLLIDING_PACK_DIR = HERE / "test_fixtures" / "colliding_rule_pack"
PLUGIN_RULE_ID = "9f8e7d6c-5b4a-4930-8271-605948372615"
COLLIDING_RULE_ID = "1d2c3b4a-5e6f-4708-8a91-0b1c2d3e4f05"  # == common_port_scan.yml's id


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _ep(name: str, module_attr: str) -> EntryPoint:
    return EntryPoint(name=name, value=module_attr, group="fengarde.rule_packs")


# -- discover_rule_pack_dirs (entry-point loading in isolation) -------------

def test_discovers_a_well_formed_rule_pack_dir():
    # Points at a callable (a lambda-free module-level function) returning a
    # Path -- the documented convention -- via this test module itself.
    eps = [_ep("example", f"{__name__}:_example_pack_dir")]
    found = discover_rule_pack_dirs(eps=eps)
    check(len(found) == 1 and found[0][0] == "example",
          f"the well-formed entry point must be discovered, got {found}")
    check(found[0][1] == EXAMPLE_PACK_DIR, "the resolved path must be the real fixture directory")


def _example_pack_dir() -> Path:
    return EXAMPLE_PACK_DIR


def test_broken_and_nonexistent_targets_are_skipped():
    eps = [
        _ep("broken-module", "nonexistent_fengarde_test_plugin_module.sub:whatever"),
        _ep("not-a-dir", f"{__name__}:_returns_a_file_not_a_dir"),
        _ep("good", f"{__name__}:_example_pack_dir"),
    ]
    found = discover_rule_pack_dirs(eps=eps)
    check([n for n, _ in found] == ["good"],
          f"only the well-formed entry must survive, got {found}")


def _returns_a_file_not_a_dir() -> Path:
    return EXAMPLE_PACK_DIR / "plugin_marker.yml"  # a file, not a directory


def test_no_entry_points_is_a_clean_noop():
    check(discover_rule_pack_dirs(eps=[]) == [], "zero entry points must yield zero rule packs")


def test_real_environment_has_no_plugins_installed():
    # Sanity, proven not assumed: this repo ships zero fengarde.rule_packs
    # entry points, so the REAL discovery (no eps override) must be empty.
    check(discover_rule_pack_dirs() == [],
          "no rule-pack plugins are installed in this environment, expected []")


# -- Detector merge behavior --------------------------------------------------

def test_detector_merges_a_plugin_rule_pack_and_it_fires():
    det = Detector(plugin_rule_dirs=[EXAMPLE_PACK_DIR])
    ids = {r.id for r in det.rules}
    check(PLUGIN_RULE_ID in ids, "the plugin's rule must be present in Detector.rules")

    baseline = Detector(plugin_rule_dirs=[])
    check(len(det.rules) == len(baseline.rules) + 1,
          "exactly one extra rule must have been merged in")

    event = {
        "class_uid": 4001, "category_uid": 4, "activity_id": 6, "time": 1_800_000_000_000,
        "src_endpoint": {"ip": "203.0.113.9"},
        "unmapped": {"example": {"plugin_marker": True}},
        "siem": {"ingest_id": "plugin-test-1"},
    }
    _scored, matched, _action = det.process(event)
    matched_ids = {r.id for r in matched}
    check(PLUGIN_RULE_ID in matched_ids,
          f"the plugin rule must actually FIRE on a matching event (not just be loaded), matched={matched_ids}")


def test_colliding_rule_id_never_overrides_the_builtin():
    det = Detector(plugin_rule_dirs=[COLLIDING_PACK_DIR])
    survivors = [r for r in det.rules if r.id == COLLIDING_RULE_ID]
    check(len(survivors) == 1, f"an id collision must not duplicate the rule, got {len(survivors)}")
    check(survivors[0].title.startswith("Port scan"),
          f"the BUILT-IN rule (loaded first) must win an id collision, got title={survivors[0].title!r}")
    check(survivors[0].score_weight != 99,
          "the plugin's score_weight=99 must never have been applied -- the built-in fully wins, not merges")


def test_detector_default_matches_plain_load_rules_when_no_plugins_installed():
    # With no plugins installed in THIS environment, Detector()'s default
    # (plugin_rule_dirs=None -> real discovery) must yield exactly the same
    # rule set as calling load_rules() directly -- proves the M4.5 wiring is
    # a true no-op absent any installed plugin package.
    det = Detector()
    plain = load_rules(RULES_DIR, ALLOWLISTS_DIR)
    check({r.id for r in det.rules} == {r.id for r in plain},
          "Detector()'s default rule set must match load_rules() directly with no plugins installed")


def main():
    test_discovers_a_well_formed_rule_pack_dir()
    test_broken_and_nonexistent_targets_are_skipped()
    test_no_entry_points_is_a_clean_noop()
    test_real_environment_has_no_plugins_installed()
    test_detector_merges_a_plugin_rule_pack_and_it_fires()
    test_colliding_rule_id_never_overrides_the_builtin()
    test_detector_default_matches_plain_load_rules_when_no_plugins_installed()

    if FAILS:
        print(f"[FAIL] rule pack plugins: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] M4.5 rule-pack plugin discovery: well-formed pack discovered via a REAL "
          "EntryPoint.load(), broken/non-dir targets skipped, Detector actually MERGES a "
          "plugin's rule and it FIRES on a matching event, an id collision leaves the "
          "built-in fully in charge (never even partially applies the plugin's fields), "
          "and the real (plugin-free) environment matches plain load_rules() exactly")


if __name__ == "__main__":
    main()
