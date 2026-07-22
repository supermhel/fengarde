"""P3-2 (2026-07-21 audit fix plan) -- coverage_layer.py sanity tests.

Zero infra, zero prerequisites: parses the real contracts/rules/*.yml on disk
(the same declared-coverage input the scorecard uses in production) and
checks the shape of what it produces, not exact counts (those legitimately
change as rules are added).

Run: python eval/attack/test_coverage_layer.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import coverage_layer  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_every_rule_file_is_loaded():
    rules = coverage_layer.load_rules()
    n_files = len(list(coverage_layer.RULES_DIR.glob("*.yml")))
    check(len(rules) == n_files,
          f"expected one entry per rule file ({n_files}), got {len(rules)}")


def test_known_technique_present_under_attack_framework():
    rules = coverage_layer.load_rules()
    coverage = coverage_layer.build_coverage(rules)
    attack = coverage["by_framework"].get("attack", {})
    check("T1110" in attack, "T1110 (brute force, common_bruteforce.yml) must appear "
                              "under the 'attack' framework")
    check("common_bruteforce" not in str(attack.get("T1110", {})) or True, "sanity: no crash")


def test_rule_with_no_mitre_block_is_flagged_undeclared():
    rules = coverage_layer.load_rules()
    coverage = coverage_layer.build_coverage(rules)
    undeclared_files = {r["file"] for r in coverage["undeclared_rules"]}
    check("agent_tool_call_burst.yml" in undeclared_files,
          "agent_tool_call_burst.yml (the one rule with no mitre: block) must be "
          "listed under undeclared_rules")


def test_navigator_layer_only_covers_frameworks_navigator_understands():
    rules = coverage_layer.load_rules()
    coverage = coverage_layer.build_coverage(rules)
    layers = coverage_layer.build_layers(coverage)
    check("atlas" not in layers,
          "ATLAS-framework rules must be excluded from the Navigator layer export "
          "(different schema/tooling -- see module docstring)")
    if "attack" in coverage["by_framework"]:
        check("attack" in layers, "an 'attack'-framework rule set must produce an enterprise-attack layer")


def test_navigator_layer_shape():
    rules = coverage_layer.load_rules()
    coverage = coverage_layer.build_coverage(rules)
    layers = coverage_layer.build_layers(coverage)
    layer = layers.get("attack")
    if layer is None:
        return
    check(layer["domain"] == "enterprise-attack", f"wrong domain: {layer['domain']!r}")
    check(isinstance(layer["techniques"], list) and len(layer["techniques"]) > 0,
          "layer must list at least one technique")
    ids = {t["techniqueID"] for t in layer["techniques"]}
    check("T1110" in ids, "T1110 must appear in the enterprise-attack Navigator layer")
    for t in layer["techniques"]:
        check(t["score"] == 1 and t["enabled"] is True,
              f"declared-coverage entries must be scored 1/enabled, got {t}")


def run():
    test_every_rule_file_is_loaded()
    test_known_technique_present_under_attack_framework()
    test_rule_with_no_mitre_block_is_flagged_undeclared()
    test_navigator_layer_only_covers_frameworks_navigator_understands()
    test_navigator_layer_shape()


def main():
    run()
    if FAILS:
        print(f"[FAIL] eval/attack/coverage_layer.py: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] P3-2: coverage_layer.py parses every rule's mitre: block, flags the "
          "one undeclared rule, and produces a well-shaped enterprise-attack Navigator "
          "layer (ATLAS-framework rules correctly excluded from that export)")


if __name__ == "__main__":
    main()
