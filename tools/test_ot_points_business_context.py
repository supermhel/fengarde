"""Test gate for the OPTIONAL `business_context` block on contracts/ot-points/ (WP-3-E).

The block is schema-only: business/operational-impact attributes a point or
device belongs to (plant, production line, business service, owner,
operational state, safety relevance). Everything in it is optional; absent =
no claim. Nothing in the pipeline reads it yet — this gate pins the
contract surface, not any detection behavior.

Asserts:
  (a) every YAML file under contracts/ot-points/ loads with yaml.safe_load
  (b) plc-line3.yml's `business_context` block parses to the six expected keys
  (c) `operational_state` and `safety_relevance` values are within their
      documented enums
  (d) the README's field-obligations table lists the business_context fields
      (static string check on the README file)
  (e) mutation-sound: deleting business_context from the sample makes (b) fail

Run: python tools/test_ot_points_business_context.py   (exit 0 = pass)
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OT_DIR = ROOT / "contracts" / "ot-points"
README = OT_DIR / "README.md"
SAMPLE = OT_DIR / "plc-line3.yml"

_SIX_FIELDS = {
    "plant",
    "production_line",
    "business_service",
    "owner",
    "operational_state",
    "safety_relevance",
}
_OPERATIONAL_STATES = {"production", "maintenance", "decommissioned"}
_SAFETY_RELEVANCE = {"none", "advisory", "safety-instrumented"}


def six_keys_present(bc) -> bool:
    """Core of check (b), shared with the mutation check (e) so that (e)
    proves deleting the block makes EXACTLY this assertion fail.

    Requires a mapping with exactly the six documented keys — no fewer
    (a partial block is a claim the schema does not define), no extras
    (a typo'd field would silently carry no meaning to a future loader).
    """
    return isinstance(bc, dict) and set(bc) == _SIX_FIELDS


def main() -> int:
    failures: list[str] = []

    # (a) every YAML file under contracts/ot-points/ loads
    yml_files = sorted(OT_DIR.glob("*.yml"))
    ok_a = True
    for f in yml_files:
        try:
            yaml.safe_load(f.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - report any load failure
            ok_a = False
            print(f"[FAIL] (a) {f.name} does not load with yaml.safe_load: {exc}")
    if ok_a:
        print(f"[OK] (a) every YAML under contracts/ot-points/ loads with "
              f"yaml.safe_load ({len(yml_files)} file(s))")
    else:
        failures.append("a")

    # (b) sample business_context parses to the six documented keys
    sample = yaml.safe_load(SAMPLE.read_text(encoding="utf-8"))
    bc = sample.get("business_context")
    if six_keys_present(bc):
        print(f"[OK] (b) plc-line3.yml business_context has the six documented "
              f"keys: {', '.join(sorted(_SIX_FIELDS))}")
    else:
        shown = sorted(bc) if isinstance(bc, dict) else repr(bc)
        print(f"[FAIL] (b) business_context is not exactly the six documented "
              f"keys, got: {shown}")
        failures.append("b")

    # (c) enum values within their documented enums
    block = bc if isinstance(bc, dict) else {}
    os_ok = block.get("operational_state") in _OPERATIONAL_STATES
    sr_ok = block.get("safety_relevance") in _SAFETY_RELEVANCE
    if os_ok and sr_ok:
        print(f"[OK] (c) operational_state={block['operational_state']!r} and "
              f"safety_relevance={block['safety_relevance']!r} are within their "
              f"documented enums")
    else:
        print(f"[FAIL] (c) operational_state={block.get('operational_state')!r} "
              f"(expected one of {sorted(_OPERATIONAL_STATES)}), "
              f"safety_relevance={block.get('safety_relevance')!r} "
              f"(expected one of {sorted(_SAFETY_RELEVANCE)})")
        failures.append("c")

    # (d) README field-obligations table lists the business_context fields
    readme_text = README.read_text(encoding="utf-8")
    missing = [
        f"business_context.{field}"
        for field in sorted(_SIX_FIELDS)
        if f"`business_context.{field}`" not in readme_text
    ]
    if not missing:
        print("[OK] (d) README field-obligations table lists all six "
              "business_context fields")
    else:
        print(f"[FAIL] (d) README does not list: {missing}")
        failures.append("d")

    # (e) mutation-sound: deleting business_context from the sample makes (b) fail
    mutated = dict(sample)
    del mutated["business_context"]
    if not six_keys_present(mutated.get("business_context")):
        print("[OK] (e) mutation-sound: deleting business_context from the "
              "sample makes check (b) fail")
    else:
        print("[FAIL] (e) deleting business_context did NOT make check (b) fail "
              "(six_keys_present was gutted?)")
        failures.append("e")

    if failures:
        print(f"[FAIL] {len(failures)} check(s) failed: {', '.join(failures)}")
        return 1
    print("[OK] all checks passed (exit 0)")
    return 0


if __name__ == "__main__":
    sys.exit(main())