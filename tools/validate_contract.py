#!/usr/bin/env python3
"""Zero-dependency contract validator for Phase 0.

Validates OCSF event fixtures against contracts/ocsf-event.schema.json using a
minimal JSON-Schema subset (required, type, enum, pattern, $ref, nested objects)
plus the SIEM-specific invariant:  type_uid == class_uid*100 + activity_id.

No external packages. Intended to run in CI as the cross-workstream contract gate.

Usage:
    python tools/validate_contract.py                 # validate all fixtures/
    python tools/validate_contract.py path/to/event.json
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contracts" / "ocsf-event.schema.json"
FIXTURES_DIR = ROOT / "fixtures"


def load(p):
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


JSON_TYPES = {
    "object": dict, "array": list, "string": str,
    "integer": int, "number": (int, float), "boolean": bool,
}


def resolve_ref(ref, root_schema):
    # only supports local refs like "#/$defs/endpoint"
    parts = ref.lstrip("#/").split("/")
    node = root_schema
    for part in parts:
        node = node[part]
    return node


def validate(node, schema, root_schema, path, errors):
    if "$ref" in schema:
        schema = resolve_ref(schema["$ref"], root_schema)

    t = schema.get("type")
    if t:
        expected = JSON_TYPES[t]
        # bool is subclass of int in python; guard integers
        if t == "integer" and isinstance(node, bool):
            errors.append(f"{path}: expected integer, got boolean")
            return
        if not isinstance(node, expected):
            errors.append(f"{path}: expected {t}, got {type(node).__name__}")
            return

    if "enum" in schema and node not in schema["enum"]:
        errors.append(f"{path}: value {node!r} not in enum {schema['enum']}")

    if "pattern" in schema and isinstance(node, str):
        if not re.search(schema["pattern"], node):
            errors.append(f"{path}: {node!r} does not match pattern")

    if "minimum" in schema and isinstance(node, (int, float)) and node < schema["minimum"]:
        errors.append(f"{path}: {node} < minimum {schema['minimum']}")
    if "maximum" in schema and isinstance(node, (int, float)) and node > schema["maximum"]:
        errors.append(f"{path}: {node} > maximum {schema['maximum']}")

    if schema.get("type") == "object" or "properties" in schema:
        for req in schema.get("required", []):
            if not isinstance(node, dict) or req not in node:
                errors.append(f"{path}: missing required property '{req}'")
        props = schema.get("properties", {})
        if isinstance(node, dict):
            for k, v in node.items():
                if k in props:
                    validate(v, props[k], root_schema, f"{path}.{k}", errors)

    if schema.get("type") == "array" and isinstance(node, list):
        item_schema = schema.get("items")
        if item_schema:
            for i, item in enumerate(node):
                validate(item, item_schema, root_schema, f"{path}[{i}]", errors)


def check_invariant(event, errors):
    try:
        c, a, t = event["class_uid"], event["activity_id"], event["type_uid"]
    except KeyError:
        return  # missing fields already reported by schema pass
    # H6 (2026-07-30 audit): a type-mismatched field (e.g. a fixture typo
    # class_uid: "3002") used to raise an unhandled TypeError out of this
    # function, crashing main()'s `for f in files:` loop and silently
    # skipping validation of every alphabetically-later fixture in the run.
    # A wrong-typed value is already reported by the schema pass -- just
    # don't also crash the invariant check on it.
    if not all(isinstance(x, int) and not isinstance(x, bool) for x in (c, a, t)):
        return
    if t != c * 100 + a:
        errors.append(
            f".type_uid: invariant violated: {t} != class_uid*100+activity_id "
            f"({c}*100+{a}={c*100+a})"
        )


def validate_event(event, schema):
    errors = []
    validate(event, schema, schema, "", errors)
    check_invariant(event, errors)
    return errors


def main() -> int:
    schema = load(SCHEMA_PATH)
    args = sys.argv[1:]
    if args:
        files = [Path(a) for a in args]
    else:
        files = sorted(FIXTURES_DIR.glob("*.json"))

    # Gap-hunt finding (2026-08-26): with zero fixtures (empty/renamed
    # fixtures dir -- or, in CI, no fixtures checked out) the loop below never
    # runs, overall_ok stays True, and this printed "RESULT: PASS" with exit 0
    # -- a contract gate that validated NOTHING kept the tree green. Count
    # floor: an empty fixture set is an explicit failure, never a pass.
    if not files:
        print("[FAIL] ZERO fixtures were validated -- every check below is "
              "vacuously true over an empty set, so this gate would print "
              "PASS while validating NOTHING. The fixtures directory "
              f"{FIXTURES_DIR} is empty or missing.")
        return 1

    overall_ok = True
    for f in files:
        try:
            event = load(f)
        except (OSError, json.JSONDecodeError) as exc:
            overall_ok = False
            print(f"[FAIL] {f.name}: could not load ({type(exc).__name__}: {exc})")
            continue
        errors = validate_event(event, schema)
        expect_invalid = "invalid" in f.stem
        if errors:
            if expect_invalid:
                print(f"[OK ] {f.name}: correctly rejected ({len(errors)} error(s))")
                for e in errors:
                    print(f"        - {e}")
            else:
                overall_ok = False
                print(f"[FAIL] {f.name}: {len(errors)} error(s)")
                for e in errors:
                    print(f"        - {e}")
        else:
            if expect_invalid:
                overall_ok = False
                print(f"[FAIL] {f.name}: expected rejection but it validated")
            else:
                print(f"[OK ] {f.name}: valid")

    print("\nRESULT:", "PASS" if overall_ok else "FAIL")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
