from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from import_sigma_rules import import_sigma_rule  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def run() -> None:
    # Basic equality + condition rewrite.
    rule = import_sigma_rule({
        "title": "Test Rule",
        "id": "11111111-1111-1111-1111-111111111111",
        "level": "high",
        "logsource": {"category": "authentication"},
        "detection": {
            "sel": {"class_uid": 3002, "activity_id": {"in": [4, 5]}},
            "condition": "sel",
        },
        "siem": {"score_weight": 20},
    })
    check(rule["detection"]["sel"]["class_uid"] == 3002, "equality preserved")
    check(rule["condition"] == "sel", "condition preserved")
    check(rule["siem"]["score_weight"] == 20, "siem preserved")

    # Sigma selection names sanitized.
    rule = import_sigma_rule({
        "title": "Test Special Chars",
        "id": "22222222-2222-2222-2222-222222222222",
        "level": "medium",
        "logsource": {"category": "network_activity"},
        "detection": {
            "Special-Name": {"dst_port": 443},
            "condition": "Special-Name",
        },
    })
    check("special_name" in rule["detection"], "selection sanitized")
    check("special_name" in rule["condition"], "condition name rewritten")

    # Modifiers -> local operators. Unsupported/unsafe modifiers are silently
    # dropped; the rule still imports if anything usable remains.
    rule = import_sigma_rule({
        "title": "Test Modifiers",
        "id": "33333333-3333-3333-3333-333333333333",
        "level": "low",
        "logsource": {"category": "process_creation"},
        "detection": {
            "sel": {
                "file.name|contains": "bad",
                "file.path|startswith": "/tmp",
                "file.name|endswith": ".sh",
                "cmd|re": "^/usr/bin/.*$",
                "user|re": "^$",
            },
            "condition": "sel",
        },
        "siem": {"score_weight": 5},
    })
    sel = rule["detection"]["sel"]
    check(sel["file.name"] == {"contains": "bad"}, "contains modifier translated")
    check(sel["file.path"] == {"glob": "/tmp*"}, "startswith modifier translated")
    check(sel["file.name_1"] == {"glob": "*.sh"}, "endswith modifier translated")
    check(sel["cmd"] == {"glob": "/usr/bin/*"}, "safe regex->glob translated")
    # ^$/empty regex is rejected by _safe_glob_from_regex, so that field is dropped.
    check("user" not in sel, "unsupported empty regex dropped from selection")

    # Unsafe regex dropped. If the selection still has usable fields, the rule
    # still imports; if every field was unsupported, the rule is rejected.
    rule = import_sigma_rule({
        "title": "Unsafe partial",
        "id": "44444444-4444-4444-4444-444444444444",
        "level": "medium",
        "logsource": {"category": "process_creation"},
        "detection": {
            "sel": {"cmd|re": "^(a+)+$", "file.name|contains": "bad"},
            "condition": "sel",
        },
    })
    check(rule is not None, "unsupported regex dropped, rule still imports with remaining fields")
    check("cmd" not in rule["detection"]["sel"], "unsupported regex field dropped")
    check(rule["detection"]["sel"]["file.name"] == {"contains": "bad"}, "remaining fields preserved")

    rule = import_sigma_rule({
        "title": "All unsafe",
        "id": "55555555-5555-5555-5555-555555555555",
        "level": "medium",
        "logsource": {"category": "process_creation"},
        "detection": {
            "sel": {"cmd|re": "^(a+)+$"},
            "condition": "sel",
        },
    })
    check(rule is None, "all-unsupported selection makes rule unimportable")

    # Fallback id + level when missing.
    rule = import_sigma_rule({
        "title": "Minimal",
        "logsource": {"category": "cloud"},
        "detection": {"a": {"class_uid": 1}, "condition": "a"},
    })
    check(rule["id"] != "imported-sigma-rule", "missing id replaced with stable fake id")
    check(rule["level"] == "medium", "missing level defaults to medium")

    # Field-list OR shape becomes named selections. The engine's parser handles
    # `or`, so the imported rule is structurally correct even if full
    # Rule.evaluate() has a pre-existing limitation with `or` conditions.
    rule = import_sigma_rule({
        "title": "Or list",
        "id": "55555555-5555-5555-5555-555555555555",
        "level": "high",
        "logsource": {"category": "authentication"},
        "detection": {
            "sel": [{"activity_id": 4}, {"activity_id": 5}],
            "condition": "sel_1 or sel_2",
        },
        "siem": {"score_weight": 10},
    })
    check("sel_1" in rule["detection"], "or list expanded to named selection 1")
    check("sel_2" in rule["detection"], "or list expanded to named selection 2")
    check(rule["condition"] == "sel_1 or sel_2", "condition preserved for or list")
    # Prove the parser accepts the rewritten condition by tokenizing it through
    # the engine's own regex.
    sys.path.insert(0, str(ROOT / "services" / "ws4-detection"))
    import re as _re
    from engine import _parse_or  # noqa: E402
    toks = _re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[\w.]+", rule["condition"])
    values = {"sel_1": True, "sel_2": False}
    val, end = _parse_or(toks, 0, values)
    check(bool(val) is True and end == len(toks),
          "imported or-list condition parses true under engine's parser")


def main() -> None:
    run()
    if FAILS:
        print(f"[FAIL] import_sigma_rules: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] import_sigma_rules")


if __name__ == "__main__":
    main()
