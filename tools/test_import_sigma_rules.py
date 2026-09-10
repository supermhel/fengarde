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

    # Review-fix (2026-09-04): exposure_gate must round-trip like llm_gate --
    # this allowlist drifted out of sync with validate_rules.py's once
    # before (exposure_gate landed in one but not the other).
    gate_errs: list[str] = []
    rule = import_sigma_rule({
        "title": "exposure_gate round-trips",
        "id": "33333333-3333-3333-3333-333333333333",
        "level": "low",
        "logsource": {"category": "network_activity"},
        "detection": {"sel": {"class_uid": 4001}, "condition": "sel"},
        "siem": {"score_weight": 10, "exposure_gate": False},
    }, gate_errs)
    check(not gate_errs, f"exposure_gate must be accepted, not reported as unsupported, got {gate_errs}")
    check(rule["siem"].get("exposure_gate") is False,
          f"exposure_gate must survive the rewrite, got {rule['siem'].get('exposure_gate')!r}")

    gate_type_errs: list[str] = []
    import_sigma_rule({
        "title": "exposure_gate must be a real bool",
        "id": "44444444-4444-4444-4444-444444444444",
        "level": "low",
        "logsource": {"category": "network_activity"},
        "detection": {"sel": {"class_uid": 4001}, "condition": "sel"},
        "siem": {"exposure_gate": "false"},
    }, gate_type_errs)
    check(any("exposure_gate" in e and "bool" in e for e in gate_type_errs),
          f"a non-bool exposure_gate must be rejected with a clear reason, got {gate_type_errs}")

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

    # A REAL SigmaHQ rule references a list-selection by its ORIGINAL name
    # (`condition: sel`), never by the expanded `sel_1 or sel_2` the test above
    # hand-writes. That original-name path is the one an importer must get
    # right: collapsing the group to its first branch silently drops every
    # other value the rule was meant to match.
    rule = import_sigma_rule({
        "title": "Or list referenced by original name",
        "id": "66666666-6666-6666-6666-666666666666",
        "level": "high",
        "logsource": {"category": "process_creation"},
        "detection": {
            "sel": [{"file.name": "a.exe"}, {"file.name": "b.exe"}],
            "filter": {"user.name": "svc"},
            "condition": "sel and not filter",
        },
    })
    check(rule["condition"] == "(sel_1 or sel_2) and not filter",
          "list-selection referenced by original name keeps every OR branch")

    # Sigma requires `detection.condition`. When it is missing, the generated
    # fallback must still OR the branches of one list-selection: AND-ing them
    # (same field, two different values) produces a rule that can never fire --
    # a dead rule that would pass a shape check and never a real one.
    errs: list[str] = []
    rule = import_sigma_rule({
        "title": "Or list default condition",
        "id": "77777777-7777-7777-7777-777777777777",
        "level": "high",
        "logsource": {"category": "process_creation"},
        "detection": {
            "sel": [{"file.name": "a.exe"}, {"file.name": "b.exe"}],
        },
    }, errs)
    check(rule["condition"] == "(sel_1 or sel_2)",
          "default condition ORs list-selection branches instead of AND-ing them")
    check(any("condition" in e for e in errs),
          "missing condition is reported, not silently defaulted")
    # Prove the generated default actually fires on ONE branch through the
    # engine's own parser -- the AND version returned False here.
    toks = _re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[\w.]+", rule["condition"])
    val, end = _parse_or(toks, 0, {"sel_1": True, "sel_2": False})
    check(bool(val) is True and end == len(toks),
          "default or-list condition fires when only one branch matches")

    # Unsupported Sigma aggregation syntax must be rejected, not emitted as a
    # rule referencing selections that do not exist.
    errs = []
    rule = import_sigma_rule({
        "title": "Unsupported aggregation",
        "id": "88888888-8888-8888-8888-888888888888",
        "level": "medium",
        "logsource": {"category": "process_creation"},
        "detection": {
            "sel": {"file.name": "a.exe"},
            "condition": "1 of them",
        },
    }, errs)
    check(rule is None, "unsupported `1 of them` aggregation rejected, not emitted")
    check(any("unknown selection" in e for e in errs),
          "rejection reason names the unknown selection references")

    # Dropped detection logic must be visible to the caller. An import that
    # silently discards an unsafe regex produces a WEAKER rule than the Sigma
    # original, and a caller with no error channel cannot know that.
    errs = []
    import_sigma_rule({
        "title": "Reports dropped fields",
        "id": "99999999-9999-9999-9999-999999999999",
        "level": "medium",
        "logsource": {"category": "process_creation"},
        "detection": {
            "sel": {"cmd|re": "^(a+)+$", "file.name|contains": "bad"},
            "condition": "sel",
        },
        "siem": {"bogus_key": 1},
    }, errs)
    check(errs, "dropped/unsupported source content is reported via the errors channel")

    # A selection named after a boolean keyword can never be referenced: the
    # rewriter must leave `and`/`or`/`not` alone to preserve real operators, so
    # the reference survives unsubstituted and the condition is invalid. That
    # imports cleanly and then never fires -- reject it instead.
    for keyword in ("and", "or", "not"):
        errs = []
        rule = import_sigma_rule({
            "title": f"Keyword selection {keyword}",
            "logsource": {"category": "process_creation"},
            "detection": {
                keyword: {"file.name": "a.exe"},
                "condition": keyword,
            },
        }, errs)
        check(rule is None, f"selection named '{keyword}' is rejected, not silently dead")
        check(any("reserved condition keyword" in e for e in errs),
              f"rejection of selection named '{keyword}' names the real reason")

    # Same collision via a list-selection, whose expansions (`and_1`, `and_2`)
    # are not themselves keywords -- the unreferenceable name is the original.
    errs = []
    rule = import_sigma_rule({
        "title": "Keyword list selection",
        "logsource": {"category": "process_creation"},
        "detection": {
            "or": [{"file.name": "a.exe"}, {"file.name": "b.exe"}],
            "condition": "or",
        },
    }, errs)
    check(rule is None, "list-selection named after a keyword is rejected too")

    # Case-folding must not smuggle one past the check.
    errs = []
    rule = import_sigma_rule({
        "title": "Keyword selection uppercased",
        "logsource": {"category": "process_creation"},
        "detection": {"AND": {"file.name": "a.exe"}, "condition": "AND"},
    }, errs)
    check(rule is None, "selection named 'AND' is rejected after sanitization lowercases it")


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
