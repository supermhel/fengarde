"""P3-2 (2026-07-21 audit fix plan) -- declared ATT&CK coverage scorecard.

Parses every rule's `mitre:` block in contracts/rules/*.yml and emits:
  1. A per-tactic/per-technique coverage summary (stdout + JSON).
  2. A MITRE ATT&CK Navigator layer JSON per framework (enterprise-attack,
     ics-attack) -- viewable at mitre-attack.github.io/attack-navigator by
     loading the layer file.

This is DECLARED coverage only: it proves a rule CLAIMS to detect a
technique, not that a real execution of that technique actually fires it.
That empirical half is `eval/detection_accuracy/` (the oracle-replay harness
against EVTX/Splunk corpora) -- see this repo's audit fix plan doc, P3-1/P3-2
sections, for why the two numbers are kept separate and never conflated.

`framework: atlas` rules (MITRE ATLAS, for LLM/agent-specific techniques) are
counted in the summary but excluded from the Navigator layer export: ATLAS
uses its own visualization tooling with a different schema, not the ATT&CK
Navigator's, so writing a same-shaped layer file for it would silently
mislabel it as enterprise-attack when loaded there.

Run: python eval/attack/coverage_layer.py
     make attack-scorecard
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = ROOT / "contracts" / "rules"
OUT_DIR = Path(__file__).resolve().parent / "out"

# framework (rule's own `mitre.framework`, default "attack") -> Navigator
# layer domain string.
_NAVIGATOR_DOMAIN = {
    "attack": "enterprise-attack",
    "attack-ics": "ics-attack",
}

_TACTIC_NAMES = {
    "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
    "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion",
    "TA0006": "Credential Access", "TA0007": "Discovery",
    "TA0008": "Lateral Movement", "TA0009": "Collection",
    "TA0010": "Exfiltration", "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0106": "Impair Process Control", "TA0108": "Initial Access (ICS)",
    "AML.TA0004": "AML Initial Access",
}


def load_rules() -> list[dict]:
    rules = []
    for path in sorted(RULES_DIR.glob("*.yml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            continue
        rules.append({"file": path.name, "id": raw.get("id"),
                       "title": raw.get("title"), "mitre": raw.get("mitre")})
    return rules


def build_coverage(rules: list[dict]) -> dict:
    """{framework: {technique: {tactic, rules: [rule_id,...]}}} plus a flat
    list of rules with no `mitre:` block at all (the anti-dormancy-adjacent
    gap tools/validate_rules.py doesn't itself fail CI on -- declaring a
    technique is optional, unlike the schema fields validate_rules.py DOES
    enforce)."""
    by_framework: "dict[str, dict[str, dict]]" = defaultdict(dict)
    undeclared = []
    for r in rules:
        m = r.get("mitre")
        if not isinstance(m, dict) or not m.get("technique"):
            undeclared.append({"file": r["file"], "id": r["id"], "title": r["title"]})
            continue
        framework = m.get("framework", "attack")
        technique = m["technique"]
        tactic = m.get("tactic", "")
        entry = by_framework[framework].setdefault(
            technique, {"tactic": tactic, "rules": []})
        entry["rules"].append(r["id"])
    return {"by_framework": by_framework, "undeclared_rules": undeclared}


def _navigator_layer(framework: str, techniques: dict) -> dict:
    domain = _NAVIGATOR_DOMAIN[framework]
    return {
        "name": f"FENGARDE declared coverage ({domain})",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": domain,
        "description": ("Declared coverage only -- a rule claiming a technique, "
                        "not a proven detection. See eval/attack/coverage_layer.py."),
        "techniques": [
            {"techniqueID": tid, "score": 1, "enabled": True,
             "comment": f"{len(v['rules'])} rule(s): {', '.join(v['rules'])}"}
            for tid, v in sorted(techniques.items())
        ],
        "gradient": {"colors": ["#ffffff", "#66b2ff"], "minValue": 0, "maxValue": 1},
        "legendItems": [{"label": "Declared (rule mitre: block present)", "color": "#66b2ff"}],
    }


def build_layers(coverage: dict) -> dict:
    """framework -> Navigator layer dict, only for frameworks Navigator
    understands (see module docstring re: ATLAS)."""
    layers = {}
    for framework, techniques in coverage["by_framework"].items():
        if framework not in _NAVIGATOR_DOMAIN:
            continue
        layers[framework] = _navigator_layer(framework, techniques)
    return layers


def print_summary(rules: list[dict], coverage: dict) -> None:
    total = len(rules)
    declared = total - len(coverage["undeclared_rules"])
    print(f"FENGARDE declared ATT&CK/ATLAS coverage -- {declared}/{total} rules carry a mitre: block")
    for framework in sorted(coverage["by_framework"]):
        techniques = coverage["by_framework"][framework]
        by_tactic: "dict[str, list[str]]" = defaultdict(list)
        for tid, v in techniques.items():
            by_tactic[v["tactic"]].append(tid)
        print(f"\n  framework={framework} ({len(techniques)} distinct technique(s), "
              f"{sum(len(v['rules']) for v in techniques.values())} rule mapping(s))")
        for tactic in sorted(by_tactic):
            name = _TACTIC_NAMES.get(tactic, "")
            print(f"    {tactic} {name}: {', '.join(sorted(by_tactic[tactic]))}")
    if coverage["undeclared_rules"]:
        print(f"\n  {len(coverage['undeclared_rules'])} rule(s) with no mitre: block:")
        for r in coverage["undeclared_rules"]:
            print(f"    {r['id']} ({r['file']}) -- {r['title']}")


def main() -> int:
    rules = load_rules()
    coverage = build_coverage(rules)
    print_summary(rules, coverage)

    layers = build_layers(coverage)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    summary_path = OUT_DIR / "coverage_summary.json"
    summary_path.write_text(json.dumps(
        {"by_framework": coverage["by_framework"],
         "undeclared_rules": coverage["undeclared_rules"]}, indent=2))
    print(f"\nwrote {summary_path}")
    for framework, layer in layers.items():
        layer_path = OUT_DIR / f"navigator_layer_{framework}.json"
        layer_path.write_text(json.dumps(layer, indent=2))
        print(f"wrote {layer_path} (load at mitre-attack.github.io/attack-navigator)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
