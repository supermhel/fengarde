"""blind_grader -- technique-level comparison of a BLIND oracle against the committed oracle (P4).

A blind oracle (docs/handoff/blind-oracles/) is written by an author who never saw this
repository: it carries ATT&CK techniques and "detectable in principle" judgements, and NO rule
ids, so the rule-id graders cannot read it. This module grades it at the level it can be graded:

    class      per step: ``detect`` (a rule should fire), ``gap`` (should be detected, nothing
               does / can), ``context`` (benign enabling telemetry, must not fire). The blind
               side reads ``gap`` / ``detectable_in_principle`` / a technique of "none ...";
               the committed side reads ``context`` / ``gap.no_rule_exists`` / ``expected_rules``.
    technique  the committed side's techniques are the gap's ``attack_technique`` plus every
               expected rule's ``mitre.technique`` (read from the rule file, not the oracle);
               the blind side's are the ids in its free text. ``exact`` / ``parent`` (same
               base technique, e.g. T1071 vs T1071.001) / ``differ`` / ``n/a``.

Each row is ``agree`` (same class, technique not ``differ``) or ``disagree`` with the reason,
and carries an ``owner_decision`` read from ``docs/handoff/blind-oracles/owner_decisions.yaml``
(``OPEN`` when the owner has not decided). The register is ANALYSIS, not a gate: a disagreement
is a question for the owner (is the product missing a rule, or is the blind author wrong?),
never something to tune away. Deterministic: sorted keys, no clock.

Run: python eval/twin/blind_grader.py [--write]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

TWIN = Path(__file__).resolve().parent
ROOT = TWIN.parents[1]
BLIND_DIR = ROOT / "docs" / "handoff" / "blind-oracles"
DECISIONS = BLIND_DIR / "owner_decisions.yaml"
OUT = TWIN / "out" / "blind_register.json"
RULES_DIR = ROOT / "contracts" / "rules"

#: storyline -> archived blind oracle (relative to the repo root)
BLIND_ORACLES = {"phishing_bec": "docs/handoff/blind-oracles/2026-10-14-phishing-bec-blind.yaml"}

_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _techniques(text) -> set:
    return set(_TECH.findall(str(text or "")))


def _rule_techniques(rules_dir: Path = RULES_DIR) -> dict:
    out = {}
    for path in sorted(rules_dir.glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        mitre = doc.get("mitre")
        if not isinstance(mitre, dict):
            mitre = {}
        out[str(doc.get("id"))] = _techniques(mitre.get("technique"))
    return out


def blind_class(point: dict) -> str:
    if str(point.get("attack_technique", "")).strip().lower().startswith("none"):
        return "context"
    if point.get("gap") is True:
        return "gap"
    return "detect" if point.get("detectable_in_principle") is True else "gap"


def committed_class(point: dict) -> str:
    if point.get("context"):
        return "context"
    if point.get("expected_rules"):
        return "detect"
    return "gap"


def technique_match(mine: set, theirs: set) -> str:
    if not mine or not theirs:
        return "n/a"
    if mine & theirs:
        return "exact"
    if {t.split(".")[0] for t in mine} & {t.split(".")[0] for t in theirs}:
        return "parent"
    return "differ"


def grade(blind: dict, committed: dict, rule_tech: dict, decisions: dict | None = None) -> dict:
    decisions = decisions or {}
    oid = str(blind.get("oracle_id"))
    rows = []
    bpts, cpts = blind.get("detection_points") or {}, committed.get("detection_points") or {}
    for step in sorted(set(bpts) | set(cpts), key=lambda s: (
            (committed.get("expected_sequence") or []).index(s)
            if s in (committed.get("expected_sequence") or []) else 99, s)):
        b, c = bpts.get(step), cpts.get(step)
        if b is None or c is None:
            rows.append({"step": step, "verdict": "disagree", "reason": "step missing on one side",
                         "blind_class": blind_class(b) if b else None,
                         "committed_class": committed_class(c) if c else None,
                         "technique": "n/a", "owner_decision": decisions.get(oid, {}).get(step, "OPEN")})
            continue
        bc, cc = blind_class(b), committed_class(c)
        mine = _techniques((c.get("gap") or {}).get("attack_technique"))
        for r in c.get("expected_rules") or []:
            mine |= rule_tech.get(str(r.get("rule_id")), set())
        tm = technique_match(mine, _techniques(b.get("attack_technique")))
        if bc != cc:
            verdict, reason = "disagree", f"class: blind={bc} committed={cc}"
        elif tm == "differ":
            verdict, reason = "disagree", "technique differs"
        else:
            verdict, reason = "agree", ""
        rows.append({"step": step, "verdict": verdict, "reason": reason, "blind_class": bc,
                     "committed_class": cc, "technique": tm,
                     "committed_techniques": sorted(mine), "blind_techniques": sorted(_techniques(b.get("attack_technique"))),
                     "blind_confidence": b.get("confidence"),
                     "owner_decision": decisions.get(oid, {}).get(step, "OPEN")})
    agree = sum(1 for r in rows if r["verdict"] == "agree")
    open_disagreements = [r["step"] for r in rows if r["verdict"] == "disagree" and r["owner_decision"] == "OPEN"]
    return {"blind_oracle": oid, "steps": len(rows), "agree": agree, "disagree": len(rows) - agree,
            "open_disagreements": open_disagreements, "rows": rows}


def run(root: Path = ROOT) -> dict:
    sys.path.insert(0, str(TWIN))
    import scenario_registry as reg  # noqa: PLC0415
    decisions = (yaml.safe_load(DECISIONS.read_text(encoding="utf-8")) or {}) if DECISIONS.exists() else {}
    rule_tech = _rule_techniques(root / "contracts" / "rules")
    out = {}
    for name, rel in sorted(BLIND_ORACLES.items()):
        blind = yaml.safe_load((root / rel).read_text(encoding="utf-8"))
        out[name] = grade(blind, reg.load_oracle(reg.get(name)), rule_tech, decisions.get("decisions") or {})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write", action="store_true", help=f"write {OUT.relative_to(ROOT).as_posix()}")
    args = ap.parse_args(argv)
    res = run()
    for name, g in res.items():
        print(f"== {name} vs {g['blind_oracle']}: {g['agree']}/{g['steps']} agree, "
              f"{len(g['open_disagreements'])} open disagreement(s) ==")
        for r in g["rows"]:
            print(f"   {r['step']:<20} {r['verdict']:<9} blind={r['blind_class']:<8} committed={r['committed_class']:<8} "
                  f"technique={r['technique']:<6} owner={r['owner_decision']}"
                  + (f"  ({r['reason']})" if r["reason"] else ""))
    if args.write:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(res, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        print(f"-> {OUT.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
