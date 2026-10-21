#!/usr/bin/env python3
"""rule_cascade -- run the generated parts of a new-rule cascade, find what is still missing, print the rest.

Adding a rule under contracts/rules/ used to be discovered one failure at a time: PR #112 needed about 15
harness edits found over 3 full ~30 min gate runs. This tool does the mechanical part and reports the manual
part in minutes, by running the CHEAP gate scripts that fail first.

    python tools/rule_cascade.py                       # new rules = added vs origin/main, plus uncommitted
    python tools/rule_cascade.py --rule contracts/rules/win_foo.yml
    python tools/rule_cascade.py --no-generate         # report only: touch no file
    python tools/rule_cascade.py --no-floor            # generate docs but leave evasion_floor.yaml alone

What it RUNS (all deterministic, all existing tools; it never edits anything by hand):
  * eval/adversarial/technique_matrix.py --write-doc          (gap-register block in contracts/detection-coverage.md)
  * eval/adversarial/evasion_cost.py --seed 7 --write-doc     (evasion-cost table in contracts/detection-coverage.md)
  * eval/adversarial/evasion_cost.py --seed 7 --update-floor  only when a new rule is STATEFUL; this moves the
    floor toward the defender only, and is NEVER run with --allow-lower: a refusal is reported, not forced.
Then it runs the gates that catch the next failures: validate_rules, check_rule_producers, check_lane_coverage,
technique_matrix (recomputes scenario_matrix when its artifact is absent: a few minutes).

What it NEVER does: edit an oracle, a waiver, a findings register, a producer fixture, a probe template, a rule
count, or the ratchet baseline. Those are decisions (or hand-written fixtures); they are printed as a checklist,
with the ones the gates already prove missing marked TODO and the rest marked CHECK.

Exit 0 = nothing missing that the cheap gates can see (CHECK items are reminders); 1 = a gate failed or a TODO
item is open; 2 = no new rule found / bad usage.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = "contracts/rules"
COVERAGE_DOC = "contracts/detection-coverage.md"
# Files that quote the rule total; CHECK-listed with every number that differs from the real count.
COUNT_FILES = ("README.md", "SSOT.md", "docs/index.html", "tools/console_e2e/pages.mjs", "tools/console_e2e/README.md")
_COUNT_RE = re.compile(
    r"(?:\((\d+)\)\s*\*\*"                    # "**Detection rules (46)**"
    r"|\b(\d+)\s+(?:detection\s+)?rules\b"   # "46 rules"
    r"|\ball\s+(\d+)\s+rules\b"
    r"|\b(\d+)\s+stateless\s+rules\b)", re.IGNORECASE)


@dataclass
class Item:
    status: str  # "DONE" | "TODO" | "CHECK"
    what: str
    how: str = ""


@dataclass
class Report:
    rule: str
    stateful: bool
    items: list[Item] = field(default_factory=list)


def run(cmd: list[str], timeout: int = 1800) -> tuple[int, str]:
    """Run one repo command from the repo root; (returncode, combined output)."""
    t0 = time.time()
    p = subprocess.run([sys.executable, *cmd], cwd=ROOT, capture_output=True, text=True, timeout=timeout,
                       encoding="utf-8", errors="replace")
    print(f"    [{time.time() - t0:5.0f}s] {' '.join(cmd)} -> rc {p.returncode}", flush=True)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def git(*args: str) -> list[str]:
    p = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    return [ln.strip() for ln in p.stdout.splitlines() if ln.strip()] if p.returncode == 0 else []


def new_rule_files(base: str) -> list[str]:
    """Rule files added vs ``base`` (committed) or present but not yet committed. Renames/edits are not 'new'."""
    found: set[str] = set(git("diff", "--name-only", "--diff-filter=A", f"{base}...HEAD", "--", RULES_DIR))
    for ln in git("status", "--porcelain", "--", RULES_DIR):
        if ln[:2].strip() in {"A", "??", "AM"}:
            found.add(ln[3:].strip().strip('"'))
    return sorted(f for f in found if re.fullmatch(rf"{RULES_DIR}/[^/]+\.ya?ml", f))


def load_rule(path: str) -> dict:
    doc = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    return doc if isinstance(doc, dict) else {}


def is_stateful(rule: dict) -> bool:
    siem = rule.get("siem") or {}
    return siem.get("window_seconds") is not None and siem.get("threshold") is not None


def failing_lines(output: str, needle: str = "") -> list[str]:
    lines = [ln.strip() for ln in output.splitlines() if "[FAIL]" in ln or "FAIL:" in ln]
    mine = [ln for ln in lines if needle and needle in ln]
    return (mine or lines)[:4]


def mentions(path: str, *needles: str) -> bool:
    p = ROOT / path
    if not p.exists():
        return False
    text = p.read_text(encoding="utf-8", errors="replace")
    return any(n and n in text for n in needles)


def count_mentions(total: int) -> list[str]:
    """``file:line: N`` for every rule-total-looking number that is not the real total (a stale count or an
    unrelated one; the reader decides)."""
    out = []
    for f in COUNT_FILES:
        p = ROOT / f
        if not p.exists():
            continue
        for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for m in _COUNT_RE.finditer(line):
                val = next(int(g) for g in m.groups() if g)
                if val != total and val > 20:
                    out.append(f"{f}:{n}: says {val}")
    return out


def cascade(rules: list[str], base: str, generate: bool, floor: bool, recompute: bool) -> list[Report]:
    docs = {p: load_rule(p) for p in rules}
    reports = [Report(p, is_stateful(d)) for p, d in docs.items()]
    any_stateful = any(r.stateful for r in reports)
    total = len(list((ROOT / RULES_DIR).glob("*.y*ml")))
    outputs: dict[str, tuple[int, str]] = {}

    print(f"== rule_cascade: {len(rules)} new rule(s), {total} rules in total ==")
    if generate:
        print("-- generators (deterministic; review the diff they leave) --")
        outputs["tm_doc"] = run(["eval/adversarial/technique_matrix.py", "--write-doc"])
        outputs["ec_doc"] = run(["eval/adversarial/evasion_cost.py", "--seed", "7", "--write-doc"])
        if any_stateful and floor:
            outputs["floor"] = run(["eval/adversarial/evasion_cost.py", "--seed", "7", "--update-floor"])
    print("-- cheap gates (the ones that fail first) --")
    outputs["validate"] = run(["tools/validate_rules.py"])
    outputs["producers"] = run(["tools/check_rule_producers.py"])
    outputs["lanes"] = run(["tools/check_lane_coverage.py"])
    art = ROOT / "eval/adversarial/out/scenario_matrix.latest.json"
    tm_cmd = ["eval/adversarial/technique_matrix.py"] + ([] if art.exists() and not recompute else ["--recompute"])
    outputs["matrix"] = run(tm_cmd)
    outputs["cost"] = run(["eval/adversarial/evasion_cost.py", "--seed", "7"])

    findings_text = (ROOT / "eval/adversarial/evasion_findings.yaml").read_text(encoding="utf-8")
    for rep in reports:
        stem = Path(rep.rule).stem
        rid = str(docs[rep.rule].get("id", ""))
        it = rep.items

        def gate(name: str, label: str, how: str, key: str = "", it: list[Item] = it, stem: str = stem) -> None:
            rc, out = outputs[name]
            if rc == 0:
                it.append(Item("DONE", label + " (gate green)"))
            else:
                detail = "; ".join(failing_lines(out, key or stem)) or (out.strip().splitlines() or [f"rc {rc}"])[-1][:160]
                it.append(Item("TODO", label, f"{how} -- gate says: {detail}"))

        gate("validate", "rule file valid", "fix the rule YAML (tools/validate_rules.py)")
        gate("producers", "producer fixture (anti-dormancy)",
             "add/extend the fixture in tools/check_rule_producers.py so a REAL parser can satisfy the rule")
        gate("lanes", "lane coverage", "see tools/check_lane_coverage.py output")
        has_row = mentions(COVERAGE_DOC, f"`{stem}`", f"| {stem} |", rid)
        it.append(Item("DONE" if has_row else "TODO", f"detection-coverage row for {stem}",
                       f"add a rule row to {COVERAGE_DOC} (class, group_by, threshold, producer, ATT&CK tag)"))
        waived = mentions("eval/adversarial/technique_waivers.yaml", stem)
        rc, out = outputs["matrix"]
        if rc == 0:
            it.append(Item("DONE", "storyline coverage or dated waiver (technique matrix gate green)" +
                           (" -- via waiver" if waived else "")))
        else:
            it.append(Item("TODO", "storyline or dated waiver for the technique matrix",
                           "extend a storyline (eval/twin/storyline_*.py + its oracle) or add a dated line to "
                           "eval/adversarial/technique_waivers.yaml -- an owner decision; this tool never writes it. "
                           f"Gate says: {'; '.join(failing_lines(out, stem)) or 'rc ' + str(rc)}"))
        if rep.stateful:
            if mentions("eval/adversarial/rule_probes.py", stem):
                it.append(Item("DONE", "rule_probes.py reference-burst template"))
            else:
                it.append(Item("CHECK", "rule_probes.py reference-burst template (stateful rule not found there)",
                               "needed when no storyline exercises the rule (it is the only burst the evasion searches have); "
                               "add a template (burst at threshold, one short, key setter) or skip when a storyline covers it"))
            rc, out = outputs["cost"]
            if rc != 0:
                it.append(Item("TODO", "evasion-cost gate / evasion floor",
                               f"{'; '.join(failing_lines(out, stem)) or 'rc ' + str(rc)}; a new floor entry comes from "
                               "`evasion_cost.py --seed 7 --update-floor` (this tool ran it unless --no-floor/--no-generate)"))
            else:
                it.append(Item("DONE", "evasion-cost gate + floor (gate green)"))
            in_f4 = bool(re.search(rf"\b{re.escape(stem)}\b", findings_text))
            it.append(Item("DONE" if in_f4 else "CHECK", f"F4 listing in evasion_findings.yaml for {stem}",
                           "" if in_f4 else "if the evasion-cost gate reports the F4 record-clock-trust finding reproducing for "
                           "this rule set, register it in that finding's rule_sets (a deliberate registration, not a pass-through)"))
        it.append(Item("CHECK", "oracle pins", "if a storyline now exercises the rule: eval/twin/oracle_*.yaml expected_rules, "
                       "oracle_strength.json and the ratchet baseline move -- by `eval/twin/ratchet.py` rules, with a recorded "
                       "reason, never by this tool"))
        stale = count_mentions(total)
        it.append(Item("CHECK", f"rule counts (real total is {total})",
                       "; ".join(stale) if stale else "no differing count found in " + ", ".join(COUNT_FILES)))
    return reports


def render(reports: list[Report]) -> int:
    open_todo = 0
    for rep in reports:
        print(f"\n### {rep.rule}  ({'stateful' if rep.stateful else 'stateless'})")
        for i in rep.items:
            mark = {"DONE": "[x]", "TODO": "[ ] TODO ", "CHECK": "[ ] CHECK"}[i.status]
            print(f"  {mark} {i.what}")
            if i.how and i.status != "DONE":
                print(f"        -> {i.how}")
            open_todo += i.status == "TODO"
    print(f"\n{open_todo} TODO item(s) open (a gate proves them missing); CHECK items are reminders no cheap gate can verify.")
    print("Re-run this tool after each fix; it is cheap. Then run the full gate once: bash run_all_tests.sh")
    return 1 if open_todo else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="rule_cascade", description=__doc__.split("\n\n")[0])
    ap.add_argument("--rule", action="append", default=[], help="a rule file (repeatable); default: files added vs --base")
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--no-generate", action="store_true", help="report only; run no generator, touch no file")
    ap.add_argument("--no-floor", action="store_true", help="never run evasion_cost --update-floor")
    ap.add_argument("--recompute", action="store_true", help="re-run scenario_matrix even if its artifact exists")
    args = ap.parse_args(argv)
    rules = sorted({r.replace("\\", "/") for r in args.rule}) or new_rule_files(args.base)
    missing = [r for r in rules if not (ROOT / r).is_file()]
    if missing:
        print(f"[FAIL] no such rule file: {missing}", file=sys.stderr)
        return 2
    if not rules:
        print(f"no new rule file under {RULES_DIR}/ (vs {args.base} or uncommitted); pass --rule to force one")
        return 2
    return render(cascade(rules, args.base, not args.no_generate, not args.no_floor, args.recompute))


if __name__ == "__main__":
    raise SystemExit(main())
