"""Repo-wide statement + branch coverage over the M2 coverage gate's suite set.

Phase 5 item 10 (OpenSSF Best Practices: test_statement_coverage80/90,
test_branch_coverage80). Runs every suite tools/coverage_gate.py runs
(TARGETS + the run_all_tests.sh-derived sets -- the gate's exact universe)
into ONE combined data file with --branch, then prints the three numbers
coverage.py's JSON totals support, each with its definition:

* statement = covered_lines / num_statements
* branch    = covered_branches / num_branches        (branch arcs taken)
* combined  = coverage.py's own TOTAL percent_covered
              ((covered_lines + covered_branches) / (num_statements + num_branches))

Review of PR #96 (2026-10-14): the first published numbers came from a
one-off script that labeled the COMBINED total "statement coverage" and gave
partially-covered branch LINES half credit as "branch coverage". Neither is
a coverage.py metric; this script is the committed, reproducible replacement.

Slow (~100+ suite invocations under coverage) -- deliberately NOT in the gate.
Run:  python tools/coverage_summary.py
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import coverage_gate as G  # noqa: E402

DATA = ROOT / ".coverage.summary.tmp"


def pct(num: int, den: int) -> float | None:
    return round(100.0 * num / den, 2) if den else None


def summarize(totals: dict) -> dict:
    return {
        "statement_pct": pct(totals["covered_lines"], totals["num_statements"]),
        "branch_pct": pct(totals.get("covered_branches", 0), totals.get("num_branches", 0)),
        "combined_pct": round(totals["percent_covered"], 2),
        "statements": f'{totals["covered_lines"]}/{totals["num_statements"]}',
        "branches": f'{totals.get("covered_branches", 0)}/{totals.get("num_branches", 0)}',
    }


def main() -> int:
    DATA.unlink(missing_ok=True)
    try:
        derived = G._derive_scripts((ROOT / "run_all_tests.sh").read_text(encoding="utf-8"))
    except FileNotFoundError:
        derived = {}
    ran, failures = 0, []
    for service_dir, (source, scripts, _min) in G.TARGETS.items():
        for script in G._effective_scripts(source, scripts, derived):
            r = subprocess.run(
                [sys.executable, "-m", "coverage", "run", "--branch",
                 f"--source={source}", "-a", f"--data-file={DATA}",
                 str(ROOT / source / script)],
                cwd=ROOT, capture_output=True, text=True)
            ran += 1
            if r.returncode != 0:  # reported, never silently dropped
                failures.append(f"{service_dir}/{script}")
    out = subprocess.run(
        [sys.executable, "-m", "coverage", "json", f"--data-file={DATA}", "-o", "-"],
        cwd=ROOT, check=True, capture_output=True, text=True)
    DATA.unlink(missing_ok=True)
    s = summarize(json.loads(out.stdout)["totals"])
    print(f"suites_run={ran} suite_failures={len(failures)} {failures if failures else ''}")
    print(f"statement_coverage={s['statement_pct']}% ({s['statements']} statements)")
    print(f"branch_coverage={s['branch_pct']}% ({s['branches']} branch arcs)")
    print(f"combined_total={s['combined_pct']}% (coverage.py TOTAL, statements+branches)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
