#!/usr/bin/env python3
"""The CI tiers together ARE the full gate (nothing dropped by the split).

run_all_tests.sh wraps every stanza in `if tier_on <tier>; then ... fi  # tier: <tier>`; ci.yml runs
each tier as its own job and the whole file as `full-gate` on main. This test pins the pieces:

  * every `$PY` invocation sits inside exactly one tier block (no stanza in no tier, none in two);
  * every declared tier has a block, and every block names a declared tier;
  * ci.yml runs each tier via GATE_TIER and `full-gate` runs the script with no GATE_TIER;
  * artifact consumers run after their producers, in the file AND in the job graph (needs:).
"""
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE = (ROOT / "run_all_tests.sh").read_text(encoding="utf-8").split("\n")
WF = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
problems: list[str] = []

declared = next(re.search(r'GATE_TIERS="([^"]+)"', l).group(1).split() for l in GATE if l.startswith("GATE_TIERS="))  # type: ignore[union-attr]
blocks: list[tuple[str, int, int]] = []  # (tier, first line, last line), 1-indexed
open_tier, start = None, 0
for n, line in enumerate(GATE, 1):
    m = re.match(r"if tier_on (\S+); then\s+# tier: (\S+)$", line)
    if m:
        if open_tier:
            problems.append(f"line {n}: tier block nested inside '{open_tier}' (opened line {start})")
        if m.group(1) != m.group(2):
            problems.append(f"line {n}: if-line names '{m.group(1)}' but its comment says '{m.group(2)}'")
        open_tier, start = m.group(1), n
        continue
    m = re.match(r"fi\s+# tier: (\S+)$", line)
    if m:
        if m.group(1) != open_tier:
            problems.append(f"line {n}: closes '{m.group(1)}' but the open block is '{open_tier}'")
        else:
            blocks.append((open_tier, start, n))
        open_tier = None
        continue
    if re.search(r"\$PY\b", line) and not open_tier and not line.lstrip().startswith("PY="):
        problems.append(f"line {n}: stanza outside every tier block (it would run only in the full gate): {line.strip()[:90]}")
if open_tier:
    problems.append(f"tier '{open_tier}' opened at line {start} is never closed")
for t, _, _ in blocks:
    if t not in declared:
        problems.append(f"block names undeclared tier '{t}'")
for t in declared:
    if not any(b[0] == t for b in blocks):
        problems.append(f"declared tier '{t}' has no block")

# Producers before consumers inside the file (the scorecard/ratchet read what earlier tiers wrote).
# eval-twin's later blocks (detection-accuracy controls) write no artifact, only its FIRST block does.
last_of = {t: max((b[2] for b in blocks if b[0] == t), default=0) for t in declared}
last_of["eval-twin"] = min((b[2] for b in blocks if b[0] == "eval-twin"), default=0)
first_gates = min((b[1] for b in blocks if b[0] == "eval-gates"), default=0)
for t in ("eval-twin", "eval-layers", "eval-matrix", "eval-report"):
    if last_of[t] > first_gates:
        problems.append(f"tier '{t}' has a block after the first eval-gates block (artifact consumers must run last)")
first_report = min((b[1] for b in blocks if b[0] == "eval-report"), default=0)
if last_of["eval-layers"] > first_report:
    problems.append("eval-layers must precede eval-report (report.py reads matrix.latest.json)")

# ci.yml: one job per tier, the full gate unfiltered, and a job graph that matches the file order.
jobs = WF["jobs"]
runs: dict[str, list[str]] = {}
for jid, job in jobs.items():
    for step in job.get("steps", []):
        if "run" in step and "run_all_tests.sh" in step["run"]:
            runs.setdefault(jid, []).append(str(step.get("env", {}).get("GATE_TIER", "")))
tier_jobs = {t: next((j for j, v in runs.items() if t in v), None) for t in declared}
for t, j in tier_jobs.items():
    if j is None:
        problems.append(f"ci.yml has no job running GATE_TIER={t}")
if runs.get("full-gate") != [""]:
    problems.append(f"ci.yml full-gate must run run_all_tests.sh once with no GATE_TIER (got {runs.get('full-gate')})")


def needs(job: str) -> set[str]:
    n = jobs[job].get("needs", [])
    return {n} if isinstance(n, str) else set(n)


if not problems:
    if "eval-layers" not in needs(tier_jobs["eval-report"]):
        problems.append("the eval-report job must `needs:` the eval-layers job (it downloads matrix.latest.json)")
    for t in ("eval-twin", "eval-layers", "eval-matrix", "eval-report"):
        if tier_jobs[t] not in needs(tier_jobs["eval-gates"]):
            problems.append(f"the eval-gates job must `needs:` the {t} job (it consumes its artifacts)")
    agg = needs("contract-tests")
    for t in declared:
        if tier_jobs[t] not in agg:
            problems.append(f"required check contract-tests must `needs:` the {t} job, or a red tier would not block merging")
    if "full-gate" not in agg:
        problems.append("required check contract-tests must `needs:` full-gate")

for p in problems:
    print(f"[FAIL] {p}")
if problems:
    sys.exit(1)
print(f"[OK] gate tiers: {len(blocks)} blocks over {len(declared)} tiers cover every stanza; "
      "ci.yml runs each tier, the unfiltered full gate, and orders producers before consumers")
