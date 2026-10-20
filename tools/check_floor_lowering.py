#!/usr/bin/env python3
"""PR guard (owner decision Q2, 2026-10-20): fail if eval/adversarial/evasion_floor.yaml
was LOWERED relative to a base ref without a new dated ``lowered:`` entry.

evasion_cost.py --update-floor --allow-lower --reason records such an entry; a hand edit
does not, which is exactly what this catches. Any maintainer may lower a floor, but the
reason must be written in the file (and so in the PR diff).

    python tools/check_floor_lowering.py --base origin/main
"""
import argparse
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FLOOR = "eval/adversarial/evasion_floor.yaml"
sys.path.insert(0, str(ROOT / "eval" / "adversarial"))
import evasion_cost as EC  # noqa: E402


def _lowered_count(rule_set: dict) -> int:
    return len((rule_set or {}).get("lowered") or [])


def violations(base: dict, new: dict) -> list:
    """Floor moves toward the attacker with no new ``lowered:`` entry on that rule set."""
    out = []
    for rid, nrs in (new.get("rule_sets") or {}).items():
        brs = (base.get("rule_sets") or {}).get(rid)
        if not brs:
            continue
        grew = _lowered_count(nrs) > _lowered_count(brs)
        for name, nf in (nrs.get("fields") or {}).items():
            bf = (brs.get("fields") or {}).get(name)
            if not bf or "value" not in nf or "value" not in bf:
                continue
            if EC._worse(nf.get("better", bf.get("better", "max")), nf["value"], bf["value"]) and not grew:
                out.append(f"{rid}.{name}: {bf['value']} -> {nf['value']} with no new 'lowered:' entry")
        nj, bj = nrs.get("joint_frontier") or {}, brs.get("joint_frontier") or {}
        if nj.get("frontier") and bj.get("frontier") and not grew:
            if EC.frontier_regressed(bj["frontier"], nj["frontier"]):
                out.append(f"{rid}.joint_frontier regressed with no new 'lowered:' entry")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="origin/main")
    a = ap.parse_args(argv)
    r = subprocess.run(["git", "show", f"{a.base}:{FLOOR}"], cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[SKIP] check_floor_lowering: {a.base}:{FLOOR} not readable (new file or no base ref)")
        return 0
    base = yaml.safe_load(r.stdout) or {}
    new = EC.load_floor()
    bad = violations(base, new)
    for b in bad:
        print("[FAIL] " + b)
    if bad:
        print("Lower a floor only via: evasion_cost.py --update-floor --allow-lower --reason '<why>'")
        return 1
    print(f"[OK] check_floor_lowering: no floor lowered vs {a.base} without a recorded reason")
    return 0


if __name__ == "__main__":
    sys.exit(main())
