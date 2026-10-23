"""Print the per-rule evidence map for every shipped detection rule (static, no pipeline run).

For each ``contracts/rules/*.yml``: its ATT&CK/ATLAS/ICS technique(s), whether a twin storyline oracle names it
(``eval/twin/oracle*.yaml`` ``detection_points[].expected_rules``) and whether the real-corpus lanes grade it
(the oracle-backed ids in ``eval/detection_accuracy``). The blocking gates that apply to EVERY rule are listed in
``benchmark/rule-evidence.md``; this table shows where the evidence beyond them is thin.

    python tools/rule_evidence_table.py            # markdown to stdout
"""
from __future__ import annotations

import glob
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
# Rules the real-corpus lanes (evtx_eval.py / splunk_eval.py) grade against hand-built oracles.
CORPUS_GRADED = {"common_bruteforce", "common_password_spray", "common_lateral_movement", "common_priv_grant",
                 "common_after_hours_admin", "common_bruteforce_sourceless"}


def _load(path: str) -> dict:
    return yaml.safe_load(open(path, encoding="utf-8")) or {}


def oracle_named() -> set[str]:
    named: set[str] = set()
    for f in glob.glob(str(ROOT / "eval" / "twin" / "oracle*.yaml")):
        for dp in (_load(f).get("detection_points") or {}).values():
            for er in (dp.get("expected_rules") or []):
                rid = er.get("rule_id") if isinstance(er, dict) else er
                if rid:
                    named.add(str(rid))
    return named


def rows() -> list[tuple]:
    named = oracle_named()
    out = []
    for f in sorted(glob.glob(str(ROOT / "contracts" / "rules" / "*.yml"))):
        d = _load(f)
        name = Path(f).stem
        mitre = d.get("mitre") or {}
        tech = mitre.get("technique") or mitre.get("techniques") or ""
        if isinstance(tech, list):
            tech = ", ".join(map(str, tech))
        out.append((name, str(d.get("id", "")), str(tech) or "none", str(d.get("id", "")) in named, name in CORPUS_GRADED))
    return out


def main() -> int:
    r = rows()
    print("| rule | technique | in a twin storyline oracle | graded on real corpora |")
    print("|---|---|---|---|")
    for name, _id, tech, in_oracle, graded in r:
        print(f"| `{name}` | {tech} | {'yes' if in_oracle else '**no**'} | {'yes' if graded else 'no'} |")
    print(f"\n{len(r)} rules; {sum(1 for x in r if x[3])} named in a twin oracle; {sum(1 for x in r if x[4])} graded on real corpora; "
          f"{sum(1 for x in r if x[2] == 'none')} without a technique tag.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
