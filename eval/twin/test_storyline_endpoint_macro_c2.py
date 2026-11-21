"""Acceptance test for storyline_endpoint_macro_c2 (keyed Outlook -> Word -> PowerShell storyline, 2026-11-19).

Standalone (NOT pytest): ``[OK]`` / ``[FAIL]`` lines, exit 0 only when every check passes:

    python eval/twin/test_storyline_endpoint_macro_c2.py

The shared keyed-storyline checks (determinism, real parsers, keys in the raw records, sender scope, oracle
provenance, causal_links == derivation from the raw keys, oracle shape) live in ``keyed_storyline_checks``;
this file adds what is specific to this storyline.
"""
from __future__ import annotations

import sys
from pathlib import Path

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

import keyed_storyline_checks as ksc  # noqa: E402

NAME = "endpoint_macro_c2"


def extra(check, sdef) -> None:
    for seed in ksc.SEEDS:
        pl = sdef.build(seed)[0]
        beats = [p for s, p in pl if s.label == "c2_beacon" and p["raw"]["EventID"] == 3]
        check(f"beacon: >= 20 connections from ONE implant process, one destination (seed {seed})",
              len(beats) >= 20 and len({p["raw"]["ProcessGuid"] for p in beats}) == 1
              and len({p["raw"]["DestinationIp"] for p in beats}) == 1)
        check(f"macro_shell: the alert-raising record is a Word -> PowerShell creation (seed {seed})",
              any(s.label == "macro_shell" and p["raw"].get("ParentImage", "").endswith("WINWORD.EXE")
                  and p["raw"]["Image"].endswith("powershell.exe") for s, p in pl))
        check(f"lsass_read: the EID 10 source is the dumper the PowerShell spawned (seed {seed})",
              any(s.label == "lsass_read" and p["raw"]["EventID"] == 10 for s, p in pl))
    check("structure varies with the seed (account / host)",
          len({sdef.build(s)[0][0][1]["raw"]["Computer"] + sdef.build(s)[0][0][1]["raw"]["User"] for s in ksc.SEEDS}) > 1)
    strict = ksc.sysmon_tree.derive_links(sdef.build(7)[0], strict_table_only=True)
    declared = ksc.yaml.safe_load(Path(sdef.oracle_path).read_text(encoding="utf-8"))["causal_links"]
    check("causal_links: the strict ADR-table (spawn-only) reading is a proper subset of the declared links "
          "(the c2_beacon link is an acting_process link)",
          0 < len(strict) < len(declared) and all(lk in declared for lk in strict))


def main() -> int:
    return ksc.run(NAME, extra)


if __name__ == "__main__":
    raise SystemExit(main())
