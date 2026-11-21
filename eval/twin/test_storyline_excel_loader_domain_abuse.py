"""Acceptance test for storyline_excel_loader_domain_abuse (keyed Excel -> mshta -> PowerShell storyline, 2026-11-19).

Standalone (NOT pytest): ``[OK]`` / ``[FAIL]`` lines, exit 0 only when every check passes:

    python eval/twin/test_storyline_excel_loader_domain_abuse.py

Shared keyed-storyline checks live in ``keyed_storyline_checks``; this file adds what is specific here: the
two domain-controller-side steps come from a DIFFERENT host and shipper address than the workstation, and the
tree is a spawn-only tree (no acting-process link).
"""
from __future__ import annotations

import sys
from pathlib import Path

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

import keyed_storyline_checks as ksc  # noqa: E402

NAME = "excel_loader_domain_abuse"


def extra(check, sdef) -> None:
    for seed in ksc.SEEDS:
        pl = sdef.build(seed)[0]
        first = next(p for s, p in pl if s.label == "loader_shell")
        wks, wks_ip = first["raw"]["Computer"], first["meta"]["shipper_ip"]
        dc = [p for s, p in pl if s.label in ("directory_tamper", "group_escalation") and p["source_type"] == "windows_eventlog"]
        check(f"two hosts: the DC-side records name another Computer and ship from another address (seed {seed})",
              len(dc) == 2 and all(p["raw"]["Computer"] == "dc01" and p["raw"]["Computer"] != wks
                                   and p["meta"]["shipper_ip"] != wks_ip for p in dc))
        check(f"loader_shell: the alert-raising record is an Excel -> mshta creation (seed {seed})",
              any(s.label == "loader_shell" and p["raw"].get("ParentImage", "").endswith("EXCEL.EXE")
                  and p["raw"]["Image"].endswith("mshta.exe") for s, p in pl))
    links = ksc.yaml.safe_load(Path(sdef.oracle_path).read_text(encoding="utf-8"))["causal_links"]
    check("spawn-only tree: every declared link is a spawn link", all(lk["via"] == "spawn" for lk in links))
    check("the PowerShell step (ps_cradle) is the parent of the four later steps",
          {(lk["from"], lk["to"]) for lk in links} >= {("ps_cradle", t) for t in
                                                    ("lsass_read", "directory_tamper", "group_escalation", "log_clear")})


def main() -> int:
    return ksc.run(NAME, extra)


if __name__ == "__main__":
    raise SystemExit(main())
