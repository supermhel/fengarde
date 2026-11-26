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
        check(f"loader_shell: the alert-raising record is an Excel -> mshta creation, marked as the step's trigger (seed {seed})",
              any(s.label == "loader_shell" and p["meta"].get("twin_trigger") and p["raw"].get("ParentImage", "").endswith("EXCEL.EXE")
                  and p["raw"]["Image"].endswith("mshta.exe") for s, p in pl))
        helpers = {s.label for s, p in pl if p["source_type"] == "sysmon" and p["raw"]["EventID"] == 1
                   and not p["meta"].get("twin_trigger")}
        check(f"the DC-side steps carry only helper process records (ldifde, net group): never link endpoints (seed {seed})",
              {"directory_tamper", "group_escalation"} <= helpers
              and not any(p["meta"].get("twin_trigger") for s, p in pl if s.label in ("directory_tamper", "group_escalation")))
    declared = {(lk["from"], lk["to"]) for lk in
                ksc.yaml.safe_load(Path(sdef.oracle_path).read_text(encoding="utf-8"))["causal_links"]}
    want = {("loader_shell", "ps_encoded"), ("loader_shell", "tool_download"), ("ps_encoded", "lsass_read"),
            ("ps_encoded", "service_persistence"), ("ps_encoded", "stage2_shell"), ("stage2_shell", "shadow_delete"),
            ("stage2_shell", "sched_task"), ("stage2_shell", "log_clear")}
    check("causal_links: the eight trigger-to-trigger spawn links (two roots' children, a second-stage parent), nothing else",
          declared == want, f"{sorted(declared ^ want)}")
    ctx = {(lk["from"], lk["to"]) for lk in ksc.sysmon_tree.context_links(sdef.build(7)[0])}
    check("context: the ps_cradle recon children and the DC-side helpers are context only, not graded truth",
          {("ps_encoded", "ps_cradle"), ("ps_encoded", "directory_tamper"), ("ps_encoded", "group_escalation")} <= ctx
          and not (ctx & declared))


def main() -> int:
    return ksc.run(NAME, extra)


if __name__ == "__main__":
    raise SystemExit(main())
