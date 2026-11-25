"""Acceptance test for storyline_reader_staged_loader (keyed deep spawn-chain storyline, 2026-11-19).

Standalone (NOT pytest): ``[OK]`` / ``[FAIL]`` lines, exit 0 only when every check passes:

    python eval/twin/test_storyline_reader_staged_loader.py

Shared keyed-storyline checks live in ``keyed_storyline_checks``; this file adds what is specific here: a
deep spawn chain (explorer -> reader -> cmd -> PowerShell -> loader -> child) before the fan-out, and a
DC-side record shipped from the domain controller.
"""
from __future__ import annotations

import sys
from pathlib import Path

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

import keyed_storyline_checks as ksc  # noqa: E402

NAME = "reader_staged_loader"


def _depth(pl) -> int:
    """Longest chain of EID 1 spawn relations in the raw records (child guid -> parent guid -> ...)."""
    parent = {p["raw"]["ProcessGuid"]: p["raw"].get("ParentProcessGuid") for _, p in pl
              if p["source_type"] == "sysmon" and p["raw"].get("EventID") == 1}
    best = 0
    for g in parent:
        d, cur = 0, g
        while parent.get(cur):
            d, cur = d + 1, parent[cur]
        best = max(best, d)
    return best


def extra(check, sdef) -> None:
    for seed in ksc.SEEDS:
        pl = sdef.build(seed)[0]
        check(f"the raw tree is at least five spawn hops deep (reader -> cmd -> powershell -> loader -> child) (seed {seed})",
              _depth(pl) >= 5, f"depth={_depth(pl)}")
        dc = [p for s, p in pl if s.label == "directory_tamper" and p["source_type"] == "windows_eventlog"]
        wks_ip = next(p for s, p in pl if s.label == "reader_shell")["meta"]["shipper_ip"]
        check(f"directory_tamper: the 5136 record is shipped by the domain controller, not the workstation (seed {seed})",
              len(dc) == 1 and dc[0]["raw"]["Computer"] == "dc02" and dc[0]["meta"]["shipper_ip"] != wks_ip)
    links = {(lk["from"], lk["to"]) for lk in
             ksc.yaml.safe_load(Path(sdef.oracle_path).read_text(encoding="utf-8"))["causal_links"]}
    want = {("reader_shell", "ps_encoded"), ("ps_encoded", "lsass_read")} | {("lsass_read", t) for t in (
        "tool_download", "service_persistence", "sched_task", "shadow_delete", "account_add", "log_clear")}
    check("step-level links run down the chain (reader -> cmd -> PowerShell -> loader), then fan out from the loader's step",
          links == want, f"{sorted(links ^ want)}")
    ctx = {(lk["from"], lk["to"]) for lk in ksc.sysmon_tree.context_links(sdef.build(7)[0])}
    check("context: the recon children and the ldifde helper are context only, never graded truth",
          {("ps_encoded", "ps_cradle"), ("lsass_read", "directory_tamper")} <= ctx and not (ctx & links))


def main() -> int:
    return ksc.run(NAME, extra)


if __name__ == "__main__":
    raise SystemExit(main())
