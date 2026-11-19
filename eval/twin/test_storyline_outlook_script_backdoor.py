"""Acceptance test for storyline_outlook_script_backdoor (keyed Outlook -> wscript -> PowerShell storyline, 2026-11-19).

Standalone (NOT pytest): ``[OK]`` / ``[FAIL]`` lines, exit 0 only when every check passes:

    python eval/twin/test_storyline_outlook_script_backdoor.py

Shared keyed-storyline checks live in ``keyed_storyline_checks``; this file adds what is specific here: the
create-then-delete account pair on ONE target and the star of steps around the PowerShell.
"""
from __future__ import annotations

import sys
from pathlib import Path

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

import keyed_storyline_checks as ksc  # noqa: E402

NAME = "outlook_script_backdoor"


def extra(check, sdef) -> None:
    for seed in ksc.SEEDS:
        pl = sdef.build(seed)[0]
        acct = {p["raw"]["EventID"]: p for s, p in pl
                if s.label == "ephemeral_account" and p["source_type"] == "windows_eventlog"}
        check(f"ephemeral_account: 4720 then 4726 on ONE target, inside the rule's hour (seed {seed})",
              set(acct) == {4720, 4726}
              and acct[4720]["raw"]["TargetUserName"] == acct[4726]["raw"]["TargetUserName"]
              and 0 < acct[4726]["raw"]["TimeCreated"] - acct[4720]["raw"]["TimeCreated"] < 3_600_000)
        beats = [p for s, p in pl if s.label == "c2_beacon" and p["raw"]["EventID"] == 3]
        check(f"beacon: >= 20 connections from one process (seed {seed})",
              len(beats) >= 20 and len({p["raw"]["ProcessGuid"] for p in beats}) == 1)
        check(f"lolbin_shell: the alert-raising record is an Outlook -> wscript creation (seed {seed})",
              any(s.label == "lolbin_shell" and p["raw"].get("ParentImage", "").endswith("OUTLOOK.EXE")
                  and p["raw"]["Image"].endswith("wscript.exe") for s, p in pl))
    links = ksc.yaml.safe_load(Path(sdef.oracle_path).read_text(encoding="utf-8"))["causal_links"]
    check("the PowerShell step (ps_cradle) is the parent of the five later steps, and of nothing earlier",
          {(lk["from"], lk["to"]) for lk in links} == {("lolbin_shell", "ps_cradle")} | {("ps_cradle", t) for t in (
              "lsass_read", "ephemeral_account", "group_add", "c2_beacon", "log_clear")})


def main() -> int:
    return ksc.run(NAME, extra)


if __name__ == "__main__":
    raise SystemExit(main())
