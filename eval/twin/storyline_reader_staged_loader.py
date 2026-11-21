"""storyline_reader_staged_loader -- a staged loader chain started from a PDF reader: reader -> cmd ->
PowerShell -> a native loader that does the credential theft and the persistence, with the Security log
cleared at the end.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    reader_shell -> ps_cradle -> lsass_read -> directory_tamper -> service_persistence -> log_clear

WHY IT EXISTS (ADR-011 n gap, ADR-012 WP 7). The DEEP-chain keyed shape: every stage is the child of the
previous one (reader -> cmd -> PowerShell -> loader), so the step-level links run down a chain of three
spawn hops before they fan out from the loader, unlike the stars of the other keyed storylines. The
step that holds the loader's creation (``lsass_read``) is therefore the parent of three later steps.

PROCESS TREE (one workstation; the DC emits only a Windows Security record)

    explorer -> FoxitReader -> cmd C (reader_shell) -> powershell P (ps_cradle) -> loader L (lsass_read)
        L --EID10--> lsass                              (lsass_read)
        L -> ldifde                                     (directory_tamper)
        L -> sc.exe                                     (service_persistence)
        L -> wevtutil                                   (log_clear)

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
    ChainStepSpec("ps_cradle", "windows_eventlog", True,
                  "the shell starts a PowerShell whose script block is a download-and-execute cradle"),
    ChainStepSpec("lsass_read", "sysmon", True,
                  "the loader the PowerShell staged opens lsass.exe with a memory-read mask"),
    ChainStepSpec("directory_tamper", "windows_eventlog", True,
                  "the stolen account writes a delegation / key-credential attribute on the domain controller"),
    ChainStepSpec("service_persistence", "windows_eventlog", True,
                  "a service is installed whose image path is in a user-writable folder"),
    ChainStepSpec("log_clear", "windows_eventlog", True,
                  "the Security event log is cleared"),
)
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_log_maintenance", "windows_eventlog", True,
                  "another administrator clears a different server's Security log during scheduled maintenance (BENIGN)"),
)

_ACCOUNTS = ("g.ops", "v.finance", "i.admin", "q.helpdesk")
_WKS = ("wks-ops-10", "wks-fin-28", "wks-adm-06", "wks-hlp-15")
_LOADERS = ("stage3.exe", "ldr_x64.exe", "wuauhelp.exe")
_ATTRS = ("msDS-AllowedToDelegateTo", "msDS-KeyCredentialLink", "servicePrincipalName")
_CRADLE = "$b=[Convert]::FromBase64String('SGVsbG8gd29ybGQ='); [Reflection.Assembly]::Load($b)"
_PS_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
_SYS = "C:\\Windows\\System32\\"


def build(seed: int):
    rng = Random(seed * 1299827 + 83)
    user = rng.choice(_ACCOUNTS)
    wks_name = rng.choice(_WKS)
    ip = f"10.49.{rng.randint(1, 9)}.{rng.randint(20, 200)}"
    dc_ip = f"10.49.0.{rng.randint(2, 9)}"
    loader_name = rng.choice(_LOADERS)
    attr = rng.choice(_ATTRS)
    n_ps = 1 + seed % 3
    svc_name = f"WinHlp{rng.randint(10, 99)}"
    svc_path = f"C:\\ProgramData\\{svc_name.lower()}.exe"

    wks = Host(wks_name, ip, seed)
    em = Emitter(seed, TAG, STEPS)
    notes: dict = {}
    t0 = BASE_MS

    explorer = wks.proc("C:\\Windows\\explorer.exe", "explorer.exe", user, t0 - 1_000)
    reader = wks.proc("C:\\Program Files (x86)\\Foxit Software\\Foxit Reader\\FoxitReader.exe",
                      "FoxitReader.exe C:\\Users\\Public\\statement.pdf", user, t0, explorer)
    cmd = wks.proc(_SYS + "cmd.exe", "cmd.exe /c powershell -nop -w hidden", user, t0 + 4_000, reader)
    ps = wks.proc(_SYS + "WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -nop -w hidden", user, t0 + 8_000, cmd)
    recon = [wks.proc(_SYS + exe, c, user, t0 + 14_000 + i * 1_000, ps) for i, (exe, c) in enumerate((
        ("whoami.exe", "whoami /all"), ("hostname.exe", "hostname"), ("systeminfo.exe", "systeminfo")))]
    t_ps = t0 + 25_000
    loader = wks.proc(f"C:\\Users\\Public\\{loader_name}", loader_name, user, t_ps + 45_000, ps)
    lsass = wks.proc(_SYS + "lsass.exe", "lsass.exe", "SYSTEM", t0 - 7_200_000)
    ldif = wks.proc(_SYS + "ldifde.exe", f"ldifde.exe -i -f C:\\Users\\Public\\{attr}.ldf", user, t_ps + 110_000, loader)
    sc = wks.proc(_SYS + "sc.exe", f"sc.exe create {svc_name} binPath= {svc_path}", user, t_ps + 190_000, loader)
    wevt = wks.proc(_SYS + "wevtutil.exe", "wevtutil.exe cl Security", user, t_ps + 330_000, loader)

    for p in (explorer, reader, cmd):
        em.add("reader_shell", "sysmon", p.create_record(), p.start_ms, ip)
    notes["reader_shell"] = f"{user} on {wks_name}: FoxitReader -> cmd.exe"

    for p in (ps, *recon):
        em.add("ps_cradle", "sysmon", p.create_record(), p.start_ms, ip)
    for i in range(n_ps):
        ts = t_ps + i * 10_000
        em.add("ps_cradle", "windows_eventlog",
               {"EventID": 4104, "Channel": _PS_CHANNEL, "ProviderName": "Microsoft-Windows-PowerShell",
                "Computer": wks_name, "SubjectUserName": user, "SubjectDomainName": "CORP",
                "ScriptBlockText": _CRADLE, "TimeCreated": ts}, ts, ip)
    notes["ps_cradle"] = f"{n_ps} script-block event(s) on {wks_name}"

    em.add("lsass_read", "sysmon", loader.create_record(), loader.start_ms, ip)
    t_acc = loader.start_ms + 5_000
    em.add("lsass_read", "sysmon", loader.access_record(t_acc, lsass.image, lsass.guid, lsass.pid, "0x1010"), t_acc, ip)
    notes["lsass_read"] = f"{loader_name} opens lsass.exe with GrantedAccess 0x1010"

    em.add("directory_tamper", "sysmon", ldif.create_record(), ldif.start_ms, ip)
    t_dir = ldif.start_ms + 4_000
    em.add("directory_tamper", "windows_eventlog",
           {"EventID": 5136, "Computer": "dc02", "SubjectUserName": user, "SubjectDomainName": "CORP",
            "ObjectDN": "CN=svc-web,OU=Services,DC=corp,DC=example", "ObjectClass": "user",
            "AttributeLDAPDisplayName": attr, "AttributeValue": "HTTP/web01.corp.example",
            "OperationType": "%%14674", "TimeCreated": t_dir}, t_dir, dc_ip)
    notes["directory_tamper"] = f"{user} writes {attr} on CN=svc-web via dc02"

    em.add("service_persistence", "sysmon", sc.create_record(), sc.start_ms, ip)
    t_svc = sc.start_ms + 4_000
    em.add("service_persistence", "windows_eventlog",
           {"EventID": 7045, "Channel": "System", "ProviderName": "Service Control Manager",
            "Computer": wks_name, "SubjectUserName": user, "SubjectDomainName": "CORP",
            "ServiceName": svc_name, "ImagePath": svc_path, "TimeCreated": t_svc}, t_svc, ip)
    notes["service_persistence"] = f"{svc_name} -> {svc_path} on {wks_name}"

    em.add("log_clear", "sysmon", wevt.create_record(), wevt.start_ms, ip)
    t_clr = wevt.start_ms + 3_000
    em.add("log_clear", "windows_eventlog",
           {"EventID": 1102, "Channel": "Security", "ProviderName": "Microsoft-Windows-Eventlog",
            "Computer": wks_name, "SubjectUserName": user, "SubjectDomainName": "CORP",
            "TimeCreated": t_clr}, t_clr, ip)
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
    summary="PDF reader -> cmd -> PowerShell -> native loader (a three-hop Sysmon spawn chain), LSASS read, "
            "attribute write on the DC, service from a user-writable path, Security log cleared",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS,
)
