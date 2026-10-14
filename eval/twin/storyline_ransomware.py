"""storyline_ransomware -- low-and-slow credential spray -> foothold -> off-hours admin -> lateral
spread -> backdoor account -> recovery inhibition -> mass VM delete -> file encryption.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    cred_spray -> foothold_logon -> admin_privilege_use -> lateral_spread -> backdoor_account
        -> inhibit_recovery -> backup_wipe_cloud -> mass_vm_delete -> encrypt_files

WHAT IT CAN SHOW THAT THE OTHER STORYLINES CANNOT
    * a ONE-WORKSTATION, MANY-ACCOUNT spray (``common_bruteforce_sourceless``: distinct accounts per
      source hostname) that stays under every per-address and per-account threshold by design;
    * a TIME-OF-DAY rule firing on a real privileged logon (``common_after_hours_admin``: the chain
      runs at night, ``scenario_kit.BASE_MS``);
    * a create-then-delete account lifecycle (``common_rapid_account_lifecycle``);
    * four honest gaps -- valid-account foothold (T1078), shadow-copy deletion (T1490), cloud
      snapshot wipe (T1490, the VM-delete rule is scoped to vSphere) and mass file encryption
      (T1486, class 1001 has no rule) -- with NO rule invented to cover them.

TELEMETRY. Real parsers throughout (active_directory, windows_eventlog, sysmon, cloudtrail,
vmware_vsphere); every step parses (``parse_expected=True``).

STRUCTURE VARIES WITH THE SEED: sprayed-account count (6-9), lateral host count (6-8), VM count
(6-10), encrypted-file count (40-60), the compromised account, the attacker workstation and
address, the backdoor account name.

SAFETY. Simulation only: private 10.0.0.0/8 addresses for the internal foothold, ``.invalid`` /
``example`` names, fixed calendar timestamps (no wall clock). Nothing is encrypted or deleted; the
"events" are plain dicts in the sources' audit-log shapes.
"""
from __future__ import annotations

import sys
from pathlib import Path
from random import Random

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

from scenario import ChainStepSpec, NegativeTwin, ScenarioDef  # noqa: E402
from scenario_kit import BASE_MS, iso, meta  # noqa: E402

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("cred_spray", "active_directory", True,
                  "one workstation fails a logon for 6-9 different accounts, 15 s apart"),
    ChainStepSpec("foothold_logon", "active_directory", True,
                  "one sprayed account logs on successfully (valid credentials -- ordinary telemetry)"),
    ChainStepSpec("admin_privilege_use", "windows_eventlog", True,
                  "the account is assigned special privileges at night (4672)"),
    ChainStepSpec("lateral_spread", "windows_eventlog", True,
                  "the account logs on to 6-8 distinct servers within minutes"),
    ChainStepSpec("backdoor_account", "windows_eventlog", True,
                  "a local account is created and deleted again within minutes (4720 -> 4726)"),
    ChainStepSpec("inhibit_recovery", "sysmon", True,
                  "vssadmin deletes the volume shadow copies"),
    ChainStepSpec("backup_wipe_cloud", "cloudtrail", True,
                  "the cloud backup snapshots are deleted"),
    ChainStepSpec("mass_vm_delete", "vmware_vsphere", True,
                  "6-10 virtual machines are deleted in two minutes"),
    ChainStepSpec("encrypt_files", "sysmon", True,
                  "40-60 files are rewritten with a .locked extension"),
)

_ACCOUNTS = ("h.berger", "s.okafor", "l.martin", "r.costa")
_SPRAYED = ("svc_print", "j.wong", "k.ito", "a.silva", "m.novak", "t.reed", "b.adams", "c.lopez",
            "d.kim", "e.ross")

def _rule_id(stem: str) -> str:
    """A rule's id read from its own file (the twins name a rule by stem, never by a copied id)."""
    import yaml  # noqa: PLC0415
    path = TWIN.parents[1] / "contracts" / "rules" / f"{stem}.yml"
    return str(yaml.safe_load(path.read_text(encoding="utf-8"))["id"])


def _build(seed: int, *, n_spray: int | None = None):
    """The one builder every twin shares; ``n_spray`` overrides the sprayed-account count only
    (all random draws happen before the override, so it shifts no other draw)."""
    rng = Random(seed * 104729 + 41)
    account = rng.choice(_ACCOUNTS)
    wks = f"wks-tmp-{rng.randint(10, 99)}"
    ip = f"10.60.{rng.randint(1, 9)}.{rng.randint(20, 200)}"
    drawn_spray = rng.randint(6, 9)                 # rule threshold: 5 distinct accounts / 120 s
    n_hosts = rng.randint(6, 8)                     # rule threshold: 5 distinct hosts / 300 s
    n_vms = rng.randint(6, 10)                      # rule threshold: 5 deletes / 120 s
    n_files = rng.randint(40, 60)
    backdoor = f"svc_upd{rng.randint(100, 999)}"
    n_spray = drawn_spray if n_spray is None else n_spray
    sprayed = [a for a in _SPRAYED if a != account][: max(0, n_spray - 1)] + [account]
    steps = {s.label: s for s in STEPS}
    ordinal = {s.label: i for i, s in enumerate(STEPS)}
    payloads: list = []
    notes: dict = {}
    seen: dict = {}

    def add(label: str, source_type: str, raw, ts: int, src_ip: str | None) -> None:
        k = seen.get(label, 0)
        seen[label] = k + 1
        payloads.append((steps[label], {"source_type": source_type, "raw": raw,
                                        "meta": meta(seed, "rw", ordinal[label] * 100 + k, ts, src_ip)}))

    t = BASE_MS
    for i, user in enumerate(sprayed):                       # 15 s apart: n=9 -> 120 s span
        add("cred_spray", "active_directory",
            {"EventID": 4625, "TimeCreated": t + i * 15_000, "TargetUserName": user,
             "TargetDomainName": "CORP", "IpAddress": ip, "WorkstationName": wks}, t + i * 15_000, ip)
    notes["cred_spray"] = f"{len(sprayed)} failed logons for {len(sprayed)} accounts from {wks} ({ip})"

    t = BASE_MS + 200_000
    add("foothold_logon", "active_directory",
        {"EventID": 4624, "TimeCreated": t, "TargetUserName": account, "TargetDomainName": "CORP",
         "IpAddress": ip, "WorkstationName": wks}, t, ip)
    notes["foothold_logon"] = f"{account} logs on from {wks}"

    t = BASE_MS + 260_000
    add("admin_privilege_use", "windows_eventlog",
        {"EventID": 4672, "SubjectUserName": account, "Computer": wks, "IpAddress": ip,
         "TimeCreated": t}, t, ip)
    notes["admin_privilege_use"] = f"{account} receives special privileges on {wks} at night"

    t = BASE_MS + 300_000
    for i in range(n_hosts):                                 # 25 s apart -> inside 300 s
        add("lateral_spread", "windows_eventlog",
            {"EventID": 4624, "TargetUserName": account, "Computer": f"srv{i + 1:02d}",
             "IpAddress": ip, "WorkstationName": wks, "TimeCreated": t + i * 25_000}, t + i * 25_000, ip)
    notes["lateral_spread"] = f"{account} logs on to {n_hosts} servers from {ip}"

    t = BASE_MS + 600_000
    add("backdoor_account", "windows_eventlog",
        {"EventID": 4720, "SubjectUserName": account, "TargetUserName": backdoor, "Computer": "dc01",
         "IpAddress": ip, "TimeCreated": t}, t, ip)
    add("backdoor_account", "windows_eventlog",
        {"EventID": 4726, "SubjectUserName": account, "TargetUserName": backdoor, "Computer": "dc01",
         "IpAddress": ip, "TimeCreated": t + 240_000}, t + 240_000, ip)
    notes["backdoor_account"] = f"{account} creates {backdoor} on dc01 and deletes it 4 min later"

    t = BASE_MS + 900_000
    add("inhibit_recovery", "sysmon",
        {"EventID": 1, "TimeCreated": t, "Computer": "srv01",
         "Image": "C:\\Windows\\System32\\vssadmin.exe",
         "CommandLine": "vssadmin.exe delete shadows /all /quiet", "ProcessId": "6120",
         "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentProcessId": "6100", "User": account}, t, ip)
    notes["inhibit_recovery"] = "vssadmin delete shadows /all on srv01"

    t = BASE_MS + 950_000
    for i in range(8):
        add("backup_wipe_cloud", "cloudtrail",
            {"eventTime": iso(t + i * 4_000), "eventSource": "ec2.amazonaws.com",
             "eventName": "DeleteSnapshot", "sourceIPAddress": "198.51.100.77",
             "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/backup-admin",
                              "userName": "backup-admin"},
             "requestParameters": {"snapshotId": f"snap-{seed:04d}{i:04d}"}}, t + i * 4_000, "198.51.100.77")
    notes["backup_wipe_cloud"] = "8 EBS snapshots deleted with the backup admin's key"

    t = BASE_MS + 1_000_000
    for i in range(n_vms):                                   # 8 s apart -> inside 120 s
        add("mass_vm_delete", "vmware_vsphere",
            {"operation": "VM.Delete", "vm": f"prod-vm-{i:02d}", "userName": account,
             "host": "vcenter-01", "ipAddress": ip, "createdTime": t + i * 8_000}, t + i * 8_000, ip)
    notes["mass_vm_delete"] = f"{account} deletes {n_vms} VMs from {ip}"

    t = BASE_MS + 1_200_000
    for i in range(n_files):
        add("encrypt_files", "sysmon",
            {"EventID": 11, "TimeCreated": t + i * 2_000, "Computer": "fs01",
             "Image": "C:\\Users\\Public\\lckr.exe",
             "TargetFilename": f"D:\\shares\\finance\\doc{i:03d}.xlsx.locked", "User": account},
            t + i * 2_000, ip)
    notes["encrypt_files"] = f"{n_files} files rewritten as *.locked on fs01"

    return payloads, {}, notes, None


def build(seed: int):
    return _build(seed)


# ---------------------------------------------------------------------------
# Benign look-alike: an authorised administrator patching six servers in one sitting -- the
# documented false-positive shape of common_lateral_movement. Disjoint account, address and
# workstation; overlaps the attack window. A correct correlator keeps it out of the attack.
# ---------------------------------------------------------------------------
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_patch_admin", "windows_eventlog", True,
                  "an administrator logs on to six servers to patch them (BENIGN, ticketed)"),
)


def _build_decoys(seed: int) -> list:
    spec = DECOY_STEPS[0]
    out: list = []
    t = BASE_MS + 320_000
    for i in range(6):
        ts = t + i * 30_000
        out.append((spec, {"source_type": "windows_eventlog",
                           "raw": {"EventID": 4624, "TargetUserName": "patch.admin", "Computer": f"app{i + 1:02d}",
                                   "IpAddress": "10.70.0.5", "WorkstationName": "jump-01", "TimeCreated": ts},
                           "meta": meta(seed, "rwd", i, ts, "10.70.0.5")}))
    return out


NEGATIVES: tuple[NegativeTwin, ...] = (
    NegativeTwin(
        name="spray_4_of_5_accounts", step="cred_spray", rule_ids=(_rule_id("common_bruteforce_sourceless"),),
        attribute="distinct accounts sprayed from the workstation: 4, one under the rule's 5",
        build=lambda seed, restored: _build(seed, n_spray=5 if restored else 4)),
)

STORYLINE = ScenarioDef(
    name="ransomware",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_ransomware.yaml",
    summary="credential spray -> foothold -> off-hours admin -> lateral spread -> backdoor account -> "
            "shadow-copy and snapshot wipe -> mass VM delete -> file encryption",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS,
    negatives=NEGATIVES,
)
