"""scenarios_extra -- additional attack STORYLINES for the twin / adversarial harness.

WHY THIS EXISTS (2026-10-01)
    Every number the twin and the Phase-4 mutation matrix publish used to be
    measured on ONE storyline: ``scenario.py``'s AI-to-OT chain. The seed varied
    identifiers only (session id, sensor values), never the attack's STRUCTURE,
    so "robust on seeds 7/11/13/17" was one data point measured four times.
    Generality needs different attack SHAPES, each with its own answer key.

    These are the first two, chosen to exercise what the AI-to-OT chain cannot:

      it_intrusion      scan -> brute force -> login -> lateral movement ->
                        privilege grant -> DNS exfil.  A pure-IT chain on six
                        real parsers whose detections are STATEFUL, windowed,
                        volume rules (thresholds 10-40 events). The AI-to-OT
                        chain is almost entirely single-shot rules, so it
                        could never show a threshold/window evasion at all.
                        Three different entities carry the story (attacker IP,
                        the stolen account, the foothold host) -- an attack
                        that pivots, where the AI-to-OT chain reuses one IP and
                        one actor end to end.

      infra_takeover    cloud root login without MFA -> privileged container
                        -> mass VM deletion.  Three heterogeneous control-plane
                        sources (CloudTrail, Kubernetes audit, vSphere), a
                        different actor at every step, ONE shared source IP.

    Both are emitted in RAW source formats and parsed by the REAL registered
    parsers (type_uid derived, never hand-set) -- the same honesty rule as
    scenario.py. ``seed`` varies STRUCTURE here (attacker IP, burst sizes,
    account names, host names), not only identifiers, so a multi-seed run is a
    real spread over different instances of the same shape.

BURSTS
    A stateful rule needs volume. A step may therefore own many raw events
    (``recon_port_scan`` is 16-22 denied connections). Every event of a step
    carries the step's label; graders aggregate by step.

SAFETY
    Simulation only. No network, no real credentials, documentation-range IPs
    (RFC 5737) and ``.invalid`` / ``example`` domains throughout.
"""
from __future__ import annotations

import sys
from pathlib import Path
from random import Random

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

from datetime import datetime, timezone  # noqa: E402

from scenario import ChainStepSpec, ScenarioDef  # noqa: E402

_BASE_MS = 1751500000000  # same fixed deterministic epoch as scenario.py (no wall clock)


def _meta(seed: int, tag: str, idx: int, ts: int, ip: str | None) -> dict:
    meta = {
        "received_at": ts,
        "ingest_id": f"ing-{tag}-{seed:04d}-{idx:03d}",
        "trace_id": f"trace-{tag}-{seed}",
        "tenant_id": "acme",
    }
    if ip is not None:
        meta["ip"] = ip
    return meta


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ===========================================================================
# it_intrusion
# ===========================================================================
IT_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("recon_port_scan", "cisco_asa", True,
                  "vertical port scan against the edge host (denied connections, many distinct ports)"),
    ChainStepSpec("ssh_bruteforce", "linux_ssh", True,
                  "SSH password guessing against one account from the same external source"),
    ChainStepSpec("initial_access", "linux_ssh", True,
                  "the guessed password works: successful SSH login from the attacker"),
    ChainStepSpec("lateral_movement", "windows_eventlog", True,
                  "the stolen account logs on to many distinct internal hosts from the foothold"),
    ChainStepSpec("priv_grant", "windows_eventlog", True,
                  "the stolen account adds a member to a privileged group on the domain controller"),
    ChainStepSpec("dns_exfil", "dns_query", True,
                  "the foothold resolves dozens of distinct names in a minute (DNS tunnelling shape)"),
)

_EXTERNAL_IPS = ("203.0.113.21", "203.0.113.77", "192.0.2.44", "192.0.2.91")
_ACCOUNTS = ("deploy", "svc-backup", "jenkins", "ci-runner")


def _build_it_intrusion(seed: int):
    rng = Random(seed * 7919 + 13)
    attacker = rng.choice(_EXTERNAL_IPS)
    foothold_ip = f"10.50.0.{rng.randint(20, 60)}"
    foothold_host = "db01"
    user = rng.choice(_ACCOUNTS)
    n_ports = rng.randint(16, 22)          # rule threshold: 15 distinct ports / 60s
    n_fail = rng.randint(12, 16)           # rule threshold: 10 failures / 60s
    n_hosts = rng.randint(6, 8)            # rule threshold: 5 distinct hosts / 300s
    n_names = rng.randint(44, 56)          # rule threshold: 40 distinct names / 60s
    steps = {s.label: s for s in IT_STEPS}
    payloads: list = []
    notes: dict = {}
    idx = 0

    def add(label: str, source_type: str, raw, ts: int, ip: str | None):
        nonlocal idx
        payloads.append((steps[label], {
            "source_type": source_type, "raw": raw,
            "meta": _meta(seed, "it", idx, ts, ip)}))
        idx += 1

    t = _BASE_MS
    for i in range(n_ports):                                  # 2 s apart -> well inside 60 s
        add("recon_port_scan", "cisco_asa",
            f"%ASA-4-106023: Deny tcp src outside:{attacker}/{40000 + i} "
            f"dst inside:10.0.0.10/{20 + i * 7} by access-group acl_out",
            t + i * 2_000, attacker)
    notes["recon_port_scan"] = f"{n_ports} denied connections to distinct ports from {attacker}"

    t = _BASE_MS + 120_000
    for i in range(n_fail):                                   # 3 s apart
        add("ssh_bruteforce", "linux_ssh",
            f"Jun 10 13:55:{i:02d} db01 sshd[{2000 + i}]: Failed password for {user} "
            f"from {attacker} port {51000 + i} ssh2",
            t + i * 3_000, attacker)
    notes["ssh_bruteforce"] = f"{n_fail} failed SSH logons for {user} from {attacker}"

    t = _BASE_MS + 240_000
    add("initial_access", "linux_ssh",
        f"Jun 10 13:59:00 db01 sshd[2999]: Accepted password for {user} "
        f"from {attacker} port 52000 ssh2", t, attacker)
    notes["initial_access"] = f"Accepted password for {user} from {attacker}"

    t = _BASE_MS + 400_000
    hosts = [f"fs{h:02d}" for h in range(1, n_hosts + 1)]
    for i, host in enumerate(hosts):                          # 25 s apart -> inside 300 s
        add("lateral_movement", "windows_eventlog",
            {"EventID": 4624, "TargetUserName": user, "Computer": host,
             "IpAddress": foothold_ip, "WorkstationName": foothold_host,
             "TimeCreated": t + i * 25_000},
            t + i * 25_000, foothold_ip)
    notes["lateral_movement"] = f"{user} logs on to {n_hosts} distinct hosts from {foothold_ip}"

    t = _BASE_MS + 700_000
    add("priv_grant", "windows_eventlog",
        {"EventID": 4728, "SubjectUserName": user, "TargetUserName": "backdoor-svc",
         "Computer": "dc01", "IpAddress": foothold_ip, "TimeCreated": t},
        t, foothold_ip)
    notes["priv_grant"] = f"{user} adds backdoor-svc to a privileged group on dc01"

    t = _BASE_MS + 900_000
    for i in range(n_names):                                  # 1 s apart -> inside 60 s
        add("dns_exfil", "dns_query",
            f"query[A] chunk{i:03d}.t{seed % 97}.exfil.example.invalid from {foothold_ip}",
            t + i * 1_000, foothold_ip)
    notes["dns_exfil"] = f"{n_names} distinct names resolved from {foothold_ip} in {n_names}s"

    return payloads, {}, notes, None


IT_DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_scanner", "cisco_asa", True,
                  "an internal vulnerability scanner sweeping the edge host (BENIGN, authorised)"),
    ChainStepSpec("decoy_admin_maintenance", "windows_eventlog", True,
                  "a real administrator patching many hosts in one sitting (BENIGN)"),
)


def _build_it_decoys(seed: int) -> list:
    """Benign activity that trips the SAME volume rules as the attack, from
    entities the attack never touches (different IPs, different account,
    different workstation, and a DIFFERENT scan target than the attack's 10.0.0.10
    -- a target-keyed rule pools every source hitting one host, so a scanner on the
    attack's own target is not "disjoint"; that case is tested separately as the
    documented cost of the pooled rule). Overlaps the attack's windows on purpose."""
    steps = {s.label: s for s in IT_DECOY_STEPS}
    out: list = []
    scanner = "10.60.0.99"
    admin_ip = "10.60.0.9"
    for i in range(17):                                       # 17 > 15 distinct ports
        ts = _BASE_MS + 10_000 + i * 2_000
        out.append((steps["decoy_scanner"], {
            "source_type": "cisco_asa",
            "raw": f"%ASA-4-106023: Deny tcp src inside:{scanner}/{45000 + i} "
                   f"dst inside:10.0.0.77/{1000 + i * 11} by access-group acl_in",
            "meta": _meta(seed, "itd", i, ts, scanner)}))
    for i in range(6):                                        # 6 > 5 distinct hosts
        ts = _BASE_MS + 410_000 + i * 20_000
        out.append((steps["decoy_admin_maintenance"], {
            "source_type": "windows_eventlog",
            "raw": {"EventID": 4624, "TargetUserName": "ops-admin", "Computer": f"app{i + 1:02d}",
                    "IpAddress": admin_ip, "WorkstationName": "ops-wks-1", "TimeCreated": ts},
            "meta": _meta(seed, "itd", 100 + i, ts, admin_ip)}))
    return out


IT_INTRUSION = ScenarioDef(
    name="it_intrusion",
    steps=IT_STEPS,
    build=_build_it_intrusion,
    oracle_path=TWIN / "oracle_it_intrusion.yaml",
    summary="scan -> SSH brute force -> login -> lateral movement -> priv grant -> DNS exfil",
    decoy=_build_it_decoys,
    decoy_steps=IT_DECOY_STEPS,
)


# ===========================================================================
# infra_takeover
# ===========================================================================
INFRA_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("cloud_root_login", "cloudtrail", True,
                  "AWS root console login without MFA from the attacker address"),
    ChainStepSpec("privileged_container", "k8s_audit", True,
                  "a privileged pod is created through the Kubernetes API"),
    ChainStepSpec("mass_vm_delete", "vmware_vsphere", True,
                  "the hypervisor API is used to delete many VMs in two minutes"),
)


def _build_infra_takeover(seed: int):
    rng = Random(seed * 104729 + 7)
    attacker = rng.choice(_EXTERNAL_IPS)
    k8s_user = rng.choice(["alice", "build-bot", "platform-admin"])
    vsphere_user = rng.choice(["svc_orchestrator", "svc_backup_ops", "vc-automation"])
    n_vms = rng.randint(6, 10)                     # rule threshold: 5 deletes / 120 s
    steps = {s.label: s for s in INFRA_STEPS}
    payloads: list = []
    notes: dict = {}
    idx = 0

    def add(label: str, source_type: str, raw, ts: int):
        nonlocal idx
        payloads.append((steps[label], {
            "source_type": source_type, "raw": raw,
            "meta": _meta(seed, "infra", idx, ts, attacker)}))
        idx += 1

    t0 = _BASE_MS
    add("cloud_root_login", "cloudtrail",
        {"eventTime": _iso(t0), "eventSource": "signin.amazonaws.com",
         "eventName": "ConsoleLogin", "sourceIPAddress": attacker,
         "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456789012:root"},
         "responseElements": {"ConsoleLogin": "Success"},
         "additionalEventData": {"MFAUsed": "No"}}, t0)
    notes["cloud_root_login"] = f"root ConsoleLogin without MFA from {attacker}"

    t1 = _BASE_MS + 300_000
    add("privileged_container", "k8s_audit",
        {"auditID": f"audit-{seed}", "verb": "create", "user": {"username": k8s_user},
         "sourceIPs": [attacker],
         "objectRef": {"resource": "pods", "namespace": "kube-system", "name": "debug-shell"},
         "requestObject": {"spec": {"securityContext": {"privileged": True}}},
         "responseStatus": {"code": 201}}, t1)
    notes["privileged_container"] = f"{k8s_user} creates a privileged pod from {attacker}"

    t2 = _BASE_MS + 600_000
    for i in range(n_vms):                                    # 8 s apart -> inside 120 s
        add("mass_vm_delete", "vmware_vsphere",
            {"operation": "VM.Delete", "vm": f"prod-vm-{i:02d}", "userName": vsphere_user,
             "host": "vcenter-01", "ipAddress": attacker, "createdTime": t2 + i * 8_000},
            t2 + i * 8_000)
    notes["mass_vm_delete"] = f"{vsphere_user} deletes {n_vms} VMs from {attacker}"

    return payloads, {}, notes, None


INFRA_DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_decommission", "vmware_vsphere", True,
                  "a platform engineer decommissioning a retired cluster (BENIGN, ticketed change)"),
)


def _build_infra_decoys(seed: int) -> list:
    """A legitimate bulk VM decommission by a different account from a
    different address, inside the attack's deletion window."""
    steps = {s.label: s for s in INFRA_DECOY_STEPS}
    out: list = []
    engineer_ip = "10.60.0.9"
    for i in range(6):                                        # 6 > 5 deletes / 120 s
        ts = _BASE_MS + 620_000 + i * 6_000
        out.append((steps["decoy_decommission"], {
            "source_type": "vmware_vsphere",
            "raw": {"operation": "VM.Delete", "vm": f"retired-vm-{i:02d}", "userName": "svc_decom",
                    "host": "vcenter-02", "ipAddress": engineer_ip, "createdTime": ts},
            "meta": _meta(seed, "infrad", i, ts, engineer_ip)}))
    return out


INFRA_TAKEOVER = ScenarioDef(
    name="infra_takeover",
    steps=INFRA_STEPS,
    build=_build_infra_takeover,
    oracle_path=TWIN / "oracle_infra_takeover.yaml",
    summary="cloud root login (no MFA) -> privileged container -> mass VM deletion",
    decoy=_build_infra_decoys,
    decoy_steps=INFRA_DECOY_STEPS,
)
