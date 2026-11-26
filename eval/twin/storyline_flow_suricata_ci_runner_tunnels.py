"""storyline_flow_suricata_ci_runner_tunnels -- a compromised CI build runner sweeps the build network, is
brute-forced (a Windows build agent in the domain), then keeps a reverse shell, an SSH tunnel and a
bulk upload open to the outside for hours,
all of it seen by a Suricata sensor on the build-network edge.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    asa_sweep -> ad_bruteforce -> lateral_logons -> rev_shell_open -> priv_grant -> tunnel_alert -> rev_shell_cmd
        -> upload_alert -> tunnel_alert2 -> rev_shell_loot -> upload_alert2 -> upload_close -> rev_shell_close

WHY IT EXISTS (ADR-012 WP 7, basis ``network_flow``). Three long flows on ONE Suricata sensor (``build-edge-ids``),
each raising several DISTINCT alerts on its own ``flow_id``:

    * the reverse shell (one TCP flow, ~4 h 30): three severity-1 signatures in three different hours
      (``common_ids_high_severity_alert``), then the flow record when it ends carrying 1.1 GiB to the outside
      (``common_large_outbound_flow``): four alerts, three links;
    * the SSH tunnel (one TCP flow): two severity-1 signatures 80 minutes apart: two alerts, one link;
    * the bulk upload (one TLS flow): two severity-1 signatures 85 minutes apart, then the flow record with 1.5 GiB:
      three alerts, two links.

Six links. The builder mints the ``flow_id`` values itself (``flow_kit``; no import of
``services/shared/causal_keys.py``) and the oracle's ``causal_links`` are DERIVED from the TRIGGER records only
(``derive_causal_links``), never typed and never read from the parser's output.

NO FOLDING, BY DESIGN. The IDS passthrough rule's alert id is (rule, flow_id, hour bucket) with a 3600 s window, so two
hits on one flow in one bucket would upsert ONE alert. Every severity-1 hit on a flow here is more than one hour after
the previous one, and the flow-end record goes through a different rule, so each step owns a distinct alert id.

SCOPE. ``bystander_other_sensor`` is a benign alert from a SECOND sensor (``ci-ids-b``) whose ``flow_id`` is
numerically IDENTICAL to the reverse shell's: a value comparison across sensors would link it, a scoped one must not.

TELEMETRY. Real parsers: ``cisco_asa`` (106023 Deny), ``active_directory`` (4625), ``windows_eventlog`` (4624, 4728),
``suricata_eve`` (alert / flow). Simulation only: private addresses inside, RFC 5737 documentation addresses outside,
a fixed calendar epoch.
"""
from __future__ import annotations

import sys
from pathlib import Path
from random import Random

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

import flow_kit  # noqa: E402
from flow_kit import FlowBook, Sensor  # noqa: E402
from scenario import ChainStepSpec, NegativeTwin, ScenarioDef  # noqa: E402
from scenario_kit import epoch_ms  # noqa: E402

START_MS = epoch_ms(2025, 7, 18, 1, 0)       # Fri 2025-07-18 01:00 UTC
_MIN = 60_000
_GIB = 1024 ** 3

EDGE = Sensor("build-edge-ids", "suricata", "10.60.0.250")
EDGE_B = Sensor("ci-ids-b", "suricata", "10.60.1.250")

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("asa_sweep", "cisco_asa", True, "the build runner is denied on port 22 across 16-22 build hosts"),
    ChainStepSpec("ad_bruteforce", "active_directory", True, "the runner fails logon 11-13 times in under a minute"),
    ChainStepSpec("lateral_logons", "windows_eventlog", True, "the guessed account logs on to six build servers from the runner"),
    ChainStepSpec("rev_shell_open", "suricata_eve", True,
                  "severity-1 IDS alert on a reverse shell from the runner to an outside address (hour 1)"),
    ChainStepSpec("priv_grant", "windows_eventlog", True,
                  "the account adds a backdoor service account to a privileged group on the build DC"),
    ChainStepSpec("tunnel_alert", "suricata_eve", True,
                  "severity-1 IDS alert on one long SSH flow from the runner to a second outside address"),
    ChainStepSpec("rev_shell_cmd", "suricata_eve", True,
                  "second severity-1 signature on the SAME reverse-shell flow, 75 minutes later (command execution)"),
    ChainStepSpec("upload_alert", "suricata_eve", True,
                  "severity-1 IDS alert on one outbound TLS flow carrying repository archives to an outside host"),
    ChainStepSpec("tunnel_alert2", "suricata_eve", True,
                  "second severity-1 signature on the SAME SSH tunnel flow, 80 minutes later"),
    ChainStepSpec("rev_shell_loot", "suricata_eve", True,
                  "third severity-1 signature on the SAME reverse-shell flow, 75 minutes later (secret harvesting)"),
    ChainStepSpec("upload_alert2", "suricata_eve", True,
                  "second severity-1 signature on the SAME bulk-upload flow, 85 minutes later"),
    ChainStepSpec("upload_close", "suricata_eve", True,
                  "the bulk-upload flow record (1.5 GiB to an outside address), written when it ends"),
    ChainStepSpec("rev_shell_close", "suricata_eve", True,
                  "the reverse-shell flow record (1.1 GiB to an outside address), written when it ends"),
)
STEP_ORDER = [s.label for s in STEPS]

BYSTANDER = ChainStepSpec("bystander_other_sensor", "suricata_eve", True,
                          "a benign alert from a SECOND sensor whose flow_id equals the reverse shell's (BENIGN, other scope)")
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_vuln_scanner", "cisco_asa", True,
                  "an authorised vulnerability scanner is denied on port 22 across 16 other hosts (BENIGN, noisy: fires the sweep rule on a disjoint host)"),  # noqa: E501
)

_VICTIMS = ("svc_build", "ci.deploy", "m.keller", "r.santos")
_ATTACKERS = ("203.0.113.34", "203.0.113.88", "203.0.113.144", "203.0.113.190")


def _rule_id(stem: str) -> str:
    import yaml  # noqa: PLC0415
    path = TWIN.parents[1] / "contracts" / "rules" / f"{stem}.yml"
    return str(yaml.safe_load(path.read_text(encoding="utf-8"))["id"])


def _make(seed: int, *, n_hosts: int | None = None):
    rng = Random(seed * 15485863 + 503)
    c2 = rng.choice(_ATTACKERS)
    tun_dst, up_dst = "203.0.113.60", "203.0.113.61"
    rn = f"10.60.3.{40 + seed % 7}"
    n_hosts = (16 + seed % 7) if n_hosts is None else n_hosts       # rule threshold: 15 distinct hosts / 60 s
    n_fail = 11 + seed % 3                                          # rule threshold: 10 failures / 60 s
    victim = rng.choice(_VICTIMS)
    book = FlowBook(seed, "crt", STEPS + (BYSTANDER,) + DECOY_STEPS)
    f_rev, f_tun, f_up = book.flow_id(), book.flow_id(), book.flow_id()
    s_rev, d_rev = (rn, 44100), (c2, 4444)
    s_tun, d_tun = (rn, 44200), (tun_dst, 22)
    s_up, d_up = (rn, 44300), (up_dst, 443)
    cat = "Potentially Bad Traffic"

    for i in range(n_hosts):                                       # 2 s apart: 22 hosts span 42 s
        ts = START_MS + i * 2_000
        book.raw("asa_sweep", "cisco_asa",
                 f"%ASA-4-106023: Deny tcp src inside:{rn}/{41000 + i} dst inside:10.61.{2 + i // 250}.{10 + i % 250}/22 "
                 f"by access-group acl_build", ts, rn)

    for i in range(n_fail):                                        # 4 s apart: ~44 s
        ts = START_MS + 8 * _MIN + i * 4_000
        book.raw("ad_bruteforce", "active_directory",
                 {"EventID": 4625, "TimeCreated": ts, "TargetUserName": victim, "TargetDomainName": "BUILD",
                  "IpAddress": rn}, ts, rn)

    for i in range(6):                                             # 25 s apart: six hosts inside 300 s
        ts = START_MS + 14 * _MIN + i * 25_000
        book.raw("lateral_logons", "windows_eventlog",
                 {"EventID": 4624, "TargetUserName": victim, "Computer": f"bld{i + 1:02d}", "IpAddress": rn,
                  "WorkstationName": "rn-" + rn.rsplit(".", 1)[1], "TimeCreated": ts}, ts, rn)

    book.eve_alert("rev_shell_open", EDGE, START_MS + 30 * _MIN, f_rev, s_rev, d_rev,
                   signature="ET MALWARE Reverse Shell Initial Connection (bash -i)", sid=2300101, category=cat,
                   severity=1, app_proto="failed")
    ts = START_MS + 40 * _MIN
    book.raw("priv_grant", "windows_eventlog",
             {"EventID": 4728, "SubjectUserName": victim, "TargetUserName": "backdoor-svc", "Computer": "dc-build01",
              "IpAddress": rn, "TimeCreated": ts}, ts, rn)
    book.eve_alert("tunnel_alert", EDGE, START_MS + 60 * _MIN, f_tun, s_tun, d_tun,
                   signature="ET POLICY SSH Reverse Tunnel Established to Rare Host", sid=2300110, category=cat,
                   severity=1, app_proto="ssh")
    book.eve_alert("rev_shell_cmd", EDGE, START_MS + 105 * _MIN, f_rev, s_rev, d_rev,
                   signature="ET MALWARE Reverse Shell Command Execution Pattern", sid=2300102, category=cat,
                   severity=1, app_proto="failed")
    book.eve_alert("upload_alert", EDGE, START_MS + 120 * _MIN, f_up, s_up, d_up,
                   signature="ET POLICY Large Outbound Archive Upload to Rare Host", sid=2300120, category=cat,
                   severity=1, app_proto="tls")
    book.eve_alert("tunnel_alert2", EDGE, START_MS + 140 * _MIN, f_tun, s_tun, d_tun,
                   signature="ET POLICY SSH Tunnel Sustained High Volume", sid=2300111, category=cat,
                   severity=1, app_proto="ssh")
    book.eve_alert("rev_shell_loot", EDGE, START_MS + 180 * _MIN, f_rev, s_rev, d_rev,
                   signature="ET MALWARE Reverse Shell Credential File Read", sid=2300103, category=cat,
                   severity=1, app_proto="failed")
    book.eve_alert("upload_alert2", EDGE, START_MS + 205 * _MIN, f_up, s_up, d_up,
                   signature="ET POLICY Large Outbound Archive Upload Continuing", sid=2300121, category=cat,
                   severity=1, app_proto="tls")
    book.eve_flow("upload_close", EDGE, START_MS + 118 * _MIN, START_MS + 250 * _MIN, f_up, s_up, d_up, app_proto="tls",
                  bytes_ts=int(1.5 * _GIB), bytes_tc=210_000, alerted=True, trigger=True)
    book.eve_flow("rev_shell_close", EDGE, START_MS + 29 * _MIN, START_MS + 260 * _MIN, f_rev, s_rev, d_rev,
                  app_proto="failed", bytes_ts=int(1.1 * _GIB), bytes_tc=48_000_000, alerted=True, trigger=True)

    # benign alert from a DIFFERENT sensor whose flow_id equals the reverse shell's (same value, other scope)
    book.eve_alert("bystander_other_sensor", EDGE_B, START_MS - 2 * _MIN, f_rev, ("10.62.7.15", 52111),
                   ("192.0.2.80", 80), signature="ET POLICY Outdated Browser User-Agent", sid=2008120,
                   category=cat, severity=3, app_proto="http")
    notes = {
        "asa_sweep": f"{rn} is denied on port 22 across {n_hosts} distinct build hosts",
        "ad_bruteforce": f"{rn} fails logon for {victim} {n_fail} times",
        "lateral_logons": f"{victim} logs on to six build servers from {rn} in 125 s",
        "priv_grant": f"{victim} adds backdoor-svc to a privileged group on dc-build01",
        "rev_shell_open": f"IDS alert on flow {f_rev} ({rn} -> {c2}:4444); the flow lives until +260 min",
    }
    return book, notes


def _build(seed: int, *, n_hosts: int | None = None):
    book, notes = _make(seed, n_hosts=n_hosts)
    return book.payloads, {}, notes, None


def build(seed: int):
    return _build(seed)


def derive_causal_links(seed: int = 7) -> list:
    """The network_flow truth links for ``seed``, derived from the flow_ids this builder minted on its TRIGGER
    records (the bystander's other-scope key is context and must produce no link)."""
    book, _notes = _make(seed)
    return flow_kit.derive_links(book.notes, STEP_ORDER)


def key_notes(seed: int = 7) -> tuple:
    book, _n = _make(seed)
    return book.notes, STEP_ORDER


def _build_decoys(seed: int) -> list:
    """An authorised vulnerability scanner: denied on port 22 across 16 hosts (fires the sweep rule on a disjoint host)."""
    book = FlowBook(seed, "crtd", STEPS + (BYSTANDER,) + DECOY_STEPS)
    for i in range(16):
        ts = START_MS + 5_000 + i * 2_000
        book.raw("decoy_vuln_scanner", "cisco_asa",
                 f"%ASA-4-106023: Deny tcp src inside:10.60.8.9/{45000 + i} dst inside:10.63.{1 + i // 250}.{10 + i % 250}/22 "
                 f"by access-group acl_build", ts, "10.60.8.9")
    return book.payloads


NEGATIVES: tuple[NegativeTwin, ...] = (
    NegativeTwin(
        name="build_sweep_14_of_15_hosts", step="asa_sweep", rule_ids=(_rule_id("common_port_sweep"),),
        attribute="distinct build hosts denied from the one source: 14, one under the rule's 15",
        build=lambda seed, restored: _build(seed, n_hosts=15 if restored else 14)),
)


STORYLINE = ScenarioDef(
    name="flow_suricata_ci_runner_tunnels",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_flow_suricata_ci_runner_tunnels.yaml",
    summary="a compromised CI runner sweeps the build network and is brute-forced, then keeps a reverse shell, an "
            "SSH tunnel and a bulk upload open for hours; Suricata alerts on each flow in several different hours "
            "and writes the flow record at the end (network_flow truth links)",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS + (BYSTANDER,),
    negatives=NEGATIVES,
)
