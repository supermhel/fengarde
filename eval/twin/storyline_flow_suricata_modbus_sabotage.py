"""storyline_flow_suricata_modbus_sabotage -- an engineering workstation is swept, brute-forced and used to log on
laterally, then drives TWO Modbus/TCP sessions to two PLCs that a Suricata sensor on the OT tap watches.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    asa_sweep -> ad_bruteforce -> lateral_logons -> modbus_poll_recon -> priv_grant -> modbus_write_coil
        -> modbus_ids_alert -> plc2_write -> plc2_ids_alert -> plc2_close -> modbus_session_close

WHY IT EXISTS (ADR-012 WP 7, basis ``network_flow``). Suricata writes the ``modbus`` records, the IDS ``alert`` and
the ``flow`` record of one TCP session under the SAME ``flow_id``, so a Modbus session is the textbook
network_flow group:

    * PLC 1 session:  recon reads, a write, an IDS alert on the write, and the flow record written when the session
      ends 55 minutes later (four steps, three links);
    * PLC 2 session:  a write, the IDS alert on it and the flow record (three steps, two links).

The builder mints both ``flow_id`` values itself (``flow_kit``; no import of ``services/shared/causal_keys.py``)
and the oracle's ``causal_links`` are DERIVED from them (``derive_causal_links``).

THE SHARED-ENTITY NEGATIVE. ``bystander_historian_poll`` is a legitimate historian polling PLC 1 over its OWN
connection (a different ``flow_id``, same sensor). The entity join sees one device; the flow key says two flows;
the oracle forbids ``modbus_write_coil -> bystander_historian_poll``.

WHAT IS HONEST ABOUT THE DETECTION SIDE. The sweep (ASA denies), the brute force (AD 4625), the lateral logons
(4624) and the privileged-group add (4728) fire shipped rules, all keyed on the engineering workstation's
address. No shipped rule reads a Suricata ``modbus`` record, an IDS alert or a flow record, so the seven Suricata
steps are declared gaps and every link has two unalerted endpoints today.

TELEMETRY. Real parsers: ``cisco_asa`` (106023 Deny), ``active_directory`` (4625), ``windows_eventlog``
(4624, 4728), ``suricata_eve`` (modbus / alert / flow). Simulation only: private addresses, a fixed calendar epoch.
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

START_MS = epoch_ms(2025, 7, 17, 3, 0)       # Thu 2025-07-17 03:00 UTC
_MIN = 60_000

TAP = Sensor("ot-tap-ids", "suricata", "10.50.0.250")

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("asa_sweep", "cisco_asa", True, 
                  "the engineering workstation is denied on port 502 across 16-22 OT hosts"),
    ChainStepSpec("ad_bruteforce", "active_directory", True, "the workstation fails logon 11-13 times in under a minute"),
    ChainStepSpec("lateral_logons", "windows_eventlog", True, "the guessed account logs on to six hosts from the workstation"),
    ChainStepSpec("modbus_poll_recon", "suricata_eve", True, "five Modbus read requests on ONE long TCP session to PLC 1"),
    ChainStepSpec("priv_grant", "windows_eventlog", True, "the account adds a backdoor service account to a privileged group"),
    ChainStepSpec("modbus_write_coil", "suricata_eve", True, "a Modbus write-single-coil request on the SAME PLC 1 session"),
    ChainStepSpec("modbus_ids_alert", "suricata_eve", True, "the IDS alert on that write, on the SAME flow_id"),
    ChainStepSpec("plc2_write", "suricata_eve", True, "a Modbus write-single-register request on ONE session to PLC 2"),
    ChainStepSpec("plc2_ids_alert", "suricata_eve", True, "the IDS alert on that write, on the PLC 2 flow_id"),
    ChainStepSpec("plc2_close", "suricata_eve", True, "the PLC 2 flow record, written when that session ends"),
    ChainStepSpec("modbus_session_close", "suricata_eve", True, "the PLC 1 flow record, written when that session ends"),
)
STEP_ORDER = [s.label for s in STEPS]

BYSTANDER = ChainStepSpec("bystander_historian_poll", "suricata_eve", True,
                          "a legitimate historian polls PLC 1 over its OWN connection (BENIGN, other flow_id, same sensor)")
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_maintenance_sweep", "cisco_asa", True,
                  "an authorised maintenance scanner is denied on port 502 across 16 other hosts (BENIGN, noisy: fires the sweep rule on a disjoint host)"),  # noqa: E501
)

_VICTIMS = ("eng.ops", "plc.admin", "h.ortiz", "s.nakamura")


def _rule_id(stem: str) -> str:
    import yaml  # noqa: PLC0415
    path = TWIN.parents[1] / "contracts" / "rules" / f"{stem}.yml"
    return str(yaml.safe_load(path.read_text(encoding="utf-8"))["id"])


def _make(seed: int, *, n_hosts: int | None = None):
    rng = Random(seed * 15485863 + 401)
    victim = rng.choice(_VICTIMS)
    ew = f"10.50.9.{30 + seed % 7}"
    plc1, plc2 = "10.50.1.10", "10.50.1.11"
    n_hosts = (16 + seed % 7) if n_hosts is None else n_hosts       # rule threshold: 15 distinct hosts / 60 s
    n_fail = 11 + seed % 3                                          # rule threshold: 10 failures / 60 s
    book = FlowBook(seed, "msb", STEPS + (BYSTANDER,) + DECOY_STEPS)
    f1, f2, f_hist = book.flow_id(), book.flow_id(), book.flow_id()
    s1, d1 = (ew, 49701), (plc1, 502)
    s2, d2 = (ew, 49702), (plc2, 502)

    for i in range(n_hosts):                                       # 2 s apart: 22 hosts span 42 s
        ts = START_MS + i * 2_000
        book.raw("asa_sweep", "cisco_asa",
                 f"%ASA-4-106023: Deny tcp src inside:{ew}/{41000 + i} dst inside:10.50.{2 + i // 250}.{10 + i % 250}/502 "
                 f"by access-group acl_ot", ts, ew)

    for i in range(n_fail):                                        # 4 s apart: ~44 s
        ts = START_MS + 5 * _MIN + i * 4_000
        book.raw("ad_bruteforce", "active_directory",
                 {"EventID": 4625, "TimeCreated": ts, "TargetUserName": victim, "TargetDomainName": "OT",
                  "IpAddress": ew}, ts, ew)

    for i in range(6):                                             # 25 s apart: six hosts inside 300 s
        ts = START_MS + 12 * _MIN + i * 25_000
        book.raw("lateral_logons", "windows_eventlog",
                 {"EventID": 4624, "TargetUserName": victim, "Computer": f"hmi{i + 1:02d}", "IpAddress": ew,
                  "WorkstationName": "ew-" + ew.rsplit(".", 1)[1], "TimeCreated": ts}, ts, ew)

    t_recon = START_MS + 20 * _MIN
    for i in range(5):                                             # one read every 20 s
        book.eve_modbus("modbus_poll_recon", TAP, t_recon + i * 20_000, f1, s1, d1, function_raw=3,
                        function_code="RdHoldRegs", access_type="READ | HOLDING", address=100 + i, quantity=2,
                        unit_id=1, tx=i + 1)

    ts = START_MS + 28 * _MIN
    book.raw("priv_grant", "windows_eventlog",
             {"EventID": 4728, "SubjectUserName": victim, "TargetUserName": "backdoor-svc", "Computer": "dc-ot01",
              "IpAddress": ew, "TimeCreated": ts}, ts, ew)

    t_w1 = START_MS + 35 * _MIN
    book.eve_modbus("modbus_write_coil", TAP, t_w1, f1, s1, d1, function_raw=5, function_code="WrSingleCoil",
                    access_type="WRITE | COILS | SINGLE | WRITE_SINGLE", address=2, unit_id=1, tx=20)
    book.eve_alert("modbus_ids_alert", TAP, t_w1 + 40_000, f1, s1, d1, signature="ET SCADA Modbus Write Single Coil from non-HMI host",
                   sid=2200101, category="Potentially Bad Traffic", severity=1, app_proto="modbus")
    t_w2 = START_MS + 45 * _MIN
    book.eve_modbus("plc2_write", TAP, t_w2, f2, s2, d2, function_raw=6, function_code="WrSingleReg",
                    access_type="WRITE | HOLDING | SINGLE | WRITE_SINGLE", address=5, unit_id=1, tx=1)
    book.eve_alert("plc2_ids_alert", TAP, t_w2 + 30_000, f2, s2, d2, signature="ET SCADA Modbus Write Single Register from non-HMI host",  # noqa: E501
                   sid=2200102, category="Potentially Bad Traffic", severity=1, app_proto="modbus")
    book.eve_flow("plc2_close", TAP, t_w2 - 5_000, START_MS + 60 * _MIN, f2, s2, d2, app_proto="modbus",
                  bytes_ts=480, bytes_tc=410, alerted=True)
    book.eve_flow("modbus_session_close", TAP, t_recon - 5_000, START_MS + 75 * _MIN, f1, s1, d1, app_proto="modbus",
                  bytes_ts=1_900, bytes_tc=1_650, alerted=True)

    # the legitimate historian: same PLC 1, its own long connection (different flow_id), one read a minute, ending before the write
    for i in range(12):
        book.eve_modbus("bystander_historian_poll", TAP, START_MS + 22 * _MIN + i * _MIN, f_hist, ("10.50.2.40", 50120), d1,
                        function_raw=3, function_code="RdHoldRegs", access_type="READ | HOLDING", address=0, quantity=8,
                        unit_id=1, tx=500 + i)
    notes = {
        "asa_sweep": f"{ew} is denied on port 502 across {n_hosts} distinct OT hosts",
        "ad_bruteforce": f"{ew} fails logon for {victim} {n_fail} times",
        "lateral_logons": f"{victim} logs on to six hosts from {ew} in 125 s",
        "priv_grant": f"{victim} adds backdoor-svc to a privileged group on dc-ot01",
        "modbus_poll_recon": f"five Modbus reads on flow {f1} ({ew} -> {plc1}:502)",
    }
    return book, notes


def _build(seed: int, *, n_hosts: int | None = None):
    book, notes = _make(seed, n_hosts=n_hosts)
    return book.payloads, {}, notes, None


def build(seed: int):
    return _build(seed)


def derive_causal_links(seed: int = 7) -> list:
    """The network_flow truth links for ``seed``, derived from the flow_ids this builder minted (the historian's
    flow_id is a different group, so the bystander yields no link)."""
    book, _notes = _make(seed)
    return flow_kit.derive_links(book.notes, STEP_ORDER)


def key_notes(seed: int = 7) -> tuple:
    book, _n = _make(seed)
    return book.notes, STEP_ORDER


def _build_decoys(seed: int) -> list:
    """An authorised maintenance scanner: denied on port 502 across 16 hosts (fires the sweep rule on a disjoint host)."""
    book = FlowBook(seed, "msbd", STEPS + (BYSTANDER,) + DECOY_STEPS)
    for i in range(16):
        ts = START_MS + 5_000 + i * 2_000
        book.raw("decoy_maintenance_sweep", "cisco_asa",
                 f"%ASA-4-106023: Deny tcp src inside:10.50.8.9/{45000 + i} dst inside:10.51.{1 + i // 250}.{10 + i % 250}/502 "
                 f"by access-group acl_ot", ts, "10.50.8.9")
    return book.payloads


NEGATIVES: tuple[NegativeTwin, ...] = (
    NegativeTwin(
        name="ot_sweep_14_of_15_hosts", step="asa_sweep", rule_ids=(_rule_id("common_port_sweep"),),
        attribute="distinct OT hosts denied from the one source: 14, one under the rule's 15",
        build=lambda seed, restored: _build(seed, n_hosts=15 if restored else 14)),
)


STORYLINE = ScenarioDef(
    name="flow_suricata_modbus_sabotage",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_flow_suricata_modbus_sabotage.yaml",
    summary="an engineering workstation is swept, brute-forced and used laterally, then drives two Modbus/TCP "
            "sessions that Suricata logs as modbus + alert + flow under one flow_id each (network_flow truth links)",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS + (BYSTANDER,),
    negatives=NEGATIVES,
)
