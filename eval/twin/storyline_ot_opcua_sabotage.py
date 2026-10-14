"""storyline_ot_opcua_sabotage -- rogue OT device -> concurrent engineering sessions -> out-of-hours
process write -> setpoint tamper -> forged-ticket Modbus write.

Registered by ``scenario_registry._discover`` (module name ``storyline_*``, exports ``STORYLINE``).

    rogue_device -> engineering_sessions -> process_write_night -> setpoint_tamper
        -> forged_ticket_write

WHAT IT CAN SHOW THAT NO OTHER STORYLINE CAN
    * the whole OT/ICS detection surface on REAL OT telemetry: the OPC UA audit parser
      (``opcua_audit``), the Modbus protocol-anomaly parser (``modbus_anomaly``) and the
      inventory-diff notification parser (``inventory_diff``). Six shipped rules live only here --
      ``ot_new_device_on_segment``, ``ot_new_engineering_connection``, ``ot_config_change``,
      ``ot_write_outside_maintenance``, ``ot_opcua_write_unauthorized_node`` and
      ``ot_modbus_unauthorized_write_ticketed`` -- so before this storyline those six were covered
      by no oracle at all;
    * a DEFAULT-OFF rule (``ot_opcua_write_unauthorized_node``, ``siem.default_enabled: false``)
      exercised through the harness's opt-in convention, which is what makes the in-hours OPC UA
      write visible: the older rules see only config-shaped nodes and off-hours writes;
    * a DOWNGRADE-NOT-SUPPRESS detection: a forged change ticket on the envelope's meta channel
      moves an out-of-range Modbus write from HIGH to LOW and keeps it indexed
      (``ot_modbus_unauthorized_write_ticketed``), while the HIGH sibling is declared
      ``must_not_fire`` on that very event;
    * two rules that OVERLAP on one event (``ot_config_change`` and
      ``ot_write_outside_maintenance`` both match a setpoint write at night), so a mutation that
      moves the stream into business hours removes one of them and the step must stay covered by
      the other.

TELEMETRY. Real parsers throughout, one per OT source, and every raw record is emitted in the
source's own native shape: an OPC UA Part 5 audit-log JSON record, an observed Modbus frame (the
shape a tap/protocol-aware proxy reports -- Modbus has NO vendor audit-log format, see
``modbus_anomaly.py``'s module docstring) and an inventory-diff notification. Nothing hand-sets a
``type_uid``; the parser derives it. There are NO declared dependency gaps: every step runs on a
registered parser (``parse_expected=True``).

STRUCTURE VARIES WITH THE SEED (not only identifiers): the number of OPC UA session events in the
engineering burst (4 or 5), the addresses (the device's own address plus two other client
addresses), the rogue device's MAC and hostname, the PLC/server id, the ordinary and setpoint node
ids, the client account and the forged ticket id. Seeds 7/11/13/17 fall into two distinct 4/5-event
shapes, which is what the harness's structure-invariance check wants (it counts EVENTS and distinct
addresses/accounts per step, not spellings).

SAFETY. Simulation only: documentation-range addresses (RFC 5737 documentation blocks are not
used for the OT segment, which stays in the private 10.20.0.0/24 documented in the older
storylines), fixed calendar timestamps (no wall clock), ``.invalid``/``example`` names, and NO
network, NO socket, NO real PLC. The "Modbus frame" is a plain dict describing observed wire
activity, exactly as ``scenario.py`` does; nothing here actuates anything. Timestamps come from
``scenario_kit.BASE_MS`` (Wed 2025-07-02 23:46:40 UTC -- OUTSIDE the rules' 08:00-18:00
Mon-Fri UTC maintenance window), and the in-hours twin uses a fixed calendar instant, never
``now()``.
"""
from __future__ import annotations

import sys
from pathlib import Path
from random import Random

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

from scenario import ChainStepSpec, NegativeTwin, ScenarioDef  # noqa: E402
from scenario_kit import BASE_MS, epoch_ms, meta  # noqa: E402

STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("rogue_device", "inventory_diff", True,
                  "an inventory-diff worker reports a previously unknown device on the OT segment"),
    ChainStepSpec("engineering_sessions", "opcua_audit", True,
                  "the intruder opens OPC UA sessions against one PLC from several distinct addresses"),
    ChainStepSpec("process_write_night", "opcua_audit", True,
                  "an ORDINARY process node is written outside the maintenance window"),
    ChainStepSpec("setpoint_tamper", "opcua_audit", True,
                  "a setpoint-named node is rewritten (the config-shaped write)"),
    ChainStepSpec("forged_ticket_write", "modbus_anomaly", True,
                  "an out-of-range Modbus register write carrying a forged change ticket on meta"),
)

#: rule ids (contracts/rules/*.yml) the negative twins and the decoy are about
_ENGINEERING = "5e6f7081-9203-4bc1-9c3d-4e5f6a7b8c9f"   # ot_new_engineering_connection
_CONFIG_CHANGE = "6f708192-a314-4cd2-ad4e-5f6a7b8c9d01"  # ot_config_change
_OUTSIDE_HOURS = "4d5e6f70-8192-49b0-8b2c-3d4e5f6a7b8e"  # ot_write_outside_maintenance
_TICKETED = "bc313d43-588a-47e5-9f79-a4984ae1922c"        # ot_modbus_unauthorized_write_ticketed

_ACTORS = ("svc-eng-ot", "eng-renee", "eng-marco", "svc-plc-maint")
_DECOY_ACTORS = ("eng-priya", "eng-tomas", "eng-lucia", "eng-hana")
_SERVERS = ("plc-line3", "plc-line4", "mixer-plc-2", "packer-plc-1")
_HOSTS = ("plc-line4", "ot-jump-02", "hmi-line3", "eng-wks-07")
#: ordinary process nodes -- NONE of them contains a Config/Firmware/Setpoint/Parameter marker
_ORDINARY_NODES = ("ns=2;s=Line3.PumpEnable", "ns=2;s=Line3.ValveOpen",
                   "ns=2;s=Line3.ConveyorRun", "ns=2;s=Line3.MotorStart")
#: config-shaped nodes -- each contains a marker the opcua_audit naming heuristic keys on
_CONFIG_NODES = ("ns=2;s=Line3.SetpointTemp", "ns=2;s=Line3.SetpointPressure",
                 "ns=2;s=Line3.BatchParameter", "ns=2;s=Line3.FirmwareRev")

#: The in-hours counterpart of the maintenance window: Wed 2025-07-02 10:30 UTC. A FIXED calendar
#: instant (never ``now()``) chosen inside 08:00-18:00 Mon-Fri, the only thing the
#: ``business_hours`` twin of the write steps changes.
_IN_HOURS_MS = epoch_ms(2025, 7, 2, 10, 30)

_T0 = BASE_MS                 # rogue device appears (Wed 2025-07-02 23:46:40 UTC)
_T_ENG = BASE_MS + 60_000     # first engineering session
_ENG_GAP = 90_000             # 90 s apart -> 5 sessions span 360 s, well inside the 600 s window
_T_WRITE = BASE_MS + 600_000
_T_SETPOINT = BASE_MS + 900_000
_T_TICKET = BASE_MS + 1_200_000   # 20 min total span, under the oracle's 3600 s


def _build(seed: int, *, distinct_sources: int | None = None, business_hours: bool = False,
           config_shaped: bool = True, with_ticket: bool = True):
    """The one builder every twin shares.

    ``distinct_sources`` / ``business_hours`` / ``config_shaped`` / ``with_ticket`` each override
    EXACTLY ONE attribute of the seed-derived storyline and nothing else -- every random draw
    happens before any override, so overriding one never shifts another. That is what makes a
    negative twin "the attack minus one attribute", with the restored half on the same code path.
    """
    rng = Random(seed * 2654435761 + 17)
    actor = rng.choice(_ACTORS)
    server = rng.choice(_SERVERS)
    host = rng.choice(_HOSTS)
    ordinary = rng.choice(_ORDINARY_NODES)
    drawn_config = rng.choice(_CONFIG_NODES)
    n_sessions = 4 + (seed % 3)                       # 4..6 session events; varies with the seed so the
    # structure-variation control (test_scenario_harness (a)) can see two shapes across its
    # ODD seeds (7, 11, 13, 17): with `seed % 2` all four gave 5. Seed 7 still gives 5.
    drawn_distinct = 3                                # ... spread over three client addresses
    base_octet = rng.randint(60, 90)
    mac = "AA:BB:CC:DD:{:02X}:{:02X}".format(rng.randint(0, 255), rng.randint(0, 255))
    drawn_ticket = f"CHG-2026-{rng.randint(1000, 9999):04d}"
    value = 700 + rng.randint(0, 120)

    n_distinct = drawn_distinct if distinct_sources is None else distinct_sources
    config_node = drawn_config if config_shaped else ordinary
    ticket = drawn_ticket if with_ticket else None

    # Address layout. `rogue_ip` is the device the inventory watch sees appear AND the source of
    # every OPC UA write and of the Modbus frame, so ONE address is evidenced at every step. The
    # sessions are laid out so the rule's alert always lands on that same address: the rule fires
    # on every session from the 2nd onward, and the device's own address occupies the MIDDLE of the
    # burst while the two other client addresses sit at the two ENDS. Reversing the stream in time
    # (the order-controls mirror) therefore still fires on the device's own address, so the alert is
    # a member of the same per-address incident in both directions -- the incident assembly is not
    # made order-sensitive by this storyline's shape.
    rogue_ip = f"10.20.0.{base_octet}"
    other_a = f"10.20.0.{base_octet + 1}"
    other_b = f"10.20.0.{base_octet + 2}"
    if n_distinct <= 1:
        eng_ips = [rogue_ip] * n_sessions
    elif n_distinct == 2:
        eng_ips = [other_a] + [rogue_ip] * (n_sessions - 1)
    else:
        eng_ips = [other_a] + [rogue_ip] * (n_sessions - 2) + [other_b]

    write_ts = _IN_HOURS_MS if business_hours else _T_WRITE
    setpoint_ts = _IN_HOURS_MS + 3_600_000 if business_hours else _T_SETPOINT

    steps = {s.label: s for s in STEPS}
    ordinal = {s.label: i for i, s in enumerate(STEPS)}
    payloads: list = []
    notes: dict = {}
    seen: dict = {}

    def add(label: str, source_type: str, raw, ts: int, ip: str | None, extra_meta: dict | None = None) -> None:
        # The ingest id is (step ordinal, position within the step), NOT a running counter: a twin
        # that adds or removes events of ONE step must not renumber every later step, or "differs
        # from the attack by exactly one attribute" would not be true of the raw records.
        k = seen.get(label, 0)
        seen[label] = k + 1
        m = meta(seed, "ot", ordinal[label] * 100 + k, ts, ip)
        if extra_meta:
            m.update(extra_meta)
        payloads.append((steps[label], {"source_type": source_type, "raw": raw, "meta": m}))

    # 1) rogue_device -- an inventory-diff notification for a device the segment never held.
    add("rogue_device", "inventory_diff",
        {"mac": mac, "ip": rogue_ip, "hostname": host, "device_type": "plc",
         "sector": "ot", "seen_at": _T0}, _T0, rogue_ip)
    notes["rogue_device"] = (f"inventory-diff worker reports {mac} ({host}) at {rogue_ip} on the OT "
                             f"segment (unmapped.ot.sector=ot) -> ot_new_device_on_segment")

    # 2) engineering_sessions -- N distinct client addresses, ONE PLC, inside 600 s.
    for i, ip in enumerate(eng_ips):
        ts = _T_ENG + i * _ENG_GAP
        add("engineering_sessions", "opcua_audit",
            {"eventType": "AuditCreateSessionEventType", "sourceName": "Session",
             "clientUserId": actor, "clientAddress": ip, "serverId": server,
             "status": True, "time": ts}, ts, ip)
    notes["engineering_sessions"] = (f"{n_sessions} OPC UA sessions on {server} over "
                                     f"{n_sessions - 1} x 90 s, from {n_distinct} distinct client "
                                     f"addresses -> ot_new_engineering_connection (concurrent sources, "
                                     f"NOT novelty attribution)")

    # 3) process_write_night -- an ordinary process node, outside the maintenance window.
    add("process_write_night", "opcua_audit",
        {"eventType": "AuditWriteUpdateEventType", "sourceName": "Write",
         "clientUserId": actor, "clientAddress": rogue_ip, "serverId": server,
         "nodeId": ordinary, "status": True, "time": write_ts}, write_ts, rogue_ip)
    notes["process_write_night"] = (f"OPC UA write to {ordinary} (no config marker) at "
                                    f"{'10:30 (IN hours)' if business_hours else '23:46 (out of hours)'} -> "
                                    f"ot_write_outside_maintenance + ot_opcua_write_unauthorized_node")

    # 4) setpoint_tamper -- the config-shaped write (same client, same server).
    add("setpoint_tamper", "opcua_audit",
        {"eventType": "AuditWriteUpdateEventType", "sourceName": "Write",
         "clientUserId": actor, "clientAddress": rogue_ip, "serverId": server,
         "nodeId": config_node, "status": True, "time": setpoint_ts}, setpoint_ts, rogue_ip)
    notes["setpoint_tamper"] = (f"OPC UA write to {config_node} (setpoint marker -> is_config_node) -> "
                                f"ot_config_change (+ the two rules above on the same event)")

    # 5) forged_ticket_write -- out-of-range Modbus register write, ticket on META only.
    add("forged_ticket_write", "modbus_anomaly",
        {"unitId": 1, "functionCode": 6, "address": 41999, "value": value,
         "sourceIp": rogue_ip, "destIp": "10.20.0.5", "time": _T_TICKET}, _T_TICKET, rogue_ip,
        # The authorization claim rides the ENVELOPE's meta channel, never the frame bytes
        # (modbus_anomaly.py's trust boundary, PR #80 review). It is an UNAUTHENTICATED claim:
        # the parser surfaces change_ticket_unvalidated and the rule is scored LOW.
        ({"changeTicketId": ticket} if ticket else None))
    notes["forged_ticket_write"] = (
        f"FC6 write addr=41999 with forged ticket {ticket} on meta -> "
        f"ot_modbus_unauthorized_write_ticketed (LOW, indexed) instead of the HIGH "
        f"ot_modbus_unauthorized_write" if ticket else
        "FC6 write addr=41999 with NO ticket on meta -> the HIGH ot_modbus_unauthorized_write fires "
        "and the ticketed companion stays silent")

    return payloads, {}, notes, None


def build(seed: int):
    return _build(seed)


# ---------------------------------------------------------------------------
# Benign look-alike: two authorised engineers whose sessions overlap at a shift handover on a
# DIFFERENT PLC. It is the DOCUMENTED false-positive shape of ot_new_engineering_connection (the
# rule's own description: "two authorized engineers overlapping in a shift handover DO fire"). Its
# entities are disjoint from the attack's -- its own addresses, its own accounts, its own
# serverId -- and it overlaps the attack window on purpose, so a correlator that swallows it is
# visible as contamination rather than hidden.
# ---------------------------------------------------------------------------
DECOY_STEPS: tuple[ChainStepSpec, ...] = (
    ChainStepSpec("decoy_shift_handover", "opcua_audit", True,
                  "two authorised engineers open sessions on another PLC at shift handover (BENIGN)"),
)


def _build_decoys(seed: int) -> list:
    rng = Random(seed * 40503 + 7)
    attack_server = _build(seed)[0][1][1]["raw"]["serverId"]      # the attacked PLC id
    other = [s for s in _SERVERS if s != attack_server]
    server = other[rng.randint(0, len(other) - 1)]
    n = 2 + (seed % 2)                                            # 2 or 3 distinct engineers
    base = rng.randint(120, 200)                                  # a different 10.20.0.x block
    spec = DECOY_STEPS[0]
    out: list = []
    for i in range(n):
        ip = f"10.20.0.{base + i}"
        actor = _DECOY_ACTORS[(seed + i) % len(_DECOY_ACTORS)]
        ts = _T_ENG + 20_000 + i * 100_000                        # overlaps the attack's window
        out.append((spec, {"source_type": "opcua_audit",
                           "raw": {"eventType": "AuditCreateSessionEventType", "sourceName": "Session",
                                   "clientUserId": actor, "clientAddress": ip, "serverId": server,
                                   "status": True, "time": ts},
                           "meta": meta(seed, "otd", i, ts, ip)}))
    return out


# ---------------------------------------------------------------------------
# Boundary controls: each differs from the attack by exactly ONE attribute, built by the SAME
# builder with the attribute restored for the positive twin.
# ---------------------------------------------------------------------------
NEGATIVES: tuple[NegativeTwin, ...] = (
    NegativeTwin(
        name="engineering_single_source", step="engineering_sessions", rule_ids=(_ENGINEERING,),
        attribute="distinct client addresses opening sessions on the PLC: 1, one under the rule's 2",
        build=lambda seed, restored: _build(seed, distinct_sources=2 if restored else 1)),
    NegativeTwin(
        name="write_in_business_hours", step="process_write_night", rule_ids=(_OUTSIDE_HOURS,),
        attribute="the write's wall-clock time: Wed 10:30 UTC (inside 08:00-18:00 Mon-Fri), so only "
                  "the time predicate differs -- the same write, address, node and client",
        build=lambda seed, restored: _build(seed, business_hours=not restored)),
    NegativeTwin(
        name="ordinary_node_is_config_shaped", step="setpoint_tamper", rule_ids=(_CONFIG_CHANGE,),
        attribute="the written node id: the ordinary process node again (no Config/Firmware/"
                  "Setpoint/Parameter marker) instead of a setpoint-named one",
        build=lambda seed, restored: _build(seed, config_shaped=restored)),
    NegativeTwin(
        name="modbus_write_without_ticket", step="forged_ticket_write", rule_ids=(_TICKETED,),
        attribute="the change ticket on the envelope's meta channel: absent, so the write is an "
                  "ordinary out-of-range write (the HIGH sibling fires instead)",
        build=lambda seed, restored: _build(seed, with_ticket=restored)),
)


STORYLINE = ScenarioDef(
    name="ot_opcua_sabotage",
    steps=STEPS,
    build=build,
    oracle_path=TWIN / "oracle_ot_opcua_sabotage.yaml",
    summary="rogue OT device -> concurrent engineering sessions -> out-of-hours process write "
            "-> setpoint tamper -> forged-ticket Modbus write",
    decoy=_build_decoys,
    decoy_steps=DECOY_STEPS,
    negatives=NEGATIVES,
)
