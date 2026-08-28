"""negative_controls.py -- false-positive-rate (FPR) source for the AI-to-OT twin.

WP-1-D. The honest counterpart to the (positive) attack chain in scenario.py
(WP-1-B): the SAME PLC write primitives, but performed in a legitimately
benign context. The maintainer's story is simple -- an approved maintenance
window write, an authorized operator, a routine setpoint tweak, a benign n8n
edit should all produce ZERO incidents. Any incident (alert) that fires on
one of these is a false positive, and this module is the FPR claim's source
of truth: a non-zero count here is a red flag for rule coarseness, NOT
something to paper over by weakening the scenario.

Each negative runs through the SAME pipeline the positive chain uses --
memory bus + real WS-2 parser + real WS-4 detection -- so the comparison is
apples-to-apples. Detection is the real `Detector.process()` path
(class_uid bucket prefilter + per-tenant rule disable + Rule.evaluate),
counting every matched rule as an alert.

DETERMINISM: no wall clock anywhere. Every raw event carries an explicit
epoch-ms timestamp chosen from a fixed calendar (past dates, inside the
08:00-18:00 Mon-Fri maintenance window). The same seed -> the same PLC write
trace -> the same raw frames -> byte-identical verdicts forever. The only
randomness is PLCSim's own seeded RNG.

SCOPE / CONTRACT
    * Owns ONLY this file. Reads (never edits) plc_sim.py, the parsers, and
      contracts/rules/*.yml.
    * Four negatives, each asserting zero incidents. Exit 0 only when all
      four produced zero alerts.

THE FINDING THIS MODULE SURFACED, AND THE FIX (read before running)
    Scenario 1 (approved maintenance window) deliberately reuses the exact
    pump-enable write that produces the incident in the attack chain: writing
    the pump-enable COIL, from the SAME source IP, inside business hours.
    Modbus single-coil writes live in the 0xxxx coil address space, which
    `modbus_anomaly._EXPECTED_WRITE_ADDRESSES` (40001-40010, holding
    registers only) does not include -- so the parser classified EVERY coil
    write as `unauthorized_write`, and `ot_modbus_unauthorized_write` fired
    on it regardless of the maintenance window, the authorizer, or the hour.
    That was a real, honestly-reported FPR (0.25): address, source IP, and
    time-of-day are exactly the same between the attack write and this
    approved write, so no rule keyed on any of those three fields can tell
    them apart -- the gap was that the pipeline had NO authorization signal
    at all to key on.

    The fix (`unmapped.ot.change_ticket_id`, see modbus_anomaly.py's module
    docstring and `contracts/rules/ot_modbus_unauthorized_write.yml`) adds
    exactly that: an explicit, out-of-band field a real tap/proxy could
    attach when it also has access to a change-management system. This
    scenario now attaches a change-ticket id to the approved write (see
    `_write_pump_enable`'s `change_ticket_id` param below), simulating that
    integration, and the rule's `authorized_change` selection suppresses the
    alert when it's present. The attack chain (`eval/twin/scenario.py`) never
    sets this field, so it still fires -- see that module's `modbus_write`
    step.

    This proves the SUPPRESSION MECHANISM works correctly on the twin's
    simulated data. It is not a claim that FENGARDE solves real-world OT
    change authorization: nothing here validates a `changeTicketId` against
    an actual ticketing system (there is none to validate against), so a
    deployment wiring this field for real must trust its own tap/proxy
    integration, not this twin.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVICES = ROOT / "services"
for _p in (ROOT, SERVICES / "ws2-normalization", SERVICES / "ws4-detection",
           SERVICES, ROOT / "tools"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from shared.bus import Bus  # noqa: E402
from parsers import _REGISTRY  # noqa: E402
from enrichment import enrich  # noqa: E402
from main import Detector  # noqa: E402 -- ws4-detection's real Detector
from eval.twin.plc_sim import (  # noqa: E402
    COIL_PUMP_ENABLE, REG_LEVEL, REG_SETPOINT, PLCSim,
)

# --------------------------------------------------------------------------
# Deterministic, in-the-past timestamps inside the 08:00-18:00 Mon-Fri window
# (engine's outside_hours predicate evalutes the raw epoch directly, and the
# stateful clock-skew guard accepts anything not >5min ahead of wall-clock).
# --------------------------------------------------------------------------
_TZ_UTC = timezone.utc


def _epoch_ms(*dt_utc: int) -> int:
    """epoch-ms for a fixed UTC datetime ``(y, m, d, h, min)`` -- pure, no now()."""
    y, m, d, h, mi = dt_utc
    return round(datetime(y, m, d, h, mi, tzinfo=_TZ_UTC).timestamp() * 1000)


# Single fixed calendar week (past on every real run date after 2026-08-28):
# all inside Mon-Fri 08:00-18:00 UTC.
T_TUE_1030 = _epoch_ms(2026, 8, 25, 10, 30)   # maintenance-window write
T_TUE_1100 = _epoch_ms(2026, 8, 25, 11, 0)    # authorized operator session
T_TUE_1300 = _epoch_ms(2026, 8, 25, 13, 0)    # benign n8n edit
T_TUE_1301 = _epoch_ms(2026, 8, 25, 13, 1)    # ... and workflow activate
T_MON_1400 = _epoch_ms(2026, 8, 24, 14, 0)
T_WED_0915 = _epoch_ms(2026, 8, 26, 9, 15)
T_THU_1640 = _epoch_ms(2026, 8, 27, 16, 40)

_SRC_ENG = "10.20.0.50"      # authorized engineering workstation
_SRC_OPS = "10.20.0.51"      # authorized operator workstation
_DST_PLC = "10.20.0.5"       # the simulated PLC

# Modbus wire addresses for the twin's register/coil map (holding regs are
# 1-based 4xxxx on the wire; the coil is a 0xxxx coil address).
_ADDR_SETPOINT = 40001
_ADDR_LEVEL = 40002
_FRAME = "modbus_anomaly"    # SOURCE_TYPE in the parsers registry


# --------------------------------------------------------------------------
# Shared pipeline: memory bus -> real parser -> enrich -> real Detector.
# --------------------------------------------------------------------------
def run_pipeline(raw_events: list[tuple[str, dict]], tenant: str) -> list[dict]:
    """Run raw envelopes through the real pipeline; return every fired alert.

    ``raw_events`` is a list of ``(source_type, raw_record)`` pairs. Each is
    produced onto the in-memory bus, consumed, parsed by the REAL registered
    parser, enriched, normalized onto the bus, and finally run through a
    FRESH real `Detector`. A fresh detector per scenario isolates the
    stateful sliding-window counters so no negative can contaminate another.
    The returned list holds one dict per fired rule: ``{rule_id, rule_title,
    source_type}``. Zero-length return == zero incidents for the scenario.
    """
    bus = Bus()  # BUS_BACKEND unset -> in-memory (zero-infra dev loop)
    events: list[dict] = []
    for source_type, rec in raw_events:
        envelope = {"source_type": source_type, "raw": rec}
        bus.produce("raw.events", key=_DST_PLC, payload=envelope)
    for msg in list(bus.consume("raw.events", group="cg-normalize")):
        envelope = msg.payload
        source_type = envelope.get("source_type")
        parser = _REGISTRY.get(source_type)
        event = parser.parse(envelope) if parser is not None else None
        if event is None:
            continue
        event = enrich(event)
        (event.setdefault("siem", {})).update(
            {"tenant": tenant, "ingest_id": f"neg:{tenant}:{len(events)}"})
        bus.produce("normalized.events", key=_DST_PLC, payload=event)
        events.append(event)

    detector = Detector(plugin_rule_dirs=[])  # deterministic rule set
    alerts: list[dict] = []
    for msg in list(bus.consume("normalized.events", group="cg-detect")):
        event = msg.payload
        _ev, matched, _action = detector.process(event)
        for rule in matched:
            alerts.append({"rule_id": rule.id, "rule_title": rule.title,
                           "score_weight": rule.score_weight,
                           "source_type": (event.get("siem") or {}).get(
                               "source_type")})
    return alerts


# --------------------------------------------------------------------------
# PLC write primitives reused from the (positive) attack chain -- the SAME
# writes, in benign contexts. Each applies the write to a seeded PLCSim (the
# real twin) and returns the Modbus frame a tap would report for it.
# --------------------------------------------------------------------------
def _write_setpoint(sim: PLCSim, value: int, ts: int, src: str) -> dict:
    sim.write_holding(REG_SETPOINT, value)
    sim.tick()
    return {"functionCode": 6, "address": _ADDR_SETPOINT, "value": value,
            "unitId": 1, "sourceIp": src, "destIp": _DST_PLC, "time": ts}


def _write_pump_enable(sim: PLCSim, enabled: bool, ts: int, src: str,
                       change_ticket_id: str | None = None) -> dict:
    sim.write_coil(COIL_PUMP_ENABLE, enabled)
    sim.tick()
    frame = {"functionCode": 5, "address": COIL_PUMP_ENABLE,
             "value": 0xFF00 if enabled else 0x0000,
             "unitId": 1, "sourceIp": src, "destIp": _DST_PLC, "time": ts}
    if change_ticket_id is not None:
        # The out-of-band authorization signal a real tap/proxy integrated
        # with a change-management system could attach -- see
        # modbus_anomaly.py's module docstring.
        frame["changeTicketId"] = change_ticket_id
    return frame


def _write_level_adjust(sim: PLCSim, value: int, ts: int, src: str) -> dict:
    sim.write_holding(REG_LEVEL, value)
    sim.tick()
    return {"functionCode": 6, "address": _ADDR_LEVEL, "value": value,
            "unitId": 1, "sourceIp": src, "destIp": _DST_PLC, "time": ts}


# --------------------------------------------------------------------------
# Benign MCP / n8n records (scenarios 2 & 4). Ordinary arguments only -- no
# credential paths, no injection phrasing, no destructive commands, no egress
# URL -- so the agent_* / n8n_* heuristics all stay clear.
# --------------------------------------------------------------------------
def _agent_benign(sim: PLCSim, ts: int, src: str) -> dict:
    """A single normal agent tool call: read the tank level (authorized op)."""
    level = sim.read_holding(REG_LEVEL)
    return {"tool": "modbus_read_holding", "session_id": "sess-ops-1",
            "agent": "fengarde-ops", "server": "modbus",
            "arguments": {"register": "level", "unitId": 1, "value": level},
            "outcome": "success", "ts": ts, "src_ip": src}


def _agent_setpoint_write(sim: PLCSim, ts: int, src: str) -> dict:
    """The authorized operator changes the setpoint via a normal tool call."""
    return {"tool": "modbus_write_holding", "session_id": "sess-ops-1",
            "agent": "fengarde-ops", "server": "modbus",
            "arguments": {"register": "setpoint", "address": _ADDR_SETPOINT,
                          "unitId": 1},
            "outcome": "success", "ts": ts, "src_ip": src}


def _n8n_workflow_update(user: str, ip: str, ts: int) -> dict:
    return {"eventType": "workflow.updated", "user": user, "ip": ip,
            "workflowId": "wf-order-intake", "ts": ts}


def _n8n_workflow_activate(user: str, ip: str, ts: int) -> dict:
    return {"eventType": "workflow.activated", "user": user, "ip": ip,
            "workflowId": "wf-order-intake", "ts": ts}


# --------------------------------------------------------------------------
# The four negative scenarios. Each returns (name, alerts).
# --------------------------------------------------------------------------
_MAINTENANCE_CHANGE_TICKET = "CHG-2026-08-1042"


def scenario_maintenance_window(seed: int) -> tuple[str, list[dict]]:
    """S1: the attack's exact PLC write, inside an APPROVED maintenance window,
    carrying an approved change ticket.

    An approved work order changes the setpoint AND re-enables the pump coil
    at Tue 10:30 UTC -- squarely inside the approved 08:00-18:00 Mon-Fri
    window. The setpoint write (40001) is in the expected write range and is
    (correctly) never flagged regardless. The pump-enable COIL write is still
    classified `unauthorized_write` by the modbus_anomaly parser (the
    expected-write set only covers holding registers 40001-40010, not the
    0xxxx coil space) -- that classification is an honest protocol-level
    observation and doesn't change. What changes is that this write carries
    `_MAINTENANCE_CHANGE_TICKET`, the out-of-band authorization signal
    `ot_modbus_unauthorized_write` now checks for, so the rule's
    `authorized_change` selection suppresses the alert. See this module's
    docstring for why this was a real FPR before the field existed, and why
    the fix only proves the mechanism, not real-world authorization.
    """
    sim = PLCSim(seed=seed)
    raw = [
        (_FRAME, _write_setpoint(sim, 520, T_TUE_1030, _SRC_ENG)),
        (_FRAME, _write_pump_enable(sim, True, T_TUE_1030, _SRC_ENG,
                                    change_ticket_id=_MAINTENANCE_CHANGE_TICKET)),
    ]
    return "approved-maintenance-window", run_pipeline(raw, "neg-maintenance")


def scenario_authorized_operator(seed: int) -> tuple[str, list[dict]]:
    """S2: the same control write, made by an AUTHORIZED OPERATOR session.

    A single legitimate agent session (authorized role 'fengarde-ops') reads
    the tank level, then adjusts the setpoint. Ordinary tool arguments --
    no credential-path access, no injection phrasing, no destructive command,
    no egress domain -- and a single tool call (nowhere near the 50-in-60s
    burst threshold). Expect zero agent_* and zero OT alerts.
    """
    sim = PLCSim(seed=seed)
    raw = [
        ("mcp_agent", _agent_benign(sim, T_TUE_1100, _SRC_OPS)),
        ("mcp_agent", _agent_setpoint_write(sim, T_TUE_1100, _SRC_OPS)),
    ]
    return "authorized-operator", run_pipeline(raw, "neg-operator")


def scenario_unrelated_writes(seed: int) -> tuple[str, list[dict]]:
    """S3: UNRELATED Modbus writes -- normal, scattered setpoint tweaks.

    Routine setpoint/level adjustments across the week at in-window times,
    with no connection to any attack chain. All target in-bounds holding
    registers (40001/40002) -- none is an out-of-range write, so
    `ot_modbus_unauthorized_write` must stay silent.
    """
    sim = PLCSim(seed=seed)
    raw = [
        (_FRAME, _write_level_adjust(sim, 300, T_MON_1400, _SRC_OPS)),
        (_FRAME, _write_setpoint(sim, 520, T_WED_0915, _SRC_ENG)),
        (_FRAME, _write_setpoint(sim, 480, T_THU_1640, _SRC_OPS)),
    ]
    return "unrelated-writes", run_pipeline(raw, "neg-unrelated")


def scenario_benign_n8n_edits(seed: int) -> tuple[str, list[dict]]:
    """S4: BENIGN n8n workflow edits -- no webhook, no credentials, no abuse.

    A developer updates and activates an ordinary order-intake workflow in
    business hours. No `webhook.created`, no `credentials.accessed`, so
    neither the webhook rule nor the after-hours rule (edit is in-window) can
    fire. When the workflow runs it only triggers the benign level read above.
    """
    raw = [
        ("n8n_audit", _n8n_workflow_update("dev.alex", _SRC_ENG, T_TUE_1300)),
        ("n8n_audit", _n8n_workflow_activate("dev.alex", _SRC_ENG, T_TUE_1301)),
        ("mcp_agent", _agent_benign(PLCSim(seed=seed), T_TUE_1301, _SRC_OPS)),
    ]
    return "benign-n8n-edits", run_pipeline(raw, "neg-n8n")


_ALL_SCENARIOS = (
    scenario_maintenance_window,
    scenario_authorized_operator,
    scenario_unrelated_writes,
    scenario_benign_n8n_edits,
)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="negative_controls",
        description="WP-1-D: FPR source for the AI-to-OT twin (four negatives, "
                    "all must yield ZERO incidents).")
    parser.add_argument("--seed", type=int, default=1,
                        help="PLCSim RNG seed (same seed => same verdicts)")
    args = parser.parse_args(argv)

    results: list[tuple[str, list[dict]]] = []
    total_alerts = 0
    for scenario in _ALL_SCENARIOS:
        name, alerts = scenario(args.seed)
        results.append((name, alerts))
        total_alerts += len(alerts)
        if not alerts:
            print(f"[OK]   {name} -- {0} incidents (zero alerts)")
        else:
            print(f"[FAIL] {name} -- {len(alerts)} incident(s):")
            for a in alerts:
                print(f"        - rule '{a['rule_title']}' fired "
                      f"on a {a['source_type']} event "
                      f"(id {a['rule_id']})")

    print("-" * 60)
    if total_alerts == 0:
        print(f"ZERO-INCIDENT SUMMARY: all {len(results)} negative scenarios "
              "produced 0 incidents -- FPR clean for the tested benign set.")
        return 0
    print(f"ZERO-INCIDENT SUMMARY: {total_alerts} incident(s) across "
          f"{len(results)} negative scenario(s) -- FALSE-POSITIVE FINDING; "
          "the honest FPR claim is NOT met until these are resolved.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
