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
    scenario now attaches a change-ticket id to the approved write -- carried
    on the ENVELOPE's meta channel, never inside the frame bytes (see
    scenario_maintenance_window / modbus_anomaly.py's trust boundary, per
    the PR #80 review), simulating that integration.
    `ot_modbus_unauthorized_write`'s `authorized_change`
    selection steps aside when it's present, and
    `ot_modbus_unauthorized_write_ticketed.yml` fires INSTEAD, at
    `level: low` -- the event is downgraded, never dropped: it still
    reaches the index, still shows up in search/hunting, and `is_incident()`
    below is what makes this scenario's "zero incidents" claim mean "zero
    HIGH+ alerts," not "zero alerts of any kind." The attack chain
    (`eval/twin/scenario.py`) never sets this field, so the HIGH rule still
    fires unchanged -- see that module's `modbus_write` step.

    This proves the DOWNGRADE MECHANISM works correctly on the twin's
    simulated data. It is not a claim that FENGARDE solves real-world OT
    change authorization: nothing here validates a `changeTicketId` against
    an actual ticketing system (there is none to validate against), so a
    deployment wiring this field for real must trust its own tap/proxy
    integration, not this twin -- and must treat that trust boundary as
    load-bearing, since anyone who can populate the field on the transport
    meta channel moves a write from HIGH to LOW with no cross-check. See
    SECURITY.md.

    THE GATE (this module's exit code) enforces more than "zero incidents":
    scenario 1 (approved-maintenance-window) MUST also produce the
    LOW-severity ticketed alert (`ot_modbus_unauthorized_write_ticketed`,
    id bc313d43-...). Zero alerts there would be indistinguishable from a
    regression to silent suppression (the thing the downgrade design
    replaced), so the gate fails on that too.
"""
from __future__ import annotations

import argparse
import importlib
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
# Lazy import of the REAL WS-2 normalization pipeline (mirrors
# scenario._get_ws2, which manages the `main` module-name collision: this
# module binds ws4's Detector at import time, so popping/importing ws2's own
# `main` later does not disturb the already-bound Detector class).
# --------------------------------------------------------------------------
_ws2 = None


def _get_ws2():
    """Return ws2-normalization's ``main`` module (the REAL normalize path):
    resolve -> parse -> _sanitize_free_text (M1) -> enrich (A5) -> validate
    (Contract A). Findings 3 of PR #80 review: the twin's headline metrics
    (TPR/FPR) MUST measure THIS pipeline -- not a hand-rolled parse+enrich
    that skipped the M1 sanitizer and Contract-A validation.

    Loaded by explicit file path under a UNIQUE module name (mirroring
    report.py's load of ws4) rather than `import main`: both ws2 and ws4 ship
    a top-level ``main.py``, and bare ``import main`` after the path juggling
    deterministically resolves to ws4's here (whereas scenario.py runs first
    and wins the name). A unique name also leaves ``sys.modules["main"]``
    bound to ws4's Detector, which this module already imported."""
    global _ws2
    if _ws2 is not None:
        return _ws2
    for p in (str(SERVICES / "ws2-normalization"), str(SERVICES)):
        if p not in sys.path:
            sys.path.insert(0, p)
    spec = importlib.util.spec_from_file_location(
        "ws2_normalization_main", str(SERVICES / "ws2-normalization" / "main.py"))
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot locate ws2-normalization/main.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ws2_normalization_main"] = mod
    spec.loader.exec_module(mod)
    _ws2 = mod
    return _ws2


# --------------------------------------------------------------------------
# Shared pipeline: memory bus -> REAL WS-2 normalize_one -> real Detector.
# --------------------------------------------------------------------------
def run_pipeline(raw_events: list[tuple], tenant: str) -> list[dict]:
    """Run raw envelopes through the REAL WS-2 -> WS-4 pipeline; return fired alerts.

    ``raw_events`` is a list of tuples, each ``(source_type, raw_record)``
    optionally followed by ``(source_type, raw_record, meta)`` and optionally
    a 4th element ``step`` (a chain-step label used for per-step attribution
    by report.py's TPR -- see plausible-A of the PR #80 review; the negatives
    pass no step). Each envelope is produced onto the in-memory bus, then run
    through ``ws2.normalize_one`` -- the SAME real WS-2 code path the attack
    chain uses: resolve -> parse -> sanitize free text (M1) -> enrich (A5) ->
    validate against Contract A (finding 3: the old path hand-rolled
    parse+enrich and skipped both the sanitizer and validation). Events that
    fail to normalize (no parser / validation errors / parser raised) are
    dropped exactly as the real pipeline dead-letters them -- never counted
    as an alert. The surviving events run through a FRESH real `Detector`; a
    fresh detector per scenario isolates the stateful sliding-window counters
    so no negative can contaminate another.

    The returned list holds one dict per fired rule:
    ``{rule_id, rule_title, score_weight, level, source_type, step}`` (step
    only when provided). Zero-length return == zero incidents/zero alerts.
    """
    ws2 = _get_ws2()
    bus = Bus()  # BUS_BACKEND unset -> in-memory (zero-infra dev loop)
    events: list[dict] = []
    for entry in raw_events:
        source_type = entry[0]
        rec = entry[1]
        meta = entry[2] if len(entry) > 2 and isinstance(entry[2], dict) else {}
        step = entry[3] if len(entry) > 3 else None
        envelope = {"source_type": source_type, "raw": rec, "meta": meta}
        bus.produce("raw.events", key=_DST_PLC, payload=envelope)
        event, errors = ws2.normalize_one(envelope)
        if event is None or errors:
            continue  # dead-lettered by the real pipeline -> never an alert
        (event.setdefault("siem", {})).update(
            {"tenant": tenant, "ingest_id": f"neg:{tenant}:{len(events)}"})
        # Per-step attribution for report.py's TPR (PR #80 review plausible-A):
        # tag which chain step this event belongs to, so a fired rule is
        # credited to the exact step that triggered it, not pooled by
        # source_type (two steps can share a source_type, e.g. mcp_agent).
        if step is not None:
            event.setdefault("siem", {})["twin_step"] = step
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
                           "level": rule.level,
                           "source_type": (event.get("siem") or {}).get(
                               "source_type"),
                           "step": (event.get("siem") or {}).get("twin_step")})
    return alerts


def is_incident(alert: dict) -> bool:
    """An alert counts as an incident (a false positive, in this module's
    context) unless it's `low`/`informational` -- e.g. the ticketed-write
    companion rule (`ot_modbus_unauthorized_write_ticketed.yml`), which
    deliberately still fires and indexes a ticketed write instead of
    silently dropping it (see that rule's description). A LOW alert on an
    explained write is accurate telemetry, not a false positive."""
    return alert.get("level") not in ("low", "informational")


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


def _write_pump_enable(sim: PLCSim, enabled: bool, ts: int, src: str) -> dict:
    sim.write_coil(COIL_PUMP_ENABLE, enabled)
    sim.tick()
    # PR #80 trust-boundary review: the frame record is the WIRE channel -- a
    # changeTicketId must NEVER ride inside it (an attacker on the wire could
    # forge the HIGH->LOW downgrade). The ticket belongs on the envelope's
    # META channel, which the caller attaches when it wraps this frame (see
    # scenario_maintenance_window). We do not write it into the frame.
    return {"functionCode": 5, "address": COIL_PUMP_ENABLE,
            "value": 0xFF00 if enabled else 0x0000,
            "unitId": 1, "sourceIp": src, "destIp": _DST_PLC, "time": ts}


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
    `ot_modbus_unauthorized_write`'s `authorized_change` selection checks
    for, so `ot_modbus_unauthorized_write_ticketed.yml` fires INSTEAD of the
    HIGH rule -- same protocol observation, LOW severity, still indexed (see
    `is_incident()`: a LOW alert here is not counted as an incident). See
    this module's docstring for why this was a real FPR before the field
    existed, and why the fix only proves the downgrade mechanism, not
    real-world authorization.
    """
    sim = PLCSim(seed=seed)
    pump_frame = _write_pump_enable(sim, True, T_TUE_1030, _SRC_ENG)
    raw = [
        (_FRAME, _write_setpoint(sim, 520, T_TUE_1030, _SRC_ENG)),
        # The approved write's authorization ticket rides the envelope META
        # channel (never the frame bytes -- modbus_anomaly.py's trust
        # boundary, PR #80 review). run_pipeline (real WS-2 normalize_one)
        # forwards meta so the parser maps it to unmapped.ot.change_ticket_id.
        (_FRAME, pump_frame, {"changeTicketId": _MAINTENANCE_CHANGE_TICKET}),
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

# F2 (PR #80 review): the approved-maintenance-window write MUST still produce
# this LOW-severity alert -- it is the proof the downgrade mechanism is alive
# rather than a silent suppression. The gate fails if it is absent.
_TICKETED_RULE_ID = "bc313d43-588a-47e5-9f79-a4984ae1922c"
_MAINTENANCE_NAME = "approved-maintenance-window"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="negative_controls",
        description="WP-1-D: FPR source for the AI-to-OT twin (four negatives, "
                    "all must yield ZERO incidents AND scenario 1 must still "
                    "produce the LOW ticketed-downgrade alert).")
    parser.add_argument("--seed", type=int, default=1,
                        help="PLCSim RNG seed (same seed => same verdicts)")
    args = parser.parse_args(argv)

    results: list[tuple[str, list[dict]]] = []
    total_incidents = 0
    s1_alerts: list[dict] = []
    for scenario in _ALL_SCENARIOS:
        name, alerts = scenario(args.seed)
        results.append((name, alerts))
        if name == _MAINTENANCE_NAME:
            s1_alerts = alerts
        incidents = [a for a in alerts if is_incident(a)]
        explained = [a for a in alerts if not is_incident(a)]
        total_incidents += len(incidents)
        if not incidents:
            note = (f" ({len(explained)} low-severity ticketed alert(s), "
                     f"still indexed -- expected)" if explained else "")
            print(f"[OK]   {name} -- 0 incidents{note}")
        else:
            print(f"[FAIL] {name} -- {len(incidents)} incident(s):")
            for a in incidents:
                print(f"        - rule '{a['rule_title']}' fired "
                      f"on a {a['source_type']} event "
                      f"(id {a['rule_id']})")

    # F2 (PR #80 review): prove the downgrade mechanism is ALIVE, not silently
    # regressed to suppression. Scenario 1 must produce the LOW ticketed alert
    # (ot_modbus_unauthorized_write_ticketed). Zero alerts here passes the
    # incident count trivially -- exactly the regression a future silent-
    # suppression redesign would introduce -- so the gate FAILS on it.
    gate_failures = total_incidents
    if total_incidents == 0:
        s1_ticketed = [a for a in s1_alerts if a["rule_id"] == _TICKETED_RULE_ID]
        if not s1_ticketed:
            print("[FAIL] approved-maintenance-window produced no "
                  f"{_TICKETED_RULE_ID} (ot_modbus_unauthorized_write_ticketed) "
                  "alert -- the downgrade mechanism has silently regressed to "
                  "suppression. An approved ticketed write MUST still index a "
                  "LOW alert (see is_incident / SECURITY.md 12); zero alerts "
                  "is indistinguishable from a reverted design.")
            gate_failures += 1

    print("-" * 60)
    if gate_failures == 0:
        print(f"ZERO-INCIDENT SUMMARY: all {len(results)} negative scenarios "
              "produced 0 incidents -- FPR clean for the tested benign set. "
              "(A low-severity ticketed alert is not an incident -- see "
              "is_incident().) Scenario 1 also still emits the LOW ticketed "
              "downgrade alert, so the downgrade mechanism is proven alive.")
        return 0
    print(f"ZERO-INCIDENT SUMMARY: {total_incidents} incident(s) across "
          f"{len(results)} negative scenario(s) -- FALSE-POSITIVE FINDING; "
          "the honest FPR claim is NOT met until these are resolved.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
