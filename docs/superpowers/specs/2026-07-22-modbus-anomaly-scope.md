# Modbus/TCP: protocol-anomaly detector, not a vendor-log parser (M7, 2026-07-22)

## Context

SSOT.md's M7 forward-roadmap row lists "OT expansion" as a continuous
track. `opcua_audit.py` is the only OT source so far (v0.4 Track P2); S7/
PROFINET stays deferred on a real access gap (Siemens support login,
`docs/superpowers/specs/2026-07-21-s7-profinet-decision-gate.md`). This doc
records why Modbus/TCP was picked as the next OT source, and — this is the
part worth reading before adding a third — why its parser is shaped
differently from every other parser in this repo.

## The scope boundary

Every other parser in `services/ws2-normalization/parsers/` converts a
**vendor-published, structured audit-log format** into OCSF: Windows Event
Log, OPC UA's Part 5 audit events, AWS CloudTrail, etc. Modbus/TCP (Modbus
Application Protocol Specification V1.1b3, fully public, no vendor login
required) has **no audit-log format at all** — it is a bare request/response
control protocol. There is no vendor log to "parse" honestly; a module
claiming to do so would be fabricating a source, exactly the failure mode
`docs/superpowers/specs/2026-07-21-s7-profinet-decision-gate.md` warns
against for S7.

`modbus_anomaly.py` is scoped instead as a **protocol-anomaly detector**: it
classifies one *observed* Modbus/TCP frame (function code, address, unit
id — as a tap or protocol-aware proxy would report it, not raw MBAP bytes,
which is a wire-parsing job out of scope for a WS-2 normalization parser)
against the protocol's own public function-code table. Three anomaly
classes, all derivable from the spec alone:

- `exception_response` — the protocol's own error signal (function code |
  0x80), always meaningful.
- `unknown_function_code` — a code outside the documented standard AND
  vendor-specific-reserved ranges (65-72, 100-110 are correctly left
  unflagged — the spec itself says these are legitimately vendor-defined,
  not a violation).
- `unauthorized_write` — a write function code (05/06/15/16) to an address
  outside a small, explicitly declared "expected safe" range
  (`_EXPECTED_WRITE_ADDRESSES`). This is a coarse heuristic, the same shape
  as `opcua_audit.py`'s `_CONFIG_NODE_MARKERS` — not real per-device
  knowledge this repo doesn't have. A real deployment overrides the range;
  this repo's default is deliberately narrow (fails toward flagging traffic,
  never toward silent pass-through).

Every observed frame — anomalous or not — still becomes a normal OCSF
Network Activity (4001) event. `unmapped.ot.anomaly_type` is what
`ot_modbus_unauthorized_write.yml` keys on (single-shot, MITRE ATT&CK for
ICS T0855 "Unauthorized Command Message" / TA0106 "Impair Process Control").

## What this does NOT claim

- Not a claim that any specific address range is actually safe on a real
  plant floor — that's a per-deployment config decision, not something this
  repo can know.
- Not a replacement for a real Modbus intrusion-detection system that
  tracks legitimate read/write sequences per PLC; this is a coarse, spec-
  derived first pass, same honesty discipline as every other heuristic-
  based rule in this repo (`agent_credential_file_access.yml`, etc.).
- Not evidence this was tested against a real PLC or Modbus tap. Fixtures in
  `test_modbus_anomaly.py` are protocol-spec-derived (built from the public
  function-code table), same convention `opcua_audit.py`'s own fixtures
  already use and label explicitly.

## Verification

`tools/check_rule_producers.py`'s anti-dormancy gate proves
`ot_modbus_unauthorized_write.yml` has a real producer;
`eval/attack/fire_check.py` proves it actually fires on that fixture (see
`docs/superpowers/specs/2026-07-22-mitre-fire-check.md`).
