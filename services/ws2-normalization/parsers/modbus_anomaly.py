"""Modbus/TCP protocol-anomaly detector -> OCSF.

v0.5 M7 Track X (2026-07-22): the second OT source, deliberately scoped
DIFFERENTLY from `opcua_audit.py`. Read this before adding a third.

**This is NOT a vendor audit-log parser.** OPC UA and (deferred) S7/PROFINET
are judged on whether a vendor publishes a structured, documented AUDIT-EVENT
format -- OPC UA does (Part 5), S7's event *vocabulary* doesn't (access-
gated, see `docs/superpowers/specs/2026-07-21-s7-profinet-decision-gate.md`).
Modbus/TCP (Modbus Application Protocol Specification V1.1b3, a fully public,
no-login-required spec) has NO audit-event format at all -- it is a bare
request/response control protocol with no concept of "this write was
authorized." Claiming to "parse Modbus vendor logs" would be exactly the
fabricated-fixture trap the S7 doc warns against, because no such vendor log
exists to parse.

What this module does instead: classify one OBSERVED Modbus/TCP frame (as a
tap or protocol-aware proxy would report it -- function code, address,
unit id, not raw MBAP bytes, which is a wire-parsing job out of scope for a
WS-2 normalization parser) against the PUBLIC function-code table for
protocol-level anomalies: an exception response (the spec's own error
signal), a function code outside the documented standard table, or a WRITE
function code targeting an address outside a small, explicitly-declared
"expected safe" range -- the same kind of coarse, documented heuristic
`opcua_audit.py`'s `_CONFIG_NODE_MARKERS` already uses, not real per-device
knowledge this repo doesn't have. Every frame (anomalous or not) still
becomes a normal OCSF Network Activity event; `unmapped.ot.anomaly_type` is
what a rule keys on.

Function-code table source: Modbus Application Protocol V1.1b3 §6 (public,
modbus.org). Exception responses are function_code | 0x80 per §7.

Raw bus payload ``raw`` is one observed-frame record, e.g.::

    {"unitId": 1, "functionCode": 6, "address": 40001, "value": 500,
     "sourceIp": "10.20.0.50", "destIp": "10.20.0.5", "time": 1751500000000}

**Authorization context (optional ``changeTicketId``).** The wire protocol
itself carries no such concept -- this field is a deliberate, explicit,
OUT-OF-BAND signal a real tap or protocol-aware proxy could attach when it
also has access to a change-management/ticketing system (e.g. it correlates
the write's source IP + time window against an open, approved change
ticket). Present and non-blank on the **envelope's ``meta`` channel**, it
maps straight through to ``unmapped.ot.change_ticket_id`` -- this parser
does NOT validate the ticket against any real ticketing system (it has none
to check), so it neither changes ``anomaly_type`` nor ``severity_id``: the
write is still, honestly, an out-of-range write at the protocol level. It
exists so `contracts/rules/ot_modbus_unauthorized_write.yml` DOWNGRADES
rather than suppresses when a ticket is attached:
`ot_modbus_unauthorized_write_ticketed.yml` fires instead, at LOW severity
-- the event still reaches the index, it is never silently dropped. See
eval/twin/negative_controls.py ::scenario_maintenance_window for how the
twin proves the downgrade mechanism works on simulated data -- that is not
a claim this solves real-world OT change-authorization. **Trust boundary
(load-bearing, PR #80 review):** the ticket is read ONLY from the transport
envelope's ``meta`` channel, NEVER from the frame record (``raw.raw``) --
the frame is the wire/tap channel, and anything an attacker with write
access to the bus could also set must never move a write from HIGH to LOW.
A ``changeTicketId`` inside the frame bytes is ignored by this parser. A
conservative shape check (``_valid_ticket_id``) rejects blank/junk values,
and every accepted ticket is surfaced with
``unmapped.ot.change_ticket_unvalidated: true`` so consumers can see it is
an unauthenticated claim. It must come from a source independent of the
observed Modbus frame -- never from frame bytes, never from anything an
attacker with write access to the bus could also set. See SECURITY.md.
"""
from __future__ import annotations

import re
import time
from typing import Optional

from .base import Parser, SEV_HIGH, SEV_INFO, SEV_MEDIUM
from .timeutil import to_epoch_ms
from shared.ocsf import valid_ip

_CLASS_NETWORK = 4001    # Network Activity
_ACTIVITY_TRAFFIC = 6    # OCSF Network Activity: Traffic

# Modbus Application Protocol V1.1b3 Table 5/6 -- the full public standard
# function-code table (excludes vendor-specific 65-72/100-110, which are
# legitimately unknown to a generic tap and NOT flagged as anomalous on
# their own -- only genuinely undefined/reserved codes are).
_KNOWN_FUNCTION_CODES = frozenset({
    1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 15, 16, 17, 20, 21, 22, 23, 24, 43,
})
_WRITE_FUNCTION_CODES = frozenset({5, 6, 15, 16})  # single/multi coil/register writes
_VENDOR_SPECIFIC_RANGE = range(65, 73)  # 65-72, and 100-110 below

# A small, DOCUMENTED-as-a-heuristic "expected to be written" address range
# (e.g. a heartbeat/watchdog register block) -- coarse and explicit, the same
# spirit as opcua_audit.py's _CONFIG_NODE_MARKERS. A real deployment would
# override this via its own allowlist; this repo has no live PLC to derive
# one from, so the default is deliberately narrow (fails toward flagging,
# not toward silence).
_EXPECTED_WRITE_ADDRESSES = range(40001, 40010)

# PR #80 review (2026-08-28): the change-ticket authorization signal is a
# TRUST-BOUNDARY-enforced field. It is read ONLY from the transport envelope's
# ``meta`` channel -- never from the frame record (``raw.raw``). The frame
# record is what the Modbus wire/tap bytes produce, and anything an attacker
# with write access to the wire could also control must never be able to move
# a HIGH alert to LOW (the rules' and SECURITY.md 12's own documented
# requirement: the ticket must come from a source independent of the observed
# wire). A ``changeTicketId`` inside the frame bytes is attacker data and is
# deliberately ignored.
#
# A conservative SHAPE check still applies (a ticket id looks like
# "<PREFIX>-<reference>", e.g. CHG-2026-08-1042): accidental junk or a blank
# value never downgrades. This is a shape check only -- NOT authentication
# against any real ticketing system (there is none in this repo to check) --
# so a value that passes here is still an unauthenticated claim, surfaced as
# ``unmapped.ot.change_ticket_unvalidated: true`` on the event.
_TICKET_ID_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{2,63}")


def _valid_ticket_id(value) -> Optional[str]:
    """Return the ticket id if ``value`` is a non-blank, ticket-shaped string,
    else None (no authorization claim). Independent of the frame record --
    callers decide the channel (meta only)."""
    if not isinstance(value, str):
        return None
    ticket = value.strip()
    if not (4 <= len(ticket) <= 64):
        return None
    if _TICKET_ID_RE.fullmatch(ticket) is None:
        return None
    if not any(ch.isdigit() for ch in ticket):
        return None
    return ticket


def _classify(function_code: int, address: Optional[int]) -> Optional[str]:
    if function_code & 0x80:
        return "exception_response"
    if function_code not in _KNOWN_FUNCTION_CODES and function_code not in _VENDOR_SPECIFIC_RANGE \
            and function_code not in range(100, 111):
        return "unknown_function_code"
    if function_code in _WRITE_FUNCTION_CODES:
        if address is None or address not in _EXPECTED_WRITE_ADDRESSES:
            return "unauthorized_write"
    return None


class ModbusAnomalyParser(Parser):
    SOURCE_TYPE = "modbus_anomaly"
    SECTOR = "datacenter"  # OT/industrial routes alongside the DC vertical, same as opcua_audit
    ORIGINAL_FORMAT = "api"  # observed-frame report from a tap/proxy, not a log line
    PRODUCT = {"name": "Modbus/TCP tap", "vendor_name": "generic"}

    def parse(self, raw: dict) -> Optional[dict]:
        rec = raw.get("raw")
        if not isinstance(rec, dict):
            return None
        meta = raw.get("meta") or {}

        function_code = rec.get("functionCode")
        if not isinstance(function_code, int) or isinstance(function_code, bool):
            return None  # a frame with no function code isn't a Modbus frame

        address = rec.get("address")
        if not isinstance(address, int) or isinstance(address, bool):
            address = None
        anomaly = _classify(function_code, address)

        src_ip = valid_ip(rec.get("sourceIp") or meta.get("ip"))
        dst_ip = valid_ip(rec.get("destIp"))
        unit_id = rec.get("unitId")

        change_ticket_id = None
        # Trust boundary (PR #80 review): read the authorization claim ONLY
        # from the envelope's meta channel. The frame record (``rec``) is the
        # wire/tap channel -- a changeTicketId placed there is attacker data
        # and must never downgrade this event (see module docstring above).
        if isinstance(meta, dict):
            change_ticket_id = _valid_ticket_id(
                meta.get("changeTicketId") or meta.get("change_ticket_id"))

        severity_id = SEV_INFO if anomaly is None else {
            "unauthorized_write": SEV_HIGH,
            "exception_response": SEV_MEDIUM,
            "unknown_function_code": SEV_MEDIUM,
        }.get(anomaly, SEV_INFO)

        message = f"Modbus/TCP function {function_code} unit {unit_id}" + (
            f" address {address}" if address is not None else "") + (
            f" -- {anomaly}" if anomaly else "")

        event = self.base_event(
            class_uid=_CLASS_NETWORK,
            activity_id=_ACTIVITY_TRAFFIC,
            severity_id=severity_id,
            time_ms=self._time_ms(rec, meta),
            ingest_id=meta.get("ingest_id"),
            status="Success",
            message=message,
            meta=meta,
            sector=self.resolve_sector(meta),
        )
        if src_ip:
            event["src_endpoint"] = {"ip": src_ip}
        if dst_ip:
            event["dst_endpoint"] = {"ip": dst_ip}
        event["unmapped"] = {"ot": {
            "protocol": "modbus_tcp", "function_code": function_code,
            "address": address, "unit_id": unit_id, "anomaly_type": anomaly,
            "change_ticket_id": change_ticket_id,
        }}
        if change_ticket_id is not None:
            # PR #80 review: surface that the downgrade rests on an
            # UNAUTHENTICATED claim (no ticketing system validates it) so no
            # consumer mistakes a ticket-shaped string for verified
            # authorization. Rules key on change_ticket_id only; this marker
            # is informational honesty, never a selection input.
            event["unmapped"]["ot"]["change_ticket_unvalidated"] = True
        return event

    @staticmethod
    def _time_ms(rec: dict, meta: dict) -> int:
        return (to_epoch_ms(rec.get("time"))
                or to_epoch_ms(meta.get("received_at"))
                or int(time.time() * 1000))
