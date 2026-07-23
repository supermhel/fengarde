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
"""
from __future__ import annotations

import time
from typing import Optional

from .base import Parser, SEV_HIGH, SEV_INFO, SEV_MEDIUM
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
        }}
        return event

    @staticmethod
    def _time_ms(rec: dict, meta: dict) -> int:
        ts = rec.get("time") or meta.get("received_at")
        if isinstance(ts, (int, float)) and not isinstance(ts, bool):
            return int(ts * 1000) if ts < 1e12 else int(ts)
        return int(time.time() * 1000)
