"""OPC UA audit-event parser: industrial control-system audit logs -> OCSF.

v0.4 Track P2 (OT/industrial wedge). OPC UA (IEC 62541) is the first OT
source, not S7/PROFINET: Part 5 of the spec defines a PUBLICLY documented,
structured audit-event model (AuditCreateSessionEventType,
AuditActivateSessionEventType, AuditCertificateEventType,
AuditWriteUpdateEventType, AuditUpdateMethodEventType) that a server exports
as a JSON audit-log line. S7/PROFINET telemetry is proprietary-shaped and
needs hardware access to fixture honestly -- deferred to a later release,
named here rather than silently dropped.

Fixtures in this module/its tests are SPEC-DERIVED (built from the OPC UA
Part 5 event field definitions), not captured from a live PLC/SCADA stack --
labeled as such per the honest-status convention. A design partner with a
real OPC UA server validates the shape later.

Mapping (Contract A / ocsf-classes.md):
    Session/activate/certificate audit events -> 3002 Authentication
        (activity 1 Logon / 2 Logoff, per the event's action)
    Write/method-call audit events            -> 6003 API Activity
        (activity 3 Update for a value write, 1 Create for a method call
         that provisions something new -- see _classify_api)

Raw bus payload ``raw`` is one JSON audit-log record, e.g.::

    {"eventType": "AuditWriteUpdateEventType", "sourceName": "Write",
     "clientUserId": "engineer01", "clientAddress": "10.20.0.15",
     "serverId": "plc-line3", "nodeId": "ns=2;s=Line3.SetpointTemp",
     "status": true, "time": 1751500000000}
"""
from __future__ import annotations

import json
import time
from typing import Optional

from .base import Parser, SEV_HIGH, SEV_INFO, SEV_MEDIUM, status_from_outcome

_CLASS_AUTH = 3002       # Authentication
_CLASS_API = 6003        # API Activity

# OPC UA Part 5 audit event types this parser recognizes.
_SESSION_EVENTS = {"AuditCreateSessionEventType", "AuditActivateSessionEventType"}
_CLOSE_EVENTS = {"AuditCloseSessionEventType"}
_CERT_EVENTS = {"AuditCertificateEventType", "AuditCertificateDataMismatchEventType",
                "AuditCertificateExpiredEventType", "AuditCertificateInvalidEventType"}
_WRITE_EVENTS = {"AuditWriteUpdateEventType", "AuditUpdateStateEventType"}
_METHOD_EVENTS = {"AuditUpdateMethodEventType"}

# Node-id patterns commonly used for configuration/firmware namespaces --
# a coarse heuristic (documented as such), consumed by ot_config_change.yml.
_CONFIG_NODE_MARKERS = ("Config", "Firmware", "Setpoint", "Parameter")


def _pick(rec: dict, *keys):
    for k in keys:
        if k in rec and rec[k] is not None:
            return rec[k]
    return None


class OpcUaAuditParser(Parser):
    SOURCE_TYPE = "opcua_audit"
    SECTOR = "datacenter"  # OT/industrial routes alongside the DC vertical for now
    ORIGINAL_FORMAT = "json"
    PRODUCT = {"name": "OPC UA Server", "vendor_name": "generic"}

    def parse(self, raw: dict) -> Optional[dict]:
        rec = raw.get("raw")
        if isinstance(rec, str):
            try:
                rec = json.loads(rec)
            except (ValueError, TypeError):
                return None
        if not isinstance(rec, dict):
            return None
        meta = raw.get("meta") or {}

        event_type = _pick(rec, "eventType", "EventType")
        if not event_type:
            return None

        if event_type in _SESSION_EVENTS or event_type in _CLOSE_EVENTS or event_type in _CERT_EVENTS:
            return self._auth_event(rec, meta, event_type)
        if event_type in _WRITE_EVENTS or event_type in _METHOD_EVENTS:
            return self._api_event(rec, meta, event_type)
        return None  # an OPC UA audit event type we don't model yet

    # -- session/certificate audit -> Authentication ------------------------
    def _auth_event(self, rec: dict, meta: dict, event_type: str) -> dict:
        user = _pick(rec, "clientUserId", "userId")
        client_ip = _pick(rec, "clientAddress", "clientIp") or meta.get("ip")
        server_id = _pick(rec, "serverId", "server")
        # Robust outcome parse: a string "false" or 4xx code is a Failure; naive
        # bool(_pick(...)) treated any non-empty value as truthy -> Success.
        status_ok = status_from_outcome(rec, keys=("status", "success")) == "Success"

        if event_type in _CLOSE_EVENTS:
            activity_id, severity_id = 2, SEV_INFO
        else:
            activity_id = 1
            severity_id = SEV_INFO if status_ok else SEV_HIGH
        if event_type in _CERT_EVENTS:
            severity_id = SEV_HIGH if not status_ok else SEV_MEDIUM

        message = f"OPC UA {event_type} for {user or 'unknown client'} on {server_id or 'server'}"
        event = self.base_event(
            class_uid=_CLASS_AUTH,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=self._time_ms(rec, meta),
            ingest_id=meta.get("ingest_id"),
            logged_time=self._logged_time(rec, meta),
            status="Success" if status_ok else "Failure",
            message=message,
            sector=self.resolve_sector(meta),
        )
        if client_ip:
            event["src_endpoint"] = {"ip": client_ip}
        if user:
            event["actor"] = {"user": {"name": user}}
        event["unmapped"] = {"ot": {"server_id": server_id, "event_type": event_type}}
        return event

    # -- write/method-call audit -> API Activity -----------------------------
    def _api_event(self, rec: dict, meta: dict, event_type: str) -> dict:
        user = _pick(rec, "clientUserId", "userId")
        client_ip = _pick(rec, "clientAddress", "clientIp") or meta.get("ip")
        server_id = _pick(rec, "serverId", "server")
        node_id = _pick(rec, "nodeId", "targetNodeId") or ""
        status_ok = status_from_outcome(rec, keys=("status", "success")) == "Success"

        activity_id = 1 if event_type in _METHOD_EVENTS else 3  # Create : Update
        is_config = any(marker.lower() in str(node_id).lower() for marker in _CONFIG_NODE_MARKERS)
        severity_id = SEV_HIGH if is_config else SEV_MEDIUM

        message = f"OPC UA {event_type} on {node_id or 'unknown node'} by {user or 'unknown client'}"
        event = self.base_event(
            class_uid=_CLASS_API,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=self._time_ms(rec, meta),
            ingest_id=meta.get("ingest_id"),
            logged_time=self._logged_time(rec, meta),
            status="Success" if status_ok else "Failure",
            message=message,
            sector=self.resolve_sector(meta),
        )
        event["api"] = {"operation": event_type}
        if client_ip:
            event["src_endpoint"] = {"ip": client_ip}
        if user:
            event["actor"] = {"user": {"name": user}}
        event["unmapped"] = {"ot": {
            "server_id": server_id, "node_id": node_id,
            "device_type": "plc", "is_config_node": is_config,
        }}
        return event

    @staticmethod
    def _time_ms(rec: dict, meta: dict) -> int:
        ts = rec.get("time") or rec.get("timestamp") or meta.get("received_at")
        if isinstance(ts, (int, float)):
            return int(ts * 1000) if ts < 1e12 else int(ts)
        return int(time.time() * 1000)

    @staticmethod
    def _logged_time(rec: dict, meta: dict) -> Optional[int]:
        lt = meta.get("received_at")
        if isinstance(lt, (int, float)):
            return int(lt * 1000) if lt < 1e12 else int(lt)
        return None
