"""VMware vSphere parser: hypervisor API events -> OCSF API Activity (6003).

Maps vCenter task/event operations to API Activity activity_ids
(Contract A / ocsf-classes.md):

    1 Create, 2 Read, 3 Update, 4 Delete

Raw bus payload ``raw`` is a vCenter event dict, e.g.::

    {"operation": "VM.Delete", "vm": "prod-db-07", "userName": "svc_orchestrator",
     "host": "vcenter-01", "ipAddress": "172.16.5.9", "createdTime": 1750000100000}
"""
from __future__ import annotations

import json
import time
from typing import Optional

from .base import Parser, SEV_INFO, SEV_BY_CATEGORY, status_from_outcome

_CLASS = 6003  # API Activity


def _safe_int(value):
    """int() that never raises on hostile input (list/dict/non-numeric string).
    A bad ``port`` in an attacker-shaped vCenter record must not crash parse()
    and abort the whole normalization batch -- drop the field instead."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None

# operation keyword -> (activity_id, severity), severity from the shared
# cross-source rubric (base.SEV_BY_CATEGORY, P2.2).
_OP_MAP = {
    "create": (1, SEV_BY_CATEGORY["write"]),
    "deploy": (1, SEV_BY_CATEGORY["write"]),
    "read": (2, SEV_BY_CATEGORY["read"]),
    "get": (2, SEV_BY_CATEGORY["read"]),
    "update": (3, SEV_BY_CATEGORY["modify"]),
    "reconfig": (3, SEV_BY_CATEGORY["modify"]),
    "delete": (4, SEV_BY_CATEGORY["destroy"]),
    "destroy": (4, SEV_BY_CATEGORY["destroy"]),
    "remove": (4, SEV_BY_CATEGORY["destroy"]),
}


class VmwareVsphereParser(Parser):
    SOURCE_TYPE = "vmware_vsphere"
    SECTOR = "datacenter"
    ORIGINAL_FORMAT = "api"
    PRODUCT = {"name": "vSphere", "vendor_name": "VMware"}

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

        operation = (rec.get("operation") or "").lower()
        activity_id, severity_id = 2, SEV_INFO
        for kw, (aid, sev) in _OP_MAP.items():
            if kw in operation:
                activity_id, severity_id = aid, sev
                break

        time_ms = self._time_ms(rec, meta)
        user = rec.get("userName") or rec.get("user")
        vm = rec.get("vm") or rec.get("target")
        src_ip = rec.get("ipAddress") or meta.get("ip")
        src_host = rec.get("host")

        verb = {1: "created", 2: "read", 3: "updated", 4: "deleted"}[activity_id]
        message = f"{rec.get('operation') or 'API op'}: {vm or '?'} {verb} by {user or '?'}"

        event = self.base_event(
            class_uid=_CLASS,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=time_ms,
            ingest_id=meta.get("ingest_id"),
            logged_time=self._logged_time(rec, meta),
            status=status_from_outcome(rec),
            message=message,
            sector=self.resolve_sector(meta),
        )

        if src_ip or src_host:
            sep: dict = {}
            if src_ip:
                sep["ip"] = src_ip
            if src_host:
                sep["hostname"] = src_host
            port = _safe_int(rec.get("port"))
            if port is not None:
                sep["port"] = port
            event["src_endpoint"] = sep
        if vm:
            event["dst_endpoint"] = {"hostname": vm}
        if user:
            event["actor"] = {"user": {"name": user}}

        return event

    @staticmethod
    def _time_ms(rec: dict, meta: dict) -> int:
        tc = rec.get("createdTime") or meta.get("received_at")
        if isinstance(tc, (int, float)):
            return int(tc * 1000) if tc < 1e12 else int(tc)
        return int(time.time() * 1000)

    @staticmethod
    def _logged_time(rec: dict, meta: dict) -> Optional[int]:
        lt = meta.get("received_at")
        if isinstance(lt, (int, float)):
            return int(lt * 1000) if lt < 1e12 else int(lt)
        return None
