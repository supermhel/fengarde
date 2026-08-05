"""Inventory-diff event parser.

v0.5 M7 Track Y: emits a synthetic OCSF Network Activity open event when the
inventory worker observes a previously unknown MAC/device on the OT segment.
This is intentionally minimal: the inventory worker owns the actual diff logic;
this parser only normalizes its notification into the shape the WS-4 engine
and existing anti-dormancy gates expect.

Raw bus payload ``raw`` is one inventory-diff notification, e.g. ::

    {"mac": "AA:BB:CC:DD:EE:FF", "ip": "10.20.0.77",
     "hostname": "plc-line4", "device_type": "plc",
     "sector": "ot", "seen_at": 1751500000000}
"""
from __future__ import annotations

from typing import Optional

from .base import Parser, SEV_INFO
from shared.ocsf import valid_ip


_CLASS_NETWORK = 4001   # Network Activity
_ACTIVITY_OPEN = 1      # OCSF Network Activity: Open


class InventoryDiffParser(Parser):
    SOURCE_TYPE = "inventory_diff"
    SECTOR = "datacenter"
    ORIGINAL_FORMAT = "json"
    PRODUCT = {"name": "Inventory diff worker", "vendor_name": "fengarde"}

    def parse(self, raw: dict) -> Optional[dict]:
        rec = raw.get("raw")
        if not isinstance(rec, dict):
            return None
        meta = raw.get("meta") or {}

        mac = rec.get("mac")
        ip = valid_ip(rec.get("ip") or meta.get("ip"))
        hostname = rec.get("hostname")
        device_type = rec.get("device_type")
        sector = rec.get("sector")

        if not mac or not ip:
            return None

        severity_id = SEV_INFO
        if sector == "ot":
            severity_id = 4  # High: new OT device is explicitly security-relevant

        message = f"New device {mac} ({device_type or 'unknown'}) on {ip}"
        event = self.base_event(
            class_uid=_CLASS_NETWORK,
            activity_id=_ACTIVITY_OPEN,
            severity_id=severity_id,
            time_ms=self._time_ms(rec, meta),
            ingest_id=meta.get("ingest_id"),
            logged_time=self._logged_time(rec, meta),
            status="Success",
            message=message,
            meta=meta,
            sector=self.resolve_sector(meta),
        )
        event["src_endpoint"] = {"ip": ip}
        if mac:
            event["src_endpoint"]["mac"] = mac
        if hostname:
            event["src_endpoint"]["hostname"] = hostname
        event["unmapped"] = {
            "ot": {
                "sector": sector or "",
                "device_type": device_type or "",
                "vendor": "",
                "hostname": hostname or "",
            }
        }
        return event

    @staticmethod
    def _time_ms(rec: dict, meta: dict) -> int:
        seen = rec.get("seen_at")
        if isinstance(seen, (int, float)):
            return int(seen)
        from .timeutil import to_epoch_ms
        return (to_epoch_ms(seen)
                or to_epoch_ms(meta.get("received_at"))
                or int(__import__("time").time() * 1000))

    @staticmethod
    def _logged_time(rec: dict, meta: dict) -> Optional[int]:
        from .timeutil import to_epoch_ms
        seen = rec.get("seen_at")
        if isinstance(seen, (int, float)):
            return int(seen)
        return to_epoch_ms(meta.get("received_at"))
