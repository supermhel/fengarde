"""Generic DB-audit parser: database audit events -> OCSF Datastore Activity (6005).

Un-dormants `contracts/rules/bank_db_priv_esc.yml`, which references class 6005 /
activity_id 5 but had NO real parser producing it (confirmed by
`tools/check_rule_producers.py` — the rule could pass every synthetic test yet
never fire on real data, the exact bug class flagged in
`contracts/detection-coverage.md`).

Vendor-agnostic: Oracle/SQL-Server/Postgres audit logs converge on the same
shape once shipped through a collector — {operation, object, user, host, ip,
timestamp}. A vendor-specific parser can be split out later without touching
this one (per-source isolation, `docs/adding-a-parser.md`).

Activity_id mapping (Contract A / ocsf-classes.md, Datastore Activity):
    1 Query, 2 Write, 3 Update, 4 Delete, 5 Privileged Op

Raw bus payload ``raw`` is a DB-audit event dict, e.g.::

    {"operation": "GRANT", "object": "customers", "user": "dba_svc",
     "host": "db-prod-01", "ipAddress": "10.4.4.9", "timestamp": 1750000100000}
"""
from __future__ import annotations

import json
import time
from typing import Optional

from .base import Parser, SEV_INFO, SEV_BY_CATEGORY, status_from_outcome
from shared.ocsf import valid_ip, safe_str

_CLASS = 6005  # Datastore Activity

# operation keyword -> (activity_id, severity). GRANT/ALTER/REVOKE are privileged
# ops (5) -- the class the bank_db_priv_esc rule targets. Severities come from
# the shared cross-source rubric (base.SEV_BY_CATEGORY, P2.2) so "delete a row"
# and "drop a table" both land as CRITICAL like vmware's delete/destroy does,
# not a source-specific MEDIUM that dodges the severity floor.
_OP_MAP = {
    "select": (1, SEV_BY_CATEGORY["read"]),
    "query": (1, SEV_BY_CATEGORY["read"]),
    "insert": (2, SEV_BY_CATEGORY["write"]),
    "write": (2, SEV_BY_CATEGORY["write"]),
    "update": (3, SEV_BY_CATEGORY["modify"]),
    "delete": (4, SEV_BY_CATEGORY["destroy"]),
    "drop": (4, SEV_BY_CATEGORY["destroy"]),
    "grant": (5, SEV_BY_CATEGORY["privilege"]),
    "revoke": (5, SEV_BY_CATEGORY["privilege"]),
    "alter": (5, SEV_BY_CATEGORY["privilege"]),
    "create user": (5, SEV_BY_CATEGORY["privilege"]),
}


class DbAuditParser(Parser):
    SOURCE_TYPE = "db_audit"
    SECTOR = "bank"
    ORIGINAL_FORMAT = "json"
    PRODUCT = {"name": "DB Audit", "vendor_name": "generic"}

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
        activity_id, severity_id = 1, SEV_INFO
        for kw, (aid, sev) in _OP_MAP.items():
            if kw in operation:
                activity_id, severity_id = aid, sev
                break

        time_ms = self._time_ms(rec, meta)
        user = rec.get("user") or rec.get("userName")
        db_object = rec.get("object") or rec.get("table")
        host = rec.get("host")
        src_ip = rec.get("ipAddress") or rec.get("ip") or meta.get("ip")

        verb = {1: "queried", 2: "wrote to", 3: "updated", 4: "deleted",
               5: "ran a privileged op on"}[activity_id]
        message = f"{rec.get('operation') or 'DB op'}: {user or '?'} {verb} " \
                  f"{db_object or 'database'}"

        event = self.base_event(
            class_uid=_CLASS,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=time_ms,
            ingest_id=meta.get("ingest_id"),
            logged_time=self._logged_time(rec, meta),
            status=status_from_outcome(rec),
            message=message,
            meta=meta,
            sector=self.resolve_sector(meta),
        )

        src_ip = valid_ip(src_ip)
        host = safe_str(host)
        if src_ip:
            event["src_endpoint"] = {"ip": src_ip}
        if host:
            event["dst_endpoint"] = {"hostname": host}
        user = safe_str(user)
        if user:
            event["actor"] = {"user": {"name": user}}

        return event

    @staticmethod
    def _time_ms(rec: dict, meta: dict) -> int:
        tc = rec.get("timestamp") or meta.get("received_at")
        if isinstance(tc, (int, float)):
            return int(tc * 1000) if tc < 1e12 else int(tc)
        return int(time.time() * 1000)

    @staticmethod
    def _logged_time(rec: dict, meta: dict) -> Optional[int]:
        lt = meta.get("received_at")
        if isinstance(lt, (int, float)):
            return int(lt * 1000) if lt < 1e12 else int(lt)
        return None
