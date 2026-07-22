"""AWS CloudTrail parser: management/data-event records -> OCSF.

v0.5 Track A4 (first cloud-control-plane producer). CloudTrail's JSON record
shape is publicly documented (https://docs.aws.amazon.com/awscloudtrail/latest/
userguide/cloudtrail-event-reference-record-contents.html) -- fixtures here
are spec-derived, same discipline as opcua_audit.py/k8s_audit.py, not captured
from a real AWS account.

Mapping (Contract A / ocsf-classes.md):
    eventName == "ConsoleLogin"  -> 3002 Authentication, activity_id 1 Logon,
        status from responseElements.ConsoleLogin (Success/Failure).
    every other eventName        -> 6003 API Activity, activity_id from a
        verb-prefix heuristic on eventName (Create/Put/Run->1, Describe/Get/
        List->2, Update/Modify/Attach->3, Delete/Terminate/Remove->4,
        default 2).

``unmapped.cloud.identity_type``/``mfa_used`` carry userIdentity.type and
additionalEventData.MFAUsed straight through -- consumed by
contracts/rules/cloud_root_console_login.yml (root login, no MFA).
"""
from __future__ import annotations

import time
from typing import Optional

from .base import Parser, SEV_BY_CATEGORY, SEV_HIGH, SEV_INFO, status_from_outcome
from shared.ocsf import valid_ip

_CLASS_AUTH = 3002
_CLASS_API = 6003

_PREFIX_TO_ACTIVITY = [
    (("Create", "Put", "Run", "Add", "Register"), 1, "write"),
    (("Describe", "Get", "List", "Head"), 2, "read"),
    (("Update", "Modify", "Attach", "Set"), 3, "modify"),
    (("Delete", "Terminate", "Remove", "Detach"), 4, "destroy"),
]


def _classify_api(event_name: str):
    for prefixes, activity_id, category in _PREFIX_TO_ACTIVITY:
        if event_name.startswith(prefixes):
            return activity_id, SEV_BY_CATEGORY[category]
    return 2, SEV_BY_CATEGORY["read"]


class CloudTrailParser(Parser):
    SOURCE_TYPE = "cloudtrail"
    SECTOR = "common"
    ORIGINAL_FORMAT = "json"
    PRODUCT = {"name": "AWS CloudTrail", "vendor_name": "Amazon Web Services"}

    def parse(self, raw: dict) -> Optional[dict]:
        rec = raw.get("raw")
        if not isinstance(rec, dict):
            return None
        meta = raw.get("meta") or {}

        event_name = str(rec.get("eventName") or "")
        if not event_name:
            return None
        user_identity = rec.get("userIdentity") if isinstance(rec.get("userIdentity"), dict) else {}

        if event_name == "ConsoleLogin":
            response = rec.get("responseElements") if isinstance(rec.get("responseElements"), dict) else {}
            status = status_from_outcome(response, keys=("ConsoleLogin",))
            activity_id = 1
            severity_id = SEV_INFO if status == "Success" else SEV_HIGH
            class_uid = _CLASS_AUTH
        else:
            activity_id, severity_id = _classify_api(event_name)
            status = "Success"  # CloudTrail records the call was made; errorCode (if any) below
            if rec.get("errorCode"):
                status = "Failure"
            class_uid = _CLASS_API

        event = self.base_event(
            class_uid=class_uid,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=self._time_ms(rec, meta),
            ingest_id=meta.get("ingest_id") or rec.get("eventID"),
            status=status,
            message=f"CloudTrail {event_name} ({rec.get('eventSource', '?')})",
            meta=meta,
            sector=self.resolve_sector(meta),
        )

        arn_or_account = user_identity.get("arn") or user_identity.get("accountId")
        if arn_or_account:
            event["actor"] = {"user": {"name": arn_or_account}}

        src_ip = rec.get("sourceIPAddress")
        if valid_ip(src_ip):
            event["src_endpoint"] = {"ip": src_ip}

        additional = rec.get("additionalEventData") if isinstance(rec.get("additionalEventData"), dict) else {}
        event["unmapped"] = {
            "cloud": {
                "identity_type": user_identity.get("type"),
                "mfa_used": additional.get("MFAUsed"),
                "event_source": rec.get("eventSource"),
            }
        }
        return event

    @staticmethod
    def _time_ms(rec: dict, meta: dict) -> int:
        ts = rec.get("eventTime")
        if isinstance(ts, str) and ts:
            from .timeutil import to_epoch_ms
            parsed = to_epoch_ms(ts)
            if parsed is not None:
                return parsed
        ra = meta.get("received_at")
        if isinstance(ra, (int, float)):
            return int(ra * 1000) if ra < 1e12 else int(ra)
        return int(time.time() * 1000)
