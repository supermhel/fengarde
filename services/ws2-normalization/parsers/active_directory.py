"""Active Directory parser: Windows Event Log -> OCSF Authentication (3002).

Maps Windows Security event IDs to Authentication activity_ids
(Contract A / ocsf-classes.md):

    4624 successful logon  -> activity_id 1 (Logon),   status Success
    4634 logoff            -> activity_id 2 (Logoff),  status Success
    4625 failed logon      -> activity_id 4 (Failure), status Failure

Raw bus payload ``raw`` is the parsed winevent record as a dict, e.g.::

    {"EventID": 4625, "TimeCreated": 1750000000000,
     "TargetUserName": "jdoe", "TargetDomainName": "BANKCORP",
     "IpAddress": "10.20.30.40", "WorkstationName": "wks-jdoe"}
"""
from __future__ import annotations

import json
import time
from typing import Optional

from .base import Parser, SEV_HIGH, SEV_INFO
from .timeutil import to_epoch_ms

_CLASS = 3002  # Authentication

# Windows Security EventID -> (activity_id, status, severity)
_EVENT_MAP = {
    4624: (1, "Success", SEV_INFO),   # Logon
    4634: (2, "Success", SEV_INFO),   # Logoff
    4647: (2, "Success", SEV_INFO),   # User-initiated logoff
    4625: (4, "Failure", SEV_HIGH),   # Failed logon
    4768: (3, "Success", SEV_INFO),   # Kerberos TGT requested (Auth Ticket)
    4771: (4, "Failure", SEV_HIGH),   # Kerberos pre-auth failed
}


class ActiveDirectoryParser(Parser):
    SOURCE_TYPE = "active_directory"
    SECTOR = "bank"
    ORIGINAL_FORMAT = "winevent"
    PRODUCT = {"name": "Active Directory", "vendor_name": "Microsoft"}

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

        try:
            event_id = int(rec.get("EventID"))
        except (TypeError, ValueError):
            return None
        if event_id not in _EVENT_MAP:
            return None
        activity_id, status, severity_id = _EVENT_MAP[event_id]

        time_ms = self._time_ms(rec, meta)
        user = rec.get("TargetUserName") or rec.get("SubjectUserName")
        domain = rec.get("TargetDomainName") or rec.get("SubjectDomainName")
        ip = rec.get("IpAddress") or meta.get("ip")
        host = rec.get("WorkstationName") or rec.get("Computer")

        verb = {1: "Logon", 2: "Logoff", 3: "Auth ticket", 4: "Failed logon"}[activity_id]
        message = f"{verb} for user {user or '?'}"
        if ip:
            message += f" from {ip}"

        event = self.base_event(
            class_uid=_CLASS,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=time_ms,
            ingest_id=meta.get("ingest_id"),
            logged_time=self._logged_time(rec, meta),
            status=status,
            message=message,
            meta=meta,
        )

        if ip or host:
            sep: dict = {}
            if ip:
                sep["ip"] = ip
            if host:
                sep["hostname"] = host
            if rec.get("MacAddress"):
                sep["mac"] = rec["MacAddress"]
            event["src_endpoint"] = sep

        if user:
            actor_user: dict = {"name": user}
            if domain:
                actor_user["domain"] = domain
            if rec.get("TargetUserSid"):
                actor_user["uid"] = rec["TargetUserSid"]
            event["actor"] = {"user": actor_user}

        return event

    @staticmethod
    def _time_ms(rec: dict, meta: dict) -> int:
        # TimeCreated may be epoch s/ms, an ISO-8601 string, or a Windows FILETIME
        # -- to_epoch_ms handles all three (the old int-only check turned an ISO
        # string into now() and a FILETIME into a year-33000 timestamp).
        return (to_epoch_ms(rec.get("TimeCreated"))
                or to_epoch_ms(meta.get("received_at"))
                or int(time.time() * 1000))

    @staticmethod
    def _logged_time(rec: dict, meta: dict) -> Optional[int]:
        return to_epoch_ms(meta.get("received_at"))
