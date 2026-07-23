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
from shared.ocsf import valid_ip, valid_mac, safe_str

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
            event_id = int(str(rec.get("EventID")))
        except (TypeError, ValueError):
            return None
        if event_id not in _EVENT_MAP:
            return None
        activity_id, status, severity_id = _EVENT_MAP[event_id]

        time_ms = self._time_ms(rec, meta)
        # Structured-record parser: rec is attacker-controllable JSON, so any
        # field bound for a schema-constrained OCSF slot must be validated
        # before assignment (same M1 fix already applied to db_audit,
        # linux_ssh, mcp_agent, n8n_audit, opcua_audit, windows_eventlog --
        # this parser was the one missed). An unguarded int/list/dict here
        # would fail Contract A's endpoint pattern at validate() and
        # silently drop a real logon/failure event instead of crashing --
        # fail-closed, but on this bank-sector Authentication source that's
        # a missed brute-force/spray/lateral-movement detection, not just a
        # cosmetic issue.
        user = safe_str(rec.get("TargetUserName") or rec.get("SubjectUserName"))
        domain = safe_str(rec.get("TargetDomainName") or rec.get("SubjectDomainName"))
        ip = valid_ip(rec.get("IpAddress") or meta.get("ip"))
        host = safe_str(rec.get("WorkstationName") or rec.get("Computer"))
        mac = valid_mac(rec.get("MacAddress"))

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
            sector=self.resolve_sector(meta),
        )

        if ip or host or mac:
            sep: dict = {}
            if ip:
                sep["ip"] = ip
            if host:
                sep["hostname"] = host
            if mac:
                sep["mac"] = mac
            event["src_endpoint"] = sep

        if user:
            actor_user: dict = {"name": user}
            if domain:
                actor_user["domain"] = domain
            user_sid = rec.get("TargetUserSid")
            if user_sid:
                # str(), not safe_str(): a SID is schema-typed as a plain
                # string (no format pattern), same convention
                # windows_eventlog.py already uses for this exact field --
                # str() always produces a valid, schema-conformant value
                # (never raises) even for a wrong-typed input, so a
                # non-string TargetUserSid degrades to a stringified
                # representation rather than silently dropping the whole
                # actor/user block.
                actor_user["uid"] = str(user_sid)
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
