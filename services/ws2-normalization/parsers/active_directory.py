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


def _hostname(value) -> Optional[str]:
    """WorkstationName -> src_endpoint.hostname, treating Windows's literal
    ``'-'`` (what NTLM/network logons log when there is no interactive
    workstation) as ABSENT.

    2026-08-26 gap-hunt finding: ``safe_str(rec.get("WorkstationName") or
    rec.get("Computer"))`` let '-' through -- it's a truthy, non-empty string,
    so the ``or Computer`` fallback never fired and every such event was
    grouped under src_endpoint.hostname='-'. Downstream,
    common_bruteforce_sourceless treated '-' as a real host (a permanently
    firing noise bucket), and because the coordinated-attack rules key their
    deterministic alert_id on src_endpoint.hostname, all of those events
    collided on one idempotent alert -- hiding brute-forces inside a bucket
    seeded by legitimately different workstations. Empty/None are covered by
    ``safe_str``; '-' (and its whitespace-wrapped variants) is the case the
    ``or`` chain missed."""
    v = safe_str(value)
    return None if v is None or v.strip() in ("", "-") else v


# PR #153 review: a 4625 without any named event data (Fluent Bit without
# event_data_as_map, StringInserts only, EventData as a list) used to
# normalize into a hollow event (no user, no IP, victim host as source).
# Without one of these keys there is nothing to attribute, so it is dropped
# (dead-lettered by the pipeline) instead of being counted silently.
_NAMED_DATA_KEYS = ("TargetUserName", "SubjectUserName", "IpAddress", "WorkstationName",
                    "TargetDomainName", "TargetUserSid")


# Microsoft's 4625 template order (positional StringInserts, what Fluent Bit's winevtlog emits without
# event_data_as_map). Used ONLY when the record carries no named event data at all.
_4625_INSERTS = ("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
                 "TargetUserSid", "TargetUserName", "TargetDomainName", "Status", "FailureReason",
                 "SubStatus", "LogonType", "LogonProcessName", "AuthenticationPackageName",
                 "WorkstationName", "TransmittedServices", "LmPackageName", "KeyLength",
                 "ProcessId", "ProcessName", "IpAddress", "IpPort")
_MIN_4625_INSERTS = 6  # through TargetUserName; fewer is too short to attribute anything

#: SIDs that mean "no account" (S-1-0-0 is the null SID Windows logs when the target is unknown).
_NULL_SIDS = ("", "-", "S-1-0-0")


def _positional_4625(rec: dict) -> Optional[dict]:
    ins = rec.get("StringInserts")
    if not isinstance(ins, (list, tuple)) or len(ins) < _MIN_4625_INSERTS:
        return None
    named = {k: v for k, v in zip(_4625_INSERTS, ins) if isinstance(v, (str, int)) and not isinstance(v, bool)}
    return dict(rec, **{k: v for k, v in named.items() if k not in rec})


def _event_id(value) -> Optional[int]:
    """EventID as int; integral floats/strings ("4625.0") count, others not."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(str(value))
    except (TypeError, ValueError):
        pass
    try:
        f = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return int(f) if f.is_integer() else None


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

        event_id = _event_id(rec.get("EventID"))
        if event_id not in _EVENT_MAP:
            return None
        if not any(k in rec for k in _NAMED_DATA_KEYS):
            rec = _positional_4625(rec) if event_id == 4625 else None
            if rec is None:
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
        # PR #153 review: '-' is Windows's "no value" (same as _hostname), and
        # a FAILED logon must never fall back to SubjectUserName -- that is the
        # requesting process (usually the machine account, e.g. WIN11-LAB$),
        # not the account that failed, so the failure was misattributed.
        user = _hostname(rec.get("TargetUserName"))
        domain = _hostname(rec.get("TargetDomainName"))
        if user is None and activity_id != 4:
            user = _hostname(rec.get("SubjectUserName"))
            domain = domain or _hostname(rec.get("SubjectDomainName"))
        ip = valid_ip(rec.get("IpAddress") or meta.get("ip"))
        host = _hostname(rec.get("WorkstationName")) or _hostname(rec.get("Computer"))
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

        # gap-hunt R4-136: a logon's TARGET host (the machine the event was logged on) is the destination, as
        # windows_eventlog.py already maps it; without it the lateral-movement rules could never count AD logons.
        # src_endpoint.hostname is left exactly as before (WorkstationName, falling back to Computer) because
        # common_bruteforce_sourceless depends on that fallback.
        target_host = _hostname(rec.get("Computer"))
        if target_host:
            event["dst_endpoint"] = {"hostname": target_host}

        if user:
            actor_user: dict = {"name": user}
            if domain:
                actor_user["domain"] = domain
            user_sid = rec.get("TargetUserSid")
            if user_sid is not None and str(user_sid).strip() not in _NULL_SIDS:
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

        # PR #153 review: 4625/4771 Status/SubStatus (bad password vs unknown
        # user vs locked/disabled) were dropped; keep them for triage.
        codes = {k: safe_str(rec.get(src)) for k, src in
                 (("status", "Status"), ("sub_status", "SubStatus"),
                  ("failure_reason", "FailureReason")) if safe_str(rec.get(src))}
        if codes:
            event["unmapped"] = {"logon_status": codes}

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
