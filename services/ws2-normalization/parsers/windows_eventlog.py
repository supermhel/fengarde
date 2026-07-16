"""Windows Event Log parser: broad Windows Security/System events -> OCSF.

This parser handles the ``windows_eventlog`` source type. It deliberately covers
a *broader* set of security-relevant Windows EventIDs than the product-specific
``active_directory`` parser (which is scoped to AD logon/Kerberos events). There
is no collision: the two parsers are keyed on different ``source_type`` strings.

Raw bus payload ``raw`` is the parsed Windows event record as a dict (mirroring
the convention used by the AD parser), e.g.::

    {"EventID": 4688, "TimeCreated": 1750000000000,
     "Computer": "wks-jdoe", "SubjectUserName": "jdoe",
     "SubjectDomainName": "BANKCORP",
     "NewProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe",
     "NewProcessId": "0x1f4"}

EventID -> OCSF mapping (class_uid / activity_id constrained to Contract A):

    4624  Successful logon          -> 3002 Authentication, activity 1 (Logon)
    4634  Logoff                    -> 3002 Authentication, activity 2 (Logoff)
    4647  User-initiated logoff     -> 3002 Authentication, activity 2 (Logoff)
    4688  New process created       -> 1002 Kernel/Process, activity 1 (Launch)
    4672  Special privileges        -> 1002 Kernel/Process, activity 2 (Priv use)
    4720  Account created           -> 3003 Account Change, activity 1 (Create)
    4722  Account enabled           -> 3003 Account Change, activity 2 (Enable)
    4732  Member added to local security-enabled group
                                     -> 3003 Account Change, activity 5 (Priv Grant)
    4728  Member added to global security-enabled group
                                     -> 3003 Account Change, activity 5 (Priv Grant)
    4726  Account deleted           -> 3003 Account Change, activity 4 (Delete)

For authentication events, IpAddress/WorkstationName is the logon SOURCE
(``src_endpoint``) and ``Computer`` is the host being logged INTO
(``dst_endpoint.hostname``) -- the lateral-movement rule counts distinct
destination hosts per account off that. Process events have no network
direction, so ``Computer`` stays on ``src_endpoint``.

Class 1002 (Kernel / Process) is used for 4688/4672 because Contract A's
``class_uid`` enum does not include a dedicated Process Activity class (1007);
``ocsf-classes.md`` explicitly scopes 1002 to "process exec, privilege use",
which matches both events. EventIDs not in the table (including 4625, owned by
the AD parser) and malformed input return ``None``.

Class 3003 (Account Change) events (4720/4722/4732/4728/4726) have no logon
source/dest -- they are an ADMIN acting on a TARGET account. The acting admin
goes in ``actor.user`` (SubjectUserName/SubjectDomainName/SubjectUserSid, same
fields 4688/4672 already read for the actor). The account being created/
enabled/granted/deleted is a *different* identity than the actor and is
exposed as ``unmapped.target_user`` (name/domain/sid), populated from
TargetUserName/TargetDomainName/TargetUserSid -- the same raw field names used
for the logon-target identity elsewhere in this file, kept consistent here but
under ``unmapped`` since OCSF's ``actor``/``user`` top-level slots are already
spoken for by the acting admin.
"""
from __future__ import annotations

import json
import time
from typing import Optional

from .base import Parser, SEV_INFO, SEV_MEDIUM, SEV_HIGH
from .timeutil import to_epoch_ms

_CLS_AUTH = 3002    # Authentication
_CLS_PROC = 1002    # Kernel / Process
_CLS_ACCT = 3003    # Account Change

# Activity ids within class 1002 (Contract A leaves these open, 0-99).
_ACT_PROC_LAUNCH = 1   # process launch / exec
_ACT_PROC_PRIV = 2     # privilege use

# EventID -> (class_uid, activity_id, status, severity_id, verb)
_EVENT_MAP: dict[int, tuple] = {
    4624: (_CLS_AUTH, 1, "Success", SEV_INFO, "Logon"),
    4634: (_CLS_AUTH, 2, "Success", SEV_INFO, "Logoff"),
    4647: (_CLS_AUTH, 2, "Success", SEV_INFO, "Logoff"),
    4688: (_CLS_PROC, _ACT_PROC_LAUNCH, None, SEV_INFO, "Process created"),
    4672: (_CLS_PROC, _ACT_PROC_PRIV, "Success", SEV_MEDIUM, "Special privileges assigned"),
    # v0.3 (A4): Account Change events -- see the module docstring's "Class 3003"
    # section for the actor/target-account field mapping this table feeds.
    4720: (_CLS_ACCT, 1, "Success", SEV_MEDIUM, "Account created"),
    4722: (_CLS_ACCT, 2, "Success", SEV_INFO, "Account enabled"),
    4726: (_CLS_ACCT, 4, "Success", SEV_MEDIUM, "Account deleted"),
    4728: (_CLS_ACCT, 5, "Success", SEV_HIGH, "Member added to global security group"),
    4732: (_CLS_ACCT, 5, "Success", SEV_HIGH, "Member added to local security group"),
}


class WindowsEventLogParser(Parser):
    SOURCE_TYPE = "windows_eventlog"
    SECTOR = "common"
    ORIGINAL_FORMAT = "winevent"
    PRODUCT = {"name": "Windows Event Log", "vendor_name": "Microsoft"}

    def parse(self, raw: dict) -> Optional[dict]:
        if not isinstance(raw, dict):
            return None
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
        mapping = _EVENT_MAP.get(event_id)
        if mapping is None:
            return None
        class_uid, activity_id, status, severity_id, verb = mapping

        time_ms = self._epoch_ms(rec.get("TimeCreated") or meta.get("received_at"))

        # Subject = the account performing the action; Target = affected account
        # (4624/4672 carry both; logon classes prefer Target identity).
        if class_uid == _CLS_AUTH:
            user = rec.get("TargetUserName") or rec.get("SubjectUserName")
            domain = rec.get("TargetDomainName") or rec.get("SubjectDomainName")
            user_sid = rec.get("TargetUserSid") or rec.get("SubjectUserSid")
        else:
            user = rec.get("SubjectUserName") or rec.get("TargetUserName")
            domain = rec.get("SubjectDomainName") or rec.get("TargetDomainName")
            user_sid = rec.get("SubjectUserSid") or rec.get("TargetUserSid")

        ip = rec.get("IpAddress") or meta.get("ip")
        src_host = rec.get("WorkstationName")   # origin workstation (logon source)
        target_host = rec.get("Computer")       # host the event occurred ON

        # Account Change events (4720/4722/4726/4728/4732): the acting admin is
        # already captured above as `user` (Subject-first, via the `else` branch).
        # The account being created/enabled/deleted/granted is a DIFFERENT
        # identity -- exposed separately, per the module docstring, since OCSF's
        # actor/user slot is already spoken for by the acting admin.
        target_user = target_domain = target_user_sid = None
        if class_uid == _CLS_ACCT:
            target_user = rec.get("TargetUserName")
            target_domain = rec.get("TargetDomainName")
            target_user_sid = rec.get("TargetUserSid")

        message = f"{verb} for user {user or '?'}"
        if class_uid == _CLS_ACCT and target_user:
            message = f"{verb}: {target_user} (by {user or '?'})"
        elif event_id == 4688 and rec.get("NewProcessName"):
            message = f"{verb}: {rec['NewProcessName']} (by {user or '?'})"
        elif ip:
            message += f" from {ip}"

        sector = meta.get("sector") or self.SECTOR

        event = self.base_event(
            class_uid=class_uid,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=time_ms,
            ingest_id=meta.get("ingest_id"),
            logged_time=self._epoch_ms(meta.get("received_at")) if meta.get("received_at") else None,
            status=status,
            message=message,
            meta=meta,
        )
        event["siem"]["sector"] = sector

        # Endpoint direction matters for detection. For an AUTHENTICATION event,
        # IpAddress/WorkstationName is where the logon came FROM (source) and
        # `Computer` is the host being logged INTO (destination) -- so they map to
        # src_endpoint and dst_endpoint respectively. This is what lets the
        # lateral-movement rule count distinct destination hosts per account. For a
        # process/kernel event there is no network direction; `Computer` is simply
        # the host it ran on, so it stays on src_endpoint.
        src: dict = {}
        if ip:
            src["ip"] = ip
        if rec.get("MacAddress"):
            src["mac"] = rec["MacAddress"]
        if class_uid == _CLS_AUTH:
            if src_host:
                src["hostname"] = src_host
            if target_host:
                event["dst_endpoint"] = {"hostname": target_host}
        elif target_host or src_host:
            src["hostname"] = target_host or src_host
        if src:
            event["src_endpoint"] = src

        actor: dict = {}
        if user:
            actor_user: dict = {"name": user}
            if domain:
                actor_user["domain"] = domain
            if user_sid:
                actor_user["uid"] = str(user_sid)
            actor["user"] = actor_user

        if event_id == 4688 and rec.get("NewProcessName"):
            proc: dict = {"name": rec["NewProcessName"]}
            pid = self._parse_pid(rec.get("NewProcessId"))
            if pid is not None:
                proc["pid"] = pid
            actor["process"] = proc

        if actor:
            event["actor"] = actor

        if target_user:
            target: dict = {"name": target_user}
            if target_domain:
                target["domain"] = target_domain
            if target_user_sid:
                target["uid"] = str(target_user_sid)
            event["unmapped"] = {"target_user": target}

        return event

    # ---- helpers ------------------------------------------------------

    @staticmethod
    def _epoch_ms(value) -> int:
        # Handles epoch s/ms, ISO-8601 strings, and Windows FILETIME (the native
        # TimeCreated shape) -- the old int-only path mis-scaled both of the latter.
        return to_epoch_ms(value) or int(time.time() * 1000)

    @staticmethod
    def _parse_pid(value) -> Optional[int]:
        """Windows logs PIDs as hex strings ("0x1f4") or plain ints."""
        if value is None:
            return None
        if isinstance(value, int):
            return value
        try:
            s = str(value).strip()
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except (ValueError, TypeError):
            return None
