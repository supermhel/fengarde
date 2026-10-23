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
import re
import time
from typing import Optional

from .base import Parser, SEV_INFO, SEV_MEDIUM, SEV_HIGH
from shared.ocsf import valid_ip, valid_mac, safe_str
from .timeutil import to_epoch_ms
from .proc_launch import launch_info

_CLS_AUTH = 3002    # Authentication
_CLS_PROC = 1002    # Kernel / Process
_CLS_ACCT = 3003    # Account Change

# Activity ids within class 1002 (Contract A leaves these open, 0-99).
_ACT_PROC_LAUNCH = 1   # process launch / exec
_ACT_PROC_PRIV = 2     # privilege use
_ACT_SERVICE_INSTALL = 3   # 7045 / 4697 (2026-10-20, recall work: T1543.003); shares 3 with sysmon's Terminate
_ACT_LOG_CLEARED = 4       # Security 1102 / System 104 (T1070.001)
_ACT_PROC_ACCESS = 5       # sysmon.py owns this one (EventID 10); listed so the ids stay unique
_ACT_SCRIPT = 6            # PowerShell script block / module / pipeline log (4104 / 4103 / 800)

# EventID -> (class_uid, activity_id, status, severity_id, verb)
_EVENT_MAP: dict[int, tuple] = {
    4624: (_CLS_AUTH, 1, "Success", SEV_INFO, "Logon"),
    4634: (_CLS_AUTH, 2, "Success", SEV_INFO, "Logoff"),
    4647: (_CLS_AUTH, 2, "Success", SEV_INFO, "Logoff"),
    4688: (_CLS_PROC, _ACT_PROC_LAUNCH, None, SEV_INFO, "Process created"),
    4672: (_CLS_PROC, _ACT_PROC_PRIV, "Success", SEV_MEDIUM, "Special privileges assigned"),
    # 2026-10-20 (recall work, blind-recall funnel NO_PARSER/NO_RULE heads): a service was
    # installed (System 7045 / Security 4697) and an audit log was cleared (Security 1102 / System 104).
    4697: (_CLS_PROC, _ACT_SERVICE_INSTALL, "Success", SEV_MEDIUM, "Service installed"),
    7045: (_CLS_PROC, _ACT_SERVICE_INSTALL, "Success", SEV_MEDIUM, "Service installed"),
    1102: (_CLS_PROC, _ACT_LOG_CLEARED, "Success", SEV_HIGH, "Audit log cleared"),
    104: (_CLS_PROC, _ACT_LOG_CLEARED, "Success", SEV_HIGH, "Audit log cleared"),
    # PowerShell logging (Microsoft-Windows-PowerShell/Operational 4104 script block, 4103 module logging;
    # classic 'Windows PowerShell' 800 pipeline execution). EventIDs are only unique per provider: see _SCOPED below.
    # 5136 directory service object modified (AD change auditing): an Account Change (3003) with activity 6.
    5136: (_CLS_ACCT, 6, "Success", SEV_MEDIUM, "Directory object modified"),
    4104: (_CLS_PROC, _ACT_SCRIPT, "Success", SEV_INFO, "PowerShell script block"),
    4103: (_CLS_PROC, _ACT_SCRIPT, "Success", SEV_INFO, "PowerShell module logging"),
    800: (_CLS_PROC, _ACT_SCRIPT, "Success", SEV_INFO, "PowerShell pipeline execution"),
    # v0.3 (A4): Account Change events -- see the module docstring's "Class 3003"
    # section for the actor/target-account field mapping this table feeds.
    4720: (_CLS_ACCT, 1, "Success", SEV_MEDIUM, "Account created"),
    4722: (_CLS_ACCT, 2, "Success", SEV_INFO, "Account enabled"),
    4726: (_CLS_ACCT, 4, "Success", SEV_MEDIUM, "Account deleted"),
    4728: (_CLS_ACCT, 5, "Success", SEV_HIGH, "Member added to global security group"),
    4732: (_CLS_ACCT, 5, "Success", SEV_HIGH, "Member added to local security group"),
}

#: EventIDs are unique per PROVIDER, not globally (another provider's 104 is not a log clear). For these IDs a record
#: that names its Channel / Provider must name the expected one (case-folded), else the parser declines it. A record
#: naming neither is still accepted, as before (many shippers flatten those fields away).
_SCOPED: dict[int, tuple] = {
    104: ({"system"}, {"microsoft-windows-eventlog", "eventlog"}),
    1102: ({"security"}, {"microsoft-windows-eventlog", "eventlog"}),
    7045: ({"system"}, {"service control manager"}),
    800: ({"windows powershell"}, {"powershell"}),
    4103: ({"microsoft-windows-powershell/operational"}, {"microsoft-windows-powershell"}),
    4104: ({"microsoft-windows-powershell/operational"}, {"microsoft-windows-powershell"}),
}


def _out_of_scope(event_id: int, rec: dict) -> bool:
    scope = _SCOPED.get(event_id)
    if scope is None:
        return False
    channels, providers = scope
    channel = rec.get("Channel")
    provider = rec.get("ProviderName") or rec.get("Provider") or rec.get("SourceName")
    if isinstance(provider, dict):
        provider = provider.get("Name")
    if isinstance(channel, str) and channel.strip().lower() not in channels:
        return True
    return isinstance(provider, str) and provider.strip().lower() not in providers


#: Substrings (case-folded) that make a service image path suspicious: user-writable or
#: temp locations, a shell as the service binary, UNC paths, or a script/LOLBin host. A
#: HEURISTIC, like the agent-parser indicators - legitimate installers under %ProgramFiles%
#: or %SystemRoot%\System32 do not match. Tune per deployment.
_SUSPICIOUS_SERVICE_PATH = (
    r"\temp" "\\", r"\appdata" "\\", r"\users\public" "\\", r"\programdata" "\\", r"\windows\tasks" "\\",
    "%comspec%", "cmd.exe /c", "cmd /c", "powershell", "pwsh", "rundll32", "mshta", "wscript", "cscript",
    "regsvr32", "\\\\",
    # 7045 often logs the ImagePath unexpanded, so the same locations as environment variables:
    "%temp%", "%tmp%", "%appdata%", "%localappdata%", "%public%", "%programdata%", "%userprofile%",
)


def _suspicious_service_path(path: str) -> bool:
    low = path.lower().replace("/", "\\")
    return any(tok in low for tok in _SUSPICIOUS_SERVICE_PATH)


#: PowerShell indicators (case-folded regexes). A HEURISTIC over the logged script text, not a classifier:
#: STRONG = one hit is enough; WEAK = need two distinct. Tune per site; see win_powershell_suspicious_script.yml.
_PS_STRONG = tuple(re.compile(x) for x in (
    r"downloadstring", r"downloadfile", r"frombase64string", r"net\.webclient", r"amsiinitfailed", r"amsiutils",
    r"invoke-mimikatz", r"invoke-shellcode", r"invoke-reflectivepeinjection", r"reflection\.assembly\]::load",
    # -EncodedCommand under any prefix PowerShell accepts (-e, -ec, -en, -enc, -enco ...), with -, /, en or em dash.
    r"virtualalloc", r"(?:^|\s)[-/–—](?:e|ec|en[a-z]*)\s+[a-z0-9+/=]{30,}",
))
_PS_WEAK = tuple(re.compile(x) for x in (
    r"\biex\b", r"invoke-expression", r"-exec(utionpolicy)?\s+bypass", r"-nop(rofile)?\b",
    r"-w(indowstyle)?\s+hidden", r"invoke-webrequest|\biwr\b", r"start-process", r"new-object\s+net\.",
))
_PS_MAX = 2000

#: AD attributes whose modification is a known attack step (case-folded LDAP display names): SPN set (kerberoast
#: prep), delegation (constrained / RBCD), shadow-credentials key, GPO link, logon script, UAC flags, SID history.
_DS_SENSITIVE_ATTRS = frozenset((
    "serviceprincipalname", "msds-allowedtodelegateto", "msds-allowedtoactonbehalfofotheridentity",
    "msds-keycredentiallink", "gplink", "gpcfilesyspath", "scriptpath", "useraccountcontrol", "sidhistory",
))


def _powershell_info(text: str) -> dict:
    low = text.lower()
    strong = [p.pattern for p in _PS_STRONG if p.search(low)]
    weak = [p.pattern for p in _PS_WEAK if p.search(low)]
    return {"script": text[:_PS_MAX], "truncated": len(text) > _PS_MAX,
            "suspicious": bool(strong) or len(weak) >= 2, "indicators": (strong + weak)[:8]}


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
            event_id = int(str(rec.get("EventID")))
        except (TypeError, ValueError):
            return None
        mapping = _EVENT_MAP.get(event_id)
        if mapping is None or _out_of_scope(event_id, rec):
            return None
        class_uid, activity_id, status, severity_id, verb = mapping

        time_ms = self._epoch_ms(rec.get("TimeCreated") or meta.get("received_at"))

        # Subject = the account performing the action; Target = affected account
        # (4624/4672 carry both; logon classes prefer Target identity).
        if class_uid == _CLS_AUTH:
            user = safe_str(rec.get("TargetUserName") or rec.get("SubjectUserName"))
            domain = safe_str(rec.get("TargetDomainName") or rec.get("SubjectDomainName"))
            user_sid = rec.get("TargetUserSid") or rec.get("SubjectUserSid")
        else:
            user = safe_str(rec.get("SubjectUserName") or rec.get("TargetUserName"))
            domain = safe_str(rec.get("SubjectDomainName") or rec.get("TargetDomainName"))
            user_sid = rec.get("SubjectUserSid") or rec.get("TargetUserSid")

        ip = valid_ip(rec.get("IpAddress") or meta.get("ip"))
        src_host = safe_str(rec.get("WorkstationName"))   # origin workstation (logon source)
        target_host = safe_str(rec.get("Computer"))       # host the event occurred ON

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
        service_name = service_path = None
        if event_id in (4697, 7045):
            service_name = safe_str(rec.get("ServiceName"))
            service_path = safe_str(rec.get("ImagePath") or rec.get("ServiceFileName"))
            message = f"{verb}: {service_name or '?'} -> {service_path or '?'} (by {user or '?'})"
        elif event_id in (1102, 104):
            message = f"{verb} (by {user or '?'})"
        ds_info = None
        if event_id == 5136:
            attr = safe_str(rec.get("AttributeLDAPDisplayName")) or ""
            ds_info = {"object_dn": safe_str(rec.get("ObjectDN")), "object_class": safe_str(rec.get("ObjectClass")),
                       "attribute": attr, "value": (safe_str(rec.get("AttributeValue")) or "")[:500],
                       "operation": safe_str(rec.get("OperationType")),
                       "sensitive_attribute": attr.lower() in _DS_SENSITIVE_ATTRS}
            message = f"{verb}: {attr or '?'} on {ds_info['object_dn'] or '?'} (by {user or '?'})"
        ps_info = None
        if event_id in (4104, 4103, 800):
            data = rec.get("ScriptBlockText") or rec.get("Payload") or rec.get("ContextInfo") \
                or rec.get("HostApplication") or rec.get("Data")
            if isinstance(data, (list, tuple)):
                data = " ".join(str(x) for x in data)
            ps_info = _powershell_info(safe_str(data) or "")
            message = f"{verb} (by {user or '?'})"
        if class_uid == _CLS_ACCT and target_user:
            message = f"{verb}: {target_user} (by {user or '?'})"
        elif event_id == 4688 and rec.get("NewProcessName"):
            message = f"{verb}: {safe_str(rec['NewProcessName']) or '?'} (by {user or '?'})"
        elif ip:
            message += f" from {ip}"

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
            sector=self.resolve_sector(meta),
        )

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
        mac = valid_mac(rec.get("MacAddress"))
        if mac:
            src["mac"] = mac
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

        proc_name = safe_str(rec.get("NewProcessName")) if event_id == 4688 else None
        if event_id == 4688 and proc_name:
            proc: dict = {"name": proc_name}
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

        if ps_info is not None:
            event.setdefault("unmapped", {})["powershell"] = ps_info
        if ds_info is not None:
            event.setdefault("unmapped", {})["directory"] = ds_info
        if event_id == 4688 and proc_name:
            event.setdefault("unmapped", {})["process_launch"] = launch_info(
                safe_str(rec.get("ParentProcessName")), proc_name, safe_str(rec.get("CommandLine")))

        if service_name or service_path:
            svc: dict = {}
            if service_name:
                svc["name"] = service_name
            if service_path:
                svc["path"] = service_path
                svc["suspicious_path"] = _suspicious_service_path(service_path)
            event.setdefault("unmapped", {})["service"] = svc

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
        if value is None or isinstance(value, bool):  # True would pass isinstance(int) and fail the schema (pid: boolean)
            return None
        if isinstance(value, int):
            return value
        try:
            s = str(value).strip()
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except (ValueError, TypeError):
            return None
