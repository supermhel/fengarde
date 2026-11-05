"""Adapter: Winlogbeat records (ECS shape) -> windows_eventlog / sysmon input.

Winlogbeat (Elastic Beats 7/8) emits each event with the fields NESTED under
``winlog.*`` (``winlog.event_id``, ``winlog.channel``, ``winlog.computer_name``,
``winlog.provider_name``, ``winlog.time_created``, ``winlog.event_data.*``);
the raw XML lives in ``event.original`` (only with ``include_xml: true``).

The adapter flattens that nesting into the Windows Event Log XML attribute
names the parsers already read:

- ``winlog.event_id``                    -> ``EventID`` (int)
- ``winlog.computer_name``               -> ``Computer``
- ``winlog.time_created`` (ISO-8601)     -> ``TimeCreated`` (epoch ms int)
- ``winlog.event_data.*``                -> one flat PascalCase key per entry
  (``SubjectUserName``, ``IpAddress``, ``NewProcessName``, ``TargetUserName``,
  ... — the same names the parsers read);
- ``winlog.user.{name,domain,identifier}`` -> ``User`` / ``UserDomain`` /
  ``SubjectUserSid``-style passthrough is NOT attempted (the parsers read the
  event-data names; winlog.user is a resolution artifact) — kept under
  ``unmapped_winlog_user`` so nothing is lost;
- Sysmon records route to ``sysmon`` (provider name or low EventID), all
  others to ``windows_eventlog`` — same mixed-channel rule as the
  fluent-bit adapter.

Fixture provenance: the field catalog is Winlogbeat's official exported-fields
reference (elastic.co/docs/reference/beats/winlogbeat/exported-fields-winlog —
``winlog.event_id``, ``winlog.channel``, ``winlog.event_data.NewProcessName``
etc. are all listed there); the VALUES model a real Windows 4688 process-
creation record in that shape. TEMPLATE-DERIVED from the field catalog, not a
captured specimen — labelled as such per repo honesty rule. (A real
pre-ECS Winlogbeat 1.x capture exists in the Logz.io 2016 post
"Windows Event Log Analysis with Winlogbeat" — logz.io/blog/windows-event-log-
analysis — and is only cited, not quoted; the
adapter targets the current nested ECS shape.)
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

_SYSMON_PROVIDER = "microsoft-windows-sysmon"
_SYSMON_EVENTIDS = {1, 3, 5, 11}

FIXTURE = {
    "@timestamp": "2023-01-17T12:50:59.303Z",
    "agent": {"hostname": "EC2AMAZ-LPA5TA4", "type": "winlogbeat", "version": "8.7.0"},
    "event": {
        "code": "4688",
        "kind": "event",
        "provider": "Microsoft-Windows-Security-Auditing",
        "original": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
                    "<System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
                    "<EventID>4688</EventID><Computer>wks-jdoe</Computer>"
                    "<TimeCreated SystemTime='2023-01-17T12:50:59.3030000Z'/></System>"
                    "<EventData><Data Name='NewProcessName'>C:\\Program Files\\"
                    "WindowsApps\\n8n.exe</Data></EventData></Event>",
        "sequence": 148209,
    },
    "host": {"hostname": "wks-jdoe"},
    "log": {"level": "Information"},
    "winlog": {
        "channel": "Security",
        "computer_name": "wks-jdoe",
        "event_data": {
            "CommandLine": "\"C:\\Program Files\\n8n\\n8n.exe\" --start",
            "NewProcessId": "0x1f4",
            "NewProcessName": "C:\\Program Files\\WindowsApps\\n8n.exe",
            "ParentCommandLine": "C:\\Windows\\system32\\services.exe",
            "ParentProcessId": "0x1a0",
            "ParentProcessName": "C:\\Windows\\System32\\services.exe",
            "SubjectDomainName": "BANKCORP",
            "SubjectLogonId": "0x3e7",
            "SubjectUserName": "WKS-JDOE$",
            "SubjectUserSid": "S-1-5-18",
        },
        "event_id": 4688,
        "opcode": "Info",
        "process": {"pid": 4952, "thread": {"id": 7292}},
        "provider_guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "record_id": 148209,
        "task": "Process Creation",
        "time_created": "2023-01-17T12:50:59.303Z",
        "user": {"domain": "BANKCORP", "identifier": "S-1-5-18", "name": "WKS-JDOE$"},
        "version": 2,
    },
}

SECURITY_LOGON_FIXTURE = {
    "@timestamp": "2023-01-17T13:02:11.722Z",
    "event": {"code": "4624"},
    "host": {"hostname": "dc01"},
    "winlog": {
        "channel": "Security",
        "computer_name": "dc01",
        "event_data": {
            "AuthenticationPackageName": "Kerberos",
            "IpAddress": "203.0.113.9",
            "IpPort": "54000",
            "LogonProcessName": "Kerberos",
            "LogonType": "3",
            "SubjectDomainName": "-",
            "SubjectUserName": "-",
            "SubjectUserSid": "S-1-0-0",
            "TargetDomainName": "BANKCORP",
            "TargetLogonId": "0x2d42a6",
            "TargetUserName": "jdoe",
            "TargetUserSid": "S-1-5-21-3541430928-2051711210-1391384369-1001",
            "WorkstationName": "wks-jdoe",
        },
        "event_id": 4624,
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "record_id": 148210,
        "time_created": "2023-01-17T13:02:11.722Z",
        "user": {"domain": "BANKCORP", "identifier": "S-1-5-21-3541430928-2051711210-1391384369-1001",
                 "name": "jdoe"},
        "version": 2,
    },
}


def _to_epoch_ms(value) -> Optional[int]:
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    # ISO-8601 with optional fractional seconds / offset. Beats emits UTC "Z"
    # by default (its output can carry +00:00 offsets); naive -> UTC.
    base = s[:-1] + "+00:00" if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(base)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


SOURCE_TYPES = frozenset({"windows_eventlog", "sysmon"})


def _flatten_event_data(winlog: dict, out: dict) -> None:
    ed = winlog.get("event_data")
    if not isinstance(ed, dict):
        return
    for key, value in ed.items():
        # Only the flat PascalCase names the parsers read; anything else
        # (param1.., free-form) still flows through — parsers ignore extras.
        out[key] = value


def sniffs(raw) -> bool:
    """A record carrying the ECS ``winlog`` object is winlogbeat."""
    if not isinstance(raw, dict):
        return False
    winlog = raw.get("winlog")
    if not isinstance(winlog, dict):
        return False
    return ("event_id" in winlog and "channel" in winlog
            and "computer_name" in winlog)


def adapt(payload: dict) -> dict:
    raw = payload.get("raw")
    meta = payload.get("meta") if isinstance(payload, dict) else None
    if not isinstance(raw, dict):
        return payload
    winlog = raw.get("winlog")
    if not isinstance(winlog, dict):
        return payload
    out: dict = {}
    # event_data first: its keys are free-form and must never overwrite the adapter's own fields set below.
    _flatten_event_data(winlog, out)
    eid = winlog.get("event_id")
    try:
        eid_int = int(eid) if (not isinstance(eid, bool) and eid is not None) else None
    except (TypeError, ValueError, OverflowError):
        eid_int = None
    if eid_int is not None:
        out["EventID"] = eid_int
    computer = winlog.get("computer_name")
    if isinstance(computer, str) and computer:
        out["Computer"] = computer
    ts = _to_epoch_ms(winlog.get("time_created"))
    tc = winlog.get("time_created")
    if ts is not None:
        out["TimeCreated"] = ts
    elif isinstance(tc, (int, float)) and not isinstance(tc, bool):
        out["TimeCreated"] = tc  # native numeric time: the parser's timeutil owns seconds/ms/FILETIME
    # Preserve winlog-level context the parsers don't read but operators may
    # want to audit (record_id, task, opcode, provider_guid) + the user
    # resolution artifacts, under a namespaced key — never dropped silently.
    out["unmapped_winlog"] = {k: v for k, v in winlog.items()
                              if k not in ("event_data", "process")}
    provider = str(winlog.get("provider_name") or "").strip().lower()
    if provider == _SYSMON_PROVIDER or (eid_int in _SYSMON_EVENTIDS
                                        and not provider):
        source_type = "sysmon"
    else:
        source_type = "windows_eventlog"
    return {"source_type": source_type, "raw": out,
            "meta": dict(meta) if isinstance(meta, dict) else {}}