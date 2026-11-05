"""Adapter: Fluent Bit ``winevtlog`` records -> windows_eventlog / sysmon input.

Target convention: the Windows Event Log XML attribute names the parsers
already read (``EventID``, ``Computer``, ``SubjectUserName``, ...) — which is
exactly the record shape Fluent Bit's ``winevtlog`` input emits in
``event_data_as_map: true`` mode (the plugin flattens the event-data map into
the record top level). The adapter must therefore convert almost nothing:

- ``TimeCreated`` arrives as a formatted string (``"2023-01-17 12:50:59 +0000"``)
  -> epoch MILLISECONDS int, the parser's convention;
- records from the Sysmon provider (or a Sysmon EventID without a named
  provider) route to the ``sysmon`` parser, everything else to
  ``windows_eventlog`` — because one ``winevtlog`` channel list mixes
  ``Security`` and ``Microsoft-Windows-Sysmon/Operational`` (the documented
  setup), and a fixed sender-side ``source_type`` cannot cover both.

Fixture provenance (transcribed from a published capture; not byte-exact, no capture file stored): the sample below is the output
of fluent-bit 2.0.6's ``winevtlog`` input on a Windows host (2023-01-17),
published by ClickHouse in their community post
"Send Windows Event Logs to ClickHouse with Fluent Bit"
(clickhouse.com/blog/sending-windows-event-logs-to-clickhouse-with-fluent-bit);
it was ingested into ClickHouse ``JSONEachRow`` and the object is transcribed
here (the ``StringInserts`` array truncated to its first two entries
for fixture size — the adapter does not read it). No specimen value was
invented. ``event_data_as_map: true`` is REQUIRED (the recipe sets it); in
default mode Fluent Bit renders the event text under ``Message`` and the event
data only as ``StringInserts``, which this adapter does not attempt to
reverse-engineer (honest scope, see docs/input-adapters.md).
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

_SYSMON_PROVIDER = "microsoft-windows-sysmon"
#: Sysmon EventIDs are provider-scoped low numbers; if the provider is unnamed
#: a record in this set is still Sysmon-shaped (mirrors parsers/__init__.py).
_SYSMON_EVENTIDS = {1, 3, 5, 11}

FIXTURE = {
    "ActivityID": "",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "Computer": "EC2AMAZ-LPA5TA4",
    "EventID": 1,
    "EventRecordID": 483,
    "Keywords": "0x8000000000000000",
    "Level": 4,
    "Message": "Process Create:\r\nRuleName: -\r\n"
               "UtcTime: 2023-01-17 12:50:59.303\r\n"
               "ProcessGuid: {f51ddac1-99b3-63c6-bb01-00000000e100}\r\n"
               "ProcessId: 5216\r\n"
               "Image: C:\\fluent\\fluent-bit-2.0.6-win64\\bin\\fluent-bit.exe\r\n"
               "CommandLine: fluent-bit.exe  -c ../conf/fluent-bit.conf\r\n"
               "User: EC2AMAZ-LPA5TA4\\Administrator\r\n"
               "LogonId: 0xCE96D\r\n"
               "Hashes: MD5=4A19C3D18B025F49AA157FD2D360283A\r\n"
               "ParentProcessId: 7720\r\n"
               "ParentImage: C:\\Windows\\System32\\cmd.exe",
    "Opcode": 0,
    "ProcessID": 7536,
    "ProviderGuid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
    "ProviderName": "Microsoft-Windows-Sysmon",
    "Qualifiers": "",
    "RelatedActivityID": "",
    "StringInserts": ["-", "2023-01-17 12:50:59.303"],
    "Task": 1,
    "ThreadID": 7456,
    "TimeCreated": "2023-01-17 12:50:59 +0000",
    "UserID": "S-1-5-18",
    "Version": 5,
}

# Security-channel shape for the windows_eventlog target. NOT a verbatim
# capture of the same post's output: the Keys are the standard Security-4624
# event-data names (documented in Microsoft's 4624 event template and echoed
# by the Winlogbeat exported-fields catalog for winlog.event_data.*), in the
# plugin's flat rendering mode; the VALUES are a representative logon record
# in the same style as the captured Sysmon one. Fixture is therefore
# TEMPLATE-DERIVED, not captured — labelled as such per repo honesty rule.
SECURITY_FIXTURE = {
    "Channel": "Security",
    "Computer": "DC01",
    "EventID": 4624,
    "EventRecordID": 129345,
    "Keywords": "0x8020000000000000",
    "Level": 0,
    "ProviderName": "Microsoft-Windows-Security-Auditing",
    "Task": 12544,
    "TimeCreated": "2023-01-17 12:50:59 +0000",
    "IpAddress": "203.0.113.9",
    "IpPort": "54000",
    "SubjectDomainName": "BANKCORP",
    "SubjectUserName": "-",
    "TargetDomainName": "BANKCORP",
    "TargetUserName": "jdoe",
    "WorkstationName": "wks-jdoe",
    "LogonType": "3",
    "LogonProcessName": "Kerberos",
}


SOURCE_TYPES = frozenset({"windows_eventlog", "sysmon"})


def _to_epoch_ms(value) -> Optional[int]:
    """Fluent Bit's TimeCreated string -> epoch ms, or None when it is not the plugin's rendering.

    Accepts ``%Y-%m-%d %H:%M:%S %z`` (the plugin's rendering), optional
    fractional seconds, and a missing timezone (assumed UTC). Anything else
    (numbers, digit strings, junk) returns None and the caller leaves the value
    UNTOUCHED: the parser's own time handling (parsers/timeutil.py: seconds, ms,
    FILETIME, ISO) already deals with native shapes, and a conversion here would
    misdate them.
    """
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s or s.isdigit():
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S %z", "%Y-%m-%d %H:%M:%S.%f %z",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(s, fmt)
            break
        except ValueError:
            continue
    else:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=__import__("datetime").timezone.utc)
    return int(dt.timestamp() * 1000)


def sniffs(raw) -> bool:
    """Winlog-flavored record with the plugin's flat PascalCase keys."""
    if not isinstance(raw, dict):
        return False
    if "winlog" in raw:  # winlogbeat nests under "winlog" — not this shape
        return False
    return bool(isinstance(raw.get("Channel"), str) and raw.get("Channel")
                and "EventID" in raw and isinstance(raw.get("Computer"), str)
                and "TimeCreated" in raw)


def adapt(payload: dict) -> dict:
    """Rewrite a fluentbit-winevtlog payload for the target parser."""
    raw = payload.get("raw")
    meta = payload.get("meta") if isinstance(payload, dict) else None
    if not isinstance(raw, dict):
        return payload
    out = dict(raw)
    ts = _to_epoch_ms(out.get("TimeCreated"))
    if ts is not None:
        out["TimeCreated"] = ts
    provider = str(out.get("ProviderName") or "").strip().lower()
    eid = out.get("EventID")
    try:
        eid_int = int(eid) if (not isinstance(eid, bool) and eid is not None) else None
    except (TypeError, ValueError, OverflowError):
        eid_int = None
    if provider == _SYSMON_PROVIDER or (eid_int in _SYSMON_EVENTIDS
                                        and not provider):
        source_type = "sysmon"
    else:
        source_type = "windows_eventlog"
    return {"source_type": source_type, "raw": out,
            "meta": dict(meta) if isinstance(meta, dict) else {}}