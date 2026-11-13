"""Adapter: Fluent Bit ``winevtlog`` records -> windows_eventlog / sysmon input.

Target convention: the Windows Event Log XML attribute names the parsers
already read (``EventID``, ``Computer``, ``SubjectUserName``, ...), FLAT at the
record top level. Fluent Bit's ``winevtlog`` input in ``event_data_as_map: true``
mode does NOT emit that: a real Fluent Bit 4.2.8 run on Windows 11 (see
CAPTURED_WIN11_APPLICATION) puts the named event data in a nested ``EventData``
map next to the system fields (``ProviderName``, ``EventID``, ``Computer``,
``TimeCreated``, ``Message``, ``StringInserts`` ...). The 2023 published capture
(FIXTURE, Fluent Bit 2.0.6) predates the map and carries no event-data keys at
all; the adapter therefore normalizes either shape to flat:

- a dict ``EventData`` is flattened into the top level (system keys win on a
  collision, so event data can never overwrite ``EventID``/``Computer``/...);
  the map exists only when the provider's template resolves -- classic
  providers (e.g. Service Control Manager 7045) arrive with ``StringInserts``
  only and nothing is mapped (honest scope below);
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

Known limit (DST): Fluent Bit prints ``TimeCreated`` with the host's CURRENT UTC offset, not the offset in force when the
event happened. The Windows 11 capture below reads ``2026-08-11 21:21:44 +0100`` while the host's own event log says
``2026-08-11T21:21:44+02:00`` (W. Europe Standard Time, DST): the wall clock is right, the offset is not, so by default an
event from the other side of a DST switch is dated one hour off (the capture lands at 20:21:44Z instead of 19:21:44Z).
Opt-in fix: set ``FENGARDE_WINEVTLOG_TZ`` to the host's IANA zone; the printed offset is then ignored and the wall clock is
resolved in that zone with correct DST (an ambiguous fall-back hour resolves to its first occurrence). Where DST accuracy
matters, prefer Winlogbeat, which emits UTC.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Optional
from zoneinfo import ZoneInfo

#: Optional IANA zone (e.g. ``Europe/Berlin``) in which the printed TimeCreated wall clock is interpreted. Read at call time.
TZ_ENV = "FENGARDE_WINEVTLOG_TZ"

_SYSMON_PROVIDER = "microsoft-windows-sysmon"
#: Sysmon EventIDs are provider-scoped low numbers; if the provider is unnamed
#: a record in this set is still Sysmon-shaped (mirrors parsers/__init__.py).
_SYSMON_EVENTIDS = {1, 3, 5, 11}
#: Security EventIDs the active_directory parser maps and windows_eventlog does not (4624/4634/4647 are mapped by both and stay
#: on windows_eventlog). With source_type=windows_eventlog these would dead-letter ("parser returned None"), so the adapter
#: re-routes them, as it does for Sysmon. A test derives this set from the two parsers' maps so it cannot drift.
AD_ONLY_EVENTIDS = frozenset({4625, 4768, 4771})
_SECURITY_PROVIDER = "microsoft-windows-security-auditing"

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


# REAL capture: Fluent Bit v4.2.8 (official win64 zip) winevtlog, Application channel, run as a normal user on Windows 11
# (de-DE) on 2026-11-05 with Event_Data_As_Map true; Computer scrubbed to a placeholder, everything else verbatim --
# including the localized Message/Response text and the mangled UserID (U+E0C4 where "NT-AUTORITAET" has its umlaut).
CAPTURED_WIN11_APPLICATION = {
    "ProviderName": "Windows Error Reporting",
    "ProviderGuid": "{0EAD09BD-2157-539A-8D6D-C87F95B64D70}",
    "Qualifiers": "",
    "EventID": 1001,
    "Version": 0,
    "Level": 4,
    "Task": 0,
    "Opcode": 0,
    "Keywords": "0x8000000000000000",
    "TimeCreated": "2026-08-11 21:21:44 +0100",
    "EventRecordID": 61384,
    "ActivityID": "",
    "RelatedActivityID": "",
    "ProcessID": 20672,
    "ThreadID": 18324,
    "Channel": "Application",
    "Computer": "WIN11-LAB",
    "UserID": "NT-AUTORIT\ue0c4T\\SYSTEM",
    "Message": ("Fehlerbucket , Typ 0\r\nEreignisname: crashpad_log\r\nAntwort: Nicht verf\u00fcgbar\r\nCAB"
        "-Datei-ID: 0\r\n\r\nProblemsignatur:\r\nP1: setup.exe\r\nP2: 151.0.4129.72\r\nP3: EdgeInst"
        "allerError|msedge\r\nP4: 0x3c\r\nP5: \r\nP6: \r\nP7: \r\nP8: \r\nP9: \r\nP10: \r\n\r\nAnge"
        "f\u00fcgte Dateien:\r\n\\\\?\\C:\\Windows\\SystemTemp\\msedge_installer.log\r\n\r\nDiese D"
        "ateien befinden sich m\u00f6glicherweise hier:\r\nNULL\r\n\r\nAnalysesymbol: \r\nEs wird e"
        "rneut nach einer L\u00f6sung gesucht: 0\r\nBerichts-ID: af3e1eaf-434a-43aa-9398-b6c8192e1d"
        "ee\r\nBerichtstatus: 268697600\r\nBucket mit Hash: \r\nCAB-Datei-Guid: 0"),
    "EventData": {
        "Bucket": "",
        "BucketType": "0",
        "EventName": "crashpad_log",
        "Response": "Nicht verf\u00fcgbar",
        "CabId": "0",
        "P1": "setup.exe",
        "P2": "151.0.4129.72",
        "P3": "EdgeInstallerError|msedge",
        "P4": "0x3c",
        "P5": "",
        "P6": "",
        "P7": "",
        "P8": "",
        "P9": "",
        "P10": "",
        "AttachedFiles": "\r\n\\\\?\\C:\\Windows\\SystemTemp\\msedge_installer.log",
        "StorePath": "NULL",
        "AnalysisSymbol": "",
        "Rechecking": 0,
        "ReportId": "af3e1eaf-434a-43aa-9398-b6c8192e1dee",
        "ReportStatus": 268697600,
        "HashedBucket": "",
        "CabGuid": "0"
    },
    "StringInserts": [
        "",
        "0",
        "crashpad_log",
        "Nicht verf\u00fcgbar",
        "0",
        "setup.exe",
        "151.0.4129.72",
        "EdgeInstallerError|msedge",
        "0x3c",
        "",
        "",
        "",
        "",
        "",
        "",
        "\r\n\\\\?\\C:\\Windows\\SystemTemp\\msedge_installer.log",
        "NULL",
        "",
        0,
        "af3e1eaf-434a-43aa-9398-b6c8192e1dee",
        268697600,
        "",
        "0"
    ]
}


SOURCE_TYPES = frozenset({"windows_eventlog", "sysmon"})  # active_directory is an output-only re-route


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
    if dt.tzinfo is not None:
        zone = _configured_zone()
        if zone is not None:
            # Fluent Bit prints the CURRENT UTC offset, not the one in force at the event time (see TZ_ENV): trust only the
            # wall clock and let the zone database supply the offset valid on that date.
            dt = dt.replace(tzinfo=zone)
    else:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


_WARNED_ZONES: set = set()


def _configured_zone():
    """The IANA zone named by FENGARDE_WINEVTLOG_TZ, or None (unset / invalid -> today's behaviour). Never raises."""
    name = os.environ.get(TZ_ENV, "").strip()
    if not name:
        return None
    try:
        return ZoneInfo(name)
    except Exception:  # noqa: BLE001  (ZoneInfoNotFoundError, ValueError on '../x', missing tzdata, ...)
        if name not in _WARNED_ZONES:
            _WARNED_ZONES.add(name)
            logging.getLogger("ws2.adapters").warning(
                "%s=%r is not a usable IANA zone (is tzdata installed?); ignoring it, using the offset Fluent Bit printed",
                TZ_ENV, name[:64])
        return None


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
    ed = out.get("EventData")
    if isinstance(ed, dict):  # Fluent Bit >= 4.x nests the named event data; the parsers read it flat
        del out["EventData"]
        for k, v in ed.items():
            if isinstance(k, str):
                out.setdefault(k, v)
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
    elif eid_int in AD_ONLY_EVENTIDS and provider in ("", _SECURITY_PROVIDER):
        source_type = "active_directory"
    else:
        source_type = "windows_eventlog"
    return {"source_type": source_type, "raw": out,
            "meta": dict(meta) if isinstance(meta, dict) else {}}