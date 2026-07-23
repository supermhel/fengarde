"""Sysmon parser: Microsoft-Windows-Sysmon/Operational -> OCSF.

P0-3 (2026-07-21 audit fix plan): the single highest-leverage detection-
coverage gap the audit found. EVTX-ATTACK-SAMPLES/Splunk attack_data replay
showed FENGARDE parsed only ~9% of the Security-channel volume in real
attack captures and ZERO Sysmon -- yet Sysmon (process/network/file
telemetry) was the DOMINANT channel in both real-world corpora (EVTX:
Sysmon EventIDs 1/3/7/10/11/12/13 outnumbered every Security EventID
combined; same shape in Splunk attack_data). This parser closes the three
Sysmon event types with a clean fit in Contract A's restricted OCSF profile:

    EventID 1  (ProcessCreate)     -> 1002 Kernel/Process,   activity 1 (Launch)
    EventID 3  (NetworkConnect)    -> 4001 Network Activity, activity 7 (Accept)
    EventID 11 (FileCreate)        -> 1001 File System Activity, activity 1 (Create)
                                       -- the FIRST producer for class 1001,
                                       previously a documented total gap
                                       (contracts/detection-coverage.md).

EventID 13 (RegistryValueSet) is deliberately NOT mapped: Contract A's
restricted profile has no Registry Activity class, and forcing it onto an
ill-fitting class (Process? File?) would be exactly the "wrong mapping is
worse than an honest gap" mistake this codebase avoids elsewhere (see
agent_tool_call_burst.yml shipping with no MITRE tag rather than a forced
one). Left as a documented, honest gap for a follow-up parser revision.

Raw bus payload ``raw`` is the parsed Sysmon EventData record as a dict,
mirroring windows_eventlog.py's convention (the shape a WEF/JSON forwarder
or this repo's own EVTX/Splunk-XML extractor produces), e.g.::

    {"EventID": 1, "TimeCreated": 1750000000000, "Computer": "wks-jdoe",
     "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami",
     "ProcessId": "1234", "ParentImage": "C:\\...\\explorer.exe",
     "ParentProcessId": "800", "User": "CORP\\jdoe", "Hashes": "SHA256=..."}

    {"EventID": 3, "TimeCreated": ..., "Computer": "wks-jdoe",
     "Image": "C:\\...\\powershell.exe", "User": "CORP\\jdoe",
     "SourceIp": "10.0.1.15", "SourcePort": "51000", "SourceHostname": "wks-jdoe",
     "DestinationIp": "203.0.113.9", "DestinationPort": "443",
     "DestinationHostname": "evil.example"}

    {"EventID": 11, "TimeCreated": ..., "Computer": "wks-jdoe",
     "Image": "C:\\...\\powershell.exe", "TargetFilename": "C:\\Users\\...\\payload.exe",
     "User": "CORP\\jdoe"}
"""
from __future__ import annotations

import json
import time
from typing import Optional

from .base import Parser, SEV_INFO, SEV_MEDIUM
from shared.ocsf import valid_ip, safe_str
from .timeutil import to_epoch_ms

_CLS_PROC = 1002    # Kernel / Process
_CLS_NET = 4001     # Network Activity
_CLS_FILE = 1001    # File System Activity

_ACT_PROC_LAUNCH = 1   # matches windows_eventlog.py's own convention

# Network Activity (4001): 6=Deny, 7=Accept, per ocsf-classes.md / cisco_asa.py's
# existing convention. Sysmon EventID 3 only fires on an ESTABLISHED connection
# (the OS already accepted it), so this is always 7/Accept, never 6/Deny.
_ACT_NET_ACCEPT = 7

# File System Activity (1001): this parser is the FIRST producer, so no prior
# convention to match -- 1=Create mirrors Account Change's own "1 Create".
_ACT_FILE_CREATE = 1

_EVENT_MAP = {
    1: (_CLS_PROC, _ACT_PROC_LAUNCH, SEV_INFO, "Process created"),
    3: (_CLS_NET, _ACT_NET_ACCEPT, SEV_INFO, "Network connection"),
    11: (_CLS_FILE, _ACT_FILE_CREATE, SEV_MEDIUM, "File created"),
}


class SysmonParser(Parser):
    SOURCE_TYPE = "sysmon"
    SECTOR = "common"
    ORIGINAL_FORMAT = "winevent"
    PRODUCT = {"name": "Sysmon", "vendor_name": "Microsoft Sysinternals"}

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
        if mapping is None:
            return None
        class_uid, activity_id, severity_id, verb = mapping

        time_ms = self._epoch_ms(rec.get("TimeCreated") or meta.get("received_at"))
        host = safe_str(rec.get("Computer"))
        user = safe_str(rec.get("User"))
        image = safe_str(rec.get("Image"))
        pid = self._parse_pid(rec.get("ProcessId"))

        if class_uid == _CLS_PROC:
            message = f"{verb}: {image or '?'} (by {user or '?'})"
        elif class_uid == _CLS_NET:
            dst_ip = valid_ip(rec.get("DestinationIp"))
            message = f"{verb} from {image or '?'}"
            if dst_ip:
                message += f" to {dst_ip}"
        else:  # _CLS_FILE
            target = safe_str(rec.get("TargetFilename"))
            message = f"{verb}: {target or '?'} (by {image or '?'})"

        event = self.base_event(
            class_uid=class_uid,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=time_ms,
            ingest_id=meta.get("ingest_id"),
            logged_time=self._epoch_ms(meta.get("received_at")) if meta.get("received_at") else None,
            status="Success",
            message=message,
            meta=meta,
            sector=self.resolve_sector(meta),
        )

        # actor: the process that did the thing, on every event type -- Sysmon's
        # one consistent identity (Image/ProcessId/User), unlike Security-channel
        # events where actor shape varies by class.
        actor: dict = {}
        if user:
            actor["user"] = {"name": user}
        if image or pid is not None:
            proc: dict = {}
            if image:
                proc["name"] = image
            if pid is not None:
                proc["pid"] = pid
            actor["process"] = proc
        if actor:
            event["actor"] = actor

        if class_uid == _CLS_NET:
            src: dict = {}
            src_ip = valid_ip(rec.get("SourceIp"))
            src_host = safe_str(rec.get("SourceHostname")) or host
            if src_ip:
                src["ip"] = src_ip
            if src_host:
                src["hostname"] = src_host
            src_port = self._parse_port(rec.get("SourcePort"))
            if src_port is not None:
                src["port"] = src_port
            if src:
                event["src_endpoint"] = src

            dst: dict = {}
            dst_ip = valid_ip(rec.get("DestinationIp"))
            dst_host = safe_str(rec.get("DestinationHostname"))
            if dst_ip:
                dst["ip"] = dst_ip
            if dst_host:
                dst["hostname"] = dst_host
            dst_port = self._parse_port(rec.get("DestinationPort"))
            if dst_port is not None:
                dst["port"] = dst_port
            if dst:
                event["dst_endpoint"] = dst
        elif host:
            # Process/file events have no network direction; the host they ran
            # on stays on src_endpoint, matching windows_eventlog.py's own
            # convention for its non-auth (process) event classes.
            event["src_endpoint"] = {"hostname": host}

        if class_uid == _CLS_FILE:
            target = safe_str(rec.get("TargetFilename"))
            if target:
                event["unmapped"] = {"target_filename": target}

        return event

    # ---- helpers ------------------------------------------------------

    @staticmethod
    def _epoch_ms(value) -> int:
        return to_epoch_ms(value) or int(time.time() * 1000)

    @staticmethod
    def _parse_pid(value) -> Optional[int]:
        """Sysmon logs ProcessId as a plain decimal string or int (unlike
        Windows Security's occasional hex "0x1f4" -- ProcessId here is
        always decimal in real Sysmon output)."""
        if value is None:
            return None
        if isinstance(value, int):
            return value
        try:
            return int(str(value).strip())
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_port(value) -> Optional[int]:
        if value is None:
            return None
        try:
            port = int(str(value).strip())
        except (ValueError, TypeError):
            return None
        return port if 0 <= port <= 65535 else None
