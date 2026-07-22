"""WS-2 parser registry.

One parser per source type. Adding a source = add a module + register it here;
no existing parser is touched. ``get_parser(source_type)`` returns an instance or
``None`` if unknown. ``resolve(raw_payload)`` adds a content sniff so a protocol-level
source (e.g. ``syslog_rfc5424``) is routed to the right product parser.
"""
from __future__ import annotations

import json
from typing import Optional

from .base import Parser
from .cisco_asa import CiscoAsaParser
from .active_directory import ActiveDirectoryParser
from .vmware_vsphere import VmwareVsphereParser
from .linux_ssh import LinuxSshParser
from .generic_syslog import GenericSyslogParser
from .windows_eventlog import WindowsEventLogParser
from .db_audit import DbAuditParser
from .mcp_agent import McpAgentParser
from .opcua_audit import OpcUaAuditParser
from .n8n_audit import N8nAuditParser
from .dns_query import DnsQueryParser
from .k8s_audit import K8sAuditParser
from .cef import CefParser
from .cloudtrail import CloudTrailParser
from .sysmon import SysmonParser
from .plugins import discover_plugin_parsers

_REGISTRY: dict[str, Parser] = {
    p.SOURCE_TYPE: p
    for p in (CiscoAsaParser(), ActiveDirectoryParser(), VmwareVsphereParser(),
              LinuxSshParser(), GenericSyslogParser(), WindowsEventLogParser(),
              DbAuditParser(), McpAgentParser(), OpcUaAuditParser(), N8nAuditParser(),
              DnsQueryParser(), K8sAuditParser(), CefParser(), CloudTrailParser(),
              SysmonParser())
}

# M4.5: external pip packages can register additional parsers (docs/plugin-
# development.md) via the "fengarde.parsers" entry-point group. Purely
# additive -- a plugin can never override a built-in SOURCE_TYPE (see
# discover_plugin_parsers' docstring). No installed plugins -> this is a
# no-op, zero behavior change (the common case; this repo ships none).
_REGISTRY.update(discover_plugin_parsers(set(_REGISTRY)))


def get_parser(source_type: str) -> Optional[Parser]:
    return _REGISTRY.get(source_type)


# --- content-sniff discriminators (used only when source_type is unknown) -----
# EventIDs the AD parser owns; every OTHER EventID goes to windows_eventlog (its
# superset producer). Previously ANY "EventID" substring routed to AD, so a
# windows-only 4688/4720/... hit AD, returned None, and was dropped.
_AD_EVENTIDS = {4624, 4634, 4647, 4625, 4768, 4771}
# P0-3: Sysmon (Microsoft-Windows-Sysmon/Operational) uses the SAME "EventID"
# field name as the Security channel but a disjoint, low-numbered ID space
# (1-29ish vs. Security's 4-thousand range) -- no numeric collision with
# _AD_EVENTIDS or windows_eventlog._EVENT_MAP. Checked explicitly (not left to
# the windows_eventlog fallback) so a sysmon.py-shaped payload without an
# explicit source_type doesn't silently dead-letter through the wrong parser.
_SYSMON_EVENTIDS = {1, 3, 11}
# operation verbs unique to each of the two class-sharing "operation" parsers.
# Shared verbs (delete/update) are deliberately absent -- a bare "delete" with no
# discriminating field is genuinely ambiguous and must NOT be silently guessed.
_DB_ONLY_VERBS = ("grant", "revoke", "alter", "select", "insert", "drop", "query")
_VMWARE_ONLY_VERBS = ("deploy", "read", "get", "reconfig", "destroy", "remove",
                      "create", "clone", "migrate", "poweron", "poweroff")


def _as_record(raw) -> Optional[dict]:
    """Return the structured record dict from a raw payload, or None if it isn't
    JSON-object-shaped (a plain syslog text line is not)."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.lstrip().startswith("{"):
        try:
            obj = json.loads(raw)
            return obj if isinstance(obj, dict) else None
        except (ValueError, TypeError):
            return None
    return None


def _resolve_structured(rec: dict) -> Optional[Parser]:
    """Route a structured (JSON) record by SPECIFIC fields/values, never by a
    substring of a value (which attacker-controlled log content could spoof).
    Returns None when routing is genuinely ambiguous, so main() dead-letters it
    with a "set source_type" hint instead of silently mis-parsing."""
    # MCP/agent tool-call audit
    if "tool" in rec and ("arguments" in rec or "args" in rec):
        return _REGISTRY["mcp_agent"]
    # k8s audit event: auditID is unique to the k8s audit-log schema.
    if "auditID" in rec:
        return _REGISTRY["k8s_audit"]
    # AWS CloudTrail record: this exact field combo is CloudTrail-specific.
    if "eventName" in rec and "eventSource" in rec and "eventTime" in rec:
        return _REGISTRY["cloudtrail"]
    # eventType: OPC UA (CamelCase Audit*EventType) vs n8n (dotted lower-case)
    et = rec.get("eventType") or rec.get("event_type") or rec.get("type")
    if isinstance(et, str) and et:
        if et.startswith("Audit") and et.endswith("EventType"):
            return _REGISTRY["opcua_audit"]
        if "." in et or et in ("login", "logout") or "workflowId" in rec or "webhook" in rec:
            return _REGISTRY["n8n_audit"]
        if "nodeId" in rec or "sourceName" in rec:
            return _REGISTRY["opcua_audit"]
        return _REGISTRY["n8n_audit"]
    # Windows Event Log vs Active Directory by EventID VALUE
    eid = rec.get("EventID")
    if isinstance(eid, (int, str)) and not isinstance(eid, bool):
        try:
            eid_i = int(eid)
        except (ValueError, TypeError):
            eid_i = None
        if eid_i is not None:
            if eid_i in _AD_EVENTIDS:
                return _REGISTRY["active_directory"]
            if eid_i in _SYSMON_EVENTIDS:
                return _REGISTRY["sysmon"]
            return _REGISTRY["windows_eventlog"]  # superset; None -> honest DLQ
    # DB audit vs vSphere (both class-share on "operation") by verb + fields
    if "operation" in rec:
        op = str(rec.get("operation") or "").lower()
        db_ish = any(v in op for v in _DB_ONLY_VERBS) or "object" in rec or "table" in rec
        vm_ish = (any(v in op for v in _VMWARE_ONLY_VERBS) or "." in op
                  or "vm" in rec or "target" in rec or "createdTime" in rec)
        if db_ish and not vm_ish:
            return _REGISTRY["db_audit"]
        if vm_ish and not db_ish:
            return _REGISTRY["vmware_vsphere"]
        return None  # ambiguous -> dead-letter, don't corrupt
    return None


def resolve(raw_payload: dict) -> Optional[Parser]:
    """Pick a parser for a raw.events payload.

    ``source_type`` is authoritative (exact registry match). Content-sniff is a
    best-effort fallback for protocol-level sources whose product isn't named; it
    routes on specific fields/values, keeps every registered parser reachable, and
    returns None (-> dead-letter) rather than silently mis-routing an ambiguous
    payload.
    """
    st = raw_payload.get("source_type", "") or ""
    parser = _REGISTRY.get(st)
    if parser is not None:
        return parser
    raw = raw_payload.get("raw")
    # Text-line sources (raw is a syslog string, not JSON).
    if isinstance(raw, str) and not raw.lstrip().startswith("{"):
        if raw.startswith("CEF:"):
            return _REGISTRY["cef"]
        if "%ASA-" in raw or "%ASA" in raw:
            return _REGISTRY["cisco_asa"]
        if "sshd[" in raw or "pam_unix(sshd:" in raw:
            return _REGISTRY["linux_ssh"]
        if "query[" in raw and " from " in raw:
            return _REGISTRY["dns_query"]
        return _REGISTRY["generic_syslog"]  # catch-all syslog is now reachable
    rec = _as_record(raw)
    if rec is None:
        return None
    return _resolve_structured(rec)


def known_sources() -> list[str]:
    return sorted(_REGISTRY)
