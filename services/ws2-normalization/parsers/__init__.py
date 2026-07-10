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

_REGISTRY: dict[str, Parser] = {
    p.SOURCE_TYPE: p
    for p in (CiscoAsaParser(), ActiveDirectoryParser(), VmwareVsphereParser(),
              LinuxSshParser(), GenericSyslogParser(), WindowsEventLogParser(),
              DbAuditParser(), McpAgentParser(), OpcUaAuditParser())
}


def get_parser(source_type: str) -> Optional[Parser]:
    return _REGISTRY.get(source_type)


def resolve(raw_payload: dict) -> Optional[Parser]:
    """Pick a parser for a raw.events payload (exact source_type, else content sniff)."""
    st = raw_payload.get("source_type", "")
    parser = _REGISTRY.get(st)
    if parser is not None:
        return parser
    raw = raw_payload.get("raw")
    text = raw if isinstance(raw, str) else json.dumps(raw)
    if st.startswith("syslog") and "%ASA" in text:
        return _REGISTRY["cisco_asa"]
    if "sshd[" in text or "pam_unix(sshd:" in text:
        return _REGISTRY["linux_ssh"]
    if "EventID" in text:
        return _REGISTRY["active_directory"]
    if '"tool"' in text and ('"arguments"' in text or '"args"' in text):
        return _REGISTRY["mcp_agent"]
    if '"eventType"' in text and "Audit" in text:
        return _REGISTRY["opcua_audit"]
    if '"operation"' in text:
        return _REGISTRY["vmware_vsphere"]
    return None


def known_sources() -> list[str]:
    return sorted(_REGISTRY)
