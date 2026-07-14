"""MCP/AI-agent audit-log parser: tool-call logs -> OCSF API Activity (6003).

No open-source SIEM ships detection content for AI-agent telemetry (v0.4
Track P1 — the market-analysis "attention play"). There is no single standard
MCP server log format yet; this parser defines and documents the shape it
accepts, following an MCP-server/gateway's natural JSON-RPC `tools/call`
record shape rather than inventing something exotic:

    {"ts": 1751500000000, "session_id": "sess-42", "agent": "claude-code",
     "server": "filesystem", "tool": "read_file",
     "arguments": {"path": "/home/user/.aws/credentials"},
     "outcome": "success"}

Vendor field-name variance is tolerated via a small alias map (`_pick`) --
this is a log parser, not an MCP client; it never talks to a live MCP server.

Activity_id mapping (Contract A / ocsf-classes.md, API Activity):
    2 Read (default -- most tool calls query/inspect)
    1 Create, 3 Update, 4 Delete -- inferred from a write/mutate keyword in
    the tool name (mirrors db_audit.py's operation-keyword approach)

Detection substrate (v0.4 Track P1 rule pack): the ENGINE only does equality/
comparison/allowlist matching (no substring "contains" operator, per
contracts/sigma-convention.md) -- so pattern classification (credential-path
access, prompt-injection markers) happens HERE at parse time, exposed as
simple booleans the rules equality-match on:

    unmapped.mcp.credential_path_access: bool
    unmapped.mcp.injection_indicator: bool

Both are heuristic, string-match classifiers -- labeled as such in the rule
descriptions, not sold as an ML capability.
"""
from __future__ import annotations

import json
import re
import time
from typing import Optional

from .base import Parser, SEV_HIGH, SEV_INFO, SEV_MEDIUM, status_from_outcome

_CLASS = 6003  # API Activity

_WRITE_KEYWORDS = ("write", "create", "insert", "add", "put")
_UPDATE_KEYWORDS = ("update", "edit", "modify", "patch", "rename")
_DELETE_KEYWORDS = ("delete", "remove", "rm", "drop")

# Heuristic path patterns that indicate a tool call is touching secret
# material. Deliberately simple/documented, not a security boundary on its
# own -- the rule that consumes this flag says so too.
_CREDENTIAL_PATH_PATTERNS = re.compile(
    r"(\.env\b|id_rsa|id_ed25519|\.aws[/\\]credentials|\.ssh[/\\]|"
    r"secrets?\.(ya?ml|json|txt)|credentials\.(ya?ml|json)|\.pem$|\.key$|"
    r"\.kube[/\\]config|\.netrc\b)",
    re.IGNORECASE,
)

# Common prompt-injection phrasing seen in log-line/tool-arg content. A
# heuristic string-match, not a classifier -- exactly what the rule's
# description says.
_INJECTION_PATTERNS = re.compile(
    r"(ignore (all )?previous instructions|disregard (the )?system prompt|"
    r"you are now|new instructions:|reveal your (system )?prompt|"
    r"act as if you have no restrictions)",
    re.IGNORECASE,
)

_MAX_ARGS_CHARS = 2000  # arguments are attacker-controlled -- cap, never eval.


def _pick(rec: dict, *keys):
    for k in keys:
        if k in rec and rec[k] is not None:
            return rec[k]
    return None


class McpAgentParser(Parser):
    SOURCE_TYPE = "mcp_agent"
    SECTOR = "common"
    ORIGINAL_FORMAT = "json"
    PRODUCT = {"name": "MCP Agent Gateway", "vendor_name": "generic"}

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

        tool = _pick(rec, "tool", "tool_name", "name")
        if not tool:
            return None  # not a recognizable tool-call record

        session = _pick(rec, "session_id", "session", "sessionId")
        agent = _pick(rec, "agent", "agent_id", "agentId")
        server = _pick(rec, "server", "mcp_server", "server_name")
        arguments = _pick(rec, "arguments", "args", "params") or {}

        activity_id, severity_id = self._classify(str(tool))
        args_text = self._args_text(arguments)

        time_ms = self._time_ms(rec, meta)
        verb = {1: "created via", 2: "called (read)", 3: "updated via", 4: "deleted via"}[activity_id]
        message = f"MCP tool {tool} {verb} agent {agent or session or '?'}"

        event = self.base_event(
            class_uid=_CLASS,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=time_ms,
            ingest_id=meta.get("ingest_id"),
            logged_time=self._logged_time(rec, meta),
            status=status_from_outcome(rec, keys=("outcome", "status")),
            message=message,
        )
        event["api"] = {"operation": str(tool),
                        "request": {"data": args_text}}
        if agent or session:
            event["actor"] = {"user": {"name": str(agent or session)}}
        src_ip = _pick(rec, "src_ip", "client_ip", "ip") or meta.get("ip")
        if src_ip:
            event["src_endpoint"] = {"ip": src_ip}

        unmapped: dict = {"mcp": {
            "session_id": session,
            "server": server,
            "credential_path_access": bool(_CREDENTIAL_PATH_PATTERNS.search(args_text)),
            "injection_indicator": bool(_INJECTION_PATTERNS.search(args_text)),
        }}
        event["unmapped"] = unmapped

        return event

    @staticmethod
    def _classify(tool: str):
        t = tool.lower()
        for kw in _DELETE_KEYWORDS:
            if kw in t:
                return 4, SEV_HIGH
        for kw in _UPDATE_KEYWORDS:
            if kw in t:
                return 3, SEV_MEDIUM
        for kw in _WRITE_KEYWORDS:
            if kw in t:
                return 1, SEV_MEDIUM
        return 2, SEV_INFO  # default: Read

    @staticmethod
    def _args_text(arguments) -> str:
        try:
            text = json.dumps(arguments) if not isinstance(arguments, str) else arguments
        except (TypeError, ValueError):
            text = str(arguments)
        return text[:_MAX_ARGS_CHARS]

    @staticmethod
    def _time_ms(rec: dict, meta: dict) -> int:
        ts = rec.get("ts") or rec.get("timestamp") or meta.get("received_at")
        if isinstance(ts, (int, float)):
            return int(ts * 1000) if ts < 1e12 else int(ts)
        return int(time.time() * 1000)

    @staticmethod
    def _logged_time(rec: dict, meta: dict) -> Optional[int]:
        lt = meta.get("received_at")
        if isinstance(lt, (int, float)):
            return int(lt * 1000) if lt < 1e12 else int(lt)
        return None
