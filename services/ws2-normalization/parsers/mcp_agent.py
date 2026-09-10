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

v0.5 M3 (combined roadmap, PLAN_A P3 R4/R5) extends the same pattern with two
more fields:

    unmapped.mcp.destructive_command_indicator: bool  -- R5: rm -rf/DROP
        TABLE/format/mkfs-shaped content in tool arguments. Single-shot
        (unlike dc_mass_vm_delete.yml's 5-in-120s burst threshold): a single
        destructive command from an agent is already the signal, worth
        flagging immediately rather than waiting for a repeat.
    unmapped.mcp.egress_domain: str | None  -- R4: the hostname parsed from
        an arguments.url/uri/endpoint field, when the tool call carries one.
        unmapped.mcp.is_egress_call: bool -- true only when a real domain was
        parsed (a tool NAME merely suggesting network egress with no
        parseable URL does not set this -- would wrongly gate the R4 rule
        open with nothing to check against the allowlist). Reuses the
        engine's existing not_in/Allowlist mechanism (contracts/allowlists/)
        rather than adding new engine logic -- the rule combines the
        is-egress-call gate with a `not_in` clause against an
        operator-populated domain allowlist.
"""
from __future__ import annotations

import base64
import json
import re
import time
import unicodedata
import urllib.parse
from typing import Optional

from .base import Parser, SEV_HIGH, SEV_INFO, SEV_MEDIUM, status_from_outcome
from .timeutil import to_epoch_ms
from shared.ocsf import valid_ip

_CLASS = 6003  # API Activity

# FIX L3: "put"/"add" are short enough that plain substring containment matches
# them inside unrelated tool names (compute, output, status, addon, address),
# misclassifying routine read tool-calls as Create. Longer verbs stay substring
# (write/create/insert are low-risk), while the short ones are matched as
# standalone tokens -- the same discipline the _RM_TOKEN fix (N1) applied to
# "rm" -- so "object_put"/"put_object" still classify as Create but "compute"/
# "output" don't.
_WRITE_KEYWORDS = ("write", "create", "insert")
_WRITE_TOKENS = ("put", "add")
_UPDATE_KEYWORDS = ("update", "edit", "modify", "patch", "rename")
# N1 (2026-07-30 audit): "delete"/"remove"/"drop" are long enough that plain
# substring containment is low-risk, but the 2-char "rm" matched inside many
# unrelated tool names (perform_backup, format_report, confirm_action,
# terminate_session, warm_cache all naturally contain "rm" mid-word) --
# mislabeling routine tool calls as destructive deletes. "rm" is checked
# separately as its own token (split on _/-/whitespace/./:/camelCase), not by
# substring. The split set includes "."/":" (round-2 gap: a first cut only
# split on _/-/whitespace/camelCase, so dot- or colon-namespaced names like
# "resource.rm"/"fs:rm" fell through neither the substring list nor the
# tokenizer and silently escaped delete-classification).
_DELETE_KEYWORDS = ("delete", "remove", "drop")
_RM_TOKEN = "rm"
_TOKEN_SPLIT_RE = re.compile(r"[_\-\s.:]+|(?<=[a-z0-9])(?=[A-Z])")


def _tokenize(tool: str) -> list:
    return [t.lower() for t in _TOKEN_SPLIT_RE.split(tool) if t]

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
# description says. 2026-09-10: broadened with the documented synonym set
# and the German equivalent tested by eval/adversarial/mutate.py's
# equivalent_phrasing/language_switch variants (Phase 4 measured this rule
# at 0/2 against those two specifically). Still a finite, bounded list, not
# a claim of covering every phrasing or every language -- a semantic
# classifier would generalize further and remains a documented future
# option, not built here.
_INJECTION_PATTERNS = re.compile(
    r"(ignore (all )?previous instructions|"
    r"disregard (all |the )?(previous instructions|system prompt)|"
    r"disclose (the )?(system )?prompt|reveal your (system )?prompt|"
    r"you are now|new instructions:|act as if you have no restrictions|"
    r"ignoriere (alle )?vorherigen anweisungen|nenne deinen system-prompt)",
    re.IGNORECASE,
)

# R5: heuristic patterns for a catastrophically destructive command/query in
# tool-call content. Deliberately simple/documented (bounded alternation, no
# nested quantifiers -- no ReDoS risk on attacker-controlled arguments),
# same discipline as the credential/injection patterns above.
_DESTRUCTIVE_COMMAND_PATTERNS = re.compile(
    r"(rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r|"
    r"drop\s+(table|database|schema)|truncate\s+table|delete\s+from\s+\w+\s*;?\s*$|"
    r"format\s+[a-z]:|mkfs(\.\w+)?\s+/dev|:\(\)\{\s*:\|:&\s*\};:)",
    re.IGNORECASE,
)

_MAX_ARGS_CHARS = 2000  # arguments are attacker-controlled -- cap, never eval.

# 2026-09-10: bounded, deterministic normalization pass closing the encoding-
# evasion gap eval/adversarial/mutate.py::mutate_prompt's "prompt" axis
# measured and disclosed (Phase 4, 2026-09-03): 6 of 10 content mutations
# (Cyrillic homoglyphs, URL-encoding, base64 wrapping, run-together
# whitespace, plus the two phrasing variants the pattern list above now
# covers directly) defeated the plain-ASCII regex below. This does not
# widen the regex itself -- it widens what text gets searched, by decoding/
# folding the SAME attacker-controlled string through the specific
# transforms the harness tests, then scanning original + every decoded
# variant. Still a heuristic, still documented as one (see the rule
# descriptions and docs/agent-monitoring.md) -- not a claim this closes
# every possible encoding, just the measured, disclosed ones plus their
# near neighbors.
_HOMOGLYPH_FOLD = str.maketrans({
    # Cyrillic look-alikes (the exact pair eval/adversarial/mutate.py's
    # unicode_confusables variant uses is і/о; the rest are the
    # same visual-confusable family, most likely to appear alongside them).
    "і": "i", "І": "I",
    "о": "o", "О": "O",
    "а": "a", "А": "A",
    "е": "e", "Е": "E",
    "р": "p", "Р": "P",
    "с": "c", "С": "C",
    "у": "y", "У": "Y",
    "х": "x", "Х": "X",
    # Greek look-alikes, same rationale.
    "ο": "o", "Ο": "O",
    "α": "a", "Α": "A",
})

_WHITESPACE_RUN_RE = re.compile(r"\s+")
# Base64 detection is intentionally narrow: a 16+ char run of base64-alphabet
# characters (with optional padding). Short runs risk false-positive decodes
# of ordinary alphanumeric tokens (session IDs, hashes) into garbage, which
# _decoded_variants already tolerates (decode failure -> skipped, not
# raised) but there is no reason to spend the cycles on tokens too short to
# plausibly carry a wrapped phrase.
_B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _decoded_variants(text: str) -> list:
    """Bounded, deterministic alternate readings of attacker-controlled
    text, for the heuristic classifiers below to scan ALONGSIDE the
    original -- never replacing it, so nothing that matched before this
    fix stops matching now."""
    variants = []
    folded = unicodedata.normalize("NFKC", text).translate(_HOMOGLYPH_FOLD)
    folded = _WHITESPACE_RUN_RE.sub(" ", folded)
    variants.append(folded)
    try:
        decoded = urllib.parse.unquote(text, errors="strict")
        if decoded != text:
            variants.append(decoded)
    except (UnicodeDecodeError, ValueError):
        pass
    for token in _B64_TOKEN_RE.findall(text):
        try:
            variants.append(base64.b64decode(token, validate=True).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
    return variants


def _scan_text(text: str) -> str:
    """The corpus R1/R3/R5 search: the original text plus every decoded/
    normalized variant, newline-joined so a pattern spanning a decode
    boundary can't accidentally splice two variants into a false match."""
    return "\n".join([text] + _decoded_variants(text))


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
            meta=meta,
            sector=self.resolve_sector(meta),
        )
        event["api"] = {"operation": str(tool),
                        "request": {"data": args_text}}
        if agent or session:
            event["actor"] = {"user": {"name": str(agent or session)}}
        src_ip = valid_ip(_pick(rec, "src_ip", "client_ip", "ip") or meta.get("ip"))
        if src_ip:
            event["src_endpoint"] = {"ip": src_ip}

        egress_domain = self._egress_domain(str(tool), arguments)
        scan_text = _scan_text(args_text)
        unmapped: dict = {"mcp": {
            "session_id": session,
            "server": server,
            "credential_path_access": bool(_CREDENTIAL_PATH_PATTERNS.search(scan_text)),
            "injection_indicator": bool(_INJECTION_PATTERNS.search(scan_text)),
            "destructive_command_indicator": bool(_DESTRUCTIVE_COMMAND_PATTERNS.search(scan_text)),
            "is_egress_call": egress_domain is not None,
        }}
        if egress_domain is not None:
            unmapped["mcp"]["egress_domain"] = egress_domain
        event["unmapped"] = unmapped

        return event

    @staticmethod
    def _egress_domain(tool: str, arguments) -> Optional[str]:
        """R4: the hostname a network-egress-shaped tool call is reaching, or
        None if this call isn't recognizable as network egress. Prefers an
        explicit url/uri/endpoint argument (most MCP fetch-style tools carry
        one); falls back to nothing if the tool name merely LOOKS like an
        egress tool but carries no parseable URL -- a false 'is_egress_call'
        would wrongly gate the R4 rule open on calls with no real domain to
        check against the allowlist."""
        if isinstance(arguments, dict):
            url = _pick(arguments, "url", "uri", "endpoint", "target_url")
            if isinstance(url, str) and url:
                try:
                    host = urllib.parse.urlsplit(url).hostname
                except ValueError:
                    host = None
                if host:
                    return host.lower()
        return None

    @staticmethod
    def _classify(tool: str):
        t = tool.lower()
        for kw in _DELETE_KEYWORDS:
            if kw in t:
                return 4, SEV_HIGH
        if _RM_TOKEN in _tokenize(tool):
            return 4, SEV_HIGH
        for kw in _UPDATE_KEYWORDS:
            if kw in t:
                return 3, SEV_MEDIUM
        for kw in _WRITE_KEYWORDS:
            if kw in t:
                return 1, SEV_MEDIUM
        # FIX L3: short write verbs matched as standalone tokens (not substring).
        if any(tok in _tokenize(tool) for tok in _WRITE_TOKENS):
            return 1, SEV_MEDIUM
        return 2, SEV_INFO  # default: Read

    @staticmethod
    def _args_text(arguments) -> str:
        try:
            # ensure_ascii=False: the default True would \uXXXX-escape any
            # non-ASCII byte (a Cyrillic/Greek homoglyph included) into
            # literal backslash-u text -- silently defeating
            # _HOMOGLYPH_FOLD, which folds real Unicode codepoints, not
            # their escaped ASCII spelling. 2026-09-10, found writing the
            # test for the fold: the fold worked in isolation but not
            # through this path, because json.dumps was mangling the input
            # before the fold ever saw it.
            text = (json.dumps(arguments, ensure_ascii=False)
                     if not isinstance(arguments, str) else arguments)
        except (TypeError, ValueError):
            text = str(arguments)
        return text[:_MAX_ARGS_CHARS]

    @staticmethod
    def _time_ms(rec: dict, meta: dict) -> int:
        return (to_epoch_ms(rec.get("ts"))
                or to_epoch_ms(rec.get("timestamp"))
                or to_epoch_ms(meta.get("received_at"))
                or int(time.time() * 1000))

    @staticmethod
    def _logged_time(rec: dict, meta: dict) -> Optional[int]:
        return to_epoch_ms(meta.get("received_at"))
