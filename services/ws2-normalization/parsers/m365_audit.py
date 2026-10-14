"""Microsoft 365 unified audit log parser -> OCSF.

Built 2026-10-14 (owner decision: build the mail-gateway and M365 parsers the
phishing_bec storyline declared as placeholders). The record shape is the
publicly documented Office 365 Management Activity API common schema
(Operation, Workload, UserId, ClientIP, CreationTime, Parameters as a list of
{Name, Value}); fixtures are spec-derived, same discipline as cloudtrail.py --
not captured from a real tenant.

Mapping (Contract A / ocsf-classes.md):
    Operation UserLoggedIn / UserLoginFailed -> 3002 Authentication,
        activity 1 Logon / 4 Failure.
    every other Operation -> 6003 API Activity, activity from the cmdlet verb
        (New/Add/Enable -> 1 Create, Get/Search -> 2 Read, Set/Update/
        Disable -> 3 Update, Remove -> 4 Delete, default 2 Read).

Mailbox-rule operations (New-/Set-InboxRule, Set-Mailbox forwarding) carry the
rule's effect under ``unmapped.m365.inbox_rule``: where it forwards to,
whether the target is OUTSIDE the user's own domain, and whether it hides mail
(delete / move to a rarely read folder / mark as read) -- the T1114.003
"forwarding rule" shape. This parser only reports those facts; no rule is
shipped over them yet (a declared gap, contracts/detection-coverage.md).

``Parameters`` is attacker-influenced text (a rule an intruder writes): it is
read as data, length-capped, never evaluated.
"""
from __future__ import annotations

import json
import time
from typing import Iterable, Optional

from .base import Parser, SEV_BY_CATEGORY, SEV_HIGH, SEV_INFO
from .timeutil import to_epoch_ms
from shared.ocsf import valid_ip, safe_str

_CLASS_AUTH = 3002
_CLASS_API = 6003
_MAX_PARAM_CHARS = 512

_VERB_TO_ACTIVITY = (
    (("New-", "Add-", "Enable-"), 1, "write"),
    (("Get-", "Search-"), 2, "read"),
    (("Set-", "Update-", "Disable-"), 3, "modify"),
    (("Remove-",), 4, "destroy"),
)
# Rule-like operations whose parameters describe where mail goes.
_RULE_OPS = frozenset({"New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox"})
_FORWARD_KEYS = ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "ForwardingSmtpAddress",
                 "ForwardingAddress")
# Folders an intruder moves replies into so the victim does not see them.
_HIDING_FOLDERS = frozenset({"rss feeds", "rss subscriptions", "archive", "deleted items",
                             "junk email", "conversation history"})


def _params(raw) -> dict:
    """Parameters as {name: value}. The API emits a list of {Name, Value};
    exports and test fixtures often flatten it to a dict. Anything else -> {}."""
    out: dict = {}
    items: Iterable[tuple]
    if isinstance(raw, dict):
        items = raw.items()
    elif isinstance(raw, list):
        items = ((p.get("Name"), p.get("Value")) for p in raw if isinstance(p, dict))
    else:
        return out
    for k, v in items:
        if isinstance(k, str) and k:
            out[k] = v
    return out


def _addresses(value) -> list[str]:
    """Forwarding targets: a string ("a@x;b@y" or "smtp:a@x") or a list of them."""
    vals = value if isinstance(value, list) else [value]
    out = []
    for v in vals:
        if not isinstance(v, str):
            continue
        for part in v.replace(",", ";").split(";"):
            part = part.strip()
            if part.lower().startswith("smtp:"):
                part = part[5:]
            if "@" in part:
                out.append(part[:_MAX_PARAM_CHARS].lower())
    return out


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip().lower() if "@" in addr else ""


def _truthy(v) -> bool:
    return v is True or (isinstance(v, str) and v.strip().lower() in ("true", "1", "yes"))


def _inbox_rule(op: str, params: dict, user: str) -> Optional[dict]:
    if op not in _RULE_OPS:
        return None
    targets = []
    for key in _FORWARD_KEYS:
        targets += _addresses(params.get(key))
    own = _domain(user)
    folder = params.get("MoveToFolder")
    folder = folder.strip().lower() if isinstance(folder, str) else ""
    hides = (_truthy(params.get("DeleteMessage")) or _truthy(params.get("MarkAsRead"))
             or folder in _HIDING_FOLDERS)
    return {
        "name": (safe_str(params.get("Name")) or "")[:_MAX_PARAM_CHARS] or None,
        "forward_to": sorted(set(targets)),
        # unknown own domain -> cannot call anything external; stay False (no guess)
        "forwards_external": bool(own) and any(_domain(t) != own for t in targets),
        "hides_mail": hides,
    }


def _client_ip(raw) -> Optional[str]:
    """ClientIP is "1.2.3.4", "1.2.3.4:5678" or "[2001:db8::1]:443" in real logs."""
    if not isinstance(raw, str):
        return valid_ip(raw)
    s = raw.strip()
    if s.startswith("[") and "]" in s:
        s = s[1:s.index("]")]
    elif s.count(":") == 1:
        s = s.split(":", 1)[0]
    return valid_ip(s)


class M365AuditParser(Parser):
    SOURCE_TYPE = "m365_audit"
    SECTOR = "common"
    ORIGINAL_FORMAT = "json"
    PRODUCT = {"name": "Microsoft 365 Unified Audit Log", "vendor_name": "Microsoft"}

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
        op = rec.get("Operation")
        if not isinstance(op, str) or not op:
            return None
        user = safe_str(rec.get("UserId")) or ""

        if op in ("UserLoggedIn", "UserLoginFailed"):
            class_uid, activity_id = _CLASS_AUTH, (1 if op == "UserLoggedIn" else 4)
            status = "Success" if op == "UserLoggedIn" else "Failure"
            severity_id = SEV_INFO if status == "Success" else SEV_HIGH
        else:
            class_uid, status = _CLASS_API, "Success"
            activity_id, severity_id = 2, SEV_BY_CATEGORY["read"]
            for prefixes, act, category in _VERB_TO_ACTIVITY:
                if op.startswith(prefixes):
                    activity_id, severity_id = act, SEV_BY_CATEGORY[category]
                    break
            if op == "UpdateInboxRules":           # Outlook-client rule edits
                activity_id, severity_id = 3, SEV_BY_CATEGORY["modify"]
            result = rec.get("ResultStatus")
            if isinstance(result, str) and result.lower() in ("failed", "failure", "false"):
                status = "Failure"

        event = self.base_event(
            class_uid=class_uid,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=self._time_ms(rec, meta),
            ingest_id=meta.get("ingest_id") or safe_str(rec.get("Id")),
            status=status,
            message=f"M365 {op} ({safe_str(rec.get('Workload')) or 'Exchange'})",
            meta=meta,
            sector=self.resolve_sector(meta),
        )
        if user:
            event["actor"] = {"user": {"name": user}}
        src_ip = _client_ip(rec.get("ClientIP") or rec.get("ClientIPAddress")) or valid_ip(meta.get("ip"))
        if src_ip:
            event["src_endpoint"] = {"ip": src_ip}
        if class_uid == _CLASS_API:
            event["api"] = {"operation": op}
        m365: dict = {"workload": rec.get("Workload"), "operation": op}
        rule = _inbox_rule(op, _params(rec.get("Parameters")), user)
        if rule is not None:
            m365["inbox_rule"] = rule
        event["unmapped"] = {"m365": m365}
        return event

    @staticmethod
    def _time_ms(rec: dict, meta: dict) -> int:
        for value in (rec.get("CreationTime"), meta.get("received_at")):
            parsed = to_epoch_ms(value)
            if parsed is not None:
                return parsed
        return int(time.time() * 1000)
