"""Secure-email-gateway message log parser -> OCSF Email Activity (4009).

Built 2026-10-14 (owner decision: build the mail-gateway and M365 parsers the
phishing_bec storyline declared as placeholders). Gateways (Proofpoint,
Mimecast, Exchange Online Protection, Cisco ESA...) all export one JSON record
per message with the same core facts under vendor-specific names; this parser
reads the common ones and nothing vendor-proprietary. Fixtures are spec-derived,
not captured from a real gateway.

Mapping:
    every record -> class 4009 Email Activity (OCSF 1.1: activity 1 Send,
    2 Receive, 3 Scan). Inbound (the default) -> 2 Receive; direction
    "outbound" -> 1 Send. status: Success when the message was delivered,
    Failure when it was blocked / quarantined / rejected -- the gateway's own
    verdict, carried verbatim in ``unmapped.email.verdict``.

Attachments are summarised under ``unmapped.email.attachments`` (name,
extension, ``macro_capable`` for the Office macro-enabled extensions) -- the
T1566.001 "spear-phishing attachment" shape. No rule consumes these yet (a
declared gap). Every field is sender-controlled text: length-capped, never
evaluated.
"""
from __future__ import annotations

import json
import time
from typing import Optional

from .base import Parser, SEV_INFO, SEV_MEDIUM
from .timeutil import to_epoch_ms
from shared.ocsf import valid_ip, safe_str

_CLASS_EMAIL = 4009
_MAX = 512
_MAX_ATTACHMENTS = 32
# Office formats that can carry VBA macros (plus the legacy binary ones).
_MACRO_EXT = frozenset({"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam",
                        "ppsm", "sldm", "doc", "xls", "ppt"})
_BLOCKED = frozenset({"blocked", "quarantined", "rejected", "dropped", "deleted"})


def _pick(rec: dict, *keys):
    for k in keys:
        v = rec.get(k)
        if v not in (None, "", []):
            return v
    return None


def _addr(v) -> Optional[str]:
    s = safe_str(v)
    return s.strip()[:_MAX].lower() if s else None


def _addr_list(v) -> list[str]:
    vals = v if isinstance(v, list) else [v]
    out = []
    for x in vals:
        s = safe_str(x)
        if s:
            out += [p.strip()[:_MAX].lower() for p in s.replace(",", ";").split(";") if p.strip()]
    return out


def _attachments(v) -> list[dict]:
    vals = v if isinstance(v, list) else [v]
    out = []
    for x in vals[:_MAX_ATTACHMENTS]:
        name = safe_str(x.get("name") or x.get("filename")) if isinstance(x, dict) else safe_str(x)
        if not name:
            continue
        name = name.strip()[:_MAX]
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        out.append({"name": name, "extension": ext, "macro_capable": ext in _MACRO_EXT})
    return out


class MailGatewayParser(Parser):
    SOURCE_TYPE = "mail_gateway"
    SECTOR = "common"
    ORIGINAL_FORMAT = "json"
    PRODUCT = {"name": "Secure Email Gateway", "vendor_name": "generic"}

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
        sender = _addr(_pick(rec, "from", "sender", "mail_from", "SenderAddress"))
        recipients = _addr_list(_pick(rec, "to", "recipients", "rcpt_to", "RecipientAddress"))
        if not sender or not recipients:
            return None                        # not a message record
        verdict = (safe_str(_pick(rec, "verdict", "action", "disposition", "Status")) or "").strip().lower()
        blocked = verdict in _BLOCKED
        outbound = (safe_str(rec.get("direction")) or "").strip().lower() == "outbound"
        attachments = _attachments(_pick(rec, "attachments", "attachment", "files"))
        macro = any(a["macro_capable"] for a in attachments)

        event = self.base_event(
            class_uid=_CLASS_EMAIL,
            activity_id=1 if outbound else 2,
            severity_id=SEV_MEDIUM if (macro and not blocked) else SEV_INFO,
            time_ms=self._time_ms(rec, meta),
            ingest_id=meta.get("ingest_id") or safe_str(_pick(rec, "message_id", "MessageId")),
            status="Failure" if blocked else "Success",
            message=f"mail {'to' if outbound else 'from'} {sender if not outbound else recipients[0]}"
                    f" ({verdict or 'no verdict'})",
            meta=meta,
            sector=self.resolve_sector(meta),
        )
        subject = safe_str(_pick(rec, "subject", "Subject"))
        event["email"] = {"from": sender, "to": recipients,
                          "subject": subject.strip()[:_MAX] if subject else None}
        src_ip = valid_ip(_pick(rec, "src_ip", "sender_ip", "client_ip", "SenderIP")) \
            or valid_ip(meta.get("ip"))
        if src_ip:
            event["src_endpoint"] = {"ip": src_ip}
        event["unmapped"] = {"email": {
            "verdict": verdict or None,
            "direction": "outbound" if outbound else "inbound",
            "sender_domain": sender.rsplit("@", 1)[-1] if "@" in sender else None,
            "attachments": attachments,
            "has_macro_attachment": macro,
            "delivered": not blocked,
        }}
        return event

    @staticmethod
    def _time_ms(rec: dict, meta: dict) -> int:
        for value in (_pick(rec, "ts", "timestamp", "received", "Received"), meta.get("received_at")):
            parsed = to_epoch_ms(value)
            if parsed is not None:
                return parsed
        return int(time.time() * 1000)
