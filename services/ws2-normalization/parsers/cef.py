"""CEF (Common Event Format) parser: generic security-appliance feed -> OCSF.

v0.5 Track A4. CEF (https://www.microfocus.com/documentation/arcsight/) is a
vendor-neutral log wire format shipped by a large swath of firewalls, IDS/IPS,
and proxy appliances -- unlike the other parsers in this repo, CEF's value is
feeding the EXISTING common_* rules (bruteforce, port_scan) from any CEF-
emitting device, not unlocking a new rule of its own (documented, not an
oversight -- see contracts/detection-coverage.md's C3 note on this parser).

Wire format::

    CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|key=value key2=value2 ...

Mapping (Contract A / ocsf-classes.md): the extension's well-known keys decide
the class --
  - ``suser``/``duser`` present (an identity acted) -> 3002 Authentication,
    activity 1 Logon / 4 Failure per ``outcome``.
  - otherwise -> 4001 Network Activity, activity 6 Deny / 7 Accept per ``act``.
This is a coarse, documented heuristic (real CEF deployments vary the
extension keys they populate), not a full per-vendor CEF dictionary.
"""
from __future__ import annotations

import time
from typing import Optional

from .base import Parser, SEV_HIGH, SEV_INFO, status_from_outcome
from shared.ocsf import valid_ip

_CLASS_AUTH = 3002
_CLASS_NET = 4001

_DENY_TOKENS = frozenset({"blocked", "denied", "deny", "drop", "dropped", "reject", "rejected"})


def _parse_extension(ext: str) -> dict:
    """CEF extension is space-separated key=value pairs; a value may itself
    contain spaces (no standard escaping enforced here), so split on the
    LAST recognized ``key=`` boundary greedily is overkill for this repo's
    needs -- a simple ``token=value`` scan handling the common single-word-
    value case covers every field this parser actually reads."""
    fields: dict = {}
    for tok in ext.split():
        if "=" in tok:
            k, _, v = tok.partition("=")
            if k:
                fields[k] = v
    return fields


class CefParser(Parser):
    SOURCE_TYPE = "cef"
    SECTOR = "common"
    ORIGINAL_FORMAT = "cef"
    PRODUCT = {"name": "CEF appliance", "vendor_name": "various"}

    def parse(self, raw: dict) -> Optional[dict]:
        line = raw.get("raw")
        if not isinstance(line, str) or not line.startswith("CEF:"):
            return None
        parts = line.split("|", 7)
        if len(parts) < 7:
            return None
        vendor, product = parts[1], parts[2]
        name = parts[5]
        extension = _parse_extension(parts[7]) if len(parts) > 7 else {}
        meta = raw.get("meta") or {}

        src_ip = extension.get("src")
        dst_ip = extension.get("dst")
        suser, duser = extension.get("suser"), extension.get("duser")

        status = None
        if suser or duser:
            outcome = status_from_outcome(extension, keys=("outcome", "act"))
            activity_id = 1 if outcome == "Success" else 4
            severity_id = SEV_INFO if outcome == "Success" else SEV_HIGH
            class_uid = _CLASS_AUTH
            status = outcome
        else:
            act = str(extension.get("act") or "").strip().lower()
            activity_id = 6 if act in _DENY_TOKENS else 7
            severity_id = SEV_HIGH if activity_id == 6 else SEV_INFO
            class_uid = _CLASS_NET

        event = self.base_event(
            class_uid=class_uid,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=self._time_ms(meta),
            ingest_id=meta.get("ingest_id"),
            status=status,
            message=f"{vendor}/{product} {name}",
            meta=meta,
            sector=self.resolve_sector(meta),
        )
        if valid_ip(src_ip):
            sep = {"ip": src_ip}
            spt = _as_int(extension.get("spt"))
            if spt is not None:
                sep["port"] = spt
            event["src_endpoint"] = sep
        if valid_ip(dst_ip):
            dep = {"ip": dst_ip}
            dpt = _as_int(extension.get("dpt"))
            if dpt is not None:
                dep["port"] = dpt
            event["dst_endpoint"] = dep
        actor_name = suser or duser
        if actor_name:
            event["actor"] = {"user": {"name": actor_name}}
        return event

    @staticmethod
    def _time_ms(meta: dict) -> int:
        ra = meta.get("received_at")
        if isinstance(ra, (int, float)):
            return int(ra * 1000) if ra < 1e12 else int(ra)
        return int(time.time() * 1000)


def _as_int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
