"""Shared helpers for the JSON network-sensor parsers (suricata_eve, zeek_json).

Everything here is total: any input type returns a value or ``None``, never raises. These sensors write
attacker-influenced text (DNS names, signatures, notice messages) and the bus delivers whatever a collector sent.
"""
from __future__ import annotations

import json
import math
from typing import Optional

from shared.ocsf import valid_ip

_TEXT_MAX = 512
_INT_MAX = 2 ** 63 - 1  # keeps a hostile 400-digit integer out of the index (a long overflow downstream)
_SECTORS = frozenset({"bank", "datacenter", "common"})


def load_record(raw) -> Optional[dict]:
    """The sensor record as a dict from ``raw["raw"]`` -- a dict (already decoded) or one JSON line (file tail)."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.lstrip().startswith("{"):
        try:
            obj = json.loads(raw)
        except (ValueError, RecursionError):  # RecursionError: deeply nested hostile JSON
            return None
        return obj if isinstance(obj, dict) else None
    return None


def envelope_meta(raw) -> dict:
    meta = raw.get("meta") if isinstance(raw, dict) else None
    return meta if isinstance(meta, dict) else {}


def sector(meta: dict, default: str) -> str:
    """``meta.sector`` when it is a recognised value, else the per-event default (OT events default to datacenter)."""
    v = meta.get("sector")
    return v if isinstance(v, str) and v in _SECTORS else default


def text(v, limit: int = _TEXT_MAX) -> Optional[str]:
    return v[:limit] if isinstance(v, str) and v.strip() else None


def integer(v) -> Optional[int]:
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= _INT_MAX else None


def number(v) -> Optional[float]:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    try:
        f = float(v)
    except OverflowError:
        return None
    return f if math.isfinite(f) else None


def port(v) -> Optional[int]:
    p = integer(v)
    return p if p is not None and p <= 65535 else None


def endpoint(ip, prt) -> Optional[dict]:
    ep: dict = {}
    addr = valid_ip(ip)
    if addr:
        ep["ip"] = addr
    p = port(prt)
    if p is not None:
        ep["port"] = p
    return ep or None


def strings(v, limit: int = 16) -> list:
    """A bounded list of non-empty strings from ``v`` (anything else -> [])."""
    if not isinstance(v, list):
        return []
    return [s[:_TEXT_MAX] for s in v[:limit] if isinstance(s, str) and s]


def drop_none(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is not None and v != []}
