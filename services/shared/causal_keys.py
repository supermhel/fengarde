"""Causal evidence keys: canonicalisers and the key hash (ADR-012 WP 2).

Pure functions, stdlib only. This module must NOT import from any ws* service
(bus-only coupling rule), and the twin builders must not import it: the key a
detector computes and the key a test expects must not share an implementation
with the data generator.

Canonical forms (WS-2 applies them before a value reaches the event):

* ``proc``  : GUID, lowercase, no braces (Sysmon ProcessGuid / ParentProcessGuid).
* ``logon`` : LogonId, lowercase hex without ``0x`` and without leading zeros.
* ``flow``  : Suricata ``flow_id`` as a decimal string; a Zeek ``uid`` is kept verbatim.
* ``agent`` : MCP ``session_id``, free text, stripped.

All values are capped at 128 chars. An empty, ``-``, ``0x0``, all-zero or
null-GUID value is "none" in Windows/Suricata/Zeek and is DROPPED (returns
None): treating it as a key would join every unrelated event.

Key hash: sha256 over the canonical JSON of the five-string array
``[tenant, namespace, sender, scope, value]`` (``ensure_ascii``, no whitespace,
UTF-8), first 16 hex chars. A delimiter join is forbidden: scope and value are
free text from the log, and with ``|`` as separator ``("a|b","c")`` and
``("a","b|c")`` would collide. Canonical JSON is injective over string tuples.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable, Optional, Sequence

MAX_VALUE_LEN = 128
HASH_HEX_LEN = 16

_NONE_WORDS = {"", "-", "{}", "null", "none"}
_ALL_ZERO = re.compile(r"^(0x)?0+$", re.IGNORECASE)
_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_NULL_GUID = "00000000-0000-0000-0000-000000000000"
_HEX = re.compile(r"^[0-9a-f]+$")


def _clean(raw: Any) -> Optional[str]:
    """Strip a string value and drop the 'none' spellings; None for non-strings."""
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if s.lower() in _NONE_WORDS or _ALL_ZERO.match(s):
        return None
    if s.strip("{}").strip().lower() == _NULL_GUID:
        return None
    return s


def canon_guid(raw: Any) -> Optional[str]:
    s = _clean(raw)
    if s is None:
        return None
    s = s.strip("{}").strip().lower()
    if len(s) == 32 and re.fullmatch(r"[0-9a-f]{32}", s):
        s = f"{s[:8]}-{s[8:12]}-{s[12:16]}-{s[16:20]}-{s[20:]}"
    if not _GUID.match(s) or s == _NULL_GUID:
        return None
    return s


def canon_logon_id(raw: Any) -> Optional[str]:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return format(raw, "x")[:MAX_VALUE_LEN] if raw > 0 else None
    s = _clean(raw)
    if s is None:
        return None
    s = s.lower()
    if s.startswith("0x"):
        s = s[2:]
    s = s.lstrip("0")
    if not s or not _HEX.match(s):
        return None
    return s[:MAX_VALUE_LEN]


def canon_flow_id(raw: Any) -> Optional[str]:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return str(raw)[:MAX_VALUE_LEN] if raw > 0 else None
    s = _clean(raw)
    if s is None:
        return None
    return s[:MAX_VALUE_LEN]


def canon_agent_session(raw: Any) -> Optional[str]:
    s = _clean(raw)
    if s is None:
        return None
    return s[:MAX_VALUE_LEN]


CANONICALISERS: dict[str, Callable[[Any], Optional[str]]] = {
    "proc": canon_guid,
    "logon": canon_logon_id,
    "flow": canon_flow_id,
    "agent": canon_agent_session,
}


def canonical_tuple(parts: Sequence[str]) -> bytes:
    """Injective byte encoding of a string tuple (canonical JSON, UTF-8)."""
    return json.dumps(list(parts), ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def key_hash(tenant: Any, ns: str, sender: Any, scope: Any, raw_value: Any) -> Optional[str]:
    """First 16 hex of sha256(canonical_json([tenant, ns, sender, scope, value])).

    ``raw_value`` is canonicalised per ``ns``; returns None when the value is
    dropped or ``ns`` is unknown (fail closed: no key, never a guessed key).
    ``sender`` is ``siem.sender.ip`` only when the operator declared ws1
    directly reachable, else "" (None is treated as ""). ``scope`` is the host /
    sensor / agent-runtime the value is unique in.
    """
    canon = CANONICALISERS.get(ns)
    if canon is None:
        return None
    value = canon(raw_value)
    if value is None:
        return None
    parts = ["" if p is None else str(p) for p in (tenant, ns, sender, scope)] + [value]
    return hashlib.sha256(canonical_tuple(parts)).hexdigest()[:HASH_HEX_LEN]
