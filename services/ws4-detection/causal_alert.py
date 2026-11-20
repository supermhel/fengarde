"""ADR-012 WP 5: build the alert's ``causal_keys`` from the TRIGGER event only.

Pure and stateless. Hashing is done by ``shared.causal_keys.key_hash`` (the one
shared implementation); this module only picks the raw values and their scope
and decides the trust level.

Trust (ADR-012 "Scope trust"):

* The sender ``siem.sender.ip`` goes into the hash, and ``scope_trust`` is
  ``observed``, ONLY when the operator declared ws1 directly reachable
  (``FENGARDE_WS1_DIRECT=1``, default off: behind a proxy/NAT the shipper IP is
  the proxy's, which would vouch for nothing) AND the event carries a sender ip.
  Otherwise the sender is the empty string and the trust is ``asserted``.
* ``agent`` keys are self-declared by the monitored software: always
  ``declared``.

Fail closed: a key with no scope (no ``siem.key_scope`` value for it) is not
emitted, because an unscoped value could join events across hosts.
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional

from shared.causal_keys import key_hash

MAX_KEYS = 6
_TRUE = ("1", "true", "yes", "on")


def ws1_direct() -> bool:
    return os.environ.get("FENGARDE_WS1_DIRECT", "").strip().lower() in _TRUE


def _d(x: Any) -> dict:
    return x if isinstance(x, dict) else {}


def _flow_scope(siem: dict, sensor: Any, host: Any) -> Optional[str]:
    """Sensor ids like "suricata"/"zeek" are not unique per deployment, so a flow
    scope is (sensor, qualifier) with qualifier = host, else siem.sender.ip,
    else siem.sender.source. No qualifier: no flow key (fail closed). Encoded as
    canonical JSON so the pair cannot be forged by a delimiter in either part."""
    if not isinstance(sensor, str) or not sensor.strip():
        return None
    sender = _d(siem.get("sender"))
    for q in (host, sender.get("ip"), sender.get("source")):
        if isinstance(q, str) and q.strip():
            return json.dumps([sensor.strip(), q.strip()], separators=(",", ":"))
    return None


def _candidates(event: dict) -> list[tuple[str, str, Any, Any]]:
    """(ns, role, raw_value, scope) in a fixed order, so output is deterministic."""
    siem = _d(event.get("siem"))
    scope = _d(siem.get("key_scope"))
    host, sensor = scope.get("host"), scope.get("sensor")
    actor = _d(event.get("actor"))
    proc = _d(actor.get("process"))
    out: list[tuple[str, str, Any, Any]] = [
        ("proc", "self", proc.get("uid"), host),
        ("proc", "parent", _d(proc.get("parent_process")).get("uid"), host),
        ("logon", "self", _d(actor.get("session")).get("uid"), host),
        ("flow", "self", _d(event.get("connection_info")).get("uid"), _flow_scope(siem, sensor, host)),
        ("agent", "self", _d(_d(event.get("unmapped")).get("mcp")).get("session_id"), host),
    ]
    return out


def build_causal_keys(event: dict) -> list[dict]:
    siem = _d(event.get("siem"))
    tenant = siem.get("tenant") or "default"
    sender_ip = _d(siem.get("sender")).get("ip")
    bound = ws1_direct() and isinstance(sender_ip, str) and bool(sender_ip.strip())
    sender = sender_ip.strip() if bound and isinstance(sender_ip, str) else ""
    keys: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for ns, role, raw, scope in _candidates(event):
        if not isinstance(scope, str) or not scope.strip():
            continue
        h: Optional[str] = key_hash(tenant, ns, sender, scope.strip(), raw)
        if h is None or (ns, role, h) in seen:
            continue
        seen.add((ns, role, h))
        trust = "declared" if ns == "agent" else ("observed" if bound else "asserted")
        keys.append({"ns": ns, "role": role, "h": h, "scope_trust": trust})
        if len(keys) >= MAX_KEYS:
            break
    return keys
