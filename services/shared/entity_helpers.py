"""Shared per-alert identity helpers reused by WS-8 (correlator.py) and WS-9
(resolver.py).

Split out (2026-09-02 review) because both services independently
implemented the SAME four algorithms -- tenant validation, clock-skew-guarded
time parsing, entity-value byte bounding, and deterministic per-alert member
ids -- with the same magic constants (``_MAX_CLOCK_SKEW_MS``,
``_ENTITY_VALUE_MAX_BYTES``). Two copies meant a fix to one (e.g. the
clock-skew guard) had to be manually re-applied to the other or they'd
silently drift apart. Both services now import from here; behavior is
unchanged.
"""
from __future__ import annotations

import hashlib
import json
import math

from shared.envelope import valid_tenant_id

DEFAULT_TENANT = "default"

#: Tolerated source clock drift for an alert's ``time`` field: an attacker
#: who stamps an alert implausibly far ahead of wall-clock must not be able
#: to shift a track/entity's first_seen/last_seen anchors or eviction order.
MAX_CLOCK_SKEW_MS = 300_000  # 5 minutes

#: Bounds an attacker-controlled entity_value (username/hostname/etc.) so it
#: can never be an unbounded memory or id-size vector -- OpenSearch's
#: 512-byte document-id ceiling, minus headroom for the id's other fields.
ENTITY_VALUE_MAX_BYTES = 448


class InvalidTenant(ValueError):
    """Raised when an alert's tenant_id isn't safe to key state on.

    Reject-at-edge, never normalize: silently lowercasing "Acme"/"ACME" to
    the same id would merge two customers' state, the exact isolation bug
    this discipline exists to prevent.
    """


def validated_tenant(tenant, default: str = DEFAULT_TENANT) -> str:
    tenant = tenant or default
    if tenant != default and not valid_tenant_id(tenant):
        raise InvalidTenant(f"invalid tenant_id {tenant!r}")
    return tenant


def valid_window_time(value, now_ms: int, max_skew_ms: int = MAX_CLOCK_SKEW_MS) -> int | None:
    """Return ``value`` as epoch-ms int if it can safely drive a
    track/entity's timeline anchors, else None (fail closed: bool,
    non-numeric, NaN/inf, or skew-future timestamps never move it). Past
    timestamps always pass -- that is legitimate historical replay.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    now = int(value)
    if now > now_ms + max_skew_ms:
        return None
    return now


def to_str(x) -> str:
    """Decode a possibly-bytes value to str. NOT the same as ``str(x)`` --
    ``str(b"bz1")`` produces the literal ``"b'bz1'"``, not ``"bz1"``."""
    return x.decode() if isinstance(x, bytes) else str(x)


def bounded_entity_value(entity_value, max_bytes: int = ENTITY_VALUE_MAX_BYTES) -> str:
    """Truncate + a stable sha256 suffix if ``entity_value`` exceeds
    ``max_bytes``: two distinct long values keep DISTINCT bounded values
    (never-merge discipline survives the cap), and a redelivered alert
    re-derives the same bounded value (idempotent)."""
    raw = str(entity_value)
    encoded = raw.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return raw
    digest = hashlib.sha256(encoded).hexdigest()[:16]
    head = encoded[: max_bytes - 17].decode("utf-8", errors="replace")
    return f"{head}:{digest}"


def deterministic_member_id(alert: dict) -> str:
    """Deterministic per-alert member id: stable across redelivery of the
    SAME alert (replay never inflates a member set) yet distinct for
    different alerts (no false merge/dedup). ``alert_id`` when present;
    else a synthetic id from time/rule_id/event_ids; else a content hash of
    the whole payload (deterministic across processes, so a multi-replica
    deployment agrees, and redelivery of the same anonymous alert re-derives
    the same member instead of inflating)."""
    alert_id = alert.get("alert_id")
    if alert_id not in (None, ""):
        return to_str(alert_id)
    parts: list[str] = []
    t = alert.get("time")
    if t is not None:
        parts.append(str(t))
    rule_id = alert.get("rule_id")
    if rule_id is not None:
        parts.append(str(rule_id))
    event_ids = alert.get("event_ids")
    if event_ids:
        ev = event_ids if isinstance(event_ids, (list, tuple)) else [event_ids]
        parts.append("|".join(to_str(e) for e in ev))
    if parts:
        return "anon:" + ":".join(parts)
    try:
        blob = json.dumps(alert, sort_keys=True, default=str)
    except (TypeError, ValueError):
        blob = repr(alert)
    digest = hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()[:16]
    return "anon:" + digest
