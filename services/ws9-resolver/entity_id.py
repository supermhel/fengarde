"""WS-9 entity identity (WP-2-B): deterministic entity_id + edge canonicalization.

The two pure rules ADR-009 (`docs/adr/009-entity-plane-bus-topics.md`, lines
47-52) hands the resolver, separated from every bus/service concern so the
identity contract is unit-pinnable in isolation from `resolver.py`:

    entity_id = sha256("{tenant}|{entity_type}|{canonical_value}")

``compute_entity_id`` is a PURE function of its inputs -- same discipline as
WS-4's ``Rule.alert_key()`` (services/ws4-detection/engine.py:585-647, the
repo's deterministic-id role model): a redelivered alert re-derives the SAME
entity_id, never a fresh uuid, so WS-3's upsert of ``entity.updates`` is
replay-safe under at-least-once delivery.

Canonical value (normalized at the EDGE, per ADR-009 lines 49-52):

* ``ip``      -> ``shared.ip_utils.valid_ip`` -- the EXACT normalization every
                 parser applies at parse time (services/ws2-normalization/
                 parsers/cef.py:98-106, cloudtrail.py:96-98, ...), which is
                 therefore the value WS-8's ``ip:`` track keys on raw
                 (services/ws8-correlation/correlator.py:574-576). Re-applying
                 it here is idempotent (valid_ip(valid_ip(x)) == valid_ip(x))
                 and collapses ``::ffff:a.b.c.d`` to ``a.b.c.d`` so the
                 resolver hashes exactly what WS-8 already tracks.
                 NOTE: mirroring shared exactly, a bare IPv6 is returned as-is
                 (case preserved) -- that is shared/ocsf.py's contract.
* ``actor``   -> case-folded (str.casefold) per the ADR's "usernames
                 case-folded" wording -- ``Alice`` / ``ALICE`` / ``alice`` are
                 ONE identity. (WS-8 stores actor names raw today --
                 correlator.py:573,581 -- this is the ADR's new, ratified
                 canonicalization; see INTERFACE.md.)
* ``device``  -> lowercased (str.lower) per the ADR's "MACs lowercased";
                 the device value is ``src_endpoint.mac`` or the
                 ``hostname`` fallback (both case-insensitive identifiers,
                 RFC 1035 for hostnames), so the whole device edge is
                 lowercased on one path.

An un-normalizable value (valid_ip returns None, or ``raw`` isn't a string at
all) resolves to None and the caller skips the entity -- degrade, never
fabricate, and never coerce a non-string into a string that could collide
with a genuine one (2026-09-02 review).
"""
from __future__ import annotations

import hashlib

from shared.ip_utils import valid_ip  # the ADR-named canonicalization source; no tools/ dependency

# Entity_type strings mirror WS-8's track kinds EXACTLY (correlator.py:579,
# 591, 610 -- actor/ip/device), so a later incident.graph node derived from a
# WS-9 entity_id lines up with the same track WS-8 promoted.
ENTITY_TYPE_ACTOR = "actor"
ENTITY_TYPE_IP = "ip"
ENTITY_TYPE_DEVICE = "device"

#: The three trackable entity kinds WS-8 resolves identity for.
ENTITY_TYPES = frozenset({ENTITY_TYPE_ACTOR, ENTITY_TYPE_IP, ENTITY_TYPE_DEVICE})


def canonical_entity_value(entity_type: str, raw) -> str | None:
    """Normalize one raw alert value to the ADR-009 canonical form, else None.

    ``raw`` is whatever the alert carried (attacker-controlled, and not
    guaranteed shaped): it is cast defensively before normalization, and an
    un-normalizable value returns None so the caller skips the entity rather
    than hashing garbage into a stable id.
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        # Degrade, don't crash -- but degrade to "unidentifiable", never to a
        # coerced string (2026-09-02 review): str()-casting a bool/int/float
        # before casefold/lower used to collapse it onto whatever STRING
        # value normalizes to the identical spelling -- e.g. the JSON boolean
        # `true` (`str(True)` -> "True" -> casefold() -> "true") merged with
        # a genuine username literally "true" into ONE entity_id, silently
        # combining two unrelated identities' timelines/tactics/member-sets.
        # A non-string actor/IP/MAC is not an entity we can identify
        # deterministically, so it is skipped, not hashed.
        return None
    s = raw
    if entity_type == ENTITY_TYPE_IP:
        # shared.ip_utils.valid_ip validates shape AND collapses the
        # IPv4-mapped-IPv6 form the parsers already normalize (ocsf.py:54-84).
        # Since 2026-08-29 valid_ip ALSO canonicalizes IPv6 spelling (case +
        # compression: "2001:DB8::1", "2001:db8:0:0:0:0:0:1" and
        # "2001:0db8:0000:0000:0000:0000:0000:0001" are ONE address) -- the
        # ADR's one-identity-across-spellings intent (independent review D4).
        # .lower() below is belt-and-suspenders.
        v = valid_ip(s)
        if v is None:
            return None
        return v.lower()
    if entity_type == ENTITY_TYPE_ACTOR:
        # ADR-009: "usernames case-folded" -- one identity across casing.
        # Trailing/leading whitespace is also normalized (a parser that
        # appends a stray space must not split one actor into two ids).
        return s.strip().casefold()
    if entity_type == ENTITY_TYPE_DEVICE:
        # ADR-009: "MACs lowercased"; device mac-or-hostname both lowercase.
        return s.strip().lower()
    raise ValueError(f"unknown entity_type {entity_type!r} (known: {sorted(ENTITY_TYPES)})")


def compute_entity_id(tenant: str, entity_type: str, canonical_value: str) -> str:
    """``sha256("{tenant}|{entity_type}|{canonical_value}")`` hexdigest.

    ``canonical_value`` must ALREADY be canonical (pass it through
    :func:`canonical_entity_value` first); this function is the pure hash of
    the exact ADR preimage so the id is stable forever and test-pinnable.
    """
    preimage = "|".join((tenant, entity_type, canonical_value))
    return hashlib.sha256(preimage.encode("utf-8", errors="replace")).hexdigest()
