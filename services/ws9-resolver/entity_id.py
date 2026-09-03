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

The two functions below (2026-09-03) delegate to ``shared.entity_helpers``,
which WS-8's ``correlator.py`` also imports: this used to be a second,
hand-copied implementation (WS-8 mirrors it independently, since its
container ships only shared/ + contracts/, not ws9-resolver) kept in sync
only by a cross-process identifier-agreement test. Moving the one algorithm
into shared/ -- which both services already depend on -- means a
canonicalization-rule change is made once, not twice; this module's public
names (``canonical_entity_value``, ``compute_entity_id``, the
``ENTITY_TYPE_*`` constants) are unchanged for every existing caller.
"""
from __future__ import annotations

from shared.entity_helpers import (  # noqa: E402
    ENTITY_TYPE_ACTOR,
    ENTITY_TYPE_DEVICE,
    ENTITY_TYPE_IP,
    ENTITY_TYPES,
    canonical_entity_value,
    compute_entity_id,
)

__all__ = [
    "ENTITY_TYPE_ACTOR",
    "ENTITY_TYPE_DEVICE",
    "ENTITY_TYPE_IP",
    "ENTITY_TYPES",
    "canonical_entity_value",
    "compute_entity_id",
]
