"""WS-9 Entity Resolver engine (WP-2-B): alerts -> deterministic entity.updates.

**SAFETY: WS-9 is a resolver/analyzer -- an information plane, NOT a control
path.** It never decides or issues an action: it cannot block, drop, suppress,
quarantine, or alter an alert or event, and it holds no authority over any
other workstream. Its only output is resolved ENTITY STATE (``entity.updates``
messages). Every control decision stays with WS-4 (firing), WS-8 (promoting),
or the analyst -- this module just answers "which identity does this alert
name, and when was it first/last seen".

Design -- ADR-009 (docs/adr/009-entity-plane-bus-topics.md). Entity resolution
consumes `alerts`, extracts the same trackable entities WS-8 correlation tracks
(services/ws8-correlation/correlator.py:564-612: actor:user.name, src ip,
device mac-or-hostname -- plus dst_endpoint.ip, see INTERFACE.md), canonically
normalizes each at the edge (entity_id.py, ADR-009 lines 49-52), computes the
deterministic ``entity_id``, and emits one ``entity.updates`` payload per
entity, keyed by entity_id.

Idempotency under at-least-once redelivery (ADR-009 lines 47-54):

* ``entity_id`` is a PURE function of (tenant, entity_type, canonical_value),
  so a redelivered alert re-derives the SAME id (same discipline as WS-4's
  Rule.alert_key(), engine.py:585-647).
* Member accounting is IDEMPOTENT on the alert identity (the same
  ``_member_id`` derived for an alert, mirroring ws8 correlator.py:295-345),
  so replaying the same alert never inflates state: first_seen_ms is the min
  member time ever, last_seen_ms the max ever, and nothing ever regresses.
* An ``entity.updates`` upsert carrying the same entity_id with a non-newer
  last_seen_ms is a NO-OP: re-applying a replayed update via ``apply_update``
  changes nothing and returns False (test_contract.py (d)/(e)).

WS-8 mirror points (all in services/ws8-correlation/correlator.py):
  - field extraction + degrade-don't-crash  :564-576
  - _validated_tenant reject-not-normalize  :136-140
  - _valid_window_time skew-future guard    :143-161
  - deterministic synthetic member id       :295-345
  - member_cap bounds the side table        :461-471
  - observable no-op skip reasons           :614-626
"""
from __future__ import annotations

import math
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.envelope import valid_tenant_id  # noqa: E402
from shared.log import get_logger  # noqa: E402

from entity_id import (  # noqa: E402
    ENTITY_TYPE_ACTOR,
    ENTITY_TYPE_DEVICE,
    ENTITY_TYPE_IP,
    canonical_entity_value,
    compute_entity_id,
)

_log = get_logger("ws9-resolver")

DEFAULT_TENANT = "default"

# Tolerated source clock drift for alert `time` (same ceiling WS-4's
# engine.py::_MAX_CLOCK_SKEW_MS and WS-8's correlator.py apply): an attacker
# who stamps an alert implausibly far ahead of wall-clock must not be able to
# shift an entity's first_seen/last_seen anchors or its eviction ordering.
_MAX_CLOCK_SKEW_MS = 300_000  # 5 minutes of tolerated source clock drift

# Bounds the per-entity live member side table (mirror of ws8's member_cap /
# correlator.py:461-471): a sustained single-entity flood (one brute-force
# source IP) grows the member set to the cap and no further; the STABLE
# aggregates (first/last_seen, tactics) survive eviction in `_meta`, so the
# payload never changes shape as the cap binds.
DEFAULT_MEMBER_CAP = 200

# Reverse of ws8's entity_value cap (correlator.py:_ENTITY_VALUE_MAX_BYTES,
# the OpenSearch 512-byte document-id ceiling): an attacker-controlled
# username/hostname is embedded in entity_value and keyed by entity_id; bound
# it so the stored/emitted value can never be an unbounded memory or id-size
# vector. Same truncate+stable-sha256-suffix policy as ws8, so two distinct
# long values keep DISTINCT ids (never-merge discipline survives) and a
# redelivered alert re-derives the same bounded value.
_ENTITY_VALUE_MAX_BYTES = 448

# Full-scan sweep cadence for the entity table -- same amortized full-scan
# tradeoff ws8's _SIDES_SWEEP_EVERY and shared/window.py's _SWEEP_EVERY
# accept: a scan every N calls is cheap, an unbounded dict is not.
_ENTITY_SWEEP_EVERY = 256


class InvalidTenant(ValueError):
    """Raised when an alert's tenant_id isn't safe to key entity state on.

    Reject-at-edge, never normalize -- same discipline as ws8's
    InvalidTenant (correlator.py:128-140) and WS-6's store.py: silently
    lowercasing "Acme"/"ACME" to the same id would merge two customers'
    entity state, the exact isolation bug the pattern exists to prevent.
    """


def _validated_tenant(tenant) -> str:
    """Mirror ws8 correlator.py:136-140 exactly."""
    tenant = tenant or DEFAULT_TENANT
    if tenant != DEFAULT_TENANT and not valid_tenant_id(tenant):
        raise InvalidTenant(f"invalid tenant_id {tenant!r}")
    return tenant


def _valid_window_time(value, now_ms: int) -> int | None:
    """Mirror ws8 correlator.py:143-161 (which mirrors WS-4's guard).

    Returns alert ``time`` as epoch-ms if it can safely drive first/last_seen
    anchors, else None (fail closed: bool, non-numeric, NaN/inf, or skew-future
    timestamps never move an entity's timeline). Past timestamps always pass --
    that is legitimate historical replay.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    now = int(value)
    if now > now_ms + _MAX_CLOCK_SKEW_MS:
        return None
    return now


def _to_str(x) -> str:
    """Decode a possibly-bytes value to str (mirror ws8 correlator.py:98-105)."""
    return x.decode() if isinstance(x, bytes) else str(x)


def _bounded_entity_value(entity_value) -> str:
    """Bound an attacker-controlled entity_value (mirror ws8 _bounded_entity_value).

    Truncate + a stable sha256 suffix: two distinct long values keep DISTINCT
    ids (never-merge survives the cap) and a redelivered alert re-derives the
    same bounded value (idempotent). An unbounded username/hostname is a
    memory + crafted-id-size vector the same way it is in ws8.
    """
    raw = str(entity_value)
    encoded = raw.encode("utf-8", errors="replace")
    if len(encoded) <= _ENTITY_VALUE_MAX_BYTES:
        return raw
    import hashlib  # local: only on the capped path
    digest = hashlib.sha256(encoded).hexdigest()[:16]
    head = encoded[: _ENTITY_VALUE_MAX_BYTES - 17].decode("utf-8", errors="replace")
    return f"{head}:{digest}"


class EntityResolver:
    """Resolves alert-named entities to deterministic ids and emits their state.

    ``now_fn`` is injectable for tests (same as ws8 Correlator's now_fn).
    """

    def __init__(self, *, now_fn=time.time, member_cap: int = DEFAULT_MEMBER_CAP,
                 horizon_s: int = 86400):
        self._now_fn = now_fn
        self.member_cap = member_cap
        self.horizon_s = horizon_s
        self._update_calls = 0  # sweep cadence counter (mirror ws8 _update_calls)
        # entity_id -> last processing-time touch, for the entity-table sweep.
        self._last_touch: dict[str, int] = {}
        # entity_id -> {"entity_id","entity_type","tenant_id","entity_value",
        #               "first_seen_ms","last_seen_ms","attributes"} -- the
        # stable aggregate that survives member eviction (mirror ws8 _side_meta).
        self._meta: dict[str, dict] = {}
        # entity_id -> {member_id: time_ms} insertion-ordered, bounded at the cap.
        self._members: dict[str, dict] = {}
        # entity_id -> count of times the cap evicted an old member (observable).
        self._truncated: dict[str, bool] = {}
        # entity_id -> bounded LRU of recently-EVICTED member ids, so a
        # cap-evicted member re-added on redelivery is NOT counted as a fresh
        # state change (independent review D3: cap+replay must not inflate
        # resolved_updates). Capped at member_cap per entity via the same
        # eviction discipline -- a distinct-id spray is bounded, never
        # unbounded growth.
        self._evicted_lru: dict[str, dict[str, int]] = {}
        # reason -> count of alerts that named NO resolvable entity (observable
        # no-op; mirror ws8 _skip_reasons correlator.py:614-626).
        self._skip_reasons: dict[str, int] = {}
        # Distinct state-changing upserts (a new entity _meta row, or a new
        # member landing on an existing entity). Redelivery of an already-seen
        # alert re-EMITS the same state-identical payload but does not count
        # here -- this number tracks state changes, not bus emissions.
        self.resolved_updates = 0  # total entity.updates payloads emitted
        self.truncated_total = 0
        self.swept_entities = 0  # entities dropped by _sweep_dead_entities

    def _now_ms(self) -> int:
        return int(self._now_fn() * 1000)

    # -- extraction (mirror ws8 correlator.py:564-612) ------------------------

    def extract_entities(self, alert: dict) -> list[tuple[str, object]]:
        """The trackable entities one alert names, in ws8's order
        (actor, src ip, device) plus dst_endpoint.ip (see INTERFACE.md).

        Returns (entity_type, raw_value) pairs; a malformed block degrades to
        naming no entity rather than raising (ws8's degrade-don't-crash,
        correlator.py:564-576).
        """
        out: list[tuple[str, object]] = []
        actor = alert.get("actor") or {}
        user = actor.get("user") or {}
        if not isinstance(user, dict):  # ws8:570-572 -- plain-string user degrade
            user = {}
        actor_name = user.get("name")
        if actor_name:
            out.append((ENTITY_TYPE_ACTOR, actor_name))
        src_endpoint = alert.get("src_endpoint") or {}
        src_ip = src_endpoint.get("ip")
        if src_ip:
            out.append((ENTITY_TYPE_IP, src_ip))
        # Task scope adds the destination side; both are resolved as `ip`
        # entities so an endpoint's identity is the same on either side.
        dst_endpoint = alert.get("dst_endpoint") or {}
        dst_ip = dst_endpoint.get("ip")
        if dst_ip:
            out.append((ENTITY_TYPE_IP, dst_ip))
        device_id = src_endpoint.get("mac") or src_endpoint.get("hostname")
        if device_id:
            out.append((ENTITY_TYPE_DEVICE, device_id))
        return out

    def _member_id(self, alert: dict) -> str:
        """Deterministic per-alert member id (mirror ws8 _member_id, :295-345).

        We need ONE id that is stable across redelivery of the same alert
        (so replay never inflates an entity's member set) yet distinct for
        different alerts (no false merge). alert_id when present; else a
        synthetic id from time/rule_id/event_ids; else a content hash.
        """
        alert_id = alert.get("alert_id")
        if alert_id not in (None, ""):
            return _to_str(alert_id)
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
            parts.append("|".join(_to_str(e) for e in ev))
        if parts:
            return "anon:" + ":".join(parts)
        import json  # local: only used on the fully-anonymous fallback path
        try:
            blob = json.dumps(alert, sort_keys=True, default=str)
        except (TypeError, ValueError):
            blob = repr(alert)
        import hashlib
        digest = hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()[:16]
        return "anon:" + digest

    # -- upsert core (the ADR no-op rule) -------------------------------------

    def apply_update(self, update: dict) -> bool:
        """Merge one entity.updates payload into state.

        Returns True if it actually changed state. Per ADR-009: an upsert
        carrying the same entity_id with a NON-NEWER last_seen_ms is a no-op
        (replay-safe) -- replaying a payload we ourselves emitted changes
        nothing and returns False. This is the "self" consumer path
        (WS-9 consumes entity.updates per bus-topics.md) and the rule WS-3's
        indexer applies on the same payload.
        """
        entity_id = update["entity_id"]
        prev = self._meta.get(entity_id)
        if prev is None:
            self._meta[entity_id] = {
                "entity_id": entity_id,
                "entity_type": update["entity_type"],
                "tenant_id": update["tenant_id"],
                "entity_value": update["entity_value"],
                "first_seen_ms": update["first_seen_ms"],
                "last_seen_ms": update["last_seen_ms"],
                "attributes": dict(update.get("attributes") or {}),
            }
            self.resolved_updates += 1
            return True
        # Non-newer last_seen_ms -> nothing moves -> pure no-op.
        if update["last_seen_ms"] <= prev["last_seen_ms"]:
            return False
        prev["last_seen_ms"] = update["last_seen_ms"]
        self.resolved_updates += 1
        return True

    def _upsert_sighting(self, *, tenant, entity_type, entity_value,
                         entity_id, member, time_ms, tactics, alert_id) -> dict:
        """Record one sighting on one entity; return its entity.updates payload
        (post-merge state). Idempotent on (entity_id, member)."""
        # Entity-table sweep cadence (mirror ws8 _update_track: full scan every
        # N calls -- the entity COUNT is attacker-controlled, so it must be
        # bounded even when no single entity's member set grows).
        self._update_calls += 1
        if self._update_calls % _ENTITY_SWEEP_EVERY == 0:
            self._sweep_dead_entities(self._now_ms())
        # Processing-time touch (mirror ws8 _last_touch): an entity seen now
        # stays live for a full horizon from this point.
        self._last_touch[entity_id] = self._now_ms()
        prev = self._meta.get(entity_id)
        if prev is None:
            meta = {
                "entity_id": entity_id,
                "entity_type": entity_type,
                "tenant_id": tenant,
                "entity_value": entity_value,
                "first_seen_ms": time_ms,
                "last_seen_ms": time_ms,
                "attributes": {
                    "member_count": 1,
                    "truncated": False,
                    "mitre_tactics": sorted(tactics) if tactics else [],
                    "first_alert_id": alert_id,
                    "last_alert_id": alert_id,
                },
            }
            self._meta[entity_id] = meta
            side = {member: time_ms}
            self._members[entity_id] = side
            self.resolved_updates += 1
            return dict(meta)
        meta = prev
        side = self._members.setdefault(entity_id, {})
        evicted_lru = self._evicted_lru.setdefault(entity_id, {})
        is_new_member = member not in side
        # Was this member already an established state of this entity (seen
        # before, possibly cap-evicted)? A re-add after cap eviction is NOT a
        # fresh state change -- decide BEFORE any mutation so the bookkeeping
        # below cannot clobber the memory it needs (D3: cap+replay must not
        # inflate resolved_updates).
        previously_known = member in evicted_lru or member in side
        if is_new_member:
            side[member] = time_ms
            if len(side) > self.member_cap:
                # Evict the OLDEST member (by time) -- mirror ws8:466-471.
                oldest = min(side, key=side.get)
                del side[oldest]
                # Remember it in the bounded evicted-LRU so a redelivery of the
                # evicted alert is NOT counted as a fresh state change (D3).
                if oldest != member:  # never evict the member we just added
                    evicted_lru[oldest] = time_ms
                    if len(evicted_lru) > self.member_cap:
                        evicted_lru.pop(next(iter(evicted_lru)), None)
                meta["attributes"]["truncated"] = True
                self._truncated[entity_id] = True
                self.truncated_total += 1
            meta["attributes"]["member_count"] = len(side)
        # Stable aggregates: min/max over ALL evidence ever seen on this live
        # entity (mirror ws8's _side_meta -- never regress, never shrink).
        meta["first_seen_ms"] = min(meta["first_seen_ms"], time_ms)
        meta["last_seen_ms"] = max(meta["last_seen_ms"], time_ms)
        if tactics:
            seen = set(meta["attributes"]["mitre_tactics"])
            seen.update(tactics)
            meta["attributes"]["mitre_tactics"] = sorted(seen)
        meta["attributes"]["last_alert_id"] = alert_id
        if is_new_member and not previously_known:
            self.resolved_updates += 1
        return dict(meta)

    # -- entry point ----------------------------------------------------------

    def _sweep_dead_entities(self, now_ms: int) -> None:
        """Drop ``_meta``/``_members``/``_truncated``/``_last_touch`` entries
        for entities not touched within the last ``horizon_s``.

        Mirror of ws8's ``_sweep_dead_tracks`` (correlator.py:515-554), on the
        same staleness basis (processing-time ``now_ms`` via ``_last_touch``)
        and cadence (a full scan every 256 ``_upsert_sighting`` calls): an
        entity that simply stops receiving alerts would otherwise live in the
        entity table forever -- a distinct-attacker-id spray grows ``_meta`` /
        ``_members`` without limit, exactly the vector that makes the entity
        count attacker-controlled. A key is dropped only after a FULL horizon
        of silence, so a still-live entity (and redelivery-stable state) is
        never touched.
        """
        stale_before = now_ms - self.horizon_s * 1000
        dead = [k for k, ts in self._last_touch.items() if ts < stale_before]
        for k in dead:
            self._meta.pop(k, None)
            self._members.pop(k, None)
            self._truncated.pop(k, None)
            self._evicted_lru.pop(k, None)
            self._last_touch.pop(k, None)
            self.swept_entities += 1

    def resolve_alert(self, alert: dict, now_ms: int | None = None) -> list[dict]:
        """Resolve every trackable entity of one alert to an entity.updates
        payload (one per entity, in extraction order). Returns the list to
        emit on the bus; [] when the alert names no resolvable entity (recorded
        as a skip reason, never silent)."""
        if now_ms is None:
            now_ms = self._now_ms()
        tenant = _validated_tenant(alert.get("tenant_id"))
        member = self._member_id(alert)
        # Same skew guard WS-8/WS-4 apply to attacker-controlled alert time.
        # DETERMINISTIC time-less anchor (independent review D3): when the alert
        # carries no usable time, anchor the member on a stable digest of the
        # member id instead of wall-clock now_ms -- a redelivered time-less
        # alert must re-derive the SAME member time, so last_seen_ms never
        # moves and replay stays state-identical (raw wall-clock also let a
        # replay of two time-less alerts silently swap their eviction order).
        valid_time = _valid_window_time(alert.get("time"), now_ms)
        if valid_time is not None:
            time_ms = valid_time
        else:
            import hashlib  # local: only on the deterministic-fallback path
            time_ms = int(hashlib.sha256(
                member.encode("utf-8", errors="replace")).hexdigest()[:12], 16)
        alert_id = member if member.startswith("anon:") else _to_str(alert.get("alert_id"))
        tactic = (alert.get("mitre") or {}).get("tactic")
        tactics = [tactic] if tactic else []

        updates: list[dict] = []
        skipped = False
        for entity_type, raw in self.extract_entities(alert):
            canonical = canonical_entity_value(entity_type, raw)
            if canonical is None:
                skipped = True  # e.g. src_endpoint.ip that isn't a real IP
                continue
            # Bound the value BEFORE keying/emitting so the stored entity_value
            # and any id embedding it can never be an unbounded attacker vector
            # (independent review D2: mirror ws8's _bounded_entity_value).
            canonical = _bounded_entity_value(canonical)
            entity_id = compute_entity_id(tenant, entity_type, canonical)
            updates.append(self._upsert_sighting(
                tenant=tenant, entity_type=entity_type,
                entity_value=canonical, entity_id=entity_id, member=member,
                time_ms=time_ms, tactics=tactics, alert_id=alert_id))
        if not updates:
            reason = "no_trackable_entity" if not skipped else "unresolvable_value"
            self._skip_reasons[reason] = self._skip_reasons.get(reason, 0) + 1
        return updates

    def entity_state(self, entity_id: str) -> dict | None:
        """The current emitted entity state for ``entity_id`` (tests/metrics)."""
        meta = self._meta.get(entity_id)
        return dict(meta) if meta is not None else None

    def entity_ids(self) -> list[str]:
        return sorted(self._meta)

    def count(self) -> int:
        return len(self._meta)

    def metrics(self) -> dict:
        out = {
            "ws9_resolved_entities": self.count(),
            "ws9_updates_total": self.resolved_updates,
            "ws9_truncated_total": self.truncated_total,
            "ws9_swept_entities": self.swept_entities,
            "ws9_skipped_alerts_by_reason": dict(self._skip_reasons),
            "ws9_skipped_total": sum(self._skip_reasons.values()),
        }
        for reason, count in self._skip_reasons.items():
            out[f"ws9_skipped_reason_{reason}"] = count
        return out
