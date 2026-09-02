"""Behavioral baselines for the entity plane (WP-2-D).

Per-entity "normal behavior" tracker. For each entity it learns, over a
configurable warm-up window, the activity the entity is expected to show:

- active hours (UTC hour-of-day, from the OCSF ``time`` field),
- expected source-IP set,
- expected event-type set,
- expected destinations (dst IP set).

An observation that falls outside the learned normal is reported as a
DEVIATION with explicit reasons, so a caller can see *what* was abnormal
(hour / source IP / event type / destination), not just a boolean.

STATUS -- deliberately NOT wired into the live rule engine.
-----------------------------------------------------------
The roadmap sequence is baselines first, wiring later. This module is
self-contained and additive: ``observe()`` returns a verdict dict and
mutates nothing (the input event is never modified; no bus topic is
invented). A future integration (an engine rule, or the WS-9 resolver
turning a verdict into a ``baseline_deviation`` signal) decides how to
carry the deviation forward. Shipping the signal as a *returned dict*
instead of an event-field mutation or a bus emission is the least-invasive
honest shape: it imposes no schema on the rest of the pipeline before the
integration is designed, and it keeps this module importable/testable with
zero infrastructure.

STORAGE -- reuses shared/window.py's window counter, no new store.
------------------------------------------------------------------
All per-entity state lives inside a single sliding-window counter (the
same ``DequeWindowCounter`` the engine uses for stateful rules, swapped
for ``RedisWindowCounter`` on a multi-replica deployment -- inject it
via ``counter=``, mirroring ``engine.Rule.set_counter``). Window keys are
derived deterministically from the entity key ``bbv1:{entity_key}:{feature}``:

- observations window: ``hit(key, now, warm_up, member=ingest_id)`` --
  distinct-count of OCSF ``ingest_id`` members in-window, so redelivered
  events count ONCE (the counter's member dedup; same discipline as the
  engine).
- hour / event-type windows: ``hit(key, now, warm_up, member=value)`` --
  the in-window ``members()`` IS the learned set of hours / type_uids.
- source / destination windows: ``hit_distinct(..., value=ip)`` -- the
  in-window ``distinct_members()`` IS the learned IP set.

BOUNDED -- attacker-controlled key space.
-----------------------------------------
``entity_id`` comes from the entity plane and is attacker-controlled; the
entity table (``_first_seen`` / ``_last_seen``) is capped at
``max_entities`` with deterministic LRU eviction, and idle entities are
swept every ``_SWEEP_EVERY`` observes (the deque counter's own idle-key
sweep discipline). The window-counter state itself is bounded by the
counter's trim + sweep: a sprayed entity's windows die ``warm_up_ms``
after its last observation. Net invariant: the entity table never exceeds
``max_entities``, and the counter never holds more than (distinct entities
touched within the warm-up window) x (features + 1) keys.

DETERMINISTIC / REPLAY-SAFE.
----------------------------
There is NO wall-clock read anywhere in this module: every call takes an
explicit ``now_ms`` (mirroring ``DequeWindowCounter.hit``), so the same
(events, now_ms) sequence always yields the same baseline state --
tests drive an injected clock. ``first_seen`` is a min, ``last_seen`` a
max, so out-of-order redelivery cannot corrupt either. Redelivered
observations (same ``ingest_id``) do not double-count: the member dedup
on the observation window and value dedup on the IP windows mean a replay
only *refreshes* recency, exactly like the counter itself.

Honest limits (not over-promised):
- Without an OCSF ``ingest_id`` an observation cannot be deduped (the
  counter's ``member=None`` path) -- replay safety degrades to the same
  constraint the engine lives with.
- An entity whose feature field is missing (e.g. no ``src_endpoint.ip``)
  is skipped for that feature: absence is never a deviation.
- The baseline FORGETS: with a sliding warm-up window, values that stop
  recurring age out, so a permanently changed behavior is re-learned as
  normal rather than flagged forever. Relatedly, deviation is judged on the
  PRE-observation set: a value's FIRST in-window sighting deviates, and
  recurrence re-learns it (it stops flagging while it keeps recurring) --
  the same refresh semantics as the counter's member dedup.
- Never flags during warm-up: ``learned=False`` verdicts are "can't judge
  yet", never "passes".
"""
from __future__ import annotations

from typing import Optional, Tuple

from shared.window import DequeWindowCounter  # noqa: E402

# Mirror shared/window.py's idle-sweep cadence: every _SWEEP_EVERY observes
# we drop entity-table rows that have been idle for a full warm-up window.
_SWEEP_EVERY = 256

# Feature names recognized by the constructor. Each maps to an OCSF
# extraction and to one per-entity window key; a subset can be enabled so a
# future integration tunes what "normal" means per deployment.
_FEATURE_HOUR = "hour"
_FEATURE_SRC_IP = "src_ip"
_FEATURE_EVENT_TYPE = "event_type"
_FEATURE_DST_IP = "dst_ip"
FEATURES = (
    _FEATURE_HOUR,
    _FEATURE_SRC_IP,
    _FEATURE_EVENT_TYPE,
    _FEATURE_DST_IP,
)

# Window-key prefix. The version nibble lets a future baseline-format
# change (new window semantics) migrate keys instead of colliding with
# whatever a previous version left in a shared Redis namespace.
_KEY_PREFIX = "bbv1"


def _tenant_of(event: dict) -> str:
    return (event.get("siem") or {}).get("tenant") or "default"


def _ingest_id_of(event: dict) -> Optional[str]:
    # The engine reads ingest_id from the same path (engine.py
    # contributing_event_ids_with_omitted); mirror it exactly so redelivery
    # dedup behaves identically to the rule engine's windows.
    return (event.get("siem") or {}).get("ingest_id")


def _type_uid_of(event: dict) -> Optional[int]:
    tid = event.get("type_uid")
    if tid is None:  # class_uid is the coarser but still-available fallback
        tid = event.get("class_uid")
    if isinstance(tid, bool) or not isinstance(tid, int):
        # Degrade, don't crash (2026-09-02 review): an unvalidated value here
        # used to reach DequeWindowCounter.hit()'s set membership test
        # unfiltered -- a malformed event with type_uid/class_uid as a list
        # or dict raised an uncaught TypeError: unhashable type, crashing
        # observe(). Only a real int (never bool, which subclasses int) is a
        # meaningful type/class uid.
        return None
    return tid


def _src_ip_of(event: dict) -> Optional[str]:
    ip = (event.get("src_endpoint") or {}).get("ip")
    # Same degrade-don't-crash guard as _type_uid_of: hit_distinct() builds a
    # set over these values, so a non-string (list/dict) ip would raise an
    # uncaught TypeError instead of just being skipped.
    return ip if isinstance(ip, str) else None


def _dst_ip_of(event: dict) -> Optional[str]:
    ip = (event.get("dst_endpoint") or {}).get("ip")
    return ip if isinstance(ip, str) else None


def _hour_of(event: dict, now_ms: int) -> int:
    """UTC hour-of-day of the observation.

    Uses the OCSF ``time`` (epoch ms, UTC by OCSF convention) when present,
    else the caller-supplied arrival ``now_ms``. 24 fixed slots make the
    learned hour-set naturally bounded (at most 24 members ever).
    """
    t = event.get("time")
    if isinstance(t, bool) or not isinstance(t, (int, float)):
        # bool is an int subclass in Python (isinstance(True, int) is True),
        # so a bare `not isinstance(t, (int, float))` silently accepted
        # time=True/False as epoch ms 1/0 instead of falling back to now_ms
        # -- inconsistent with every other time-validator in this codebase
        # (resolver.py/correlator.py/engine.py's _valid_window_time), which
        # all explicitly exclude bool (2026-09-02 review).
        t = now_ms
    return int(t) // 3_600_000 % 24


class BehavioralBaseline:
    """Per-entity behavioral baseline over a sliding warm-up window.

    State layout (kept deliberately tiny so the boundedness argument is
    checkable): two per-entity timestamp dicts (``_first_seen``,
    ``_last_seen``, both capped at ``max_entities``) + one injected window
    counter that owns ALL feature state. There is deliberately no private
    per-entity feature store: the window counter IS the store.
    """

    def __init__(
        self,
        *,
        counter: Optional["DequeWindowCounter"] = None,
        warm_up_ms: int = 86_400_000,  # 24h: reference window AND maturity span
        min_observations: int = 50,
        max_entities: int = 10_000,
        features: Tuple[str, ...] = FEATURES,
    ) -> None:
        if warm_up_ms <= 0:
            raise ValueError("warm_up_ms must be > 0")
        if min_observations < 1:
            raise ValueError("min_observations must be >= 1")
        if max_entities < 1:
            raise ValueError("max_entities must be >= 1")
        unknown = [f for f in features if f not in FEATURES]
        if unknown:
            raise ValueError(f"unknown baseline features: {unknown}")

        # Duck-typed counter (hit / hit_distinct / members / distinct_members).
        # Defaults to the in-process deque backend; a multi-replica deploy
        # injects RedisWindowCounter, exactly like engine.Rule.set_counter.
        self._counter = counter if counter is not None else DequeWindowCounter()
        self.warm_up_ms = int(warm_up_ms)
        self.min_observations = int(min_observations)
        self.max_entities = int(max_entities)
        self.features = tuple(features)

        # The ONLY per-entity bookkeeping. Both bounded by max_entities via
        # _evict_if_full + _sweep.
        self._first_seen: dict = {}
        self._last_seen: dict = {}
        self._observes = 0

    # -- public API -------------------------------------------------------

    @staticmethod
    def key(
        entity_id: Optional[str] = None,
        tenant: Optional[str] = None,
        entity_type: Optional[str] = None,
        entity_value: Optional[str] = None,
    ) -> str:
        """Deterministic per-entity key, ADR-009 first.

        ``entity_id`` (the WS-9 ``sha256("{tenant}|{type}|{value}")`` hex
        id from the entity plane) is used verbatim when given. The fallback
        for callers that only have the composite -- ``(tenant, entity_type,
        entity_value)`` -- is a length-prefixed join
        ``{tenant}:{len(type)}:{type}:{len(value)}:{value}``, mirroring
        ``engine.Rule._namespaced_group``: entity_value is attacker-controlled
        raw text, and length-prefixing makes the join unambiguous no matter
        what characters (including ':') it contains. This fallback key is
        NOT the ADR-009 sha256 -- canonicalizing the value is WS-9's job,
        and this module does not pretend to do it.
        """
        if entity_id is not None:
            return entity_id
        tenant = tenant or "default"
        entity_type = entity_type or "?"
        entity_value = entity_value or "?"
        return f"{tenant}:{len(entity_type)}:{entity_type}:{len(entity_value)}:{entity_value}"

    def observe(self, entity_key: str, event: dict, now_ms: int) -> dict:
        """Record one observation and return its verdict.

        Verdict dict (the additive deviation signal)::

            {"learned": bool,        # baseline mature for this entity?
             "deviation": bool,      # any feature outside learned normal?
             "reasons": [str, ...],  # per-feature explanations (why)
             "observations": int,    # distinct ingest_ids in-window (after add)
             "span_ms": int}         # now_ms - first_seen for this entity

        ``learned=False`` means "can't judge yet" -- the observation is
        still recorded, but NO deviation is ever reported during warm-up.
        The input ``event`` dict is not mutated.
        """
        own_id = _ingest_id_of(event)
        self._touch(entity_key, now_ms)

        # Observations window: distinct ingest_ids alive in the warm-up
        # window. Redelivery of the same event (same ingest_id) refreshes
        # rather than re-counts -- the counter's member dedup.
        obs_key = self._window_key(entity_key, "obs")
        observations = self._counter.hit(
            obs_key, now_ms, self.warm_up_ms, member=own_id
        )

        first_seen = self._first_seen.get(entity_key)
        span_ms = now_ms - first_seen if first_seen is not None else 0
        learned = (
            first_seen is not None
            and span_ms >= self.warm_up_ms
            and observations >= self.min_observations
        )

        # Feature windows are populated on EVERY observation -- including the
        # warm-up period -- so the baseline is BUILT while learning and only
        # *evaluated* once mature. (An earlier shape that skipped recording
        # until learned produced baselines that were empty at maturity and
        # flagged the entity's own normal values as unknown on first look.)
        before, values = self._record_features(entity_key, event, now_ms)
        reasons = self._reasons(before, values) if learned else []

        return {
            "learned": learned,
            "deviation": bool(reasons),
            "reasons": reasons,
            "observations": observations,
            "span_ms": span_ms,
        }

    def entity_count(self) -> int:
        """Number of entities currently tracked (bounded by max_entities)."""
        return len(self._last_seen)

    def snapshot(self, entity_key: str) -> dict:
        """Plain-data view of one entity's baseline state.

        Used by the determinism test: same observation sequence must produce
        an identical snapshot. Readings go through the counter's public
        read methods -- the counter is the store, so the snapshot also
        proves the reuse is real.
        """
        members = (
            list(self._counter.members(self._window_key(entity_key, "obs"))),
            [int(h) for h in self._counter.members(self._window_key(entity_key, "hour"))],
            [int(t) for t in self._counter.members(self._window_key(entity_key, "event_type"))],
        )
        distinct = (
            list(self._counter.distinct_members(self._window_key(entity_key, "src_ip"))),
            list(self._counter.distinct_members(self._window_key(entity_key, "dst_ip"))),
        )
        return {
            "first_seen": self._first_seen.get(entity_key),
            "last_seen": self._last_seen.get(entity_key),
            # Sets, not deques: the counter's member-REFRESH path legitimately
            # reorders a window by recency, so order is not part of the
            # baseline state contract -- membership (and therefore
            # double-counting) is.
            "observations": sorted(set(members[0])),
            "hours": sorted(set(members[1])),
            "event_types": sorted(set(members[2])),
            "src_ips": sorted(set(distinct[0])),
            "dst_ips": sorted(set(distinct[1])),
        }

    # -- internals --------------------------------------------------------

    def _window_key(self, entity_key: str, feature: str) -> str:
        # entity_key is either ADR-009 hex (no ':') or the length-prefixed
        # composite from key(); feature is a fixed ASCII constant -- the
        # join is unambiguous under either shape.
        return f"{_KEY_PREFIX}:{entity_key}:{feature}"

    def _touch(self, entity_key: str, now_ms: int) -> None:
        """LRU bookkeeping: register/re-fresh the entity, enforce the cap."""
        self._observes += 1
        self._first_seen[entity_key] = min(
            self._first_seen.get(entity_key, now_ms), now_ms
        )
        # max() so a redelivered/out-of-order old event cannot erase
        # recency (the entity stays alive as long as it keeps being seen).
        self._last_seen[entity_key] = max(self._last_seen.get(entity_key, 0), now_ms)
        if len(self._last_seen) > self.max_entities:
            self._evict_oldest()
        if self._observes % _SWEEP_EVERY == 0:
            self._sweep_idle(now_ms)

    def _evict_oldest(self) -> None:
        """Deterministic LRU drop: the tracked entity with the oldest
        last-seen timestamp. Tie-break on the key itself so eviction order
        is fully deterministic. Only the table row is dropped -- the window
        counter still owns that entity's feature state, which ages out on
        its own schedule (``warm_up_ms`` after the last observation)."""
        oldest = min(self._last_seen.items(), key=lambda kv: (kv[1], kv[0]))
        self._last_seen.pop(oldest[0], None)
        self._first_seen.pop(oldest[0], None)

    def _sweep_idle(self, now_ms: int) -> None:
        """Drop table rows for entities idle for a full warm-up window. Their
        counter windows are already empty (trimmed on the counter's side);
        this only removes the dead string keys -- the deque counter's
        idle-sweep discipline, applied to the entity table."""
        horizon = now_ms - self.warm_up_ms
        stale = [k for k, ts in self._last_seen.items() if ts < horizon]
        for k in stale:
            self._last_seen.pop(k, None)
            self._first_seen.pop(k, None)

    def _record_features(self, entity_key: str, event: dict, now_ms: int):
        """Populate each enabled feature's sliding window; return
        ``(before, values)`` for deviation evaluation.

        ``before`` maps feature -> the in-window set read BEFORE this
        observation (only for features with an extractable value); values
        are the observation's own per-feature values. Deviation is keyed on
        the PRE-observation set: the FIRST in-window sighting of a value
        (hour / src IP / type / dst IP) deviates; the hit then adds it, so
        a recurring value is re-learned into the baseline and stops flagging
        while it keeps recurring -- the same refresh semantics as the
        counter's member dedup ("a value alive in the window is known"). A
        value that stops recurring ages out ``warm_up_ms`` later and flags
        again on its next sighting.
        """
        before: dict = {}
        values: dict = {}

        if _FEATURE_HOUR in self.features:
            hour = _hour_of(event, now_ms)
            key = self._window_key(entity_key, _FEATURE_HOUR)
            before[_FEATURE_HOUR] = set(self._counter.members(key))
            self._counter.hit(key, now_ms, self.warm_up_ms, member=hour)
            values[_FEATURE_HOUR] = hour

        if _FEATURE_SRC_IP in self.features:
            ip = _src_ip_of(event)
            if ip is not None:
                key = self._window_key(entity_key, _FEATURE_SRC_IP)
                before[_FEATURE_SRC_IP] = set(self._counter.distinct_members(key))
                self._counter.hit_distinct(key, now_ms, self.warm_up_ms, value=ip)
                values[_FEATURE_SRC_IP] = ip

        if _FEATURE_EVENT_TYPE in self.features:
            tid = _type_uid_of(event)
            if tid is not None:
                key = self._window_key(entity_key, _FEATURE_EVENT_TYPE)
                before[_FEATURE_EVENT_TYPE] = set(self._counter.members(key))
                self._counter.hit(key, now_ms, self.warm_up_ms, member=tid)
                values[_FEATURE_EVENT_TYPE] = tid

        if _FEATURE_DST_IP in self.features:
            ip = _dst_ip_of(event)
            if ip is not None:
                key = self._window_key(entity_key, _FEATURE_DST_IP)
                before[_FEATURE_DST_IP] = set(self._counter.distinct_members(key))
                self._counter.hit_distinct(key, now_ms, self.warm_up_ms, value=ip)
                values[_FEATURE_DST_IP] = ip

        return before, values

    @staticmethod
    def _reasons(before: dict, values: dict) -> list:
        """One explicit reason per feature whose observation value was not in
        the learned (pre-observation) set. Absent fields never deviate --
        they are simply not in ``values``."""
        reasons: list = []
        if _FEATURE_HOUR in values and values[_FEATURE_HOUR] not in before.get(
            _FEATURE_HOUR, set()
        ):
            reasons.append(
                f"activity_hour={values[_FEATURE_HOUR]} outside baseline hours"
            )
        if _FEATURE_SRC_IP in values and values[_FEATURE_SRC_IP] not in before.get(
            _FEATURE_SRC_IP, set()
        ):
            reasons.append(f"unknown_src_ip={values[_FEATURE_SRC_IP]}")
        if (
            _FEATURE_EVENT_TYPE in values
            and values[_FEATURE_EVENT_TYPE] not in before.get(_FEATURE_EVENT_TYPE, set())
        ):
            reasons.append(f"unexpected_event_type={values[_FEATURE_EVENT_TYPE]}")
        if _FEATURE_DST_IP in values and values[_FEATURE_DST_IP] not in before.get(
            _FEATURE_DST_IP, set()
        ):
            reasons.append(f"unknown_dst_ip={values[_FEATURE_DST_IP]}")
        return reasons