"""WS-8 per-track correlator state: where tactics, scores and member entries live.

``Correlator`` used to keep ``_sides`` (member entries) and ``_side_meta``
(first_seen / tactics / truncated) in process dicts while only window
MEMBERSHIP lived in Redis. After a restart a track's members were counted but
its tactics were gone, and two replicas each held half the tactics, so an
incident formed only when both tactics landed on one replica.

Two backends behind one interface, selected like the window counter
(``main.make_correlator``):

- ``MemoryTrackState`` -- the old dicts, default, zero-infra (BUS_BACKEND=memory).
- ``RedisTrackState`` -- the same data in Redis so every replica, and a restarted
  one, sees the same tracks. Design: docs/ws8-shared-correlator-state-design.md.

Every Redis write is commutative and idempotent (entry keyed by its
deterministic member id, first_seen = min, tactics = set-add), so replicas
racing on one track converge on the union of what they recorded.
"""
from __future__ import annotations

import json

NAMESPACE = "ws8:state"

#: One atomic record step. KEYS: side hash, meta hash, tactics set.
#: ARGV: member, entry json, tactic ('' = none), entry time (ms), ttl seconds.
_RECORD_LUA = """
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
local fs = redis.call('HGET', KEYS[2], 'first_seen')
if (not fs) or tonumber(ARGV[4]) < tonumber(fs) then
  redis.call('HSET', KEYS[2], 'first_seen', ARGV[4])
end
if ARGV[3] ~= '' then
  redis.call('SADD', KEYS[3], ARGV[3])
end
redis.call('EXPIRE', KEYS[1], ARGV[5])
redis.call('EXPIRE', KEYS[2], ARGV[5])
redis.call('EXPIRE', KEYS[3], ARGV[5])
return 1
"""


class MemoryTrackState:
    """In-process state (the original behaviour, kept byte-for-byte)."""

    shared = False

    def __init__(self) -> None:
        self.sides: dict[str, dict] = {}
        self.metas: dict[str, dict] = {}
        self._claimed: set = set()
        self.cids: dict[str, str] = {}

    def record(self, key: str, member: str, entry: dict, now_ms: int) -> None:
        self.sides.setdefault(key, {})[member] = entry
        meta = self.metas.setdefault(
            key, {"first_seen": entry["time"], "tactics": set(), "truncated": False})
        meta["first_seen"] = min(meta["first_seen"], entry["time"])
        if entry["tactic"]:
            meta["tactics"].add(entry["tactic"])

    def snapshot(self, key: str) -> tuple[dict, dict]:
        return dict(self.sides.get(key, {})), self.metas[key]

    def prune(self, key: str, member_ids) -> None:
        side = self.sides.get(key)
        for m in member_ids:
            if side is not None:
                side.pop(m, None)

    def mark_truncated(self, key: str) -> None:
        self.metas[key]["truncated"] = True

    def claim_incident(self, incident_id: str) -> bool:
        if incident_id in self._claimed:
            return False
        self._claimed.add(incident_id)
        return True

    def bind_incident_id(self, key: str, candidate: str) -> str:
        return self.cids.setdefault(key, candidate)

    def forget_track(self, key: str) -> None:
        self.sides.pop(key, None)
        self.metas.pop(key, None)
        self.cids.pop(key, None)

    def forget_incident(self, incident_id: str) -> None:
        self._claimed.discard(incident_id)


class RedisTrackState:
    """Shared state in Redis; survives a restart and converges across replicas."""

    shared = True

    def __init__(self, client, ttl_s: int, namespace: str = NAMESPACE) -> None:
        self.r = client
        self.ns = namespace
        self.ttl_s = max(1, int(ttl_s))

    def _k(self, kind: str, key: str) -> str:
        return f"{self.ns}:{kind}:{key}"

    def record(self, key: str, member: str, entry: dict, now_ms: int) -> None:
        payload = json.dumps(entry, separators=(",", ":"), sort_keys=True)
        self.r.eval(_RECORD_LUA, 3, self._k("side", key), self._k("meta", key),
                    self._k("tac", key), member, payload, entry["tactic"] or "",
                    int(entry["time"]), self.ttl_s)

    def snapshot(self, key: str) -> tuple[dict, dict]:
        pipe = self.r.pipeline()
        pipe.hgetall(self._k("side", key))
        pipe.hgetall(self._k("meta", key))
        pipe.smembers(self._k("tac", key))
        raw_side, raw_meta, tactics = pipe.execute()
        side = {}
        for member, blob in raw_side.items():
            entry = json.loads(blob)
            entry["cooccur"] = [tuple(p) for p in entry.get("cooccur") or []]
            ts = entry.get("typed_signal")
            entry["typed_signal"] = tuple(ts) if ts is not None else None
            side[member] = entry
        meta = {"first_seen": int(raw_meta["first_seen"]),
                "tactics": set(tactics),
                "truncated": raw_meta.get("truncated") == "1"}
        return side, meta

    def prune(self, key: str, member_ids) -> None:
        ids = list(member_ids)
        if ids:
            self.r.hdel(self._k("side", key), *ids)

    def mark_truncated(self, key: str) -> None:
        self.r.hset(self._k("meta", key), "truncated", "1")

    def claim_incident(self, incident_id: str) -> bool:
        k = self._k("inc", incident_id)
        pipe = self.r.pipeline()
        pipe.set(k, "1", nx=True, ex=self.ttl_s)
        pipe.expire(k, self.ttl_s)
        return bool(pipe.execute()[0])

    def bind_incident_id(self, key: str, candidate: str) -> str:
        """First promoter's id wins for the track's lifetime (SET NX), so replicas never mint two ids."""
        k = self._k("cid", key)
        pipe = self.r.pipeline()
        pipe.set(k, candidate, nx=True, ex=self.ttl_s)
        pipe.get(k)
        pipe.expire(k, self.ttl_s)
        return pipe.execute()[1]

    def forget_track(self, key: str) -> None:
        pass  # EXPIRE reclaims abandoned tracks

    def forget_incident(self, incident_id: str) -> None:
        pass
