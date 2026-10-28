"""WS-8 shared correlator state: restart survival + multi-replica convergence.

Per-track tactics/scores/members used to live in process memory while only window
membership was in Redis, so (a) a restart lost the tactics and (b) two replicas each
saw half of them. These tests drive Correlators over ONE shared fake Redis (the
"restart" is a fresh Correlator on the same store; a "replica" is a second one) and
assert incidents form, converge on one id, and are not double-minted.
Zero-infra; the live Redis proof is in docs/ws8-shared-correlator-state-design.md.

Run: python services/ws8-correlation/test_shared_state.py
"""
from __future__ import annotations

import fnmatch
import os
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.allowlist import Allowlist  # noqa: E402
from shared.window import DequeWindowCounter, RedisWindowCounter  # noqa: E402
from correlator import Correlator  # noqa: E402
import track_state  # noqa: E402
from track_state import MemoryTrackState, RedisTrackState  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _Pipe:
    def __init__(self, r):
        self.r, self.ops = r, []

    def __getattr__(self, name):
        def queue(*a, **kw):
            self.ops.append((name, a, kw))
            return self
        return queue

    def execute(self):
        return [getattr(self.r, n)(*a, **kw) for n, a, kw in self.ops]


class FakeRedis:
    """The Redis subset ws8 uses (zset window + hash/set/string track state)."""

    def __init__(self):
        self.d: dict = {}
        self.ttl: dict = {}

    def pipeline(self):
        return _Pipe(self)

    def info(self, section=None):
        return {"redis_version": "7.2.0"}

    # zset (RedisWindowCounter)
    def zadd(self, k, m, gt=False):
        z = self.d.setdefault(k, {})
        for mem, sc in m.items():
            if not gt or mem not in z or sc > z[mem]:
                z[mem] = sc

    def zremrangebyscore(self, k, lo, hi):
        z = self.d.get(k, {})
        for mem in [m for m, s in z.items() if lo <= s <= hi]:
            del z[mem]

    def zcard(self, k):
        return len(self.d.get(k, {}))

    def zrange(self, k, a, b, withscores=False):
        z = sorted(self.d.get(k, {}).items(), key=lambda kv: kv[1])
        return z if withscores else [m for m, _ in z]

    def expire(self, k, s):
        if k in self.d:
            self.ttl[k] = s
        return 1

    # hash / set / string (RedisTrackState)
    def hset(self, k, f, v):
        self.d.setdefault(k, {})[f] = v

    def hget(self, k, f):
        return self.d.get(k, {}).get(f)

    def hgetall(self, k):
        return dict(self.d.get(k, {}))

    def hdel(self, k, *fs):
        for f in fs:
            self.d.get(k, {}).pop(f, None)

    def sadd(self, k, v):
        self.d.setdefault(k, set()).add(v)

    def smembers(self, k):
        return set(self.d.get(k, set()))

    def get(self, k):
        return self.d.get(k)

    def set(self, k, v, nx=False, ex=None):
        if nx and k in self.d:
            return None
        self.d[k] = v
        return True

    def eval(self, script, numkeys, *args):
        assert script == track_state._RECORD_LUA, "unexpected script"
        side, meta, tac = args[:3]
        member, payload, tactic, t, ttl = args[3:8]
        self.hset(side, member, payload)
        fs = self.hget(meta, "first_seen")
        if fs is None or int(t) < int(fs):
            self.hset(meta, "first_seen", str(int(t)))
        if tactic != "":
            self.sadd(tac, tactic)
        for k in (side, meta, tac):
            self.ttl[k] = ttl
        return 1


T0 = 1_750_000_000_000
NOW = [T0 + 10_000_000]


def _alert(aid, tactic, actor="mallory", ip=None, t=T0, score=10):
    a = {"alert_id": aid, "tenant_id": "acme", "time": t, "score": score,
         "mitre": {"tactic": tactic}, "actor": {"user": {"name": actor}}}
    if ip:
        a["src_endpoint"] = {"ip": ip}
    return a


def _replica(store, shared=True, wc=None, **kw):
    state = RedisTrackState(store, ttl_s=86401) if shared else MemoryTrackState()
    return Correlator(wc if wc is not None else RedisWindowCounter(store, namespace="ws8:corr"),
                      allowlist=Allowlist([]), now_fn=lambda: NOW[0] / 1000,
                      track_state=state, **kw)


def test_baseline_without_shared_state_loses_tactics():
    """The bug: shared window membership but per-process tactics -> no incident."""
    store = FakeRedis()
    a, b = _replica(store, shared=False), _replica(store, shared=False)
    a.ingest_alert(_alert("a1", "TA0006"))
    out = b.ingest_alert(_alert("a2", "TA0008"))
    check(not any(i["entity_type"] == "actor" for i in out),
          "baseline: memory state on two replicas unexpectedly formed an incident")


def test_restart_survival():
    store = FakeRedis()
    a = _replica(store)
    check(a.ingest_alert(_alert("a1", "TA0006")) == [], "restart: one tactic must not promote")
    restarted = _replica(store)               # fresh process, same Redis
    out = [i for i in restarted.ingest_alert(_alert("a2", "TA0008")) if i["entity_type"] == "actor"]
    check(len(out) == 1, f"restart: incident must form after restart, got {out}")
    if out:
        check(out[0]["tactics"] == ["TA0006", "TA0008"], f"restart: tactics {out[0]['tactics']}")
        check(out[0]["member_count"] == 2 and out[0]["member_alert_ids"] == ["a1", "a2"],
              f"restart: members {out[0]['member_alert_ids']}")
        check(out[0]["severity"] == 20, f"restart: scores must survive, severity={out[0]['severity']}")


def test_two_replicas_converge_one_incident_id():
    for first, second in ((0, 1), (1, 0)):                 # both orderings
        store = FakeRedis()
        reps = [_replica(store), _replica(store)]
        r1 = reps[first].ingest_alert(_alert("a1", "TA0006"))
        r2 = reps[second].ingest_alert(_alert("a2", "TA0008"))
        inc = [i for i in r1 + r2 if i["entity_type"] == "actor"]
        check(len(inc) == 1, f"convergence({first}{second}): exactly one incident emission, got {len(inc)}")
        # both replicas now emit the SAME incident (same deterministic id), same members
        r3 = reps[first].ingest_alert(_alert("a3", "TA0006"))
        r4 = reps[second].ingest_alert(_alert("a4", "TA0008"))
        ids = {i["incident_id"] for i in inc + r3 + r4 if i["entity_type"] == "actor"}
        check(len(ids) == 1, f"convergence({first}{second}): replicas minted different ids {ids}")
        last = [i for i in r4 if i["entity_type"] == "actor"][0]
        check(last["member_count"] == 4, f"convergence({first}{second}): union of members, got {last['member_count']}")


def test_no_duplicate_incidents_under_redelivery_and_double_promotion():
    store = FakeRedis()
    reps = [_replica(store), _replica(store)]
    reps[0].ingest_alert(_alert("a1", "TA0006"))
    reps[1].ingest_alert(_alert("a2", "TA0008"))           # promotes on replica 1
    for _ in range(3):                                      # at-least-once redelivery, both replicas
        for r in reps:
            for al in (_alert("a1", "TA0006"), _alert("a2", "TA0008")):
                out = [i for i in r.ingest_alert(al) if i["entity_type"] == "actor"]
                check(len(out) == 1 and out[0]["member_count"] == 2,
                      f"redelivery changed the incident: {out}")
    total = sum(r.metrics()["ws8_promotions_total"] for r in reps)
    check(total == 1, f"an incident must be counted as promoted ONCE across replicas, got {total}")


def test_horizon_boundary_does_not_fork_the_incident_id():
    """Two alerts of one chain straddle a horizon boundary and arrive out of order: before the sticky id,
    the late early-stamped alert lowered first_seen into the previous bucket and minted a second id."""
    for shared in (True, False):                  # shared Redis state (two replicas) and plain memory
        store = FakeRedis()
        r1 = _replica(store, shared=shared)
        r2 = _replica(store, shared=shared) if shared else r1
        edge = (NOW[0] // r1.horizon_ms) * r1.horizon_ms   # a boundary in the past (future stamps are rejected)
        out = r1.ingest_alert(_alert("b", "TA0008", t=edge + 1)) + r1.ingest_alert(_alert("c", "TA0006", t=edge + 2))
        out += r2.ingest_alert(_alert("a", "TA0006", t=edge - 1))   # late, stamped in the previous bucket
        out += r1.ingest_alert(_alert("a", "TA0006", t=edge - 1))   # redelivery on the other replica
        ids = {i["incident_id"] for i in out if i["entity_type"] == "actor"}
        check(len(ids) == 1, f"horizon boundary (shared={shared}): one chain minted ids {sorted(ids)}")
        last = [i for i in out if i["entity_type"] == "actor"][-1]
        check(last["first_seen"] == edge - 1 and last["member_count"] == 3,
              f"horizon boundary (shared={shared}): payload must still carry the true min / all members: {last}")


def test_first_seen_is_min_across_replicas():
    store = FakeRedis()
    a, b = _replica(store), _replica(store)
    a.ingest_alert(_alert("late", "TA0006", t=T0 + 5_000))
    out = [i for i in b.ingest_alert(_alert("early", "TA0008", t=T0 + 1_000))
           if i["entity_type"] == "actor"][0]
    check(out["first_seen"] == T0 + 1_000, f"first_seen must be the min, got {out['first_seen']}")


def test_member_cap_and_truncated_flag_shared():
    store = FakeRedis()
    a, b = _replica(store, member_cap=3), _replica(store, member_cap=3)
    a.ingest_alert(_alert("r0", "TA0043", t=T0))
    out = []
    for i in range(1, 8):
        out = (a if i % 2 else b).ingest_alert(_alert(f"bf{i}", "TA0006", t=T0 + i * 1000))
    inc = [x for x in out if x["entity_type"] == "actor"][0]
    check(inc["member_count"] == 3 and inc["truncated"] is True, f"cap: {inc['member_count']} {inc['truncated']}")
    check(inc["tactics"] == ["TA0006", "TA0043"], f"cap: tactics survive eviction, got {inc['tactics']}")


def test_graph_survives_restart():
    store = FakeRedis()
    a = _replica(store)
    a.ingest_alert(_alert("a1", "TA0006", ip="203.0.113.9"))
    b = _replica(store)
    out = [i for i in b.ingest_alert(_alert("a2", "TA0008", ip="203.0.113.9"))
           if i["entity_type"] == "actor"][0]
    g = b.incident_graph(out["incident_id"])
    check(g is not None and g["version"] == 2 and len(g["nodes"]) == 2 and len(g["edges"]) == 1,
          f"graph must rebuild from shared members after restart: {g}")


def test_tracks_expire_and_tenants_isolated():
    store = FakeRedis()
    a = _replica(store)
    a.ingest_alert(_alert("a1", "TA0006"))
    keys = [k for k in store.d if k.startswith("ws8:state:")]
    check(keys and all(store.ttl.get(k) == 86401 for k in keys), f"state keys need a TTL: {store.ttl}")
    other = _alert("b1", "TA0008")
    other["tenant_id"] = "globex"
    out = _replica(store).ingest_alert(other)
    check(not any(i["entity_type"] == "actor" for i in out), "tenant isolation: globex must not see acme's tactics")


def test_make_correlator_selection():
    import importlib.util
    spec = importlib.util.spec_from_file_location("ws8_main_ss", HERE / "main.py")
    main = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(main)
    store = FakeRedis()

    class _R:
        @classmethod
        def from_url(cls, url, **kw):
            return store
    fake = types.ModuleType("redis")
    fake.Redis = _R
    saved = sys.modules.get("redis")
    sys.modules["redis"] = fake
    try:
        for k in ("BUS_BACKEND", "REDIS_URL"):
            os.environ.pop(k, None)
        os.environ["BUS_BACKEND"] = "memory"
        c = main.make_correlator()
        check(isinstance(c.state, MemoryTrackState) and isinstance(c.window_counter, DequeWindowCounter),
              "memory backend must stay in-process")
        os.environ["BUS_BACKEND"] = "redis"
        c = main.make_correlator()
        check(isinstance(c.state, RedisTrackState), f"redis backend must use RedisTrackState, got {type(c.state)}")
    finally:
        os.environ.pop("BUS_BACKEND", None)
        if saved is not None:
            sys.modules["redis"] = saved
        else:
            sys.modules.pop("redis", None)


def test_redis_error_propagates_for_redelivery():
    """A failing shared-state write must raise (runner leaves the message unacked) and the
    redelivery must then succeed without double counting."""
    store = FakeRedis()
    real_eval = store.eval
    calls = {"n": 0}

    def flaky(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("master failed over")
        return real_eval(*a, **kw)
    store.eval = flaky
    c = _replica(store)
    try:
        c.ingest_alert(_alert("a1", "TA0006"))
        check(False, "state write failure must raise")
    except ConnectionError:
        pass
    c.ingest_alert(_alert("a1", "TA0006"))
    out = [i for i in c.ingest_alert(_alert("a2", "TA0008")) if i["entity_type"] == "actor"][0]
    check(out["member_count"] == 2, f"redelivery after failure: {out['member_count']}")


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    if FAILS:
        print(f"[FAIL] ws8 shared state: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] ws8 shared state (restart survival, two-replica convergence, no duplicate incidents) PASS")


if __name__ == "__main__":
    main()
