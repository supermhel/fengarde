"""WS-8 correlation contract test: the 8 scenarios from the design doc's
test plan (docs/superpowers/specs/2026-08-18-ws8-correlation-build-plan.md).

Zero infrastructure: DequeWindowCounter (in-process) + directly-constructed
Allowlist objects, no Redis/OpenSearch needed.

Run: python services/ws8-correlation/test_contract.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.allowlist import Allowlist  # noqa: E402
from shared.window import DequeWindowCounter, RedisWindowCounter  # noqa: E402
from correlator import Correlator, InvalidTenant  # noqa: E402

FAILS: list[str] = []


class _BytesFakePipe:
    """Emulates a REAL (non-decode_responses) redis-py pipeline: ZRANGE
    (via RedisWindowCounter.members()) returns bytes, not str -- the exact
    shape that caused a live bug (2026-08-18): correlator.py's side table
    is keyed by plain str alert_ids, and `bytes_id not in {str_id, ...}` is
    always True, so every track silently lost all its members on the very
    next hit and nothing ever promoted on real Redis. Every OTHER fake
    Redis pipeline in this repo (ws4-detection/test_window*.py) stores and
    returns whatever type it's given, which is why none of them would have
    caught this -- this fake exists specifically to close that gap."""

    def __init__(self, store):
        self.store = store
        self.ops = []

    def zadd(self, key, mapping):
        self.ops.append(("zadd", key, mapping)); return self

    def zremrangebyscore(self, key, lo, hi):
        self.ops.append(("zremrangebyscore", key, lo, hi)); return self

    def zcard(self, key):
        self.ops.append(("zcard", key)); return self

    def expire(self, key, seconds):
        self.ops.append(("expire", key, seconds)); return self

    def execute(self):
        results = []
        for op in self.ops:
            kind = op[0]
            if kind == "zadd":
                _, key, mapping = op
                d = self.store.setdefault(key, {})
                for member, score in mapping.items():
                    d[str(member)] = score
                results.append(len(mapping))
            elif kind == "zremrangebyscore":
                _, key, lo, hi = op
                d = self.store.get(key, {})
                for m in [m for m, s in d.items() if lo <= s <= hi]:
                    del d[m]
                results.append(0)
            elif kind == "zcard":
                _, key = op
                results.append(len(self.store.get(key, {})))
            elif kind == "expire":
                results.append(True)
        self.ops = []
        return results


class _BytesFakeRedis:
    def __init__(self):
        self.store: dict = {}

    def pipeline(self):
        return _BytesFakePipe(self.store)

    def zrange(self, key, start, stop, withscores=False):
        d = self.store.get(key, {})
        items = sorted(d.items(), key=lambda kv: kv[1])
        if stop == -1:
            stop = len(items) - 1
        sliced = items[start:stop + 1]
        # THE POINT: members come back as bytes, matching real redis-py
        # with decode_responses unset/False.
        if withscores:
            return [(m.encode(), s) for m, s in sliced]
        return [m.encode() for m, _ in sliced]


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _Clock:
    def __init__(self, t: float = 1_700_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def _alert(alert_id, tactic=None, actor=None, ip=None, score=10, tenant="default", time_ms=None):
    a = {"alert_id": alert_id, "score": score, "tenant_id": tenant,
         "time": time_ms if time_ms is not None else 0}
    if tactic is not None:
        a["mitre"] = {"tactic": tactic}
    if actor is not None:
        a["actor"] = {"user": {"name": actor}}
    if ip is not None:
        a["src_endpoint"] = {"ip": ip}
    return a


def _new_correlator(allowlist_entries=None, **kwargs):
    return Correlator(DequeWindowCounter(), allowlist=Allowlist(allowlist_entries or []), **kwargs)


# --- 1. positive low-and-slow: two tactics on one actor -> incident --------
def test_positive_low_and_slow():
    c = _new_correlator()
    incs = c.ingest_alert(_alert("a1", tactic="TA0001", actor="alice"))
    check(incs == [], "1: single-tactic alert must not yet promote")
    incs = c.ingest_alert(_alert("a2", tactic="TA0002", actor="alice"))
    check(len(incs) == 1, "1: second distinct-tactic alert must promote exactly one incident")
    if incs:
        inc = incs[0]
        check(inc["entity_type"] == "actor" and inc["entity_value"] == "alice",
              "1: incident must be the actor:alice track")
        check(set(inc["tactics"]) == {"TA0001", "TA0002"}, "1: incident must carry both tactics")
        check(sorted(inc["member_alert_ids"]) == ["a1", "a2"], "1: incident must cite both alerts")


# --- 2 / 6. single-tactic non-promotion, incl. repeated volume -------------
def test_single_tactic_never_promotes():
    c = _new_correlator()
    for i in range(20):
        incs = c.ingest_alert(_alert(f"a{i}", tactic="TA0001", actor="bob"))
        check(incs == [], f"2/6: alert {i} of 20 same-tactic alerts must never promote")


# --- 3. NAT/DHCP: allowlisted IP never opens a track ------------------------
def test_allowlisted_ip_never_opens_track():
    c = _new_correlator(allowlist_entries=["203.0.113.5"])
    c.ingest_alert(_alert("a1", tactic="TA0001", ip="203.0.113.5"))
    c.ingest_alert(_alert("a2", tactic="TA0002", ip="203.0.113.5"))
    check(c._track_key("default", "ip", "203.0.113.5") not in c._sides,
          "3: an allowlisted IP must never get an ip: track entry at all")


# --- 4. unbounded growth: horizon eviction reclaims a quiet track ----------
def test_horizon_eviction_reclaims_quiet_track():
    clock = _Clock()
    c = _new_correlator(horizon_s=60, now_fn=clock)
    c.ingest_alert(_alert("old1", tactic="TA0001", actor="carol"))
    key = c._track_key("default", "actor", "carol")
    check("old1" in c._sides.get(key, {}), "4: freshly-ingested alert must be in the side table")
    clock.advance(61)  # past the 60s horizon
    c.ingest_alert(_alert("new1", tactic="TA0002", actor="carol"))
    check("old1" not in c._sides.get(key, {}),
          "4: an alert older than the horizon must be evicted from the side table")
    check("new1" in c._sides.get(key, {}), "4: the fresh alert must remain")


# --- 5. tenant isolation: same actor name, two tenants, never merge -------
def test_tenant_isolation():
    c = _new_correlator()
    incs_a = c.ingest_alert(_alert("t1", tactic="TA0001", actor="dave", tenant="acme"))
    incs_a += c.ingest_alert(_alert("t2", tactic="TA0002", actor="dave", tenant="acme"))
    incs_b = c.ingest_alert(_alert("t3", tactic="TA0001", actor="dave", tenant="beta"))
    incs_b += c.ingest_alert(_alert("t4", tactic="TA0002", actor="dave", tenant="beta"))
    check(len(incs_a) == 1 and len(incs_b) == 1, "5: each tenant's dave must independently promote")
    if incs_a and incs_b:
        check(incs_a[0]["incident_id"] != incs_b[0]["incident_id"],
              "5: two tenants must never share an incident_id")
        check(set(incs_a[0]["member_alert_ids"]).isdisjoint(incs_b[0]["member_alert_ids"]),
              "5: two tenants' incidents must never share member alert ids")
    check(c._track_key("acme", "actor", "dave") != c._track_key("beta", "actor", "dave"),
          "5: tenant must be part of the track key, not a filter")


def test_invalid_tenant_rejected_not_normalized():
    c = _new_correlator()
    try:
        c.ingest_alert(_alert("bad1", tactic="TA0001", actor="eve", tenant="Not Valid!"))
        check(False, "invalid tenant_id must raise, never be silently normalized")
    except InvalidTenant:
        pass


# --- 7. replay idempotency --------------------------------------------------
def test_replay_idempotency():
    c = _new_correlator()
    c.ingest_alert(_alert("r1", tactic="TA0001", actor="frank"))
    incs = c.ingest_alert(_alert("r2", tactic="TA0002", actor="frank"))
    check(len(incs) == 1, "7: promotion must fire on first delivery of the second alert")
    first_id = incs[0]["incident_id"]
    first_count = incs[0]["member_count"]
    # redeliver the SAME alert (at-least-once bus semantics)
    incs2 = c.ingest_alert(_alert("r2", tactic="TA0002", actor="frank"))
    check(len(incs2) == 1, "7: a redelivered alert on an already-promoted track still re-emits")
    check(incs2[0]["member_count"] == first_count,
          "7: redelivery of an already-counted alert must not inflate member_count")
    check(incs2[0]["incident_id"] == first_id,
          "7: redelivery must re-emit under the SAME incident_id (update, not a new incident)")


def test_incident_id_stable_across_a_horizon_bucket_boundary():
    """Regression (adversarial review, 2026-08-19): incident_id used to
    bucket on now_ms (wall-clock processing time), not on the track's own
    data. Two calls to the same track processed on opposite sides of a
    horizon-bucket boundary -- entirely plausible under real, asynchronous
    bus delivery -- minted TWO different incident_ids for one conceptual
    incident, silently forking it into two documents. incident_id must
    bucket on first_seen (the earliest live member's own time) instead,
    which stays anchored to the first alert as long as it hasn't aged out."""
    # horizon_s=1000 -> 1,000,000ms buckets. b1 is inserted at t=999s (bucket 0,
    # 999,000ms), b2 only 2s later at t=1001s (bucket 1, 1,001,000ms) -- a tiny
    # gap that leaves b1 comfortably inside the 1000s window (cutoff at the
    # second call is 1,001,000 - 1,000,000 = 1,000ms, and b1's insertion at
    # 999,000ms is far above that), so BOTH alerts are still live and
    # promotion fires -- the boundary crossing is the only thing under test.
    clock = _Clock(t=999.0)
    c = _new_correlator(horizon_s=1000, now_fn=clock)
    incs = c.ingest_alert(_alert("b1", tactic="TA0001", actor="judy", time_ms=999000))
    check(incs == [], "boundary: single-tactic alert must not yet promote")
    clock.advance(2)  # now at t=1001s -- crossed the bucket boundary (999_000 -> bucket 0; 1_001_000 -> bucket 1)
    incs = c.ingest_alert(_alert("b2", tactic="TA0002", actor="judy", time_ms=1001000))
    check(len(incs) == 1, "boundary: second distinct-tactic alert must promote (b1 must still be live)")
    if incs:
        # first_seen is b1's real time (999_000ms), so the bucket must be
        # 999_000 // 1_000_000 == 0 -- NOT the processing time's bucket
        # (1_001_000 // 1_000_000 == 1), which is what the bug used to compute.
        expected_id = "default:actor:judy:0"
        check(incs[0]["incident_id"] == expected_id,
              f"boundary: incident_id must bucket on first_seen (expected {expected_id!r}, "
              f"got {incs[0]['incident_id']!r} -- a now_ms-bucketed id would read "
              f"'default:actor:judy:1', forking this incident in two)")


# --- 8. no transitive merge -------------------------------------------------
def test_no_transitive_merge_via_shared_ip():
    c = _new_correlator()  # shared IP below is NOT allowlisted -- accepted-limitation path
    c.ingest_alert(_alert("s1", tactic="TA0001", actor="grace", ip="198.51.100.9"))
    incs = c.ingest_alert(_alert("s2", tactic="TA0002", actor="grace", ip="198.51.100.9"))
    actor_g_id = next(i["incident_id"] for i in incs if i["entity_type"] == "actor")
    c.ingest_alert(_alert("s3", tactic="TA0001", actor="heidi", ip="198.51.100.9"))
    incs2 = c.ingest_alert(_alert("s4", tactic="TA0002", actor="heidi", ip="198.51.100.9"))
    actor_h_id = next(i["incident_id"] for i in incs2 if i["entity_type"] == "actor")

    check(actor_g_id != actor_h_id, "8: two different actors must never share an incident_id")
    grace_key = c._track_key("default", "actor", "grace")
    heidi_key = c._track_key("default", "actor", "heidi")
    check(set(c._sides[grace_key]) == {"s1", "s2"}, "8: grace's track must hold only her own alerts")
    check(set(c._sides[heidi_key]) == {"s3", "s4"}, "8: heidi's track must hold only her own alerts")
    check(len({c._track_key("default", "actor", "grace"),
               c._track_key("default", "actor", "heidi"),
               c._track_key("default", "ip", "198.51.100.9")}) == 3,
          "8: actor A, actor B, and the shared IP must be three DISTINCT tracks, never merged")


# --- regression: RedisWindowCounter on a client that returns bytes --------
def test_promotion_works_with_real_redis_bytes_semantics():
    """The exact live bug (2026-08-18): re-runs scenario 1's positive
    promotion through RedisWindowCounter against a fake that returns bytes
    from ZRANGE (real redis-py's default without decode_responses=True).
    Must still promote correctly -- correlator.py normalizes member ids to
    str before comparing, so this must pass regardless of what type the
    window counter's backing client happens to return."""
    fake = _BytesFakeRedis()
    c = Correlator(RedisWindowCounter(fake), allowlist=Allowlist([]))
    incs = c.ingest_alert(_alert("bz1", tactic="TA0001", actor="ivan"))
    check(incs == [], "bytes-redis: single-tactic alert must not yet promote")
    incs = c.ingest_alert(_alert("bz2", tactic="TA0002", actor="ivan"))
    check(len(incs) == 1,
          "bytes-redis: second distinct-tactic alert must promote -- if this fails, "
          "the live 2026-08-18 bug (bytes never matching str side-table keys) is back")
    if incs:
        check(sorted(incs[0]["member_alert_ids"]) == ["bz1", "bz2"],
              "bytes-redis: incident must cite both alerts by their real str ids, not bytes")


def run_all():
    test_positive_low_and_slow()
    test_single_tactic_never_promotes()
    test_allowlisted_ip_never_opens_track()
    test_horizon_eviction_reclaims_quiet_track()
    test_tenant_isolation()
    test_invalid_tenant_rejected_not_normalized()
    test_replay_idempotency()
    test_incident_id_stable_across_a_horizon_bucket_boundary()
    test_no_transitive_merge_via_shared_ip()
    test_promotion_works_with_real_redis_bytes_semantics()


if __name__ == "__main__":
    run_all()
    if FAILS:
        print(f"[FAIL] WS-8 correlation: {len(FAILS)} problem(s)")
        for f in FAILS:
            print(f"  - {f}")
        sys.exit(1)
    print("[OK] WS-8 correlation contract test PASS (8/8 design-doc scenarios)")
