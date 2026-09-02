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
from correlator import Correlator, InvalidTenant, _SIDES_SWEEP_EVERY  # noqa: E402

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


def _alert(alert_id, tactic=None, actor=None, ip=None, mac=None, hostname=None,
           score=10, tenant="default", time_ms=None):
    a = {"alert_id": alert_id, "score": score, "tenant_id": tenant,
         "time": time_ms if time_ms is not None else 0}
    if tactic is not None:
        a["mitre"] = {"tactic": tactic}
    if actor is not None:
        a["actor"] = {"user": {"name": actor}}
    if ip is not None or mac is not None or hostname is not None:
        src = {}
        if ip is not None:
            src["ip"] = ip
        if mac is not None:
            src["mac"] = mac
        if hostname is not None:
            src["hostname"] = hostname
        a["src_endpoint"] = src
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


# --- 9. pivot-correlation: mac stays stable across a DHCP IP change --------
def test_device_track_correlates_across_ip_change():
    """The documented "actor pivots to a new IP" gap, closed 2026-08-19:
    same host (mac AA:BB:CC:DD:EE:FF), two DIFFERENT ips, two DIFFERENT
    tactics, NO actor identity ever captured (pre-auth/unauthenticated --
    the case the pre-existing actor: track can't help with, since it has
    nothing to key on). The ip: tracks alone never see 2 tactics each
    (one tactic per ip), so only the device: track can promote this."""
    c = _new_correlator()
    incs = c.ingest_alert(_alert("d1", tactic="TA0043", ip="10.0.0.5", mac="AA:BB:CC:DD:EE:FF"))
    check(incs == [], "9: first device alert (recon, ip1) must not yet promote")
    incs = c.ingest_alert(_alert("d2", tactic="TA0006", ip="10.0.0.9", mac="AA:BB:CC:DD:EE:FF"))
    check(len(incs) == 1, "9: second device alert (new ip, new tactic) must promote via device: track")
    if incs:
        inc = incs[0]
        check(inc["entity_type"] == "device" and inc["entity_value"] == "AA:BB:CC:DD:EE:FF",
              "9: promoted incident must be the device: track, not an ip: track")
        check(set(inc["tactics"]) == {"TA0043", "TA0006"}, "9: incident must carry both tactics")
        check(sorted(inc["member_alert_ids"]) == ["d1", "d2"], "9: incident must cite both alerts")


def test_device_track_falls_back_to_hostname_without_mac():
    c = _new_correlator()
    c.ingest_alert(_alert("h1", tactic="TA0043", ip="10.0.0.5", hostname="WORKSTATION7"))
    incs = c.ingest_alert(_alert("h2", tactic="TA0006", ip="10.0.0.9", hostname="WORKSTATION7"))
    check(len(incs) == 1, "9b: hostname-only device linkage (no mac in either alert) must still promote")
    if incs:
        check(incs[0]["entity_value"] == "WORKSTATION7",
              "9b: without a mac, the device: track must key on hostname")


def test_device_track_never_merges_with_actor_or_ip_tracks():
    """The device: track is a THIRD independent leg, same non-merge
    discipline as actor:/ip: (test 8) -- one alert carrying actor + ip +
    mac all together must open three DISTINCT tracks, not one."""
    c = _new_correlator()
    c.ingest_alert(_alert("m1", tactic="TA0001", actor="mallory", ip="10.0.0.5",
                           mac="11:22:33:44:55:66"))
    keys = {
        c._track_key("default", "actor", "mallory"),
        c._track_key("default", "ip", "10.0.0.5"),
        c._track_key("default", "device", "11:22:33:44:55:66"),
    }
    check(len(keys) == 3, "9c: actor, ip, and device must be three distinct track keys")
    check(all(k in c._sides for k in keys), "9c: all three tracks must independently record the alert")


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


# --- regression: _sides/_last_incident must not grow unbounded ------------
def test_sweep_dead_tracks_prunes_stale_but_not_live_tracks():
    """Regression (independent review, 2026-08-19): `_update_track`'s own
    per-hit prune only ever touches the ONE key being hit right now, so a
    track that receives alerts and is then never touched again grew
    `_sides`/`_last_incident` forever -- reproduced live as 5000 sprayed
    source IPs each opening a track that never shrank, even long after
    every one had aged out of its own window (see `_sweep_dead_tracks`'s
    docstring for the fix). Calls the sweep directly (same internals-access
    style the rest of this file already uses for `_sides`/`_track_key`) so
    the scenario doesn't depend on hitting an exact call-count boundary:
    a promoted, still-live track and 3 abandoned one-shot tracks, advanced
    past the horizon, one sweep call -- the abandoned ones must go, the
    live one must not (preserving the `test_replay_idempotency` contract:
    only evict an incident once its OWN track's membership is genuinely
    gone, never merely because time passed)."""
    clock = _Clock()
    c = _new_correlator(horizon_s=60, now_fn=clock)

    c.ingest_alert(_alert("s1", tactic="TA0001", actor="oscar"))
    c.ingest_alert(_alert("s2", tactic="TA0001", actor="peggy"))
    c.ingest_alert(_alert("s3", tactic="TA0001", actor="quinn"))
    stale_keys = [c._track_key("default", "actor", n) for n in ("oscar", "peggy", "quinn")]
    check(all(k in c._sides for k in stale_keys), "sweep: setup -- all 3 one-shot tracks recorded")

    clock.advance(61)  # past the 60s horizon -- oscar/peggy/quinn are now stale

    # a fresh, still-live, promoted track, touched AFTER the horizon passed
    c.ingest_alert(_alert("keep1", tactic="TA0001", actor="norah"))
    incs = c.ingest_alert(_alert("keep2", tactic="TA0002", actor="norah"))
    keep_id = incs[0]["incident_id"]
    keep_key = c._track_key("default", "actor", "norah")

    c._sweep_dead_tracks(c._now_ms())

    check(all(k not in c._sides for k in stale_keys),
          "sweep: all 3 abandoned one-shot tracks must be pruned from _sides")
    check(keep_key in c._sides, "sweep: a track touched after the horizon passed must survive")
    check(keep_id in c._last_incident, "sweep: its incident must survive too")

    # replay idempotency must still hold for the surviving live track
    incs2 = c.ingest_alert(_alert("keep2", tactic="TA0002", actor="norah"))
    check(incs2[0]["incident_id"] == keep_id,
          "sweep: redelivery on a track that survived the sweep must still "
          "re-emit under the SAME incident_id")


def test_update_track_wires_sweep_at_the_right_cadence():
    """Confirms `_sweep_dead_tracks` is actually invoked periodically from
    `_update_track` (the previous test exercises the sweep's own logic
    directly) -- `_SIDES_SWEEP_EVERY - 1` one-shot alerts stay below the
    trigger point, then exactly one more call crosses it and must shrink
    `_sides` back down, mirroring `shared/window.py`'s own `_SWEEP_EVERY`
    cadence test shape."""
    clock = _Clock()
    c = _new_correlator(horizon_s=60, now_fn=clock)
    for i in range(_SIDES_SWEEP_EVERY - 1):
        c.ingest_alert(_alert(f"spray{i}", tactic="TA0001", actor=f"sprayed-{i}"))
    check(len(c._sides) == _SIDES_SWEEP_EVERY - 1,
          "cadence: no sweep should have run yet (below the trigger threshold)")

    clock.advance(61)  # past the 60s horizon -- every sprayed track is now stale
    # this single call is _update_track call #_SIDES_SWEEP_EVERY -- the sweep's
    # own trigger point -- and opens a brand-new key that can't itself be stale
    c.ingest_alert(_alert("trigger1", tactic="TA0001", actor="trigger-actor"))

    check(len(c._sides) == 1,
          f"cadence: crossing the sweep threshold must prune every stale track, "
          f"leaving only the just-created one, got {len(c._sides)}")


# --- gap-hunt (2026-08-26): member_cap memory + tactics correctness ---------
def test_member_cap_bounds_side_table_and_keeps_tactics():
    """Findings #1/#2/#3 + the task's reproduction: 1 recon alert + 400
    brute-force alerts through the REAL correlator. The bug: member_cap
    truncated members BEFORE computing tactics, so past the cap the live
    list showed only the one-tactic flood -> the incident silently froze
    (alerts #199-399 emitted nothing), _sides[key] itself grew unboundedly
    (401 entries at cap 200), and first_seen shifted as truncation moved the
    minimum -> one incident under multiple ids. Now: side table bounded at
    the cap, tactics/first_seen from a stable per-track aggregate, incident
    keeps re-emitting under ONE id for the whole flood."""
    clock = _Clock()
    c = _new_correlator(member_cap=10, now_fn=clock)
    incs = c.ingest_alert(_alert("recon1", tactic="TA0043", actor="mallory"))
    check(incs == [], "cap: recon alone must not yet promote")
    first_id = None
    emitted = 0
    saw_truncated = False
    for i in range(400):
        incs = c.ingest_alert(_alert(f"bf-{i}", tactic="TA0006", actor="mallory"))
        if incs:
            emitted += 1
            if first_id is None:
                first_id = incs[0]["incident_id"]
            check(incs[0]["incident_id"] == first_id,
                  f"cap: incident_id must stay STABLE under truncation (alert bf-{i})")
            check(set(incs[0]["tactics"]) == {"TA0043", "TA0006"},
                  f"cap: tactics must keep BOTH tactics past the cap (alert bf-{i}) -- "
                  "a frozen single-tactic doc is the bug")
            check(incs[0]["member_count"] <= 10,
                  f"cap: emitted member_count must never exceed member_cap (alert bf-{i})")
            if incs[0]["truncated"]:
                saw_truncated = True
    key = c._track_key("default", "actor", "mallory")
    check(len(c._sides[key]) <= 10,
          f"cap: side table must stay bounded at member_cap (got {len(c._sides[key])})")
    check(emitted == 400,
          f"cap: incident must keep re-emitting under a sustained flood (emitted {emitted}/400) -- "
          "alerts #199-399 emitting nothing is the bug")
    check(saw_truncated,
          "cap: truncated flag must be set once the flood passes the cap")


def test_severity_cap_clamps_score_sum():
    """Truncation path (gap-hunt nit): severity = min(score sum, 1000) had
    zero coverage; the 1000 ceiling is part of the same capped-payload
    family as member_cap/truncated."""
    c = _new_correlator(member_cap=20)
    c.ingest_alert(_alert("sev1", tactic="TA0001", actor="sev-user", score=700))
    incs = c.ingest_alert(_alert("sev2", tactic="TA0002", actor="sev-user", score=700))
    check(len(incs) == 1, "sev-cap: two-tactic track must promote")
    if incs:
        check(incs[0]["severity"] == 1000,
              f"sev-cap: score sum 1400 must clamp to 1000, got {incs[0]['severity']}")


def test_sweep_prunes_stale_promoted_tracks_last_incident():
    """Finding #11: the `_last_incident` pruning branch was only ever
    exercised by UNPROMOTED one-shot tracks -- a PROMOTED track going stale
    must also have its incident pruned (and, once the actor returns fresh,
    a NEW incident is minted rather than resurrecting the dead one)."""
    clock = _Clock()
    c = _new_correlator(horizon_s=60, now_fn=clock)
    c.ingest_alert(_alert("pd1", tactic="TA0001", actor="stale-promo"))
    incs = c.ingest_alert(_alert("pd2", tactic="TA0002", actor="stale-promo"))
    stale_id = incs[0]["incident_id"]
    stale_key = c._track_key("default", "actor", "stale-promo")
    check(stale_id in c._last_incident, "promo-sweep: promoted incident must be recorded")
    check(stale_key in c._side_meta, "promo-sweep: aggregate must be recorded")

    clock.advance(61)  # the promoted track's window membership is now fully gone
    c._sweep_dead_tracks(c._now_ms())

    check(stale_key not in c._sides, "promo-sweep: stale promoted side table must be pruned")
    check(stale_key not in c._side_meta,
          "promo-sweep: stale promoted aggregate must be pruned")
    check(stale_id not in c._last_incident,
          "promo-sweep: stale PROMOTED incident must be pruned from _last_incident "
          "-- this branch never ran for promoted tracks before")

    # the actor returning fresh must mint a NEW incident (old one is gone),
    # and the pipeline must still work for the fresh track
    incs = c.ingest_alert(_alert("pd3", tactic="TA0001", actor="stale-promo"))
    incs += c.ingest_alert(_alert("pd4", tactic="TA0002", actor="stale-promo"))
    check(len(incs) == 1, "promo-sweep: a fresh return must promote again")
    if incs:
        check(incs[0]["incident_id"] != stale_id,
              "promo-sweep: a fresh track must mint a NEW incident_id, not reuse the pruned one")


# --- gap-hunt (2026-08-26): degrade-don't-crash on malformed/no-op alerts ---
def test_ws5_shaped_alert_is_skipped_with_reason():
    """Finding #4: WS-5's enrichment alert payload (alert_id, time, level,
    classification, event_ids -- no actor/src_endpoint/mitre/tenant_id)
    used to be a SILENT no-op in correlation. Must degrade, not crash: no
    incident, but the skip is recorded in metrics()."""
    c = _new_correlator()
    incs = c.ingest_alert({
        "alert_id": "ai-ev1",
        "time": 100,
        "level": "medium",
        "classification": {"label": "suspicious"},
        "sector": "core",
        "event_ids": ["ev-1"],
    })
    check(incs == [], "ws5: alert with no trackable entity -> no incident")
    metrics = c.metrics()
    check(metrics["ws8_skipped_alerts_by_reason"].get("no_trackable_entity") == 1,
          f"ws5: the no-op must be recorded as a skip reason, got {metrics['ws8_skipped_alerts_by_reason']}")


def test_missing_alert_id_never_dedups_unrelated_alerts():
    """Finding #5: a missing alert_id stringified to the literal 'None',
    so every id-less alert collapsed onto ONE member -- two unrelated
    id-less alerts could never promote, and unrelated alerts deduplicated
    against each other. Synthetic per-alert ids (time/rule/event_ids) keep
    them distinct; redelivering the SAME id-less alert must re-derive the
    same member (idempotency preserved)."""
    c = _new_correlator()
    c.ingest_alert({"time": 100, "rule_id": "r1", "event_ids": ["e1"],
                    "score": 5, "mitre": {"tactic": "TA0001"},
                    "actor": {"user": {"name": "no-id-user"}}})
    incs = c.ingest_alert({"time": 200, "rule_id": "r1", "event_ids": ["e2"],
                           "score": 5, "mitre": {"tactic": "TA0002"},
                           "actor": {"user": {"name": "no-id-user"}}})
    check(len(incs) == 1,
          "no-id: two distinct id-less alerts (2 tactics) must promote -- collapsing "
          "onto literal 'None' would leave one member and never promote")
    if incs:
        check(sorted(incs[0]["member_alert_ids"]) == ["anon:100:r1:e1", "anon:200:r1:e2"],
              f"no-id: members must be distinct synthetic ids, got {incs[0]['member_alert_ids']}")
    # redelivery of the SAME id-less alert (same time/rule/event_ids) must
    # re-derive the same member id -> member_count stays put
    redelivered = c.ingest_alert({"time": 200, "rule_id": "r1", "event_ids": ["e2"],
                                  "score": 5, "mitre": {"tactic": "TA0002"},
                                  "actor": {"user": {"name": "no-id-user"}}})
    check(redelivered and redelivered[0]["member_count"] == 2,
          "no-id: redelivered id-less alert must re-derive the same synthetic member id")
    check(redelivered[0]["incident_id"] == incs[0]["incident_id"],
          "no-id: redelivery must re-emit under the same incident_id")


def test_entity_value_bounded_under_opensearch_doc_id_limit():
    """Finding #7: an attacker-controlled actor/hostname past ~512 bytes
    made the incident doc id (which embeds entity_value) an OpenSearch
    document-id rejection -- an attacker-suppressible incident. entity_value
    must be bounded (truncate + stable hash), the incident_id must stay
    under 512 bytes, the original value must remain visible
    (entity_value_full), and two distinct long values must never
    false-merge onto one track."""
    c = _new_correlator()
    long_name = "x" * 600
    c.ingest_alert(_alert("big1", tactic="TA0001", actor=long_name))
    incs = c.ingest_alert(_alert("big2", tactic="TA0002", actor=long_name))
    check(len(incs) == 1, "long-value: a long entity_value track must still promote")
    if incs:
        inc = incs[0]
        check(len(inc["incident_id"].encode("utf-8")) <= 512,
              f"long-value: incident_id must stay under the 512-byte OpenSearch doc-id limit, "
              f"got {len(inc['incident_id'].encode('utf-8'))} bytes")
        check("x" * 600 not in inc["incident_id"],
              "long-value: the raw 600-char value must NOT be embedded in the incident_id")
        check(len(inc["entity_value"].encode("utf-8")) <= 448,
              f"long-value: bounded entity_value must stay under the byte budget, "
              f"got {len(inc['entity_value'].encode('utf-8'))}")
        check(inc["entity_value"] != long_name, "long-value: entity_value must be bounded")
        check(inc.get("entity_value_full") == long_name,
              "long-value: the original value must be preserved in entity_value_full")
    other_long = "y" * 600
    c.ingest_alert(_alert("big3", tactic="TA0003", actor=other_long))
    check(c._track_key("default", "actor", c._bounded_entity_value(long_name)) !=
          c._track_key("default", "actor", c._bounded_entity_value(other_long)),
          "long-value: two distinct long values must stay on DISTINCT tracks (stable hash suffix)")


def test_device_track_respects_allowlist():
    """Finding #6: the device: track keyed on a spoofable, unauthenticated
    hostname had no allowlist (unlike the ip: leg). Shared infrastructure
    must never open a device: track either; a non-listed hostname must
    still correlate normally."""
    c = _new_correlator(allowlist_entries=["GATEWAY-CORP"])
    c.ingest_alert(_alert("g1", tactic="TA0001", hostname="GATEWAY-CORP"))
    c.ingest_alert(_alert("g2", tactic="TA0002", hostname="GATEWAY-CORP"))
    key = c._track_key("default", "device", "GATEWAY-CORP")
    check(key not in c._sides,
          "device-allowlist: allowlisted hostname must never open a device: track")
    check(c._skip_reasons.get("allowlisted_device") == 2,
          f"device-allowlist: suppression must be observable in skip reasons, "
          f"got {c._skip_reasons}")

    c2 = _new_correlator(allowlist_entries=["GATEWAY-CORP"])
    incs = c2.ingest_alert(_alert("n1", tactic="TA0043", hostname="WORKSTATION9"))
    incs += c2.ingest_alert(_alert("n2", tactic="TA0006", hostname="WORKSTATION9"))
    check(any(i["entity_type"] == "device" for i in incs),
          "device-allowlist: a non-listed hostname must still open/promote a device: track")


def test_actor_user_as_plain_string_degrades_not_crashes():
    """Finding #8: a malformed `actor.user` plain string used to raise
    AttributeError on `.get("name")`. Must degrade: no actor track, no
    crash, and the alert's OTHER legs (ip here) keep working."""
    c = _new_correlator()
    incs = c.ingest_alert({
        "alert_id": "u1", "score": 5, "tenant_id": "default", "time": 0,
        "mitre": {"tactic": "TA0001"},
        "actor": {"user": "plain-string-user"},
        "src_endpoint": {"ip": "10.1.1.1"},
    })
    check(incs == [], "actor-string: must not crash, and no actor: track may open")
    check(c._track_key("default", "ip", "10.1.1.1") in c._sides,
          "actor-string: the ip: leg must still record the alert")


def test_main_redis_window_counter_uses_own_namespace():
    """Finding #10: main.py built RedisWindowCounter with WS-4's default
    'ws4:win' namespace -- a latent zset collision (reference-review
    finding). WS-8 must use its own namespace, matching INTERFACE.md's
    documented `ws8:corr` key prefix. Static assertion on the shipped
    wiring (make_correlator only constructs it under BUS_BACKEND=redis)."""
    src = (HERE / "main.py").read_text(encoding="utf-8")
    check('RedisWindowCounter(client, namespace="ws8:corr")' in src,
          "namespace: main.py must construct RedisWindowCounter with ws8's "
          "OWN namespace (ws8:corr), not WS-4's ws4:win default")


def test_ipv6_spelling_variants_promote_one_incident():
    """IPv6 identity gap (2026-08-29 review): case- and compression-variant
    spellings of ONE address must key the SAME ip: track and promote ONE
    incident. Old behavior keyed the raw spelling -- a two-tactic spray
    across spellings of one address never promoted (identity-evasion)."""
    c = _new_correlator()
    incs1 = c.ingest_alert(_alert("v1", tactic="TA0001",
                                  ip="2001:0db8:0000:0000:0000:0000:0000:0001"))
    incs2 = c.ingest_alert(_alert("v2", tactic="TA0002", ip="2001:DB8::1"))
    ip_incs = [i for i in incs1 + incs2 if i["entity_type"] == "ip"]
    check(len(ip_incs) == 1,
          f"ipv6: two spellings of one address must promote ONE ip: incident "
          f"(spelling split is identity-evasion), got {len(ip_incs)} "
          f"ip-track incidents")
    if ip_incs:
        check(ip_incs[0]["entity_value"] == "2001:db8::1",
              f"ipv6: the incident must carry the canonical spelling, got "
              f"{ip_incs[0]['entity_value']!r}")


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
    test_device_track_correlates_across_ip_change()
    test_device_track_falls_back_to_hostname_without_mac()
    test_device_track_never_merges_with_actor_or_ip_tracks()
    test_promotion_works_with_real_redis_bytes_semantics()
    test_sweep_dead_tracks_prunes_stale_but_not_live_tracks()
    test_update_track_wires_sweep_at_the_right_cadence()
    test_member_cap_bounds_side_table_and_keeps_tactics()
    test_severity_cap_clamps_score_sum()
    test_sweep_prunes_stale_promoted_tracks_last_incident()
    test_ws5_shaped_alert_is_skipped_with_reason()
    test_missing_alert_id_never_dedups_unrelated_alerts()
    test_entity_value_bounded_under_opensearch_doc_id_limit()
    test_device_track_respects_allowlist()
    test_ipv6_spelling_variants_promote_one_incident()
    test_actor_user_as_plain_string_degrades_not_crashes()
    test_main_redis_window_counter_uses_own_namespace()


if __name__ == "__main__":
    run_all()
    if FAILS:
        print(f"[FAIL] WS-8 correlation: {len(FAILS)} problem(s)")
        for f in FAILS:
            print(f"  - {f}")
        sys.exit(1)
    print("[OK] WS-8 correlation contract test PASS (8/8 design-doc scenarios "
          "+ 3 pivot-correlation device: track scenarios + 2 dead-track-sweep "
          "scenarios + 9 gap-hunt scenarios: member-cap boundedness/tactics, "
          "severity cap, promoted-track sweep, WS-5 skip, alert_id fallback, "
          "entity_value bound, device allowlist, actor.user degrade, ws8 namespace)")
