"""Tests for behavioral_baseline.py (WP-2-D, entity-plane baselines).

Standalone (NOT pytest) -- run from inside services/ws4-detection with the
venv python, mirroring test_window.py:

    cd services/ws4-detection
    python test_behavioral_baseline.py

Proves, with zero infrastructure and an injected clock (all times are
explicit ``now_ms`` arguments -- the module never reads the wall clock):

  (a) learn-then-detect: a normal period establishes a baseline; a deviating
      observation (different hour / unknown source IP / unexpected event
      type / unknown destination) is flagged with an explicit reason, and a
      normal observation is not.
  (b) bounded: a spray of distinct entity_ids (attacker-controlled key
      space) cannot grow memory without limit -- entity table capped at
      ``max_entities`` and the window-counter state shrinks after the
      sprayed windows age out.
  (c) deterministic: the same (event, now_ms) sequence produces the same
      baseline state on two fresh instances.
  (d) replay-safe: redelivered observations (same ingest_id) do not
      double-count -- observation count and learned sets are unchanged.
  (e) reuse proof: the module really stores everything in
      ``shared.window.DequeWindowCounter`` -- it has no private feature
      store of its own.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.window import DequeWindowCounter  # noqa: E402
from behavioral_baseline import BehavioralBaseline  # noqa: E402

FAILS: list = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


# --- fixture helpers -------------------------------------------------------

BASE = 1_750_000_000_000            # epoch ms; UTC hour 15
HOUR_MS = 3_600_000                 # one hour in ms
WARM_UP = 10 * HOUR_MS              # 10h warm-up window for the learn test


def _event(ingest_id, *, time_ms, src_ip="10.0.0.5", type_uid=400101,
           dst_ip="8.8.8.8"):
    """Minimal OCSF-normalized event dict (the shape normalized.events
    carries, with the siem.ingest_id the engine keys replay-dedup on)."""
    return {
        "time": time_ms,
        "type_uid": type_uid,
        "src_endpoint": {"ip": src_ip},
        "dst_endpoint": {"ip": dst_ip},
        "siem": {"ingest_id": ingest_id, "tenant": "default"},
    }


def _new_baseline(**kw):
    defaults = dict(warm_up_ms=WARM_UP, min_observations=5, max_entities=100)
    defaults.update(kw)
    return BehavioralBaseline(**defaults)


def _plain_counter_state(b):
    """Counter internals as comparable plain tuples."""
    c = b._counter
    return (
        tuple(sorted((k, tuple(v)) for k, v in c._w.items())),
        tuple(sorted((k, tuple(v)) for k, v in c._dw.items())),
        tuple(sorted(c._last.items())),
    )


def _learn_normal_period(b, entity, n=8):
    """Feed `entity` n hourly events (hours 15..15+n-1 UTC) from one src IP,
    one event type, one destination -- the 'normal' the entity is seen in."""
    for i in range(n):
        b.observe(entity, _event(f"ig-{entity}-{i}", time_ms=BASE + i * HOUR_MS),
                  now_ms=BASE + i * HOUR_MS)


# --- (a) learn-then-detect --------------------------------------------------

def test_learn_then_detect():
    b = _new_baseline()
    e = "ent-alpha"
    _learn_normal_period(b, e)

    # Deviation arrived > warm-up after the first normal observation, so the
    # obs window still holds n-1 normal events (i>=1) and the entity is
    # mature: span >= warm_up_ms AND observations >= min_observations.
    dev_now = BASE + WARM_UP + 1000

    # 1) different hour (UTC hour 1 -- normals were hours 16..22)
    v = b.observe(e, _event("ig-dev-hour", time_ms=dev_now), now_ms=dev_now)
    check(v["learned"], f"(a) entity should be learned, got {v}")
    check(v["deviation"], "(a) different-hour activity must deviate")
    check(v["reasons"] == ["activity_hour=1 outside baseline hours"],
          f"(a) expected single hour reason, got {v['reasons']}")

    # 2) unknown source IP
    v = b.observe(e, _event("ig-dev-src", time_ms=BASE + 3 * HOUR_MS,
                            src_ip="203.0.113.66"), now_ms=dev_now)
    check(v["deviation"], "(a) unknown src IP must deviate")
    check(v["reasons"] == ["unknown_src_ip=203.0.113.66"],
          f"(a) expected single src-ip reason, got {v['reasons']}")

    # 3) unexpected event type
    v = b.observe(e, _event("ig-dev-type", time_ms=BASE + 3 * HOUR_MS,
                            type_uid=400102), now_ms=dev_now)
    check(v["deviation"], "(a) unexpected event type must deviate")
    check(v["reasons"] == ["unexpected_event_type=400102"],
          f"(a) expected single type reason, got {v['reasons']}")

    # 4) unknown destination
    v = b.observe(e, _event("ig-dev-dst", time_ms=BASE + 3 * HOUR_MS,
                            dst_ip="1.1.1.1"), now_ms=dev_now)
    check(v["deviation"], "(a) unknown dst IP must deviate")
    check(v["reasons"] == ["unknown_dst_ip=1.1.1.1"],
          f"(a) expected single dst reason, got {v['reasons']}")

    # 5) a fully normal observation is NOT a deviation
    v = b.observe(e, _event("ig-normal-1", time_ms=BASE + 2 * HOUR_MS),
                  now_ms=dev_now)
    check(v["learned"], "(a) still learned after deviants")
    check(not v["deviation"], f"(a) normal observation must pass, got {v}")
    check(v["reasons"] == [], "(a) no reasons for a normal observation")

    # 6) never flags during warm-up: fresh entity, wouldn't-be-deviant hour
    fresh = "ent-fresh"
    v1 = b.observe(fresh, _event("ig-f1", time_ms=BASE), now_ms=BASE)
    v2 = b.observe(fresh, _event("ig-f2", time_ms=BASE + 60_000),
                   now_ms=BASE + 60_000)
    check(not v1["learned"] and not v1["deviation"],
          f"(a) warm-up entity must be 'can't judge yet', got {v1}")
    check(not v2["learned"] and not v2["deviation"],
          f"(a) warm-up entity must stay unjudged, got {v2}")

    # 7) span gate: many observations in a minute are still NOT learned
    burst = "ent-burst"
    for i in range(6):
        b.observe(burst, _event(f"ig-b{i}", time_ms=BASE + i * 1000),
                  now_ms=BASE + i * 1000)
    vb = b.observe(burst, _event("ig-b6", time_ms=BASE + 6 * 1000),
                   now_ms=BASE + 6 * 1000)
    check(not vb["learned"],
          f"(a) 1-minute burst must not mature an entity, got {vb}")

    # 8) the observation event dict is NOT mutated (least-invasive signal)
    ev = _event("ig-no-mutate", time_ms=BASE + 2 * HOUR_MS)
    before = dict(ev)
    b.observe(e, ev, now_ms=dev_now)
    check(ev == before, "(a) observe() must not mutate the input event")


# --- (b) bounded -------------------------------------------------------------

def test_bounded():
    cap = 500
    b = _new_baseline(max_entities=cap, warm_up_ms=60_000,
                      min_observations=2)
    base = BASE + 50_000_000_000  # far from the learn-test's timestamps
    N = 3000
    for i in range(N):
        entity = f"spray-{i:05d}"
        ip = f"10.0.{(i >> 8) & 255}.{i & 255}"
        b.observe(entity, _event(f"spray-ig-{i}", time_ms=base + i * 10,
                                 src_ip=ip, dst_ip="9.9.9.9"),
                  now_ms=base + i * 10)

    # the entity table is hard-capped -- 3000 sprayed never grow it past cap
    check(b.entity_count() == cap,
          f"(b) entity table must sit at the {cap}-entity cap after a "
          f"{N}-entity spray, got {b.entity_count()}")

    # the counter genuinely holds one 5-key window set per sprayed entity
    # (this is the honest intermediate state BEFORE aging does its job)
    live_before = len(b._counter._w) + len(b._counter._dw)
    check(live_before == N * 5,
          f"(b) window state right after spray should be {N * 5} keys, "
          f"got {live_before}")

    # advance the injected clock far past the warm-up window and keep the
    # bus busy: the counter's idle-key sweep drops EVERY sprayed window, so
    # memory shrinks back to ~(live pokes) -- never N.
    far_now = base + N * 10 + 2 * 60_000
    for i in range(70):
        b.observe(f"spray-{i:05d}",
                  _event(f"poke-ig-{i}", time_ms=far_now,
                         src_ip=f"10.99.99.{i}", dst_ip="9.9.9.9"),
                  now_ms=far_now)

    live_after = len(b._counter._w) + len(b._counter._dw)
    check(b.entity_count() <= cap,
          f"(b) entity table must never exceed the cap, got {b.entity_count()}")
    check(live_after < N * 5,
          f"(b) aged-out sprayed windows must be evicted: {live_after} live "
          f"keys vs {N * 5} right after the spray")
    check(live_after <= cap * 5 + 256,
          f"(b) live window state must be bounded by (cap x keys-per-entity) "
          f"+ sweep slack, got {live_after}")


# --- (c) deterministic --------------------------------------------------------

def test_deterministic():
    b1, b2 = _new_baseline(), _new_baseline()
    e = "ent-det"
    seq = []
    for i in range(8):
        seq.append((_event(f"ig-det-{i}", time_ms=BASE + i * HOUR_MS),
                    BASE + i * HOUR_MS))
    seq.append((_event("ig-det-x", time_ms=BASE + 2 * HOUR_MS,
                       src_ip="192.0.2.7"), BASE + WARM_UP + 500))
    for ev, now in seq:
        v1, v2 = b1.observe(e, ev, now), b2.observe(e, ev, now)
        check(v1 == v2, f"(c) verdicts diverged at now={now}: {v1} vs {v2}")

    check(b1.snapshot(e) == b2.snapshot(e),
          f"(c) entity snapshots diverged: {b1.snapshot(e)} vs "
          f"{b2.snapshot(e)}")
    check(_plain_counter_state(b1) == _plain_counter_state(b2),
          "(c) full counter state diverged for the same observation sequence")
    check(b1.entity_count() == b2.entity_count(), "(c) table sizes diverged")


# --- (d) replay-safe ------------------------------------------------------------

def test_replay_safe():
    b = _new_baseline()
    e = "ent-replay"
    _learn_normal_period(b, e)
    dev_now = BASE + WARM_UP + 1000

    # normal event delivered twice (at-least-once redelivery)
    ev = _event("ig-dedup", time_ms=BASE + 2 * HOUR_MS)
    v_first = b.observe(e, ev, now_ms=dev_now)
    snap_first = b.snapshot(e)
    v_replay = b.observe(e, ev, now_ms=dev_now + 1000)
    snap_replay = b.snapshot(e)

    check(v_first["learned"] and not v_first["deviation"], "(d) control pass")
    check(v_replay["observations"] == v_first["observations"],
          f"(d) redelivery must not double-count observations: "
          f"{v_first['observations']} -> {v_replay['observations']}")
    check(v_replay == {**v_first, "span_ms": v_first["span_ms"] + 1000},
          f"(d) redelivered normal event must be judged identically, "
          f"{v_first} vs {v_replay}")
    check(snap_replay == {**snap_first, "last_seen": snap_first["last_seen"] + 1000},
          f"(d) learned sets must not grow on redelivery: "
          f"{snap_first} vs {snap_replay}")

    # deviant event delivered twice: first delivery flags it, redelivery
    # must not ADD anything (same member/value dedup as the counter) --
    # observation count and set sizes stay put
    dev = _event("ig-dev-replay", time_ms=dev_now, src_ip="198.51.100.9")
    d1 = b.observe(e, dev, now_ms=dev_now)
    snap1 = b.snapshot(e)
    check(d1["deviation"] and "unknown_src_ip=198.51.100.9" in d1["reasons"],
          f"(d) first delivery of a deviant src IP must flag, got {d1}")
    # NOTE: last_seen is already dev_now+1000 (the ig-dedup replay bumped it),
    # so the ig-dev-replay redelivery at dev_now+2000 bumps it by a further
    # 1000 -- proving recency is refreshed but nothing else moves.
    d2 = b.observe(e, dev, now_ms=dev_now + 2000)
    snap2 = b.snapshot(e)
    check(d2["observations"] == d1["observations"],
          f"(d) deviant redelivery must not double-count observations, "
          f"{d1['observations']} -> {d2['observations']}")
    check(snap2 == {**snap1, "last_seen": snap1["last_seen"] + 1000},
          f"(d) deviant redelivery must not grow any learned set: "
          f"{snap1} vs {snap2}")


# --- (e) reuse proof ----------------------------------------------------------

def test_reuse_proof():
    b = _new_baseline()
    check(isinstance(b._counter, DequeWindowCounter),
          "(e) default counter must be shared.window.DequeWindowCounter")

    # the window counter IS the store: after observations, every feature
    # set read by the baseline lives in the counter's own keyspace
    e = "ent-reuse"
    _learn_normal_period(b, e, n=3)
    b.observe(e, _event("ig-reuse-x", time_ms=BASE + 2 * HOUR_MS,
                        src_ip="203.0.113.7"), now_ms=BASE + 2 * HOUR_MS)
    check(set(b._counter.members(f"bbv1:{e}:obs")) ==
          {f"ig-ent-reuse-{j}" for j in range(3)} | {"ig-reuse-x"},
          "(e) observations must live in the counter's obs window")
    check(set(b._counter.members(f"bbv1:{e}:hour")) == {15, 16, 17},
          "(e) learned hours must live in the counter's hour window")
    check(set(b._counter.distinct_members(f"bbv1:{e}:src_ip")) ==
          {"10.0.0.5", "203.0.113.7"},
          "(e) learned src-IP set must live in the counter's distinct window")
    check(set(b._counter.members(f"bbv1:{e}:event_type")) == {400101},
          "(e) learned types must live in the counter's type window")

    # by construction: the baseline keeps ONLY timestamp bookkeeping per
    # entity -- no private feature store exists to grow unboundedly
    own = set(vars(b))
    check(own <= {"_counter", "warm_up_ms", "min_observations",
                  "max_entities", "features", "_first_seen",
                  "_last_seen", "_observes"},
          f"(e) unexpected per-entity state on the baseline: {own}")

    # fallback entity key: length-prefixed composite, deterministic,
    # unambiguous under attacker-controlled values containing ':'
    k1 = BehavioralBaseline.key(entity_id="a" * 64)
    check(k1 == "a" * 64, "(e) ADR-009 entity_id must pass through verbatim")
    k2 = BehavioralBaseline.key(tenant="t", entity_type="user",
                                entity_value="a:b")
    k3 = BehavioralBaseline.key(tenant="t", entity_type="user:",
                                entity_value="b")
    check(k2 == "t:4:user:3:a:b", f"(e) composite key shape wrong: {k2}")
    check(k2 != k3, "(e) length-prefixing must prevent ':' collisions")


# --- feature gating (small extra) ----------------------------------------------

def test_feature_gating():
    b = _new_baseline(features=("hour",))
    e = "ent-gate"
    _learn_normal_period(b, e, n=6)
    gate_now = BASE + WARM_UP + 500  # mature (span >= warm_up, obs >= min)
    # src_ip feature disabled -> a NEW src IP must not deviate...
    v = b.observe(e, _event("ig-gate-1", time_ms=BASE + 2 * HOUR_MS,  # hour 17, in set
                            src_ip="203.0.113.55"), now_ms=gate_now)
    check(v["learned"], f"(g) gate entity should be learned by now, got {v}")
    check(not v["deviation"],
          "(g) src_ip feature disabled -> a new src IP must not deviate")
    # ...while the enabled hour feature still does
    v = b.observe(e, _event("ig-gate-2", time_ms=gate_now),  # hour 1, outside set
                  now_ms=gate_now + 1000)
    check(v["deviation"] and "activity_hour" in v["reasons"][0],
          "(g) hour feature enabled -> new hour must still deviate")


def main():
    test_learn_then_detect()
    test_bounded()
    test_deterministic()
    test_replay_safe()
    test_reuse_proof()
    test_feature_gating()
    if FAILS:
        print(f"[FAIL] behavioral baselines: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] behavioral baselines (learn/detect, bounded, deterministic, "
          "replay-safe, DequeWindowCounter reuse) PASS")


if __name__ == "__main__":
    main()