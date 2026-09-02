"""WS-9 entity resolver contract test (WP-2-B, ADR-009).

Standalone (no pytest), mirroring the ws8-correlation test shape: a `check`
accumulator + a `run_all()` and a FAILS summary. Zero infrastructure: the
in-memory `shared.bus` Bus (BUS_BACKEND=memory) and a directly-constructed
EntityResolver with an injected clock.

Covers the WS-9 acceptance contract:
  (a) deterministic  -- same identity input -> same entity_id
  (b) distinct       -- different tenant/type/value -> different entity_id
  (c) canonicalize   -- IP / MAC / username variants -> SAME entity_id
  (d) replay idem.   -- the same alert twice -> one logical entity state,
                        same entity_id, no last_seen regression
  (e) redelivery-safe-- a replayed entity.updates re-applied is a no-op, and a
                        full memory-bus round trip (produce alert -> cg-entity
                        handler -> entity.updates on the bus) yields exactly
                        the deterministic id.

Run:  python services/ws9-resolver/test_contract.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.bus import Bus  # noqa: E402

import main as ws9_main  # noqa: E402  (import side: brings resolver on path)
from entity_id import canonical_entity_value, compute_entity_id  # noqa: E402
from resolver import EntityResolver, InvalidTenant  # noqa: E402

FAILS: list[str] = []


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


def _alert(alert_id, tenant="default", time_ms=None, actor=None, src_ip=None,
           dst_ip=None, mac=None, hostname=None, tactic=None):
    a = {"alert_id": alert_id, "tenant_id": tenant,
         "time": time_ms if time_ms is not None else 0}
    if tactic is not None:
        a["mitre"] = {"tactic": tactic}
    if actor is not None:
        a["actor"] = {"user": {"name": actor}}
    src = {}
    if src_ip is not None:
        src["ip"] = src_ip
    if mac is not None:
        src["mac"] = mac
    if hostname is not None:
        src["hostname"] = hostname
    if src:
        a["src_endpoint"] = src
    if dst_ip is not None:
        a["dst_endpoint"] = {"ip": dst_ip}
    return a


def _new(clock=None, **kwargs) -> EntityResolver:
    return EntityResolver(now_fn=clock or _Clock(), **kwargs)


# --- (a) deterministic identity --------------------------------------------
def test_same_input_same_entity_id():
    r = _new()
    eid = compute_entity_id("default", "actor", "alice")
    check(compute_entity_id("default", "actor", "alice") == eid,
          "a: identical preimage must re-derive the identical entity_id")
    # ... across two independent resolver instances, same alert shape
    u1 = r.resolve_alert(_alert("a1", actor="alice", src_ip="10.0.0.5"))
    r2 = _new()
    u2 = r2.resolve_alert(_alert("a1", actor="alice", src_ip="10.0.0.5"))
    ids1 = {u["entity_id"] for u in u1}
    ids2 = {u["entity_id"] for u in u2}
    check(ids1 == ids2, f"a: two instances must agree on every entity_id, got {ids1} vs {ids2}")
    check(compute_entity_id("default", "actor", "alice") in ids1,
          "a: the actor entity_id must equal the pure-hash of the ADR preimage")
    # entity_id is a real sha256 (64 hex chars), not a stringified hash object
    check(len(eid) == 64 and all(c in "0123456789abcdef" for c in eid),
          f"a: entity_id must be a 64-char sha256 hex digest, got {eid!r}")


# --- (b) distinct inputs -> distinct ids ------------------------------------
def test_distinct_tenant_type_value_distinct_id():
    base = compute_entity_id("default", "actor", "alice")
    check(compute_entity_id("acme", "actor", "alice") != base,
          "b: different tenant must give a different entity_id (tenant isolation)")
    check(compute_entity_id("default", "ip", "alice") != base,
          "b: different entity_type must give a different entity_id")
    check(compute_entity_id("default", "actor", "bob") != base,
          "b: different canonical value must give a different entity_id")


# --- (c) canonicalization ----------------------------------------------------
def test_canonicalization_ip_variants_same_id():
    base = compute_entity_id("default", "ip", "10.0.0.5")
    # IPv4-mapped-IPv6 collapses to the same plain IPv4 (shared valid_ip).
    check(canonical_entity_value("ip", "::ffff:10.0.0.5") == "10.0.0.5",
          "c: valid_ip must collapse ::ffff:10.0.0.5 -> 10.0.0.5")
    check(compute_entity_id("default", "ip", canonical_entity_value("ip", "::ffff:10.0.0.5")) == base,
          "c: ::ffff:10.0.0.5 must hash to the same entity_id as 10.0.0.5")
    # an unparseable IP must degrade to NO canonical value (None), never hash garbage
    check(canonical_entity_value("ip", "not-an-ip at all") is None,
          "c: invalid IP must canonicalize to None (entity skipped, never fabricated)")


def test_canonicalization_mac_variants_same_id():
    base = compute_entity_id("default", "device", "aa:bb:cc:dd:ee:ff")
    check(canonical_entity_value("device", "AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff",
          "c: MAC must be lowercased")
    check(compute_entity_id("default", "device", canonical_entity_value("device", "AA:BB:CC:DD:EE:FF")) == base,
          "c: AA:BB:CC:DD:EE:FF must hash to the same entity_id as its lowercase form")


def test_canonicalization_username_variants_same_id():
    base = compute_entity_id("default", "actor", "alice")
    for variant in ("Alice", "ALICE", "ALICE "):
        canon = canonical_entity_value("actor", variant.rstrip())
        check(canon == "alice",
              f"c: username {variant!r} must case-fold to 'alice', got {canon!r}")
    check(compute_entity_id("default", "actor", canonical_entity_value("actor", "Alice")) == base,
          "c: 'Alice' must hash to the same entity_id as 'alice'")
    # ... through the FULL resolver on a real alert shape
    r = _new()
    up_alice = r.resolve_alert(_alert("c1", actor="Alice", src_ip="10.0.0.5"))
    r2 = _new()
    up_alice2 = r2.resolve_alert(_alert("c2", actor="alice", src_ip="10.0.0.5"))

    def _actor_id(updates):
        return next(u for u in updates if u["entity_type"] == "actor")["entity_id"]

    check(_actor_id(up_alice) == _actor_id(up_alice2),
          "c: resolver must give one actor entity_id across username casing")


def test_canonicalization_location_mac_vs_hostname():
    # device value is mac-or-hostname (ws8 correlator.py:576); hostnames are
    # case-insensitive, so the device edge lowercases both.
    r = _new()
    up = r.resolve_alert(_alert("c3", mac="AA:BB:CC:DD:EE:FF"))
    dev = next(u for u in up if u["entity_type"] == "device")
    check(dev["entity_value"] == "aa:bb:cc:dd:ee:ff",
          "c: device entity_value must be the lowercased MAC")
    check(dev["entity_id"] == compute_entity_id("default", "device", "aa:bb:cc:dd:ee:ff"),
          "c: device entity_id must hash the lowercased MAC")


# --- (d) replay idempotency ---------------------------------------------------
def test_replay_same_alert_twice_is_one_logical_state():
    clock = _Clock()
    r = _new(clock)
    alert = _alert("replay-1", actor="mallory", src_ip="198.51.100.7",
                   mac="11:22:33:44:55:66", time_ms=1_700_000_000_000, tactic="TA0001")
    first = r.resolve_alert(alert)
    check(len(first) == 3, f"d: one fully-populated alert must resolve 3 entities (actor/ip/device), got {len(first)}")
    ids = {u["entity_id"] for u in first}
    check(len(ids) == 3, f"d: entity_ids must be distinct per trackable entity, got {len(ids)}")
    first_last_seen = {u["entity_id"]: u["last_seen_ms"] for u in first}
    first_meta = {u["entity_id"]: dict(r.entity_state(u["entity_id"]) or {}) for u in first}
    before_count = r.count()
    before_updates = r.resolved_updates

    # -- at-least-once redelivery: the SAME alert processed a second time --
    replay = r.resolve_alert(alert)
    check(len(replay) == 3, "d: redelivery must re-emit the same 3 payloads (at-least-once)")

    # exactly one logical entity state per entity_id
    check(r.count() == before_count,
          f"d: replay must not create duplicate entity state (count {before_count} -> {r.count()})")
    check(all(u["entity_id"] in ids for u in replay),
          "d: replay must produce the SAME entity_ids")
    # no regression of last_seen, no change to ANY state field
    for u in replay:
        check(u["last_seen_ms"] == first_last_seen[u["entity_id"]],
              f"d: replay must not move last_seen for {u['entity_id']}")
        cur = r.entity_state(u["entity_id"])
        check(cur["last_seen_ms"] == u["last_seen_ms"]
              and cur["first_seen_ms"] == u["first_seen_ms"]
              and cur == first_meta[u["entity_id"]],
              f"d: entity state after replay must be byte-identical to after first pass for {u['entity_id']}")
    check(r.resolved_updates == before_updates,
          f"d: replay must not count as a new state change (got {r.resolved_updates} vs {before_updates})")

    # and the replayed payloads are strict no-ops when re-applied (self-consumer path)
    changed = any(r.apply_update(u) for u in replay)
    check(not changed, "d: re-applying a replayed update must be a no-op (returns False)")


# --- (e) redelivery-safe memory-bus round trip --------------------------------
def test_memory_bus_round_trip_deterministic_entity_id():
    """Produce one alert-ish input onto the real (memory) bus, drive it
    through the EXACT ws9 main.py handler wiring, and assert an
    entity.updates message carrying the deterministic entity_id appears --
    then redeliver the same alert and show the upsert is a state no-op."""
    clock = _Clock()
    bus = Bus()
    resolver = EntityResolver(now_fn=clock)
    handler = ws9_main.make_handler(bus, resolver)

    alert = _alert("e2e-1", tenant="acme", actor="carol", src_ip="203.0.113.9",
                   time_ms=1_700_000_000_500, tactic="TA0001")
    bus.produce("alerts", key=alert["alert_id"], payload=alert)
    delivered = []
    for msg in bus.consume("alerts", group="cg-entity"):
        delivered.append(msg)
        handler(msg.payload)
    check(len(delivered) == 1, "e: exactly one alert must be delivered to cg-entity")

    updates = [m for m in bus.consume("entity.updates", group="cg-test")]
    check(len(updates) == 2, f"e: one alert must produce 2 entity.updates (actor+ip), got {len(updates)}")
    keyed = {m.key: m.payload for m in updates}
    for m in updates:
        p = m.payload
        check(set(p) == {"entity_id", "entity_type", "tenant_id", "entity_value",
                         "first_seen_ms", "last_seen_ms", "attributes"},
              f"e: payload must carry exactly the ADR-009 field set, got {sorted(p)}")
        check(m.key == p["entity_id"], "e: bus partition key must be entity_id")
        check(p["tenant_id"] == "acme", "e: tenant_id must flow through")
    expected_actor = compute_entity_id("acme", "actor", "carol")
    check(expected_actor in keyed, "e: an actor entity.updates must appear under the deterministic id")
    check(keyed[expected_actor]["entity_value"] == "carol", "e: entity_value must be the canonical actor name")
    exp_ip = compute_entity_id("acme", "ip", "203.0.113.9")
    check(exp_ip in keyed, "e: an ip entity.updates must appear under the deterministic id")

    # redelivery through the bus (at-least-once): same alert, delivered again
    bus.produce("alerts", key=alert["alert_id"], payload=alert)
    for msg in bus.consume("alerts", group="cg-entity"):
        handler(msg.payload)
    updates2 = [m for m in bus.consume("entity.updates", group="cg-test")]
    check(len(updates2) == 2, "e: redelivery must re-emit exactly the same 2 payloads")
    for m in updates2:
        p = m.payload
        check(p["entity_id"] == keyed[p["entity_id"]]["entity_id"]
              and p["last_seen_ms"] == keyed[p["entity_id"]]["last_seen_ms"],
              f"e: redelivered {p['entity_id']} must carry the same entity_id + non-newer last_seen_ms")
    # the redelivered payloads are no-ops against current state (ADR rule)
    changed = any(resolver.apply_update(m.payload) for m in updates2)
    check(not changed, "e: applying the redelivered payloads must be a no-op (replay-safe)")
    check(resolver.count() == 2, "e: exactly 2 logical entity states after redelivery")


# --- tenant discipline (mirror ws8/ws6: reject, never normalize) ------------
def test_invalid_tenant_rejected_not_normalized():
    r = _new()
    try:
        r.resolve_alert(_alert("bad-tenant", tenant="Not Valid!", actor="eve"))
        check(False, "invalid tenant_id must raise InvalidTenant, never be normalized")
    except InvalidTenant:
        pass


# --- independent-review regressions (D1/D3/D4) ------------------------------


def test_time_less_replay_stable_under_advancing_clock():
    """D3 regression: a time-less alert redelivered LATER (clock advanced) must
    re-derive the SAME time anchor, so last_seen_ms never moves and the
    entity stays state-identical. (Old code embedded wall-clock now_ms; the
    frozen test clock masked it.)"""
    clock = _Clock()
    r = EntityResolver(now_fn=clock)
    alerts = _alert("tl1", actor="eve", src_ip="203.0.113.9")  # time=0 -> time-less
    r.resolve_alert(alerts)
    before = {eid: s["last_seen_ms"] for eid, s in
              [(e, r.entity_state(e)) for e in r.entity_ids()]}
    clock.advance(60)  # a wall-clock hour later
    r.resolve_alert(alerts)  # redeliver
    after = {eid: s["last_seen_ms"] for eid, s in
             [(e, r.entity_state(e)) for e in r.entity_ids()]}
    check(before == after,
          f"D3: time-less replay under an advancing clock must NOT move last_seen_ms "
          f"(before {before}, after {after})")
    check(r.resolved_updates == len(r.entity_ids()),
          f"D3: time-less redelivery must not inflate resolved_updates "
          f"(got {r.resolved_updates})")


def test_entity_count_bounded_by_sweep():
    """D1 regression: a distinct-attacker-id spray must not grow the entity
    table without limit -- the AUTO-WIRED sweep (called from _upsert_sighting
    on the _ENTITY_SWEEP_EVERY cadence, not a test-only manual call) must evict
    entities silent for a full horizon.

    The test deliberately does NOT call ``_sweep_dead_entities`` directly: it
    shrinks the module cadence constant so a small spray crosses the boundary
    and trips the REAL production wiring -- a regression that removes the
    auto-wiring call goes RED (adversarial-reverify finding: a direct call
    masked the wiring)."""
    import resolver as resolver_mod
    orig_cadence = resolver_mod._ENTITY_SWEEP_EVERY
    resolver_mod._ENTITY_SWEEP_EVERY = 8  # shrink so a small spray crosses it
    try:
        clock = _Clock()
        r = EntityResolver(now_fn=clock, horizon_s=60)
        # 8 distinct actors (each its own actor entity) all from one shared
        # source IP = 9 distinct entities. Each alert is 2 upsert calls
        # (actor+ip), so 8 alerts = 16 calls, crossing the 8-cadence twice
        # during the spray -- but the clock is frozen, so nothing is stale yet.
        for i in range(8):
            r.resolve_alert(_alert(f"spray-{i}", actor=f"a{i}", src_ip="203.0.113.9"))
        check(r.count() == 9,
              f"D1: spray must record 9 entities (8 actor + 1 shared ip), got {r.count()}")
        # Advance past the horizon; the next sightings (crossing the next
        # cadence boundary) must AUTO-SWEEP the 7 stale actors (a1..a7 were
        # not touched for > horizon). a0 + the shared ip get re-touched.
        clock.advance(61)
        for j in range(4):  # 4 more alerts = 8 upsert calls -> crosses 8-cadence
            r.resolve_alert(_alert(f"revive-{j}", actor="a0", src_ip="203.0.113.9"))
        # a0 + shared ip live; the 7 stale actors are swept.
        check(r.count() == 2,
              f"D1: after a full horizon the silent spray must be auto-swept, got "
              f"{r.count()} entities (expected 2: revived a0 + shared ip)")
        check(r.swept_entities >= 7,
              f"D1: auto-sweep must have dropped the stale spray (swept {r.swept_entities})")
        # Every surviving entity was touched within the horizon (live, not stale).
        stale_before = r._now_ms() - 60 * 1000
        for eid in r.entity_ids():
            check(r._last_touch.get(eid, 0) >= stale_before,
                  f"D1: surviving entity {eid} must have been touched within the horizon")
    finally:
        resolver_mod._ENTITY_SWEEP_EVERY = orig_cadence


def test_entity_value_bounded():
    """D1/D2 regression: an attacker-controlled >max entity_value must be
    truncated+stability-suffixed before storage/emission (never retained
    verbatim, distinct values stay distinct ids)."""
    r = _new()
    long = "u" * 2000
    updates = r.resolve_alert(_alert("long1", actor=long, src_ip="203.0.113.9"))
    # the actor entity's stored entity_value must be bounded
    for u in updates:
        if u["entity_type"] == "actor":
            check(len(u["entity_value"]) <= 448,
                  f"D2: entity_value must be bounded, got len {len(u['entity_value'])}")
    # two distinct long values must stay distinct ids (never-merge survives cap)
    e1 = compute_entity_id("default", "actor", "x" * 2000)
    e2 = compute_entity_id("default", "actor", "y" * 2000)
    check(e1 != e2, "D2: two distinct long values must keep distinct entity_ids")


def test_username_whitespace_normalized():
    """D5 regression: 'ALICE ' and 'alice' must be ONE identity (parser stray
    whitespace must not split one actor into two ids). Old code did not strip."""
    a = canonical_entity_value("actor", "ALICE ")
    b = canonical_entity_value("actor", "alice")
    check(a == b, f"D5: 'ALICE ' and 'alice' must normalize to the same value "
                  f"(got {a!r} vs {b!r})")
    check(compute_entity_id("d", "actor", a) == compute_entity_id("d", "actor", b),
          "D5: whitespace variants must hash to ONE entity_id")


def test_ipv6_case_insensitive_one_identity():
    """D4 regression: IPv6 is case-insensitive AND compression-insensitive;
    every spelling of one address (2001:DB8::1, 2001:db8:0:0:0:0:0:1,
    2001:0db8:0000:0000:0000:0000:0000:0001) must collapse to ONE entity_id
    (valid_ip canonicalizes since 2026-08-29)."""
    a = canonical_entity_value("ip", "2001:0DB8::1")
    b = canonical_entity_value("ip", "2001:0db8::1")
    c = canonical_entity_value("ip", "2001:0db8:0000:0000:0000:0000:0000:0001")
    check(a is not None and a == b == c,
          f"D4: IPv6 spellings must normalize to ONE canonical value "
          f"(got {a!r}, {b!r}, {c!r})")
    if a is not None and c is not None:
        check(compute_entity_id("d", "ip", a) == compute_entity_id("d", "ip", c),
              "D4: every IPv6 spelling must hash to ONE entity_id")


def test_cap_evicted_replay_not_double_counted():
    """D3 regression: a member cap-evicted then redelivered must NOT inflate
    resolved_updates (the bounded evicted-LRU must carry the memory)."""
    r = _new(member_cap=2)
    for i in range(4):  # 4 distinct members -> evicts oldest
        r.resolve_alert(_alert(f"m{i}", actor="eve", src_ip="203.0.113.9"))
    updates_after_spray = r.resolved_updates
    # redeliver the FIRST (evicted) member -- must not be a fresh state change
    r.resolve_alert(_alert("m0", actor="eve", src_ip="203.0.113.9"))
    check(r.resolved_updates == updates_after_spray,
          f"D3: redelivering a cap-evicted member must not inflate resolved_updates "
          f"({updates_after_spray} -> {r.resolved_updates})")


def test_self_evicted_member_still_recorded_in_evicted_lru():
    """2026-09-02 regression: a NEW member whose own alert time is the
    side table's minimum used to be evicted in the SAME call it was added
    (eviction was decided AFTER insertion), and the `oldest != member` guard
    then skipped recording it into evicted_lru -- so its redelivery was
    treated as fresh again, inflating resolved_updates on every replay.

    Uses explicit ascending real `time` values (not the all-zero ties
    test_cap_evicted_replay_not_double_counted uses) specifically so the
    NEWLY-added member is the side table's chronological minimum -- the
    exact condition that used to trigger the bug.
    """
    r = _new(member_cap=2)
    r.resolve_alert(_alert("m0", actor="eve", src_ip="203.0.113.9", time_ms=100))
    r.resolve_alert(_alert("m1", actor="eve", src_ip="203.0.113.9", time_ms=200))
    updates_before = r.resolved_updates
    # m2's own time (1) is EARLIER than both existing members -- under the
    # old (buggy) code this alert would evict itself instead of an existing
    # member.
    r.resolve_alert(_alert("m2", actor="eve", src_ip="203.0.113.9", time_ms=1))
    updates_after_m2 = r.resolved_updates
    check(updates_after_m2 == updates_before + 2,  # +1 actor, +1 ip entity
          f"m2 must count as one fresh state change per entity "
          f"({updates_before} -> {updates_after_m2})")
    # Redeliver m2 -- it must NOT be treated as fresh again.
    r.resolve_alert(_alert("m2", actor="eve", src_ip="203.0.113.9", time_ms=1))
    check(r.resolved_updates == updates_after_m2,
          f"2026-09-02: redelivering the self-evicted member m2 must not "
          f"inflate resolved_updates ({updates_after_m2} -> {r.resolved_updates})")


def test_time_less_sighting_does_not_corrupt_last_seen_with_real_sightings():
    """2026-09-02 regression: the deterministic time-fallback digest for a
    time-less alert used to be folded directly into first_seen_ms/
    last_seen_ms via plain min()/max() alongside genuine alert times. That
    digest can be (and usually is) far larger than any real epoch-ms value,
    so mixing it in permanently pinned last_seen_ms to a nonsensical
    far-future value that no later, genuinely-later real timestamp could
    ever exceed again."""
    r = _new()
    real_t1 = 1_700_000_000_000
    real_t2 = 1_700_000_010_000  # 10s later
    r.resolve_alert(_alert("real1", actor="mallory", src_ip="203.0.113.9", time_ms=real_t1))
    time_less = _alert("timeless1", actor="mallory", src_ip="203.0.113.9")
    del time_less["time"]  # no `time` key at all -> hits the digest-fallback path
    r.resolve_alert(time_less)
    eid = compute_entity_id("default", "actor", "mallory")
    after_timeless = r.entity_state(eid)["last_seen_ms"]
    check(after_timeless < 10**15,
          f"2026-09-02: a time-less sighting must never pin last_seen_ms to a "
          f"digest-magnitude value (got {after_timeless})")
    r.resolve_alert(_alert("real2", actor="mallory", src_ip="203.0.113.9", time_ms=real_t2))
    after_real2 = r.entity_state(eid)["last_seen_ms"]
    check(after_real2 == real_t2,
          f"2026-09-02: a genuinely later real timestamp must be able to advance "
          f"last_seen_ms past whatever a prior time-less sighting recorded "
          f"(expected {real_t2}, got {after_real2})")


def test_src_dst_ip_collision_emits_one_update():
    """2026-09-02 regression: src_endpoint.ip == dst_endpoint.ip (loopback/
    reflected traffic) used to resolve to two entity tuples that canonicalize
    to the SAME entity_id, and resolve_alert emitted one entity.updates
    payload per tuple with no dedup -- doubling bus traffic for one logical
    sighting."""
    r = _new()
    updates = r.resolve_alert(_alert("loop1", src_ip="203.0.113.9", dst_ip="203.0.113.9"))
    ip_updates = [u for u in updates if u["entity_type"] == "ip"]
    check(len(ip_updates) == 1,
          f"2026-09-02: src==dst ip must emit exactly ONE entity.updates payload, "
          f"got {len(ip_updates)}")


def test_non_string_actor_value_never_collides_with_matching_string():
    """2026-09-02 regression: canonical_entity_value used to str()-coerce a
    non-string raw value (e.g. JSON bool `true`) before casefolding, so
    `str(True).casefold() == "true"` collided with a genuine username
    literally "true" -- silently merging two unrelated identities."""
    from_bool = canonical_entity_value("actor", True)
    from_string = canonical_entity_value("actor", "true")
    check(from_bool is None,
          f"2026-09-02: a non-string actor value must resolve to None, not a "
          f"coerced string (got {from_bool!r})")
    check(from_string == "true",
          f"sanity: a genuine string actor value must still normalize normally "
          f"(got {from_string!r})")


def test_apply_update_new_entity_is_swept_after_horizon():
    """2026-09-02 regression: apply_update() never touched _last_touch, so an
    entity created ONLY via apply_update (e.g. a WS-6 inventory sighting that
    never went through resolve_alert) was invisible to _sweep_dead_entities
    (which only iterates _last_touch) and lived in _meta forever."""
    clock = _Clock()
    r = _new(clock=clock, horizon_s=60)
    entity_id = compute_entity_id("default", "ip", "203.0.113.50")
    r.apply_update({
        "entity_id": entity_id, "entity_type": "ip", "tenant_id": "default",
        "entity_value": "203.0.113.50", "first_seen_ms": 0, "last_seen_ms": 0,
        "attributes": {},
    })
    check(entity_id in r._last_touch,
          "2026-09-02: apply_update must touch _last_touch the same way "
          "_upsert_sighting does")
    clock.advance(120)  # past the 60s horizon
    r._sweep_dead_entities(r._now_ms())
    check(r.entity_state(entity_id) is None,
          "2026-09-02: an entity created only via apply_update must be swept "
          "after a full horizon of silence, same as an alert-sighted one")


def test_apply_update_merges_attributes_not_just_timestamp():
    """2026-09-02 regression: apply_update's already-known-entity branch used
    to advance ONLY last_seen_ms, silently discarding entity_value/attributes
    carried by a genuinely newer update."""
    r = _new()
    entity_id = compute_entity_id("default", "ip", "203.0.113.60")
    r.apply_update({
        "entity_id": entity_id, "entity_type": "ip", "tenant_id": "default",
        "entity_value": "203.0.113.60", "first_seen_ms": 0, "last_seen_ms": 0,
        "attributes": {"asset_type": "workstation"},
    })
    r.apply_update({
        "entity_id": entity_id, "entity_type": "ip", "tenant_id": "default",
        "entity_value": "203.0.113.60", "first_seen_ms": 0, "last_seen_ms": 1000,
        "attributes": {"owner": "alice"},
    })
    attrs = r.entity_state(entity_id)["attributes"]
    check(attrs.get("asset_type") == "workstation",
          f"2026-09-02: a newer update must not silently drop an earlier "
          f"attribute the new payload didn't mention (got {attrs!r})")
    check(attrs.get("owner") == "alice",
          f"2026-09-02: a newer update's own attributes must be applied "
          f"(got {attrs!r})")


def test_dockerfile_copy_set_imports_without_tools_dir():
    """2026-09-02 regression: the ws9-resolver Dockerfile copies ONLY
    services/shared, contracts, and services/ws9-resolver into the image
    (never tools/) -- entity_id.py used to import shared.ocsf for valid_ip,
    and shared/ocsf.py raises RuntimeError at import time if it can't find
    tools/validate_contract.py, so the container crashed on every startup.

    Reproduces the container's exact file layout in a temp dir (the SAME
    three COPY sources the Dockerfile lists, nothing else -- no tools/) and
    imports main.py the way `python main.py` would, in a subprocess so a
    regression fails loudly here instead of only at `docker run` time.
    """
    import shutil
    import subprocess
    import tempfile

    repo_root = SERVICES.parent
    with tempfile.TemporaryDirectory() as td:
        app = Path(td) / "app"
        shutil.copytree(repo_root / "services" / "shared", app / "shared")
        shutil.copytree(repo_root / "contracts", app / "contracts")
        shutil.copytree(repo_root / "services" / "ws9-resolver", app / "ws9-resolver")
        proc = subprocess.run(
            [sys.executable, "-c", "import main"],
            cwd=str(app / "ws9-resolver"),
            env={**__import__("os").environ, "PYTHONPATH": str(app)},
            capture_output=True, text=True,
        )
        check(proc.returncode == 0,
              f"2026-09-02: importing main.py from the Dockerfile's exact COPY "
              f"set (no tools/) must succeed, got exit {proc.returncode}:\n"
              f"{proc.stderr}")


def test_apply_update_then_alert_sighting_does_not_crash():
    """2026-09-02 regression: an entity first created via apply_update (a
    producer-supplied attributes shape with no "mitre_tactics" key, e.g.
    WS-6's asset-only sightings) used to make a LATER alert-driven sighting
    on the same entity_id crash with KeyError in _upsert_sighting's merge
    branch, which read meta["attributes"]["mitre_tactics"] unguarded."""
    r = _new()
    entity_id = compute_entity_id("default", "ip", "203.0.113.70")
    r.apply_update({
        "entity_id": entity_id, "entity_type": "ip", "tenant_id": "default",
        "entity_value": "203.0.113.70", "first_seen_ms": 0, "last_seen_ms": 0,
        "attributes": {"asset_type": "workstation"},  # no mitre_tactics key
    })
    try:
        r.resolve_alert(_alert("a1", src_ip="203.0.113.70", tactic="TA0006"))
    except KeyError as exc:
        check(False, f"2026-09-02: alert-driven sighting on an apply_update-"
                      f"created entity must not raise KeyError({exc})")
        return
    tactics = r.entity_state(entity_id)["attributes"]["mitre_tactics"]
    check(tactics == ["TA0006"],
          f"the alert's tactic must be recorded (got {tactics!r})")


def run_all():
    test_same_input_same_entity_id()
    test_distinct_tenant_type_value_distinct_id()
    test_canonicalization_ip_variants_same_id()
    test_canonicalization_mac_variants_same_id()
    test_canonicalization_username_variants_same_id()
    test_canonicalization_location_mac_vs_hostname()
    test_replay_same_alert_twice_is_one_logical_state()
    test_memory_bus_round_trip_deterministic_entity_id()
    test_invalid_tenant_rejected_not_normalized()
    test_time_less_replay_stable_under_advancing_clock()
    test_entity_count_bounded_by_sweep()
    test_entity_value_bounded()
    test_username_whitespace_normalized()
    test_ipv6_case_insensitive_one_identity()
    test_cap_evicted_replay_not_double_counted()
    test_self_evicted_member_still_recorded_in_evicted_lru()
    test_time_less_sighting_does_not_corrupt_last_seen_with_real_sightings()
    test_src_dst_ip_collision_emits_one_update()
    test_non_string_actor_value_never_collides_with_matching_string()
    test_apply_update_new_entity_is_swept_after_horizon()
    test_apply_update_merges_attributes_not_just_timestamp()
    test_apply_update_then_alert_sighting_does_not_crash()
    test_dockerfile_copy_set_imports_without_tools_dir()


if __name__ == "__main__":
    run_all()
    if FAILS:
        print(f"[FAIL] WS-9 resolver: {len(FAILS)} problem(s)")
        for f in FAILS:
            print(f"  - {f}")
        sys.exit(1)
    print("[OK] WS-9 entity resolver contract test PASS "
          "(a) deterministic id (b) distinct tenant/type/value "
          "(c) canonicalization IP/MAC/username (d) replay idempotency "
          "(e) redelivery-safe memory-bus round trip + tenant reject-not-normalize; "
          "plus D1/D3/D4/D5 regressions: entity-count sweep, entity_value bound, "
          "time-less replay stability, whitespace + IPv6-case identity, cap+replay count; "
          "plus 2026-09-02 regressions: self-evicted-member bookkeeping, time-less/real "
          "timestamp isolation, src==dst ip dedup, non-string actor never collides, "
          "apply_update sweep/merge/cross-path-shape safety)")
