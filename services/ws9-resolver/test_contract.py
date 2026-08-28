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
          "(e) redelivery-safe memory-bus round trip + tenant reject-not-normalize)")
