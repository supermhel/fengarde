"""_MemoryBus wire parity with _RedisBus.

Every zero-infra test in the repo runs on the memory bus, so any way it is more
forgiving than Redis is a way for a bug to pass every test and first appear in
production. Redis does ``json.dumps(payload)`` on produce and parses the wire
bytes anew on every delivery. These checks pin the three consequences:

  (1) a payload JSON cannot encode is REJECTED at produce (Redis raises);
  (2) the stored message is independent of the producer's dict (mutating it after
      produce() must not change what consumers receive);
  (3) every consumer group, and every redelivery, receives its OWN copy (one
      consumer mutating msg.payload -- WS-2 sanitises in place -- must not leak
      into another group's view, nor into the redelivery of the same message).

Run: python services/shared/test_bus_wire_parity.py
     BUS_PARITY_REDIS_URL=redis://localhost:6379/0 python services/shared/test_bus_wire_parity.py
     (the second form runs the SAME assertions against the real Redis backend as well --
      this is the only way to know the memory backend is actually faithful, not merely
      self-consistent; it is skipped, with a message, when no URL is given)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ["BUS_BACKEND"] = "memory"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uuid  # noqa: E402

from shared.bus import Bus, _RedisBus  # noqa: E402

_REDIS_URL = os.environ.get("BUS_PARITY_REDIS_URL", "").strip()

FAILS: list = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def run(kind="memory"):
    """Run every assertion against one backend. ``kind`` is "memory" or "redis"."""
    tag = f"[{kind}] "
    run_id = uuid.uuid4().hex[:8]
    redis = kind == "redis"

    def Bus():  # noqa: N802 - local factory shadows the import on purpose
        return _RedisBus(_REDIS_URL) if redis else _real_bus()

    def T(name):                   # unique topic per run on Redis (streams persist)
        return f"parity-{run_id}-{name}" if redis else name

    def G(name):                   # unique group per run on Redis
        return f"{name}-{run_id}" if redis else name

    def check(cond, msg):          # noqa: F811 - prefix the backend
        if not cond:
            FAILS.append(tag + msg)

    def consume(bus, topic, group):
        return list(bus.consume(topic, group=group, **({"block_ms": 200} if redis else {})))

    def claim(bus, topic, group):
        return [m for m, _n in bus.claim_pending(topic, group=group, min_idle_ms=0)]

    # (1) non-JSON payloads are rejected, exactly as Redis's json.dumps would
    bus = Bus()
    for bad in ({"x": b"bytes"}, {"x": {1, 2}}, {"x": object()}):
        try:
            bus.produce(T("t1"), "k", bad)
            check(False, f"produce() accepted a payload Redis would reject: {bad!r}")
        except TypeError:
            pass
    if not redis:
        check(not bus.drain("t1"), "a rejected produce() must leave nothing in the stream")

    # (2) producer cannot reach into the stored message
    bus = Bus()
    payload = {"a": 1, "nested": {"b": [1, 2]}}
    bus.produce(T("t2"), "k", payload)
    payload["a"] = 999
    payload["nested"]["b"].append(3)
    got = consume(bus, T("t2"), G("g1"))[0]
    check(got.payload == {"a": 1, "nested": {"b": [1, 2]}},
          f"mutating the dict after produce() changed the stored message: {got.payload}")

    # (3a) groups do not share a dict
    bus = Bus()
    bus.produce(T("t3"), "k", {"v": 1, "list": [1]})
    m1 = consume(bus, T("t3"), G("g1"))[0]
    m1.payload["v"] = "mutated-by-g1"
    m1.payload["list"].append("x")
    m2 = consume(bus, T("t3"), G("g2"))[0]
    check(m2.payload == {"v": 1, "list": [1]},
          f"group g2 saw group g1's in-place mutation: {m2.payload}")

    # (3b) a redelivery is a fresh copy, not the mutated one
    bus = Bus()
    bus.produce(T("t4"), "k", {"v": 1})
    m = consume(bus, T("t4"), G("g"))[0]
    m.payload["v"] = "half-processed"                  # handler crashed mid-mutation, never acked
    redelivered = claim(bus, T("t4"), G("g"))
    check(len(redelivered) == 1 and redelivered[0].payload == {"v": 1},
          f"the redelivery carried the failed handler's partial mutation: "
          f"{[r.payload for r in redelivered]}")

    # (3c) drain() copies too (memory-only API)
    if not redis:
        bus = Bus()
        bus.produce("t5", "k", {"v": 1})
        d1 = bus.drain("t5")
        d1[0].payload["v"] = 2
        check(bus.drain("t5")[0].payload == {"v": 1}, "drain() handed out the stored dict itself")

    # wire normalisation matches a json round-trip (tuples become lists)
    bus = Bus()
    bus.produce(T("t6"), "k", {"t": (1, 2)})
    check(consume(bus, T("t6"), G("g"))[0].payload == {"t": [1, 2]},
          "a tuple must arrive as a list, as it does through Redis")

    # a None key arrives as "" through Redis (xadd {"key": key or ""})
    bus = Bus()
    bus.produce(T("t7"), None, {"n": 1})
    _keys[kind] = consume(bus, T("t7"), G("g"))[0].key

    # every key type: Redis does xadd({"key": key or ""}) through redis-py's encoder, so falsy keys
    # (0, False, 0.0, "", None) read back as "", int/float/bytes keys read back as their str form,
    # and keys redis-py cannot encode (True, tuple, dict) are REJECTED at produce. The memory
    # backend used to hand the original Python object (5 -> int 5) or accept the unencodable.
    for n, key in enumerate(_KEY_CASES):
        bus = Bus()
        topic = T(f"key{n}")
        try:
            bus.produce(topic, key, {"n": 1})
            outcome = consume(bus, topic, G("g"))[0].key
        except Exception:  # redis.exceptions.DataError on Redis, TypeError on memory
            outcome = _RAISES
        _key_outcomes.setdefault(kind, {})[repr(key)] = outcome
        want = _KEY_EXPECT[n]
        check(outcome == want and type(outcome) is type(want),
              f"key {key!r}: expected {want!r} (what Redis returns), got {outcome!r}")

    # at-least-once is intact: an unacked message is redelivered, an acked one is not
    bus = Bus()
    bus.produce(T("t8"), "k", {"n": 1})
    bus.produce(T("t8"), "k", {"n": 2})
    a_, b_ = consume(bus, T("t8"), G("g"))
    bus.ack(a_, group=G("g"))
    left = claim(bus, T("t8"), G("g"))
    check([mm.payload["n"] for mm in left] == [2],
          f"only the unacked message may be redelivered, got {[mm.payload for mm in left]}")

    # (4) structural (memory only, no timing): the stream stores the serialised wire
    # string ONCE -- not a parsed dict that every delivery would re-dump -- and the
    # PEL shares that same record instead of copying payloads.
    if not redis:
        import json
        bus = Bus()
        bus.produce("t9", None, {"t": (1, 2), "n": 1})
        entry = bus._streams["t9"][0]
        check(isinstance(getattr(entry, "wire", None), str) and json.loads(entry.wire) == {"t": [1, 2], "n": 1},
              f"stream entry must hold the serialised wire string, got {entry!r}")
        check(entry.key == "", f"stored None key must already be '' (Redis xadd), got {entry.key!r}")
        check(not isinstance(getattr(entry, "payload", None), str) and entry.payload is not entry.payload,
              "entry.payload must be a fresh parse per access, never a shared dict")
        got = consume(bus, "t9", "g")[0]
        check(bus._pel["t9"]["g"][got.id][0] is entry,
              "the PEL must reference the stored record, not hold a second copy of the payload")
        check(got.payload == {"t": [1, 2], "n": 1} and got.key == "",
              f"delivery must parse the wire into a plain Message, got {got!r}")
        # drain() returns only the undelivered tail, each with an independent dict
        for i in range(3):
            bus.produce("t10", "k", {"i": i})
        consume(bus, "t10", "g")
        bus.produce("t10", "k", {"i": 3})
        tail = bus.drain("t10")
        check([m.payload for m in tail] == [{"i": 3}], f"drain() must return only the undelivered tail: {tail}")


_keys: dict = {}
_key_outcomes: dict = {}
_RAISES = "<raises>"
# key -> what a real Redis (decode_responses=True) hands the consumer, observed against redis:7 + redis-py 8
_KEY_CASES = [None, "", 0, False, 0.0, (), "k", 5, 1.5, b"b", True, ("t",), {"a": 1}, 10 ** 30]
_KEY_EXPECT = ["", "", "", "", "", "", "k", "5", "1.5", "b", _RAISES, _RAISES, _RAISES, str(10 ** 30)]


def _real_bus():
    return Bus()


def main():
    run("memory")
    if _REDIS_URL:
        run("redis")
        check(_keys.get("memory") == _keys.get("redis"),
              f"a None key must read back identically on both backends: memory={_keys.get('memory')!r} "
              f"redis={_keys.get('redis')!r}")
        check(_key_outcomes.get("memory") == _key_outcomes.get("redis"),
              f"key handling differs between backends: memory={_key_outcomes.get('memory')} "
              f"redis={_key_outcomes.get('redis')}")
    else:
        print("[SKIP] real-Redis half of the parity test: set BUS_PARITY_REDIS_URL to run it")
    if FAILS:
        print(f"[FAIL] bus wire parity: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] bus wire parity: memory backend rejects what Redis rejects and never shares a payload dict")


if __name__ == "__main__":
    main()
