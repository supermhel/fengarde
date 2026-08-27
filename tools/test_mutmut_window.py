"""pytest shim for mutmut (2026-08-19): expands mutation-testing scope beyond
services/shared/sessions.py to services/shared/window.py -- the "expanding
scope to the rest of services/shared... stays a real, disclosed follow-up"
item SSOT.md's M2 row named. window.py is a natural second target: small
(313 lines), self-contained, and the highest correctness-relevance module in
services/shared next to sessions.py -- every stateful detection rule (T6) and
WS-8's correlation tracks depend on its window/dedup/eviction semantics being
exactly right.

Same "import the way mutmut's own rootdir does" discipline
tools/test_mutmut_shared.py established: absolute ``services.shared.window``
import, no sys.path insertion, so mutant coverage attributes correctly to
this module's trampoline keys instead of producing zero-coverage mutants.

Scope: DequeWindowCounter is exercised directly (the in-process backend
every zero-infra test already runs against). RedisWindowCounter is exercised
against an in-process fake pipeline (same pattern
services/ws8-correlation/test_contract.py::_BytesFakeRedis established for
exactly this purpose) rather than a live Redis -- consistent with this
gate's own "zero-infra, informational, measure first" scoping, not a live-
infra requirement smuggled into the mutation-testing gate itself. A live
Redis is a separate, disclosed non-goal here (same reasoning
tools/test_mutmut_shared.py gives for excluding RedisSessionStore).
"""
from __future__ import annotations

from services.shared.window import DequeWindowCounter, RedisWindowCounter


# ---- DequeWindowCounter: hit() / member dedup / eviction -------------------

def test_hit_counts_within_window():
    c = DequeWindowCounter()
    assert c.hit("k", 1000, 60_000, member="a") == 1
    assert c.hit("k", 2000, 60_000, member="b") == 2
    assert c.hit("k", 3000, 60_000, member="c") == 3


def test_hit_evicts_events_older_than_window():
    c = DequeWindowCounter()
    c.hit("k", 0, 1000, member="a")
    assert c.hit("k", 1500, 1000, member="b") == 1  # "a" (t=0) aged out at horizon=500


def test_hit_redelivery_dedup_by_member():
    c = DequeWindowCounter()
    c.hit("k", 1000, 60_000, member="dup")
    assert c.hit("k", 1001, 60_000, member="dup") == 1  # same member -> not double-counted
    assert c.hit("k", 1002, 60_000, member="new") == 2


def test_hit_none_member_never_dedups():
    c = DequeWindowCounter()
    assert c.hit("k", 1000, 60_000, member=None) == 1
    assert c.hit("k", 1001, 60_000, member=None) == 2


def test_hit_out_of_order_arrival_still_evicts_correctly():
    c = DequeWindowCounter()
    c.hit("k", 5000, 1000, member="late-window")
    # An out-of-order (older) arrival that's still inside the window from k=5000's
    # perspective must be inserted in sorted position, not just appended.
    assert c.hit("k", 4600, 1000, member="reordered") == 2
    # Now push past the horizon relative to the newest event -- both should evict.
    assert c.hit("k", 6100, 1000, member="fresh") == 1


def test_hit_different_keys_are_independent():
    c = DequeWindowCounter()
    c.hit("a", 1000, 60_000, member="x")
    c.hit("a", 1000, 60_000, member="y")
    c.hit("b", 1000, 60_000, member="z")
    assert c.members("a") == ["x", "y"]
    assert c.members("b") == ["z"]


def test_empty_window_key_is_reclaimed():
    c = DequeWindowCounter()
    c.hit("gone", 0, 1000, member="a")
    c.hit("stays", 0, 60_000, member="x")
    # Gap-hunt (2026-08-26) R4-116: this test was mis-named AND asserted the
    # opposite of reclamation (a key retaining a live member stays in _w).
    # Real reclamation is _sweep(): after (_SWEEP_EVERY=256) hits, keys whose
    # NEWEST event is older than the window (idle groups) are dropped from
    # _w/_live/_last -- that is the bounded-memory guarantee that stops an
    # attacker's endless distinct keys from OOMing the counter. Drive it.
    c.hit("gone", 60_000, 1000, member="stale_again")  # _last["gone"]=60000 (old)
    for i in range(256):                               # trigger the periodic _sweep
        c.hit(f"filler-{i}", 1_500_000 + i, 60_000, member="z")
    assert "gone" not in c._w, "idle past-window key 'gone' must be swept (_w)"
    assert "gone" not in c._live_members, "idle key must be swept (_live_members)"
    assert "gone" not in c._last, "idle key must be swept (_last)"
    # A key touched just before the sweep's horizon must survive it.
    assert "filler-255" in c._w, "a freshly-hit key must NOT be swept"


# ---- hit_distinct() ---------------------------------------------------------

def test_hit_distinct_counts_unique_values_not_events():
    c = DequeWindowCounter()
    assert c.hit_distinct("k", 1000, 60_000, value="p80") == 1
    assert c.hit_distinct("k", 1001, 60_000, value="p80") == 1  # same value, still 1
    assert c.hit_distinct("k", 1002, 60_000, value="p22") == 2  # new distinct value


def test_hit_distinct_evicts_by_window():
    c = DequeWindowCounter()
    c.hit_distinct("k", 0, 1000, value="p1")
    assert c.hit_distinct("k", 1500, 1000, value="p2") == 1  # p1 aged out


def test_distinct_members_reports_unique_values_in_order():
    c = DequeWindowCounter()
    c.hit_distinct("k", 1000, 60_000, value="p1")
    c.hit_distinct("k", 1001, 60_000, value="p2")
    c.hit_distinct("k", 1002, 60_000, value="p1")  # repeat, must not duplicate
    assert c.distinct_members("k") == ["p1", "p2"]


# ---- hit_periodic() / coefficient of variation ------------------------------

def test_hit_periodic_returns_none_cv_under_three_events():
    c = DequeWindowCounter()
    count, cv = c.hit_periodic("k", 1000, 60_000, member="a")
    assert count == 1 and cv is None
    count, cv = c.hit_periodic("k", 2000, 60_000, member="b")
    assert count == 2 and cv is None  # only 1 delta -- still undefined


def test_hit_periodic_low_cv_for_regular_cadence():
    c = DequeWindowCounter()
    for i, t in enumerate((0, 1000, 2000, 3000, 4000)):
        count, cv = c.hit_periodic("k", t, 60_000, member=f"m{i}")
    assert count == 5
    assert cv is not None and cv < 0.01  # perfectly even spacing -> ~0 CV


def test_hit_periodic_high_cv_for_irregular_cadence():
    c = DequeWindowCounter()
    for i, t in enumerate((0, 100, 5000, 5100, 30000)):
        count, cv = c.hit_periodic("k", t, 60_000, member=f"m{i}")
    assert cv is not None and cv > 0.5  # wildly uneven spacing -> high CV


# ---- RedisWindowCounter: same contract, in-process fake pipeline -----------

class _FakePipe:
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
        for op, key, *rest in self.ops:
            d = self.store.setdefault(key, {})
            if op == "zadd":
                for member, score in rest[0].items():
                    d[str(member)] = score
                results.append(len(rest[0]))
            elif op == "zremrangebyscore":
                lo, hi = rest
                for m in [m for m, s in d.items() if lo <= s <= hi]:
                    del d[m]
                results.append(0)
            elif op == "zcard":
                results.append(len(d))
            elif op == "expire":
                results.append(True)
        self.ops = []
        return results


class _FakeRedis:
    def __init__(self):
        self.store: dict = {}

    def pipeline(self):
        return _FakePipe(self.store)

    def zrange(self, key, start, stop, withscores=False):
        d = self.store.get(key, {})
        items = sorted(d.items(), key=lambda kv: kv[1])
        if stop == -1:
            stop = len(items) - 1
        sliced = items[start:stop + 1]
        if withscores:
            return sliced
        return [m for m, _ in sliced]


def test_redis_hit_counts_and_evicts_like_deque():
    r = _FakeRedis()
    c = RedisWindowCounter(r)
    assert c.hit("k", 0, 1000, member="a") == 1
    assert c.hit("k", 500, 1000, member="b") == 2
    # horizon at t=2000 is 1000 -> zremrangebyscore drops score in [0, 999],
    # which evicts BOTH "a" (0) and "b" (500); only "c" (2000) survives.
    assert c.hit("k", 2000, 1000, member="c") == 1
    # Gap-hunt (2026-08-26) R4-116 second half: the Redis EXPIRE ("quiet
    # groups self-delete" guard) was real in window.py but was NEVER asserted
    # anywhere -- the fake pipe happened to record it without any test
    # checking it, so deleting the expire() call shipped green. Pin it by
    # wrapping pipeline() once and inspecting the raw ops queue.
    orig_pipeline = r.pipeline
    captured: list = []

    def _spy_pipeline():
        p = _FakePipe(r.store)
        base_execute = p.execute
        # execute() clears p.ops; record a copy before it does so we can
        # assert the expire() was issued (not merely accumulated then dropped).
        def _recording_execute():
            captured.append(list(p.ops))
            return base_execute()
        p.execute = _recording_execute
        return p

    r.pipeline = _spy_pipeline
    c.hit("k", 4000, 1000, member="e")
    r.pipeline = orig_pipeline
    assert captured, "expected at least one pipeline() call"
    assert any(op[0] == "expire" for op in captured[0]), \
        "RedisWindowCounter must EXPIRE its zset key (self-delete guard)"


def test_redis_hit_member_dedup_via_zadd():
    r = _FakeRedis()
    c = RedisWindowCounter(r)
    c.hit("k", 1000, 60_000, member="dup")
    assert c.hit("k", 1001, 60_000, member="dup") == 1  # ZADD on same member updates, no growth


def test_redis_hit_distinct_counts_unique_values():
    r = _FakeRedis()
    c = RedisWindowCounter(r)
    assert c.hit_distinct("k", 1000, 60_000, value="p80") == 1
    assert c.hit_distinct("k", 1001, 60_000, value="p80") == 1
    assert c.hit_distinct("k", 1002, 60_000, value="p22") == 2


def test_redis_hit_periodic_low_cv_for_regular_cadence():
    r = _FakeRedis()
    c = RedisWindowCounter(r)
    count = cv = None
    for i, t in enumerate((0, 1000, 2000, 3000, 4000)):
        count, cv = c.hit_periodic("k", t, 60_000, member=f"m{i}")
    assert count == 5
    assert cv is not None and cv < 0.01


def test_redis_hit_periodic_returns_none_cv_under_three_events():
    r = _FakeRedis()
    c = RedisWindowCounter(r)
    count, cv = c.hit_periodic("k", 1000, 60_000, member="a")
    assert count == 1 and cv is None


def test_redis_members_and_distinct_members_readback():
    r = _FakeRedis()
    c = RedisWindowCounter(r)
    c.hit("k", 1000, 60_000, member="a")
    c.hit("k", 1001, 60_000, member="b")
    c.hit_distinct("k2", 1000, 60_000, value="p1")
    assert set(c.members("k")) == {"a", "b"}
    assert c.distinct_members("k2") == ["p1"]
