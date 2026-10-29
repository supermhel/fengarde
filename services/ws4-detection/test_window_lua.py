"""Zero-infra dispatch test for RedisWindowCounter's single-EVALSHA path.

What this proves: WHICH call shape each method uses and with WHAT arguments
(member, score, trim bound, ttl), that a client without register_script (the
pipeline fakes the other window tests use) and use_lua=False keep the original
MULTI pipelines, that the legacy Redis < 6.2 distinct path is untouched, and
that the script is registered lazily and once. What it cannot prove is the Lua
itself: that needs a real server, see test_window_lua_live.py (old-vs-new
parity on identical streams, run by CI's redis-integration job via REDIS_URL).

Run: python services/ws4-detection/test_window_lua.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from shared.window import _HIT_DISTINCT_GT_LUA, _HIT_LUA, RedisWindowCounter  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _Script:
    def __init__(self, src, log):
        self.src, self.log = src, log

    def __call__(self, keys, args):
        self.log.append((self.src, list(keys), list(args)))
        return 7


class _LuaClient:
    def __init__(self):
        self.registered = []
        self.calls = []
        self.pipelines = 0

    def register_script(self, src):
        self.registered.append(src)
        return _Script(src, self.calls)

    def pipeline(self):
        self.pipelines += 1
        raise AssertionError("pipeline used on the Lua path")

    def info(self, section=None):
        return {"redis_version": "7.2.0"}


class _PipeOnlyClient:
    """No register_script (like the in-test fakes): must keep the pipeline."""

    def __init__(self):
        self.pipelines = 0

    def pipeline(self):
        self.pipelines += 1
        return self

    def zadd(self, *a, **k): return self
    def zremrangebyscore(self, *a, **k): return self
    def zcard(self, *a, **k): return self
    def expire(self, *a, **k): return self
    def execute(self): return [1, 0, 3, True]
    def info(self, section=None): return {"redis_version": "7.2.0"}


def test_hit_uses_one_script_with_pipeline_equivalent_args():
    c = _LuaClient()
    w = RedisWindowCounter(c, namespace="ns")
    check(c.registered == [], "script registered lazily, not at construction")
    n = w.hit("rule:grp", 1_750_000_000_000, 60_000, member="evt-1")
    check(n == 7, f"returns the script's count: {n}")
    src, keys, args = c.calls[0]
    check(src == _HIT_LUA and keys == ["ns:rule:grp"], f"hit script/key: {keys}")
    check(args == ["evt-1", 1_750_000_000_000, 1_750_000_000_000 - 60_000 - 1, 61],
          f"args = member, score, trim bound (horizon-1), ttl (window_s+1): {args}")
    w.hit("rule:grp", 1_750_000_000_001, 60_000, member="evt-2")
    check(len(c.registered) == 1, "registered once, reused")
    check(c.calls[1][2][0] == "evt-2", "member passed through")
    w.hit("k", 5, 500)   # no member -> timestamp as member, ttl floor of 1 s
    check(c.calls[-1][2] == ["5", 5, 5 - 500 - 1, 1], f"defaults: {c.calls[-1][2]}")
    check(c.pipelines == 0, "no pipeline on the Lua path")


def test_hit_distinct_uses_gt_script_on_modern_redis():
    c = _LuaClient()
    w = RedisWindowCounter(c, namespace="ns")
    w.hit_distinct("k", 2_000_000, 300_000, value="22")
    src, keys, args = c.calls[0]
    check(src == _HIT_DISTINCT_GT_LUA and "'GT'" in src, "distinct uses the ZADD GT script")
    check(keys == ["ns:d:k"] and args == ["22", 2_000_000, 2_000_000 - 300_000 - 1, 301], f"{keys} {args}")
    check(_HIT_LUA != _HIT_DISTINCT_GT_LUA and "'GT'" not in _HIT_LUA, "plain hit has no GT")


def test_legacy_redis_and_use_lua_false_and_fakes_keep_old_paths():
    class _Old(_LuaClient):
        def info(self, section=None):
            return {"redis_version": "6.0.9"}

        def eval(self, *a):
            self.calls.append(("eval", a))
            return 3

    o = _Old()
    check(RedisWindowCounter(o).hit_distinct("k", 10, 1000, value="v") == 3
          and o.calls[0][0] == "eval" and o.registered == [],
          "Redis < 6.2 distinct stays on the existing eval() script")
    f = _PipeOnlyClient()
    w = RedisWindowCounter(f)
    check(w._use_lua is False, "client without register_script -> auto-off")
    check(w.hit("k", 1000, 1000) == 3 and f.pipelines == 1, "fake keeps the MULTI pipeline")
    forced = RedisWindowCounter(_LuaClient(), use_lua=False)
    try:
        forced.hit("k", 1000, 1000)
    except AssertionError:
        pass
    else:
        check(False, "use_lua=False must use the pipeline")
    check(RedisWindowCounter(_LuaClient(), use_lua=True)._use_lua is True, "use_lua=True honoured")


def test_capped_members_equal_sliced_full_read():
    """members_capped == slice + count of the full read, deque backend (the
    engine falls back to the full read for counters without members_capped, so
    this also pins both engine paths to one answer)."""
    from shared.window import DequeWindowCounter
    w = DequeWindowCounter()
    base = 1_750_000_000_000
    for i in range(120):
        w.hit("k", base + i, 600_000, member=f"e{i}")
        w.hit_distinct("d", base + i, 600_000, value=f"v{i % 70}", member=f"e{i}")
    for cap in (1, 50, 119, 120, 500):
        full = w.members("k")
        check(w.members_capped("k", cap) == (full[:cap], max(0, len(full) - cap)), f"count cap={cap}")
        fd = w.distinct_members("d")
        check(w.members_capped("d", cap, distinct=True) == (fd[:cap], max(0, len(fd) - cap)), f"distinct cap={cap}")
    check(w.members_capped("missing", 50) == ([], 0), "empty window")


def test_redis_capped_members_one_pipeline_round_trip():
    class _P:
        def __init__(self, log):
            self.log = log

        def zrange(self, *a): self.log.append(("zrange",) + a); return self
        def zcard(self, *a): self.log.append(("zcard",) + a); return self
        def execute(self): return [["a", "b"], 130]

    class _C(_PipeOnlyClient):
        def __init__(self):
            super().__init__()
            self.log = []

        def pipeline(self):
            self.pipelines += 1
            return _P(self.log)

    c = _C()
    w = RedisWindowCounter(c, namespace="ns")
    page, omitted = w.members_capped("k", 50)
    check(page == ["a", "b"] and omitted == 80, f"omitted = zcard - cap: {page} {omitted}")
    check(c.pipelines == 1 and c.log[0] == ("zrange", "ns:k", 0, 49) and c.log[1] == ("zcard", "ns:k"),
          f"one pipeline, first `cap` oldest-first: {c.log}")
    w.members_capped("k", 50, distinct=True)
    check(c.log[2][1] == "ns:d:k", "distinct windows live under the :d: key")


def main() -> int:
    for fn in (test_hit_uses_one_script_with_pipeline_equivalent_args,
               test_hit_distinct_uses_gt_script_on_modern_redis,
               test_legacy_redis_and_use_lua_false_and_fakes_keep_old_paths,
               test_capped_members_equal_sliced_full_read,
               test_redis_capped_members_one_pipeline_round_trip):
        n = len(FAILS)
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            FAILS.append(f"{fn.__name__} raised {type(exc).__name__}: {exc}")
        print(f"{'FAIL' if len(FAILS) > n else 'PASS'}: {fn.__name__}")
    if FAILS:
        print("FAILURES:\n - " + "\n - ".join(FAILS))
        return 1
    print("window Lua dispatch test OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
