"""make_correlator() window backend selection (regression: redis-sentinel).

The HA compose runs ws8 with BUS_BACKEND=redis-sentinel. make_correlator() once
gated on == "redis", so HA silently used the in-process deque (state lost on
restart, not shared across replicas). Zero-infra: fake redis + fake Sentinel.
"""
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
import importlib.util  # noqa: E402

sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "ws4-detection"))
from test_window import _FakeRedis  # noqa: E402
# ws4 also has a main.py: load ws8's by path to avoid the name clash.
sys.path.insert(0, str(HERE))
_spec = importlib.util.spec_from_file_location("ws8_main", HERE / "main.py")
assert _spec is not None and _spec.loader is not None
main = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(main)
from shared.window import DequeWindowCounter, RedisWindowCounter  # noqa: E402
import types  # noqa: E402

STORE = _FakeRedis()
CALLS: list = []


class _FakeSentinel:
    def __init__(self, hosts, **kw):
        CALLS.append(("sentinel", hosts, kw))

    def master_for(self, name, **kw):
        CALLS.append(("master_for", name, kw))
        return STORE


def _env(**kv):
    for k in ("BUS_BACKEND", "REDIS_SENTINEL_HOSTS", "REDIS_SENTINEL_MASTER", "REDIS_URL"):
        os.environ.pop(k, None)
    os.environ.update(kv)


class _FakeRedisClass:
    @classmethod
    def from_url(cls, url, **kw):
        CALLS.append(("url", url, kw))
        return STORE


def run():
    # Fake redis-py entirely (the CI `quality` job has no redis installed, and
    # nothing here needs a real client): shadow `redis` + `redis.sentinel`.
    fake = types.ModuleType("redis")
    fake.Redis = _FakeRedisClass  # type: ignore[attr-defined]
    fake_s = types.ModuleType("redis.sentinel")
    fake_s.Sentinel = _FakeSentinel  # type: ignore[attr-defined]
    fake.sentinel = fake_s  # type: ignore[attr-defined]
    sys.modules["redis"] = fake
    sys.modules["redis.sentinel"] = fake_s

    _env(BUS_BACKEND="memory")
    assert isinstance(main.make_correlator().window_counter, DequeWindowCounter)

    _env(BUS_BACKEND="redis", REDIS_URL="redis://x:6379/0")
    wc = main.make_correlator().window_counter
    assert isinstance(wc, RedisWindowCounter) and wc.ns == "ws8:corr"
    assert CALLS[-1][0] == "url" and CALLS[-1][2]["decode_responses"] is True

    CALLS.clear()
    _env(BUS_BACKEND="redis-sentinel",
         REDIS_SENTINEL_HOSTS="s1:26379, s2", REDIS_SENTINEL_MASTER="m1")
    wc = main.make_correlator().window_counter
    assert isinstance(wc, RedisWindowCounter) and wc.ns == "ws8:corr", type(wc)
    assert CALLS[0][1] == [("s1", 26379), ("s2", 26379)], CALLS[0]
    assert CALLS[1][1] == "m1" and CALLS[1][2]["decode_responses"] is True
    ws4_src = (HERE.parent / "ws4-detection" / "main.py").read_text(encoding="utf-8")
    for needle in ("Sentinel(sentinel_hosts, password=password,", "socket_timeout=1, decode_responses=True)",
                   "redis_class=redis.Redis,"):
        assert needle in ws4_src, f"ws4 Sentinel wiring changed ({needle!r}); re-sync the helper"
    # Same kwargs as ws4-detection/main.py (Sentinel(socket_timeout=1,
    # decode_responses=True, password); master_for(redis_class, password,
    # decode_responses)) so this fake cannot drift from the real wiring.
    assert CALLS[0][2] == {"password": None, "socket_timeout": 1, "decode_responses": True}, CALLS[0]
    assert CALLS[1][2] == {"redis_class": _FakeRedisClass, "password": None,
                           "decode_responses": True}, CALLS[1]

    # state lives in the shared store: a fresh correlator ("restart") sees it
    wc.hit("k", 1_000, 60_000, member="a")
    wc2 = main.make_correlator().window_counter
    assert wc2.hit("k", 2_000, 60_000, member="b") == 2, "window state lost across re-instantiation"
    assert any(k.startswith("ws8:corr") for k in STORE.store), list(STORE.store)

    _env(BUS_BACKEND="redis-sentinel")
    try:
        main.make_correlator()
        raise AssertionError("missing REDIS_SENTINEL_HOSTS must fail loudly")
    except RuntimeError as e:
        assert "REDIS_SENTINEL_HOSTS" in str(e)
    print("[OK] ws8 window backend selection (memory/redis/redis-sentinel) PASS")


def run_failover_redelivery():
    """A Sentinel failover makes the window write raise once: the shared runner must leave the message unacked,
    the redelivery must succeed, and a further identical redelivery must not double-count (member = alert id)."""
    from shared.runner import _process_message
    from correlator import Correlator

    class _Flaky(RedisWindowCounter):
        calls = 0

        def hit(self, *a, **kw):
            type(self).calls += 1
            if type(self).calls == 1:
                raise ConnectionError("master failed over")
            return super().hit(*a, **kw)

    class _Bus:
        def produce(self, *a, **kw):
            pass

    class _Msg:
        id, key = "m1", "k"
        payload = {"alert_id": "a-failover", "time": 1_750_000_000_000, "rule_id": "r1", "tenant_id": "acme",
                   "level": "high", "mitre": {"tactic": "TA0006"}, "actor": {"user": {"name": "jdoe"}}}

    class _ZFake(_FakeRedis):  # ws4's fake has no zrange; the correlator reads members back with it
        def zrange(self, key, start, stop):
            return list(self.store.get(key, {}))

    store = _ZFake()
    wc = _Flaky(store, namespace="ws8:corr")
    handler = main.make_handler(_Bus(), Correlator(wc, horizon_s=3600, member_cap=100))
    acked: list = []
    ack = lambda m, g: acked.append(m)  # noqa: E731
    msg = _Msg()
    import contextlib
    import io
    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):  # the runner logs the expected failure
        r1 = _process_message(_Bus(), "alerts", "cg-correlate", msg, handler, 5, 1, ack_fn=ack)
    assert r1 == "failed" and not acked, (r1, acked)
    r2 = _process_message(_Bus(), "alerts", "cg-correlate", msg, handler, 5, 2, ack_fn=ack)
    assert r2 == "acked" and len(acked) == 1, (r2, acked)
    keys = [k for k in store.store if k.startswith("ws8:corr")]
    assert keys, "the redelivery wrote no window state"
    before = {k: len(wc.members(k.split("ws8:corr:", 1)[-1])) for k in keys}
    r3 = _process_message(_Bus(), "alerts", "cg-correlate", msg, handler, 5, 3, ack_fn=ack)
    after = {k: len(wc.members(k.split("ws8:corr:", 1)[-1])) for k in keys}
    assert r3 == "acked" and before == after, ("duplicate redelivery changed the window", before, after)
    print("[OK] ws8 failover: failed write -> unacked -> redelivered once, duplicate redelivery not double-counted PASS")


if __name__ == "__main__":
    run()
    run_failover_redelivery()
