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
import redis  # noqa: E402
import redis.sentinel  # noqa: E402

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


def run():
    redis.sentinel.Sentinel = _FakeSentinel
    redis.Redis.from_url = classmethod(lambda cls, url, **kw: (CALLS.append(("url", url, kw)), STORE)[1])

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


if __name__ == "__main__":
    run()
