"""Q11 (2026-10-14) on a REAL Redis: the Lua fallback of hit_distinct (for servers
older than 6.2, which lack ZADD GT) gives the same counts as the GT pipeline.

The zero-infra gate proves the same property against a Python fake of the Lua
script (test_window_distinct.py); only a real server proves the script itself.
Runs in the CI redis-integration job (REDIS_URL set); without REDIS_URL it says
so and exits 0 -- a documented live-only test (tools/check_test_wiring.py).

Run: REDIS_URL=redis://localhost:6379/0 python services/ws4-detection/test_window_redis_live.py
"""
from __future__ import annotations

import os
import random
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from shared.window import DequeWindowCounter, RedisWindowCounter  # noqa: E402


def main() -> int:
    url = os.environ.get("REDIS_URL")
    if not url:
        print("[SKIP] REDIS_URL unset: live Redis Lua-fallback parity not run (CI redis-integration runs it)")
        return 0
    import redis  # noqa: PLC0415 -- only the live path needs the client

    client = redis.Redis.from_url(url)
    ns = f"q11test:{uuid.uuid4().hex}"
    lua = RedisWindowCounter(client, namespace=ns + ":lua", zadd_gt=False)
    auto = RedisWindowCounter(client, namespace=ns + ":auto")
    deque = DequeWindowCounter()
    rng = random.Random(62)
    base = 1_750_000_000_000
    fails = []
    try:
        for i in range(400):
            t = base + rng.randrange(0, 200_000)       # arbitrary order, stale repeats included
            v = rng.randrange(12)
            a, b, c = (x.hit_distinct("g", t, 60_000, value=v) for x in (lua, auto, deque))
            if not a == b == c:
                fails.append(f"op {i} t={t - base} v={v}: lua={a} auto={b} deque={c}")
                break
        # the stale-repeat guarantee itself, on the Lua path
        for i in range(14):
            lua.hit_distinct("forge", base + i * 1000, 60_000, value=1000 + i)
        lua.hit_distinct("forge", base - 3_600_000, 60_000, value=1000)
        n = lua.hit_distinct("forge", base + 14_000, 60_000, value=1014)
        if n != 15:
            fails.append(f"Lua path: a stale repeat aged a live value out ({n} != 15)")
    finally:
        for key in client.scan_iter(match=f"{ns}*"):
            client.delete(key)
    if fails:
        print("[FAIL] live Redis Lua fallback:", *fails, sep="\n   - ")
        return 1
    print(f"[OK] live Redis {client.info('server').get('redis_version')}: Lua fallback == ZADD GT == deque "
          "on 400 mixed-order ops; stale repeats never age a live value out")
    return 0


if __name__ == "__main__":
    sys.exit(main())
