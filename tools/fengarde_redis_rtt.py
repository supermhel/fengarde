"""Redis round-trip micro-benchmark for WS-4's window-counter call shapes.

Compares, against a real Redis, the cost per call of: PING; the current
RedisWindowCounter shape (MULTI pipeline of ZADD GT + ZREMRANGEBYSCORE + ZCARD
+ EXPIRE); the same four commands without MULTI/EXEC; and one EVALSHA running
the same four steps server-side. Reports calls/s and ms/call so a change to the
call shape can be judged by measurement. Run inside the compose network (see
tools/fengarde_ws4_profile.py for the docker run line).
"""
import os
import time

import redis

r = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
LUA = ("redis.call('ZADD',KEYS[1],'GT',ARGV[2],ARGV[1]) "
       "redis.call('ZREMRANGEBYSCORE',KEYS[1],0,ARGV[3]) "
       "local c=redis.call('ZCARD',KEYS[1]) redis.call('EXPIRE',KEYS[1],ARGV[4]) return c")
sha = r.script_load(LUA)
N = 3000


def bench(name, fn):
    fn(0)
    t = time.perf_counter()
    for i in range(N):
        fn(i)
    d = time.perf_counter() - t
    print(f"{name:42s} {N / d:8.0f} calls/s  {d / N * 1000:6.3f} ms/call")


def multi(i):
    p = r.pipeline()
    p.zadd("rtt:k", {f"m{i}": i}, gt=True); p.zremrangebyscore("rtt:k", 0, i - 300000)
    p.zcard("rtt:k"); p.expire("rtt:k", 301)
    return p.execute()


def nomulti(i):
    p = r.pipeline(transaction=False)
    p.zadd("rtt:k", {f"m{i}": i}, gt=True); p.zremrangebyscore("rtt:k", 0, i - 300000)
    p.zcard("rtt:k"); p.expire("rtt:k", 301)
    return p.execute()


bench("PING", lambda i: r.ping())
bench("MULTI pipeline (current)", multi)
bench("pipeline, no MULTI/EXEC", nomulti)
bench("EVALSHA (one command, same 4 steps)", lambda i: r.evalsha(sha, 1, "rtt:k", f"m{i}", i, i - 300000, 301))
r.delete("rtt:k")
