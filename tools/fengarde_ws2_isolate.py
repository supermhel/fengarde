"""Does WS-2 or Redis saturate first? Controlled drain experiments on the
isolated load-test stack (benchmark/loadtest.md section 6).

Everything except redis (and WS-2 itself) is stopped, a fixed backlog is
prefilled on `raw.events`, then WS-2 runs with K replicas and drains it:

  throughput = backlog / drain time (cg-normalize entries-read)
  while sampling: docker stats CPU of ws2 and redis, redis ops/s
  (INFO stats instantaneous_ops_per_sec), SLOWLOG length.

Reading the result: if K replicas scale the drain rate ~K-fold, one WS-2
process was the limit (Redis had headroom). If the drain rate stops scaling
while redis CPU approaches one core / ops/s approaches the redis-benchmark
ceiling, Redis (a single thread) is. `--bench` also runs redis-benchmark
inside the redis container for the raw XADD/GET ceiling.

Run (stack up as in loadtest.md, services other than redis/ws2 will be
stopped by this script and are NOT restarted):
  python tools/fengarde_ws2_isolate.py --replicas 1 2 3 --events 30000 --out benchmark/raw/ws2-isolate-2026-10-29.json
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

import redis

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import fengarde_loadtest_live as LL  # noqa: E402

COMPOSE = ["docker", "compose", "-f", str(ROOT / "infra/docker-compose.yml"), "-f",
           str(ROOT / "infra/docker-compose.loadtest.yml")]
ENV = {"COMPOSE_PROJECT_NAME": "fgloadtest", "LT_REDIS_PORT": "16379", "LT_OS_PORT": "19200"}


def dc(*args, check=True):
    import os
    return subprocess.run([*COMPOSE, *args], env={**os.environ, **ENV}, capture_output=True, text=True, check=check)


def docker_cpu(project="fgloadtest"):
    p = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{json .}}"],
                       capture_output=True, text=True, timeout=30)
    out: dict[str, float] = {}
    for line in p.stdout.splitlines():
        j = json.loads(line)
        if j["Name"].startswith(project + "-"):
            svc = j["Name"][len(project) + 1:].rsplit("-", 1)[0]
            out[svc] = out.get(svc, 0.0) + float(j["CPUPerc"].rstrip("%"))
    return out


def run_one(r: redis.Redis, replicas: int, events: int, tag: str) -> dict:
    dc("stop", "ws2-normalization", check=False)
    r.delete("normalized.events", "raw.events.deadletter")
    r.xtrim("raw.events", maxlen=0)
    pipe = r.pipeline(transaction=False)
    sent = 0
    while sent < events:
        n = min(1000, events - sent)
        for e in LL.make_chunk(sent + int(time.time()) % 1000 * 1_000_000, n, tag):
            pipe.xadd("raw.events", {"key": e["meta"]["ingest_id"], "payload": json.dumps(e)})
        pipe.execute()
        sent += n
    r.config_resetstat()
    r.slowlog_reset()
    dc("up", "-d", "--no-recreate", "--scale", f"ws2-normalization={replicas}", "ws2-normalization")
    t0 = time.time()
    cpu_samples: list[dict] = []
    ops: list[int] = []
    done = 0
    t_first = None
    # progress = entries WS-2 has produced on normalized.events (nothing else
    # reads or trims it while this runs); the backlog is `events` long.
    while True:
        time.sleep(1.0)
        done = r.xlen("normalized.events")
        if t_first is None and done > 0:
            t_first = time.time()
        ops.append(int(r.info("stats")["instantaneous_ops_per_sec"]))
        if len(ops) % 2 == 0:
            cpu_samples.append(docker_cpu())
        if done >= events * 0.99:
            break
        if time.time() - t0 > 600:
            break
    t1 = time.time()
    drained = done
    elapsed = t1 - (t_first or t0)
    ws2_cpu = [s.get("ws2-normalization", 0.0) for s in cpu_samples]
    redis_cpu = [s.get("redis", 0.0) for s in cpu_samples]
    slow = r.slowlog_get(10)
    return {
        "replicas": replicas, "backlog": events, "drained": drained, "seconds": round(elapsed, 1),
        "events_per_s": round(drained / elapsed, 1) if elapsed > 0 else None,
        "ws2_cpu_pct_total_mean": round(statistics.mean(ws2_cpu), 1) if ws2_cpu else None,
        "ws2_cpu_pct_per_replica_mean": round(statistics.mean(ws2_cpu) / replicas, 1) if ws2_cpu else None,
        "redis_cpu_pct_mean": round(statistics.mean(redis_cpu), 1) if redis_cpu else None,
        "redis_cpu_pct_max": round(max(redis_cpu), 1) if redis_cpu else None,
        "redis_ops_per_s_mean": round(statistics.mean(ops)) if ops else None,
        "redis_ops_per_s_max": max(ops) if ops else None,
        "slowlog_entries": len(slow),
        "slowlog_max_us": max((e["duration"] for e in slow), default=0),
        "redis_commandstats": {k: v["calls"] for k, v in r.info("commandstats").items()
                               if v["calls"] > 1000},
    }


def redis_benchmark() -> dict:
    out = {}
    for name, cmd in (("xadd_c8", "-c 8 -n 200000 -q xadd bench '*' f v"),
                      ("xadd_c8_pipeline16", "-c 8 -P 16 -n 400000 -q xadd bench '*' f v"),
                      ("ping_c8", "-c 8 -n 200000 -q -t ping_inline")):
        p = subprocess.run(["docker", "exec", "fgloadtest-redis-1", "sh", "-c", f"redis-benchmark {cmd}"],
                           capture_output=True, text=True)
        out[name] = (p.stdout or p.stderr).strip().replace("\r", "\n").splitlines()[-1][:120]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--replicas", type=int, nargs="*", default=[1, 2, 3])
    ap.add_argument("--events", type=int, default=30000)
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--bench", action="store_true")
    ap.add_argument("--redis-port", type=int, default=16379)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    r = redis.Redis(host="127.0.0.1", port=a.redis_port, decode_responses=True)
    r.ping()
    for svc in ("ws3-indexer", "ws4-detection", "ws5-ai", "ws8-correlation", "ws9-resolver"):
        dc("stop", svc, check=False)
    res: dict = {"date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "runs": []}
    if a.bench:
        res["redis_benchmark"] = redis_benchmark()
        print(json.dumps(res["redis_benchmark"]), flush=True)
    for rep in range(a.repeat):
        for k in a.replicas:
            run = run_one(r, k, a.events, f"iso{rep}k{k}")
            res["runs"].append(run)
            print(json.dumps({x: y for x, y in run.items() if x != "redis_commandstats"}), flush=True)
    dc("stop", "ws2-normalization", check=False)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(res, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
