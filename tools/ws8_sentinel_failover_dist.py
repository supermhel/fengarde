"""Distribution of Sentinel failover times with the host CPU saturated (infra/docker-compose.ws8-sentinel-proof.yml).

Each round: kill the current Redis master, time until Sentinel reports a different master AND that master accepts a write,
restart the killed node and wait until it is a synced replica again. CPU hogs (busy-loop containers) run for the whole
test so the Sentinels/Redis nodes compete for CPU the way they did in the full-stack load runs.

  COMPOSE_PROJECT_NAME=ws8sentproof REDIS_PASSWORD=proofpw python tools/ws8_sentinel_failover_dist.py --rounds 12 --hogs 16

The Sentinel timings under test come from the stack's env (WS8_SENTINEL_DOWN_AFTER_MS / WS8_SENTINEL_FAILOVER_MS in the compose
file); this script records what the stack actually runs with, plus the Sentinel events that explain slow rounds.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
import ws8_failover_load_proof as lp  # noqa: E402  (compose helpers, node map)

PW = os.environ.setdefault("REDIS_PASSWORD", "proofpw")
HOG = "ws8stress"


def log(*a):
    print(f"[{time.strftime('%H:%M:%S')}]", *a, flush=True)


def rcli(svc, *args):
    r = lp.dc("exec", "-T", svc, "redis-cli", "-a", PW, "--no-auth-warning", *args)
    return (r.stdout + r.stderr).strip()


def sentinel_cfg():
    out = lp.dc("exec", "-T", "sentinel-1", "redis-cli", "-p", "26379", "sentinel", "master", "mymaster").stdout.split()
    d = dict(zip(out[::2], out[1::2]))
    return {k: d.get(k) for k in ("down-after-milliseconds", "failover-timeout", "parallel-syncs", "quorum")}


def start_hogs(n):
    for i in range(n):
        lp.sh(["docker", "run", "-d", "--rm", "--name", f"{HOG}-{i}", "alpine", "sh", "-c", "while :; do :; done"])


def stop_hogs(n):
    lp.sh(["docker", "rm", "-f"] + [f"{HOG}-{i}" for i in range(n)])


def one_round():
    old = lp.master_ip()
    svc = lp.IP_TO_SERVICE[old]
    t0 = time.time()
    lp.dc("kill", svc)
    new, took = lp.wait_new_master(old, timeout_s=180)
    if not new:
        return svc, None, None
    nsvc = lp.IP_TO_SERVICE[new]
    while time.time() - t0 < 180 and rcli(nsvc, "set", "probe", "1") != "OK":
        time.sleep(0.2)
    writable = round(time.time() - t0, 1)
    lp.docker_start(svc)
    t1 = time.time()
    while time.time() - t1 < 120 and "connected_slaves:2" not in rcli(nsvc, "info", "replication"):
        time.sleep(1)
    return svc, writable, took


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=12)
    ap.add_argument("--hogs", type=int, default=16)
    ap.add_argument("--label", default="")
    a = ap.parse_args()
    cfg = sentinel_cfg()
    log("sentinel config in effect:", cfg, a.label)
    start_hogs(a.hogs)
    time.sleep(10)
    res = []
    try:
        for n in range(a.rounds):
            svc, writable, took = one_round()
            res.append(writable)
            log(f"round {n + 1}/{a.rounds}: killed {svc}, new master reported {took}s, writable {writable}s")
            time.sleep(5)
    finally:
        stop_hogs(a.hogs)
    ok = sorted(x for x in res if x is not None)
    ev = ""
    for s in ("sentinel-1", "sentinel-2", "sentinel-3"):
        ev += lp.dc("logs", "--no-log-prefix", s).stdout
    tilt = ev.count("+tilt")
    aborts = ev.count("failover-abort-not-elected")
    out = {"config": cfg, "rounds": a.rounds, "failed_rounds": a.rounds - len(ok), "hogs": a.hogs, "writable_s": ok,
           "min": ok[0] if ok else None, "median": statistics.median(ok) if ok else None,
           "p90": ok[int(0.9 * (len(ok) - 1))] if ok else None, "max": ok[-1] if ok else None,
           "tilt_events": tilt, "failover_aborts_not_elected": aborts}
    print("RESULT_JSON " + json.dumps(out))
    print(f"SUMMARY config={cfg} rounds={a.rounds} min={out['min']} median={out['median']} p90={out['p90']} max={out['max']} "
          f"tilt={tilt} aborts={aborts} failed={out['failed_rounds']}")
    return 0 if ok and len(ok) == a.rounds else 1


if __name__ == "__main__":
    sys.exit(main())
