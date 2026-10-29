"""ws8 consume throughput, and the cost of one HOT track on Redis shared state (infra/docker-compose.ws8-sentinel-proof.yml).

Every alert handled by the shared-state correlator reads the whole side table of its track (HGETALL + json.loads of up to
member_cap=200 entries). This injects N alerts straight into the `alerts` stream as fast as one pipeline can write, with the ws8
replicas consuming, and times until the `cg-correlate` group is idle:

  spread -- every alert has its own actor (tracks of 1 member): the cheap case
  hot    -- every alert belongs to ONE actor, alternating two tactics, so one track sits at the member cap (200) and both
            replicas hit it concurrently

No failover in this test; it measures ws8 alone (no ws3/ws9 in this stack).
  COMPOSE_PROJECT_NAME=ws8sentproof REDIS_PASSWORD=proofpw python tools/ws8_hot_track_cost.py --alerts 3000
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(__file__))
import ws8_failover_load_proof as lp  # noqa: E402

INJECT = r'''
import json, sys, time
from shared.window import redis_client_for_backend
mode, tag, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
r = redis_client_for_backend("redis-sentinel")
now = int(time.time() * 1000) - 5000
for lo in range(0, n, 500):
    p = r.pipeline(transaction=False)
    for i in range(lo, min(n, lo + 500)):
        actor = f"{tag}-hot" if mode == "hot" else f"{tag}-u{i}"
        p.xadd("alerts", {"key": actor, "payload": json.dumps({"alert_id": f"{tag}-{i}", "tenant_id": tag, "time": now + i,
            "rule_id": "r", "level": "high", "score": 10, "mitre": {"tactic": "TA0006" if i % 2 == 0 else "TA0008"},
            "actor": {"user": {"name": actor}}})})
    p.execute()
print("injected", n)
'''

IDLE = r'''
import json
from shared.window import redis_client_for_backend
r = redis_client_for_backend("redis-sentinel")
g = [x for x in r.xinfo_groups("alerts") if x["name"] == "cg-correlate"]
print(json.dumps({"lag": g[0]["lag"], "pending": g[0]["pending"]} if g else {"lag": None, "pending": None}))
'''


def run(mode, n, replicas):
    tag = f"ht{mode}-{uuid.uuid4().hex[:5]}"
    # wait idle
    while True:
        st = json.loads(lp.exec_py("ws8a", IDLE).stdout.strip().splitlines()[-1])
        if not st["lag"] and not st["pending"]:
            break
        time.sleep(2)
    t0 = time.time()
    lp.exec_py("ws8a", INJECT, mode, tag, str(n))
    t_inj = time.time() - t0
    while time.time() - t0 < 900:
        st = json.loads(lp.exec_py("ws8a", IDLE).stdout.strip().splitlines()[-1])
        if st["lag"] == 0 and st["pending"] == 0:
            break
        time.sleep(0.5)
    total = time.time() - t0
    inc = lp.exec_py("ws8a", "import sys;from shared.window import redis_client_for_backend as c;r=c('redis-sentinel');"
                     "print(sum(1 for _i,f in r.xrange('incidents') if sys.argv[1] in f['payload']))", tag).stdout.strip()
    return {"mode": mode, "alerts": n, "replicas": replicas, "inject_s": round(t_inj, 1), "until_idle_s": round(total, 1),
            "ws8_alerts_per_s": round(n / total, 1), "incident_emissions": int(inc or 0)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", type=int, default=3000)
    a = ap.parse_args()
    os.environ.setdefault("COMPOSE_PROJECT_NAME", "ws8sentproof")
    os.environ.setdefault("REDIS_PASSWORD", "proofpw")
    replicas = len(lp.dc("ps", "-q", "ws8a", "ws8b", "ws8c", "ws8d").stdout.split())
    out = [run(m, a.alerts, replicas) for m in ("spread", "hot", "spread", "hot")]
    for o in out:
        print("RESULT_JSON " + json.dumps(o))
    print("SUMMARY " + "; ".join(f"{o['mode']}: {o['ws8_alerts_per_s']}/s ({o['until_idle_s']}s for {o['alerts']})" for o in out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
