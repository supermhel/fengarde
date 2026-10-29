"""Failover-under-load proof on the FULL docker-compose.ha.yml stack (ws1..ws9 + Redis/Sentinel + 3-node OpenSearch).

Unlike tools/ws8_failover_load_proof.py (ws8 + Redis only), the neighbours are loaded too:
  - two-alert chains go onto the `alerts` topic at --rate alerts/s (consumed by ws8 replicas, ws3 cg-index, ws9, ws3 webhook),
    from --procs producer processes inside the ws2 container;
  - --raw-rate benign raw.events/s go through ws2 -> ws4 -> ws3 at the same time;
  - the Redis MASTER is killed --kills times while this runs (killed node restarted 3 s later).
It then counts, per chain, from the `incidents` stream AND from OpenSearch (incidents-*): lost, forked incident ids,
wrong member sets; plus the end state of every consumer group (pending/lag), and which ws8 replica handled which alert.

Stack bring-up: infra/docker-compose.ws8-ha-proof.yml header. Run (own project name):
  COMPOSE_PROJECT_NAME=ws8haproof REDIS_PASSWORD=proofpw python tools/ws8_ha_load_proof.py --rate 20 --chains 300 --kills 3
Exit 1 when lost/forked/wrong > 0 (or a producer gave up).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid

PROJ = os.environ.setdefault("COMPOSE_PROJECT_NAME", "ws8haproof")
os.environ.setdefault("REDIS_PASSWORD", "proofpw")
BUS_NODES = {"172.28.0.11": "siem-bus-ha-1", "172.28.0.12": "siem-bus-ha-2", "172.28.0.13": "siem-bus-ha-3"}
WS2 = f"{PROJ}-ws2-normalization-1"
WS3 = f"{PROJ}-ws3-indexer-1"

GEN = r'''
import json, sys, time
from shared.window import redis_client_for_backend
tag, n, rate, gap, k, procs = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
r = redis_client_for_backend("redis-sentinel")   # master-aware client; XADD pipelined straight into the alerts stream
mine = [i for i in range(n) if i % procs == k]
sched = []
for s in range(len(mine) + gap):
    if s < len(mine):
        sched.append((mine[s], 1, "TA0006"))
    if s >= gap:
        sched.append((mine[s - gap], 2, "TA0008"))
per_proc = rate / procs
acked, failed, retries, idx, t0 = 0, [], 0, 0, time.time()
while idx < len(sched):
    due = min(len(sched), int((time.time() - t0) * per_proc) + 1)
    if due <= idx:
        time.sleep(0.005)
        continue
    batch = sched[idx:due]
    for _ in range(120):
        try:
            p = r.pipeline(transaction=False)
            now = int(time.time() * 1000) - 5000
            for i, part, tactic in batch:
                p.xadd("alerts", {"key": f"u{i}", "payload": json.dumps({
                    "alert_id": f"{tag}-{i}-{part}", "tenant_id": tag, "time": now,
                    "rule_id": "r", "level": "high", "score": 10, "mitre": {"tactic": tactic}, "actor": {"user": {"name": f"u{i}"}}})})
            p.execute()
            acked += len(batch)
            break
        except Exception:
            retries += 1
            time.sleep(0.5)
            r = redis_client_for_backend("redis-sentinel")
    else:
        failed += [f"{tag}-{i}-{part}" for i, part, _ in batch]
    idx = due
print(json.dumps({"acked": acked, "failed": failed, "retries": retries, "seconds": round(time.time() - t0, 1)}))
'''

RAW = r'''
import json, sys, time, random
from shared.bus import Bus
tag, rate, seconds = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
bus = Bus()
n, errs, t0 = 0, 0, time.time()
while time.time() - t0 < seconds:
    ip = f"198.51.{random.randint(0, 255)}.{random.randint(1, 254)}"
    raw = (f"Jun 10 13:55:{n % 60:02d} db01 sshd[{3000 + n % 900}]: Accepted password for deploy from {ip} "
           f"port {40000 + n % 9000} ssh2")
    ev = {"source_type": "linux_ssh", "raw": raw,
          "meta": {"ingest_id": f"{tag}-raw-{n}", "tenant_id": tag, "trace_id": tag, "received_at": int(time.time() * 1000), "ip": ip}}
    try:
        bus.produce("raw.events", key=ip, payload=ev)
        n += 1
    except Exception:
        errs += 1
        time.sleep(0.5)
    time.sleep(max(0.0, t0 + (n + errs + 1) / rate - time.time()))
print(json.dumps({"raw_sent": n, "raw_errors": errs}))
'''

COLLECT = r'''
import json, sys, collections
from shared.window import redis_client_for_backend
tag, n = sys.argv[1], int(sys.argv[2])
r = redis_client_for_backend("redis-sentinel")
in_stream = collections.Counter()
for _id, f in r.xrange("alerts"):
    p = json.loads(f["payload"])
    if p.get("tenant_id") == tag:
        in_stream[p["alert_id"]] += 1
em = collections.defaultdict(list)
for _id, f in r.xrange("incidents"):
    p = json.loads(f["payload"])
    if p["incident_id"].startswith(tag + ":"):
        em[p["incident_id"]].append(p)
groups = {}
for t in ("raw.events", "normalized.events", "scored.events", "alerts", "incidents", "entity.updates"):
    try:
        groups[t] = [{k: g.get(k) for k in ("name", "pending", "lag")} for g in r.xinfo_groups(t)]
    except Exception as e:
        groups[t] = str(e)[:60]
emissions = {k: [[p["member_count"], sorted(p["member_alert_ids"]), p["tactics"]] for p in v] for k, v in em.items()}
print(json.dumps({"in_stream": dict(in_stream), "emissions": emissions, "groups": groups}))
'''


def sh(*args, **kw):
    return subprocess.run(list(args), capture_output=True, text=True, **kw)


def log(*a):
    print(f"[{time.strftime('%H:%M:%S')}]", *a, flush=True)


def sentinel_master():
    r = sh("docker", "exec", "siem-sentinel-ha-1", "redis-cli", "-p", "26379", "sentinel", "get-master-addr-by-name", "mymaster")
    return (r.stdout.split() or [""])[0]


def py(container, code, *argv, stdin=None, timeout=900):
    return sh("docker", "exec", "-i", container, "python", "-c", code, *argv, input=stdin, timeout=timeout)


def os_search(index, body):
    code = ("import json,os,sys,urllib.request as u;urls=os.environ['OPENSEARCH_URL'].split(',')\n"
            "body=sys.stdin.read().encode();last=None\n"
            "for url in urls:\n"
            "  try:\n"
            f"    req=u.Request(url+'/{index}',data=body,headers={{'Content-Type':'application/json'}},method='POST')\n"
            "    print(u.urlopen(req,timeout=30).read().decode());break\n"
            "  except Exception as e: last=e\n"
            "else: raise last")
    for _ in range(6):                      # a failed read must never look like "0 documents"
        r = py(WS3, code, stdin=json.dumps(body))
        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout)
        time.sleep(5)
    raise RuntimeError(f"OpenSearch read failed: {r.stderr[-200:]}")


def wait_idle(timeout_s=900):
    """Previous runs leave consumer backlog; start only from an idle pipeline with a live master."""
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        r = py(WS2, COLLECT, "idle", "0")
        if r.returncode == 0 and sentinel_master():
            g = json.loads(r.stdout.strip().splitlines()[-1])["groups"]
            busy = sum((x["pending"] or 0) + (x["lag"] or 0) for v in g.values() if isinstance(v, list) for x in v)
            if busy == 0:
                return
        time.sleep(10)
    raise RuntimeError("pipeline not idle")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rate", type=float, default=20.0, help="alerts/s onto the alerts topic")
    ap.add_argument("--chains", type=int, default=300)
    ap.add_argument("--procs", type=int, default=0, help="producer processes (default: ceil(rate/15))")
    ap.add_argument("--raw-rate", type=float, default=50.0, help="benign raw.events/s through ws2->ws4->ws3 (0 = off)")
    ap.add_argument("--kills", type=int, default=3)
    ap.add_argument("--kill-interval", type=float, default=0.0, help="seconds between kills (default: spread over the run)")
    ap.add_argument("--drain-s", type=int, default=300)
    ap.add_argument("--ws8", default="", help="comma list of ws8 container names (default: autodetect)")
    a = ap.parse_args()
    procs = a.procs or max(1, int(-(-a.rate // 15)))
    tag = f"hl{int(a.rate)}-{uuid.uuid4().hex[:5]}"
    gap = max(10, int(a.rate * 2))               # second tactic ~4 s after the first
    run_s = a.chains * 2 / a.rate + gap * 2 / a.rate
    ws8 = a.ws8.split(",") if a.ws8 else sh(
        "docker", "ps", "--format", "{{.Names}}", "--filter", f"name={PROJ}-ws8-correlation").stdout.split()
    log(f"tag={tag} rate={a.rate}/s procs={procs} chains={a.chains} gap={gap} raw={a.raw_rate}/s kills={a.kills} "
        f"ws8={ws8} est_run={run_s:.0f}s")
    wait_idle()
    gens = [subprocess.Popen(["docker", "exec", "-i", WS2, "python", "-c", GEN, tag, str(a.chains), str(a.rate), str(gap),
                              str(k), str(procs)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for k in range(procs)]
    raw = None
    if a.raw_rate > 0:
        raw = subprocess.Popen(["docker", "exec", "-i", WS2, "python", "-c", RAW, tag, str(a.raw_rate), str(run_s)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stats = {}

    def sample_stats():
        time.sleep(run_s * 0.5)
        out = sh("docker", "stats", "--no-stream", "--format", "{{.Name}} {{.CPUPerc}} {{.MemPerc}}").stdout.splitlines()
        parts = [ln.split() for ln in out]
        rows = sorted(((float(p[1].rstrip('%')), p[0]) for p in parts if len(p) == 3), reverse=True)
        stats["top_cpu"] = [f"{n} {c}%" for c, n in rows[:6]]
        stats["total_cpu_pct"] = round(sum(c for c, _ in rows), 0)
    threading.Thread(target=sample_stats, daemon=True).start()
    kills = []
    interval = a.kill_interval or run_s / (a.kills + 1)
    t_start = time.time()
    for k in range(a.kills):
        time.sleep(max(0, interval * (k + 1) - (time.time() - t_start)))
        old = sentinel_master()
        node = BUS_NODES[old]
        sh("docker", "kill", node)
        t0 = time.time()
        new = old
        while time.time() - t0 < 60 and new == old:
            time.sleep(1)
            new = sentinel_master()
        took = round(time.time() - t0, 1)
        log(f"KILL {k + 1}/{a.kills}: master {node} -> {BUS_NODES.get(new)} in {took}s")
        time.sleep(3)
        sh("docker", "start", node)
        kills.append({"killed": node, "failover_s": took})
    outs = [g.communicate(timeout=900)[0] for g in gens]
    gen = [json.loads(o.strip().splitlines()[-1]) for o in outs if o.strip()]
    ro = raw.communicate(timeout=900)[0].strip().splitlines() if raw else []
    rawo = json.loads(ro[-1]) if ro else {}
    acked = sum(g["acked"] for g in gen)
    failed = [x for g in gen for x in g["failed"]]
    log(f"producers: acked={acked} failed={len(failed)} retries={sum(g['retries'] for g in gen)} "
        f"seconds={[g['seconds'] for g in gen]} raw={rawo}")

    def collect():
        r = py(WS2, COLLECT, tag, str(a.chains))
        if r.returncode != 0:
            raise RuntimeError(r.stderr[-400:])
        return json.loads(r.stdout.strip().splitlines()[-1])

    def os_state():
        inc = os_search("incidents-*/_search", {"size": 10000, "query": {"term": {"tenant_id": tag}}}).get("hits", {}).get("hits", [])
        al = os_search("alerts-*/_count", {"query": {"term": {"tenant_id": tag}}}).get("count", 0)
        return [h["_source"] for h in inc], al

    last, stable, t0 = None, 0, time.time()
    drain = {}                                  # seconds after the last producer finished
    while time.time() - t0 < a.drain_s:
        time.sleep(10)
        c = collect()
        inc_docs, al_n = os_state()
        pend = sum(g["pending"] or 0 for v in c["groups"].values() if isinstance(v, list) for g in v)
        lag = sum(g["lag"] or 0 for v in c["groups"].values() if isinstance(v, list) for g in v)
        ws8_g = [g for g in (c["groups"].get("alerts") or []) if isinstance(g, dict) and g["name"] == "cg-correlate"]
        if ws8_g and not (ws8_g[0]["pending"] or ws8_g[0]["lag"]):
            drain.setdefault("ws8_cg_correlate_idle_s", round(time.time() - t0))
        if al_n >= acked:
            drain.setdefault("ws3_alerts_all_indexed_s", round(time.time() - t0))
        if len(inc_docs) >= a.chains:
            drain.setdefault("ws3_incidents_all_indexed_s", round(time.time() - t0))
        key = json.dumps([len(c["emissions"]), len(inc_docs), al_n, pend, lag])
        stable = stable + 1 if key == last else 0
        last = key
        log(f"  drain: incident_ids={len(c['emissions'])} os_incident_docs={len(inc_docs)} os_alerts={al_n} pending={pend} lag={lag}")
        if stable >= 2 and pend == 0 and lag == 0 and al_n >= acked and len(inc_docs) >= a.chains:
            break
    c = collect()
    inc_docs, al_n = os_state()
    # Verdict from OpenSearch (the end state), not from the bus: shared/bus.py trim_acked deletes fully-acked
    # stream prefixes, so the `alerts`/`incidents` streams no longer hold the run once it has drained.
    by_entity = {}
    for d in inc_docs:
        by_entity.setdefault(d.get("entity_value"), []).append(d)
    failed_set = set(failed)
    lost, forked, wrong = [], [], []
    elig = 0
    for i in range(a.chains):
        ids = [f"{tag}-{i}-1", f"{tag}-{i}-2"]
        if any(x in failed_set for x in ids):
            continue
        elig += 1
        docs = by_entity.get(f"u{i}", [])
        if not docs:
            lost.append(i)
            continue
        if len({d["incident_id"] for d in docs}) > 1:
            forked.append(i)
        if any(sorted(d.get("member_alert_ids") or []) != sorted(ids) or d.get("tactics") != ["TA0006", "TA0008"] for d in docs):
            wrong.append(i)
    bus_lost = max(0, acked - al_n)           # acked on the bus but not indexed by ws3
    os_ids = {d["incident_id"] for d in inc_docs}
    os_full = sum(1 for d in inc_docs if d.get("member_count") == 2 and d.get("tactics") == ["TA0006", "TA0008"])
    # which ws8 replica handled which alert
    seen = {}
    for name in ws8:
        for ln in sh("docker", "logs", name).stdout.splitlines() + sh("docker", "logs", name).stderr.splitlines():
            m = re.search(r'"msg": "handled alert", "alert_id": "(%s-\d+-[12])"' % re.escape(tag), ln)
            if m:
                seen.setdefault(m.group(1), set()).add(name[-1])
    split = sum(1 for i in range(a.chains) if seen.get(f"{tag}-{i}-1") and seen.get(f"{tag}-{i}-2")
                and seen[f"{tag}-{i}-1"].isdisjoint(seen[f"{tag}-{i}-2"]))
    per = {n[-1]: sum(n[-1] in v for v in seen.values()) for n in ws8}
    achieved = round(acked / max(g["seconds"] for g in gen), 1)
    res = {"rate": a.rate, "chains": a.chains, "eligible": elig, "lost": len(lost), "forked": len(forked), "wrong_members": len(wrong),
           "acked_not_indexed": bus_lost, "producer_failed": len(failed), "os_incident_docs": len(inc_docs),
           "os_incident_ids": len(os_ids),
           "os_full_incidents": os_full, "os_alerts_indexed": al_n, "alerts_acked": acked, "kills": kills,
           "ws8_per_replica": per, "host_cpu_sample": stats, "drain_after_producers": drain, "achieved_alerts_per_s": achieved,
           "chains_split_across_replicas": split, "raw": rawo,
           "groups_end": {t: v for t, v in c["groups"].items()}}
    print("RESULT_JSON " + json.dumps(res))
    good = not lost and not forked and not wrong and not failed and elig > 0 and not bus_lost
    print(f"SUMMARY rate={a.rate}/s chains={a.chains} eligible={elig} lost={len(lost)} forked={len(forked)} "
          f"wrong_members={len(wrong)} "
          f"acked_not_indexed={bus_lost} producer_failed={len(failed)} os_incident_ids={len(os_ids)} "
          f"os_full={os_full} os_alerts={al_n}/{acked} achieved={achieved}/s split_chains={split} per_replica={per} "
          f"drain={drain} cpu={stats} kills={[k['failover_s'] for k in kills]}")
    print("RESULT ha-load: " + ("PASS" if good else "FAIL"))
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
