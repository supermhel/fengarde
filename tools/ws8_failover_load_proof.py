"""Live proofs for ws8 on the Sentinel path under load (infra/docker-compose.ws8-sentinel-proof.yml).

  load   -- N two-alert chains at a steady rate through two ws8 replicas while the Redis MASTER is killed
            K times (killed node restarted a few seconds later so it rejoins as a replica); then counts
            lost/duplicated incident members and duplicate incident ids against the alerts that actually
            reached the bus.
  outage -- both Redis replicas killed (the original primary, redis-1, carries --min-replicas-to-write 1 and
            goes read-only): shows what ws8 does with unprocessed alerts, then recovers and checks the
            incident completes once.

Run (stack already up, own project name):
  COMPOSE_PROJECT_NAME=ws8sentproof REDIS_PASSWORD=proofpw python tools/ws8_failover_load_proof.py load --chains 350 --kills 4
  COMPOSE_PROJECT_NAME=ws8sentproof REDIS_PASSWORD=proofpw python tools/ws8_failover_load_proof.py outage

Exit 1 when an assertion fails. `load` prints the numbers; with --expect-loss it only reports (used for the
pre-change comparison, where the bug is expected to show up).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

COMPOSE = ["docker", "compose", "-f", "infra/docker-compose.ws8-sentinel-proof.yml"]
IP_TO_SERVICE = {"172.29.88.11": "redis-1", "172.29.88.12": "redis-2", "172.29.88.13": "redis-3"}

GEN = r'''
import json, sys, time
from shared.bus import Bus
n, rate, gap = int(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3])
bus = Bus()
acked, failed, errs = [], [], 0
def send(aid, actor, tactic):
    global errs
    for _ in range(120):
        try:
            bus.produce("alerts", key=actor, payload={"alert_id": aid, "tenant_id": "acme",
                "time": int(time.time() * 1000) - 5000, "rule_id": "r", "level": "high", "score": 10,
                "mitre": {"tactic": tactic}, "actor": {"user": {"name": actor}}})
            acked.append(aid)
            return
        except Exception:
            errs += 1
            time.sleep(0.5)
    failed.append(aid)
t0 = time.time()
slot = 1.0 / rate * 2          # two alerts per slot
for s in range(n + gap):
    if s < n:
        send(f"l-{s}-1", f"u{s}", "TA0006")
    if s >= gap:
        send(f"l-{s - gap}-2", f"u{s - gap}", "TA0008")
    time.sleep(max(0.0, t0 + (s + 1) * slot - time.time()))
json.dump({"acked": len(acked), "failed": failed, "producer_retries": errs, "seconds": round(time.time() - t0, 1)},
          open("/tmp/gen.json", "w"))
'''

COLLECT = r'''
import json, sys, collections
from shared.window import redis_client_for_backend
n = int(sys.argv[1])
r = redis_client_for_backend("redis-sentinel")
in_stream = collections.Counter()
for _id, f in r.xrange("alerts"):
    in_stream[json.loads(f["payload"])["alert_id"]] += 1
emissions = collections.defaultdict(list)
for _id, f in r.xrange("incidents"):
    p = json.loads(f["payload"])
    emissions[p["incident_id"]].append(p)
chains = dict(eligible=0, ok=0, lost=0, forked=0, wrong_members=0, bus_lost_alerts=0)
lost, forked, wrong = [], [], []
for i in range(n):
    a, b = f"l-{i}-1", f"l-{i}-2"
    have = [x for x in (a, b) if in_stream[x] > 0]
    chains["bus_lost_alerts"] += 2 - len(have)
    if len(have) < 2:
        continue
    chains["eligible"] += 1
    ids = [k for k in emissions if k.startswith(f"acme:actor:u{i}:")]
    if not ids:
        chains["lost"] += 1; lost.append(i); continue
    if len(ids) > 1:
        chains["forked"] += 1; forked.append(i)
    finals = [max(emissions[k], key=lambda p: p["member_count"]) for k in ids]
    if any(sorted(p["member_alert_ids"]) != sorted([a, b]) for p in finals):
        chains["wrong_members"] += 1; wrong.append(i)
    if len(ids) == 1 and not wrong[-1:] == [i]:
        chains["ok"] += 1
em_total = sum(len(v) for v in emissions.values())
dup_alert_msgs = sum(c - 1 for c in in_stream.values() if c > 1)
groups = r.xinfo_groups("alerts")
print(json.dumps({"chains": chains, "lost_chains": lost[:20], "forked_chains": forked[:20], "wrong_member_chains": wrong[:20],
                  "alert_messages_in_stream": sum(in_stream.values()), "duplicate_alert_messages": dup_alert_msgs,
                  "incident_ids": len(emissions), "incident_emissions": em_total,
                  "extra_emissions_same_id": em_total - len(emissions),
                  "groups": [{k: g.get(k) for k in ("name", "pending", "lag", "entries-read")} for g in groups]}))
'''


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def dc(*args, **kw):
    return sh(COMPOSE + list(args), **kw)


def docker_start(*services):
    """`docker compose start X` also starts X's depends_on chain (it revived the killed replicas through the
    Sentinels), so start the containers directly."""
    for svc in services:
        sh(["docker", "start", dc("ps", "-a", "-q", svc).stdout.strip()])


def exec_py(service, code, *argv, stdin=None, timeout=300):
    r = dc("exec", "-T", service, "python", "-c", code, *argv, input=stdin, timeout=timeout)
    return r


def master_ip():
    r = dc("exec", "-T", "sentinel-1", "redis-cli", "-p", "26379", "sentinel", "get-master-addr-by-name", "mymaster")
    return (r.stdout.split() or [""])[0]


def wait_new_master(old, timeout_s=60):
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        m = master_ip()
        if m and m != old:
            return m, round(time.time() - t0, 1)
        time.sleep(1)
    return None, timeout_s


def collect(chains):
    r = exec_py("ws8a", COLLECT, str(chains))
    if r.returncode != 0:
        raise RuntimeError(r.stderr[-500:])
    return json.loads(r.stdout.strip().splitlines()[-1])


def replica_split(replicas, chains):
    """From the per-alert trace logs: alerts handled per ws8 replica, chains whose two tactics ran on different
    replicas (the case that needs shared state), and alerts handled by more than one replica (redelivery)."""
    import re
    seen = {}
    for svc in replicas:
        for ln in dc("logs", "--no-log-prefix", svc).stdout.splitlines():
            m = re.search(r'"msg": "handled alert", "alert_id": "(l-\d+-[12])"', ln)
            if m:
                seen.setdefault(m.group(1), set()).add(svc)
    per = {svc: sum(svc in v for v in seen.values()) for svc in replicas}
    split = sum(1 for i in range(chains) if seen.get(f"l-{i}-1") and seen.get(f"l-{i}-2")
                and seen[f"l-{i}-1"].isdisjoint(seen[f"l-{i}-2"]))
    return {"alerts_traced": len(seen), "per_replica": per, "chains_split_across_replicas": split,
            "alerts_on_multiple_replicas": sum(len(v) > 1 for v in seen.values())}


def cmd_load(a):
    log = lambda *x: print(f"[{time.strftime('%H:%M:%S')}]", *x, flush=True)  # noqa: E731
    sh(COMPOSE + ["exec", "-T", "ws8a", "sh", "-c", "cat > /tmp/gen.py"], input=GEN)
    start = time.time()
    p = subprocess.Popen(COMPOSE + ["exec", "-T", "ws8a", "python", "/tmp/gen.py", str(a.chains), str(a.rate), "20"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    kills = []
    interval = a.kill_interval
    for k in range(a.kills):
        time.sleep(max(0, interval * (k + 1) - (time.time() - start)))
        old = master_ip()
        svc = IP_TO_SERVICE.get(old)
        dc("kill", svc)
        log(f"KILL {k + 1}/{a.kills}: master {old} ({svc})")
        new, took = wait_new_master(old)
        log(f"  new master {new} after {took}s")
        time.sleep(3)
        docker_start(svc)
        kills.append({"killed": svc, "new_master": new, "failover_s": took})
    p.wait(timeout=600)
    gen = json.loads(dc("exec", "-T", "ws8a", "cat", "/tmp/gen.json").stdout)
    log("producer:", gen)
    # redelivery of an unacked alert waits for claim_idle_ms (60 s): poll until the counts stop changing
    last, stable = None, 0
    t0 = time.time()
    while time.time() - t0 < a.drain_s:
        time.sleep(10)
        res = collect(a.chains)
        key = json.dumps([res["chains"], res["incident_emissions"], res["groups"]], sort_keys=True)
        stable = stable + 1 if key == last else 0
        last = key
        pend = sum(g["pending"] or 0 for g in res["groups"])
        log(f"  drain: ok={res['chains']['ok']}/{res['chains']['eligible']} pending={pend} emissions={res['incident_emissions']}")
        if stable >= 2 and pend == 0:
            break
    res["kills"] = kills
    res["replicas"] = replica_split(a.replicas.split(","), a.chains)
    res["producer"] = gen
    print("RESULT_JSON " + json.dumps(res))
    c = res["chains"]
    good = c["lost"] == 0 and c["forked"] == 0 and c["wrong_members"] == 0 and c["eligible"] > 0 and not gen["failed"]
    print(f"SUMMARY chains={a.chains} eligible={c['eligible']} ok={c['ok']} lost={c['lost']} forked_ids={c['forked']} "
          f"wrong_members={c['wrong_members']} bus_lost_alerts={c['bus_lost_alerts']} "
          f"duplicate_alert_msgs={res['duplicate_alert_messages']} incident_ids={res['incident_ids']} "
          f"emissions={res['incident_emissions']} kills={len(kills)} producer_failed={len(gen['failed'])} "
          f"replicas={res['replicas']} producer_s={gen['seconds']}")
    if a.expect_loss:
        print("RESULT load (informational, pre-change comparison)")
        return 0
    print("RESULT load: " + ("PASS" if good else "FAIL"))
    return 0 if good else 1


def alerts_group():
    r = exec_py("ws8a", "import json;from shared.window import redis_client_for_backend as c;r=c('redis-sentinel');"
                "print(json.dumps([{k:g.get(k) for k in ('name','pending','lag','entries-read')} for g in r.xinfo_groups('alerts')]))")
    return r.stdout.strip() or r.stderr[-200:]


def cmd_outage(a):
    log = lambda *x: print(f"[{time.strftime('%H:%M:%S')}]", *x, flush=True)  # noqa: E731
    send = ("import sys,time;from shared.bus import Bus;aid,tac=sys.argv[1:3];"
            "Bus().produce('alerts',key='dave',payload={'alert_id':aid,'tenant_id':'acme','time':int(time.time()*1000)-5000,"
            "'rule_id':'r','level':'high','score':10,'mitre':{'tactic':tac},'actor':{'user':{'name':'dave'}}})")
    incidents = ("import json;from shared.window import redis_client_for_backend as c;r=c('redis-sentinel');"
                 "[print(json.loads(f['payload'])['incident_id'],json.loads(f['payload'])['tactics'],"
                 "json.loads(f['payload'])['member_count']) for _i,f in r.xrange('incidents')"
                 " if 'dave' in json.loads(f['payload'])['incident_id']]")
    master = master_ip()
    log(f"master={master}; sending the first tactic and letting it complete")
    msvc = IP_TO_SERVICE[master]
    others = [v for v in IP_TO_SERVICE.values() if v != msvc]
    exec_py("ws8a", send, "o-1", "TA0006")
    time.sleep(4)
    log("stopping ws8a/ws8b so the second tactic sits unprocessed on the bus, then losing BOTH replicas")
    dc("stop", "ws8a", "ws8b")
    # produce from a throw-away container on the proof network (ws8a/ws8b are stopped)
    dc("run", "--rm", "-T", "--no-deps", "--entrypoint", "python", "ws8a", "-c", send, "o-2", "TA0008")
    dc("kill", *others)
    t0 = time.time()
    refused = None
    while time.time() - t0 < 60:
        r = dc("exec", "-T", msvc, "redis-cli", "-a", os.environ.get("REDIS_PASSWORD", "proofpw"),
               "--no-auth-warning", "set", "probe", "1")
        if "NOREPLICAS" in r.stdout + r.stderr:
            refused = round(time.time() - t0, 1)
            break
        time.sleep(1)
    log(f"master {msvc} refuses writes (NOREPLICAS) after {refused}s")
    docker_start("ws8a", "ws8b")
    log("ws8 restarted against a read-only master; observing 40 s")
    time.sleep(40)
    state = {s: sh(["docker", "inspect", "-f", "{{.State.Status}} restarts={{.RestartCount}} exit={{.State.ExitCode}}",
                    dc("ps", "-q", s).stdout.strip()]).stdout.strip() for s in ("ws8a", "ws8b")}
    log("ws8 containers during the outage:", state)
    # reading the group needs no write; do it straight from the master
    g = dc("exec", "-T", msvc, "redis-cli", "-a", os.environ.get("REDIS_PASSWORD", "proofpw"), "--no-auth-warning",
           "xinfo", "groups", "alerts").stdout.replace("\n", " ")
    log("alerts consumer group during outage:", g)
    during = dc("exec", "-T", msvc, "redis-cli", "-a", os.environ.get("REDIS_PASSWORD", "proofpw"),
                "--no-auth-warning", "xlen", "incidents").stdout.strip()
    errs = sh(COMPOSE + ["logs", "--no-log-prefix", "--since", "50s", "ws8a", "ws8b"]).stdout
    err_lines = [ln for ln in errs.splitlines() if '"level": "error"' in ln or "NOREPLICAS" in ln or "Traceback" in ln]
    log(f"ws8 error/warn lines during outage: {len(err_lines)}; sample: {(err_lines[:1] or [''])[0][:220]}")
    log(f"recovering: restart {others}")
    docker_start(*others)
    out = ""
    t0 = time.time()
    while time.time() - t0 < 180:
        time.sleep(10)
        out = exec_py("ws8a", incidents).stdout.strip()
        if out:
            break
    log(f"incident after recovery ({round(time.time() - t0)}s): {out!r}")
    time.sleep(5)
    log("alerts group after recovery:", alerts_group())
    state2 = {s: sh(["docker", "inspect", "-f", "{{.State.Status}} restarts={{.RestartCount}}",
                     dc("ps", "-q", s).stdout.strip()]).stdout.strip() for s in ("ws8a", "ws8b")}
    ids = {ln.split()[0] for ln in out.splitlines()}
    good = (refused is not None and len(ids) == 1 and out.endswith("2") and "TA0006" in out and "TA0008" in out
            and all("running" in v and "restarts=0" in v for v in state2.values()))
    print(f"SUMMARY master={msvc} refused_writes_after={refused}s ws8_during={state} incidents_stream_len_during={during} "
          f"error_lines_during={len(err_lines)} incident_after_recovery={out!r} ws8_after={state2}")
    print("RESULT outage: " + ("PASS" if good else "FAIL"))
    return 0 if good else 1


def rcli(svc, *args):
    r = dc("exec", "-T", svc, "redis-cli", "-a", os.environ.get("REDIS_PASSWORD", "proofpw"), "--no-auth-warning", *args)
    return (r.stdout + r.stderr).strip()


def cmd_promoted(a):
    """Every data node carries --min-replicas-to-write 1, so a PROMOTED replica must also go read-only when it
    loses all its replicas. Promote `a.promotions` times (killed node restarted and re-synced each time), then
    kill the new master's replicas and probe a write on the new master. Control: the same probe with
    min-replicas-to-write forced to 0 (what a node started without the flag would do) is accepted."""
    log = lambda *x: print(f"[{time.strftime('%H:%M:%S')}]", *x, flush=True)  # noqa: E731
    flags = {s: rcli(s, "config", "get", "min-replicas-to-write").split() for s in ("redis-1", "redis-2", "redis-3")}
    log("min-replicas-to-write per node:", flags)
    for n in range(a.promotions):
        old = master_ip()
        svc = IP_TO_SERVICE[old]
        dc("kill", svc)
        new, took = wait_new_master(old)
        log(f"promotion {n + 1}: killed {svc}, new master {new} ({IP_TO_SERVICE.get(new)}) after {took}s")
        docker_start(svc)
        t0 = time.time()
        while time.time() - t0 < 90 and "connected_slaves:2" not in rcli(IP_TO_SERVICE[new], "info", "replication"):
            time.sleep(2)
        log(f"  {svc} rejoined as replica after {round(time.time() - t0)}s")
    m = master_ip()
    msvc = IP_TO_SERVICE[m]
    ok_before = rcli(msvc, "set", "probe", "1")
    log(f"master {msvc} (promoted, original primary is redis-1) write with 2 replicas: {ok_before}")
    others = [v for v in IP_TO_SERVICE.values() if v != msvc]
    dc("kill", *others)
    t0 = time.time()
    refused = None
    while time.time() - t0 < 60:
        if "NOREPLICAS" in rcli(msvc, "set", "probe", "2"):
            refused = round(time.time() - t0, 1)
            break
        time.sleep(1)
    log(f"promoted master {msvc} refuses writes (NOREPLICAS) {refused}s after losing both replicas")
    rcli(msvc, "config", "set", "min-replicas-to-write", "0")
    control = rcli(msvc, "set", "probe", "3")
    rcli(msvc, "config", "set", "min-replicas-to-write", "1")
    log(f"control (flag forced to 0, = a node started without it): {control}")
    docker_start(*others)
    good = refused is not None and ok_before == "OK" and control == "OK" and all(v[-1] == "1" for v in flags.values())
    print(f"SUMMARY flags={flags} promotions={a.promotions} refused_after={refused}s control_without_flag={control}")
    print("RESULT promoted: " + ("PASS" if good else "FAIL"))
    return 0 if good else 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    ld = sub.add_parser("load")
    ld.add_argument("--chains", type=int, default=350)
    ld.add_argument("--kills", type=int, default=4)
    ld.add_argument("--rate", type=float, default=10.0, help="alerts per second")
    ld.add_argument("--kill-interval", type=float, default=15.0)
    ld.add_argument("--drain-s", type=int, default=240)
    ld.add_argument("--replicas", default="ws8a,ws8b", help="ws8 services to read traces from")
    ld.add_argument("--expect-loss", action="store_true")
    sub.add_parser("outage")
    pr = sub.add_parser("promoted")
    pr.add_argument("--promotions", type=int, default=2)
    a = ap.parse_args()
    os.environ.setdefault("COMPOSE_PROJECT_NAME", "ws8sentproof")
    os.environ.setdefault("REDIS_PASSWORD", "proofpw")
    return {"load": cmd_load, "outage": cmd_outage, "promoted": cmd_promoted}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
