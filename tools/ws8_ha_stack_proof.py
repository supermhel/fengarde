"""One attack chain through the FULL docker-compose.ha.yml stack (ws1..ws9 + Redis primary/replicas/Sentinels +
3-node OpenSearch), ws8 killed between the two tactics, incident read back from OpenSearch.

  raw.events (WS-2 input) -> normalized.events -> WS-4 alerts (port scan TA0007, then ssh brute force TA0006,
  same source IP) -> WS-8 ip track -> incidents -> WS-3 -> OpenSearch incidents-<tenant>

Stack bring-up is in infra/docker-compose.ws8-ha-proof.yml's header. Run:
  COMPOSE_PROJECT_NAME=ws8haproof REDIS_PASSWORD=proofpw python tools/ws8_ha_stack_proof.py
Exit 1 on failure.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid

PROJ = os.environ.setdefault("COMPOSE_PROJECT_NAME", "ws8haproof")
os.environ.setdefault("REDIS_PASSWORD", "proofpw")
SRC_IP = "203.0.113.9"


def sh(*args, **kw):
    return subprocess.run(list(args), capture_output=True, text=True, **kw)


def cname(svc):
    return f"{PROJ}-{svc}-1"


def log(*a):
    print(f"[{time.strftime('%H:%M:%S')}]", *a, flush=True)


def produce(events):
    code = ("import json,sys;from shared.bus import Bus;b=Bus();evs=json.loads(sys.stdin.read());"
            "[b.produce('raw.events',key=e['meta'].get('ip'),payload=e) for e in evs];print('ok',len(evs))")
    r = subprocess.run(["docker", "exec", "-i", cname("ws2-normalization"), "python", "-c", code],
                       input=json.dumps(events), capture_output=True, text=True, timeout=120)
    assert r.returncode == 0 and "ok" in r.stdout, r.stderr[-300:]


def search(index, tenant):
    q = {"size": 100, "query": {"term": {"tenant_id": tenant}}}
    code = ("import json,os,urllib.request as u;urls=os.environ['OPENSEARCH_URL'].split(',');"
            f"body=json.dumps({q!r}).encode();last=None\n"
            "for url in urls:\n"
            "  try:\n"
            f"    req=u.Request(url+'/{index}/_search',data=body,headers={{'Content-Type':'application/json'}},method='POST')\n"
            "    print(u.urlopen(req,timeout=10).read().decode());break\n"
            "  except Exception as e: last=e\n"
            "else: raise last")
    r = sh("docker", "exec", cname("ws3-indexer"), "python", "-c", code)
    if r.returncode != 0:
        return []
    return [h["_source"] for h in json.loads(r.stdout).get("hits", {}).get("hits", [])]


def wait(fn, what, timeout_s=150, every=3):
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        v = fn()
        if v:
            log(f"{what} after {round(time.time() - t0)}s")
            return v
        time.sleep(every)
    return None


def main():
    health = sh("docker", "exec", cname("ws3-indexer"), "python", "-c",
                "import os,urllib.request as u;print(u.urlopen(os.environ['OPENSEARCH_URL'].split(',')[0]+"
                "'/_cluster/health',timeout=10).read().decode())")
    if health.returncode != 0:
        print("[SKIP] stack not up:", health.stderr[-200:])
        return 1
    h = json.loads(health.stdout)
    log(f"OpenSearch cluster: status={h['status']} nodes={h['number_of_nodes']}")
    s = sh("docker", "exec", "siem-sentinel-ha-1", "redis-cli", "-p", "26379", "sentinel", "get-master-addr-by-name", "mymaster")
    log("Redis master via Sentinel:", s.stdout.split()[0] if s.stdout.split() else s.stderr[-100:])
    ws8_log = sh("docker", "logs", cname("ws8-correlation")).stdout
    startup = [ln for ln in ws8_log.splitlines() if "window counter selected" in ln]
    log("ws8 startup:", startup[-1][-140:] if startup else "(no startup line)")
    for svc in ("ws1-collectors", "ws2-normalization", "ws3-indexer", "ws4-detection", "ws5-ai", "ws6-inventory",
                "ws7-dashboard", "ws8-correlation", "ws9-resolver"):
        st = sh("docker", "inspect", "-f", "{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{else}}-{{end}}", cname(svc)).stdout.strip()
        log(f"  {svc}: {st}")

    tenant = f"ws8ha-{uuid.uuid4().hex[:8]}"
    now = int(time.time() * 1000)

    def env(i, tag, t):
        return {"ingest_id": f"ha-{tag}-{i}", "tenant_id": tenant, "trace_id": f"ha-{tag}", "received_at": t, "ip": SRC_IP}

    scan = [{"source_type": "cisco_asa",
             "raw": f"%ASA-4-106023: Deny tcp src outside:{SRC_IP}/{40000 + i} dst inside:10.0.0.10/{20 + i * 7} by access-group acl_out",
             "meta": env(i, "scan", now - 45_000 + i * 2_000)} for i in range(20)]
    brute = [{"source_type": "linux_ssh",
              "raw": f"Jun 10 13:55:{i:02d} db01 sshd[{2000 + i}]: Failed password for deploy from {SRC_IP} port {51000 + i} ssh2",
              "meta": env(i, "ssh", now - 30_000 + i * 2_000)} for i in range(12)]

    log(f"tenant {tenant}: tactic 1 = port scan (20 denied ports from {SRC_IP})")
    produce(scan)
    a1 = wait(lambda: [a for a in search("alerts-*", tenant) if (a.get("mitre") or {}).get("tactic") == "TA0007"],
              "port-scan alert indexed")
    if not a1:
        print("RESULT full HA stack: FAIL (no port-scan alert reached OpenSearch)")
        return 1
    log("alert:", {k: a1[0].get(k) for k in ("alert_id", "rule_id", "mitre")})
    inc_before = search("incidents-*", tenant)
    log(f"incident docs after tactic 1: {len(inc_before)} (a single tactic must not promote)")

    log("killing ws8-correlation between the two tactics")
    sh("docker", "kill", cname("ws8-correlation"))
    for _ in range(40):
        st = sh("docker", "inspect", "-f", "{{.State.Status}}", cname("ws8-correlation")).stdout.strip()
        if st == "running":
            break
        time.sleep(1)
    else:
        sh("docker", "start", cname("ws8-correlation"))
    time.sleep(8)
    log("ws8 state:", sh("docker", "inspect", "-f", "{{.State.Status}} restarts={{.RestartCount}}", cname("ws8-correlation")).stdout.strip())

    log(f"tactic 2 = ssh brute force (12 failures from {SRC_IP})")
    produce(brute)
    incs = wait(lambda: [i for i in search("incidents-*", tenant) if i.get("entity_type") == "ip"], "ip incident indexed")
    alerts = search("alerts-*", tenant)
    log("alerts indexed:", sorted((a.get("rule_id"), (a.get("mitre") or {}).get("tactic")) for a in alerts))
    if not incs:
        print("RESULT full HA stack: FAIL (no incident reached OpenSearch)")
        return 1
    ids = {i["incident_id"] for i in incs}
    inc = incs[0]
    log("incident doc(s):", [{k: i.get(k) for k in ("incident_id", "entity_type", "entity_value", "tactics", "member_count")} for i in incs])
    alert_ids = {a["alert_id"] for a in alerts}
    members_indexed = set(inc.get("member_alert_ids") or []) <= alert_ids
    good = (len(ids) == 1 and len(incs) == 1 and inc["tactics"] == ["TA0006", "TA0007"] and inc["entity_value"] == SRC_IP
            and members_indexed and inc["member_count"] == len(inc["member_alert_ids"]) >= 2)
    print(f"SUMMARY incident_ids={len(ids)} incident_docs={len(incs)} tactics={inc['tactics']} members={inc['member_count']} "
          f"members_are_indexed_alerts={members_indexed} cluster={h['status']}/{h['number_of_nodes']}nodes")
    print("RESULT full HA stack: " + ("PASS" if good else "FAIL"))
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
