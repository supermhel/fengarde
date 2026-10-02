"""Live end-to-end proof of the companion rules, against the real Docker stack.

The unit tests (services/ws4-detection/test_companion_rules.py) prove each
companion fires on the split attack its sibling cannot see, using real parsers and
the real engine in one process. They cannot prove that the DEPLOYED stack does the
same: that the rules shipped in the ws4 image, that Redis Streams deliver the
events, that WS-2 -> WS-4 -> WS-3 index the alert, and that the sibling-suppression
and tenant plumbing behave on real infrastructure. This script does, using the
same drive-it-from-inside-a-container pattern as tools/ot_new_device_e2e.py.

Three scenarios, each in its own throw-away tenant:

  A. SPLIT brute force (12 failures for ONE account over TWO source addresses):
     the account-keyed companion alerts; the source-keyed sibling does NOT
     (this is the evasion the harness measured, now proven closed live).
  B. PLAIN brute force (12 failures, ONE address, ONE account): the sibling
     alerts and the companion is SUPPRESSED -- an ordinary attack must not raise
     two alerts.
  C. SPLIT port scan (20 distinct denied ports on one target from TWO sources):
     the target-keyed companion alerts; the source-keyed sibling does not.

Live-only by design (needs `docker compose -f infra/docker-compose.yml up -d`).
Without a reachable stack it prints an explicit [SKIP] and exits 0, unless
FENGARDE_E2E_STRICT=1, where a skip is a failure.

Run: python tools/live_companion_e2e.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid

SIBLING_BRUTE = "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01"
COMPANION_BRUTE = "d83b71c3-93eb-439f-86f9-5985ebcc38cb"
SIBLING_SCAN = "1d2c3b4a-5e6f-4708-8a91-0b1c2d3e4f05"
COMPANION_SCAN = "aaa9dc23-8550-41ae-acbc-0ae50837d8d6"
_SETTLE_S = 45
_STRICT = os.getenv("FENGARDE_E2E_STRICT", "").strip().lower() in ("1", "true", "yes")
FAILS: list = []


def sh(*args, timeout=120):
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _skip(msg):
    print(f"{'[FAIL: unexpected skip]' if _STRICT else '[SKIP]'} companion live e2e: {msg}")
    return 1 if _STRICT else 0


def _container(service):
    out = sh("docker", "compose", "-f", "infra/docker-compose.yml", "ps", "--format",
             "{{.Name}}", service).stdout.strip()
    return out.splitlines()[-1] if out else None


def _produce(container, events):
    code = (
        "import json,sys;from shared.bus import Bus;b=Bus();"
        "evs=json.loads(sys.stdin.read());"
        "[b.produce('raw.events',key=e['meta'].get('ip'),payload=e) for e in evs];"
        "print('ok',len(evs))"
    )
    r = subprocess.run(["docker", "exec", "-i", container, "python", "-c", code],
                       input=json.dumps(events), capture_output=True, text=True, timeout=120)
    return r.returncode == 0 and "ok" in r.stdout, (r.stderr or r.stdout)[:300]


def _alerts(container, tenant):
    q = {"size": 100, "query": {"term": {"tenant_id": tenant}}}
    search = (
        "import json,os,urllib.request;"
        "url=os.environ.get('OPENSEARCH_URL','http://opensearch:9200').split(',')[0];"
        f"body=json.dumps({q!r}).encode();"
        "req=urllib.request.Request(url+'/alerts-*/_search',data=body,"
        "headers={'Content-Type':'application/json'},method='POST');"
        "print(urllib.request.urlopen(req,timeout=10).read().decode())"
    )
    r = sh("docker", "exec", container, "python", "-c", search)
    if r.returncode != 0:
        return None
    try:
        return [h["_source"] for h in json.loads(r.stdout).get("hits", {}).get("hits", [])]
    except ValueError:
        return None


def _wait_for(container, tenant, want_rule):
    deadline = time.time() + _SETTLE_S
    got = []
    while time.time() < deadline:
        a = _alerts(container, tenant)
        if a is not None:
            got = a
            if any(x.get("rule_id") == want_rule for x in got):
                time.sleep(4)             # let any (wrongly) co-emitted second alert land too
                return _alerts(container, tenant) or got
        time.sleep(3)
    return got


def _env(tenant, i, t_ms, tag):
    return {"ingest_id": f"live-{tag}-{i}", "tenant_id": tenant, "trace_id": f"live-{tag}",
            "received_at": t_ms}


def main():
    if sh("docker", "version", "--format", "{{.Server.Version}}").returncode != 0:
        return _skip("docker engine not reachable")
    ws2, ws3 = _container("ws2-normalization"), _container("ws3-indexer")
    if not ws2 or not ws3:
        return _skip("stack not up (ws2-normalization / ws3-indexer containers not found)")

    run = uuid.uuid4().hex[:8]
    now = int(time.time() * 1000)

    # --- A: split brute force ------------------------------------------------
    ta = f"livecomp-a-{run}"
    ips = ["203.0.113.21", "192.0.2.44"]
    ev = []
    for i in range(12):
        t = now - 40_000 + i * 3_000
        m = _env(ta, i, t, "a")
        m["ip"] = ips[i % 2]
        ev.append({"source_type": "linux_ssh",
                   "raw": f"Jun 10 13:55:{i:02d} db01 sshd[{2000 + i}]: Failed password for deploy "
                          f"from {ips[i % 2]} port {51000 + i} ssh2", "meta": m})
    ok, err = _produce(ws2, ev)
    if not ok:
        return _skip(f"could not produce to raw.events: {err}")
    a = _wait_for(ws3, ta, COMPANION_BRUTE)
    rules = [x.get("rule_id") for x in a]
    print(f"[live A] split brute force -> alert rule ids: {sorted(set(rules))}")
    check(COMPANION_BRUTE in rules, "A: the account-keyed companion must alert on a brute force split over two addresses")
    check(SIBLING_BRUTE not in rules, "A: the source-keyed sibling must NOT alert (each address is under its threshold) "
                                      "-- otherwise this scenario does not exercise the gap")

    # --- B: plain brute force -> sibling only ---------------------------------
    tb = f"livecomp-b-{run}"
    ev = []
    for i in range(12):
        t = now - 40_000 + i * 3_000
        m = _env(tb, i, t, "b")
        m["ip"] = "203.0.113.77"
        ev.append({"source_type": "linux_ssh",
                   "raw": f"Jun 10 13:55:{i:02d} db01 sshd[{2100 + i}]: Failed password for deploy "
                          f"from 203.0.113.77 port {52000 + i} ssh2", "meta": m})
    ok, err = _produce(ws2, ev)
    check(ok, f"B: produce failed: {err}")
    b = _wait_for(ws3, tb, SIBLING_BRUTE)
    rules = [x.get("rule_id") for x in b]
    print(f"[live B] plain brute force -> alert rule ids: {sorted(set(rules))}")
    check(SIBLING_BRUTE in rules, "B: an ordinary brute force must alert via the sibling")
    check(COMPANION_BRUTE not in rules, "B: the companion must be SUPPRESSED when its sibling already alerted "
                                        "(one attack, one alert)")

    # --- C: split port scan -----------------------------------------------------
    tc = f"livecomp-c-{run}"
    ev = []
    for i in range(20):
        t = now - 45_000 + i * 2_000
        src = ips[i % 2]
        m = _env(tc, i, t, "c")
        m["ip"] = src
        ev.append({"source_type": "cisco_asa",
                   "raw": f"%ASA-4-106023: Deny tcp src outside:{src}/{40000 + i} "
                          f"dst inside:10.0.0.10/{20 + i * 7} by access-group acl_out", "meta": m})
    ok, err = _produce(ws2, ev)
    check(ok, f"C: produce failed: {err}")
    c = _wait_for(ws3, tc, COMPANION_SCAN)
    rules = [x.get("rule_id") for x in c]
    print(f"[live C] split port scan -> alert rule ids: {sorted(set(rules))}")
    check(COMPANION_SCAN in rules, "C: the target-keyed companion must alert on a scan split over two sources")
    check(SIBLING_SCAN not in rules, "C: the source-keyed sibling must NOT alert (each source is under its threshold)")

    if FAILS:
        print(f"\n[FAIL] companion live e2e: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        return 1
    print("\n[OK] companion live e2e PASS -- on the real Redis/WS-2/WS-4/WS-3/OpenSearch stack: "
          "split attacks alert via the companion only, an ordinary attack alerts once via the sibling.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
