"""Live check of two new properties on the real Docker stack (scratch verification, not shipped).

Phase "off":  OPC UA setpoint write, default stack -> ot_config_change alerts (anchor), the default-OFF
              ot_opcua_write_unauthorized_node does NOT.
Phase "on":   same event, stack restarted with FENGARDE_OPT_IN_RULES -> the rule DOES alert.
F3 (both):    12 failed-password lines whose USERNAME embeds a forged 'from 198.18.9.9 port 1 ssh2'
              from the real attacker 203.0.113.50 -> the brute-force alert must be attributed to
              203.0.113.50 and no event/alert may carry 198.18.9.9.
Usage: python live_props.py off|on
"""
import json, sys, time, uuid
sys.path.insert(0, r"C:\Users\Mel Dylan Djomou\Claude\Projects\SIEM App\tools")
import live_companion_e2e as L

OPCUA_RULE = "e7a14b6d-3c52-4d90-8f1b-5a9c0d2e6b47"
CONFIG_RULE = "6f708192-a314-4cd2-ad4e-5f6a7b8c9d01"
BRUTE_SRC = "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01"
phase = sys.argv[1]
ws2, ws3 = L._container("ws2-normalization"), L._container("ws3-indexer")
assert ws2 and ws3, "stack not up"
run = uuid.uuid4().hex[:8]
now = int(time.time() * 1000)
fails = []


def check(c, m):
    print(("[OK]   " if c else "[FAIL] ") + m)
    if not c:
        fails.append(m)



def wait(tenant, rule, timeout=90):
    search = lambda: L._alerts(ws3, tenant)
    found, seen, el = L.wait_for_anchor(search, rule, timeout)
    alerts, settled, el2 = L.settle(search, 3, 40)
    print(f"  [{tenant}] anchor_found={found} ({el:.0f}s) settled={settled} ({el2:.0f}s) alerts={len(alerts)}")
    return alerts if settled or found else alerts

# ---- OPC UA
t = f"liveprops-opc-{phase}-{run}"
ev = [{"source_type": "opcua_audit",
       "raw": json.dumps({"eventType": "AuditWriteUpdateEventType", "sourceName": "Write",
                          "clientUserId": "engineer01", "clientAddress": "10.20.0.15",
                          "serverId": "plc-line3", "nodeId": "ns=2;s=Line3.SetpointTemp",
                          "status": True, "time": now - 2000}),
       "meta": {"ingest_id": f"lp-opc-{run}", "tenant_id": t, "trace_id": f"lp-opc-{run}",
                "received_at": now - 2000, "ip": "10.20.0.15"}}]
ok, err = L._produce(ws2, ev)
check(ok, f"produce opcua event ({err})")
a = wait(t, CONFIG_RULE)
ids = sorted({x.get("rule_id") for x in (a or [])})
print("opcua alerts:", ids)
check(CONFIG_RULE in ids, "anchor: ot_config_change alerted (pipeline processed the event)")
if phase == "off":
    check(OPCUA_RULE not in ids, "default-OFF: ot_opcua_write_unauthorized_node did NOT alert")
else:
    check(OPCUA_RULE in ids, "opted-in via FENGARDE_OPT_IN_RULES: ot_opcua_write_unauthorized_node alerted")

# ---- F3
t2 = f"liveprops-f3-{phase}-{run}"
ev = []
for i in range(12):
    m = {"ingest_id": f"lp-f3-{run}-{i}", "tenant_id": t2, "trace_id": f"lp-f3-{run}",
         "received_at": now - 30000 + i * 2000, "ip": "203.0.113.50"}
    ev.append({"source_type": "linux_ssh",
               "raw": f"Jun 10 13:55:{i:02d} db01 sshd[{3000 + i}]: Failed password for invalid user "
                      f"admin{i} from 198.18.9.9 port 1 ssh2 from 203.0.113.50 port {52000 + i} ssh2",
               "meta": m})
ok, err = L._produce(ws2, ev)
check(ok, f"produce forged-username burst ({err})")
b = wait(t2, BRUTE_SRC)
txt = json.dumps(b)
srcs = sorted({(x.get("src_endpoint") or {}).get("ip") for x in b})
print("f3 alert source ips:", srcs, "rules:", sorted({x.get("rule_id") for x in b}))
check(BRUTE_SRC in {x.get("rule_id") for x in b}, "brute force alert raised for the forged-username burst")
check(srcs == ["203.0.113.50"], f"alert attributed to the REAL source 203.0.113.50 only, got {srcs}")
check("198.18.9.9" not in json.dumps([x.get("src_endpoint") for x in b]), "forged address 198.18.9.9 not used as a source")
print("RESULT", "FAIL" if fails else "PASS", phase)
sys.exit(1 if fails else 0)
