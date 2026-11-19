"""ADR-012 WP 5: make_alert() carries `causal_keys` from the TRIGGER event only.

Run: python services/ws4-detection/test_causal_keys_alert.py
"""
from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"
os.environ.pop("FENGARDE_WS1_DIRECT", None)

import main as ws4  # noqa: E402
from shared import causal_keys as ck  # noqa: E402

FAILS: list[str] = []
GUID_A = "11111111-2222-3333-4444-555555555555"
GUID_P = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def op(extra=None, siem_extra=None):
    ev = {
        "class_uid": 6005, "category_uid": 6, "activity_id": 5, "type_uid": 600505,
        "severity_id": 4, "time": 1750000000000, "status": "Success",
        "actor": {"user": {"name": "dba1"}},
        "dst_endpoint": {"hostname": "ora-core-01"},
        "siem": {"sector": "bank", "source_type": "oracle_db", "ingest_id": "bank-1", "tenant": "t1"},
    }
    if extra:
        ev["actor"].update(extra.get("actor", {}))
        for k, v in extra.items():
            if k != "actor":
                ev[k] = v
    if siem_extra:
        ev["siem"].update(siem_extra)
    return ev


def alert_for(ev):
    det = ws4.Detector()
    ev, matched, _ = det.process(ev)
    check(bool(matched), "bank_priv_op must match a rule")
    return ws4.make_alert(ev, matched[0], ev["siem"].get("score", 0))


def keyed():
    return op(
        {"actor": {"process": {"uid": GUID_A, "parent_process": {"uid": GUID_P}},
                   "session": {"uid": "3e7"}},
         "connection_info": {"uid": "98765"}},
        {"key_scope": {"host": "WS01", "sensor": "sensor-1"}, "sender": {"ip": "10.1.2.3"}},
    )


def run():
    # keyless: field absent
    a = alert_for(op())
    check("causal_keys" not in a, "keyless event: causal_keys must be absent")
    base_id = a["alert_id"]

    # keyed, flag off
    a = alert_for(keyed())
    ks = a.get("causal_keys") or []
    check(len(ks) == 4, f"expected 4 keys, got {ks!r}")
    check(all(set(k) == {"ns", "role", "h", "scope_trust"} for k in ks), "key shape ns/role/h/scope_trust")
    check({(k["ns"], k["role"]) for k in ks} ==
          {("proc", "self"), ("proc", "parent"), ("logon", "self"), ("flow", "self")}, "ns/role set")
    check(all(k["scope_trust"] == "asserted" for k in ks), "flag off: asserted")
    want = ck.key_hash("t1", "proc", "", "WS01", GUID_A)
    check(any(k["ns"] == "proc" and k["role"] == "self" and k["h"] == want for k in ks),
          "flag off: proc hash excludes sender, scoped to host")
    flow = [k for k in ks if k["ns"] == "flow"]
    check(bool(flow) and flow[0]["h"] == ck.key_hash("t1", "flow", "", '["sensor-1","WS01"]', "98765"),
          "flow scoped to sensor")
    off_hashes = [k["h"] for k in ks]

    # alert_id unchanged by keys; redelivery stable
    check(a["alert_id"] == base_id, "alert_id unchanged by causal keys")
    check(alert_for(keyed())["causal_keys"] == ks, "redelivery: identical causal_keys")

    # flag on
    os.environ["FENGARDE_WS1_DIRECT"] = "1"
    try:
        a2 = alert_for(keyed())
        ks2 = a2["causal_keys"]
        check(all(k["scope_trust"] == "observed" for k in ks2), "flag on: observed")
        check(ks2[0]["h"] != off_hashes[0], "flag on: sender included in hash")
        check(any(k["h"] == ck.key_hash("t1", "proc", "10.1.2.3", "WS01", GUID_A) for k in ks2),
              "flag on: hash matches helper with sender ip")
        check(a2["alert_id"] == base_id, "flag on: alert_id unchanged")
        other = keyed()
        other["siem"]["sender"] = {"ip": "10.9.9.9"}
        check(alert_for(other)["causal_keys"][0]["h"] != ks2[0]["h"], "different sender -> different key")
        nos = keyed()
        del nos["siem"]["sender"]
        check(all(k["scope_trust"] == "asserted" for k in alert_for(nos)["causal_keys"]),
              "flag on but no sender: asserted")
    finally:
        os.environ.pop("FENGARDE_WS1_DIRECT", None)

    # no scope -> no key (fail closed)
    ev = keyed()
    del ev["siem"]["key_scope"]
    check("causal_keys" not in alert_for(ev), "no key_scope: no keys")

    # flow without host: scope falls back to sender ip, then source, else no key
    def flow_ev(sender):
        e = op({"connection_info": {"uid": "555"}}, {"key_scope": {"sensor": "suricata"}})
        if sender:
            e["siem"]["sender"] = sender
        return e

    def fh(e):
        return [k["h"] for k in (alert_for(e).get("causal_keys") or []) if k["ns"] == "flow"]

    h1, h2 = fh(flow_ev({"ip": "10.0.0.1"})), fh(flow_ev({"ip": "10.0.0.2"}))
    check(len(h1) == 1 and len(h2) == 1 and h1 != h2, "same flow_id, no host, different senders -> different hashes")
    sa, sb = fh(flow_ev({"source": "a"})), fh(flow_ev({"source": "b"}))
    check(len(sa) == 1 and len(sb) == 1 and sa != sb, "sender.source fallback")
    check(fh(flow_ev(None)) == [], "same flow_id, no host, no sender -> no flow key")

    # agent session: declared
    ag = op({"unmapped": {"mcp": {"session_id": "sess-1"}}}, {"key_scope": {"host": "agent-rt"}})
    k = alert_for(ag).get("causal_keys") or []
    check(len(k) == 1 and k[0]["ns"] == "agent" and k[0]["scope_trust"] == "declared", f"agent declared: {k!r}")

    # size bound: 7 candidates -> 6
    import causal_alert
    check(causal_alert.MAX_KEYS == 6, "MAX_KEYS is 6")
    orig = causal_alert._candidates
    try:
        causal_alert._candidates = lambda ev: [("proc", "self", GUID_A[:-1] + str(i), "WS01") for i in range(7)]
        out = causal_alert.build_causal_keys(keyed())
        check(len(out) == 6, f"7 candidates must cap at 6, got {len(out)}")
    finally:
        causal_alert._candidates = orig

    # event not mutated; JSON-serialisable
    ev = keyed()
    snap = copy.deepcopy(ev)
    causal_alert.build_causal_keys(ev)
    check(ev == snap, "event not mutated")
    json.dumps(alert_for(keyed()))


run()
if FAILS:
    print("[FAIL] causal keys alert tests:")
    for f in FAILS:
        print("  -", f)
    sys.exit(1)
print("[OK] ws4 causal_keys alert tests PASS")
