"""common_refused_connection_scan: Zeek conn_state S0/REJ bursts from one source fire; near-misses stay silent.

Loads the REAL rule YAML and feeds it events produced by the REAL zeek_json parser (rows shaped like the real Zeek
conn.log record in parsers/test_fixtures/zeek_json_real.json, with conn_state/history/packet counts changed to the
states a scan produces). zeek_json never maps S0/REJ to Deny (owner decision 2026-11-13), so the Deny-keyed
common_port_scan* / common_port_sweep rules are also asserted to stay silent on the same burst: this rule is the only
one that sees it. Zero infra (in-process window).

Run: python services/ws4-detection/test_refused_connection_scan.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "services" / "ws2-normalization"))

from engine import load_rules  # noqa: E402
from parsers.zeek_json import ZeekJsonParser  # noqa: E402

RULES_DIR = ROOT / "contracts" / "rules"
FIXTURE = ROOT / "services" / "ws2-normalization" / "parsers" / "test_fixtures" / "zeek_json_real.json"
RULE_ID = "7b3e9d51-4c2a-4f86-a1d0-5e8c2b6f9a14"
DENY_RULE_FILES = ("common_port_scan.yml", "common_port_scan_by_target.yml", "common_port_sweep.yml")
FAILS: list[str] = []
ZEEK = ZeekJsonParser()
T0 = 1_750_000_000.0

# Packet shape per conn_state, as Zeek writes them for a scan probe.
STATES = {
    "S0": {"history": "S", "orig_pkts": 1, "resp_pkts": 0},
    "REJ": {"history": "Sr", "orig_pkts": 1, "resp_pkts": 1},
    "S1": {"history": "Sh", "orig_pkts": 2, "resp_pkts": 1},
    "SF": {"history": "ShADadfF", "orig_pkts": 6, "resp_pkts": 6},
}


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def real_tcp_conn() -> dict:
    items = json.loads(FIXTURE.read_text(encoding="utf-8"))["records"]
    return next(i["record"] for i in items if i["log"] == "conn.log" and i["record"].get("proto") == "tcp")


def conn_event(base: dict, src: str, dport: int, state: str, n: int, dst: str = "10.0.0.8"):
    rec = dict(base)
    rec.update({"ts": T0 + n * 0.1, "uid": f"C{state}{n}x", "id.orig_h": src, "id.orig_p": 40000 + n,
                "id.resp_h": dst, "id.resp_p": dport, "conn_state": state, "duration": 0.0, **STATES[state]})
    for k in ("service", "orig_bytes", "resp_bytes"):
        rec.pop(k, None)
    ev = ZEEK.parse({"source_type": "zeek_json", "raw": rec, "meta": {"ingest_id": f"z-{src}-{state}-{n}"}})
    assert ev is not None, "zeek_json parser dropped the conn row"
    return ev


def fresh_rule():
    for r in load_rules(RULES_DIR):
        if r.id == RULE_ID:
            return r
    raise AssertionError(f"rule {RULE_ID} not loaded (contracts/rules/common_refused_connection_scan.yml missing?)")


def burst(rule, base, src, states, ports):
    return [rule.evaluate(conn_event(base, src, p, states[i % len(states)], i)) for i, p in enumerate(ports)]


def run():
    base = real_tcp_conn()
    rule = fresh_rule()
    check(rule.stateful and rule.distinct_field == "dst_endpoint.port" and rule.group_by == "src_endpoint.ip",
          "rule should be stateful, grouped by src_endpoint.ip, distinct on dst_endpoint.port")

    # Parser contract this rule depends on: Close event, raw state kept, never Deny.
    ev = conn_event(base, "203.0.113.9", 1000, "REJ", 0)
    check((ev["class_uid"], ev["activity_id"]) == (4001, 2), "zeek conn must stay 4001/2")
    check(ev["unmapped"]["zeek"]["conn"]["conn_state"] == "REJ", "raw conn_state must be exposed to the rule")

    # FIRES: 15 distinct ports, a mix of S0 and REJ from one source -> exactly the 15th probe fires.
    f = burst(fresh_rule(), base, "203.0.113.9", ["S0", "REJ"], range(1000, 1015))
    check(f[:14] == [False] * 14 and f[14] is True, "S0/REJ mix over 15 distinct ports: 15th MUST fire, first 14 must not")
    # each state alone is enough
    for st in ("S0", "REJ"):
        f = burst(fresh_rule(), base, "203.0.113.10", [st], range(2000, 2015))
        check(f[14] is True, f"15 distinct ports all {st}: MUST fire")

    # NEAR-MISSES stay silent.
    check(not any(burst(fresh_rule(), base, "203.0.113.11", ["S0", "REJ"], range(3000, 3014))),
          "14 distinct ports (below threshold) must NOT fire")
    for st in ("S1", "SF"):
        check(not any(burst(fresh_rule(), base, "203.0.113.12", [st], range(4000, 4020))),
              f"20 distinct ports with conn_state {st} (connection completed/answered) must NOT fire")
    check(not any(burst(fresh_rule(), base, "203.0.113.13", ["S0"], [22] * 30)),
          "30 refused connections to ONE port must NOT fire (distinct ports, not a plain count)")
    # 14 refused + a stream of completed connections to new ports: SF rows must not top the count up to 15.
    r = fresh_rule()
    mixed = [r.evaluate(conn_event(base, "203.0.113.14", 5000 + i, "S0", i)) for i in range(14)]
    mixed += [r.evaluate(conn_event(base, "203.0.113.14", 5100 + i, "SF", 14 + i)) for i in range(10)]
    check(not any(mixed), "14 refused + 10 completed distinct ports must NOT fire")

    # The Deny-keyed scan rules do not see this burst at all (owner decision: S0/REJ are not Deny).
    deny_rules = [x for x in load_rules(RULES_DIR) if x.id != RULE_ID and x.distinct_field in ("dst_endpoint.port", "dst_endpoint.ip")]
    check(len(deny_rules) >= 3, "expected the three deny-counting scan rules to be loaded")
    for dr in deny_rules:
        check(not any(dr.evaluate(conn_event(base, "203.0.113.15", 6000 + i, "REJ", i, dst=f"10.0.1.{i}")) for i in range(20)),
              f"{dr.title}: must stay silent on Zeek-only REJ data")


def main():
    run()
    if FAILS:
        print(f"[FAIL] common_refused_connection_scan: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] common_refused_connection_scan fires on REAL zeek_json S0/REJ bursts and stays silent on near-misses")


if __name__ == "__main__":
    main()
