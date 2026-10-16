"""WS-8: an IT brute force followed by an OT write is ONE incident when the same entity does both.

Zero infra, real code on every hop: raw SSH + raw Modbus frames -> WS-2 parsers -> WS-4 rules -> WS-8 correlator.

Proven here:
  * same source IP brute-forces SSH (TA0006) and then writes a Modbus register outside the expected range
    (ATT&CK-ICS TA0106) -> an ip: incident carrying both tactics. This is the flat-network case: the attacker
    reaches the plant floor from where they started.
  * negative control and documented limit: the OT write comes from a DIFFERENT address. No incident. A pivot
    (brute force a jump host, then write from the jump host) would need a "compromise succeeded" signal the
    pipeline does not produce, and linking a brute-force victim to any later actor would be a guess, so the
    correlator deliberately does not do it. See SSOT.md.

Run: python services/ws8-correlation/test_it_ot_chain.py
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

SERVICES = Path(__file__).resolve().parents[1]
os.environ["BUS_BACKEND"] = "memory"
sys.path.insert(0, str(SERVICES))
from shared.bus import Bus  # noqa: E402

BASE = 1750000000
ATTACKER = "203.0.113.50"
OT_HOST = "10.20.0.50"


def _import(ws, mod="main"):
    p = str(SERVICES / ws)
    while p in sys.path:
        sys.path.remove(p)
    sys.path.insert(0, p)
    return importlib.import_module(mod)


def _fresh(*mods):
    for m in mods:
        sys.modules.pop(m, None)


def _ssh(ip, i):
    return {"source_type": "linux_ssh",
            "raw": f"Jun 10 13:55:{i:02d} jump01 sshd[2154]: Failed password for invalid user admin from {ip} port 51000 ssh2",
            "meta": {"received_at": BASE + i, "ingest_id": f"ssh-{ip}-{i}"}}


def _modbus_write(src, t_s):
    # address 40500 is outside modbus_anomaly._EXPECTED_WRITE_ADDRESSES (40001..40009)
    return {"source_type": "modbus_anomaly",
            "raw": {"unitId": 1, "functionCode": 6, "address": 40500, "value": 500,
                    "sourceIp": src, "destIp": "10.20.0.5", "time": (BASE + t_s) * 1000},
            "meta": {"received_at": BASE + t_s, "ingest_id": f"mb-{src}-{t_s}"}}


def _run(bf_ip, write_ip):
    bus = Bus()
    for i in range(10):
        bus.produce("raw.events", key=bf_ip, payload=_ssh(bf_ip, i))
    bus.produce("raw.events", key=write_ip, payload=_modbus_write(write_ip, 40))
    _fresh("main", "parsers")
    _import("ws2-normalization").run(bus)
    _fresh("main", "engine", "scoring")
    ws4 = _import("ws4-detection")
    ws4.run(bus, ws4.Detector())
    _fresh("main", "correlator")
    corr = _import("ws8-correlation", "correlator").Correlator()
    alerts = [m.payload for m in bus.consume("alerts", group="cg-correlate", block_ms=0)]
    incidents = []
    for a in alerts:
        incidents += corr.ingest_alert(a)
    return alerts, incidents


def main() -> None:
    fails: list[str] = []

    alerts, incidents = _run(ATTACKER, ATTACKER)
    titles = sorted(str(a.get("rule_title", "")) for a in alerts)
    if not any("brute-force" in t.lower() for t in titles) or not any("Modbus" in t for t in titles):
        fails.append(f"expected a brute-force alert and a Modbus write alert, got {titles}")
    ip_incs = [i for i in incidents if i.get("entity_type") == "ip" and i.get("entity_value") == ATTACKER]
    if not ip_incs:
        fails.append(f"same-entity IT->OT chain did not promote an ip: incident ({incidents})")
    else:
        tactics = set(ip_incs[-1].get("tactics") or [])
        if not {"TA0006", "TA0106"} <= tactics:
            fails.append(f"incident should carry TA0006 and TA0106, got {sorted(tactics)}")

    alerts2, incidents2 = _run(ATTACKER, OT_HOST)
    if len(alerts2) != 2:
        fails.append(f"control run should still raise both alerts, got {len(alerts2)}")
    if incidents2:
        fails.append(f"different entities must NOT be correlated, got {incidents2}")

    if fails:
        print("[FAIL] ws8 IT->OT chain:", *fails, sep="\n  - ")
        sys.exit(1)
    print("[OK] ws8 IT->OT chain: SSH brute force + Modbus write from one IP = one incident (TA0006 + TA0106); "
          "a different writer is not linked (documented limit)")


if __name__ == "__main__":
    main()
