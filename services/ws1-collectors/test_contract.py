"""WS-1 contract test — zero infrastructure (memory bus).

Asserts:
  * every message produced to raw.events has source_type, raw, and a partition key,
  * SNMP asset observations carry mac+ip+seen_at,
  * the syslog/snmp/netflow collectors each emit at least one raw payload.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"

from shared.bus import Bus  # noqa: E402
import main as ws1  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def run():
    bus = Bus()
    counts = ws1.run_once(bus)

    raw = bus.drain("raw.events")
    assets = bus.drain("assets.updates")

    check(counts["raw.events"] >= 3, "expected >=3 raw events across collectors")
    source_types = {m.payload["source_type"] for m in raw}
    check(any(st.startswith("syslog") for st in source_types), "no syslog raw events")
    check("snmp" in source_types, "no snmp raw events")
    check("netflow_ipfix" in source_types, "no netflow raw events")

    for m in raw:
        p = m.payload
        check("source_type" in p, "raw payload missing source_type")
        check("raw" in p, "raw payload missing raw")
        check(m.key, f"raw event missing partition key: {p.get('source_type')}")

    check(len(assets) >= 1, "expected at least one asset observation (SNMP)")
    for m in assets:
        o = m.payload
        check(o.get("ip"), "asset observation missing ip")
        check(o.get("seen_at"), "asset observation missing seen_at")
    # SNMP specifically should supply a MAC
    snmp_assets = [m.payload for m in assets if m.payload.get("mac")]
    check(len(snmp_assets) >= 1, "expected at least one asset observation with a MAC")


def main():
    run()
    if FAILS:
        print(f"[FAIL] WS-1: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-1 contract test PASS")


if __name__ == "__main__":
    main()
