"""M7 Track Y follow-up: WS-6's assets.updates -> raw.events bus consumer.

Zero-infra (BUS_BACKEND=memory), proves the full loop this branch exists for:
an assets.updates observation reaches InventoryStore, and a genuinely new
device is republished onto raw.events in the exact shape
services/ws2-normalization/parsers/inventory_diff.py consumes -- round-tripped
through that real parser here, not asserted by resemblance.

Run with:
    python services/ws6-inventory/test_bus_consumer.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"
os.environ["INVENTORY_BASELINE_SECONDS"] = "0"

from shared.bus import Bus  # noqa: E402
from shared.ocsf import validate  # noqa: E402
from store import InventoryStore  # noqa: E402
from bus_consumer import make_handler  # noqa: E402
from parsers.inventory_diff import InventoryDiffParser  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def run() -> None:
    store = InventoryStore(":memory:")
    bus = Bus()
    handler = make_handler(store, bus)

    # A genuinely new device publishes a notification.
    handler({"mac": "AA:BB:CC:10:10:10", "ip": "10.20.0.9",
              "hostname": "plc-9", "device_type": "plc", "sector": "ot",
              "seen_at": "2026-08-05T10:00:00+00:00", "tenant_id": "acme"})
    out = list(bus.consume("raw.events", group="cg-test"))
    check(len(out) == 1, f"exactly one raw.events message published, got {len(out)}")
    msg = out[0]
    check(msg.key == "AA:BB:CC:10:10:10", "partition key is the device mac")
    check(msg.payload["source_type"] == "inventory_diff",
          "published envelope routes to the inventory_diff parser")
    check(msg.payload["meta"].get("tenant_id") == "acme",
          "tenant_id from the observation is propagated into meta")

    # The published envelope round-trips through the REAL parser into a
    # valid OCSF event -- not just shape-checked by hand here.
    event = InventoryDiffParser().parse(msg.payload)
    check(event is not None, "the published envelope parses")
    check(validate(event) == [], f"parsed event is valid OCSF: {validate(event)}")
    check(event["src_endpoint"]["mac"] == "AA:BB:CC:10:10:10",
          "parsed event carries the same mac")
    check(event["severity_id"] == 4, "OT sector raises severity as the parser defines")

    # The SAME device seen again does not republish.
    handler({"mac": "AA:BB:CC:10:10:10", "ip": "10.20.0.9",
              "seen_at": "2026-08-05T10:05:00+00:00", "tenant_id": "acme"})
    check(len(list(bus.consume("raw.events", group="cg-test"))) == 0,
          "a repeat sighting of a known device does not republish")

    # A non-OT observation (no sector/device_type) still republishes as new,
    # but is NOT fabricated as an OT device -- severity stays non-High.
    handler({"mac": "AA:BB:CC:20:20:20", "ip": "10.20.0.11",
              "seen_at": "2026-08-05T10:00:00+00:00"})
    out2 = list(bus.consume("raw.events", group="cg-test"))
    check(len(out2) == 1, "a plain (non-OT) new device still republishes")
    event2 = InventoryDiffParser().parse(out2[0].payload)
    check(event2 is not None and validate(event2) == [], "plain observation still parses to valid OCSF")
    check(event2["severity_id"] != 4,
          "sector is never fabricated as ot -- severity is not escalated for an unlabeled device")
    check("tenant_id" not in out2[0].payload["meta"],
          "no tenant_id on the observation means none is fabricated into meta")

    # Cold start inside a baseline window: no publish at all.
    os.environ["INVENTORY_BASELINE_SECONDS"] = "3600"
    store2 = InventoryStore(":memory:")
    bus2 = Bus()
    handler2 = make_handler(store2, bus2)
    for i in range(3):
        handler2({"mac": f"AA:BB:CC:30:30:{i:02X}", "ip": "10.20.0.50",
                   "seen_at": "2026-08-05T10:00:00+00:00"})
    check(len(list(bus2.consume("raw.events", group="cg-test"))) == 0,
          "cold start inside the baseline window publishes nothing")
    os.environ["INVENTORY_BASELINE_SECONDS"] = "0"

    # Missing mac: dropped, not published, no exception.
    store3 = InventoryStore(":memory:")
    bus3 = Bus()
    handler3 = make_handler(store3, bus3)
    handler3({"ip": "10.20.0.99"})
    check(len(list(bus3.consume("raw.events", group="cg-test"))) == 0,
          "an observation with no mac is dropped, not published")


def main() -> None:
    run()
    if FAILS:
        print(f"[FAIL] ws6 bus_consumer: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] ws6 bus_consumer (assets.updates -> raw.events, real parser round-trip)")


if __name__ == "__main__":
    main()
