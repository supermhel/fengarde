"""WS-9 live memory-bus round trip (acceptance (b)): produce one alert-ish
input, drive it through the EXACT main.py handler wiring, print the emitted
entity.updates payloads. Zero infrastructure (BUS_BACKEND=memory default).

Run:  python services/ws9-resolver/demo_round_trip.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.bus import Bus  # noqa: E402

import main as ws9_main  # noqa: E402
from entity_id import compute_entity_id  # noqa: E402
from resolver import EntityResolver  # noqa: E402


def main():
    bus = Bus()
    resolver = EntityResolver()
    handler = ws9_main.make_handler(bus, resolver)

    # One alert-ish input, mirroring ws4's alert shape + a mapped-IPv6 variant
    # of the source IP to show edge canonicalization live.
    alert = {
        "alert_id": "alert-9001",
        "tenant_id": "acme",
        "time": 1755792000000,
        "rule_id": "r-bruteforce-ssh",
        "level": "high",
        "score": 60,
        "mitre": {"tactic": "TA0006"},
        "actor": {"user": {"name": "CAROL.Phd-01"}},
        "src_endpoint": {"ip": "::ffff:203.0.113.9", "mac": "AA:BB:CC:DD:EE:FF"},
        "dst_endpoint": {"ip": "10.0.0.42"},
        "event_ids": ["ev-99"],
    }

    bus.produce("alerts", key=alert["alert_id"], payload=alert)
    for msg in bus.consume("alerts", group="cg-entity"):
        handler(msg.payload)

    updates = list(bus.consume("entity.updates", group="cg-demo"))
    print(f"== {len(updates)} entity.updates emitted for one alert ==")
    for m in updates:
        print(f"  topic={m.topic}  partition_key={m.key}")
        print("  " + json.dumps(m.payload, indent=2).replace("\n", "\n  "))

    print("\n== deterministic-id proof ==")
    print('  compute_entity_id("acme","actor","carol.phd-01") =',
          compute_entity_id("acme", "actor", "carol.phd-01"))
    actor_update = next(u for u in updates if u.payload["entity_type"] == "actor")
    assert actor_update.payload["entity_id"] == compute_entity_id(
        "acme", "actor", "carol.phd-01")
    ip_update = next(u for u in updates if u.payload["entity_type"] == "ip"
                     and u.payload["entity_value"] == "203.0.113.9")
    assert ip_update.payload["entity_value"] == "203.0.113.9", "mapped-IPv6 must canonicalize to plain IPv4"
    device = next(u for u in updates if u.payload["entity_type"] == "device")
    assert device.payload["entity_value"] == "aa:bb:cc:dd:ee:ff", "MAC must be lowercased"
    print("  mapped-IPv6 ::ffff:203.0.113.9 -> canonical 203.0.113.9")
    print("  device AA:BB:CC:DD:EE:FF     -> canonical aa:bb:cc:dd:ee:ff")
    print("[OK] live memory-bus round trip")
    return updates


if __name__ == "__main__":
    main()
