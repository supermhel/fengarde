"""WS-2 contract test — zero infrastructure.

For each registered parser:
  * parse its raw sample,
  * assert it validates against Contract A (shared.ocsf.validate == []),
  * assert the derived type_uid invariant holds,
  * assert the produced sector/class match expectations.
Also runs the full bus loop and checks normalized.events output.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
ROOT = SERVICES.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"

from shared.bus import Bus  # noqa: E402
from shared.ocsf import validate  # noqa: E402
from parsers import get_parser, known_sources  # noqa: E402
import main as ws2  # noqa: E402

FAILS: list[str] = []


def check(c, m):
    if not c:
        FAILS.append(m)


def run():
    samples = json.loads((HERE / "mocks" / "raw_samples.json").read_text())["samples"]
    expected = {
        "cisco_asa": (4001, "common"),
        "active_directory": (3002, "bank"),
        "vmware_vsphere": (6003, "datacenter"),
        "linux_ssh": (3002, "common"),
    }

    check(set(known_sources()) >= set(expected), f"registry missing sources: {known_sources()}")

    for s in samples:
        st = s["source_type"]
        parser = get_parser(st)
        check(parser is not None, f"no parser for {st}")
        if parser is None:
            continue
        event = parser.parse(s)
        check(event is not None, f"{st}: parser returned None")
        if event is None:
            continue
        errs = validate(event)
        check(errs == [], f"{st}: invalid OCSF -> {errs}")
        cls, sector = expected[st]
        check(event["class_uid"] == cls, f"{st}: class_uid {event['class_uid']} != {cls}")
        check(event["siem"]["sector"] == sector, f"{st}: sector {event['siem']['sector']} != {sector}")
        check(event["type_uid"] == event["class_uid"] * 100 + event["activity_id"],
              f"{st}: type_uid invariant violated")

    # full loop through the bus
    bus = Bus()
    for s in samples:
        bus.produce("raw.events", key=s["meta"].get("ip", "0.0.0.0"), payload=s)
    stats = ws2.run(bus)
    check(stats["normalized"] == len(samples), f"normalized {stats['normalized']} != {len(samples)}")
    check(stats["dropped"] == 0, f"unexpected drops: {stats['dropped']}")
    out = bus.drain("normalized.events")
    check(len(out) == len(samples), "normalized.events count mismatch")
    for m in out:
        check(m.key, "normalized event missing partition key (src ip)")


def main():
    run()
    if FAILS:
        print(f"[FAIL] WS-2: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-2 contract test PASS")


if __name__ == "__main__":
    main()
