"""WS-6 stores an observation's sector and type.

Regression (2026-10-16, found in the live console): the admin add-device form sent sector and type,
WS-6 echoed null for both because upsert never wrote them.

Run: python services/ws6-inventory/test_upsert_attrs.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from store import InventoryStore  # noqa: E402

MAC = "AA:BB:CC:00:00:01"


def main() -> int:
    s = InventoryStore(":memory:")
    a = s.upsert({"mac": MAC, "ip": "10.0.0.1", "hostname": "plc-1", "sector": "datacenter", "type": "plc"})
    assert a is not None
    assert (a["sector"], a["type"]) == ("datacenter", "plc"), a
    # a later observation without the fields (e.g. SNMP) must not erase them
    b = s.upsert({"mac": MAC, "ip": "10.0.0.1"})
    assert b is not None
    assert (b["sector"], b["type"]) == ("datacenter", "plc"), b
    # an update that supplies them changes them
    c = s.upsert({"mac": MAC, "sector": "bank", "type": "switch"})
    assert c is not None
    assert (c["sector"], c["type"]) == ("bank", "switch"), c
    # invalid values never reject the observation and never overwrite good data
    d = s.upsert({"mac": MAC, "sector": "not-a-sector", "type": "x" * 200})
    assert d is not None
    assert (d["sector"], d["type"]) == ("bank", "switch"), d
    e = s.upsert({"mac": "AA:BB:CC:00:00:02", "sector": 7, "type": ["list"]})
    assert e is not None and e["sector"] is None and e["type"] is None, e
    assert [x["mac"] for x in s.list(sector="bank")] == [MAC]
    print("[OK] WS-6 upsert persists sector + type, keeps them across field-less observations, "
          "ignores invalid values without rejecting the device")
    return 0


if __name__ == "__main__":
    sys.exit(main())
