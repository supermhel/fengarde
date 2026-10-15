"""WS-6 stores are read on every request (KEYSTORE.count()/verify() for auth, then list/get), on
one shared SQLite connection each. Concurrent requests must not fail.

Regression (2026-10-16, found by the live browser run): unlocked reads raised
TypeError 'NoneType' object is not subscriptable inside KEYSTORE.count() under the console's
parallel GETs, surfacing as HTTP 500 on /keys and /assets.

Run: python services/ws6-inventory/test_store_threading.py
"""
from __future__ import annotations

import collections
import os
import sys
import tempfile
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from keystore import TenantKeyStore  # noqa: E402
from store import InventoryStore  # noqa: E402


def main() -> int:
    d = tempfile.mkdtemp()
    inv = InventoryStore(os.path.join(d, "inv.sqlite"))
    keys = TenantKeyStore(os.path.join(d, "keys.sqlite"))
    for i in range(12):
        inv.upsert({"mac": f"AA:BB:CC:DD:EE:{i:02X}", "ip": f"10.0.0.{i + 1}", "hostname": f"h{i}"})
    raw = "k" * 40
    keys.provision("default", raw)
    errors: collections.Counter = collections.Counter()

    def reader():
        for n in range(150):
            try:
                assert keys.count() == 1
                assert keys.verify(raw)[0] is True
                assert len(keys.list_keys()) == 1
                assert len(inv.list(limit=200)) >= 12  # the writer is adding assets meanwhile
                assert inv.get("AA:BB:CC:DD:EE:03")["hostname"] == "h3"
                inv.resolve("10.0.0.5", "2999-01-01T00:00:00Z")  # must not raise
            except Exception as exc:  # noqa: BLE001 - count every failure kind
                errors[repr(exc)[:80]] += 1

    def writer():
        for n in range(40):
            try:
                inv.upsert({"mac": f"AA:BB:CC:DD:FF:{n:02X}", "ip": f"10.1.0.{n + 1}"})
            except Exception as exc:  # noqa: BLE001
                errors["writer " + repr(exc)[:70]] += 1

    threads = [threading.Thread(target=reader) for _ in range(10)] + [threading.Thread(target=writer)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        print("[FAIL] concurrent WS-6 store access raised:", dict(errors))
        return 1
    print("[OK] WS-6 InventoryStore + TenantKeyStore: 10 reader threads x 150 iterations with a concurrent "
          "writer, zero errors (reads share the write lock)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
