"""M7 Track Y: new-device detection semantics (baseline, tenancy, durability).

These are the three properties an inventory-diff detection lives or dies on,
and none of them are provable from the rule fixture alone:

  * a first sighting inside the tenant's baseline window is population, not an
    intrusion -- otherwise standing the service up against an existing segment
    emits one alert per device already there;
  * "known device" is scoped per tenant -- the same MAC in two tenants is two
    devices (this repo has already had one real cross-tenant inventory bug);
  * the baseline survives a restart -- in-memory state would make every
    service bounce look identical to the whole segment reappearing.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from store import InventoryStore  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _obs(mac, ip="10.20.0.5", tenant=None):
    obs = {"mac": mac, "ip": ip, "seen_at": "2026-08-05T10:00:00+00:00"}
    if tenant is not None:
        obs["tenant_id"] = tenant
    return obs


def run() -> None:
    # --- baselining -----------------------------------------------------
    # With a live baseline window, a fresh install populating an existing
    # segment must stay silent.
    os.environ["INVENTORY_BASELINE_SECONDS"] = "3600"
    store = InventoryStore(":memory:")
    flags = [store.upsert_with_diff(_obs(f"AA:BB:CC:00:00:{i:02X}"))[1] for i in range(5)]
    check(not any(flags),
          "cold start inside the baseline window does not alert on existing devices")

    # Same devices seen again are still not new.
    _, again = store.upsert_with_diff(_obs("AA:BB:CC:00:00:00"))
    check(again is False, "a MAC already on file is never reported as new")

    # With baselining disabled, a first-ever sighting IS alertable.
    os.environ["INVENTORY_BASELINE_SECONDS"] = "0"
    store = InventoryStore(":memory:")
    _, first = store.upsert_with_diff(_obs("AA:BB:CC:00:00:01"))
    check(first is True, "first-ever sighting alerts once the baseline is closed")
    _, repeat = store.upsert_with_diff(_obs("AA:BB:CC:00:00:01"))
    check(repeat is False, "re-observing that same device does not alert again")

    # --- tenant isolation ------------------------------------------------
    # The same MAC in two tenants is two distinct devices; tenant B's first
    # sighting must not be masked by tenant A having seen it.
    store = InventoryStore(":memory:")
    _, a_first = store.upsert_with_diff(_obs("AA:BB:CC:11:11:11", tenant="acme"))
    _, b_first = store.upsert_with_diff(_obs("AA:BB:CC:11:11:11", tenant="globex"))
    check(a_first is True and b_first is True,
          "same MAC in two tenants alerts independently, state is not shared")
    _, a_repeat = store.upsert_with_diff(_obs("AA:BB:CC:11:11:11", tenant="acme"))
    check(a_repeat is False, "per-tenant known-device state is honoured on repeat")

    # A tenant onboarded later gets its own baseline window, rather than
    # inheriting a window that closed for an earlier tenant.
    os.environ["INVENTORY_BASELINE_SECONDS"] = "3600"
    store = InventoryStore(":memory:")
    _, late = store.upsert_with_diff(_obs("AA:BB:CC:22:22:22", tenant="onboarded-later"))
    check(late is False, "a newly onboarded tenant baselines on its own clock")

    # --- durability across restart --------------------------------------
    # A restart must not look like the whole segment reappearing.
    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "inv.db")
        os.environ["INVENTORY_BASELINE_SECONDS"] = "0"
        store = InventoryStore(db)
        macs = [f"AA:BB:CC:33:33:{i:02X}" for i in range(4)]
        for mac in macs:
            store.upsert_with_diff(_obs(mac))
        store.db.close()

        reopened = InventoryStore(db)
        after = [reopened.upsert_with_diff(_obs(mac))[1] for mac in macs]
        check(not any(after),
              "known devices stay known across a restart, no post-restart storm")
        _, genuinely_new = reopened.upsert_with_diff(_obs("AA:BB:CC:44:44:44"))
        check(genuinely_new is True,
              "a genuinely new device after a restart is still detected")
        reopened.db.close()

    # An existing deployment upgrading into this feature already has its
    # inventory populated -- that IS the baseline, so it must not go quiet for
    # an hour and miss a real new device.
    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "upgrade.db")
        os.environ["INVENTORY_BASELINE_SECONDS"] = "0"
        seeded = InventoryStore(db)
        seeded.upsert_with_diff(_obs("AA:BB:CC:55:55:55"))
        seeded.db.execute("DELETE FROM tenant_state")  # pre-feature on-disk shape
        seeded.db.commit()
        seeded.db.close()

        os.environ["INVENTORY_BASELINE_SECONDS"] = "3600"
        upgraded = InventoryStore(db)
        _, post_upgrade = upgraded.upsert_with_diff(_obs("AA:BB:CC:66:66:66"))
        check(post_upgrade is True,
              "an already-populated tenant is treated as baselined, not re-baselined")
        upgraded.db.close()

    os.environ.pop("INVENTORY_BASELINE_SECONDS", None)

    # --- backward compatibility -----------------------------------------
    store = InventoryStore(":memory:")
    asset = store.upsert(_obs("AA:BB:CC:77:77:77"))
    check(isinstance(asset, dict) and asset.get("mac") == "AA:BB:CC:77:77:77",
          "legacy upsert() still returns the asset dict unchanged")
    check(store.upsert({"ip": "10.0.0.1"}) is None,
          "legacy upsert() still returns None when mac is missing")


def main() -> None:
    run()
    if FAILS:
        print(f"[FAIL] ws6 new-device diff: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] ws6 new-device diff (baseline, tenancy, restart durability)")


if __name__ == "__main__":
    main()
