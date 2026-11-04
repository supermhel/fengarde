"""Gap-hunt R4-49: InventoryStore and TenantKeyStore share one in-process write lock when they share a SQLite file.

app.py defaults the keystore database to the inventory database. Two connections with two independent locks let two
request threads contend for SQLite's single writer and stall up to the 30 s busy timeout. The fix passes the inventory
store's lock to the keystore when (and only when) both point at the same real file. app.py builds both at import, so
each case runs in a subprocess with its own environment.

Zero-infra. Run:  python services/ws6-inventory/test_shared_write_lock.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROBE = "import app; print('SHARED' if app.KEYSTORE._write_lock is app.STORE._write_lock else 'SEPARATE')"

FAILS: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        FAILS.append(msg)


def _probe(extra_env: dict) -> str:
    env = {k: v for k, v in os.environ.items()
           if k not in ("INVENTORY_DB", "INVENTORY_KEYSTORE_DB")} | extra_env
    out = subprocess.run([sys.executable, "-c", PROBE], cwd=HERE, env=env, capture_output=True, text=True, timeout=120)
    return out.stdout.strip().splitlines()[-1] if out.stdout.strip() else f"ERROR {out.stderr[-300:]}"


def main() -> int:
    with tempfile.TemporaryDirectory() as t:
        db = str(Path(t) / "inv.db")
        check(_probe({"INVENTORY_DB": db}) == "SHARED", "same file (keystore defaults to the inventory db) must share the lock")
        check(_probe({"INVENTORY_DB": db, "INVENTORY_KEYSTORE_DB": db}) == "SHARED", "explicit same path must share the lock")
        check(_probe({"INVENTORY_DB": db, "INVENTORY_KEYSTORE_DB": str(Path(t) / "keys.db")}) == "SEPARATE",
              "different files must keep independent locks")
    check(_probe({}) == "SEPARATE", ":memory: databases are private to each store and must not share a lock")
    if FAILS:
        print(f"[FAIL] ws6 shared write lock: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        return 1
    print("[OK] ws6 stores share one write lock exactly when they share a SQLite file")
    return 0


if __name__ == "__main__":
    sys.exit(main())
