"""Concurrent first start on a FRESH RBAC DB must not crash in migrate().

Regression (WP-3.2 second review): N ws3 processes starting at once on an empty
sqlite file each read user_version=0 and ran the same ALTER, so the losers died with
"duplicate column name". migrate() now serializes on BEGIN IMMEDIATE and re-reads
user_version under the lock. Separate connections + a barrier model separate processes.

Run: python services/shared/test_users_migrate_race.py
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.users import CURRENT_SCHEMA_VERSION, migrate  # noqa: E402

N = 16
ROUNDS = 5


def main() -> int:
    errors: list[str] = []
    for _ in range(ROUNDS):
        path = os.path.join(tempfile.mkdtemp(), "fresh.sqlite")
        barrier = threading.Barrier(N)
        versions: list[int] = []

        def start() -> None:
            db = sqlite3.connect(path, timeout=30)
            try:
                barrier.wait()
                versions.append(migrate(db))
            except Exception as exc:  # noqa: BLE001
                errors.append(type(exc).__name__ + ": " + str(exc))
            finally:
                db.close()

        threads = [threading.Thread(target=start) for _ in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if not errors and versions != [CURRENT_SCHEMA_VERSION] * N:
            errors.append(f"versions {versions}")
        db = sqlite3.connect(path)
        cols = [r[1] for r in db.execute("PRAGMA table_info(users)")]
        db.close()
        if len(cols) != len(set(cols)) or "disabled" not in cols or "totp_secret" not in cols:
            errors.append(f"schema wrong: {cols}")
    if errors:
        print(f"[FAIL] users migrate race: {len(errors)} problem(s)")
        for e in errors[:10]:
            print("  -", e)
        return 1
    print(f"[OK] users migrate race: {ROUNDS} rounds x {N} concurrent first starts, no crash, schema v{CURRENT_SCHEMA_VERSION}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
