"""UserStore is read on EVERY authenticated WS-3 request (session account re-check),
so concurrent reads on its one shared SQLite connection must not fail.

Regression (2026-10-16, found by the live browser run): unlocked reads raised
InterfaceError / returned wrong rows under threads; the re-check then failed
closed and invalidated healthy sessions (about 70% of concurrent requests got 401).

Run: python services/shared/test_users_threading.py
"""
from __future__ import annotations

import collections
import os
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.users import UserStore  # noqa: E402


def main() -> int:
    store = UserStore(os.path.join(tempfile.mkdtemp(), "t.sqlite"))
    store.create_user("a", "pw-aaaaaaaaaaaa", role="admin", tenant_id="default")
    store.create_user("b", "pw-bbbbbbbbbbbb", role="analyst", tenant_id="default")
    errors: collections.Counter = collections.Counter()

    def reader():
        for _ in range(300):
            try:
                row = store.get_user("a")
                assert row["role"] == "admin" and not row["disabled"]
                assert len(store.list_users()) == 2
                assert store.count_admins() == 1 and store.count() == 2
            except Exception as exc:  # noqa: BLE001 - the point is to count every failure kind
                errors[repr(exc)[:80]] += 1

    def writer():  # a writer interleaving with readers must not break them either
        for i in range(60):
            try:
                store.update_user("b", role="analyst" if i % 2 else "read_only")
            except Exception as exc:  # noqa: BLE001
                errors["writer " + repr(exc)[:70]] += 1

    threads = [threading.Thread(target=reader) for _ in range(12)] + [threading.Thread(target=writer)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        print("[FAIL] concurrent UserStore access raised:", dict(errors))
        return 1
    print("[OK] UserStore: 12 reader threads x 300 iterations + a concurrent writer, zero errors "
          "(reads share the write lock; get_user runs on every authenticated request)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
