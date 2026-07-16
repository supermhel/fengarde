"""M4.6 ops lifecycle: SQLite schema migration tests for services/shared/
users.py -- the one persistent local datastore in this system, and
therefore the one place a real "upgrade with data intact" claim is
verifiable zero-infra (no OpenSearch/Redis needed, unlike the rest of the
M4.6 ops-lifecycle work).

Run: python services/shared/test_users_migration.py
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from shared.users import (  # noqa: E402
    UserStore, CURRENT_SCHEMA_VERSION, migrate, hash_password,
)

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_fresh_db_lands_on_latest_version_with_new_column():
    store = UserStore(":memory:")
    version = store.db.execute("PRAGMA user_version").fetchone()[0]
    check(version == CURRENT_SCHEMA_VERSION,
          f"a brand-new DB must be created directly at the latest version, got {version}")
    cols = {row[1] for row in store.db.execute("PRAGMA table_info(users)")}
    check("last_login_at" in cols, f"the v2 column must exist on a fresh DB, got columns {cols}")


def test_existing_v1_db_upgrades_in_place_data_survives():
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "users.db")

        # Simulate a users.db created by an OLDER FENGARDE release: only the
        # v1 schema (no last_login_at), with a real user already in it.
        raw = sqlite3.connect(db_path)
        raw.executescript("""
            CREATE TABLE users (
              username TEXT PRIMARY KEY,
              password_hash TEXT NOT NULL,
              role TEXT NOT NULL,
              tenant_id TEXT NOT NULL DEFAULT 'default',
              created_at INTEGER NOT NULL
            );
        """)
        raw.execute(
            "INSERT INTO users (username, password_hash, role, tenant_id, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            ("preexisting_admin", hash_password("correct-horse-battery-staple"),
             "admin", "default", 1700000000),
        )
        raw.execute("PRAGMA user_version = 1")
        raw.commit()
        raw.close()

        # Opening it through UserStore (as the real service does on startup)
        # must upgrade the schema WITHOUT losing the pre-existing account.
        store = UserStore(db_path)
        version = store.db.execute("PRAGMA user_version").fetchone()[0]
        check(version == CURRENT_SCHEMA_VERSION, f"an old DB must be upgraded to {CURRENT_SCHEMA_VERSION}, got {version}")

        row = store.get_user("preexisting_admin")
        check(row is not None, "the pre-existing user must survive the migration")
        check(row["role"] == "admin" and row["tenant_id"] == "default",
              "the pre-existing user's data must be byte-for-byte intact after migration")
        check(row["last_login_at"] is None,
              "the new column must exist and start NULL for a row that predates it")

        logged_in = store.verify_login("preexisting_admin", "correct-horse-battery-staple")
        check(logged_in is not None, "the pre-existing user's password must still verify after migration")

        after_login = store.get_user("preexisting_admin")
        check(after_login["last_login_at"] is not None,
              "a successful login must populate the new column going forward")


def test_migrate_on_already_current_db_is_a_noop():
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "users.db")
        UserStore(db_path)  # creates it at the latest version

        # Re-opening (simulating a service restart against the same file)
        # must not error and must not re-run migrations.
        raw = sqlite3.connect(db_path)
        version_before = migrate(raw)
        version_again = migrate(raw)
        check(version_before == CURRENT_SCHEMA_VERSION and version_again == CURRENT_SCHEMA_VERSION,
              "calling migrate() twice on an up-to-date DB must be idempotent")
        raw.close()


def main():
    test_fresh_db_lands_on_latest_version_with_new_column()
    test_existing_v1_db_upgrades_in_place_data_survives()
    test_migrate_on_already_current_db_is_a_noop()

    if FAILS:
        print(f"[FAIL] users db migration: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] M4.6 users.db schema migration: fresh DB lands at latest version, "
          "a real pre-existing v1 DB upgrades in place with its data fully intact, "
          "re-running migrate() on a current DB is a safe no-op")


if __name__ == "__main__":
    main()
