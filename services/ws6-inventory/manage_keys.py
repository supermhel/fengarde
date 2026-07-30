"""Operator CLI: provision/rotate/list per-tenant WS-6 API keys.

Usage:
    python manage_keys.py provision <tenant_id> [--db PATH]
    python manage_keys.py list [--db PATH]

`provision` generates a fresh high-entropy key, hashes it into the keystore
(see keystore.py), and prints the RAW key to stdout EXACTLY ONCE -- this is
the only moment the plaintext key exists outside the operator's own
terminal; it is never logged, stored, or shown again. Re-running `provision`
for a tenant that already has a key ROTATES it (the old key stops working
immediately -- see TenantKeyStore.provision's docstring).

`--db` defaults to $INVENTORY_KEYSTORE_DB, then $INVENTORY_DB, then the
service's own default (`/data/inventory.db` in the shipped container) --
same resolution order app.py uses, so this CLI reads/writes the keystore
the running service actually uses without extra flags in the common case.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from keystore import ADMIN_TENANT_MARKER, TenantKeyStore, generate_raw_key  # noqa: E402


def _default_db_path() -> str:
    return (os.getenv("INVENTORY_KEYSTORE_DB")
            or os.getenv("INVENTORY_DB")
            or "/data/inventory.db")


def cmd_provision(args) -> None:
    store = TenantKeyStore(args.db)
    raw = generate_raw_key()
    store.provision(args.tenant_id, raw, source="generated")
    label = "admin (unrestricted)" if args.tenant_id == ADMIN_TENANT_MARKER else f"tenant {args.tenant_id!r}"
    print(f"Provisioned a key for {label}.")
    print("This key is shown ONCE and is not recoverable -- store it now:")
    print(raw)


def cmd_list(args) -> None:
    store = TenantKeyStore(args.db)
    tenants = store.list_tenants()
    if not tenants:
        print("No keys provisioned.")
        return
    for t in tenants:
        print("admin (unrestricted)" if t == ADMIN_TENANT_MARKER else t)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_provision = sub.add_parser("provision", help="create or rotate one tenant's key")
    p_provision.add_argument("tenant_id", help=f"tenant id, or '{ADMIN_TENANT_MARKER}' for an unrestricted admin key")
    p_provision.add_argument("--db", default=_default_db_path())
    p_provision.set_defaults(func=cmd_provision)

    p_list = sub.add_parser("list", help="list provisioned tenant ids (never key material)")
    p_list.add_argument("--db", default=_default_db_path())
    p_list.set_defaults(func=cmd_list)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
