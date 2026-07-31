"""Operator CLI: provision/revoke/list per-tenant WS-6 API keys.

Usage:
    python manage_keys.py provision <tenant_id> [--scope read_only|read_write] [--db PATH]
    python manage_keys.py revoke <key_id> [--db PATH]
    python manage_keys.py list [tenant_id] [--db PATH]

`provision` ADDS a new, independently revocable key -- it does not disturb
any key the tenant already has. That is the rotation story: provision a
new key, update the caller, confirm the cutover, THEN `revoke` the old
key_id -- no forced downtime. The raw key is printed to stdout EXACTLY
ONCE; it is never logged, stored, or shown again.

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
from keystore import (  # noqa: E402
    ADMIN_TENANT_MARKER, DuplicateKeyError, SCOPE_READ_WRITE, VALID_SCOPES,
    TenantKeyStore, generate_raw_key,
)
from store import InvalidTenantId  # noqa: E402


def _default_db_path() -> str:
    return (os.getenv("INVENTORY_KEYSTORE_DB")
            or os.getenv("INVENTORY_DB")
            or "/data/inventory.db")


def cmd_provision(args) -> None:
    store = TenantKeyStore(args.db)
    raw = generate_raw_key()
    try:
        key_id = store.provision(args.tenant_id, raw, source="generated", scope=args.scope)
    except InvalidTenantId as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except DuplicateKeyError as e:  # astronomically unlikely for a generated key, handled anyway
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    label = "admin (unrestricted)" if args.tenant_id == ADMIN_TENANT_MARKER else f"tenant {args.tenant_id!r}"
    print(f"Provisioned a {args.scope} key for {label} (key_id={key_id}).")
    print("This key is shown ONCE and is not recoverable -- store it now:")
    print(raw)
    print(f"To revoke it later: python manage_keys.py revoke {key_id}")


def cmd_revoke(args) -> None:
    store = TenantKeyStore(args.db)
    if store.revoke(args.key_id):
        print(f"Revoked key_id={args.key_id}.")
    else:
        print(f"No key found with key_id={args.key_id} (already revoked, or never existed).")


def cmd_list(args) -> None:
    store = TenantKeyStore(args.db)
    keys = store.list_keys(tenant_id=args.tenant_id)
    if not keys:
        print("No keys provisioned." if args.tenant_id is None
              else f"No keys provisioned for tenant {args.tenant_id!r}.")
        return
    for k in keys:
        label = "admin (unrestricted)" if k["tenant_id"] == ADMIN_TENANT_MARKER else k["tenant_id"]
        last_used = k["last_used_at"] or "never"
        print(f"key_id={k['key_id']}  tenant={label}  scope={k['scope']}  "
              f"source={k['source']}  created={k['created_at']}  last_used={last_used}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_provision = sub.add_parser("provision", help="issue a new key for a tenant (does not disturb existing keys)")
    p_provision.add_argument("tenant_id", help=f"tenant id, or '{ADMIN_TENANT_MARKER}' for an unrestricted admin key")
    p_provision.add_argument("--scope", choices=VALID_SCOPES, default=SCOPE_READ_WRITE)
    p_provision.add_argument("--db", default=_default_db_path())
    p_provision.set_defaults(func=cmd_provision)

    p_revoke = sub.add_parser("revoke", help="permanently disable one specific key")
    p_revoke.add_argument("key_id")
    p_revoke.add_argument("--db", default=_default_db_path())
    p_revoke.set_defaults(func=cmd_revoke)

    p_list = sub.add_parser("list", help="list provisioned keys (never key material)")
    p_list.add_argument("tenant_id", nargs="?", default=None, help="filter to one tenant; omit for all")
    p_list.add_argument("--db", default=_default_db_path())
    p_list.set_defaults(func=cmd_list)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
