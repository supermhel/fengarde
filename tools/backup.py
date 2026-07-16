#!/usr/bin/env python3
"""M4.6 ops lifecycle: back up FENGARDE's LOCAL state.

Bundles the two things that live only on this host and aren't already in
version control:

  * the RBAC user database (FENGARDE_RBAC_DB, if set and the file exists) --
    snapshotted with sqlite3's `.backup()` API, which is safe to run against
    a DB a live service still has open (unlike a raw file copy, which can
    grab a half-written page mid-transaction).
  * contracts/ -- rules, tenant configs, webhook configs. Most of this is
    already in git, but an operator's local tenant/webhook YAML additions
    (contracts/tenants/*.yml, contracts/webhooks/*.yml) may not be committed
    anywhere else, and this is the one place they're guaranteed to exist.

Produces a single .tar.gz with a manifest.json (sha256 + size per file) so
tools/restore.py can verify integrity before touching anything.

**Honest scope:** this does NOT back up OpenSearch index data (events,
alerts, reports). That needs OpenSearch's own native snapshot/restore API
against a configured snapshot repository -- a live-cluster operation this
repo's zero-infra test path can't exercise, and reimplementing it here
would just be an untested, unverified wrapper around someone else's
already-correct tool. See https://opensearch.org/docs/latest/tuning-your-cluster/availability-and-recovery/snapshots/
for OpenSearch's own snapshot docs.

Usage:
    python tools/backup.py --out ./backups
    python tools/backup.py --out ./backups --rbac-db /path/to/users.db
    python tools/backup.py --out ./backups --no-contracts   # RBAC DB only
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tarfile
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _backup_sqlite(src: Path, dest: Path) -> None:
    """Hot-copy a SQLite DB via the backup API (consistent even if a live
    process still has it open), not a raw file copy."""
    import sqlite3
    src_conn = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    dest_conn = sqlite3.connect(dest)
    try:
        src_conn.backup(dest_conn)
    finally:
        dest_conn.close()
        src_conn.close()


def build_backup(out_dir: Path, rbac_db: Path | None, include_contracts: bool) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    archive_path = out_dir / f"fengarde-backup-{timestamp}.tar.gz"

    manifest: dict = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "fengarde_component": "backup",
        "note": "local state only (RBAC DB + contracts/) -- OpenSearch index data "
                "is NOT included, use OpenSearch's own snapshot API for that",
        "files": [],
    }

    with tempfile.TemporaryDirectory() as staging_str:
        staging = Path(staging_str)

        if rbac_db is not None and rbac_db.exists():
            dest = staging / "rbac" / rbac_db.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            _backup_sqlite(rbac_db, dest)
            manifest["files"].append({
                "path": f"rbac/{rbac_db.name}", "sha256": _sha256(dest), "size": dest.stat().st_size,
            })

        if include_contracts:
            contracts_src = ROOT / "contracts"
            for path in sorted(contracts_src.rglob("*")):
                if not path.is_file():
                    continue
                rel = path.relative_to(ROOT)  # e.g. contracts/tenants/acme.yml
                dest = staging / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(path.read_bytes())
                manifest["files"].append({
                    "path": str(rel).replace(os.sep, "/"), "sha256": _sha256(dest), "size": dest.stat().st_size,
                })

        manifest_path = staging / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(manifest_path, arcname="manifest.json")
            for entry in manifest["files"]:
                tar.add(staging / entry["path"], arcname=entry["path"])

    return archive_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True, help="directory to write the backup archive into")
    parser.add_argument("--rbac-db", default=os.getenv("FENGARDE_RBAC_DB"),
                         help="path to the RBAC SQLite DB (default: $FENGARDE_RBAC_DB)")
    parser.add_argument("--no-contracts", action="store_true", help="skip bundling contracts/")
    args = parser.parse_args()

    rbac_db = Path(args.rbac_db) if args.rbac_db else None
    archive = build_backup(Path(args.out), rbac_db, include_contracts=not args.no_contracts)
    print(json.dumps({"backup": str(archive), "size_bytes": archive.stat().st_size}))


if __name__ == "__main__":
    sys.exit(main())
