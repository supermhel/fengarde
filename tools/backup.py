#!/usr/bin/env python3
"""M4.6 ops lifecycle: back up FENGARDE's LOCAL state.

Bundles the things that live only on this host, are plain files/SQLite
(a service could hold them open), and aren't already in version control:

  * the RBAC user database (FENGARDE_RBAC_DB / --rbac-db). FAILS if the
    configured path does not exist, so a missing DB can never silently
    produce an archive that claims to protect it -- snapshotted with
    sqlite3's `.backup()` API, which is safe to run against
    a DB a live service still has open (unlike a raw file copy, which can
    grab a half-written page mid-transaction).
  * the WS-6 inventory SQLite store(s). The inventory data (INVENTORY_DB /
    --inventory-db) and the API-key store (INVENTORY_KEYSTORE_DB /
    --keystore-db) are ONE file by default: INVENTORY_KEYSTORE_DB falls back
    to INVENTORY_DB exactly like services/ws6-inventory/app.py. That file is
    archived as keystore/<name>; a separately configured inventory file is
    archived as inventory/<name>. ":memory:" is skipped.
  * the WS-3 audit log (FENGARDE_AUDIT_LOG / --audit-log, a JSONL file),
    copied while holding the audit log's own cross-process `.lock`.
  * the WS-1 spool files (SYSLOG_SPOOL_PATH / INGEST_HTTP_SPOOL_PATH /
    SYSLOG_TCP_SPOOL_PATH, --spool, repeatable): unreplayed events. A spool
    file that does not exist yet is normal (spools are created lazily) and is
    recorded as not backed up, not treated as an error. Stop the collectors
    first; the spool has no file lock.
  * plugin rule-pack directories (FENGARDE_PLUGIN_RULE_DIRS / --plugin-rule-dir,
    repeatable).
  * contracts/ -- rules, tenant configs, webhook configs. Most of this is
    already in git, but an operator's local tenant/webhook YAML additions
    (contracts/tenants/*.yml, contracts/webhooks/*.yml) may not be committed
    anywhere else, and this is the one place they're guaranteed to exist.

An explicitly configured store whose path does not exist aborts the backup
non-zero. A store that is simply not configured is listed on stderr and in
manifest.json ("not_backed_up") so an archive can never look more complete
than it is.

Produces a single .tar.gz with a manifest.json (sha256 + size per file) so
tools/restore.py can verify integrity before touching anything.

**Honest scope (explicitly NOT in the archive):** OpenSearch index data
(use OpenSearch's own snapshot API), Redis (bus streams / detection window
state; use Redis RDB/AOF), and the operator GeoIP map (FENGARDE_GEOIP_PATH).
Docker named volumes are not visible to this script: run it against files
extracted from the volumes (see docs/upgrade.md).

Usage:
    python tools/backup.py --out ./backups
    python tools/backup.py --out ./backups --rbac-db /path/to/users.db
    python tools/backup.py --out ./backups --no-contracts   # skip contracts/
    python tools/backup.py --out ./backups --keystore-db /data/inventory.db --audit-log /data/audit.jsonl
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tarfile
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Always-true scope boundary, written into every manifest.
OUT_OF_SCOPE = (
    "OpenSearch index data (events/alerts/reports): use OpenSearch's snapshot API",
    "Redis state (bus streams, detection windows, entity state): use Redis RDB/AOF",
    "FENGARDE_GEOIP_PATH operator GeoIP map: copy it yourself",
    "Docker named volumes are not read directly: extract the files first (docs/upgrade.md)",
)


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
    # as_uri() percent-encodes '%', '#', '?', spaces -- an f-string path broke on '%'.
    src_conn = sqlite3.connect(src.resolve().as_uri() + "?mode=ro", uri=True)
    dest_conn = sqlite3.connect(dest)
    try:
        src_conn.backup(dest_conn)
    finally:
        dest_conn.close()
        src_conn.close()


def _audit_lock(path: Path):
    """Take the audit log's own cross-process lock (same one audit.py holds
    around every append and trim). Returns an open handle (close() releases)
    or None if the lock is unavailable -- the caller then warns."""
    try:
        spec = importlib.util.spec_from_file_location(
            "_fengarde_audit_lock", ROOT / "services" / "ws3-indexer" / "audit.py")
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod._acquire_cross_process_lock(str(path))
    except Exception:  # noqa: BLE001 - best-effort, mirrors audit.py's own fail-open lock
        return None


def _same_file(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve() or (a.exists() and b.exists() and a.samefile(b))
    except OSError:
        return False


def _require_file(label: str, src: Path) -> None:
    if not src.exists() or not src.is_file():
        raise FileNotFoundError(
            f"{label} {src} does not exist -- refusing to create an archive that "
            f"silently omits the configured store (file renamed, never initialized, "
            f"or it lives in a Docker volume this host-side script cannot see?)")


def _add(manifest: dict, rel: str, dest: Path) -> None:
    manifest["files"].append({"path": rel, "sha256": _sha256(dest), "size": dest.stat().st_size})


def build_backup(out_dir: Path, rbac_db: Path | None, include_contracts: bool,
                 keystore_db: Path | None = None,
                 audit_log: Path | None = None,
                 inventory_db: Path | None = None,
                 spool_paths: list[Path] | None = None,
                 plugin_rule_dirs: list[Path] | None = None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    archive_path = out_dir / f"fengarde-backup-{timestamp}.tar.gz"

    not_backed_up: list[str] = []
    manifest: dict = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "fengarde_component": "backup",
        "note": "local state only -- see not_backed_up for what this archive does NOT cover",
        "files": [],
    }

    with tempfile.TemporaryDirectory() as staging_str:
        staging = Path(staging_str)

        if rbac_db is not None:
            _require_file("--rbac-db", rbac_db)
            dest = staging / "rbac" / rbac_db.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            _backup_sqlite(rbac_db, dest)
            _add(manifest, f"rbac/{rbac_db.name}", dest)
        else:
            not_backed_up.append("RBAC DB (FENGARDE_RBAC_DB / --rbac-db not set)")

        if keystore_db is not None:
            _require_file("--keystore-db", keystore_db)
            dest = staging / "keystore" / keystore_db.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            _backup_sqlite(keystore_db, dest)
            _add(manifest, f"keystore/{keystore_db.name}", dest)
        else:
            not_backed_up.append("WS-6 keystore/inventory DB (INVENTORY_KEYSTORE_DB / INVENTORY_DB not set, or :memory:)")

        if inventory_db is not None and not (keystore_db is not None and _same_file(inventory_db, keystore_db)):
            _require_file("--inventory-db", inventory_db)
            dest = staging / "inventory" / inventory_db.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            _backup_sqlite(inventory_db, dest)
            _add(manifest, f"inventory/{inventory_db.name}", dest)

        if audit_log is not None:
            _require_file("--audit-log", audit_log)
            dest = staging / "ws3" / audit_log.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            lock = _audit_lock(audit_log)
            if lock is None:
                print("[WARN] could not take the audit log lock; copying without it "
                      "(stop ws3-indexer first for a consistent copy)", file=sys.stderr)
            try:
                dest.write_bytes(audit_log.read_bytes())  # snapshot taken while the lock is held
            finally:
                if lock is not None:
                    lock.close()
            _add(manifest, f"ws3/{audit_log.name}", dest)
        else:
            not_backed_up.append("WS-3 audit log (FENGARDE_AUDIT_LOG / --audit-log not set)")

        for i, spool in enumerate(spool_paths or []):
            if not spool.is_file():
                not_backed_up.append(f"WS-1 spool {spool} (not present; spools are created on first shed)")
                continue
            dest = staging / "ws1-spool" / str(i) / spool.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(spool.read_bytes())
            _add(manifest, f"ws1-spool/{i}/{spool.name}", dest)

        for i, pdir in enumerate(plugin_rule_dirs or []):
            if not pdir.is_dir():
                raise FileNotFoundError(
                    f"--plugin-rule-dir {pdir} is not a directory -- refusing to create an "
                    f"archive that silently omits a configured plugin rule pack")
            for path in sorted(pdir.rglob("*")):
                if not path.is_file():
                    continue
                rel = f"plugin-rules/{i}-{pdir.name}/{path.relative_to(pdir).as_posix()}"
                dest = staging / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(path.read_bytes())
                _add(manifest, rel, dest)

        if include_contracts:
            contracts_src = ROOT / "contracts"
            for path in sorted(contracts_src.rglob("*")):
                if not path.is_file():
                    continue
                rel_path = path.relative_to(ROOT)  # e.g. contracts/tenants/acme.yml
                dest = staging / rel_path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(path.read_bytes())
                _add(manifest, str(rel_path).replace(os.sep, "/"), dest)
        else:
            not_backed_up.append("contracts/ (--no-contracts)")

        manifest["not_backed_up"] = not_backed_up + list(OUT_OF_SCOPE)
        manifest_path = staging / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(manifest_path, arcname="manifest.json")
            for entry in manifest["files"]:
                tar.add(staging / entry["path"], arcname=entry["path"])

    return archive_path


def _env_paths(*names: str) -> list[str]:
    return [v for v in (os.getenv(n) for n in names) if v]


def _opt_path(value: str | None) -> Path | None:
    # ':memory:' is the WS-6 default, not a file -- never treat it as a path.
    return Path(value) if value and value != ":memory:" else None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True, help="directory to write the backup archive into")
    parser.add_argument("--rbac-db", default=os.getenv("FENGARDE_RBAC_DB"),
                        help="path to the RBAC SQLite DB (default: $FENGARDE_RBAC_DB)")
    parser.add_argument("--inventory-db", default=os.getenv("INVENTORY_DB"),
                        help="path to the WS-6 inventory SQLite DB (default: $INVENTORY_DB)")
    parser.add_argument("--keystore-db", default=None,
                        help="path to the WS-6 API-key SQLite store (default: $INVENTORY_KEYSTORE_DB, "
                             "else the inventory DB, matching ws6-inventory/app.py; ':memory:' is skipped)")
    parser.add_argument("--audit-log", default=os.getenv("FENGARDE_AUDIT_LOG"),
                        help="path to the WS-3 audit JSONL log (default: $FENGARDE_AUDIT_LOG)")
    parser.add_argument("--spool", action="append", default=None,
                        help="WS-1 spool file (repeatable; default: $SYSLOG_SPOOL_PATH, "
                             "$INGEST_HTTP_SPOOL_PATH, $SYSLOG_TCP_SPOOL_PATH)")
    parser.add_argument("--plugin-rule-dir", action="append", default=None,
                        help="plugin rule pack directory (repeatable; default: $FENGARDE_PLUGIN_RULE_DIRS)")
    parser.add_argument("--no-contracts", action="store_true", help="skip bundling contracts/")
    args = parser.parse_args()

    inventory_db = _opt_path(args.inventory_db)
    # Same resolution as ws6-inventory/app.py:37-38 and manage_keys.py:36.
    keystore_db = _opt_path(args.keystore_db or os.getenv("INVENTORY_KEYSTORE_DB") or args.inventory_db)
    spools = [Path(p) for p in (args.spool if args.spool is not None
                                else _env_paths("SYSLOG_SPOOL_PATH", "INGEST_HTTP_SPOOL_PATH",
                                                "SYSLOG_TCP_SPOOL_PATH"))]
    if args.plugin_rule_dir is not None:
        plugin_dirs = [Path(p) for p in args.plugin_rule_dir]
    else:
        plugin_dirs = [Path(p.strip()) for p in os.getenv("FENGARDE_PLUGIN_RULE_DIRS", "").split(os.pathsep)
                       if p.strip()]
    try:
        archive = build_backup(Path(args.out), _opt_path(args.rbac_db),
                               include_contracts=not args.no_contracts,
                               keystore_db=keystore_db, audit_log=_opt_path(args.audit_log),
                               inventory_db=inventory_db, spool_paths=spools,
                               plugin_rule_dirs=plugin_dirs)
    except FileNotFoundError as exc:
        sys.exit(f"[FAIL] backup aborted: {exc}")
    with tarfile.open(archive, "r:gz") as tar:
        member = tar.extractfile("manifest.json")
        manifest = json.loads(member.read()) if member else {}
    print("[WARN] NOT backed up by this archive:", file=sys.stderr)
    for item in manifest.get("not_backed_up", []):
        print(f"  - {item}", file=sys.stderr)
    print(json.dumps({"backup": str(archive), "size_bytes": archive.stat().st_size}))


if __name__ == "__main__":
    main()
