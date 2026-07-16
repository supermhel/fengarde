#!/usr/bin/env python3
"""M4.6 ops lifecycle: restore a backup produced by tools/backup.py.

Verifies every file's sha256 against the archive's manifest.json BEFORE
writing anything to disk (a truncated/corrupted download must never
silently restore partial or wrong data). Refuses to overwrite an existing
file unless --force is given.

Usage:
    python tools/restore.py fengarde-backup-20260716T120000Z.tar.gz --dest ./restored
    python tools/restore.py backup.tar.gz --dest ./restored --force
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
import tempfile
from pathlib import Path


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class RestoreError(Exception):
    pass


def verify_and_restore(archive_path: Path, dest: Path, force: bool = False) -> list[str]:
    """Extract `archive_path` into `dest` after verifying every manifest
    entry's checksum. Returns the list of restored (destination-relative)
    paths. Raises RestoreError on any integrity failure or (without
    --force) an existing-file collision -- nothing is written to `dest`
    until every check has already passed."""
    with tempfile.TemporaryDirectory() as staging_str:
        staging = Path(staging_str)
        with tarfile.open(archive_path, "r:gz") as tar:
            # Path-traversal guard: a hostile/corrupt archive must not be
            # able to write outside the staging directory via "../" entries.
            for member in tar.getmembers():
                target = (staging / member.name).resolve()
                if not str(target).startswith(str(staging.resolve())):
                    raise RestoreError(f"archive entry escapes staging directory: {member.name!r}")
            tar.extractall(staging)  # noqa: S202 -- traversal already checked above

        manifest_path = staging / "manifest.json"
        if not manifest_path.exists():
            raise RestoreError("archive has no manifest.json -- not a valid FENGARDE backup")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        for entry in manifest.get("files", []):
            rel = entry["path"]
            staged_file = staging / rel
            if not staged_file.exists():
                raise RestoreError(f"manifest references missing file: {rel}")
            actual = _sha256(staged_file)
            if actual != entry["sha256"]:
                raise RestoreError(f"checksum mismatch for {rel}: archive is corrupted or tampered")

        if not force:
            for entry in manifest.get("files", []):
                collision = dest / entry["path"]
                if collision.exists():
                    raise RestoreError(
                        f"{collision} already exists -- pass --force to overwrite (nothing written yet)")

        restored: list[str] = []
        for entry in manifest.get("files", []):
            rel = entry["path"]
            src = staging / rel
            dst = dest / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(src.read_bytes())
            restored.append(rel)
        return restored


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("archive", help="path to a fengarde-backup-*.tar.gz produced by tools/backup.py")
    parser.add_argument("--dest", required=True, help="directory to restore into")
    parser.add_argument("--force", action="store_true", help="overwrite existing files at the destination")
    args = parser.parse_args()

    try:
        restored = verify_and_restore(Path(args.archive), Path(args.dest), force=args.force)
    except RestoreError as exc:
        sys.exit(f"restore failed, nothing written: {exc}")
    print(json.dumps({"restored": restored, "dest": args.dest}))


if __name__ == "__main__":
    main()
