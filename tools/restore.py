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
import os
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath, PureWindowsPath


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class RestoreError(Exception):
    pass


_SQLITE_MAGIC = b"SQLite format 3\x00"
_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


def _is_sqlite(path: Path) -> bool:
    with open(path, "rb") as f:
        return f.read(16) == _SQLITE_MAGIC


def _sidecars(dst: Path) -> list[Path]:
    """Leftover SQLite WAL/journal files beside `dst`. Replacing only the main
    file under a stale -wal makes SQLite replay post-backup pages into the
    restored DB (live-reproduced: restored rows != backup rows)."""
    return [p for p in (Path(str(dst) + sfx) for sfx in _SIDECAR_SUFFIXES) if p.exists()]


def _safe_join(base: Path, rel: str) -> Path:
    """Join `rel` onto `base`, refusing anything that would escape it.

    The tar-extraction step is defended by ``filter="data"`` (PEP 706), but
    every path built from ``manifest.json`` afterward is a second,
    independent join from JSON content the archive controls -- an absolute
    ``rel`` silently discards `base` when joined with pathlib, and a ``..``
    component walks out of it, same threat class as the tar-member vector.
    """
    # PR #167 review: on Windows `C:evil.txt` (drive-relative) and `/abs/x`
    # (rooted, no drive) are not is_absolute() but still leave `base`; check
    # drive/root under BOTH path flavours so the guard is OS-independent.
    if not isinstance(rel, str) or not rel:
        raise RestoreError(f"manifest entry path is not a non-empty string: {rel!r}")
    for flavour in (PurePosixPath(rel), PureWindowsPath(rel)):
        if flavour.drive or flavour.root or ".." in flavour.parts:
            raise RestoreError(f"manifest entry path escapes the archive root: {rel!r}")
    return base / rel


def verify_and_restore(archive_path: Path, dest: Path, force: bool = False) -> tuple[list[str], str]:
    """Extract `archive_path` into `dest` after verifying every manifest
    entry's checksum. Returns the list of restored (destination-relative)
    paths. Raises RestoreError on any integrity failure or (without
    --force) an existing-file collision -- nothing is written to `dest`
    until every check has already passed."""
    with tempfile.TemporaryDirectory() as staging_str:
        staging = Path(staging_str)
        try:
            tar_cm = tarfile.open(archive_path, "r:gz")
        except (OSError, tarfile.TarError, EOFError) as exc:
            # PR #167 review: a non-gzip/truncated archive crashed with a traceback.
            raise RestoreError(f"cannot read {archive_path} as a .tar.gz backup: {exc}") from exc
        with tar_cm as tar:
            # filter="data" (PEP 706) rejects absolute paths, ".."
            # traversal, AND symlink/hardlink members pointing outside the
            # extraction root -- a name-only "does the resolved path start
            # with staging" check (the previous guard here) does NOT catch
            # a symlink member: the symlink's own name resolves harmlessly
            # inside staging, but a LATER member written *through* it can
            # still escape (the classic CVE-2007-4559 tar class), because
            # nothing has actually been extracted yet when the name is
            # checked. filter="data" also strips high-risk permission bits
            # and rejects device/fifo members. Available since Python
            # 3.11.4/3.10.12/3.9.17 and unconditional in 3.12+ (every
            # Dockerfile in this repo runs 3.12 or 3.13).
            try:
                tar.extractall(staging, filter="data")
            except tarfile.FilterError as exc:
                raise RestoreError(f"archive entry rejected by extraction filter: {exc}") from exc
            except (OSError, tarfile.TarError, EOFError) as exc:
                raise RestoreError(f"archive is corrupt or truncated: {exc}") from exc

        manifest_path = staging / "manifest.json"
        if not manifest_path.exists():
            raise RestoreError("archive has no manifest.json -- not a valid FENGARDE backup")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise RestoreError(f"manifest.json is not valid JSON: {exc}") from exc
        if not isinstance(manifest, dict):
            raise RestoreError("manifest.json is not a JSON object")

        files = manifest.get("files", [])
        if not isinstance(files, list) or not all(
                isinstance(e, dict) and isinstance(e.get("path"), str) and isinstance(e.get("sha256"), str)
                for e in files):
            raise RestoreError("manifest.json 'files' must be a list of {path, sha256} entries")
        # Gap-hunt (2026-08-26) R4-110: an empty/absent "files" list used to
        # make the restore loop below a silent no-op (nothing restored, exit 0)
        # -- the natural second half of R4-101's empty backup. A backup with
        # nothing to restore is a broken/empty archive, not a success.
        if not files:
            raise RestoreError(
                "manifest declares zero files -- nothing to restore. This archive "
                "is empty or malformed (see R4-101: a missing --rbac-db backup "
                "produces exactly this shape). Refusing to report a false success.")

        for entry in files:
            rel = entry["path"]
            staged_file = _safe_join(staging, rel)
            if not staged_file.is_file():  # a directory entry crashed _sha256 (PR #167 review)
                raise RestoreError(f"manifest references missing file: {rel}")
            actual = _sha256(staged_file)
            if actual != entry["sha256"]:
                raise RestoreError(
                    f"checksum mismatch for {rel}: archive is corrupted. The manifest travels "
                    f"inside the archive, so this check detects corruption, not deliberate "
                    f"tampering -- verify the archive's provenance separately")

        if not force:
            for entry in files:
                collision = _safe_join(dest, entry["path"])
                if collision.exists():
                    raise RestoreError(
                        f"{collision} already exists -- pass --force to overwrite (nothing written yet)")
                if _is_sqlite(_safe_join(staging, entry["path"])):
                    for leftover in _sidecars(collision):
                        raise RestoreError(
                            f"{leftover} is a leftover SQLite sidecar -- pass --force to delete it "
                            f"(restoring under a stale WAL would mix in post-backup data; nothing written yet)")

        restored: list[str] = []
        for entry in files:
            rel = entry["path"]
            src = _safe_join(staging, rel)
            dst = _safe_join(dest, rel)
            dst.parent.mkdir(parents=True, exist_ok=True)
            if _is_sqlite(src):
                for leftover in _sidecars(dst):
                    leftover.unlink()
            # PR #167 review: write beside dst and rename, so an interrupted
            # restore never leaves a half-written file under the real name;
            # owner-only because these are password-hash/API-key stores.
            tmp = dst.with_name(dst.name + ".restore-tmp")
            tmp.write_bytes(src.read_bytes())
            os.chmod(tmp, 0o600)
            os.replace(tmp, dst)
            restored.append(rel)
        return restored, str(manifest.get("fengarde_release", "unknown"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("archive", help="path to a fengarde-backup-*.tar.gz produced by tools/backup.py")
    parser.add_argument("--dest", required=True, help="directory to restore into")
    parser.add_argument("--force", action="store_true", help="overwrite existing files at the destination")
    args = parser.parse_args()

    try:
        restored, release = verify_and_restore(Path(args.archive), Path(args.dest), force=args.force)
    except RestoreError as exc:
        sys.exit(f"restore failed, nothing written: {exc}")
    print(f"[NOTE] this backup was taken on FENGARDE release {release}; restore it only "
          f"under that release's images (docs/upgrade.md, rollback).", file=sys.stderr)
    dest_abs = Path(args.dest).resolve()
    landed = [str(dest_abs / r) for r in restored]
    print("[NOTE] files were written UNDER --dest by archive folder (rbac/, keystore/, inventory/, "
          "ws3/, ws1-spool/, plugin-rules/, contracts/), NOT to your configured FENGARDE_*/INVENTORY_* "
          "paths. Copy each into place (stopped stack) -- see docs/upgrade.md.", file=sys.stderr)
    print(json.dumps({"restored": restored, "dest": args.dest, "landed": landed, "fengarde_release": release}))


if __name__ == "__main__":
    main()
