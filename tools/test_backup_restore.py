"""M4.6 ops lifecycle: end-to-end backup/restore tests.

Exercises the REAL tools/backup.py + tools/restore.py against a real SQLite
RBAC DB and this repo's actual contracts/ directory -- no mocking of the
tar/sqlite/hashing machinery, only the destination directories are
temporary.

Run: python tools/test_backup_restore.py
"""
from __future__ import annotations

import io
import sqlite3
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "services"))

import backup  # noqa: E402
import restore  # noqa: E402
from shared.users import UserStore  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _make_rbac_db(path: Path) -> None:
    store = UserStore(str(path))
    store.create_user("ops_admin", "correct-horse-battery-staple", role="admin", tenant_id="default")
    store.db.close()


def test_full_round_trip_rbac_and_contracts():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        db_path = d / "users.db"
        _make_rbac_db(db_path)

        out_dir = d / "backups"
        archive = backup.build_backup(out_dir, rbac_db=db_path, include_contracts=True)
        check(archive.exists(), "backup must produce a real archive file")
        check(archive.name.startswith("fengarde-backup-") and archive.name.endswith(".tar.gz"),
              f"archive must follow the documented naming convention, got {archive.name}")

        with tarfile.open(archive, "r:gz") as tar:
            names = tar.getnames()
        check("manifest.json" in names, "the archive must contain manifest.json")
        check(any(n.startswith("rbac/") for n in names), "the archive must contain the RBAC DB backup")
        check(any(n.startswith("contracts/rules/") for n in names),
              "the archive must contain real contracts/rules/*.yml files")

        dest = d / "restored"
        restored = restore.verify_and_restore(archive, dest, force=False)
        check(len(restored) == len(names) - 1,  # -1 for manifest.json itself, not a manifest entry
              f"every manifest entry must have been restored, got {len(restored)} of {len(names) - 1}")

        restored_db = dest / "rbac" / "users.db"
        check(restored_db.exists(), "the restored RBAC DB file must exist at dest")
        conn = sqlite3.connect(str(restored_db))
        row = conn.execute("SELECT username, role, tenant_id FROM users WHERE username = ?",
                            ("ops_admin",)).fetchone()
        conn.close()
        check(row == ("ops_admin", "admin", "default"),
              f"the restored DB must contain the exact same user row, got {row}")

        original_rule = (ROOT / "contracts" / "rules" / "common_bruteforce.yml").read_bytes()
        restored_rule = (dest / "contracts" / "rules" / "common_bruteforce.yml").read_bytes()
        check(original_rule == restored_rule, "a restored contract file must be byte-identical to the source")


def test_no_rbac_db_backs_up_contracts_only():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        archive = backup.build_backup(d / "backups", rbac_db=None, include_contracts=True)
        with tarfile.open(archive, "r:gz") as tar:
            names = tar.getnames()
        check(not any(n.startswith("rbac/") for n in names),
              "with no rbac_db given, the archive must not contain an rbac/ entry")
        check(any(n.startswith("contracts/") for n in names), "contracts/ must still be backed up")


def test_tampered_checksum_is_rejected_before_writing_anything():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        db_path = d / "users.db"
        _make_rbac_db(db_path)
        archive = backup.build_backup(d / "backups", rbac_db=db_path, include_contracts=False)

        # Rebuild the archive with a manifest whose checksum is deliberately wrong.
        tampered = d / "tampered.tar.gz"
        with tarfile.open(archive, "r:gz") as src_tar:
            manifest = src_tar.extractfile("manifest.json").read()
            import json
            manifest_obj = json.loads(manifest)
            manifest_obj["files"][0]["sha256"] = "0" * 64  # wrong on purpose
            new_manifest = json.dumps(manifest_obj).encode()

            with tarfile.open(tampered, "w:gz") as dst_tar:
                info = tarfile.TarInfo("manifest.json")
                info.size = len(new_manifest)
                dst_tar.addfile(info, io.BytesIO(new_manifest))
                for member in src_tar.getmembers():
                    if member.name == "manifest.json":
                        continue
                    dst_tar.addfile(member, src_tar.extractfile(member))

        dest = d / "restored_tampered"
        raised = False
        try:
            restore.verify_and_restore(tampered, dest, force=False)
        except restore.RestoreError:
            raised = True
        check(raised, "a tampered/corrupted archive must be rejected with RestoreError")
        check(not dest.exists() or not any(dest.rglob("*")),
              "nothing must be written to dest when checksum verification fails")


def test_collision_requires_force():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        db_path = d / "users.db"
        _make_rbac_db(db_path)
        archive = backup.build_backup(d / "backups", rbac_db=db_path, include_contracts=False)

        dest = d / "restored"
        restore.verify_and_restore(archive, dest, force=False)  # first restore: fine

        raised = False
        try:
            restore.verify_and_restore(archive, dest, force=False)  # second: collision
        except restore.RestoreError:
            raised = True
        check(raised, "restoring into an already-populated dest without --force must be rejected")

        # With --force it must succeed (overwrite).
        restored = restore.verify_and_restore(archive, dest, force=True)
        check(len(restored) > 0, "restoring with --force must succeed and overwrite")


def test_path_traversal_in_archive_is_rejected():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        malicious = d / "evil.tar.gz"
        payload = b'{"files": []}'
        with tarfile.open(malicious, "w:gz") as tar:
            manifest_info = tarfile.TarInfo("manifest.json")
            manifest_info.size = len(payload)
            tar.addfile(manifest_info, io.BytesIO(payload))
            evil_info = tarfile.TarInfo("../../evil.txt")
            evil_info.size = 4
            tar.addfile(evil_info, io.BytesIO(b"evil"))

        raised = False
        try:
            restore.verify_and_restore(malicious, d / "dest", force=False)
        except restore.RestoreError:
            raised = True
        check(raised, "an archive entry attempting to escape the staging directory must be rejected")


def test_symlink_member_escaping_staging_is_rejected():
    """F4 regression (adversarial repo-wide bug hunt, 2026-07-16): the
    original path-traversal guard only checked each member's NAME resolves
    inside staging -- it did not stop a SYMLINK member. A symlink member's
    own name resolves harmlessly inside staging (nothing has been
    extracted yet when the name is checked), but a LATER member written
    THROUGH that symlink during extraction can still escape outside
    staging entirely (the classic CVE-2007-4559 tar class). This proves
    the fix (filter="data") rejects the symlink itself, before any member
    -- through it or otherwise -- is ever written."""
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        malicious = d / "evil_symlink.tar.gz"
        payload = b'{"files": []}'
        outside_target = d / "outside_marker"  # would be the escape target

        with tarfile.open(malicious, "w:gz") as tar:
            manifest_info = tarfile.TarInfo("manifest.json")
            manifest_info.size = len(payload)
            tar.addfile(manifest_info, io.BytesIO(payload))

            # A symlink member pointing OUTSIDE the eventual staging dir.
            link_info = tarfile.TarInfo("escape_link")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = str(outside_target)
            tar.addfile(link_info)

            # A file written "through" that symlink, if the extractor
            # followed it -- this is the actual escape payload.
            through_info = tarfile.TarInfo("escape_link")
            through_info.size = 4
            tar.addfile(through_info, io.BytesIO(b"evil"))

        raised = False
        try:
            restore.verify_and_restore(malicious, d / "dest", force=False)
        except restore.RestoreError:
            raised = True
        check(raised, "a symlink member must be rejected by the extraction filter")
        check(not outside_target.exists(),
              "nothing must ever be written through the symlink to the outside target")


def main():
    test_full_round_trip_rbac_and_contracts()
    test_no_rbac_db_backs_up_contracts_only()
    test_tampered_checksum_is_rejected_before_writing_anything()
    test_collision_requires_force()
    test_path_traversal_in_archive_is_rejected()
    test_symlink_member_escaping_staging_is_rejected()

    if FAILS:
        print(f"[FAIL] backup/restore: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] M4.6 backup/restore: real RBAC SQLite DB + real contracts/ round-trip "
          "byte-identical, checksum tampering rejected before any write, restore collision "
          "requires --force, path-traversal archive entries rejected")


if __name__ == "__main__":
    main()
