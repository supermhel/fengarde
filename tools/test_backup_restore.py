"""M4.6 ops lifecycle: end-to-end backup/restore tests.

Exercises the REAL tools/backup.py + tools/restore.py against a real SQLite
RBAC DB and this repo's actual contracts/ directory -- no mocking of the
tar/sqlite/hashing machinery, only the destination directories are
temporary.

Run: python tools/test_backup_restore.py
"""
from __future__ import annotations

import io
import json
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
        restored, _release = restore.verify_and_restore(archive, dest, force=False)
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


def test_full_round_trip_all_non_docker_stores():
    """WP-3.3: every local store that runs WITHOUT Docker, one archive.

    RBAC DB + WS-6 inventory keystore (both hot-snapshotted sqlite) + WS-3
    audit JSONL + contracts/ travel in one backup; each store is then
    MUTATED in place (a user deleted, a key revoked, audit lines appended)
    and the restore must bring back the ORIGINAL state -- the exact
    backup-then-restore the operator runs before an upgrade/rollback."""
    import json as _json
    import os as _os
    _os.environ["FENGARDE_API_KEY_PEPPER"] = "test-pepper-backup-roundtrip"
    WS6 = ROOT / "services" / "ws6-inventory"
    sys.path.insert(0, str(WS6))
    from keystore import TenantKeyStore  # noqa: E402

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        db_path = d / "users.db"
        _make_rbac_db(db_path)

        keystore_path = d / "keystore.db"
        ks = TenantKeyStore(str(keystore_path))
        ks.provision("acme", "acme-secret-0", source="test")
        ks.db.close()

        audit_path = d / "audit.jsonl"
        audit_lines = [
            _json.dumps({"ts": 1, "actor": "ops", "action": "boot"}),
            _json.dumps({"ts": 2, "actor": "ops", "action": "login"}),
        ]
        audit_path.write_text("\n".join(audit_lines) + "\n", encoding="utf-8")
        original_audit = audit_path.read_bytes()

        archive = backup.build_backup(
            d / "backups", rbac_db=db_path, include_contracts=True,
            keystore_db=keystore_path, audit_log=audit_path)
        with tarfile.open(archive, "r:gz") as tar:
            names = tar.getnames()
        check(any(n.startswith("keystore/") for n in names),
              "the archive must contain the WS-6 keystore backup")
        check(any(n.startswith("ws3/") for n in names),
              "the archive must contain the WS-3 audit log backup")

        # ---- mutate ALL local stores as if time passed / disaster struck ----
        import sqlite3 as _s
        sql = _s.connect(str(db_path))
        sql.execute("DELETE FROM users WHERE username='ops_admin'")
        sql.commit(); sql.close()
        ks2 = _s.connect(str(keystore_path))
        ks2.execute("DELETE FROM api_keys WHERE tenant_id='acme'")
        ks2.commit(); ks2.close()
        audit_path.write_bytes(audit_path.read_bytes() + b'{"ts": 3, "mutated": true}\n')
        # (contracts/ are in git, never mutated)

        # ---- restore from the pre-mutation backup ----
        dest = d / "restored"
        restored, _release = restore.verify_and_restore(archive, dest, force=False)
        check(len(restored) == len(names) - 1,
              f"every manifest entry restored, got {len(restored)} of {len(names) - 1}")

        conn = _s.connect(str(dest / "rbac" / "users.db"))
        row = conn.execute("SELECT username, role, tenant_id FROM users "
                           "WHERE username='ops_admin'").fetchone()
        conn.close()
        check(row == ("ops_admin", "admin", "default"),
              f"restored RBAC DB must have the ORIGINAL user back, got {row}")

        ksr = TenantKeyStore(str(dest / "keystore" / keystore_path.name))
        ok, tenant, _scope = ksr.verify("acme-secret-0")
        check(ok and tenant == "acme",
              f"restored keystore must verify the ORIGINAL key, ok={ok} tenant={tenant}")
        ksr.db.close()

        restored_audit = (dest / "ws3" / audit_path.name).read_bytes()
        check(restored_audit == original_audit,
              "restored audit log must be the ORIGINAL bytes, not the mutated file")

        original_rule = (ROOT / "contracts" / "rules" / "common_bruteforce.yml").read_bytes()
        check((dest / "contracts" / "rules" / "common_bruteforce.yml").read_bytes()
              == original_rule, "restored contracts must be byte-identical")


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
        restored, _release = restore.verify_and_restore(archive, dest, force=True)
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


# ---------------------------------------------------------------------------
# PR #167 review-fix regressions (findings 1-6). Each was reproduced FAILING
# on 78392d0 before the fix in backup.py / restore.py / docs/upgrade.md.
# ---------------------------------------------------------------------------
import os  # noqa: E402
import subprocess  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402

BACKUP_PY = HERE / "backup.py"
RESTORE_PY = HERE / "restore.py"
_STORE_ENV = ("FENGARDE_RBAC_DB", "INVENTORY_DB", "INVENTORY_KEYSTORE_DB", "FENGARDE_AUDIT_LOG",
              "SYSLOG_SPOOL_PATH", "INGEST_HTTP_SPOOL_PATH", "SYSLOG_TCP_SPOOL_PATH",
              "FENGARDE_PLUGIN_RULE_DIRS")


def _cli(script: Path, args: list[str], env_extra: dict[str, str] | None = None):
    env = {k: v for k, v in os.environ.items() if k not in _STORE_ENV}
    env.update(env_extra or {})
    return subprocess.run([sys.executable, str(script), *args], capture_output=True,
                          text=True, env=env, timeout=120)


def _archive_names(archive: Path) -> list[str]:
    with tarfile.open(archive, "r:gz") as tar:
        return tar.getnames()


def _out_archive(out: Path) -> Path:
    found = sorted(out.glob("fengarde-backup-*.tar.gz"))
    return found[-1] if found else out / "MISSING"


def _make_inventory_db(path: Path) -> None:
    c = sqlite3.connect(str(path))
    c.execute("CREATE TABLE assets (id TEXT)")
    c.execute("INSERT INTO assets VALUES ('host-1')")
    c.commit()
    c.close()


def test_f2_inventory_db_default_covers_keystore_and_inventory():
    """Finding 2: INVENTORY_KEYSTORE_DB defaults to INVENTORY_DB (app.py:37-38,
    manage_keys.py:36). With only INVENTORY_DB set the CLI used to exit 0 with
    an archive that held neither the keystore nor the inventory data."""
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        inv = d / "inventory.db"
        _make_inventory_db(inv)
        r = _cli(BACKUP_PY, ["--out", str(d / "o"), "--no-contracts"], {"INVENTORY_DB": str(inv)})
        check(r.returncode == 0, f"F2: backup with INVENTORY_DB only must succeed, rc={r.returncode} {r.stderr}")
        names = _archive_names(_out_archive(d / "o")) if r.returncode == 0 else []
        check("keystore/inventory.db" in names,
              f"F2: INVENTORY_DB alone must be backed up (keystore falls back to it), got {names}")


def test_f2_separate_keystore_and_inventory_both_backed_up():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        inv, ks = d / "inventory.db", d / "keys.db"
        _make_inventory_db(inv)
        _make_inventory_db(ks)
        r = _cli(BACKUP_PY, ["--out", str(d / "o"), "--no-contracts"],
                 {"INVENTORY_DB": str(inv), "INVENTORY_KEYSTORE_DB": str(ks)})
        names = _archive_names(_out_archive(d / "o")) if r.returncode == 0 else []
        check("keystore/keys.db" in names and "inventory/inventory.db" in names,
              f"F2: distinct keystore + inventory files must BOTH be archived, rc={r.returncode} got {names}")


def test_f2_missing_inventory_db_fails_closed_nonzero():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        r = _cli(BACKUP_PY, ["--out", str(d / "o"), "--no-contracts"],
                 {"INVENTORY_DB": str(d / "does-not-exist.db")})
        check(r.returncode != 0, "F2: a configured-but-missing INVENTORY_DB must abort non-zero")
        check(not list((d / "o").glob("*.tar.gz")), "F2: no archive may be left behind on abort")


def test_f2_unconfigured_stores_are_declared_not_silent():
    """Nothing configured: contracts-only is allowed, but the archive and
    stderr must SAY which stores were not covered."""
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        r = _cli(BACKUP_PY, ["--out", str(d / "o")])
        check(r.returncode == 0, f"F2: contracts-only backup still works, rc={r.returncode} {r.stderr}")
        check("NOT backed up" in r.stderr and "RBAC" in r.stderr,
              f"F2: stderr must list unconfigured stores, got {r.stderr!r}")
        arc = _out_archive(d / "o")
        if arc.exists():
            with tarfile.open(arc, "r:gz") as tar:
                m = json.loads(tar.extractfile("manifest.json").read())
            check(any("rbac" in x.lower() for x in m.get("not_backed_up", [])),
                  f"F2: manifest.not_backed_up must name the RBAC DB, got {m.get('not_backed_up')}")


def test_f2_docs_no_invented_keystore_fallback():
    text = (ROOT / "docs" / "upgrade.md").read_text(encoding="utf-8")
    check("/data/keystore.db" not in text,
          "F2: docs/upgrade.md must not name the invented /data/keystore.db fallback")


def test_f1_runbook_documents_volume_extraction_and_untested_status():
    text = (ROOT / "docs" / "upgrade.md").read_text(encoding="utf-8")
    check("docker run --rm" in text and "-v" in text,
          "F1: runbook must document extracting named-volume stores before running backup.py")
    check("untested" in text.lower() or "not been run" in text.lower(),
          "F1: runbook must state plainly the compose volume steps were not run")


def test_f3_spools_and_plugin_rule_dirs_backed_up_and_scope_listed():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        spool = d / "udp.jsonl"
        spool.write_text('{"raw": "a"}\n', encoding="utf-8")
        tcp_missing = d / "tcp.jsonl"  # configured but never created: spool is lazy
        pdir = d / "packs"
        (pdir / "sub").mkdir(parents=True)
        (pdir / "sub" / "r.yml").write_text("id: x\n", encoding="utf-8")
        r = _cli(BACKUP_PY, ["--out", str(d / "o"), "--no-contracts"],
                 {"SYSLOG_SPOOL_PATH": str(spool), "SYSLOG_TCP_SPOOL_PATH": str(tcp_missing),
                  "FENGARDE_PLUGIN_RULE_DIRS": str(pdir)})
        check(r.returncode == 0, f"F3: rc={r.returncode} {r.stderr}")
        arc = _out_archive(d / "o")
        names = _archive_names(arc) if arc.exists() else []
        check(any(n.startswith("ws1-spool/") and n.endswith("udp.jsonl") for n in names),
              f"F3: configured WS-1 spool file must be archived, got {names}")
        check(any(n.startswith("plugin-rules/") and n.endswith("sub/r.yml") for n in names),
              f"F3: plugin rule dir contents must be archived, got {names}")
        if arc.exists():
            with tarfile.open(arc, "r:gz") as tar:
                m = json.loads(tar.extractfile("manifest.json").read())
            nb = " | ".join(m.get("not_backed_up", []))
            check("tcp.jsonl" in nb, f"F3: absent spool must be listed as not backed up, got {nb!r}")
            for needle in ("Redis", "OpenSearch", "GEOIP"):
                check(needle.lower() in nb.lower(),
                      f"F3: out-of-scope list must name {needle}, got {nb!r}")


def _wal_db_with_stale_sidecars(dest_db: Path) -> None:
    """Leave `dest_db` holding the ORIGINAL (1 row) main file next to a
    -wal/-shm that carry a later row -- what a crashed/killed service leaves."""
    dest_db.parent.mkdir(parents=True, exist_ok=True)
    live = dest_db.parent.parent / "_live.db"
    c = sqlite3.connect(str(live))
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA wal_autocheckpoint=0")
    c.execute("CREATE TABLE t (v TEXT)")
    c.execute("INSERT INTO t VALUES ('orig')")
    c.commit()
    c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    c.execute("INSERT INTO t VALUES ('post-backup')")
    c.commit()
    dest_db.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(live) + suffix)
        if src.exists():
            Path(str(dest_db) + suffix).write_bytes(src.read_bytes())
    c.close()


def test_f4_restore_removes_stale_wal_sidecars():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        src = d / "src.db"
        c = sqlite3.connect(str(src))
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("CREATE TABLE t (v TEXT)")
        c.execute("INSERT INTO t VALUES ('orig')")
        c.commit()
        c.close()
        archive = backup.build_backup(d / "b", rbac_db=src, include_contracts=False)
        dest = d / "restored"
        target = dest / "rbac" / "src.db"
        _wal_db_with_stale_sidecars(target)
        check(Path(str(target) + "-wal").exists(), "F4: test setup must leave a -wal")

        raised = False
        try:
            restore.verify_and_restore(archive, dest, force=False)
        except restore.RestoreError:
            raised = True
        check(raised, "F4: collision/sidecar without --force must be refused")

        restore.verify_and_restore(archive, dest, force=True)
        conn = sqlite3.connect(str(target))
        rows = sorted(r[0] for r in conn.execute("SELECT v FROM t"))
        conn.close()
        check(rows == ["orig"], f"F4: restored DB must be exactly the backup, stale WAL leaked: {rows}")
        for suffix in ("-wal", "-shm"):
            check(not Path(str(target) + suffix).exists(),
                  f"F4: stale {suffix} must be removed on --force restore")


def test_f4_sidecar_without_main_file_blocks_unforced_restore():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        src = d / "src.db"
        _make_inventory_db(src)
        archive = backup.build_backup(d / "b", rbac_db=src, include_contracts=False)
        dest = d / "restored"
        (dest / "rbac").mkdir(parents=True)
        (dest / "rbac" / "src.db-wal").write_bytes(b"leftover")
        raised = False
        try:
            restore.verify_and_restore(archive, dest, force=False)
        except restore.RestoreError:
            raised = True
        check(raised, "F4: a leftover -wal beside a missing main file must block an unforced restore")
        check(not (dest / "rbac" / "src.db").exists(), "F4: nothing written when refused")


def test_f4_cli_reports_where_files_landed():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        src = d / "src.db"
        _make_inventory_db(src)
        archive = backup.build_backup(d / "b", rbac_db=src, include_contracts=False)
        r = _cli(RESTORE_PY, [str(archive), "--dest", str(d / "r")])
        check(r.returncode == 0, f"F4: restore CLI rc={r.returncode} {r.stderr}")
        out = json.loads(r.stdout) if r.returncode == 0 else {}
        landed = out.get("landed", [])
        check(any(Path(p) == (d / "r" / "rbac" / "src.db").resolve() for p in landed),
              f"F4: CLI must print absolute landing paths (not configured paths), got {landed}")
        check("configured" in r.stderr.lower(),
              f"F4: CLI must say files are NOT placed at configured paths, stderr={r.stderr!r}")


def test_f5_audit_copy_waits_for_the_audit_lock():
    """Finding 5: backup copied audit.jsonl without taking audit.py's
    cross-process .lock, so it could capture a torn append / mid-trim file."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("_audit_probe", ROOT / "services" / "ws3-indexer" / "audit.py")
    assert spec and spec.loader
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        log = d / "audit.jsonl"
        log.write_bytes(b'{"ts": 1}\n')
        lock = audit._acquire_cross_process_lock(str(log))
        if lock is None:
            check(False, "F5: test could not take the audit lock on this platform")
            return
        result: dict = {}

        def run():
            result["archive"] = backup.build_backup(d / "b", rbac_db=None, include_contracts=False, audit_log=log)

        t = threading.Thread(target=run)
        t.start()
        time.sleep(0.6)
        blocked = t.is_alive()
        log.write_bytes(b'{"ts": 1}\n{"ts": 2}\n')  # the "append" finishes under the lock
        lock.close()
        t.join(timeout=30)
        check(blocked, "F5: backup must block while another process holds the audit lock")
        if "archive" in result:
            with tarfile.open(result["archive"], "r:gz") as tar:
                got = tar.extractfile("ws3/audit.jsonl").read()
            check(got == b'{"ts": 1}\n{"ts": 2}\n',
                  f"F5: backup must see the post-append file after the lock is released, got {got!r}")
        else:
            check(False, "F5: backup did not finish after the lock was released")


def test_f6_percent_in_sqlite_path():
    # '%41' is the repro: sqlite's URI parser decodes it to 'A' (or errors) when
    # the path is not percent-encoded. ('#' alone happened to mask the bug, so
    # each odd character gets its own directory.)
    for name in ("dir%41pct", "a%20b", "hash#dir", "sp ace"):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            weird = d / name
            weird.mkdir()
            db = weird / "users.db"
            _make_inventory_db(db)
            try:
                archive = backup.build_backup(d / "b", rbac_db=db, include_contracts=False)
            except Exception as exc:  # noqa: BLE001 - the regression IS "this raised"
                check(False, f"F6: {name!r} in a sqlite path must not break backup: {type(exc).__name__}: {exc}")
                continue
            check("rbac/users.db" in _archive_names(archive), f"F6: {name!r} DB must be archived")


def _archive_with_manifest(path: Path, manifest_bytes: bytes, extra: dict | None = None) -> Path:
    with tarfile.open(path, "w:gz") as tar:
        for name, data in [("manifest.json", manifest_bytes)] + list((extra or {}).items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def test_pr167_second_review_edges():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        # path guard holds for Windows drive-relative / rooted names on every OS
        for bad in ("C:evil.txt", "/abs/x", "\\abs\\x", "C:\\x", "a/../../x", "..\\x"):
            try:
                restore._safe_join(d, bad)
                check(False, f"_safe_join accepted {bad!r}")
            except restore.RestoreError:
                pass
        check(restore._safe_join(d, "rbac/users.db") == d / "rbac/users.db", "normal path rejected")

        # malformed archives -> RestoreError, never a traceback
        (d / "notgz.tar.gz").write_bytes(b"this is not gzip")
        cases = {
            "non-gzip": d / "notgz.tar.gz",
            "bad json": _archive_with_manifest(d / "badjson.tar.gz", b"{not json"),
            "manifest list": _archive_with_manifest(d / "list.tar.gz", b"[1, 2]"),
            "entry no sha": _archive_with_manifest(
                d / "nosha.tar.gz", json.dumps({"files": [{"path": "a"}]}).encode(), {"a": b"x"}),
            "entry is a dir": _archive_with_manifest(
                d / "dir.tar.gz", json.dumps({"files": [{"path": "sub", "sha256": "0" * 64}]}).encode(),
                {"sub/x": b"x"}),
        }
        for name, arc in cases.items():
            try:
                restore.verify_and_restore(arc, d / f"dest-{name.replace(' ', '_')}")
                check(False, f"{name}: restore must fail")
            except restore.RestoreError:
                pass
            except Exception as exc:  # noqa: BLE001
                check(False, f"{name}: raised {type(exc).__name__} instead of RestoreError: {exc}")

        # non-SQLite DB -> clear ValueError (main() reports it), not a sqlite3 traceback
        fake = d / "fake.db"
        fake.write_bytes(b"definitely not sqlite " * 10)
        try:
            backup.build_backup(d / "out-fake", fake, include_contracts=False)
            check(False, "non-SQLite --rbac-db must abort")
        except ValueError:
            pass
        except Exception as exc:  # noqa: BLE001
            check(False, f"non-SQLite DB raised {type(exc).__name__}: {exc}")

        # two backups in the same second get distinct names; release + .dead recorded
        db = d / "users.db"
        _make_rbac_db(db)
        spool = d / "http-spool.jsonl"
        spool.write_text('{"key":"k"}\n', encoding="utf-8")
        spool.with_name(spool.name + ".dead").write_text('{"key":"poison"}\n', encoding="utf-8")
        out = d / "out"
        a1 = backup.build_backup(out, db, include_contracts=False, spool_paths=[spool])
        a2 = backup.build_backup(out, db, include_contracts=False, spool_paths=[spool])
        check(a1 != a2 and a1.exists() and a2.exists(), f"same-second backups collided: {a1} {a2}")
        names = _archive_names(a1)
        check("ws1-spool/0/http-spool.jsonl.dead" in names, f".dead sidecar missing: {names}")
        restored, release = restore.verify_and_restore(a1, d / "dest-ok")
        check(isinstance(release, str) and release, f"release not recorded: {release!r}")
        check("ws1-spool/0/http-spool.jsonl.dead" in restored, ".dead not restored")
        check(not list((d / "dest-ok").rglob("*.restore-tmp")), "restore left temp files")

        # owner-only permissions: archive and restored stores hold password
        # hashes and API keys. Only meaningful on POSIX (CI runs Linux); on
        # Windows chmod only toggles read-only, so the check is skipped there.
        if os.name == "posix":
            import stat
            mode = stat.S_IMODE(a1.stat().st_mode)
            check(mode == 0o600, f"backup archive mode {oct(mode)} != 0o600")
            for rel in restored:
                m = stat.S_IMODE((d / "dest-ok" / rel).stat().st_mode)
                check(m == 0o600, f"restored {rel} mode {oct(m)} != 0o600")


def test_pr167_third_review_fixes():
    import os

    # 2. unreadable source -> clean "[FAIL] backup aborted" + non-zero, no traceback
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        db = d / "users.db"
        _make_rbac_db(db)
        real = backup._backup_sqlite

        def boom(src, dest):
            raise PermissionError(13, "Permission denied", str(src))
        backup._backup_sqlite = boom
        argv = sys.argv
        sys.argv = ["backup.py", "--out", str(d / "out"), "--rbac-db", str(db), "--no-contracts"]
        try:
            backup.main()
            msg, code = None, 0
        except SystemExit as exc:
            msg, code = str(exc.code), exc.code
        except BaseException as exc:  # noqa: BLE001 - a raw traceback is the bug
            msg, code = f"RAW {type(exc).__name__}", 99
        finally:
            backup._backup_sqlite = real
            sys.argv = argv
        check(isinstance(code, str) and code.startswith("[FAIL] backup aborted"),
              f"unreadable source must exit with a clean [FAIL] message, got {msg!r}")
        check(msg is not None and "users.db" in msg and "chown" in msg,
              f"message must name the file and suggest chown, got {msg!r}")

    # 3. archive created 0o600 at open time, never chmod'ed after the fact
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        real_open, real_chmod = os.open, os.chmod
        modes: list[int] = []

        def rec_open(path, flags, mode=0o777, *a, **k):
            if str(path).endswith(".tar.gz"):
                modes.append(mode)
            return real_open(path, flags, mode, *a, **k)

        def no_chmod(*a, **k):
            raise AssertionError("archive must be created 0600, not chmod'ed afterwards")
        os.open, os.chmod = rec_open, no_chmod
        archive = a2 = None
        try:
            archive = backup.build_backup(d / "out", rbac_db=None, include_contracts=False)
            a2 = backup.build_backup(d / "out", rbac_db=None, include_contracts=False)
        except AssertionError as exc:
            check(False, str(exc))
        finally:
            os.open, os.chmod = real_open, real_chmod
        check(modes[:1] == [0o600], f"archive must be os.open'ed with mode 0o600, saw {modes}")
        check(archive is not None and a2 is not None and archive != a2 and archive.exists() and a2.exists(),
              "same-second backups must still not overwrite each other")

    # 4. checksum failure must not claim to detect tampering
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        src = d / "src.tar.gz"
        with tarfile.open(src, "w:gz") as t:
            data = b"hello"
            ti = tarfile.TarInfo("rbac/x.db")
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
            man = json.dumps({"files": [{"path": "rbac/x.db", "sha256": "0" * 64, "size": 5}]}).encode()
            ti = tarfile.TarInfo("manifest.json")
            ti.size = len(man)
            t.addfile(ti, io.BytesIO(man))
        try:
            restore.verify_and_restore(src, d / "dest", force=False)
            text = ""
        except restore.RestoreError as exc:
            text = str(exc)
        check("checksum mismatch" in text and "not deliberate tampering" in text
              and "or tampered" not in text,
              f"checksum message must say corruption-only, got {text!r}")
    doc = (ROOT / "docs" / "upgrade.md").read_text(encoding="utf-8")
    check("not** deliberate tampering" in doc, "docs must say the manifest hash does not detect tampering")

    # 1. runbook re-injection fixes ownership per volume
    check("chown 10001:10001" in doc and "`10001:999`" in doc and "chmod 600" in doc,
          "runbook re-injection must chown/chmod after copy (10001:10001, ws1 10001:999)")
    check('chown -R "$(id -u):$(id -g)" stage' in doc, "runbook extraction must chown staged copies")

    # 5. symlinks in plugin rule dirs / contracts are skipped, not followed
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        secret = d / "secret.txt"
        secret.write_text("TOPSECRET", encoding="utf-8")
        pdir = d / "rules"
        pdir.mkdir()
        (pdir / "ok.yml").write_text("id: ok\n", encoding="utf-8")
        try:
            (pdir / "link.yml").symlink_to(secret)
        except (OSError, NotImplementedError):
            print("[SKIP] symlink creation not permitted here; symlink test skipped")
        else:
            archive = backup.build_backup(d / "out", rbac_db=None, include_contracts=False,
                                          plugin_rule_dirs=[pdir])
            with tarfile.open(archive, "r:gz") as t:
                names = t.getnames()
                manifest = json.loads(t.extractfile("manifest.json").read())
            check(any(n.endswith("ok.yml") for n in names), "regular rule file must be archived")
            check(not any(n.endswith("link.yml") for n in names), "symlinked file must not be archived")
            check(any("link.yml" in x for x in manifest["not_backed_up"]),
                  "skipped symlink must be recorded in not_backed_up")


def main():
    test_full_round_trip_rbac_and_contracts()
    test_full_round_trip_all_non_docker_stores()
    test_no_rbac_db_backs_up_contracts_only()
    test_tampered_checksum_is_rejected_before_writing_anything()
    test_collision_requires_force()
    test_path_traversal_in_archive_is_rejected()
    test_symlink_member_escaping_staging_is_rejected()
    test_f2_inventory_db_default_covers_keystore_and_inventory()
    test_f2_separate_keystore_and_inventory_both_backed_up()
    test_f2_missing_inventory_db_fails_closed_nonzero()
    test_f2_unconfigured_stores_are_declared_not_silent()
    test_f2_docs_no_invented_keystore_fallback()
    test_f1_runbook_documents_volume_extraction_and_untested_status()
    test_f3_spools_and_plugin_rule_dirs_backed_up_and_scope_listed()
    test_f4_restore_removes_stale_wal_sidecars()
    test_f4_sidecar_without_main_file_blocks_unforced_restore()
    test_f4_cli_reports_where_files_landed()
    test_f5_audit_copy_waits_for_the_audit_lock()
    test_f6_percent_in_sqlite_path()
    test_pr167_second_review_edges()
    test_pr167_third_review_fixes()

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
