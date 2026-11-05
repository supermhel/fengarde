"""Contract tests for the WP-3.2 FENGARDE_PROFILE=prod gate
(services/shared/prodcheck.py + the authz/users/triage wiring).

Every refusal is asserted with the exact aggregated failure list; the demo
path (no FENGARDE_PROFILE) is asserted byte-for-byte no-op. Env manipulation
uses os.environ save/restore in-process (no subprocesses, no timing).

Run: python tools/test_prodcheck.py
"""
from __future__ import annotations

import contextlib
import io
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "services" / "ws3-indexer"))

import shared.prodcheck as pc  # noqa: E402

FAILS: list[str] = []


def check(cond: object, msg: str) -> None:
    if not cond:
        FAILS.append(msg)


@contextlib.contextmanager
def env(**overrides):
    saved = {k: os.environ.get(k) for k in overrides}
    for k, v in overrides.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def cleared():
    """prod-relevant env fully unset (like a fresh demo run). FENGARDE_PROFILE
    is NOT included — callers set it explicitly, so overrides never collide."""
    return dict(FENGARDE_API_KEY=None, FENGARDE_RBAC_DB=None,
                FENGARDE_ADMIN_PASSWORD=None, FENGARDE_FIRST_BOOT_FILE=None,
                FENGARDE_REQUIRE_AUTH=None, REDIS_PASSWORD=None,
                BUS_BACKEND="memory")


@contextlib.contextmanager
def posix_mode():
    """Drive the POSIX generation path on any host (the real nt refusal is
    asserted separately)."""
    saved = pc._is_windows
    pc._is_windows = lambda: False
    try:
        yield
    finally:
        pc._is_windows = saved


def _captured():
    buf = io.StringIO()
    return buf, contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf)


def _read_pw(path) -> str:
    return Path(path).read_text(encoding="utf-8").splitlines()[-1]


def run_or_die(service="t") -> str:
    """Call prod_or_die capturing its stderr output; swallow the expected
    SystemExit and return what it printed (the numbered list)."""
    out = io.StringIO()
    try:
        with contextlib.redirect_stderr(out):
            pc.prod_or_die(service)
    except SystemExit:
        pass
    return out.getvalue()


def test_demo_path_is_noop():
    # no FENGARDE_PROFILE -> nothing to check, no matter what else is unset
    all_env = {**cleared(), "FENGARDE_PROFILE": None}
    with env(**all_env):
        check(not pc.prod_active(), "prod_active must be False without the var")
        check(pc.prod_or_die("ws3") is None, "prod_or_die must no-op outside prod")
    with env(**{**cleared(), "FENGARDE_PROFILE": "dev"}):
        check(not pc.prod_active() and pc.prod_or_die("ws3") is None,
              "profile dev (or any non-prod value) must no-op")


def test_aggregation_lists_every_problem():
    with env(**{**cleared(), "FENGARDE_PROFILE": "prod"}):
        problems = pc.prod_problems()
        check(len(problems) == 3, f"3 problems expected (api key, rbac, admin), got {problems}")
        out = run_or_die()
        for i in (1, 2, 3):
            check(f"{i})" in out, f"aggregated list must number problem {i}: {out}")
        check("FENGARDE_API_KEY" in out and "FENGARDE_RBAC_DB" in out,
              "aggregate must name BOTH the api key and RBAC obligations")


def test_default_credentials_refused():
    for bad in ("admin", "password", "Changeme", "fengarde", "admin123"):
        with env(**{**cleared(), "FENGARDE_PROFILE": "prod", "FENGARDE_API_KEY": "k",
                    "FENGARDE_RBAC_DB": "/tmp/r.db", "FENGARDE_ADMIN_PASSWORD": bad}):
            problems = pc.prod_problems()
            check(any("default" in p for p in problems),
                  f"default password {bad!r} must be refused: {problems}")
    with env(**{**cleared(), "FENGARDE_PROFILE": "prod", "FENGARDE_API_KEY": "k",
                "FENGARDE_RBAC_DB": "/tmp/r.db", "FENGARDE_ADMIN_PASSWORD": "short"}):
        problems = pc.prod_problems()
        check(any("shorter" in p for p in problems), "short password must be refused")


def test_all_obligations_satisfied():
    with env(**{**cleared(), "FENGARDE_PROFILE": "prod", "FENGARDE_API_KEY": "k" * 24,
                "FENGARDE_RBAC_DB": "/tmp/r.db",
                "FENGARDE_ADMIN_PASSWORD": "S3cure-！-not-default-pw-2026"}):
        check(pc.prod_problems() == [], f"no problems expected: {pc.prod_problems()}")
        check(pc.prod_or_die("ws3") is None, "satisfied prod must not exit")

    # first-boot FILE path is allowed at startup (generation is store-gated)
    with posix_mode(), env(**{**cleared(), "FENGARDE_PROFILE": "prod", "FENGARDE_API_KEY": "k" * 24,
                "FENGARDE_RBAC_DB": "/tmp/r.db",
                "FENGARDE_FIRST_BOOT_FILE": "/tmp/firstboot-pw.txt"}):
        check(pc.prod_problems() == [],
              f"first-boot file must satisfy the admin obligation: {pc.prod_problems()}")

    # redis bus in prod requires REDIS_PASSWORD
    with env(**{**cleared(), "FENGARDE_PROFILE": "prod", "FENGARDE_API_KEY": "k" * 24,
                "FENGARDE_RBAC_DB": "/tmp/r.db",
                "FENGARDE_ADMIN_PASSWORD": "S3cure-！-not-default-pw-2026",
                "BUS_BACKEND": "redis", "REDIS_PASSWORD": None}):
        problems = pc.prod_problems()
        check(any("REDIS_PASSWORD" in p for p in problems),
              "redis bus without REDIS_PASSWORD must be refused in prod")


def test_exit_with_one_list():
    with env(**cleared(), FENGARDE_PROFILE="prod"):
        try:
            pc.prod_or_die("ws3")
            check(False, "prod_or_die must exit(1) on missing obligations")
        except SystemExit as exc:
            check(exc.code == 1, f"exit code must be 1, got {exc.code}")


def test_bus_backend_case_insensitive():
    # shared/bus.py lowercases BUS_BACKEND, so BUS_BACKEND=Redis really is the
    # redis bus; the gate must not be case-sensitive (review finding 1).
    base = {**cleared(), "FENGARDE_PROFILE": "prod", "FENGARDE_API_KEY": "k" * 24,
            "FENGARDE_RBAC_DB": "/tmp/r.db",
            "FENGARDE_ADMIN_PASSWORD": "S3cure-not-default-pw-2026"}
    for v in ("REDIS", "Redis", "  redis-sentinel ", "REDIS-SENTINEL"):
        with env(**{**base, "BUS_BACKEND": v, "REDIS_PASSWORD": None}):
            check(any("REDIS_PASSWORD" in p for p in pc.prod_problems()),
                  f"BUS_BACKEND={v!r} without REDIS_PASSWORD must be refused")
        with env(**{**base, "BUS_BACKEND": v, "REDIS_PASSWORD": "x" * 16}):
            check(pc.prod_problems() == [], f"BUS_BACKEND={v!r} with a password is fine")
    with env(**{**base, "BUS_BACKEND": "memory", "REDIS_PASSWORD": None}):
        check(pc.prod_problems() == [], "memory bus needs no REDIS_PASSWORD")


def test_first_boot_file_generation():
    with tempfile.TemporaryDirectory() as d, posix_mode():
        target = str(Path(d) / "admin-password.txt")
        old_umask = os.umask(0)  # hostile umask: 0600 must hold at CREATION, not via a later chmod
        try:
            with env(FENGARDE_FIRST_BOOT_FILE=target):
                pw = pc.generate_first_boot_password()
        finally:
            os.umask(old_umask)
        check(len(pw) >= 20, f"generated password too short: {len(pw)}")
        if os.name != "nt":
            mode = stat.S_IMODE(os.stat(target).st_mode)
            check(mode == 0o600, f"first-boot file must be 0600 at creation (umask 0), got {mode:o}")
        text = Path(target).read_text(encoding="utf-8")
        check(pw in text, "the generated password must be in the file")
        check("rotate" in text.lower() and "delete" in text.lower(),
              "the file header must instruct rotate + delete")
        # an existing credential file is never overwritten
        with env(FENGARDE_FIRST_BOOT_FILE=target):
            try:
                pc.generate_first_boot_password()
                check(False, "an existing first-boot file must be refused (O_EXCL)")
            except FileExistsError:
                pass
        check(Path(target).read_text(encoding="utf-8") == text,
              "the existing first-boot file must be left untouched")
        # symlinks are not followed (POSIX; creating one needs a privilege on nt)
        if os.name != "nt":
            victim = Path(d) / "victim.txt"
            victim.write_text("keep", encoding="utf-8")
            link = Path(d) / "link.txt"
            link.symlink_to(victim)
            with env(FENGARDE_FIRST_BOOT_FILE=str(link)):
                try:
                    pc.generate_first_boot_password()
                    check(False, "a symlink first-boot path must be refused")
                except OSError:
                    pass
            check(victim.read_text(encoding="utf-8") == "keep", "symlink target must be untouched")
    with env(FENGARDE_FIRST_BOOT_FILE=None):
        try:
            pc.generate_first_boot_password()
            check(False, "generation without the env var must raise")
        except ValueError:
            pass


def test_first_boot_file_refused_on_windows():
    saved = pc._is_windows
    pc._is_windows = lambda: True
    try:
        with tempfile.TemporaryDirectory() as d:
            target = str(Path(d) / "pw.txt")
            with env(FENGARDE_FIRST_BOOT_FILE=target):
                try:
                    pc.generate_first_boot_password()
                    check(False, "generation must be refused on Windows")
                except RuntimeError as exc:
                    check("POSIX" in str(exc), f"refusal must say why: {exc}")
                check(not Path(target).exists(), "no file may be written on Windows")
            with env(**{**cleared(), "FENGARDE_PROFILE": "prod", "FENGARDE_API_KEY": "k" * 24,
                        "FENGARDE_RBAC_DB": "/tmp/r.db", "FENGARDE_FIRST_BOOT_FILE": target}):
                check(any("POSIX-only" in p for p in pc.prod_problems()),
                      "prod startup must refuse FIRST_BOOT_FILE on Windows")
    finally:
        pc._is_windows = saved


def test_bootstrap_first_admin():
    import shared.users as users
    import triage_api
    prod = {**cleared(), "FENGARDE_PROFILE": "prod"}

    def fresh(d):
        return users.UserStore(str(Path(d) / "u.sqlite"))

    # (a) empty store + prod + file: admin created, file holds ITS password,
    # and the password never reaches stdout/stderr (the real code path).
    with tempfile.TemporaryDirectory() as d, posix_mode():
        f = str(Path(d) / "pw.txt")
        store = fresh(d)
        buf = io.StringIO()
        with env(**{**prod, "FENGARDE_FIRST_BOOT_FILE": f}), \
                contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            triage_api.bootstrap_first_admin(store)
        pw = _read_pw(f)
        check(store.count() == 1 and store.verify_login("admin", pw) is not None,
              "the file's password must be the created admin's password")
        check(pw not in buf.getvalue(), "generated password leaked into log/stdout/stderr")
        check(Path(f).name in buf.getvalue(), "the file PATH is what gets logged")
        # (b) second boot, non-empty store, file var still set: error, no rewrite
        before = Path(f).read_text(encoding="utf-8")
        buf = io.StringIO()
        with env(**{**prod, "FENGARDE_FIRST_BOOT_FILE": f}), \
                contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            triage_api.bootstrap_first_admin(store)
        check("NOT empty" in buf.getvalue() and '"level": "error"' in buf.getvalue(),
              f"non-empty store + prod + file must log an error: {buf.getvalue()!r}")
        check(Path(f).read_text(encoding="utf-8") == before and store.count() == 1,
              "non-empty store must not rotate the admin / rewrite the file")
        store.db.close()

    # (c) race loser / stale file: file exists, store empty -> nothing created
    with tempfile.TemporaryDirectory() as d, posix_mode():
        f = Path(d) / "pw.txt"
        f.write_text("winner-password\n", encoding="utf-8")
        store = fresh(d)
        buf = io.StringIO()
        with env(**{**prod, "FENGARDE_FIRST_BOOT_FILE": str(f)}), \
                contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            triage_api.bootstrap_first_admin(store)
        check(store.count() == 0, "loser of the file race must not create an admin")
        check(f.read_text(encoding="utf-8") == "winner-password\n",
              "the winner's file must not be overwritten")
        check("already exists" in buf.getvalue(), "loser must log why")
        store.db.close()

    # (d) admin creation fails / yields nothing -> generated file rolled back
    real = users.ensure_first_boot_admin
    for mode in ("raise", "none"):
        with tempfile.TemporaryDirectory() as d, posix_mode():
            f = Path(d) / "pw.txt"
            store = fresh(d)
            calls = {"n": 0}

            def fake(st, username="admin", password=None, _mode=mode, _real=real, _c=calls):
                if password is None:
                    return _real(st, username, password)
                if _mode == "raise":
                    raise RuntimeError("db down")
                return None
            users.ensure_first_boot_admin = fake
            try:
                with env(**{**prod, "FENGARDE_FIRST_BOOT_FILE": str(f)}), \
                        contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    try:
                        triage_api.bootstrap_first_admin(store)
                    except RuntimeError:
                        check(mode == "raise", "only the raising mode may propagate")
            finally:
                users.ensure_first_boot_admin = real
            check(not f.exists(), f"file must be rolled back when admin creation fails ({mode})")
            store.db.close()

    # (e) not prod: FIRST_BOOT_FILE alone never generates anything
    with tempfile.TemporaryDirectory() as d, posix_mode():
        f = Path(d) / "pw.txt"
        store = fresh(d)
        with env(**{**cleared(), "FENGARDE_PROFILE": None, "FENGARDE_FIRST_BOOT_FILE": str(f)}), \
                contextlib.redirect_stdout(io.StringIO()):
            triage_api.bootstrap_first_admin(store)
        check(not f.exists() and store.count() == 0, "non-prod must never generate a password file")
        store.db.close()


def _run_entry(argv, cwd, extra_env, timeout=60):
    e = dict(os.environ)
    for k in list(e):
        if k.startswith(("FENGARDE_", "REDIS_", "INVENTORY_")) or k == "BUS_BACKEND":
            e.pop(k)
    e.update(extra_env)
    return subprocess.run([sys.executable] + argv, cwd=str(cwd), env=e,
                          capture_output=True, text=True, timeout=timeout)


def test_every_entrypoint_refuses_in_prod():
    """Each service entrypoint that the prod gate is wired into must exit 1
    with the numbered list under prod + missing config (review finding 2).
    Audit of the rest: ws7 is nginx (no python entrypoint), ws1's HTTP ingest
    already refuses to start without FENGARDE_INGEST_TOKEN, and every bus
    service gets the Redis-password obligation."""
    svc = ROOT / "services"
    redis_prod = {"FENGARDE_PROFILE": "prod", "BUS_BACKEND": "Redis"}
    for name in ("ws1-collectors", "ws2-normalization", "ws4-detection",
                 "ws5-ai", "ws8-correlation", "ws9-resolver"):
        r = _run_entry([str(svc / name / "main.py")], svc / name, redis_prod)
        check(r.returncode == 1 and "REDIS_PASSWORD" in r.stderr,
              f"{name} must refuse prod + redis bus without REDIS_PASSWORD: rc={r.returncode} err={r.stderr[-300:]!r}")
    # ws3 daemon: the full secure surface
    r = _run_entry([str(svc / "ws3-indexer" / "main.py")], svc / "ws3-indexer",
                   {"FENGARDE_PROFILE": "prod"})
    check(r.returncode == 1 and "FENGARDE_API_KEY" in r.stderr and "FENGARDE_RBAC_DB" in r.stderr,
          f"ws3 daemon must refuse bare prod: rc={r.returncode} err={r.stderr[-300:]!r}")
    # ws3 triage API serve()
    r = _run_entry(["-c", "import sys; sys.path.insert(0, '..'); import triage_api; triage_api.serve(None)"],
                   svc / "ws3-indexer", {"FENGARDE_PROFILE": "prod"})
    check(r.returncode == 1 and "FENGARDE_API_KEY" in r.stderr,
          f"ws3 triage serve() must refuse bare prod: rc={r.returncode} err={r.stderr[-300:]!r}")
    # ws6 inventory: no keys provisioned = open writes
    r = _run_entry(["-c", "from app import serve; serve(host='127.0.0.1', port=0)"],
                   svc / "ws6-inventory",
                   {"FENGARDE_PROFILE": "prod", "INVENTORY_DB": ":memory:",
                    "INVENTORY_KEYSTORE_DB": ":memory:"})
    check(r.returncode == 1 and "no per-tenant API keys" in r.stderr
          and '"msg": "listening"' not in r.stdout,
          f"ws6 serve() must refuse prod with an empty keystore: rc={r.returncode} err={r.stderr[-300:]!r}")
    # ws6 with a key + non-redis bus passes the gate (it then fails only by timeout/serving)
    r = _run_entry(["-c", "import authz; from app import KEYSTORE; "
                    "KEYSTORE.provision('acme', 'a-real-key-123'); "
                    "authz.require_auth_or_die('ws6-inventory', KEYSTORE); print('ok')"],
                   svc / "ws6-inventory",
                   {"FENGARDE_PROFILE": "prod", "INVENTORY_DB": ":memory:",
                    "INVENTORY_KEYSTORE_DB": ":memory:"})
    check(r.returncode == 0 and "ok" in r.stdout, f"ws6 with a key must pass: {r.stderr[-300:]!r}")


def test_authz_integration_demo_unchanged():
    # require_auth_or_die keeps its exact pre-prod contract outside prod
    with env(**cleared()):
        import shared.authz as a
        check(a.require_auth_or_die("ws3") is None,
              "require_auth_or_die must no-op outside prod/REQUIRE_AUTH")
    with env(**{**cleared(), "FENGARDE_REQUIRE_AUTH": "1", "FENGARDE_API_KEY": "k"}):
        import shared.authz as a
        check(a.require_auth_or_die("ws3") is None,
              "REQUIRE_AUTH with a key must pass (pre-prod behavior)")
    with env(**{**cleared(), "FENGARDE_REQUIRE_AUTH": "1"}):
        import shared.authz as a
        try:
            a.require_auth_or_die("ws3")
            check(False, "REQUIRE_AUTH without a key must exit")
        except SystemExit:
            pass


def test_users_ensure_first_boot_password_param():
    import tempfile
    d = tempfile.mkdtemp(prefix="fg-users-")
    try:
        db = str(Path(d) / "users.sqlite")
        with env(FENGARDE_ADMIN_PASSWORD=None):
            from shared.users import UserStore, ensure_first_boot_admin
            store = UserStore(db)
            created = ensure_first_boot_admin(store, password="EnvGen-NeverLogged-2026!")
            check(created == "admin", "explicit password must create the admin")
            check(store.count() == 1, "store must have one user")
            # second call (non-empty store) must not re-create / rotate
            created2 = ensure_first_boot_admin(store, password="Another-Pw-2026!")
            check(created2 is None, "non-empty store must never re-create the admin")
            store.db.close()  # Windows: release the sqlite handle before cleanup
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


def main() -> int:
    tests = [test_demo_path_is_noop, test_aggregation_lists_every_problem,
             test_default_credentials_refused, test_all_obligations_satisfied,
             test_exit_with_one_list, test_bus_backend_case_insensitive,
             test_first_boot_file_generation, test_first_boot_file_refused_on_windows,
             test_bootstrap_first_admin, test_every_entrypoint_refuses_in_prod,
             test_authz_integration_demo_unchanged,
             test_users_ensure_first_boot_password_param]
    for t in tests:
        t()
    if FAILS:
        print(f"[FAIL] prodcheck: {len(FAILS)} problem(s)")
        for f in FAILS[:30]:
            print("  -", f)
        return 1
    print(f"[OK] prodcheck: {len(tests)} test groups — prod aggregation, defaults "
          "refusal, first-boot file (atomic 0600), bootstrap race/rollback, entrypoint refusals, demo path untouched")
    return 0


if __name__ == "__main__":
    sys.exit(main())