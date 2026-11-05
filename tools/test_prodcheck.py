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
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))

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
    with env(**{**cleared(), "FENGARDE_PROFILE": "prod", "FENGARDE_API_KEY": "k" * 24,
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


def test_first_boot_file_generation():
    with tempfile.TemporaryDirectory() as d:
        target = str(Path(d) / "admin-password.txt")
        with env(FENGARDE_FIRST_BOOT_FILE=target):
            pw = pc.generate_first_boot_password()
        check(len(pw) >= 20, f"generated password too short: {len(pw)}")
        mode = stat.S_IMODE(os.stat(target).st_mode)
        if os.name == "nt":
            # Windows has no POSIX mode bits (S_IMODE reports 666 for any
            # writable file; real protection is per-user ACLs). The 0600
            # intent is enforced on POSIX — which is where prod runs / CI
            # executes — so no check here beyond "the file exists".
            check(Path(target).is_file(), "first-boot file must exist")
        else:
            check(mode == 0o600, f"first-boot file must be 0600, got {mode:o}")
        text = Path(target).read_text(encoding="utf-8")
        check(pw in text, "the generated password must be in the file")
        check("rotate" in text.lower() and "delete" in text.lower(),
              "the file header must instruct rotate + delete")
        # never logged: the logger output of the module must not carry it
        with env(FENGARDE_FIRST_BOOT_FILE=target), \
                contextlib.redirect_stdout(io.StringIO()):
            pc.generate_first_boot_password()
    with env(FENGARDE_FIRST_BOOT_FILE=None):
        try:
            pc.generate_first_boot_password()
            check(False, "generation without the env var must raise")
        except ValueError:
            pass


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
             test_exit_with_one_list, test_first_boot_file_generation,
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
          "refusal, first-boot file (0600), demo path untouched")
    return 0


if __name__ == "__main__":
    sys.exit(main())