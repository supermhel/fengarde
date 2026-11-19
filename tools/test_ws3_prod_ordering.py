#!/usr/bin/env python3
"""Pins the ws3 prod-gate ORDERING (WP-3.2 review finding).

`triage_api.serve()` calls `prod_or_die("ws3-indexer-triage")` but runs in a
daemon thread, where `sys.exit` only ends that thread (the process, and its
/health, would stay up). It is safe ONLY because `main()` runs
`require_auth_or_die` (-> `prod_or_die`) on the MAIN thread first. This test
runs the real `main()` in a subprocess under an insecure prod config with
`Thread.start`, `make_store` and `init_rbac` stubbed (so nothing else can
cause the exit), and asserts the process exits non-zero BEFORE any thread is
started. Removing the main-thread call makes the sentinel appear and fails it.

Zero-infra; wired into run_all_tests.sh beside test_prodcheck.py.
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WS3 = ROOT / "services" / "ws3-indexer"
SENTINEL = "THREAD_START_REACHED"

DRIVER = f"""
import sys, threading
sys.path.insert(0, '.')
import main as m
import triage_api
threading.Thread.start = lambda self: (print({SENTINEL!r}), sys.exit(0))
triage_api.init_rbac = lambda: None
m.make_store = lambda: object()
m.main()
"""


def run_main(extra_env):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("FENGARDE_", "REDIS_")) and k != "BUS_BACKEND"}
    env.update(extra_env)
    return subprocess.run([sys.executable, "-c", DRIVER], cwd=str(WS3), env=env,
                          capture_output=True, text=True, timeout=60)


def main() -> int:
    fails = []
    r = run_main({"FENGARDE_PROFILE": "prod"})
    if r.returncode == 0 or SENTINEL in r.stdout:
        fails.append(f"insecure prod must exit non-zero before any thread starts: rc={r.returncode} "
                     f"out={r.stdout[-200:]!r} err={r.stderr[-200:]!r}")
    if "FENGARDE_API_KEY" not in r.stderr:
        fails.append(f"exit must come from the prod gate (numbered list): err={r.stderr[-300:]!r}")
    # positive control: outside prod the same driver DOES reach the thread start,
    # so the sentinel/stubs really detect "got past the gate".
    r = run_main({})
    if SENTINEL not in r.stdout:
        fails.append(f"control (demo profile) must reach the thread start: rc={r.returncode} "
                     f"out={r.stdout[-200:]!r} err={r.stderr[-300:]!r}")
    if fails:
        print(f"[FAIL] ws3 prod ordering: {len(fails)} problem(s)")
        for f in fails:
            print("  -", f)
        return 1
    print("[OK] ws3 prod ordering: main() exits under insecure prod before the triage thread starts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
