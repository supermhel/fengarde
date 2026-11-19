#!/usr/bin/env python3
"""Zero-infra test: infra/preflight.sh recognises Git Bash/MSYS/Cygwin on Windows.

Runs the real script under a fake `uname` (first on PATH) and asserts on the OS
section only. The script may legitimately exit non-zero afterwards (no Docker,
busy ports); that is not what this test is about. An unrecognised OS must still
fail closed ("cannot bless this machine").
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "infra", "preflight.sh")
_sh = shutil.which("sh") or shutil.which("bash")
if not _sh:
    print("SKIP: no POSIX sh on this machine")
    sys.exit(0)
SH: str = _sh


def run(uname_out: str) -> str:
    with tempfile.TemporaryDirectory() as d:
        fake = os.path.join(d, "uname")
        with open(fake, "w", newline="\n") as f:
            f.write(f"#!/bin/sh\necho '{uname_out}'\n")
        os.chmod(fake, os.stat(fake).st_mode | stat.S_IEXEC)
        env = dict(os.environ, PATH=d + os.pathsep + os.environ.get("PATH", ""))
        proc = subprocess.run([SH, SCRIPT], env=env, capture_output=True, text=True, timeout=120)
        return proc.stdout + proc.stderr


fails = 0


def check(name, cond):
    global fails
    print(("ok   " if cond else "FAIL ") + name)
    fails += 0 if cond else 1


for u in ("MINGW64_NT-10.0-26200", "MSYS_NT-10.0-26200", "CYGWIN_NT-10.0"):
    out = run(u)
    check(f"{u}: recognised as Windows, not 'Unknown OS'",
          "Unknown OS" not in out and "Docker Desktop's WSL2 VM" in out)
    check(f"{u}: prints how to check vm.max_map_count", "sysctl vm.max_map_count" in out)

out = run("Plan9")
check("unrecognised OS still fails closed", "Unknown OS (Plan9)" in out and "[ FAIL ]" in out)

sys.exit(1 if fails else 0)
