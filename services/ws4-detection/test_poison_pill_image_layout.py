"""Gap-hunt R3-31: the rule validator must be present, and work, in the BUILT ws4 image layout.

``engine._validate_loaded_rule`` loads ``<app>/tools/validate_rules.py`` by path and returns early when it is absent.
The ws4 Dockerfile copied only ``shared``, ``contracts`` and ``ws4-detection``, so in the real image the poison-pill
guard (a non-numeric ``window_seconds`` / ``threshold`` rejected at load) was a silent no-op while every source-tree
test passed. This test rebuilds the image's directory layout in a temp dir, runs the guard in a subprocess exactly as
the container would (cwd ``ws4-detection``, ``PYTHONPATH`` the app root), and also pins the Dockerfile COPY line.

Zero-infra. Run:  python services/ws4-detection/test_poison_pill_image_layout.py
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "services" / "ws4-detection" / "Dockerfile"
COPY_LINE = "COPY tools/validate_rules.py /app/tools/validate_rules.py"

PROBE = """
import sys, yaml
from pathlib import Path
import engine
raw = yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8"))
raw["siem"]["window_seconds"] = "60"          # poison: a string where a number is required
try:
    engine._validate_loaded_rule(raw, Path("poison.yml"))
except ValueError as exc:
    print("REJECTED", exc)
else:
    print("ACCEPTED")
"""

FAILS: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        FAILS.append(msg)


def _stateful_rule() -> Path:
    for p in sorted((ROOT / "contracts" / "rules").glob("*.yml")):
        text = p.read_text(encoding="utf-8")
        if "window_seconds" in text and "threshold" in text:
            return p
    raise SystemExit("no stateful rule found to poison")


def _layout(tmp: Path, with_tools: bool) -> Path:
    app = tmp / "app"
    ignore = shutil.ignore_patterns("__pycache__", "test_*.py", "*.pyc")
    shutil.copytree(ROOT / "services" / "shared", app / "shared", ignore=ignore)
    shutil.copytree(ROOT / "contracts", app / "contracts")
    shutil.copytree(ROOT / "services" / "ws4-detection", app / "ws4-detection", ignore=ignore)
    if with_tools:
        (app / "tools").mkdir()
        shutil.copy(ROOT / "tools" / "validate_rules.py", app / "tools" / "validate_rules.py")
    return app


def _run(app: Path, rule: Path) -> str:
    out = subprocess.run([sys.executable, "-c", PROBE, str(rule)], cwd=app / "ws4-detection",
                         env={**os.environ, "PYTHONPATH": str(app)},
                         capture_output=True, text=True, timeout=120)
    return (out.stdout + out.stderr).strip()


def main() -> int:
    check(COPY_LINE in DOCKERFILE.read_text(encoding="utf-8"),
          f"ws4 Dockerfile must contain {COPY_LINE!r} (R3-31)")
    rule = _stateful_rule()
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        with_tools = _run(_layout(tmp / "with", True), rule)
        check(with_tools.startswith("REJECTED"),
              f"with tools/validate_rules.py in the image layout the poison rule must be REJECTED, got: {with_tools[:200]}")
        without = _run(_layout(tmp / "without", False), rule)
        check(without.startswith("ACCEPTED"),
              f"control: without the validator the guard is a no-op (that is the bug), got: {without[:200]}")
    if FAILS:
        print(f"[FAIL] ws4 poison-pill image layout: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        return 1
    print("[OK] ws4 image layout: Dockerfile ships validate_rules.py and the poison-pill guard rejects a bad rule there "
          "(control without it: accepted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
