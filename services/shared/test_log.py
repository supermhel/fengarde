"""P2-3 (2026-07-21 audit) — level gate in shared/log.py.

Before this fix, Logger._emit() unconditionally JSON-dumped + flushed every
call regardless of level, so a service configured for warn/error-only still
paid full serialize+syscall cost on every log.info()/log.debug() in its hot
path. This proves FENGARDE_LOG_LEVEL gates emission before that work happens.

Run: python services/shared/test_log.py
"""
from __future__ import annotations

import io
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import log as log_mod  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _capture(level_env: str | None, calls) -> str:
    old = os.environ.get("FENGARDE_LOG_LEVEL")
    if level_env is None:
        os.environ.pop("FENGARDE_LOG_LEVEL", None)
    else:
        os.environ["FENGARDE_LOG_LEVEL"] = level_env
    buf = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf
    try:
        logger = log_mod.get_logger("test-svc")
        for level, msg in calls:
            getattr(logger, level)(msg)
    finally:
        sys.stdout = old_stdout
        if old is None:
            os.environ.pop("FENGARDE_LOG_LEVEL", None)
        else:
            os.environ["FENGARDE_LOG_LEVEL"] = old
    return buf.getvalue()


def test_default_level_emits_info_and_above_not_debug():
    out = _capture(None, [("debug", "d"), ("info", "i"), ("warn", "w"), ("error", "e")])
    lines = out.strip().split("\n") if out.strip() else []
    check(len(lines) == 3, f"default level should emit info/warn/error (3 lines), got {len(lines)}")
    check('"d"' not in out, "debug message must be gated out at default level")


def test_warn_level_gates_out_info_and_debug():
    out = _capture("warn", [("debug", "d"), ("info", "i"), ("warn", "w"), ("error", "e")])
    lines = out.strip().split("\n") if out.strip() else []
    check(len(lines) == 2, f"warn level should emit only warn/error (2 lines), got {len(lines)}")


def test_debug_level_emits_everything():
    out = _capture("debug", [("debug", "d"), ("info", "i"), ("warn", "w"), ("error", "e")])
    lines = out.strip().split("\n") if out.strip() else []
    check(len(lines) == 4, f"debug level should emit all 4 lines, got {len(lines)}")


def test_unknown_level_env_falls_back_to_info():
    out = _capture("bogus-level", [("debug", "d"), ("info", "i")])
    lines = out.strip().split("\n") if out.strip() else []
    check(len(lines) == 1, f"unrecognized FENGARDE_LOG_LEVEL must fall back to info gate, got {len(lines)} lines")


def run():
    test_default_level_emits_info_and_above_not_debug()
    test_warn_level_gates_out_info_and_debug()
    test_debug_level_emits_everything()
    test_unknown_level_env_falls_back_to_info()


def main():
    run()
    if FAILS:
        print(f"[FAIL] shared/log.py level gate: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] P2-3: shared/log.py FENGARDE_LOG_LEVEL gates emission by level "
          "(debug/info/warn/error), defaults to info, falls back safely on bad env value")


if __name__ == "__main__":
    main()
