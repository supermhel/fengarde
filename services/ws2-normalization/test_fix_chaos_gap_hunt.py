"""Regression tests for the 2026-08-27 chaos-ws8 gap hunt ws2-normalization
findings (#4 = _int_env degrade-not-crash, #5 = unmapped top-level LIST).

NEWS hunt #3 (stale '10 parsers' comment) and #6 (INTERFACE.md pipeline order)
are doc-only fixes with no runtime assertion here.

Standalone test (NOT pytest): python test_fix_chaos_gap_hunt.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"

import main as ws2  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _Log:
    """Minimal fake logger capturing degradation warnings (no syslog/config)."""

    def __init__(self):
        self.warns = []

    def warn(self, msg: str = "", **kwargs):
        self.warns.append((msg, kwargs))


# ---- news-hunt #4: malformed NORMALIZED_EVENTS_DEPTH_WARN must not crash ----

def test_int_env_malformed_degrades_to_default_and_logs():
    """A non-integer NORMALIZED_EVENTS_DEPTH_WARN must degrade to the default
    (logged), never raise ValueError and take down the daemon at startup."""
    log = _Log()
    os.environ["NORMALIZED_EVENTS_DEPTH_WARN"] = "not-an-int"
    try:
        val = ws2._int_env("NORMALIZED_EVENTS_DEPTH_WARN", 100000, log)
        check(val == 100000, f"malformed env degraded to {val!r}, want default 100000")
        check(len(log.warns) == 1, "malformed env produced no degradation warning")
        check(log.warns and log.warns[0][1].get("name") == "NORMALIZED_EVENTS_DEPTH_WARN",
              "degradation warning missing the env var name")
        check(log.warns and log.warns[0][1].get("default") == 100000,
              "degradation warning missing the default it fell back to")
    finally:
        os.environ.pop("NORMALIZED_EVENTS_DEPTH_WARN", None)


def test_int_env_valid_value_passthrough():
    os.environ["NORMALIZED_EVENTS_DEPTH_WARN"] = "2500"
    try:
        val = ws2._int_env("NORMALIZED_EVENTS_DEPTH_WARN", 100000, _Log())
        check(val == 2500, f"valid int {val!r} != 2500")
    finally:
        os.environ.pop("NORMALIZED_EVENTS_DEPTH_WARN", None)


def test_int_env_unset_returns_default():
    os.environ.pop("NORMALIZED_EVENTS_DEPTH_WARN", None)
    val = ws2._int_env("NORMALIZED_EVENTS_DEPTH_WARN", 100000, _Log())
    check(val == 100000, f"unset env returned {val!r}, want default 100000")


def test_int_env_crash_on_bad_still_raises():
    """crash_on_bad keeps the loud path (bind ports); only tuning knobs default."""
    os.environ["NORMALIZED_EVENTS_DEPTH_WARN"] = "abc"
    try:
        raised = False
        try:
            ws2._int_env("NORMALIZED_EVENTS_DEPTH_WARN", 0, _Log(), crash_on_bad=True)
        except ValueError:
            raised = True
        check(raised, "crash_on_bad=True must re-raise ValueError on malformed value")
    finally:
        os.environ.pop("NORMALIZED_EVENTS_DEPTH_WARN", None)


# ---- NEWS-hunt #5: unmapped wildcard must recurse into a top-level LIST ------

def test_unmapped_top_level_list_is_sanitized():
    """The ('unmapped','*') wildcard previously recursed only when the cursor
    was a dict -- a producer putting a LIST at the top level of `unmapped` had
    the whole subtree skipped and hostile ANSI/control chars survived. Now the
    wildcard recurses into any dict OR list (mirroring the explicit-path
    branch, which recurses on any dict/list value)."""
    hostile = "\x1b[31m\x07"
    event = {
        "unmapped": [
            {"name": f"evil{hostile}"},                        # hostile ANSI/BEL in element
            {"inner": ["a\x0b", "c\x1e\x1b]52;c;YWJj\x07"]},  # deep nested list-of-lists
            "bare\x1b[31mand\x00control",                       # bare string in the list
            7,                                                  # non-string leaf
        ]
    }
    ws2._sanitize_free_text(event)
    check(event["unmapped"][0]["name"] == "evil",
          f"top-level-list element hostile value not stripped: {event['unmapped'][0]['name']!r}")
    check(event["unmapped"][1]["inner"][0] == "a",
          f"nested list-of-list string (\\x0b) not stripped: {event['unmapped'][1]['inner'][0]!r}")
    check(event["unmapped"][1]["inner"][1] == "c",
          f"nested ESC/OSC/control string not stripped: {event['unmapped'][1]['inner'][1]!r}")
    check(event["unmapped"][2] == "bareandcontrol",
          f"bare string at top-level of list not stripped: {event['unmapped'][2]!r}")
    check(event["unmapped"][3] == 7,
          f"non-string (int) leaf under the list got mutated: {event['unmapped'][3]!r}")


def test_unmapped_wildcard_missing_is_noop():
    """A payload with no unmapped must not crash; unrelated lists (not under
    the unmapped.* wildcard) must be left untouched."""
    event = {"message": "hi\x1b[31m", "with_list": [{"a": "x\x00y"}]}
    out = ws2._sanitize_free_text(event)
    check(out["message"] == "hi", f"explicit message not stripped: {out['message']!r}")
    check(out["with_list"][0]["a"] == "x\x00y",
          "unrelated (non-unmapped) list was sanitized when only unmapped.* was configured")


def run():
    test_int_env_malformed_degrades_to_default_and_logs()
    test_int_env_valid_value_passthrough()
    test_int_env_unset_returns_default()
    test_int_env_crash_on_bad_still_raises()
    test_unmapped_top_level_list_is_sanitized()
    test_unmapped_wildcard_missing_is_noop()


def _main():
    run()
    if FAILS:
        print(f"[FAIL] chaos-ws8 ws2 gap-hunt: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] ws2 chaos-ws8 gap-hunt findings (#4 _int_env, #5 unmapped-list wildcard) PASS")


if __name__ == "__main__":
    _main()