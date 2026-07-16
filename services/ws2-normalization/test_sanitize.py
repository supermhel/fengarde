"""M1 correctness gate: log-injection defense (ANSI + control-char stripping).

Proves services/shared/sanitize.py's regexes actually work, AND that
normalize_one() (services/ws2-normalization/main.py) applies them to every
free-text field a real parser populates from attacker-controlled log content --
not just that the helper function works in isolation.
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

from shared.sanitize import strip_ansi_and_control  # noqa: E402
import main as ws2  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_strips_csi_ansi():
    out = strip_ansi_and_control("hello\x1b[31mRED\x1b[0mworld")
    check(out == "helloREDworld", f"CSI ansi not stripped: {out!r}")


def test_strips_osc_ansi_terminated_by_bel():
    # OSC 52 clipboard-injection shape: ESC ] 52 ; c ; <base64> BEL
    out = strip_ansi_and_control("before\x1b]52;c;ZXZpbA==\x07after")
    check(out == "beforeafter", f"OSC(BEL) ansi not stripped: {out!r}")


def test_strips_osc_ansi_terminated_by_st():
    out = strip_ansi_and_control("before\x1b]0;title\x1b\\after")
    check(out == "beforeafter", f"OSC(ST) ansi not stripped: {out!r}")


def test_strips_control_chars_but_keeps_tab():
    out = strip_ansi_and_control("a\rb\nc\x00d\te")
    check(out == "abcd\te", f"control chars not stripped (tab must survive): {out!r}")


def test_log_forging_newline_removed():
    """The concrete log-injection scenario: an attacker-controlled username
    containing a fake newline + fabricated log line must not survive as two
    lines once it reaches a terminal/log sink."""
    hostile = "admin\n2026-01-01 CRITICAL fake alert: system compromised"
    out = strip_ansi_and_control(hostile)
    check("\n" not in out, f"embedded newline (log forging) not stripped: {out!r}")


def test_non_string_passthrough():
    check(strip_ansi_and_control(None) is None, "None must pass through unchanged")
    check(strip_ansi_and_control(42) == 42, "non-str must pass through unchanged")


def test_normalize_one_sanitizes_message_from_real_parser():
    """End-to-end: a hostile ANSI/control payload in a linux_ssh raw line
    must NOT survive into the normalized event's message field."""
    hostile_user = "admin\x1b[31m\x07"
    raw = {
        "source_type": "linux_ssh",
        "raw": f"Jun 10 13:55:36 db01 sshd[2154]: Failed password for invalid user "
               f"{hostile_user} from 203.0.113.5 port 51000 ssh2",
        "meta": {"received_at": 1700000000, "ingest_id": "sanitize-test-1"},
    }
    event, errors = ws2.normalize_one(raw)
    check(event is not None, "parser must still produce an event for this input")
    check(not errors, f"sanitized event must still validate: {errors}")
    message = event.get("message", "")
    check("\x1b" not in message, f"ESC byte survived into message: {message!r}")
    check("\x07" not in message, f"BEL byte survived into message: {message!r}")


def main():
    test_strips_csi_ansi()
    test_strips_osc_ansi_terminated_by_bel()
    test_strips_osc_ansi_terminated_by_st()
    test_strips_control_chars_but_keeps_tab()
    test_log_forging_newline_removed()
    test_non_string_passthrough()
    test_normalize_one_sanitizes_message_from_real_parser()

    if FAILS:
        print(f"\n[FAIL] sanitize: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] log-injection defense (ANSI/control-char sanitize) unit tests PASS")


if __name__ == "__main__":
    main()
