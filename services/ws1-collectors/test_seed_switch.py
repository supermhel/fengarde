"""WS1_SEED_MOCK switch: the bundled mock seed is on by default and off only for explicit false values.
Run: python services/ws1-collectors/test_seed_switch.py"""
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
os.environ["BUS_BACKEND"] = "memory"

import main  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _Log:
    def __init__(self):
        self.warns = []

    def warn(self, msg, **fields):
        self.warns.append((msg, fields))


def with_env(value, log=None):
    if value is None:
        os.environ.pop("WS1_SEED_MOCK", None)
    else:
        os.environ["WS1_SEED_MOCK"] = value
    return main._seed_mock_enabled(log)


check(with_env(None) is True, "unset must keep the demo seed on")
for v in ("1", "true", "yes", "on", "", "junk"):
    check(with_env(v) is True, f"{v!r} must keep the seed on")
for v in ("0", "false", "FALSE", " no ", "off"):
    check(with_env(v) is False, f"{v!r} must disable the seed")

# Unrecognised values keep the seed on but warn; recognised ones stay silent.
for v in ("n", "f", "disable", "junk", "2"):
    lg = _Log()
    check(with_env(v, lg) is True, f"{v!r} must keep the seed on")
    check(len(lg.warns) == 1 and lg.warns[0][1].get("value") == v, f"{v!r} must warn exactly once")
for v2 in (None, "", "1", "true", "YES", "on", "0", "false", " off "):
    lg = _Log()
    with_env(v2, lg)
    check(not lg.warns, f"{v2!r} is recognised and must not warn")
os.environ.pop("WS1_SEED_MOCK", None)

if FAILS:
    print("[FAIL] ws1 seed switch:", *FAILS, sep="\n  - ")
    sys.exit(1)
print("[OK] ws1 seed switch: default on, off only for 0/false/no/off, warns on unrecognised values")
