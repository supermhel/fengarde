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

FAILS = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def with_env(value):
    if value is None:
        os.environ.pop("WS1_SEED_MOCK", None)
    else:
        os.environ["WS1_SEED_MOCK"] = value
    return main._seed_mock_enabled()


check(with_env(None) is True, "unset must keep the demo seed on")
for v in ("1", "true", "yes", "on", "", "junk"):
    check(with_env(v) is True, f"{v!r} must keep the seed on")
for v in ("0", "false", "FALSE", " no ", "off"):
    check(with_env(v) is False, f"{v!r} must disable the seed")
os.environ.pop("WS1_SEED_MOCK", None)

if FAILS:
    print("[FAIL] ws1 seed switch:", *FAILS, sep="\n  - ")
    sys.exit(1)
print("[OK] ws1 seed switch: default on, off only for 0/false/no/off")
