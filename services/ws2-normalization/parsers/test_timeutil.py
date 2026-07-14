"""P1.6: shared timestamp normalization (to_epoch_ms).

Pins the shapes the old duplicated one-liner got wrong: Windows FILETIME (was
scaled to year ~33000) and ISO-8601 strings (were dropped -> now()).

Run: C:/Python313/python.exe services/ws2-normalization/parsers/test_timeutil.py
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent))  # for `shared` (parsers/__init__ imports it)

from parsers.timeutil import to_epoch_ms  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def run():
    # epoch seconds -> ms
    check(to_epoch_ms(1_750_000_000) == 1_750_000_000_000, "epoch seconds -> ms")
    # epoch millis -> unchanged
    check(to_epoch_ms(1_750_000_000_000) == 1_750_000_000_000, "epoch ms unchanged")
    # Windows FILETIME (100-ns ticks since 1601) -> a sane 21st-century year
    # 2025-06-15T12:00:00Z as FILETIME:
    ft = 133_939_296_000_000_000
    ms = to_epoch_ms(ft)
    yr = datetime.fromtimestamp(ms / 1000, tz=timezone.utc).year
    check(2020 <= yr <= 2035, f"FILETIME should map to ~2025, got year {yr}")
    # ISO-8601 string (naive -> assumed UTC)
    iso_ms = to_epoch_ms("2025-06-15T12:00:00")
    check(iso_ms is not None
          and datetime.fromtimestamp(iso_ms / 1000, tz=timezone.utc).year == 2025,
          "ISO-8601 string parsed to 2025")
    # ISO-8601 with trailing Z
    check(to_epoch_ms("2025-06-15T12:00:00Z") is not None, "ISO-8601 Z suffix parsed")
    # numeric string
    check(to_epoch_ms("1750000000000") == 1_750_000_000_000, "numeric string -> ms")
    # junk / bool / None -> None (caller falls back to now())
    for bad in (None, True, False, "not a time", "", [], {}, -5, 0):
        check(to_epoch_ms(bad) is None, f"unparseable {bad!r} -> None")


def main():
    run()
    if FAILS:
        print(f"[FAIL] timeutil: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] timeutil to_epoch_ms (epoch/ISO/FILETIME) PASS")


if __name__ == "__main__":
    main()
