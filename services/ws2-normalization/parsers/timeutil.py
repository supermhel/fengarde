"""Shared timestamp normalization for parsers.

Every parser needs "turn this record's time field into epoch-ms". The old
one-liner ``int(x*1000) if x < 1e12 else int(x)`` was copy-pasted into 9 modules
and got two real shapes wrong:

* **Windows FILETIME** (100-ns ticks since 1601, ~1.3e17 today) is ``> 1e12`` so
  it was used verbatim as ms -> a year-~33000 timestamp.
* **ISO-8601 string** ``TimeCreated`` failed the ``isinstance(int, float)`` check
  and was silently replaced with ``now()`` -- the event's real time was lost.

``to_epoch_ms`` handles epoch seconds/ms, ISO-8601 strings, and FILETIME in one
place. Returns ``None`` when it can't parse (caller falls back to ``now()``),
never raises.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

# Boundaries (practical epochs are all post-2001, so these don't misfire):
#   < 1e12  -> epoch SECONDS  (~ up to year 33658 in seconds; 1e12 s is year 33658)
#   < 1e14  -> epoch MILLIS   (1e12 ms = 2001-09, 1e14 ms = year 5138)
#   >= 1e14 -> Windows FILETIME (100-ns ticks since 1601-01-01)
_SECONDS_MAX = 1e12
_MILLIS_MAX = 1e14
# FILETIME epoch (1601-01-01) is 11644473600 seconds before the Unix epoch.
_FILETIME_EPOCH_OFFSET_MS = 11644473600000


def to_epoch_ms(value) -> Optional[int]:
    """Best-effort convert a record time field to epoch milliseconds, or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        if v <= 0:
            return None
        if v < _SECONDS_MAX:
            return int(v * 1000)          # epoch seconds
        if v < _MILLIS_MAX:
            return int(v)                 # epoch milliseconds
        return int(v // 10000) - _FILETIME_EPOCH_OFFSET_MS  # Windows FILETIME
    if isinstance(value, str):
        return _iso_to_epoch_ms(value)
    return None


def _iso_to_epoch_ms(s: str) -> Optional[int]:
    s = s.strip()
    if not s:
        return None
    # Accept a trailing 'Z' (UTC) which older datetime.fromisoformat rejects.
    iso = s[:-1] + "+00:00" if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        # Some sources emit a bare epoch as a string ("1751500000000").
        try:
            return to_epoch_ms(float(s))
        except (ValueError, TypeError):
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)  # assume UTC when unspecified
    return int(dt.timestamp() * 1000)
