"""scenario_kit -- small helpers shared by the ``storyline_<name>.py`` modules.

Not itself a storyline (its name deliberately does not match the registry's
``storyline_*.py`` discovery glob). Everything here is a pure function of its
arguments: no wall clock, no randomness, no I/O.

TIME. Rules with a time predicate (``outside_hours``) read the event's UTC
weekday/hour, so a storyline that wants to be IN business hours (or outside
them) must say so with a calendar timestamp, never with an offset from an
arbitrary epoch. ``epoch_ms`` builds one from ``datetime(...)`` exactly as
``negative_controls._epoch_ms`` does. ``BASE_MS`` is the fixed epoch every older
storyline starts at: Wed 2025-07-02 23:46:40 UTC, i.e. OUTSIDE 08:00-18:00.
"""
from __future__ import annotations

from datetime import datetime, timezone

#: Wed 2025-07-02 23:46:40 UTC (night). The epoch every pre-2026-10-03 storyline starts at.
BASE_MS = 1751500000000


def epoch_ms(year: int, month: int, day: int, hour: int = 0, minute: int = 0, second: int = 0) -> int:
    """Epoch milliseconds of a UTC calendar instant (no wall clock)."""
    return int(datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc).timestamp() * 1000)


def iso(ms: int) -> str:
    """``2025-07-02T23:46:40Z`` for an epoch-ms value."""
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def meta(seed: int, tag: str, idx: int, ts: int, ip: str | None = None, *, tenant: str = "acme") -> dict:
    """Envelope v1 ``meta`` with a deterministic, per-storyline-unique ingest id."""
    out = {
        "received_at": ts,
        "ingest_id": f"ing-{tag}-{seed:04d}-{idx:03d}",
        "trace_id": f"trace-{tag}-{seed}",
        "tenant_id": tenant,
    }
    if ip is not None:
        out["ip"] = ip
    return out
