"""Where does WS-4's live per-event time go? (benchmark/loadtest.md section 4)

Runs the real Detector against a REAL Redis (window counter + bus) one event at
a time, the way ws4's daemon handler does, and reports events/s, Redis round
trips per event (counted at the socket write, one pipeline = one round trip),
and a cProfile top list. Zero-infra WS-4 does ~4,500 events/s; the live
daemon manages ~75-100, so the difference is I/O, and this attributes it.

Run (inside the compose network so the RTT matches the real service):
  docker run --rm --network fgloadtest_default -v <repo>:/repo:ro \\
     -e BUS_BACKEND=redis -e REDIS_URL=redis://redis:6379/0 \\
     --entrypoint python fgloadtest-ws4-detection /repo/tools/fengarde_ws4_profile.py
"""
from __future__ import annotations

import argparse
import cProfile
import io
import os
import pstats
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
os.environ.setdefault("FENGARDE_LOG_LEVEL", "error")
bus_backend = os.environ.get("BUS_BACKEND", "redis")

import redis  # noqa: E402
import redis.connection  # noqa: E402

import fengarde_loadtest as L  # noqa: E402

TRIPS = {"n": 0}
_orig = redis.connection.Connection.send_packed_command


def _counting(self, command, check_health=True):
    TRIPS["n"] += 1
    return _orig(self, command, check_health)


redis.connection.Connection.send_packed_command = _counting  # type: ignore[method-assign]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--profile", default="realistic", choices=L.PROFILES)
    ap.add_argument("--no-window-counter", action="store_true",
                    help="keep the in-process deque window counter (isolate the Redis window cost)")
    ap.add_argument("--no-lua", action="store_true",
                    help="window counter with the original MULTI pipelines (use_lua=False)")
    ap.add_argument("--full-evidence", action="store_true",
                    help="alert evidence via the original full-window ZRANGE (hide members_capped)")
    ap.add_argument("--top", type=int, default=14)
    a = ap.parse_args()

    fb, ws2, _ws3, ws4 = L._load_stages()
    # fengarde_bench (imported by the loadtest module) forces BUS_BACKEND=memory
    # at import; this profile needs the REAL bus for the produce/ack round trips.
    os.environ["BUS_BACKEND"] = bus_backend
    from shared.bus import Bus
    from shared.window import RedisWindowCounter

    client = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
                                  decode_responses=True)
    client.ping()
    det = ws4.Detector()
    if not a.no_window_counter:
        counter = RedisWindowCounter(client, use_lua=False if a.no_lua else None)
        if a.full_evidence:
            counter.members_capped = None  # type: ignore[assignment]  # engine falls back to members()
        det._window_counter = counter
        for r in det.rules:
            if r.stateful:
                r.set_counter(counter)
    bus = Bus()
    events = []
    for raw in L.generate(fb, a.n, a.profile):
        ev, errs = ws2.normalize_one(raw)
        if ev is not None and not errs:
            events.append(ev)
    # warm connections before timing
    ws4.detect_one(bus, det, events[0])
    TRIPS["n"] = 0

    prof = cProfile.Profile()
    t0 = time.perf_counter()
    prof.enable()
    for ev in events[1:]:
        ws4.detect_one(bus, det, ev)
    prof.disable()
    wall = time.perf_counter() - t0
    n = len(events) - 1
    print(f"events={n} profile={a.profile} window_counter={'deque' if a.no_window_counter else 'redis'} "
          f"lua={not a.no_lua} capped_evidence={not a.full_evidence}")
    print(f"events/s (under cProfile): {n / wall:.0f}   ms/event: {wall / n * 1000:.2f}")
    print(f"redis round trips/event: {TRIPS['n'] / n:.2f}")
    s = io.StringIO()
    pstats.Stats(prof, stream=s).sort_stats("cumulative").print_stats(a.top)
    print("\n".join(ln for ln in s.getvalue().splitlines() if ln.strip())[:3500])
    return 0


if __name__ == "__main__":
    sys.exit(main())
