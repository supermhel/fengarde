"""fengarde-loadtest (zero-infra): per-stage + paced end-to-end throughput.

Companion to tools/fengarde_bench.py (batch-mode CPU baseline). This harness
adds what that one does not report: per-stage rates measured event-by-event,
p50/p95 latency, and a paced open-loop end-to-end run at several offered
rates so the saturation point is visible.

Scenarios (each runs in its OWN subprocess so peak RSS is not polluted by an
earlier scenario):

  stage-ws2   normalize_one() per event, closed loop (as fast as it goes).
              Latency = per-event service time.
  stage-ws4   Detector.process()+_emit() per pre-normalized event, closed
              loop, full 46-rule set. Latency = per-event service time.
  e2e         paced open loop at --rates: events "arrive" on a fixed
              schedule, one thread does ws2 -> ws4 -> ws3 (MemoryStore) per
              event. Latency = completion time minus scheduled arrival, so
              queueing delay shows up once offered rate > capacity. A rate
              is "sustained" when achieved >= 95% of offered.

HONEST SCOPE: single Python process, in-memory sink instead of a bus (no
Redis I/O), MemoryStore instead of OpenSearch, source mix is the three
generators in fengarde_bench.py (linux_ssh / cisco_asa / generic_syslog), so
most of the 46 rules are skipped by the class_uid prefilter. Numbers are
CPU-bound ceilings for THIS host, not production capacity.

Run:  python tools/fengarde_loadtest.py                 # full matrix
      python tools/fengarde_loadtest.py --quick         # smoke
      python tools/fengarde_loadtest.py --out benchmark/raw/zero-infra.json
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

DEFAULT_RATES = [100, 250, 500, 1000, 2000]
PROFILE = "realistic"


def pct(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return float("nan")
    i = min(len(sorted_vals) - 1, max(0, int(round(p / 100 * (len(sorted_vals) - 1)))))
    return sorted_vals[i]


def summarize(lat_s: list[float]) -> dict:
    s = sorted(lat_s)
    return {"p50_ms": round(pct(s, 50) * 1000, 3), "p95_ms": round(pct(s, 95) * 1000, 3),
            "p99_ms": round(pct(s, 99) * 1000, 3), "max_ms": round(s[-1] * 1000, 3) if s else None}


PROFILES = ("realistic", "alert-heavy")


def _ssh_fail_user(fb, ip: str, seq: int, base_s: int) -> dict:
    """fb._ssh_fail hard-codes user "admin", which trips the per-account and
    credential-stuffing rules on every line; vary the account instead."""
    e = fb._ssh_fail(ip, seq, base_s)
    e["raw"] = e["raw"].replace("invalid user admin", f"invalid user svc{seq}")
    return e


def generate(fb, n: int, profile: str) -> list[dict]:
    """alert-heavy: fengarde_bench's mix (250 attacker IPs, every ssh line is
    a brute-force hit, so alerts ~= events -- a worst-case stress, not a
    realistic ratio). realistic: ~60% syslog, ~20% ssh fail and ~20% ASA deny
    from mostly-unique sources (below every threshold) plus one 10-line ssh
    brute-force burst per 500 events, so the alert ratio is a small fraction."""
    if profile == "alert-heavy":
        return fb.generate_events(n, mixed=True)
    base = int(time.time()) - n
    out = []
    for i in range(n):
        if i % 500 < 10:
            ip = f"203.0.113.{(i // 500) % 250 + 1}"
            out.append(fb._ssh_fail(ip, i, base))
            continue
        ip = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
        k = i % 5
        out.append(_ssh_fail_user(fb, ip, i, base) if k == 0 else
                   fb._asa_deny(ip, i, base) if k == 1 else fb._generic(ip, i, base))
    return out


class SinkBus:
    """Captures produce() calls; stands in for the bus without Redis I/O."""

    def __init__(self) -> None:
        self.out: list[tuple[str, dict]] = []

    def produce(self, topic, key=None, payload=None, **_kw):
        self.out.append((topic, payload))


def _load_stages():
    """Import ws2/ws3/ws4 exactly as fengarde_bench does (shared module names)."""
    import fengarde_bench as fb  # sets BUS_BACKEND=memory, log level, sys.path
    for m in ("main", "parsers"):
        sys.modules.pop(m, None)
    ws2 = fb._import("ws2-normalization")
    for m in ("main", "engine", "scoring"):
        sys.modules.pop(m, None)
    ws4 = fb._import("ws4-detection")
    for m in ("main", "router"):
        sys.modules.pop(m, None)
    ws3 = fb._import("ws3-indexer")
    return fb, ws2, ws3, ws4


def _rss_mb(fb):
    v = fb.peak_rss_mb()
    return round(v, 1) if v is not None else None


def worker_stage_ws2(n: int) -> dict:
    fb, ws2, _ws3, _ws4 = _load_stages()
    events = generate(fb, n, PROFILE)
    lat, ok = [], 0
    t0 = time.perf_counter()
    for e in events:
        a = time.perf_counter()
        ev, errs = ws2.normalize_one(e)
        lat.append(time.perf_counter() - a)
        ok += 1 if (ev is not None and not errs) else 0
    wall = time.perf_counter() - t0
    return {"scenario": "stage-ws2", "n": n, "ok": ok, "wall_s": round(wall, 3),
            "events_per_s": round(ok / wall, 1) if wall else None,
            **summarize(lat), "peak_rss_mb": _rss_mb(fb)}


def worker_stage_ws4(n: int) -> dict:
    fb, ws2, _ws3, ws4 = _load_stages()
    norm = []
    for e in generate(fb, n, PROFILE):
        ev, errs = ws2.normalize_one(e)
        if ev is not None and not errs:
            norm.append(ev)
    det = ws4.Detector()
    sink = SinkBus()
    lat, alerts = [], 0
    t0 = time.perf_counter()
    for ev in norm:
        a = time.perf_counter()
        scored, matched, action = det.process(ev)
        n_alerts, _ai, _clf = det._emit(sink, scored, matched, action)
        lat.append(time.perf_counter() - a)
        alerts += n_alerts
        if len(sink.out) > 5000:
            sink.out.clear()
    wall = time.perf_counter() - t0
    return {"scenario": "stage-ws4", "n": len(norm), "rules": len(det.rules), "alerts": alerts,
            "wall_s": round(wall, 3), "events_per_s": round(len(norm) / wall, 1) if wall else None,
            **summarize(lat), "peak_rss_mb": _rss_mb(fb)}


def worker_e2e(rate: int, duration_s: float, max_events: int) -> dict:
    """Paced open loop. rate==0 means unpaced (closed loop, max throughput)."""
    fb, ws2, ws3, ws4 = _load_stages()
    n = max_events if rate == 0 else min(max_events, max(500, int(rate * duration_s)))
    events = generate(fb, n, PROFILE)
    det = ws4.Detector()
    store = ws3.make_store()
    sink = SinkBus()
    lat, dropped, indexed, alerts = [], 0, 0, 0

    t0 = time.perf_counter()
    for i, raw in enumerate(events):
        if rate:
            due = t0 + i / rate
            now = time.perf_counter()
            if due > now:
                time.sleep(due - now)
        else:
            due = time.perf_counter()
        ev, errs = ws2.normalize_one(raw)
        if ev is None or errs:
            dropped += 1
            continue
        sink.out.append(("normalized.events", ev))
        scored, matched, action = det.process(ev)
        n_alerts, _ai, _clf = det._emit(sink, scored, matched, action)
        alerts += n_alerts
        for topic, payload in sink.out:
            try:
                ws3.index_doc(store, payload, create_only=(topic == "normalized.events"))
                indexed += 1
            except ValueError:
                pass
        sink.out.clear()
        lat.append(time.perf_counter() - due)
    wall = time.perf_counter() - t0
    done = n - dropped
    achieved = done / wall if wall else 0.0
    return {"scenario": "e2e", "offered_eps": rate or "max", "n": n, "dropped": dropped,
            "alerts": alerts, "docs_indexed": indexed, "wall_s": round(wall, 3),
            "achieved_eps": round(achieved, 1),
            "sustained": (achieved >= 0.95 * rate) if rate else None,
            **summarize(lat), "peak_rss_mb": _rss_mb(fb)}


def run_worker(argv: list[str]) -> dict:
    ap = argparse.ArgumentParser()
    ap.add_argument("--worker", required=True)
    ap.add_argument("--n", type=int, default=20000)
    ap.add_argument("--rate", type=int, default=0)
    ap.add_argument("--duration", type=float, default=10.0)
    ap.add_argument("--max-events", type=int, default=30000)
    ap.add_argument("--profile", default="realistic", choices=PROFILES)
    a = ap.parse_args(argv)
    global PROFILE
    PROFILE = a.profile
    if a.worker == "stage-ws2":
        return worker_stage_ws2(a.n)
    if a.worker == "stage-ws4":
        return worker_stage_ws4(a.n)
    return worker_e2e(a.rate, a.duration, a.max_events)


def spawn(args: list[str]) -> dict:
    env = dict(os.environ, FENGARDE_LOG_LEVEL="error", PYTHONUNBUFFERED="1")
    p = subprocess.run([sys.executable, __file__, *args], capture_output=True, text=True, env=env)
    lines = [l for l in p.stdout.splitlines() if l.startswith("{")]
    if p.returncode != 0 or not lines:
        return {"error": f"exit {p.returncode}", "stderr_tail": p.stderr[-600:], "args": args}
    return json.loads(lines[-1])


def main() -> int:
    if "--worker" in sys.argv:
        print(json.dumps(run_worker(sys.argv[1:])))
        return 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--n", type=int, default=20000, help="events per stage scenario")
    ap.add_argument("--rates", type=int, nargs="*", default=DEFAULT_RATES)
    ap.add_argument("--duration", type=float, default=10.0, help="seconds per paced rate")
    ap.add_argument("--max-events", type=int, default=30000)
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--profiles", nargs="*", default=list(PROFILES), choices=PROFILES)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    if a.quick:
        a.n, a.rates, a.duration, a.max_events = 2000, [200, 1000], 3.0, 3000

    results = {"meta": {
        "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": platform.platform(), "machine": platform.machine(),
        "processor": platform.processor(), "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "git_head": subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                                   capture_output=True, text=True).stdout.strip(),
        "params": {"profiles": a.profiles, "n": a.n, "rates": a.rates, "duration_s": a.duration, "repeat": a.repeat}},
        "runs": []}
    for prof in a.profiles:
        for r in range(a.repeat):
            for sc in ("stage-ws2", "stage-ws4"):
                res = spawn(["--worker", sc, "--n", str(a.n), "--profile", prof])
                res.update(repeat=r, profile=prof)
                results["runs"].append(res)
                print(json.dumps(res), flush=True)
            for rate in [*a.rates, 0]:
                res = spawn(["--worker", "e2e", "--rate", str(rate), "--duration", str(a.duration),
                             "--max-events", str(a.max_events), "--profile", prof])
                res.update(repeat=r, profile=prof)
                results["runs"].append(res)
                print(json.dumps(res), flush=True)
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 1 if any("error" in r for r in results["runs"]) else 0


if __name__ == "__main__":
    sys.exit(main())
