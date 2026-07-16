"""fengarde-bench (M2 public proof artifact, PLAN_C Tier 2.1).

Reproducible load generator + throughput/footprint measurement for the
normalize -> detect -> index path.

HONESTY NOTE (read before citing these numbers anywhere): this harness runs
zero-infra -- one process, the in-memory bus, MemoryStore -- because the
environment this was authored in has no Docker daemon (see
docs/degradation-matrix.md and the M1 chaos-gate commit for why). That makes
the numbers below a real, reproducible **CPU-bound processing-speed baseline**
for WS-2/WS-4/WS-3's Python code, NOT a measurement of live-stack throughput:
it excludes Redis network I/O, OpenSearch indexing latency, and any real
queuing/backpressure behavior. Do not publish these as "FENGARDE handles N
events/sec in production" -- that claim needs this same harness pointed at
BUS_BACKEND=redis + STORAGE_BACKEND=opensearch on the reference box the
roadmap calls for, which is a still-open TODO (needs Docker).

What IS measured honestly here:
  - sustained EPS: batch-mode normalize+detect+index throughput, this host
  - peak resident memory during the run (resource.getrusage, stdlib, no dep)

What is NOT measured here (open TODO, needs live infra):
  - p50/p99 ingest->alert latency (batch processing has no realistic queuing
    delay to measure -- that number only means something against a live bus)
  - live-stack EPS on a defined reference box (4 vCPU / 8 GB VPS per the plan)
  - before/after numbers for the rule prefilter (needs a harness change to
    force a linear rule scan for comparison -- not built this pass)

Run:  python tools/fengarde_bench.py --events 5000
      python tools/fengarde_bench.py --events 50000 --mixed
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import resource
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
os.environ["BUS_BACKEND"] = "memory"
sys.path.insert(0, str(SERVICES))

from shared.bus import Bus  # noqa: E402


def _import(ws_dir: str, mod: str = "main"):
    p = str(SERVICES / ws_dir)
    if p in sys.path:
        sys.path.remove(p)
    sys.path.insert(0, p)
    return importlib.import_module(mod)


def _ssh_fail(ip: str, seq: int, base_s: int) -> dict:
    return {
        "source_type": "linux_ssh",
        "raw": (f"Jun 10 13:55:{seq % 60:02d} db01 sshd[2154]: "
                f"Failed password for invalid user admin from {ip} port 51000 ssh2"),
        "meta": {"received_at": base_s + seq, "ingest_id": f"bench-ssh-{ip}-{seq}"},
    }


def _asa_deny(ip: str, seq: int, base_s: int) -> dict:
    return {
        "source_type": "cisco_asa",
        "raw": (f"%ASA-4-106023: Deny tcp src outside:{ip}/{40000 + seq} "
                f"dst inside:10.0.0.5/{seq % 65535} by access-group \"OUTSIDE\""),
        "meta": {"received_at": base_s + seq, "ingest_id": f"bench-asa-{ip}-{seq}"},
    }


def _generic(ip: str, seq: int, base_s: int) -> dict:
    return {
        "source_type": "generic_syslog",
        "raw": f"<134>Jun 10 13:55:{seq % 60:02d} host{seq % 20} app[123]: bench event {seq}",
        "meta": {"received_at": base_s + seq},
    }


def generate_events(n: int, mixed: bool) -> list[dict]:
    base_s = int(time.time())
    events = []
    for i in range(n):
        ip = f"198.51.100.{(i % 250) + 1}"
        if not mixed:
            events.append(_ssh_fail(ip, i, base_s))
        else:
            gen = (_ssh_fail, _asa_deny, _generic)[i % 3]
            events.append(gen(ip, i, base_s))
    return events


def peak_rss_mb() -> float:
    # ru_maxrss is KB on Linux, bytes on macOS -- this repo's CI/dev targets
    # are Linux, so KB is the documented assumption here.
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def run_bench(n: int, mixed: bool) -> dict:
    bus = Bus()
    events = generate_events(n, mixed)

    t0 = time.perf_counter()
    for e in events:
        bus.produce("raw.events", key=e["meta"].get("ingest_id", ""), payload=e)
    t_produce = time.perf_counter() - t0

    for m in ("main", "parsers"):
        sys.modules.pop(m, None)
    ws2 = _import("ws2-normalization")
    t0 = time.perf_counter()
    c2 = ws2.run(bus)
    t_normalize = time.perf_counter() - t0

    for m in ("main", "engine", "scoring"):
        sys.modules.pop(m, None)
    ws4 = _import("ws4-detection")
    det = ws4.Detector()
    t0 = time.perf_counter()
    c4 = ws4.run(bus, det)
    t_detect = time.perf_counter() - t0

    for m in ("main", "router"):
        sys.modules.pop(m, None)
    ws3 = _import("ws3-indexer")
    store = ws3.make_store()
    t0 = time.perf_counter()
    c3 = ws3.run(bus, store)
    t_index = time.perf_counter() - t0

    total_s = t_produce + t_normalize + t_detect + t_index
    return {
        "n_events": n,
        "mixed_sources": mixed,
        "counts": {"normalized": c2["normalized"], "dropped": c2["dropped"],
                   "scored": c4["scored"], "alerts": c4["alerts"],
                   "indexed": c3["indexed"]},
        "stage_seconds": {"produce": round(t_produce, 4), "normalize": round(t_normalize, 4),
                           "detect": round(t_detect, 4), "index": round(t_index, 4)},
        "total_seconds": round(total_s, 4),
        "sustained_eps": round(n / total_s, 1) if total_s > 0 else None,
        "peak_rss_mb": round(peak_rss_mb(), 1),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--events", type=int, default=5000)
    ap.add_argument("--mixed", action="store_true",
                     help="rotate ssh/asa/generic_syslog sources instead of ssh-only")
    ap.add_argument("--json", action="store_true", help="machine-readable output only")
    args = ap.parse_args()

    result = run_bench(args.events, args.mixed)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print("fengarde-bench -- ZERO-INFRA baseline (see this file's module docstring "
          "for what this number does and does not represent)")
    print(f"  events:            {result['n_events']} "
          f"({'mixed ssh/asa/syslog' if result['mixed_sources'] else 'linux_ssh only'})")
    print(f"  normalized/scored/indexed: {result['counts']['normalized']}/"
          f"{result['counts']['scored']}/{result['counts']['indexed']}  "
          f"(alerts={result['counts']['alerts']}, dropped={result['counts']['dropped']})")
    print(f"  stage times (s):   produce={result['stage_seconds']['produce']} "
          f"normalize={result['stage_seconds']['normalize']} "
          f"detect={result['stage_seconds']['detect']} "
          f"index={result['stage_seconds']['index']}")
    print(f"  sustained EPS:     {result['sustained_eps']}")
    print(f"  peak RSS:          {result['peak_rss_mb']} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
