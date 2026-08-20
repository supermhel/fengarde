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
  - live-stack EPS on a defined reference box (4 vCPU / 8 GB VPS per the
    plan) -- see tools/fengarde_bench_live.py for the live-stack sibling
    that closes this TODO against a real Docker/Redis/OpenSearch stack

What IS now measured (2026-08-19, closes the "before/after" TODO this
docstring used to list):
  - rule-prefilter before/after (--compare-prefilter): ws4-detection's B1
    class_uid bucket index vs. a forced linear scan of every rule against
    every event (Detector(force_linear_scan=True), a measurement-only knob
    added to main.py specifically for this comparison -- never used on any
    real code path).

Run:  python tools/fengarde_bench.py --events 5000
      python tools/fengarde_bench.py --events 50000 --mixed
      python tools/fengarde_bench.py --events 20000 --mixed --compare-prefilter
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
import time
from pathlib import Path

# P2-2 (2026-07-21 audit): `resource` is Unix-only (POSIX), so an unconditional
# `import resource` crashed this tool with ModuleNotFoundError on Windows --
# the exact host this repo's dev environment runs on, making the README's
# published numbers unreproducible there. Imported lazily/optionally instead;
# peak_rss_mb() falls back to a Windows-native reading (or None) rather than
# crashing the whole benchmark over an RSS metric.
try:
    import resource  # type: ignore
except ImportError:  # Windows
    resource = None  # type: ignore[assignment]

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
    # 2026-08-07: `meta.received_at` becomes the event's `time` (see
    # linux_ssh.py::_time_ms and its siblings), and engine.py's window-
    # poisoning guard fail-closes any event more than _MAX_CLOCK_SKEW_MS
    # (5 minutes) in the future. The old `base_s + i` layout marched every
    # event FORWARD from "now" as `i` grew, so past i~300 every event in a
    # run was silently dropped from driving stateful windows -- flooding
    # stdout with one WARN per stateful rule per affected event and making
    # the timed section massively slower (observed ~9x on a 20k run), not
    # a real per-event processing cost. Same bug class already fixed in
    # eval/attack/fire_check.py and tools/chaos_test.py: lay events out in
    # the PAST relative to `base_s`, never the future, regardless of `n`.
    # Each helper computes `received_at = base_s + seq` internally, so passing
    # a constant `base_s - n` here (not a per-event value) makes that internal
    # `+ seq` land exactly on `base_s - n + i` for every event -- max is
    # `base_s - 1` (i = n-1), always in the past, regardless of `n`.
    run_base = int(time.time()) - n
    events = []
    for i in range(n):
        ip = f"198.51.100.{(i % 250) + 1}"
        if not mixed:
            events.append(_ssh_fail(ip, i, run_base))
        else:
            gen = (_ssh_fail, _asa_deny, _generic)[i % 3]
            events.append(gen(ip, i, run_base))
    return events


def peak_rss_mb() -> float | None:
    """Peak resident memory in MB, or None if it can't be measured on this
    platform (never crashes the benchmark over an RSS reading)."""
    if resource is not None:
        # ru_maxrss is KB on Linux, bytes on macOS -- this repo's CI/dev
        # targets are Linux, so KB is the documented assumption here.
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # type: ignore[attr-defined]  # POSIX-only, guarded above
    if sys.platform == "win32":
        # P2-2: stdlib-only Windows equivalent via the psapi PROCESS_MEMORY_
        # COUNTERS struct (ctypes, no third-party dependency, same "no dep"
        # constraint the Linux path already documents).
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        # restype/argtypes MUST be set explicitly: ctypes' default restype
        # (c_int, 32-bit) truncates GetCurrentProcess()'s 64-bit pseudo-
        # handle on 64-bit Python, corrupting it before GetProcessMemoryInfo
        # ever sees it (verified live: silently returns ok=0,
        # GetLastError()=6/ERROR_INVALID_HANDLE without this).
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        psapi = ctypes.windll.psapi  # type: ignore[attr-defined]
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        handle = kernel32.GetCurrentProcess()
        ok = psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)
        if not ok:
            return None
        return counters.PeakWorkingSetSize / (1024 * 1024)
    return None


def run_bench(n: int, mixed: bool, force_linear_scan: bool = False) -> dict:
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
    det = ws4.Detector(force_linear_scan=force_linear_scan)
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
        "rule_prefilter": "linear_scan" if force_linear_scan else "class_uid_bucket",
        "rule_count": len(det.rules),
        "counts": {"normalized": c2["normalized"], "dropped": c2["dropped"],
                   "scored": c4["scored"], "alerts": c4["alerts"],
                   "indexed": c3["indexed"]},
        "stage_seconds": {"produce": round(t_produce, 4), "normalize": round(t_normalize, 4),
                           "detect": round(t_detect, 4), "index": round(t_index, 4)},
        "total_seconds": round(total_s, 4),
        "sustained_eps": round(n / total_s, 1) if total_s > 0 else None,
        "peak_rss_mb": round(_rss, 1) if (_rss := peak_rss_mb()) is not None else None,
    }


def _run_prefilter_comparison(n: int, mixed: bool, as_json: bool) -> int:
    """Runs the SAME generated event set through the detect stage twice --
    once with the real B1 class_uid bucket index, once with it forced off
    (linear scan of every rule) -- and reports the delta. Same event set
    both times (generate_events(n, mixed) is deterministic for a given
    call, only the wall-clock base shifts) so the comparison isolates the
    prefilter's own effect from any other run-to-run variance."""
    with_bucket = run_bench(n, mixed, force_linear_scan=False)
    linear = run_bench(n, mixed, force_linear_scan=True)

    t_bucket = with_bucket["stage_seconds"]["detect"]
    t_linear = linear["stage_seconds"]["detect"]
    speedup = (t_linear / t_bucket) if t_bucket > 0 else None

    if as_json:
        print(json.dumps({"class_uid_bucket": with_bucket, "linear_scan": linear,
                           "detect_stage_speedup_x": round(speedup, 2) if speedup else None},
                          indent=2))
        return 0

    print("fengarde-bench -- rule-prefilter before/after (B1 class_uid bucket vs. linear scan)")
    print(f"  events:        {n} ({'mixed ssh/asa/syslog' if mixed else 'linux_ssh only'}), "
          f"{with_bucket['rule_count']} rules loaded")
    print(f"  detect stage:  bucket={t_bucket}s   linear={t_linear}s")
    print(f"  speedup:       {round(speedup, 2)}x" if speedup else "  speedup:       n/a")
    print("  (isolates ws4-detection's B1 class_uid index; produce/normalize/index stages "
          "are unaffected by this flag and shown here only for context)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--events", type=int, default=5000)
    ap.add_argument("--mixed", action="store_true",
                     help="rotate ssh/asa/generic_syslog sources instead of ssh-only")
    ap.add_argument("--json", action="store_true", help="machine-readable output only")
    ap.add_argument("--compare-prefilter", action="store_true",
                     help="run detect stage twice (B1 class_uid bucket vs. forced linear "
                          "rule scan) and print the before/after delta instead of a single result")
    args = ap.parse_args()

    if args.compare_prefilter:
        return _run_prefilter_comparison(args.events, args.mixed, args.json)

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
    rss = result["peak_rss_mb"]
    print(f"  peak RSS:          {f'{rss} MB' if rss is not None else 'not available on this platform'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
