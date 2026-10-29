"""Smoke tests for tools/fengarde_loadtest.py (zero-infra, no timing assertions).

Guards the two things that silently made earlier numbers meaningless: the
percentile helper, and the 'realistic' profile staying alert-light (a profile
that alerts on most events measures alert construction, not throughput).
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import fengarde_loadtest as L  # noqa: E402

FAILS: list[str] = []


def check(name: str, ok: bool) -> None:
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    if not ok:
        FAILS.append(name)


def main() -> int:
    vals = [i / 1000 for i in range(1, 101)]
    s = L.summarize(vals)
    check("p50 of 1..100ms is ~50ms", 49 <= s["p50_ms"] <= 51)
    check("p95 of 1..100ms is ~95ms", 94 <= s["p95_ms"] <= 96)
    check("empty percentile is nan", L.pct([], 50) != L.pct([], 50))

    res = L.worker_e2e(rate=0, duration_s=0, max_events=600)
    check("e2e processes every generated event", res["dropped"] == 0 and res["n"] == 600)
    check("realistic profile alert ratio < 5%", res["alerts"] < 0.05 * res["n"])
    check("e2e reports a rate and peak RSS field", res["achieved_eps"] > 0 and "peak_rss_mb" in res)

    if FAILS:
        print(f"\n{len(FAILS)} FAILED: {FAILS}")
        return 1
    print("\nall passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
