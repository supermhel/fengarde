"""Gap-hunt R4 #107 / #108: the bench must fail on mass drops, and live-bench burst ids must be unique per run.

Zero-infra. ``fengarde_bench_live`` imports ``redis`` at module scope; the client is never used here.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


bench = _load("fengarde_bench")
live = _load("fengarde_bench_live")

FAILS: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        FAILS.append(msg)


def _result(dropped_majority: bool) -> dict:
    return {"n_events": 1000, "mixed_sources": False,
            "counts": {"normalized": 10 if dropped_majority else 1000, "dropped": 990 if dropped_majority else 0,
                       "scored": 0, "alerts": 0, "indexed": 0},
            "eps_dropped_majority": dropped_majority}


def test_verdict() -> None:
    check(bench._verdict(_result(True)) == 1, "R4 #107: a mass-drop run must exit 1")
    check(bench._verdict(_result(False)) == 0, "R4 #107: a healthy run must exit 0")


def test_main_exit_code() -> None:
    for argv in (["fengarde_bench.py", "--json"], ["fengarde_bench.py"]):
        with mock.patch.object(bench, "run_bench", return_value={**_result(True), "stage_seconds": {
                "produce": 0, "normalize": 0, "detect": 0, "index": 0}, "sustained_eps": 1.0, "peak_rss_mb": None}), \
                mock.patch.object(sys, "argv", argv):
            check(bench.main() == 1, f"R4 #107: main({argv[1:]}) must return 1 when most events were dropped")


def test_burst_ids_unique_per_run() -> None:
    a = {e["meta"]["ingest_id"] for e in live._ssh_burst("203.0.113.9", 1000, run_tag="aaaa1111")}
    b = {e["meta"]["ingest_id"] for e in live._ssh_burst("203.0.113.9", 1000, run_tag="bbbb2222")}
    check(len(a) == 10 and len(b) == 10, "R4 #108: a burst must carry 10 distinct ingest_ids")
    check(a.isdisjoint(b), "R4 #108: two runs on the same ip must not share ingest_ids (WS-3 would dedupe the second)")
    same = {e["meta"]["ingest_id"] for e in live._ssh_burst("203.0.113.9", 1000, run_tag="aaaa1111")}
    check(a == same, "R4 #108: ids stay deterministic within one run tag")


if __name__ == "__main__":
    test_verdict()
    test_main_exit_code()
    test_burst_ids_unique_per_run()
    if FAILS:
        print(f"[FAIL] bench gates: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] bench gates: mass-drop run exits 1 (JSON and text), live-bench burst ids are unique per run")
