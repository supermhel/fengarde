"""Gap-hunt finding (2026-08-23): coverage_gate.py's floors are frozen
numbers with a disclosed buffer baked into each one by comment -- real
coverage could erode silently within that buffer forever, with the gate
printing [OK] the whole way down and nothing prompting anyone to notice
before it actually breaches. Fix: a [WARN] once a service's live buffer
drops under `_LOW_BUFFER_WARN_PTS`, in the same run that still passes.

`measure()` shells out to the real `coverage` CLI across the whole repo, so
this monkeypatches it rather than re-running real coverage collection --
these tests are about main()'s OK/WARN/FAIL decision, not about coverage.py
itself.
"""
from __future__ import annotations

import io
import sys
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import coverage_gate as cg  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _run_main_with(pct_by_service: dict, floor_by_service: dict | None = None):
    """Run main() against a fake TARGETS/measure(), return (returncode, stdout)."""
    orig_targets = cg.TARGETS
    orig_measure = cg.measure
    floor_by_service = floor_by_service or {}
    try:
        cg.TARGETS = {
            svc: ("fake/source", ["fake_test.py"], floor_by_service.get(svc, 50.0))
            for svc in pct_by_service
        }
        cg.measure = lambda service_dir, source, scripts: pct_by_service[service_dir]
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cg.main()
        return rc, buf.getvalue()
    finally:
        cg.TARGETS = orig_targets
        cg.measure = orig_measure


def test_comfortably_above_floor_is_ok_no_warn():
    rc, out = _run_main_with({"svc-a": 80.0}, {"svc-a": 50.0})
    check(rc == 0, f"comfortable margin must PASS, got rc={rc}")
    check("[WARN]" not in out, f"a 30pt buffer must not warn, got:\n{out}")
    check("coverage gate PASS" in out and "see [WARN]" not in out, f"clean PASS message expected:\n{out}")


def test_below_floor_is_fail():
    rc, out = _run_main_with({"svc-a": 40.0}, {"svc-a": 50.0})
    check(rc == 1, f"below-floor must FAIL, got rc={rc}")
    check("[FAIL] svc-a" in out, f"must name the failing service:\n{out}")


def test_thin_buffer_warns_but_still_passes():
    """The whole point of the fix: erosion visible BEFORE it's a failure."""
    rc, out = _run_main_with({"svc-a": 51.0}, {"svc-a": 50.0})  # 1.0pt buffer
    check(rc == 0, f"still above floor -> must still PASS, got rc={rc}")
    check("[WARN] svc-a" in out, f"a 1.0pt buffer must trigger a WARN, got:\n{out}")
    check("see [WARN] above" in out, f"the final PASS line must flag that a warning fired:\n{out}")


def test_buffer_exactly_at_warn_threshold_does_not_warn():
    """Boundary: the threshold itself is the edge of comfortable, not thin."""
    rc, out = _run_main_with({"svc-a": 53.0}, {"svc-a": 50.0})  # exactly 3.0pt
    check(rc == 0, "must PASS")
    check("[WARN]" not in out, f"exactly at the threshold must not warn (< not <=), got:\n{out}")


def test_multiple_services_independent_verdicts():
    rc, out = _run_main_with(
        {"svc-ok": 90.0, "svc-thin": 51.0, "svc-fail": 30.0},
        {"svc-ok": 50.0, "svc-thin": 50.0, "svc-fail": 50.0},
    )
    check(rc == 1, "any single failure must fail the whole gate")
    check("[OK] svc-ok" in out and "[WARN] svc-ok" not in out, f"svc-ok must be clean OK:\n{out}")
    check("[WARN] svc-thin" in out, f"svc-thin must warn:\n{out}")
    check("[FAIL] svc-fail" in out, f"svc-fail must fail:\n{out}")


def run_all() -> None:
    tests = [
        test_comfortably_above_floor_is_ok_no_warn,
        test_below_floor_is_fail,
        test_thin_buffer_warns_but_still_passes,
        test_buffer_exactly_at_warn_threshold_does_not_warn,
        test_multiple_services_independent_verdicts,
    ]
    for t in tests:
        t()
    if FAILS:
        print(f"[FAIL] coverage_gate verdict logic: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print(f"[OK] coverage_gate OK/WARN/FAIL verdict logic PASS ({len(tests)} scenarios)")


if __name__ == "__main__":
    run_all()
