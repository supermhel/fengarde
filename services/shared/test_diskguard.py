"""M4.6 ops lifecycle: disk-headroom guardrail tests.

Runs shutil.disk_usage() against the REAL filesystem (a temp directory) --
no mocking of disk state. The "not enough space" branch is proven honestly
by setting a threshold above the real disk's actual capacity/free space,
never by faking disk_usage's return value.

Run: python services/shared/test_diskguard.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from shared.diskguard import check_disk_headroom  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_a_real_tmp_dir_has_headroom_under_a_trivial_floor():
    with tempfile.TemporaryDirectory() as d:
        ok, detail = check_disk_headroom(d, min_free_bytes=1, min_free_pct=0.0)
        check(ok, f"a real filesystem must pass a near-zero floor, got {detail}")
        check(detail["total_bytes"] > 0, "a real disk_usage() call must report a nonzero total")


def test_an_absurdly_high_absolute_floor_fails_honestly():
    with tempfile.TemporaryDirectory() as d:
        # A floor larger than any real disk this test could plausibly run on
        # -- the REAL shutil.disk_usage() call still runs; only the floor is
        # deliberately unreachable, proving the comparison logic for real.
        impossible_bytes = 10**18  # an exabyte
        ok, detail = check_disk_headroom(d, min_free_bytes=impossible_bytes, min_free_pct=0.0)
        check(not ok, f"an impossible absolute floor must fail, got ok=True, detail={detail}")


def test_an_absurdly_high_percentage_floor_fails_honestly():
    with tempfile.TemporaryDirectory() as d:
        ok, detail = check_disk_headroom(d, min_free_bytes=0, min_free_pct=200.0)
        check(not ok, f"a >100% floor can never be satisfied, got ok=True, detail={detail}")


def test_both_floors_must_pass():
    with tempfile.TemporaryDirectory() as d:
        ok, _ = check_disk_headroom(d, min_free_bytes=1, min_free_pct=200.0)
        check(not ok, "failing EITHER floor must fail the overall check")


def test_nonexistent_path_walks_up_to_a_real_ancestor():
    with tempfile.TemporaryDirectory() as d:
        deep = Path(d) / "does" / "not" / "exist" / "yet"
        ok, detail = check_disk_headroom(deep, min_free_bytes=1, min_free_pct=0.0)
        check(ok, f"a not-yet-created path must resolve to a real existing ancestor, got {detail}")
        check(detail["path"] == str(Path(d)),
              f"the resolved ancestor must be the real existing directory ({d}), got {detail['path']}")


def test_result_never_raises_on_a_totally_bogus_path():
    # An empty string / relative garbage must degrade to a (False, detail)
    # tuple, never propagate an exception -- callers like BoundedSpool.append
    # rely on this never raising.
    ok, detail = check_disk_headroom("")
    check(isinstance(ok, bool), f"must always return a bool, got {type(ok)}")
    check(isinstance(detail, dict), "must always return a detail dict, even on failure")


def main():
    test_a_real_tmp_dir_has_headroom_under_a_trivial_floor()
    test_an_absurdly_high_absolute_floor_fails_honestly()
    test_an_absurdly_high_percentage_floor_fails_honestly()
    test_both_floors_must_pass()
    test_nonexistent_path_walks_up_to_a_real_ancestor()
    test_result_never_raises_on_a_totally_bogus_path()

    if FAILS:
        print(f"[FAIL] diskguard: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] M4.6 disk-headroom guardrail: real shutil.disk_usage() checks pass/fail "
          "correctly against real thresholds, both floors required, nonexistent path walks "
          "up to a real ancestor, never raises on a bogus path")


if __name__ == "__main__":
    main()
