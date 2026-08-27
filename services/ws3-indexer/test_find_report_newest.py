"""Gap-hunt finding R4-#4: MemoryStore.find_report must return the NEWEST
copy of a report across a daily-index roll-over, matching OpenSearchStore's
find_report (which sorts generated_at desc).

The report_id is deterministic (f"{alert_id}:report"), but regenerating a
report on a later day lands in a newer daily reports-* index while the old
copy still exists. The memory backend used to return the FIRST (oldest)
match; this test proves it now returns the newest by generated_at.

Run: python services/ws3-indexer/test_find_report_newest.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from storage.memory import MemoryStore  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


_DAY1_MS = 1_750_000_000_000          # e.g. day 1
_DAY2_MS = _DAY1_MS + 86_400_000      # day 2 regeneration


def _report(alert_id, generated_at, body_marker):
    return {
        "report_id": f"{alert_id}:report",
        "alert_id": alert_id,
        "format": "markdown",
        "body": f"report-{body_marker}",
        "status": "draft",
        "generated_at": generated_at,
        "backend": "template",
    }


def test_find_report_return_newest_after_rollover():
    """Day-1 report indexed into the day-1 index; then a regeneration indexed
    into the day-2 index (report_id identical). find_report must return the
    day-2 (newest) doc, not yesterday's stale copy."""
    store = MemoryStore()
    store.index("reports-2026.07.16", "a1:report", _report("a1", _DAY1_MS, "day1"))
    store.index("reports-2026.07.17", "a1:report", _report("a1", _DAY2_MS, "day2"))

    found = store.find_report("a1")
    check(found is not None, "find_report must locate an existing report")
    check(found is not None and found["body"] == "report-day2",
          f"find_report must return the NEWEST (day-2) report, got {found and found['body']}")

    # Mutation-sound: reversing the insertion order must not change the result
    # (correctness keys off generated_at, not storage order).
    store2 = MemoryStore()
    store2.index("reports-2026.07.17", "a1:report", _report("a1", _DAY2_MS, "day2"))
    store2.index("reports-2026.07.16", "a1:report", _report("a1", _DAY1_MS, "day1"))
    found2 = store2.find_report("a1")
    check(found2 is not None and found2["body"] == "report-day2",
          "find_report must be insertion-order independent (newest by generated_at)")


def test_find_report_unknown_id_returns_none():
    store = MemoryStore()
    store.index("reports-2026.07.16", "a1:report", _report("a1", _DAY1_MS, "day1"))
    check(store.find_report("does-not-exist") is None,
          "an unknown alert_id must yield None, not crash")


def main():
    test_find_report_return_newest_after_rollover()
    test_find_report_unknown_id_returns_none()

    if FAILS:
        print(f"[FAIL] find_report roll-over: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] R4-#4 MemoryStore.find_report returns the NEWEST report across a "
          "daily-index roll-over (matches OpenSearchStore), insertion-order independent")


if __name__ == "__main__":
    main()