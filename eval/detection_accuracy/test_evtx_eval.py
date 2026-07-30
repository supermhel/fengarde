"""Regression for H7 (2026-07-30 audit): evtx_eval.in_business_hours() must
agree with the real engine (services/ws4-detection/engine.py::
_time_outside_hours) at every boundary, in particular the 18:00:00-18:00:59
minute the old oracle got backwards (treated as inside hours; the real
engine's `start <= minute_of_day < end` treats it as outside).

Run with:
    python eval/detection_accuracy/test_evtx_eval.py
"""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVICES = ROOT / "services"
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES / "ws4-detection"))

from evtx_eval import in_business_hours  # noqa: E402
from engine import _time_outside_hours  # noqa: E402  -- reuse the engine's own predicate

_SPEC = {"start": "08:00", "end": "18:00"}  # common_after_hours_admin's real window


def _ms(hour, minute, day=1):
    # 2024-01-01 is a Monday.
    dt = datetime(2024, 1, day, hour, minute, tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


class TestInBusinessHoursMatchesEngine(unittest.TestCase):

    def _assert_agrees(self, hour, minute, day=1):
        t_ms = _ms(hour, minute, day)
        oracle_in_hours = in_business_hours(t_ms)
        engine_outside = _time_outside_hours(_SPEC, t_ms)
        self.assertEqual(
            oracle_in_hours, not engine_outside,
            f"{hour:02d}:{minute:02d} disagreement: oracle in_hours="
            f"{oracle_in_hours}, engine outside_hours={engine_outside}")

    def test_18_00_00_is_outside_hours(self):
        """The exact regression: the old oracle treated 18:00:00 as inside
        business hours; the real engine treats it as outside."""
        self._assert_agrees(18, 0)
        self.assertFalse(in_business_hours(_ms(18, 0)))

    def test_18_00_30_seconds_also_outside(self):
        t_ms = _ms(18, 0) + 30_000
        self.assertFalse(in_business_hours(t_ms))
        self.assertTrue(_time_outside_hours(_SPEC, t_ms))

    def test_17_59_is_inside_hours(self):
        self._assert_agrees(17, 59)
        self.assertTrue(in_business_hours(_ms(17, 59)))

    def test_08_00_is_inside_hours(self):
        self._assert_agrees(8, 0)
        self.assertTrue(in_business_hours(_ms(8, 0)))

    def test_07_59_is_outside_hours(self):
        self._assert_agrees(7, 59)
        self.assertFalse(in_business_hours(_ms(7, 59)))

    def test_midday_is_inside_hours(self):
        self._assert_agrees(12, 30)

    def test_weekend_is_outside_hours_regardless_of_time(self):
        # 2024-01-06 is a Saturday.
        t_ms = _ms(10, 0, day=6)
        self.assertFalse(in_business_hours(t_ms))
        self.assertTrue(_time_outside_hours(_SPEC, t_ms))


if __name__ == "__main__":
    unittest.main(verbosity=2)
