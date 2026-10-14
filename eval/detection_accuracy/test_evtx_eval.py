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

from evtx_eval import (in_business_hours, _verdict, _real_host, oracle,  # noqa: E402
                       run_fixtures, RULE_SPRAY, RULE_BRUTE, RULE_LATERAL,
                       RULE_PRIV, RULE_AFTERHRS, RULE_BRUTE_SOURCELESS,
                       ORACLE_RULES)
import attack_fixtures  # noqa: E402
from engine import _time_outside_hours  # noqa: E402  -- reuse the engine's own predicate


class TestRealHostMatchesEngine(unittest.TestCase):
    """R4-#138 (2026-08-27): the oracle's hostname for
    common_bruteforce_sourceless must treat Windows's literal '-' as absent
    and fall through to Computer, exactly like the real engine's _hostname --
    otherwise '-' events pool in one bucket and diverge from the engine."""

    def _engine_host(self, r):
        # Mirror of active_directory._hostname semantics WITHOUT importing the
        # module (it uses relative imports, unit-test-importable only in-repo):
        # safe_str then '-' -> absent, and the parser falls back WS -> Computer.
        def _hn(v):
            s = str(v).strip() if isinstance(v, str) else ""
            return None if not s or s == "-" else s
        return (_hn(r.get("WorkstationName")) or _hn(r.get("Computer"))) or ""

    def test_dash_workstation_falls_back_to_computer(self):
        r = {"WorkstationName": "-", "Computer": "DC01.bankcorp.local"}
        self.assertEqual(_real_host(r), "DC01.bankcorp.local")
        self.assertEqual(_real_host(r), self._engine_host(r))

    def test_dash_computer_is_absent(self):
        r = {"WorkstationName": "-", "Computer": "-"}
        self.assertEqual(_real_host(r), "")

    def test_real_workstation_kept(self):
        r = {"WorkstationName": "wks-jdoe", "Computer": "DC01"}
        self.assertEqual(_real_host(r), "wks-jdoe")

    def test_missing_fields_is_absent(self):
        self.assertEqual(_real_host({}), "")

    def test_whitespace_wrapped_dash_is_absent(self):
        r = {"WorkstationName": " - "}
        self.assertEqual(_real_host(r), "")

    def test_agrees_with_engine_across_cases(self):
        cases = [
            {"WorkstationName": "-", "Computer": "-"},
            {"WorkstationName": "wks-a", "Computer": "DC1"},
            {"WorkstationName": None, "Computer": "DC2"},
            {"WorkstationName": "-", "Computer": "DC3"},
        ]
        for r in cases:
            self.assertEqual(_real_host(r), self._engine_host(r), f"{r!r}")

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


class TestVerdictExitCode(unittest.TestCase):
    """Gap-hunt finding (2026-08-23): main() built a full confusion matrix
    (oracle vs the real engine) but unconditionally `return 0`'d regardless
    of `mismatches` -- even a real regression the oracle caught reported
    success on `$?`. `_verdict()` is the extracted, directly-testable exit-
    code decision (see evtx_eval.py's comment for the full account)."""

    def test_no_mismatches_is_success(self):
        self.assertEqual(_verdict([]), 0)

    def test_any_mismatch_is_failure(self):
        self.assertEqual(_verdict([{"file": "x.xml", "expected": "fired", "got": "silent"}]), 1)

    def test_multiple_mismatches_still_failure(self):
        self.assertEqual(_verdict([{"a": 1}, {"b": 2}, {"c": 3}]), 1)


class TestAttackFixtures(unittest.TestCase):
    """Phase 5 item 8 (2026-10-14): password_spray had zero attack-shaped
    test events in either corpus (untested on every corpus trend row).
    attack_fixtures.py adds a committed synthetic
    credential-stuffing shape; these tests pin that it trips ONLY the oracle
    rule it is meant to, that the REAL engine agrees (no mismatch), and that
    the fixtures stay deterministic."""

    def _records(self):
        return sorted(attack_fixtures.ALL["password_spray"],
                      key=lambda r: r["TimeCreated"])

    def test_oracle_labels_only_password_spray(self):
        exp = oracle(self._records())
        expected = {RULE_BRUTE: False, RULE_SPRAY: True, RULE_LATERAL: False,
                    RULE_PRIV: False, RULE_AFTERHRS: False,
                    RULE_BRUTE_SOURCELESS: False}
        self.assertEqual(exp, expected)

    def test_shape_is_attack_shaped(self):
        recs = attack_fixtures.ALL["password_spray"]
        self.assertEqual({r["EventID"] for r in recs}, {4625})
        self.assertEqual({r["TargetUserName"] for r in recs}, {"carla"})
        self.assertEqual(len({r["IpAddress"] for r in recs}), len(recs))
        times = sorted(r["TimeCreated"] for r in recs)
        self.assertLessEqual(times[-1] - times[0], 300_000)

    def test_deterministic_across_calls(self):
        self.assertEqual(attack_fixtures.ALL["password_spray"],
                         attack_fixtures.ALL["password_spray"])

    def test_run_fixtures_folds_tp_without_mismatch(self):
        confusion = {rid: {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
                     for rid in ORACLE_RULES}
        per_file, mismatches, drops = [], [], []
        run_fixtures(confusion, per_file, mismatches, drops)
        self.assertEqual(confusion[RULE_SPRAY]["tp"], 1)
        self.assertEqual(confusion[RULE_SPRAY]["fn"], 0)
        self.assertEqual(mismatches, [])
        self.assertEqual(drops, [])
        row = per_file[0]
        self.assertEqual(row["file"], "fixture:password_spray")
        self.assertIn("password_spray", row["expected"])
        self.assertIn("password_spray", row["fired"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
