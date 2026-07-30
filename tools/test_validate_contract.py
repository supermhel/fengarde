"""Unit tests for tools/validate_contract.py's check_invariant().

Regression for H6 (2026-07-30 audit): a type-mismatched class_uid/activity_id/
type_uid (e.g. a fixture typo `"class_uid": "3002"`) used to raise an
unhandled TypeError out of check_invariant(), crashing main()'s `for f in
files:` loop and silently skipping validation of every alphabetically-later
fixture in that run.

Run with:
    python tools/validate_contract.py  (wired into run_all_tests.sh separately)
    python tools/test_validate_contract.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from validate_contract import check_invariant  # noqa: E402


class TestCheckInvariant(unittest.TestCase):

    def test_type_mismatched_class_uid_does_not_raise(self):
        errors: list = []
        try:
            check_invariant(
                {"class_uid": "3002", "activity_id": 2, "type_uid": 300202}, errors)
        except TypeError as e:
            self.fail(f"check_invariant raised TypeError on a type-mismatched "
                      f"field instead of skipping the arithmetic: {e}")

    def test_type_mismatched_activity_id_does_not_raise(self):
        errors: list = []
        check_invariant({"class_uid": 3002, "activity_id": "2", "type_uid": 300202}, errors)
        # a wrong-typed field is already reported by the schema pass; the
        # invariant check itself must stay silent (not fabricate an error)
        self.assertEqual(errors, [])

    def test_type_mismatched_type_uid_does_not_raise(self):
        errors: list = []
        check_invariant({"class_uid": 3002, "activity_id": 2, "type_uid": "300202"}, errors)
        self.assertEqual(errors, [])

    def test_bool_is_not_treated_as_int(self):
        """bool is a subclass of int in Python -- must not slip through the
        isinstance(int) guard and get arithmetic applied to it."""
        errors: list = []
        check_invariant({"class_uid": True, "activity_id": 2, "type_uid": 102}, errors)
        self.assertEqual(errors, [])

    def test_correctly_typed_valid_invariant_holds_silently(self):
        errors: list = []
        check_invariant({"class_uid": 3002, "activity_id": 2, "type_uid": 300202}, errors)
        self.assertEqual(errors, [])

    def test_correctly_typed_violated_invariant_still_reported(self):
        """The fix must not accidentally suppress the real, correctly-typed
        invariant violation this check exists to catch."""
        errors: list = []
        check_invariant({"class_uid": 3002, "activity_id": 2, "type_uid": 999999}, errors)
        self.assertEqual(len(errors), 1)
        self.assertIn("invariant violated", errors[0])

    def test_missing_field_still_returns_silently(self):
        errors: list = []
        check_invariant({"class_uid": 3002}, errors)
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
