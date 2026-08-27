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

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from validate_contract import check_invariant  # noqa: E402
import validate_contract as vc  # noqa: E402  -- for FIXTURES_DIR monkeypatching in the floor test


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

    def test_bad_category_uid_is_reported(self):
        """R3-37: class_uid and category_uid must agree on the OCSF class
        hierarchy. class_uid encodes category*1000, so 3002 MUST carry
        category_uid 3 -- a 5 (IAM) silently mislabels the class and passed
        the old gate (which only checked type_uid). type_uid is still valid
        here, isolating the category_uid violation as its own error."""
        errors: list = []
        check_invariant(
            {"class_uid": 3002, "activity_id": 2, "type_uid": 300202,
             "category_uid": 5}, errors)
        self.assertEqual(len(errors), 1)
        self.assertIn("category_uid", errors[0])
        self.assertIn("invariant violated", errors[0])

    def test_valid_category_uid_holds_silently(self):
        errors: list = []
        check_invariant(
            {"class_uid": 3002, "activity_id": 2, "type_uid": 300202,
             "category_uid": 3}, errors)
        self.assertEqual(errors, [])

    def test_wrong_typed_category_uid_does_not_crash(self):
        """A wrong-typed category_uid (already reported by the schema pass)
        must not fabricate an arithmetic error in check_invariant."""
        errors: list = []
        check_invariant(
            {"class_uid": 3002, "activity_id": 2, "type_uid": 300202,
             "category_uid": "3-agent"}, errors)
        self.assertEqual(errors, [])

    def test_bool_category_uid_is_not_treated_as_int(self):
        errors: list = []
        check_invariant(
            {"class_uid": 3002, "activity_id": 2, "type_uid": 300202,
             "category_uid": True}, errors)
        self.assertEqual(errors, [])


class TestMainFloor(unittest.TestCase):
    """Zero-fixture behavior of main().

    Regression for the gap-hunt finding: with an empty fixtures dir the loop
    never ran, overall_ok stayed True, and the gate printed RESULT: PASS with
    exit 0 -- a contract gate that validated NOTHING kept the tree green.
    Mutation-sound: delete the floor in main() and this test goes red (rc
    becomes 0).

    main() reads sys.argv for explicit fixture paths; unittest's own argv
    (flags like -v) must not be mistaken for fixture paths, so argv is pinned
    to a bare script name for the duration of the call.
    """

    def _run_main(self, fixtures_dir):
        real_dir, real_argv = vc.FIXTURES_DIR, sys.argv
        buf = io.StringIO()
        try:
            vc.FIXTURES_DIR = fixtures_dir
            sys.argv = ["validate_contract.py"]
            with contextlib.redirect_stdout(buf):
                rc = vc.main()
        finally:
            vc.FIXTURES_DIR = real_dir
            sys.argv = real_argv
        return rc, buf.getvalue()

    def test_empty_fixtures_dir_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = self._run_main(Path(tmp))
        self.assertNotEqual(rc, 0, f"ZERO fixtures must fail the gate, got rc={rc}")
        self.assertIn("ZERO fixtures", out)

    def test_missing_fixtures_dir_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ghost = Path(tmp) / "does-not-exist"
            rc, out = self._run_main(ghost)
        self.assertNotEqual(rc, 0)
        self.assertIn("ZERO fixtures", out)

    def test_malformed_fixture_is_a_failure_not_a_crash(self):
        # A JSONDecodeError used to raise a traceback out of main() -- exit
        # code 1, but no verdict and no attribution. The gate must degrade to
        # a named [FAIL] instead (same silence-class as the zero fixture).
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "scrambled.json").write_text("{not json", encoding="utf-8")
            rc, out = self._run_main(Path(tmp))
        self.assertNotEqual(rc, 0)
        self.assertIn("scrambled.json", out)
        self.assertIn("could not load", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
