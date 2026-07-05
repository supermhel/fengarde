"""Tests for tools/validate_rules.py (B4 rule validation gate).

Proves the validator ACCEPTS the shipped rules and REJECTS each class of
malformed rule it exists to catch -- a validator that never says no is
worthless, so every check gets an adversarial negative case.

Run: python tools/test_validate_rules.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from validate_rules import validate_rule, RULES_DIR, main  # noqa: E402

import yaml  # noqa: E402


def _base_rule() -> dict:
    """A minimal VALID rule; each test corrupts one thing."""
    return {
        "title": "Test rule",
        "id": "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01",
        "level": "high",
        "detection": {
            "sel": {"class_uid": 3002, "activity_id": 4},
            "condition": "sel",
        },
        "siem": {"sector": "common", "score_weight": 70,
                 "window_seconds": 60, "threshold": 10},
    }


class TestValidateRule(unittest.TestCase):
    def _errs(self, mutate):
        rule = _base_rule()
        mutate(rule)
        return validate_rule(rule)

    def test_base_rule_is_valid(self):
        self.assertEqual(validate_rule(_base_rule()), [])

    def test_missing_title(self):
        self.assertTrue(any("title" in e for e in self._errs(
            lambda r: r.pop("title"))))

    def test_bad_uuid(self):
        self.assertTrue(any("UUID" in e for e in self._errs(
            lambda r: r.update(id="not-a-uuid"))))

    def test_bad_level(self):
        self.assertTrue(any("level" in e for e in self._errs(
            lambda r: r.update(level="catastrophic"))))

    def test_no_selections(self):
        self.assertTrue(any("no selections" in e for e in self._errs(
            lambda r: r.update(detection={"condition": ""}))))

    def test_condition_references_undefined_selection(self):
        # INTENTIONAL reject (not a false-reject): the engine defaults an unknown
        # selection name to False, so `sel and ghost` can never fire and
        # `sel or ghost` has a dead term -- both are typos that silently break the
        # rule. Catching that is the gate's core anti-dormancy purpose.
        errs = self._errs(lambda r: r["detection"].update(condition="sel and ghost"))
        self.assertTrue(any("undefined selection 'ghost'" in e for e in errs))

    def test_list_value_is_accepted_as_equality_match(self):
        # The engine treats a non-dict value as equality (`actual != expected`),
        # so a list value legitimately matches an array-valued OCSF field. Must
        # NOT be rejected (was a false-reject caught in review).
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"observables.value": ["a", "b"]}))
        self.assertEqual(errs, [])

    def test_empty_selection_rejected_because_it_matches_everything(self):
        errs = self._errs(lambda r: r["detection"].__setitem__("sel", {}))
        self.assertTrue(any("matches EVERY event" in e for e in errs))

    def test_condition_unbalanced_parens(self):
        errs = self._errs(lambda r: r["detection"].update(condition="(sel"))
        self.assertTrue(any("condition" in e for e in errs))

    def test_unknown_operator_rejected(self):
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"score": {"regex": ".*"}}))
        self.assertTrue(any("unknown operator 'regex'" in e for e in errs))

    def test_numeric_operator_needs_number(self):
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"score": {"gt": "sixty"}}))
        self.assertTrue(any("needs a number" in e for e in errs))

    def test_not_in_missing_allowlist(self):
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"src_endpoint.ip": {"not_in": "does_not_exist"}}))
        self.assertTrue(any("does_not_exist" in e and "missing" in e for e in errs))

    def test_not_in_existing_allowlist_ok(self):
        # corp_ranges.yml ships in contracts/allowlists/
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"src_endpoint.ip": {"not_in": "corp_ranges"}}))
        self.assertEqual(errs, [])

    def test_outside_hours_bad_time_format(self):
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"time": {"outside_hours": {"start": "8am", "end": "18:00"}}}))
        self.assertTrue(any("HH:MM" in e for e in errs))

    def test_outside_hours_empty_window(self):
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"time": {"outside_hours": {"start": "08:00", "end": "08:00"}}}))
        self.assertTrue(any("start == end" in e for e in errs))

    def test_outside_hours_unknown_key(self):
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"time": {"outside_hours": {"start": "08:00", "end": "18:00",
                                               "timezone": "UTC"}}}))
        self.assertTrue(any("unknown key" in e for e in errs))

    def test_outside_hours_valid(self):
        errs = self._errs(lambda r: r["detection"].__setitem__(
            "sel", {"time": {"outside_hours": {"start": "08:00", "end": "18:00",
                                               "days": ["mon", "tue"],
                                               "tz_offset_minutes": 60}}}))
        self.assertEqual(errs, [])

    def test_score_weight_out_of_range(self):
        self.assertTrue(any("score_weight" in e for e in self._errs(
            lambda r: r["siem"].update(score_weight=150))))

    def test_stateful_requires_both_window_and_threshold(self):
        errs = self._errs(lambda r: r["siem"].pop("threshold"))
        self.assertTrue(any("together" in e for e in errs))

    def test_negative_window(self):
        self.assertTrue(any("window_seconds" in e for e in self._errs(
            lambda r: r["siem"].update(window_seconds=-5))))


class TestShippedRules(unittest.TestCase):
    def test_all_shipped_rules_pass(self):
        for path in sorted(RULES_DIR.glob("*.yml")):
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual(validate_rule(rule), [],
                             f"shipped rule {path.name} failed validation")

    def test_main_returns_zero_on_shipped_rules(self):
        self.assertEqual(main(["validate_rules.py"]), 0)


if __name__ == "__main__":
    unittest.main()
