"""Self-test for tools/detection_quality_eval.py.

Proves the metric math (precision/recall/F1, macro-F1) is computed correctly on
a tiny in-file corpus with known counts, and that the floor gate turns red when
the macro-F1 drops below the floor. Also runs the full built-in corpus end-to-end
through the real engine and asserts the metrics are non-trivial (i.e. NOT all
perfect 1.0 — otherwise the harness would be measuring nothing).

Run:  python tools/test_detection_quality.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from detection_quality_eval import (  # noqa: E402
    CORPUS,
    FLOOR,
    main,
    macro_f1,
    rule_metrics,
)


def _mk_results(entries: list[tuple[str, set, set]]) -> list[dict]:
    """[[name, expected, fired] -> the dict-shaped results the metrics read."""
    return [{"name": n, "expected": e, "fired": f} for n, e, f in entries]


class TestThresholdContract(unittest.TestCase):
    """The floor is deliberately LOW (0.5) so it catches only catastrophic
    regressions -- the shipped corpus must clear it comfortably."""

    def test_floor_is_deliberately_low_and_honest(self):
        self.assertEqual(FLOOR, 0.5)
        self.assertLess(FLOOR, 0.9)  # must not be a quality bar


class TestRuleMetrics(unittest.TestCase):
    def test_known_counts(self):
        # Rule "r" over a synthetic corpus: tp=2, fp=1, fn=1, tn=5.
        results = _mk_results([
            ("e1", {"r"}, {"r"}),  # TP
            ("e2", {"r"}, {"r"}),  # TP
            ("e3", set(), {"r"}),  # FP
            ("e4", {"r"}, set()),  # FN
            ("e5", set(), set()),  # TN
            ("e6", set(), set()),  # TN
            ("e7", set(), set()),  # TN
            ("e8", set(), set()),  # TN
            ("e9", set(), set()),  # TN
        ])
        m = rule_metrics(results, "r")
        self.assertEqual((m["tp"], m["fp"], m["fn"], m["tn"]), (2, 1, 1, 5))
        self.assertAlmostEqual(m["precision"], 2 / 3)
        self.assertAlmostEqual(m["recall"], 2 / 3)
        self.assertAlmostEqual(m["f1"], 2 / 3)

    def test_perfect_rule_is_1_0(self):
        results = _mk_results([
            ("e1", {"r"}, {"r"}),
            ("e2", set(), set()),
        ])
        m = rule_metrics(results, "r")
        self.assertEqual((m["precision"], m["recall"], m["f1"]), (1.0, 1.0, 1.0))

    def test_all_false_negative_rule_scores_zero(self):
        # Engine fires on nothing but the label says it should: recall collapses.
        results = _mk_results([
            ("e1", {"r"}, set()),
            ("e2", {"r"}, set()),
            ("e3", set(), set()),
        ])
        m = rule_metrics(results, "r")
        self.assertEqual((m["precision"], m["recall"], m["f1"]), (0.0, 0.0, 0.0))


class TestMacroF1(unittest.TestCase):
    def test_macro_is_unweighted_mean(self):
        per = {"a": {"f1": 1.0}, "b": {"f1": 0.5}}
        self.assertAlmostEqual(macro_f1(per), 0.75)

    def test_empty_is_zero(self):
        self.assertEqual(macro_f1({}), 0.0)

    def test_catastrophic_regression_below_floor(self):
        # Engine totally dead: every scored rule scores 0 -> gate must fail.
        per = {"a": {"f1": 0.0}, "b": {"f1": 0.0}, "c": {"f1": 0.0}}
        self.assertLess(macro_f1(per), FLOOR)
        self.assertFalse(macro_f1(per) >= FLOOR)


class TestEndToEnd(unittest.TestCase):
    def test_reference_ids_are_known(self):
        # Guards the corpus against drift: the rule ids it labels must exist.
        # (main() also returns 2 on a missing id; this asserts it up front.)
        import detection_quality_eval as dqe
        rules = dqe.load_engine_rules()
        for e in CORPUS:
            for rid in e["expected_rules"]:
                self.assertIn(rid, rules, f"corpus labels unknown rule {rid}")

    def test_main_returns_zero(self):
        self.assertEqual(main(), 0)

    def test_metrics_are_non_trivial(self):
        # The whole point of the harness: precision/recall must NOT be trivially
        # 1.0. At least one scored rule must score F1 < 1.0, proving the corpus
        # actually measures disagreement with the engine rather than tautology.
        import detection_quality_eval as dqe
        rules = dqe.load_engine_rules()
        results = dqe.entry_results(CORPUS, rules)
        scored = dqe.references(CORPUS)
        per = {rid: rule_metrics(results, rid) for rid in scored}
        self.assertTrue(any(m["f1"] < 1.0 for m in per.values()),
                        "corpus produced all-perfect metrics -- it measures nothing")


if __name__ == "__main__":
    unittest.main()
