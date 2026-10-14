"""Self-test for tools/append_trend_row.py (review of PR #96, 2026-10-14).

Pins the fix for the fixture double-count: both corpus lanes replay the same
committed synthetic fixtures, so the trend row must take them ONCE and keep
them OUT of the corpus per_rule / untested_rules grading.

Run:  python tools/test_append_trend_row.py
"""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import append_trend_row as A  # noqa: E402

SPRAY = A.NAME2ID["password_spray"]
PRIV = A.NAME2ID["priv_grant"]


def _conf(**tp: int) -> dict:
    out = {name: {"tp": 0, "fp": 0, "fn": 0, "tn": 1} for name in A.ORACLE.values()}
    for name, n in tp.items():
        out[name] = {"tp": n, "fp": 0, "fn": 0, "tn": 0}
    return out


FIXTURE = _conf(password_spray=1)
EVTX = {"corpus": {"files": 278, "records_supported": 2082, "records_security": 1577,
                   "records_sysmon": 3241},
        "confusion": _conf(priv_grant=1), "fixture_confusion": FIXTURE}
SPLUNK = {"files": 1055, "supported_records": 12581, "confusion": _conf(),
          "fixture_confusion": FIXTURE}
NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)


class TestBuildRow(unittest.TestCase):
    def test_fixture_counted_once_and_kept_out_of_corpus(self):
        row = A.build_row(EVTX, SPLUNK, 0.875, 10, 4, NOW)
        self.assertEqual(row["per_rule"][SPRAY]["tp"], 0)
        self.assertEqual(row["fixture_per_rule"][SPRAY]["tp"], 1)
        self.assertIn("password_spray", row["untested_rules"])
        self.assertEqual(row["fixture_tested_rules"], ["password_spray"])
        self.assertNotIn("priv_grant", row["untested_rules"])
        # corpus TN counts: one per lane, no fixture TN folded in
        self.assertEqual(row["per_rule"][SPRAY]["tn"], 2)

    def test_counts_and_coverage(self):
        row = A.build_row(EVTX, SPLUNK, 0.875, 10, 4, NOW)
        self.assertEqual(row["corpus_size"], 2082 + 12581)
        self.assertEqual(row["parser_coverage_pct"], 43.2)
        self.assertEqual(row["corpora"], ["evtx", "quality", "splunk"])
        self.assertEqual(row["date"], "2026-10-14")
        self.assertEqual(row["quality_scored_rules"], 4)
        self.assertEqual(row["lane_files"], {"evtx": 278, "splunk": 1055})

    def test_single_lane_still_carries_fixtures(self):
        row = A.build_row(None, SPLUNK, 0.875, 10, 4, NOW)
        self.assertEqual(row["fixture_per_rule"][SPRAY]["tp"], 1)
        self.assertIsNone(row["parser_coverage_pct"])

    def test_quality_only(self):
        row = A.build_row(None, None, 0.875, 10, 4, NOW)
        self.assertEqual(row["corpora"], ["quality"])
        self.assertEqual(row["corpus_size"], 0)
        self.assertEqual(sorted(row["untested_rules"]), sorted(A.ORACLE.values()))
        self.assertEqual(row["fixture_tested_rules"], [])

    def test_oracle_map_matches_the_lane(self):
        sys.path.insert(0, str(ROOT / "eval" / "detection_accuracy"))
        import evtx_eval
        self.assertEqual(A.ORACLE, evtx_eval.RULE_NAMES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
