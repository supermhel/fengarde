"""Self-test for tools/generate_benchmark.py (Phase 5 item 8, 2026-10-14).

Pins the selection rules that keep the public benchmark honest:

* latest-corpus-row and latest-twin-row selection (max date per run-type);
* the KNOWN-FABRICATED pilot twin row (fpr=0.25, dated before every real
  twin run) is never selected, and a loud refusal if it ever wins;
* the emitted document has the exact public schema fields with documented
  units and sorted deterministic keys (modulo generated_at).

Run:  python tools/test_generate_benchmark.py
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import generate_benchmark as G  # noqa: E402

# The KNOWN-FABRICATED pilot row from the real file: fpr=0.25, dated
# 2026-08-28T12:07:10 -- BEFORE every real twin run -- so max-date selection
# never picks it. (First real twin: 2026-08-28T14:46:46+00:00.)
FAB_HISTORICAL = {
    "_schema": "1", "run_type": "twin",
    "date": "2026-08-28T12:07:10+00:00",
    "twin_metrics": {"fpr": 0.25, "chain_fidelity": 0.0, "basis": "harness-measured"},
}
# A fabricated-SHAPED row that WOULD win max date (dated after every real twin)
# -- must be refused loudly, never published.
FAB_LATEST = {
    "_schema": "1", "run_type": "twin",
    "date": "2026-09-05T00:00:00+00:00",
    "twin_metrics": {"fpr": 0.25, "chain_fidelity": 0.0, "basis": "harness-measured"},
}
REAL_TWIN = {
    "_schema": "1", "run_type": "twin",
    "date": "2026-09-04T07:51:40+00:00",
    "seed": 7,
    "twin_metrics": {"tpr": 1.0, "fpr": 0.0, "mttd_seconds": 60.0,
                     "chain_fidelity": 0.6, "evidence_completeness": 0.9375},
    "context": {"chain_steps": ["a", "b"], "parsed_count": 6, "gap_count": 1,
                "negative_controls": {"x": 0}},
}
# Trend-row per_rule keys are the STABLE ORACLE rule IDs (generate_benchmark's
# RULE_NAMES documents the id->name map; the schema publishes both).
_SPRAY_ID = "4f8a2c61-9e3d-4b57-8a1c-6d2e5f7a8b90"   # password_spray
_OTHER_ID = "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01"    # bruteforce

CORPUS_OLD = {
    "_schema": "1", "date": "2026-08-28", "corpora": ["evtx", "quality", "splunk"],
    "corpus_size": 2056, "per_rule": {_OTHER_ID: {"tp": 0, "fp": 0, "fn": 0, "tn": 188}},
    "macro_f1": 0.75, "parser_coverage_pct": 42.3,
    "untested_rules": ["password_spray", "bruteforce"],
}
CORPUS_NEW = {
    "_schema": "1", "date": "2026-09-04", "corpora": ["evtx", "quality", "splunk"],
    "corpus_size": 4804,
    "per_rule": {_OTHER_ID: {"tp": 4, "fp": 0, "fn": 0, "tn": 252},
                 _SPRAY_ID: {"tp": 1, "fp": 0, "fn": 0, "tn": 290}},
    "macro_f1": 0.875, "parser_coverage_pct": 42.3, "untested_rules": [],
}


class TestSelection(unittest.TestCase):
    def test_latest_corpus_row_wins(self):
        self.assertIs(G.latest_corpus_row([CORPUS_OLD, CORPUS_NEW]), CORPUS_NEW)

    def test_latest_twin_skips_fabricated(self):
        rows = [FAB_HISTORICAL, REAL_TWIN]
        self.assertIs(G.latest_twin_row(rows), REAL_TWIN)
        self.assertNotEqual(G.latest_twin_row(rows)["twin_metrics"]["fpr"], 0.25)

    def test_fabricated_latest_is_refused_loudly(self):
        with self.assertRaises(SystemExit):
            G.latest_twin_row([REAL_TWIN, FAB_LATEST])

    def test_no_corpus_row_is_loud(self):
        with self.assertRaises(SystemExit):
            G.latest_corpus_row([REAL_TWIN])

    def test_corrupt_trend_row_is_loud(self):
        p = ROOT / ".benchmark-test-trend.jsonl"
        p.write_text("# comment\n{\"broken\":\n", encoding="utf-8")
        try:
            with self.assertRaises(SystemExit):
                G.load_trend_rows(p)
        finally:
            p.unlink(missing_ok=True)

    def test_document_schema(self):
        doc = G.build_document(CORPUS_NEW, REAL_TWIN)
        self.assertEqual(doc["schema_version"], "1.0")
        self.assertEqual(doc["source"]["corpus_row_date"], "2026-09-04")
        self.assertEqual(doc["detection_quality"]["macro_f1"], 0.875)
        self.assertEqual(doc["detection_quality"]["untested_rules"], [])
        self.assertEqual(doc["detection_quality"]["per_rule_confusion"]
                         ["4f8a2c61-9e3d-4b57-8a1c-6d2e5f7a8b90"]["tp"], 1)
        self.assertEqual(
            doc["detection_quality"]["rule_id_to_name"]["4f8a2c61-9e3d-4b57-8a1c-6d2e5f7a8b90"],
            "password_spray")
        self.assertEqual(doc["twin"]["chain_fidelity"], 0.6)
        self.assertEqual(doc["twin"]["tpr"], 1.0)
        self.assertIn("macro_f1", doc["units"])
        self.assertIn("parser_coverage_pct", doc["units"])
        self.assertIn("chain_fidelity", doc["units"])
        self.assertTrue(doc["caveats"])
        # every unit-documented metric key has a units entry
        for key in ["macro_f1", "per_rule_confusion", "parser_coverage_pct",
                    "untested_rules", "tpr", "fpr", "mttd_seconds",
                    "mtti_seconds", "mttr_seconds", "chain_fidelity",
                    "evidence_completeness", "false_correlation_rate",
                    "alert_reduction_ratio", "incident_reconstruction_time_ms",
                    "severity_calibration_error", "attribution_accuracy"]:
            self.assertIn(key, doc["units"], f"missing units doc for {key}")

    def test_output_is_deterministic_modulo_generated_at(self):
        d1 = G.build_document(CORPUS_NEW, REAL_TWIN)
        d2 = G.build_document(CORPUS_NEW, REAL_TWIN)
        json1 = json.dumps(d1, indent=2, sort_keys=True)
        json2 = json.dumps(d2, indent=2, sort_keys=True)
        self.assertEqual(json1, json2)


if __name__ == "__main__":
    unittest.main(verbosity=2)