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
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "trend.jsonl"
            p.write_text("# comment\n{\"broken\":\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                G.load_trend_rows(p)

    def test_quality_only_row_never_wins_corpus(self):
        # NIGHTLY_EVAL_MODE=quality-only appends per_rule zeros + macro_f1 but
        # no corpus; publishing it would show corpus_records=0.
        quality_only = {"_schema": "1", "date": "2026-10-20", "corpora": ["quality"],
                        "corpus_size": 0, "per_rule": {}, "macro_f1": 0.875}
        self.assertIs(G.latest_corpus_row([CORPUS_NEW, quality_only]), CORPUS_NEW)
        with self.assertRaises(SystemExit):
            G.latest_corpus_row([quality_only])

    def test_same_day_tie_picks_last_appended(self):
        rerun = dict(CORPUS_NEW, macro_f1=0.9)
        self.assertIs(G.latest_corpus_row([CORPUS_NEW, rerun]), rerun)
        # ...but a smaller same-day (partial) run never displaces the full one
        partial = dict(CORPUS_NEW, corpus_size=2082, corpora=["evtx", "quality"])
        self.assertIs(G.latest_corpus_row([CORPUS_NEW, partial]), CORPUS_NEW)
        twin2 = dict(REAL_TWIN)
        self.assertIs(G.latest_twin_row([REAL_TWIN, twin2]), twin2)

    def test_caveats_are_derived_from_the_row(self):
        row = dict(CORPUS_NEW, untested_rules=["bruteforce", "password_spray"],
                   fixture_tested_rules=["password_spray"],
                   fixture_per_rule={_SPRAY_ID: {"tp": 1, "fp": 0, "fn": 0, "tn": 0}},
                   quality_corpus_events=10, quality_scored_rules=4)
        doc = G.build_document(row, REAL_TWIN)
        text = " ".join(doc["caveats"])
        self.assertIn("bruteforce, password_spray had zero", text)
        self.assertIn("password_spray: graded on committed synthetic fixtures", text)
        self.assertIn("(10 events, 4 scored rules)", text)
        self.assertIn("seed 7", text)
        dq = doc["detection_quality"]
        self.assertEqual(dq["fixture_per_rule_confusion"][_SPRAY_ID]["tp"], 1)
        self.assertEqual(dq["fixture_tested_rules"], ["password_spray"])
        # nothing untested -> no stale "had zero expected-positive" caveat
        clean = " ".join(G.build_document(CORPUS_NEW, REAL_TWIN)["caveats"])
        self.assertNotIn("had zero expected-positive", clean)
        self.assertNotIn("synthetic fixtures", clean)

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
        for key in ["macro_f1", "per_rule_confusion", "fixture_per_rule_confusion",
                    "fixture_tested_rules", "corpus_files", "parser_coverage_pct",
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


class TestCheckMode(unittest.TestCase):
    """--check must be able to go RED (a gate that can't fail protects
    nothing): missing results.json, schema/selection drift, and a corrupt
    file must all surface as stale."""

    def test_check_detects_stale_and_accepts_fresh(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            old_trend, old_out = G.TREND, G.OUT
            try:
                G.TREND = Path(td) / "trend.jsonl"
                G.OUT = Path(td) / "results.json"
                G.TREND.write_text(
                    json.dumps(CORPUS_NEW) + "\n" + json.dumps(REAL_TWIN) + "\n",
                    encoding="utf-8")
                rows = G.load_trend_rows(G.TREND)
                # missing file -> stale
                self.assertTrue(G.is_stale(rows)[0])
                # fresh write -> fresh
                G.OUT.write_text(G.render_document(rows), encoding="utf-8")
                self.assertFalse(G.is_stale(rows)[0])
                # drift in any real field -> stale (corrupt file)
                G.OUT.write_text("{\"schema_version\": \"0\"}\n", encoding="utf-8")
                self.assertTrue(G.is_stale(rows)[0])
                # drift in the SELECTED ROW -> stale (slightly older corpus row)
                G.OUT.write_text(G.render_document(rows), encoding="utf-8")
                rows2 = [CORPUS_OLD, REAL_TWIN]
                self.assertTrue(G.is_stale(rows2)[0])
            finally:
                G.TREND, G.OUT = old_trend, old_out


if __name__ == "__main__":
    unittest.main(verbosity=2)