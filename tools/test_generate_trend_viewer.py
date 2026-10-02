"""Phase 5 (2026-09-04) item 6: tools/generate_trend_viewer.py.

Zero infra: writes a synthetic trend.jsonl (including a `#`-comment line,
matching the real file's own annotation convention) to a temp dir, generates
the viewer against it, and asserts on the real HTML output -- not just that
the script exits 0.

Run: python tools/test_generate_trend_viewer.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from generate_trend_viewer import generate, load_rows  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


_ROW_OLD = json.dumps({"_schema": "1", "date": "2026-08-01", "macro_f1": 0.5,
                       "parser_coverage_pct": 10.0, "corpus_size": 5,
                       "corpora": ["quality"], "untested_rules": ["x"]})
_ROW_NEW = json.dumps({"_schema": "1", "date": "2026-09-01", "macro_f1": 0.9,
                       "parser_coverage_pct": 42.3, "corpus_size": 100,
                       "corpora": ["quality", "evtx"], "untested_rules": []})
_ROW_TWIN = json.dumps({"_schema": "1", "run_type": "twin",
                        "date": "2026-08-01T00:00:00+00:00", "seed": 7,
                        "basis": "harness-measured",
                        "twin_metrics": {"tpr": 1.0, "fpr": 0.0, "chain_fidelity": None}})
# A twin row written AFTER the causal-order co-metrics landed (2026-10-02): a bool, a float and a
# null in the new columns. _ROW_TWIN above predates them and must still render (as n/a).
_ROW_TWIN_CO = json.dumps({"_schema": "1", "run_type": "twin",
                           "date": "2026-10-02T00:00:00+00:00", "seed": 7,
                           "basis": "harness-measured",
                           "twin_metrics": {"tpr": 1.0, "chain_fidelity": 0.6,
                                            "causal_order_fidelity": 0.8333,
                                            "order_concordance": 1.0, "alert_order_ok": True}})
_ROW_TWIN_REV = json.dumps({"_schema": "1", "run_type": "twin",
                            "date": "2026-10-03T00:00:00+00:00", "seed": 7,
                            "basis": "harness-measured",
                            "twin_metrics": {"tpr": 1.0, "chain_fidelity": 0.6,
                                             "causal_order_fidelity": None,
                                             "order_concordance": 0.0, "alert_order_ok": False}})
_SAMPLE_JSONL = (
    "# a comment line, matching the real file's own convention -- must be skipped\n"
    f"{_ROW_OLD}\n{_ROW_NEW}\n{_ROW_TWIN}\n\nnot valid json at all\n"
)


def test_load_rows_skips_comments_and_blank_and_warns_on_malformed():
    with tempfile.TemporaryDirectory() as tmp:
        trend = Path(tmp) / "trend.jsonl"
        trend.write_text(_SAMPLE_JSONL, encoding="utf-8")
        rows = load_rows(trend)
        check(len(rows) == 3, f"must load exactly 3 real rows (comment + malformed line skipped), got {len(rows)}")
        check(all(not str(r).startswith("#") for r in rows), "no comment text must leak into a row")


def test_load_rows_missing_file_is_empty_not_an_error():
    rows = load_rows(Path("/definitely/does/not/exist/trend.jsonl"))
    check(rows == [], f"a missing trend file must return [], got {rows}")


def test_generate_writes_real_html_with_both_tables_newest_first():
    with tempfile.TemporaryDirectory() as tmp:
        trend = Path(tmp) / "trend.jsonl"
        trend.write_text(_SAMPLE_JSONL, encoding="utf-8")
        out = Path(tmp) / "viewer.html"
        count = generate(trend, out)
        check(count == 3, f"generate() must report 3 rows loaded, got {count}")
        text = out.read_text(encoding="utf-8")
        check("<title>FENGARDE eval trend</title>" in text, "must set a real title")
        check("0.875" not in text, "must not leak unrelated fixture data (sanity)")
        check("0.9" in text and "0.5" in text, "both corpora rows' macro_f1 must render")
        # newest-first: 2026-09-01 must appear before 2026-08-01 in the corpora table
        pos_new = text.index("2026-09-01")
        pos_old = text.index("2026-08-01")
        check(pos_new < pos_old, "corpora rows must render newest-first")
        check("42.3%" in text, "parser_coverage_pct must render with a % suffix")
        check("<span class=\"na\">n/a</span>" in text,
              "a null metric (chain_fidelity in the twin row) must render as n/a, not 'None' or crash")
        check("password_spray" not in text, "sanity: fixture doesn't reuse real repo strings")


def test_twin_table_has_causal_order_columns_additively():
    """The co-metrics are extra columns: the legacy columns keep their names and order, the new ones
    come AFTER them (not leading), old rows render n/a for them, and a bool False / float / null all
    render without crashing."""
    with tempfile.TemporaryDirectory() as tmp:
        trend = Path(tmp) / "trend.jsonl"
        trend.write_text(_SAMPLE_JSONL + f"{_ROW_TWIN_CO}\n{_ROW_TWIN_REV}\n", encoding="utf-8")
        out = Path(tmp) / "viewer.html"
        count = generate(trend, out)
        check(count == 5, f"generate() must load 5 rows, got {count}")
        text = out.read_text(encoding="utf-8")
        legacy = ["tpr", "fpr", "chain_fidelity", "evidence_completeness", "mtti",
                  "false_correlation_rate", "alert_reduction_ratio", "mutation_robustness"]
        new = ["causal_order_fidelity", "order_concordance", "alert_order_ok"]
        pos = [text.find(f"<th>{c}</th>") for c in legacy + new]
        check(all(p >= 0 for p in pos), f"every legacy and new twin column header must render, got {pos}")
        check(pos == sorted(pos), "legacy columns keep their order and the co-metric columns come after them")
        check("0.8333" in text, "a causal_order_fidelity float must render")
        check("<td>False</td>" in text and "<td>True</td>" in text,
              "alert_order_ok True and False must both render as values (False is not 'n/a')")
        check(text.index("2026-10-03") < text.index("2026-10-02") < text.index("2026-08-01T00"),
              "twin rows must still render newest-first")


def test_generate_empty_trend_shows_honest_empty_state():
    with tempfile.TemporaryDirectory() as tmp:
        trend = Path(tmp) / "trend.jsonl"
        trend.write_text("# only a comment, no real rows\n", encoding="utf-8")
        out = Path(tmp) / "viewer.html"
        count = generate(trend, out)
        check(count == 0, f"an all-comment file must load 0 rows, got {count}")
        text = out.read_text(encoding="utf-8")
        check("No detection-quality rows yet." in text, "empty corpora must say so plainly, not render a blank table")
        check("No twin scorecard rows yet." in text, "empty twin must say so plainly too")


def main():
    test_load_rows_skips_comments_and_blank_and_warns_on_malformed()
    test_load_rows_missing_file_is_empty_not_an_error()
    test_generate_writes_real_html_with_both_tables_newest_first()
    test_twin_table_has_causal_order_columns_additively()
    test_generate_empty_trend_shows_honest_empty_state()

    if FAILS:
        print(f"[FAIL] trend viewer generator: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] Phase 5 item 6: generate_trend_viewer.py skips comment/blank/malformed "
          "lines, renders both tables newest-first with real values (nulls as honest "
          "n/a, not crashes), and an empty trend file gets an honest empty state, "
          "not a blank table")


if __name__ == "__main__":
    main()
