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
