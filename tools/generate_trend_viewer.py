"""Phase 5 (2026-09-04) item 6: a minimal viewer for eval/trend.jsonl.

Real nightly rows have landed since Phase 0.2/1 (SSOT.md cites 10+ committed
rows) with zero rendering surface -- "check the file by hand" was genuinely
the only way to read it. This is the internal viewer the roadmap asks for
("a generated static page is enough"); the PUBLIC-facing benchmark artifact
(roadmap item 8, `benchmark/results.json` + a packaging pipeline) is a
separate, later, independently-landable track, not built here.

Reads every real row (skips the file's own `#`-prefixed comment lines, e.g.
the documented "PRE-FIX FABRICATED pilot row" annotation -- this viewer must
never render a row the file itself flags as fabricated history), renders two
tables (detection-quality corpora runs, AI-to-OT twin scorecard runs) newest
first, and writes a single self-contained HTML file. No JS framework, no
chart library, no external asset -- same "0 stock chart libraries" posture
the dashboard and tour page already hold themselves to; a plain table is
legible and correct, and correctness matters more than a sparkline here.

Usage:
    python tools/generate_trend_viewer.py
    python tools/generate_trend_viewer.py --out path/to/output.html
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TREND = ROOT / "eval" / "trend.jsonl"
DEFAULT_OUT = ROOT / "eval" / "trend_viewer.html"


def load_rows(trend_path: Path) -> list[dict]:
    """Every real (non-comment, non-blank) row, in file order. Malformed
    lines are skipped with a stderr warning rather than aborting the whole
    generation -- one bad row must not blind the viewer to every other one."""
    rows: list[dict] = []
    if not trend_path.exists():
        return rows
    for i, raw in enumerate(trend_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            print(f"[warn] {trend_path}:{i}: not valid JSON, skipping ({exc})", file=sys.stderr)
    return rows


def _fmt(value) -> str:
    if value is None:
        return "<span class=\"na\">n/a</span>"
    if isinstance(value, float):
        return f"{value:.4g}"
    if isinstance(value, list):
        return html.escape(", ".join(str(v) for v in value)) if value else "<span class=\"na\">none</span>"
    return html.escape(str(value))


def _corpora_table(rows: list[dict]) -> str:
    rows = [r for r in rows if r.get("run_type") not in ("twin",)]
    rows = sorted(rows, key=lambda r: r.get("date", ""), reverse=True)
    if not rows:
        return "<p class=\"empty\">No detection-quality rows yet.</p>"
    body = ""
    for r in rows:
        body += (
            "<tr>"
            f"<td>{_fmt(r.get('date'))}</td>"
            f"<td>{_fmt(r.get('macro_f1'))}</td>"
            f"<td>{_fmt(r.get('parser_coverage_pct'))}%</td>"
            f"<td>{_fmt(r.get('corpus_size'))}</td>"
            f"<td>{_fmt(r.get('corpora'))}</td>"
            f"<td>{_fmt(r.get('untested_rules'))}</td>"
            "</tr>\n"
        )
    return (
        "<table>\n<thead><tr>"
        "<th>Date</th><th>macro F1</th><th>Parser coverage</th>"
        "<th>Corpus size</th><th>Corpora</th><th>Untested rules</th>"
        f"</tr></thead>\n<tbody>\n{body}</tbody>\n</table>"
    )


def _twin_table(rows: list[dict]) -> str:
    rows = [r for r in rows if r.get("run_type") == "twin"]
    rows = sorted(rows, key=lambda r: r.get("date", ""), reverse=True)
    if not rows:
        return "<p class=\"empty\">No twin scorecard rows yet.</p>"
    cols = ["tpr", "fpr", "chain_fidelity", "evidence_completeness", "mtti",
            "false_correlation_rate", "alert_reduction_ratio", "mutation_robustness"]
    head = "".join(f"<th>{c}</th>" for c in cols)
    body = ""
    for r in rows:
        m = r.get("twin_metrics") or {}
        cells = "".join(f"<td>{_fmt(m.get(c))}</td>" for c in cols)
        body += f"<tr><td>{_fmt(r.get('date'))}</td><td>{_fmt(r.get('seed'))}</td>{cells}</tr>\n"
    return (
        f"<table>\n<thead><tr><th>Date</th><th>Seed</th>{head}</tr></thead>\n"
        f"<tbody>\n{body}</tbody>\n</table>"
    )


_PAGE_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>FENGARDE eval trend</title>
<style>
  body{{font:14px/1.5 -apple-system,"Segoe UI",Roboto,sans-serif;background:#f6f7fb;
    color:#12141a;margin:0;padding:32px;}}
  h1{{font-size:20px;margin:0 0 4px}}
  .sub{{color:#666f80;margin:0 0 28px;font-size:13px}}
  h2{{font-size:15px;margin:28px 0 8px}}
  table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 2px rgba(20,22,30,.04)}}
  th,td{{text-align:left;padding:6px 10px;border-bottom:1px solid #e3e6ee;
    font-variant-numeric:tabular-nums;white-space:nowrap}}
  th{{color:#666f80;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.02em}}
  tr:hover td{{background:#f0f2f9}}
  .na{{color:#9099ac}}
  .empty{{color:#666f80;font-style:italic}}
  .generated{{color:#9099ac;font-size:12px;margin-top:28px}}
</style>
</head>
<body>
<h1>FENGARDE — eval/trend.jsonl</h1>
<p class="sub">Real nightly measurements. Every row is what the nightly workflow actually
measured -- no fabricated numbers, no interpolation between runs. Generated by
<code>tools/generate_trend_viewer.py</code>, not hand-edited.</p>

<h2>Detection quality (corpora runs)</h2>
{corpora_table}

<h2>AI-to-OT twin scorecard</h2>
{twin_table}

<p class="generated">Generated {generated_at} from {row_count} row(s) in {trend_path}.</p>
</body>
</html>
"""


def generate(trend_path: Path, out_path: Path) -> int:
    rows = load_rows(trend_path)
    from datetime import datetime, timezone
    html_out = _PAGE_TEMPLATE.format(
        corpora_table=_corpora_table(rows),
        twin_table=_twin_table(rows),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        row_count=len(rows),
        trend_path=html.escape(str(trend_path)),
    )
    out_path.write_text(html_out, encoding="utf-8")
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trend", type=Path, default=DEFAULT_TREND)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    count = generate(args.trend, args.out)
    print(f"[OK] wrote {args.out} from {count} row(s) in {args.trend}")


if __name__ == "__main__":
    main()
