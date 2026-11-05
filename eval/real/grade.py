#!/usr/bin/env python3
"""Grade owner-labelled alerts (WP-2.2): per-rule precision from a real lane.

Reads a labels file (alert_labeller.py's ``label`` output:
``{"alert_id", "verdict": tp|fp|unknown, "note"}``) plus the scrubbed review
export, and reports per-rule precision = tp / (tp + fp), per-rule counts and
the verdict distribution. The result is EXPLICITLY labelled single-site /
owner-labelled — it is deliberately NOT comparable to the synthetic
benchmarks on the scorecard (different data, different ground truth) and is
never merged into SCORECARD.md.

Nothing private is ever read here: the caller points this at the SCRUBBED
directory (eval/real/out/scrubbed/). The grader itself only joins the label
records to the review's rule facts and writes eval/real/latest.json + a
markdown block.

Zero infrastructure; all logic is a pure function of the two inputs.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

MARKER = "single-site, owner-labelled"
GIT_IGNORE_DIRS = ("review", "out", "labels.jsonl")


def load_labels(path: Path) -> tuple[list[dict], int]:
    """Verdict records that survive: tp/fp/unknown with a matching alert_id."""
    out = []
    malformed = 0
    if not path.exists():
        return [], 0
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            malformed += 1
            continue
        if (isinstance(rec, dict) and isinstance(rec.get("alert_id"), str)
                and rec.get("verdict") in ("tp", "fp", "unknown")):
            out.append(rec)
        else:
            malformed += 1
    return out, malformed


def load_review(review_dir: Path) -> dict:
    """alert_id -> review record (rule_id, rule_title, src_endpoint)."""
    out: dict = {}
    if not review_dir.is_dir():
        return out
    for path in review_dir.glob("alerts.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict) and isinstance(rec.get("alert_id"), str):
                out[rec["alert_id"]] = rec
    return out


def grade(labels: list[dict], review: dict) -> dict:
    """Pure aggregation (the tested core).

    - only tp/fp count toward precision; ``unknown`` is reported separately
      and NEVER folded into the denominator (an unlabelled alert is not a
      false positive, and saying otherwise would lie about precision);
    - the result carries the explicit single-site marker and the share of
      labelled alerts that could NOT be joined to the review (orphan labels
      are surface-breaking honesty, not a silent drop).
    """
    per_rule: dict[str, dict] = {}
    verdicts: Counter = Counter()
    orphan = 0
    for rec in labels:
        verdicts[rec["verdict"]] += 1
        rid = (review.get(rec["alert_id"]) or {}).get("rule_id") or "(unmatched rule)"
        row = per_rule.setdefault(rid, {"tp": 0, "fp": 0, "unknown": 0, "title": ""})
        if rec["alert_id"] not in review:
            orphan += 1
        row[rec["verdict"]] += 1
        row["title"] = (review.get(rec["alert_id"]) or {}).get("rule_title", "")
    rows = []
    for rid, row in sorted(per_rule.items()):
        denom = row["tp"] + row["fp"]
        rows.append({
            "rule_id": rid,
            "title": row["title"],
            "tp": row["tp"],
            "fp": row["fp"],
            "unknown": row["unknown"],
            "precision": round(row["tp"] / denom, 4) if denom else None,
            "labelled_total": row["tp"] + row["fp"] + row["unknown"],
        })
    return {
        "marker": MARKER,
        "labels_used": len(labels),
        "verdicts": dict(verdicts),
        "orphan_labels": orphan,
        "per_rule": rows,
    }


def render_markdown(result: dict) -> str:
    out = [
        f"# Per-rule precision — **{MARKER}**",
        "",
        f"labels used: {result['labels_used']} (orphans not joined to the review: "
        f"{result['orphan_labels']})",
        f"verdict distribution: {result['verdicts']}",
        "",
        "> These numbers come from ONE site's alerts and the owner's own labels. ",
        "> They are NOT comparable with the synthetic-benchmark rows on the ",
        "> scorecard and are never merged into it.",
        "",
        "| rule_id | title | tp | fp | unknown | precision |",
        "|---|---|---|---|---|---|",
    ]
    for row in result["per_rule"]:
        prec = "--" if row["precision"] is None else f"{row['precision']:.2%}"
        out.append(f"| {row['rule_id']} | {row['title']} | {row['tp']} | "
                   f"{row['fp']} | {row['unknown']} | {prec} |")
    return "\n".join(out) + "\n"


def cmd_grade(args) -> int:
    labels, malformed = load_labels(args.labels)
    review = load_review(args.review_dir)
    result = grade(labels, review)
    result["review_files"] = sorted(
        p.name for p in args.review_dir.glob("*.jsonl")) if args.review_dir.is_dir() else []
    if args.out:
        result_out = args.out / "latest.json"
        result_out.parent.mkdir(parents=True, exist_ok=True)
        result_out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                              encoding="utf-8", newline="\n")
    md = render_markdown(result)
    if args.out:
        (args.out / "latest.md").write_text(md, encoding="utf-8", newline="\n")
    print(md)
    print(f"  (malformed label lines skipped: {malformed})", file=sys.stderr)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--review-dir", required=True, type=Path,
                    help="scrubbed review directory (alerts.jsonl)")
    ap.add_argument("--labels", required=True, type=Path,
                    help="labels.jsonl (alert_labeller.py label output)")
    ap.add_argument("--out", type=Path, help="write latest.json + latest.md here")
    args = ap.parse_args(argv)
    return cmd_grade(args)


if __name__ == "__main__":
    sys.exit(main())