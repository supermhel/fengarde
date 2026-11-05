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
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import alert_labeller  # noqa: E402  (output-path guard shared with the labeller)

MARKER = "single-site, owner-labelled"
MIN_N = 10  # below this many tp+fp labels a rule's precision is flagged LOW-N


def wilson(k: int, n: int, z: float = 1.96) -> list:
    """95% Wilson interval (same formula as eval/llm_triage/run_eval.py)."""
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def load_labels(path: Path) -> tuple[list[dict], int]:
    """Verdict records that survive: tp/fp/unknown with an alert_id.

    A missing file raises FileNotFoundError (an empty table with exit 0 would
    read as "no false positives"); duplicate alert_ids collapse, last wins.
    """
    out: dict[str, dict] = {}
    malformed = 0
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
            out[rec["alert_id"]] = rec
        else:
            malformed += 1
    return list(out.values()), malformed


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

    - labels are deduped by alert_id (last wins); ORPHANS (alert_id not in
      the review) are counted separately and excluded from every rule row and
      the verdict distribution - an unjoinable label says nothing about a rule;
    - only tp/fp count toward precision; ``unknown`` is reported separately
      and NEVER folded into the denominator;
    - each rule reports n = tp+fp, a 95% Wilson interval and a LOW-N flag
      (n < MIN_N): one label is not "100% precision".
    """
    by_id = {rec["alert_id"]: rec for rec in labels}
    per_rule: dict[str, dict] = {}
    verdicts: Counter = Counter()
    orphan = 0
    for rec in by_id.values():
        meta = review.get(rec["alert_id"])
        if meta is None:
            orphan += 1
            continue
        verdicts[rec["verdict"]] += 1
        row = per_rule.setdefault(meta.get("rule_id") or "(no rule_id)",
                                  {"tp": 0, "fp": 0, "unknown": 0, "title": ""})
        row[rec["verdict"]] += 1
        row["title"] = meta.get("rule_title") or row["title"]
    rows = []
    for rid, row in sorted(per_rule.items()):
        n = row["tp"] + row["fp"]
        rows.append({
            "rule_id": rid,
            "title": row["title"],
            "tp": row["tp"],
            "fp": row["fp"],
            "unknown": row["unknown"],
            "n": n,
            "precision": round(row["tp"] / n, 4) if n else None,
            "ci95": wilson(row["tp"], n),
            "low_n": n < MIN_N,
            "labelled_total": n + row["unknown"],
        })
    return {
        "marker": MARKER,
        "labels_used": sum(verdicts.values()),
        "duplicates_collapsed": len(labels) - len(by_id),
        "verdicts": dict(verdicts),
        "orphan_labels": orphan,
        "min_n": MIN_N,
        "per_rule": rows,
    }


def render_markdown(result: dict) -> str:
    out = [
        f"# Per-rule precision — **{MARKER}**",
        "",
        f"labels used: {result['labels_used']} (orphans excluded - not in the review: "
        f"{result['orphan_labels']}; duplicates collapsed: {result['duplicates_collapsed']})",
        f"verdict distribution: {result['verdicts']}",
        "",
        "> These numbers come from ONE site's alerts and the owner's own labels. ",
        "> They are NOT comparable with the synthetic-benchmark rows on the ",
        "> scorecard and are never merged into it.",
        "",
        f"Precision shows n = tp+fp and a 95% Wilson interval; n < {result['min_n']} "
        f"is flagged LOW-N and is not evidence.",
        "",
        "| rule_id | title | tp | fp | unknown | n | precision | 95% CI |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in result["per_rule"]:
        prec = "--" if row["precision"] is None else f"{row['precision']:.2%}"
        lo, hi = row["ci95"]
        ci = "--" if lo is None else f"[{lo:.0%}, {hi:.0%}]"
        flag = " LOW-N" if row["low_n"] else ""
        out.append(f"| {row['rule_id']} | {row['title']} | {row['tp']} | "
                   f"{row['fp']} | {row['unknown']} | {row['n']} | {prec}{flag} | {ci} |")
    return "\n".join(out) + "\n"


def cmd_grade(args) -> int:
    try:
        if args.out:
            alert_labeller.ensure_ignored(args.out, is_dir=True)
        labels, malformed = load_labels(args.labels)
    except (ValueError, OSError) as exc:  # incl. FileNotFoundError: fail loudly
        print(f"error: {exc}", file=sys.stderr)
        return 2
    review = load_review(args.review_dir)
    if not review:
        print(f"error: no review records under {args.review_dir} (alerts.jsonl)",
              file=sys.stderr)
        return 2
    if not labels:
        print(f"error: no usable labels in {args.labels} (malformed: {malformed})",
              file=sys.stderr)
        return 2
    result = grade(labels, review)
    result["review_files"] = sorted(p.name for p in args.review_dir.glob("*.jsonl"))
    md = render_markdown(result)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "latest.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
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
    ap.add_argument("--out", type=Path, default=alert_labeller.REAL / "out",
                    help="write latest.json + latest.md here (must be git-ignored)")
    args = ap.parse_args(argv)
    return cmd_grade(args)


if __name__ == "__main__":
    sys.exit(main())