"""Append ONE corpus+canary row to eval/trend.jsonl.

This was inline Python in .github/workflows/nightly-eval.yml; it moved here
(review of PR #96, 2026-10-14) so a local reproduction runs the SAME code the
nightly lane runs (benchmark/reproduction.md step 4) and so the row logic is
unit-tested (tools/test_append_trend_row.py).

Reads the gitignored lane outputs eval/detection_accuracy/{evtx,splunk}_eval_
results.json (each lane deletes its own file when it SKIPs, so a stale file is
never re-published under today's date), recomputes the detection-quality
canary's macro-F1, and appends a single schema-v1 row.

Corpus vs. fixture: ``per_rule`` and ``untested_rules`` are graded on the
third-party corpora ONLY. The committed synthetic fixtures
(eval/detection_accuracy/attack_fixtures.py) are replayed identically by BOTH
lanes, so they are taken ONCE (evtx lane's copy, else splunk's) into the
separate ``fixture_per_rule`` / ``fixture_tested_rules`` fields -- summing
them in (the pre-fix behavior) counted one synthetic fixture twice as corpus
positives.

Run: python tools/append_trend_row.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LANE_DIR = ROOT / "eval" / "detection_accuracy"
TREND = ROOT / "eval" / "trend.jsonl"

# Stable ORACLE rule id -> name. Single source for the trend row AND the
# public benchmark (tools/generate_benchmark.py imports it); pinned equal to
# eval/detection_accuracy/evtx_eval.py::RULE_NAMES by test_append_trend_row.py.
ORACLE = {
    "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01": "bruteforce",
    "4f8a2c61-9e3d-4b57-8a1c-6d2e5f7a8b90": "password_spray",
    "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061": "lateral_movement",
    "7d3e9a52-1f6c-4a88-9b3d-2e5c8f1a6d40": "priv_grant",
    "9b5f2d18-3c7a-4e61-8f24-5a1d7c3e9b06": "after_hours_admin",
    "8c2f5a91-4d16-4e8b-9c3a-1f6b2e7d5a83": "bruteforce_sourceless",
}
NAME2ID = {v: k for k, v in ORACLE.items()}


def load_json(p: Path) -> dict | None:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _zeros() -> dict[str, dict[str, int]]:
    return {rid: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for rid in ORACLE}


def _fold(into: dict, confusion: dict) -> None:
    """Add a lane's name-keyed confusion into an id-keyed matrix."""
    for name, m in confusion.items():
        rid = NAME2ID.get(name)
        if rid is None:
            continue
        for k in ("tp", "fp", "fn", "tn"):
            into[rid][k] += int(m[k])


def _positives(per_rule: dict) -> list[str]:
    return [ORACLE[rid] for rid in per_rule
            if per_rule[rid]["tp"] + per_rule[rid]["fn"] > 0]


def build_row(evtx: dict | None, splunk: dict | None, macro_f1: float,
              quality_events: int, quality_scored_rules: int,
              now: datetime, corpus_commits: dict | None = None) -> dict:
    corpora: list[str] = []
    corpus_size = 0
    parser_coverage_pct = None
    per_rule = _zeros()
    fixture_per_rule = _zeros()

    if evtx is not None:
        corpora.append("evtx")
        c = evtx["corpus"]
        corpus_size += int(c["records_supported"])
        rel = c["records_security"] + c["records_sysmon"]
        if rel:
            parser_coverage_pct = round(100 * c["records_supported"] / rel, 1)
        _fold(per_rule, evtx["confusion"])
    if splunk is not None:
        corpora.append("splunk")
        corpus_size += int(splunk.get("supported_records", 0))
        _fold(per_rule, splunk["confusion"])
    # Same deterministic fixtures in both lanes -> count them ONCE.
    fx = (evtx or {}).get("fixture_confusion") or (splunk or {}).get("fixture_confusion")
    if fx:
        _fold(fixture_per_rule, fx)
    if corpus_size or macro_f1 > 0:
        corpora.append("quality")

    # A rule with no expected-positive (tp+fn == 0) in the CORPORA never met
    # attack-shaped corpus events; it is surfaced, never implied-passing --
    # even when a synthetic fixture covers it (that shows in
    # fixture_tested_rules instead).
    tested = set(_positives(per_rule))
    untested = [ORACLE[rid] for rid in per_rule if ORACLE[rid] not in tested]

    return {
        "_schema": "1",
        "date": now.strftime("%Y-%m-%d"),
        "corpora": sorted(corpora),
        "corpus_size": corpus_size,
        # Provenance: how many corpus files each lane actually read. A partial
        # local checkout once produced a row with 57 splunk files where the
        # full nightly clone reads 1,055 -- the row must show which it was.
        "lane_files": {"evtx": (evtx or {}).get("corpus", {}).get("files"),
                       "splunk": (splunk or {}).get("files")},
        # The corpus commit each lane read (pinned by
        # eval/detection_accuracy/fetch_corpora.sh); null for a lane that
        # did not run or a corpus that is not a git checkout.
        "corpus_commits": {"evtx": (corpus_commits or {}).get("evtx") if evtx else None,
                           "splunk": (corpus_commits or {}).get("splunk") if splunk else None},
        "per_rule": per_rule,
        "fixture_per_rule": fixture_per_rule,
        "macro_f1": round(macro_f1, 4),
        "quality_corpus_events": quality_events,
        "quality_scored_rules": quality_scored_rules,
        "parser_coverage_pct": parser_coverage_pct,
        "untested_rules": untested,
        "fixture_tested_rules": _positives(fixture_per_rule),
    }


def _head(path: Path) -> str | None:
    import subprocess
    try:
        return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], check=True,
                              capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main() -> int:
    sys.path.insert(0, str(ROOT / "tools"))
    import detection_quality_eval as D

    rules = D.load_engine_rules()
    results = D.entry_results(D.CORPUS, rules)
    scored = D.references(D.CORPUS)
    per_rule_dq = {rid: D.rule_metrics(results, rid) for rid in sorted(scored)}
    row = build_row(load_json(LANE_DIR / "evtx_eval_results.json"),
                    load_json(LANE_DIR / "splunk_eval_results.json"),
                    D.macro_f1(per_rule_dq), len(D.CORPUS), len(scored),
                    datetime.now(timezone.utc),
                    {"evtx": _head(LANE_DIR / "evtx-samples"),
                     "splunk": _head(LANE_DIR / "splunk-attack-data")})
    with TREND.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    print("APPENDED:", json.dumps(row))
    return 0


if __name__ == "__main__":
    sys.exit(main())
