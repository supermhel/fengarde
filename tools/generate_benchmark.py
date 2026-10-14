"""Generate benchmark/results.json from the committed eval trend file.

Phase 5 item 8 (public detection benchmark, 2026-10-14): the internal
measured rows live in eval/trend.jsonl as append-only history. This tool
packages the LATEST corpus row and the LATEST twin row into a deliberately
chosen PUBLIC schema (benchmark/results.json) -- selected fields, documented
units, explicit caveats -- instead of dumping the raw internal jsonl row.

Choice discipline:

* Rows are append-only and some history is KNOWN-FABRICATED (the pre-fix
  pilot twin row dated 2026-08-28T12:07:10 is labeled as such in a comment in
  trend.jsonl). Selection therefore takes the MAX date per run-type, with a
  hard guard that the selected corpus row is a real corpus row
  (per_rule + macro_f1 present) and that the selected twin row is NOT the
  known fabricated one (its fpr=0.25 is the marker; the first REAL twin row
  also carries basis=harness-measured, so date-order alone is the correct
  discriminator -- the fabricated row is simply never the latest).
* parser_coverage_pct is published RAW (42.3% as of the current row) with a
  definition and why it is low; the benchmark's own methodology.md states it
  plainly -- the packaging job never hides the weakest number.
* Units are documented inline in a "units" object next to the values; this
  file emits JSON only, the human-readable narrative lives in
  benchmark/methodology.md and benchmark/README.md.

Run:  python tools/generate_benchmark.py            # rewrites benchmark/results.json
      python tools/test_generate_benchmark.py       # schema/latest-row self-test
Also wired into .github/workflows/nightly-eval.yml (regenerate after each run).
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TREND = ROOT / "eval" / "trend.jsonl"
OUT = ROOT / "benchmark" / "results.json"

# The one historic row that must NEVER win "latest twin": the pre-fix
# FABRICATED pilot row (fpr=0.25, chain_fidelity=0.0, hand-picked constants
# written by the pre-fix report.py -- see the comment block in trend.jsonl and
# SSOT.md section 2 "proven vs. claim"). Date-order selection already excludes
# it (it is the earliest twin row); the guard makes that explicit and loud.
FABRICATED_TWIN_FPR = 0.25


def load_trend_rows(path: Path) -> list[dict]:
    """All JSON objects in the trend file (comment/blank lines skipped)."""
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:  # a corrupt row must be loud
            raise SystemExit(
                f"generate_benchmark: corrupt trend row in {path.name}: {exc}") from exc
    return rows


def latest_corpus_row(rows: list[dict]) -> dict:
    corpus = [r for r in rows if "per_rule" in r and "macro_f1" in r]
    if not corpus:
        raise SystemExit("generate_benchmark: no corpus row found in eval/trend.jsonl")
    return max(corpus, key=lambda r: r["date"])


def latest_twin_row(rows: list[dict]) -> dict:
    twins = [r for r in rows if r.get("run_type") == "twin"]
    if not twins:
        raise SystemExit("generate_benchmark: no twin row found in eval/trend.jsonl")
    latest = max(twins, key=lambda r: r["date"])
    if latest.get("twin_metrics", {}).get("fpr") == FABRICATED_TWIN_FPR:
        raise SystemExit(
            "generate_benchmark: latest twin row is the KNOWN-FABRICATED pilot "
            "(fpr=0.25) -- refusing to publish it. Something appended a row "
            "dated after the real 2026-08-28T14:46:46+00:00 run with fpr=0.25.")
    return latest


# Stable ORACLE rule id -> name (mirrors eval/detection_accuracy/evtx_eval.py's
# RULE_NAMES). Kept in sync by hand; the trend row's per_rule keys are the ids,
# the public schema publishes both so a reader never has to look up ids.
RULE_NAMES = {
    "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01": "bruteforce",
    "4f8a2c61-9e3d-4b57-8a1c-6d2e5f7a8b90": "password_spray",
    "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061": "lateral_movement",
    "7d3e9a52-1f6c-4a88-9b3d-2e5c8f1a6d40": "priv_grant",
    "9b5f2d18-3c7a-4e61-8f24-5a1d7c3e9b06": "after_hours_admin",
    "8c2f5a91-4d16-4e8b-9c3a-1f6b2e7d5a83": "bruteforce_sourceless",
}


def build_document(corpus: dict, twin: dict) -> dict:
    """The stable public schema. Every metric has a documented unit; metrics
    that were never measured (null) stay null -- a benchmark never zero-fills
    an unmeasured metric."""
    twin_m = twin["twin_metrics"]
    per_rule = {name: dict(c) for name, c in sorted(corpus["per_rule"].items())}

    # Per-rule precision/recall/F1 are NOT recomputed here from the confusion
    # counts: the corpus lanes grade per FILE, so a per-rule precision/recall
    # would misrepresent per-event semantics. The confusion counts are
    # published as-is with their grading unit documented.
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": {
            "file": "eval/trend.jsonl",
            "corpus_row_date": corpus["date"],
            "twin_row_date": twin["date"],
        },
        "detection_quality": {
            "macro_f1": corpus["macro_f1"],
            "rule_id_to_name": dict(sorted(RULE_NAMES.items())),
            "per_rule_confusion": {k: per_rule[k] for k in sorted(per_rule)},
            "corpora": corpus.get("corpora", []),
            "corpus_records": corpus.get("corpus_size"),
            "quality_corpus_events": corpus.get("quality_corpus_events"),
            "parser_coverage_pct": corpus.get("parser_coverage_pct"),
            "untested_rules": corpus.get("untested_rules", []),
        },
        "twin": {
            "tpr": twin_m.get("tpr"),
            "fpr": twin_m.get("fpr"),
            "mttd_seconds": twin_m.get("mttd_seconds"),
            "mtti_seconds": twin_m.get("mtti"),
            "mttr_seconds": twin_m.get("mttr"),
            "chain_fidelity": twin_m.get("chain_fidelity"),
            "evidence_completeness": twin_m.get("evidence_completeness"),
            "false_correlation_rate": twin_m.get("false_correlation_rate"),
            "alert_reduction_ratio": twin_m.get("alert_reduction_ratio"),
            "incident_reconstruction_time_ms": twin_m.get(
                "incident_reconstruction_time_ms"),
            "severity_calibration_error": twin_m.get("severity_calibration_error"),
            "attribution_accuracy": twin_m.get("attribution_accuracy"),
        },
        "units": {
            "macro_f1": "dimensionless, [0,1]; unweighted mean of per-rule F1 "
                        "(engine-vs-oracle agreement on the hand-labeled "
                        "detection-quality canary, tools/detection_quality_eval.py) "
                        "-- NOT field detection fidelity",
            "per_rule_confusion": "absolute event counts (tp/fp/fn/tn) per rule, "
                                  "graded per corpus FILE by replaying supported "
                                  "records through the real WS-2->WS-4 pipeline "
                                  "against an independent oracle",
            "parser_coverage_pct": "percent; share of Security+Sysmon records in the "
                                   "EVTX corpus (records_supported / (records_security "
                                   "+ records_sysmon)) that a shipped parser can "
                                   "normalize at all -- corpus-shape-limited, see "
                                   "methodology.md",
            "untested_rules": "rule names with zero expected-positive events "
                              "(tp+fn == 0) in the latest corpus run -- surfaced, "
                              "never implied passing",
            "tpr": "dimensionless [0,1]; true-positive rate on the twin's "
                   "intrusion scenario replay",
            "fpr": "dimensionless [0,1]; false-positive rate on the twin's "
                   "benign/negative-control replay",
            "mttd_seconds": "mean time to detect, seconds, scenario replay",
            "mtti_seconds": "mean time to investigate, seconds, scenario replay "
                            "(null when the run did not produce an incident)",
            "mttr_seconds": "mean time to respond, seconds (null when not "
                            "exercised by the run)",
            "chain_fidelity": "dimensionless [0,1]; fraction of the scenario's "
                              "causal chain the correlation layer reproduced in "
                              "its incident graph",
            "evidence_completeness": "dimensionless [0,1]; fraction of expected "
                                     "evidence items present in the evidence package",
            "false_correlation_rate": "dimensionless; false correlations per true "
                                      "incident (1.0 = every positive had one "
                                      "genuine link)",
            "alert_reduction_ratio": "dimensionless [0,1]; (alerts-raw - alerts-"
                                     "correlated)/alerts-raw",
            "incident_reconstruction_time_ms": "milliseconds; wall time to rebuild "
                                               "an incident from its member alerts",
            "severity_calibration_error": "dimensionless; |predicted_severity - "
                                          "true_severity| averaged over scored alerts",
            "attribution_accuracy": "dimensionless [0,1]; share of incident "
                                    "attributions matching the scenario's ground truth",
        },
        "caveats": [
            "macro_f1 is engine-vs-oracle agreement on a hand-labeled "
            "quality canary (10 events, 4 scored rules), not field detection "
            "fidelity; see docs/detection-quality.md.",
            "per-rule confusion counts are graded per corpus FILE, not per event.",
            "per-rule expected-positives are corpus-composition-dependent (the "
            "corpora are fetched at clone time, not version-pinned): on this "
            "snapshot's run the volume-shaped rules bruteforce, "
            "lateral_movement, bruteforce_sourceless had zero expected-positives "
            "in EITHER corpus (reported as untested) -- splunk/attack_data's "
            "brute-force/spray volume lives in non-XML exports this lane's "
            "extractor documents as unread; eval/attack/fire_check.py proves all "
            "28 MITRE-tagged rules still fire on their real producer fixtures.",
            "parser_coverage_pct is a corpus-shape measurement: the EVTX corpus is "
            "Security/Sysmon-centric, so the published value (see README.md) means "
            "'that share of THE RECORDS IN THIS CORPUS parse', not 'that share of "
            "all log formats FENGARDE can ingest'; the 17 shipped parsers cover "
            "IT/OT formats the corpora do not contain.",
            "twin metrics are harness-measured on a deterministic in-process "
            "plc simulator replay (seed 7) with basis=harness-measured; null "
            "fields were not measured in that run, not zero.",
            "ci-clone contamination: GitHub clone counts are inflated by "
            "authenticated Actions checkouts and are NOT published here as "
            "traction evidence.",
        ],
    }


def render_document(rows: list[dict]) -> str:
    """The exact bytes generate_benchmark writes (or checks), sorted keys,
    trailing newline."""
    return (json.dumps(
        build_document(latest_corpus_row(rows), latest_twin_row(rows)),
        indent=2, sort_keys=True) + "\n")


def _strip_ts(doc_str: str) -> str:
    """The document with the volatile generated_at timestamp removed, so
    --check compares every REAL field (row selection, schema, numbers)
    without tripping on the one field that changes every render."""
    d = json.loads(doc_str)
    d.pop("generated_at", None)
    return json.dumps(d, indent=2, sort_keys=True)


def is_stale(rows: list[dict]) -> tuple[bool, str]:
    """(True, rendered) when OUT misses or differs from a fresh render.

    --check compares fields EXCEPT generated_at (that timestamp legitimately
    changes on every write; a committed snapshot must not be called stale
    for carrying its own generation time). Any real drift -- row selection,
    schema shape, measured numbers -- fails loudly instead."""
    rendered = render_document(rows)
    if not OUT.exists():
        return True, rendered
    try:
        current = OUT.read_text(encoding="utf-8")
        if _strip_ts(current) == _strip_ts(rendered):
            return False, rendered
    except (OSError, json.JSONDecodeError):
        pass
    return True, rendered


def main() -> int:
    rows = load_trend_rows(TREND)
    if "--check" in sys.argv:
        stale, _ = is_stale(rows)
        if stale:
            print(f"generate_benchmark --check: {OUT.relative_to(ROOT)} is STALE "
                  f"(differs from a fresh render of {TREND.relative_to(ROOT)}) -- "
                  f"run 'python tools/generate_benchmark.py' and commit the result.")
            return 1
        print(f"generate_benchmark --check: {OUT.relative_to(ROOT)} is fresh")
        return 0
    OUT.parent.mkdir(exist_ok=True, parents=True)
    rendered = render_document(rows)
    OUT.write_text(rendered, encoding="utf-8")
    src = json.loads(rendered)["source"]
    print(f"generate_benchmark: wrote {OUT.relative_to(ROOT)} "
          f"(corpus row {src['corpus_row_date']}, twin row {src['twin_row_date']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())