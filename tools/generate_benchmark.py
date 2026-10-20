"""Generate benchmark/results.json from the committed eval trend file.

Phase 5 item 8 (public detection benchmark, 2026-10-14): the internal
measured rows live in eval/trend.jsonl as append-only history. This tool
packages the LATEST corpus row and the LATEST twin row into a deliberately
chosen PUBLIC schema (benchmark/results.json) -- selected fields, documented
units, explicit caveats -- instead of dumping the raw internal jsonl row.

Choice discipline:

* Rows are append-only and some history is KNOWN-FABRICATED (the pre-fix
  pilot twin row dated 2026-08-28T12:07:10 is labeled as such in a comment in
  trend.jsonl). Selection therefore takes the MAX date per run-type (ties ->
  larger corpus_size, then the LAST-appended row, since corpus rows carry
  day-granular dates), with a
  hard guard that the selected corpus row actually replayed a corpus
  (per_rule + macro_f1 present AND corpus_size > 0 from an evtx/splunk lane
  -- a quality-only nightly row must never publish corpus_records=0) and
  that the selected twin row is NOT the known fabricated one (its fpr=0.25
  is the marker; date-order alone already excludes it).
* parser_coverage_pct is published RAW with a definition and why it is low;
  the benchmark's own methodology.md states it plainly -- the packaging job
  never hides the weakest number.
* Caveats that cite numbers (untested rules, canary size, twin seed,
  fixture-only rules) are DERIVED from the selected rows, never typed in, so
  a fresh row can never ship next to a caveat describing an older one.
* Units are documented inline in a "units" object next to the values; this
  file emits JSON only, the human-readable narrative lives in
  benchmark/methodology.md and benchmark/README.md.

Run:  python tools/generate_benchmark.py            # rewrites benchmark/results.json
      python tools/generate_benchmark.py --check    # gate: fail if results.json is stale
      python tools/test_generate_benchmark.py       # schema/latest-row self-test
Also wired into .github/workflows/nightly-eval.yml (regenerate after each run).
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from append_trend_row import ORACLE as RULE_NAMES  # single id->name source

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


def _latest(rows: list[dict]) -> dict:
    """Max date; on a same-day tie the row that replayed MORE corpus records
    wins, then the LAST-appended one (max() alone returns the first of equal
    keys, i.e. the older row). Corpus-size first so a same-day partial run --
    e.g. an evtx-only row after the splunk lane refused a partial checkout --
    can never displace the full nightly row."""
    return max(enumerate(rows),
               key=lambda ir: (ir[1]["date"], ir[1].get("corpus_size") or 0, ir[0]))[1]


def latest_corpus_row(rows: list[dict]) -> dict:
    corpus = [r for r in rows if "per_rule" in r and "macro_f1" in r
              and r.get("corpus_size")
              and {"evtx", "splunk"} & set(r.get("corpora", []))]
    if not corpus:
        raise SystemExit("generate_benchmark: no corpus row (a row that replayed "
                         "the evtx/splunk corpora) found in eval/trend.jsonl")
    return _latest(corpus)


def latest_twin_row(rows: list[dict]) -> dict:
    twins = [r for r in rows if r.get("run_type") == "twin"]
    if not twins:
        raise SystemExit("generate_benchmark: no twin row found in eval/trend.jsonl")
    latest = _latest(twins)
    if latest.get("twin_metrics", {}).get("fpr") == FABRICATED_TWIN_FPR:
        raise SystemExit(
            "generate_benchmark: latest twin row is the KNOWN-FABRICATED pilot "
            "(fpr=0.25) -- refusing to publish it. Something appended a row "
            "dated after the real 2026-08-28T14:46:46+00:00 run with fpr=0.25.")
    return latest


def _caveats(corpus: dict, twin: dict) -> list[str]:
    """Every number cited here comes from the selected rows."""
    scored = corpus.get("quality_scored_rules")
    canary = f"{corpus.get('quality_corpus_events')} events" + (
        f", {scored} scored rules" if scored else "")
    out = [
        f"macro_f1 is engine-vs-oracle agreement on a hand-labeled quality "
        f"canary ({canary}), not field detection fidelity; see "
        f"docs/detection-quality.md.",
        "per-rule confusion counts are graded per corpus FILE, not per event.",
    ]
    untested = corpus.get("untested_rules") or []
    commits = {k: v for k, v in (corpus.get("corpus_commits") or {}).items() if v}
    pin = (f"read corpus commits {commits}" if commits else
           "predates commit recording; the corpus fetch is now pinned in "
           "eval/detection_accuracy/fetch_corpora.sh")
    if untested:
        out.append(
            "per-rule expected-positives are corpus-composition-dependent (this "
            f"row {pin}; a newer upstream corpus is a pin bump in a PR): on this "
            f"snapshot's run {', '.join(untested)} had zero expected-positive "
            "files in every corpus (reported as untested); "
            "eval/attack/fire_check.py separately proves every MITRE-tagged "
            "rule fires on its own real producer fixture.")
    fx = corpus.get("fixture_tested_rules") or []
    if fx:
        out.append(
            f"{', '.join(fx)}: graded on committed synthetic fixtures "
            "(eval/detection_accuracy/attack_fixtures.py), published only in "
            "fixture_per_rule_confusion -- never in per_rule_confusion, "
            "corpus_records or parser_coverage_pct.")
    out += [
        "parser_coverage_pct is a corpus-shape measurement: it means 'that share "
        "of THIS EVTX corpus's Security+Sysmon records parse', not 'that share of "
        "all log formats FENGARDE can ingest'; most of the 19 shipped parsers "
        "cover IT/OT formats these corpora do not contain.",
        f"twin metrics are harness-measured on a deterministic in-process plc "
        f"simulator replay (seed {twin.get('seed')}, basis={twin.get('basis')}); "
        f"null fields were not measured in that run, not zero.",
        "ci-clone contamination: GitHub clone counts are inflated by "
        "authenticated Actions checkouts and are NOT published here as "
        "traction evidence.",
    ]
    return out


def build_document(corpus: dict, twin: dict) -> dict:
    """The stable public schema. Every metric has a documented unit; metrics
    that were never measured (null) stay null -- a benchmark never zero-fills
    an unmeasured metric."""
    twin_m = twin["twin_metrics"]
    per_rule = {rid: dict(c) for rid, c in sorted(corpus["per_rule"].items())}

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
            "per_rule_confusion": per_rule,
            # null on rows written before fixtures were graded separately.
            "fixture_per_rule_confusion": corpus.get("fixture_per_rule"),
            "fixture_tested_rules": corpus.get("fixture_tested_rules"),
            "corpora": corpus.get("corpora", []),
            "corpus_records": corpus.get("corpus_size"),
            "corpus_files": corpus.get("lane_files"),
            "corpus_commits": corpus.get("corpus_commits"),
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
            "per_rule_confusion": "counts of corpus FILES (tp/fp/fn/tn) per rule, "
                                  "NOT events: each third-party corpus file with "
                                  "supported records is replayed through the real "
                                  "WS-2->WS-4 pipeline and graded against an "
                                  "independent oracle; synthetic fixtures excluded",
            "fixture_per_rule_confusion": "counts of committed synthetic fixtures "
                                          "(tp/fp/fn/tn) per rule, graded exactly "
                                          "like a corpus file, counted once; null "
                                          "when the row predates separate grading",
            "fixture_tested_rules": "rule names with expected-positives from "
                                    "synthetic fixtures (when also listed in "
                                    "untested_rules: ONLY from fixtures)",
            "parser_coverage_pct": "percent; share of Security+Sysmon records in the "
                                   "EVTX corpus (records_supported / (records_security "
                                   "+ records_sysmon)) that a shipped parser can "
                                   "normalize at all -- corpus-shape-limited, see "
                                   "methodology.md",
            "corpus_commits": "git commit of each corpus the lanes read ({evtx, "
                              "splunk}), pinned in eval/detection_accuracy/"
                              "fetch_corpora.sh; null on older rows",
            "corpus_files": "files each corpus lane read ({evtx, splunk}); null "
                            "on rows written before provenance was recorded",
            "untested_rules": "rule names with zero expected-positive corpus "
                              "files (tp+fn == 0) in the latest corpus run -- "
                              "surfaced, never implied passing",
            # Twin units mirror eval/twin/report.py's own metric docstring
            # (gap-hunt 2026-10-14: the first cut described false_correlation_
            # rate=1.0 as benign and severity_calibration_error as a mean error;
            # both were wrong -- see methodology.md section 4).
            "tpr": "dimensionless [0,1]; share of the scenario's oracle-expected "
                   "detections that fired on the twin's intrusion-chain replay",
            "fpr": "dimensionless [0,1]; share of the twin's benign negative-"
                   "control replays that raised an incident",
            "mttd_seconds": "seconds from chain start to the first chain step whose "
                            "oracle-expected rule fired, on seed-derived event "
                            "timestamps of ONE deterministic scenario (not a mean "
                            "over incidents, not wall-clock)",
            "mtti_seconds": "MODELED, not measured: the real investigation step count "
                            "over the picked incident's own graph x a documented "
                            "30 s/step analyst-latency constant "
                            "(eval/twin/report.py _ANALYST_STEP_SECONDS); null when "
                            "no incident promoted",
            "mttr_seconds": "null by construction: the twin has no remediation/"
                            "closure event to time (not measured, not zero)",
            "chain_fidelity": "dimensionless [0,1]; share of the oracle's ALLOWED "
                              "causal step-pairs that a real WS-8 incident-graph "
                              "edge joined",
            "evidence_completeness": "dimensionless [0,1]; share of the oracle's "
                                     "per-step evidence fields present on parsed "
                                     "steps (unparsed gap steps count against it)",
            "false_correlation_rate": "dimensionless [0,1], LOWER IS BETTER; share of "
                                      "the oracle's FORBIDDEN causal step-pairs "
                                      "(allowed: false) that a real WS-8 graph edge "
                                      "joined anyway -- 1.0 means every forbidden "
                                      "pair was falsely joined",
            "alert_reduction_ratio": "dimensionless [0,1]; 1 - (WS-8 incidents / raw "
                                     "WS-4 alerts) over the scenario window",
            "incident_reconstruction_time_ms": "milliseconds, informational wall-clock: "
                                               "median time to assemble the real WS-3 "
                                               "evidence package for the picked "
                                               "incident; machine-load dependent",
            "severity_calibration_error": "binary 0/1, NOT a mean error: 0.0 when the "
                                          "peak fired alert score lies inside the "
                                          "oracle's severity band, 1.0 when outside; "
                                          "null when nothing fired",
            "attribution_accuracy": "dimensionless [0,1]; share of ACTOR-BEARING "
                                    "scenario steps whose attributed actor matches "
                                    "ground truth (actor-less steps excluded, not "
                                    "credited)",
        },
        "caveats": _caveats(corpus, twin),
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