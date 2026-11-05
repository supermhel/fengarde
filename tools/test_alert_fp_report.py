"""Contract tests for tools/alert_fp_report.py (WP-2.3, zero-infra).

The tool replays alert documents (the exact ``make_alert`` shape WS-4 emits
on ``alerts``) and reports alerts per rule per day + top noisy sources, so an
operator can tune thresholds from real traffic. All fixtures are generated in
code; nothing touches the bus, Redis or OpenSearch.

Run: python tools/test_alert_fp_report.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import alert_fp_report as afr  # noqa: E402

FAILS: list[str] = []


def check(cond: object, msg: str) -> None:
    if not cond:
        FAILS.append(msg)


def alert(rule: str, day: str, ip: str, title: str = "", ts=None) -> dict:
    """A make_alert-shaped document; day default gives 12:00:00 UTC."""
    if ts is None:
        dt = datetime.strptime(day + "T12:00:00", "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        ts = int(dt.timestamp() * 1000)
    a = {"alert_id": f"{rule}-{day}-{ip}", "time": ts, "rule_id": rule,
         "rule_title": title or rule, "level": "high", "score": 0.9,
         "src_endpoint": {"ip": ip}, "triage": {"status": "new"}}
    return a


def dump(alerts: list[dict]) -> str:
    return "\n".join(json.dumps(a) for a in alerts)


def test_day_of():
    check(afr.day_of(1_670_000_000_000) == "2022-12-02",
          f"epoch ms day wrong: {afr.day_of(1_670_000_000_000)}")
    check(afr.day_of(1_670_000_000) == "2022-12-02",  # raw seconds tolerated
          "epoch seconds day wrong")
    for junk in (None, True, "abc", -5, float("inf"), {}, []):
        check(afr.day_of(junk) is None, f"day_of({junk!r}) must be None")


def test_parse_tolerates_malformed_lines():
    lines = [
        json.dumps(alert("r1", "2026-10-01", "10.0.0.1")),
        "this is not json {",
        "",
        json.dumps([alert("r2", "2026-10-01", "10.0.0.2")]),  # array doc
        "42",
        json.dumps(alert("r3", "2026-10-02", "10.0.0.3")),
    ]
    parsed, malformed = afr.parse_alerts(lines)
    check(len(parsed) == 3, f"3 valid alerts expected, got {len(parsed)}")
    check(malformed == 2, f"2 malformed lines expected, got {malformed}")


def test_per_rule_per_day_counts():
    alerts = [
        alert("common_bruteforce", "2026-10-01", "10.0.0.9"),
        alert("common_bruteforce", "2026-10-01", "10.0.0.9"),
        alert("common_bruteforce", "2026-10-02", "10.0.0.9"),
        alert("m365_inbox_rule_external_forward", "2026-10-02", "10.0.0.5"),
    ]
    agg = afr.aggregate([json.loads(x) for x in dump(alerts).splitlines()])
    check(agg["per_day"] == {("common_bruteforce", "2026-10-01"): 2,
                             ("common_bruteforce", "2026-10-02"): 1,
                             ("m365_inbox_rule_external_forward", "2026-10-02"): 1},
          f"per_day wrong: {agg['per_day']}")
    check(agg["per_rule"]["common_bruteforce"] == 3,
          f"per_rule wrong: {agg['per_rule']}")
    check(agg["total"] == 4, "total wrong")


def test_noisy_sources_ordering_and_ties():
    alerts = [
        alert("r", "2026-10-01", "10.0.0.3"),
        alert("r", "2026-10-01", "10.0.0.1"),
        alert("r", "2026-10-01", "10.0.0.1"),
        alert("r", "2026-10-01", "10.0.0.2"),
        alert("r", "2026-10-01", "10.0.0.2"),
        alert("r", "2026-10-01", "10.0.0.1"),
    ]
    agg = afr.aggregate([json.loads(x) for x in dump(alerts).splitlines()])
    ranked = sorted(agg["per_source"].items(), key=lambda kv: (-kv[1], kv[0]))
    check(ranked == [("10.0.0.1", 3), ("10.0.0.2", 2), ("10.0.0.3", 1)],
          f"source ranking wrong: {ranked}")
    # tie on count -> ip ascending (deterministic output)
    agg2 = afr.aggregate([json.loads(x) for x in dump([
        alert("r", "2026-10-01", "10.0.0.9"),
        alert("r", "2026-10-01", "10.0.0.4"),
    ]).splitlines()])
    ranked2 = sorted(agg2["per_source"].items(), key=lambda kv: (-kv[1], kv[0]))
    check(ranked2 == [("10.0.0.4", 1), ("10.0.0.9", 1)],
          f"tie-break wrong: {ranked2}")


def test_window_bounds_and_undated():
    alerts = [
        alert("r1", "2026-10-01", "10.0.0.1"),
        alert("r1", "2026-10-05", "10.0.0.1"),
        alert("r1", "2026-10-10", "10.0.0.1"),
        alert("r2", "2026-10-01", "10.0.0.2"),
    ]
    parsed = [json.loads(x) for x in dump(alerts).splitlines()]
    agg = afr.aggregate(parsed, since="2026-10-02", until="2026-10-09")
    check(set(agg["per_day"]) == {("r1", "2026-10-05")},
          f"window bounds wrong: {agg['per_day']}")
    check(agg["excluded_by_window"] == 3, f"excluded wrong: {agg['excluded_by_window']}")
    # undated: no usable time -> rule total yes, per_day no, sources yes
    undated = {"rule_id": "r1", "rule_title": "t", "src_endpoint": {"ip": "10.9.9.9"}}
    agg2 = afr.aggregate(parsed + [undated], since="2026-10-02", until="2026-10-09")
    check(agg2["undated"] == 1, f"undated wrong: {agg2['undated']}")
    # r1: 10-05 in-window + undated = 2 (10-01 and 10-10 are excluded by window)
    check(agg2["per_rule"]["r1"] == 2, f"undated must count toward rule total: {agg2['per_rule']}")
    check(agg2["per_source"].get("10.9.9.9") == 1,
          f"undated must count toward sources: {agg2['per_source']}")
    check(sum(agg2["per_day"].values()) == 1, "per_day must exclude the undated")


def test_no_source_bucket_and_no_rule():
    nosrc = {"rule_id": "r1", "time": 1_670_000_000_000, "src_endpoint": {}}
    norule = {"time": 1_670_000_000_000, "src_endpoint": {"ip": "10.1.1.1"}}
    agg = afr.aggregate([nosrc, norule])
    check(agg["no_source"] == 1, f"no_source wrong: {agg['no_source']}")
    check(agg["per_source"].get("10.1.1.1") == 1,
          f"no-rule alert must still rank as a source: {agg['per_source']}")
    check(agg["per_rule"] == {"r1": 1}, f"per_rule wrong: {agg['per_rule']}")


def test_rule_filter_and_markdown():
    alerts = [alert("r1", "2026-10-01", "10.0.0.1", title="Rule One"),
              alert("r2", "2026-10-01", "10.0.0.2", title="Rule Two")]
    parsed = [json.loads(x) for x in dump(alerts).splitlines()]
    # the CLI applies --rule before aggregate; mirror that here
    filtered = [a for a in parsed if a.get("rule_id") == "r1"]
    agg = afr.aggregate(filtered)
    check(set(agg["per_rule"]) == {"r1"}, f"rule filter wrong: {agg['per_rule']}")
    md = afr.render_markdown(afr.aggregate(parsed), top_n=5, since=None, until=None)
    check("| r1 | 2026-10-01 | 1 |" in md, "per-rule-per-day row missing")
    check("| Rule One | 1 |" in md, "per-rule total row with title missing")
    check("| 10.0.0.2 | 1 |" in md, "source row missing")
    check("total alerts read: 2" in md, "summary line missing")


def test_main_cli_round_trip(tmp_path=None):
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        path = str(Path(d) / "alerts.ndjson")
        # "garbage\n" dumped via json.dumps is ONE valid-JSON string line -> 1 malformed
        Path(path).write_text(dump([
            alert("common_bruteforce", "2026-10-01", "10.0.0.9"),
            alert("common_bruteforce", "2026-10-01", "10.0.0.9"),
            "garbage\n",
        ]), encoding="utf-8")
        out = str(Path(d) / "report.md")
        rc = afr.main(["--jsonl", path, "--out", out, "--top", "5"])
        check(rc == 0, f"CLI must exit 0, got {rc}")
        text = Path(out).read_text(encoding="utf-8")
        check("common_bruteforce | 2026-10-01 | 2" in text, "CLI report missing the row")
        check("1 malformed line(s) skipped" in text, "malformed count missing from CLI output")
        rc2 = afr.main(["--jsonl", str(Path(d) / "missing.ndjson")])
        check(rc2 == 2, f"missing input must exit 2, got {rc2}")


def main() -> int:
    tests = [test_day_of, test_parse_tolerates_malformed_lines,
             test_per_rule_per_day_counts, test_noisy_sources_ordering_and_ties,
             test_window_bounds_and_undated, test_no_source_bucket_and_no_rule,
             test_rule_filter_and_markdown, test_main_cli_round_trip]
    for t in tests:
        t()
    if FAILS:
        print(f"[FAIL] alert_fp_report: {len(FAILS)} problem(s)")
        for f in FAILS[:30]:
            print("  -", f)
        return 1
    print(f"[OK] alert_fp_report: {len(tests)} test groups — per-rule/day counts, "
          "noisy-source ranking, window bounds, undated/no-source honesty, CLI")
    return 0


if __name__ == "__main__":
    sys.exit(main())