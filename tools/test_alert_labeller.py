"""Contract tests for tools/alert_labeller.py + eval/real/grade.py (WP-2.2).

The WP-2.2 lane: export alerts with contributing events for review, record
tp/fp/unknown verdicts to a local (git-ignored) labels file, scrub before
anything is shared, and refuse to publish unscrubbed data. The grader
computes per-rule precision from the labels + review with an explicit
"single-site, owner-labelled" marker. All fixtures are synthetic; nothing
touches the bus, Redis or OpenSearch.

Run: python tools/test_alert_labeller.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "eval" / "real"))

import alert_labeller as lab  # noqa: E402
import grade as real_grade  # noqa: E402

FAILS: list[str] = []


def check(cond: object, msg: str) -> None:
    if not cond:
        FAILS.append(msg)


def alert(aid: str, rule: str, event_ids: list[str], trigger: str | None = None,
          src: str = "203.0.113.9") -> dict:
    return {"alert_id": aid, "rule_id": rule, "rule_title": rule,
            "level": "high", "score": 0.9, "time": 1_670_000_000_000,
            "event_ids": event_ids, "trigger_event_id": trigger,
            "src_endpoint": {"ip": src}}


def event(eid: str, ip: str = "203.0.113.9", user: str = "jdoe") -> dict:
    return {"siem": {"ingest_id": eid, "source_type": "windows_eventlog"},
            "src_endpoint": {"ip": ip}, "actor": {"user": {"name": user}},
            "message": f"event {eid}"}


def test_export_join():
    alerts = [alert("a1", "r1", ["e2", "e1", "e-missing"], trigger="e1"),
              alert("a2", "r2", ["e1"])]
    events = [event("e1"), event("e2")]
    out = lab.export_alerts(alerts, events)
    check(len(out) == 2, f"2 records expected, got {len(out)}")
    a1 = out[0]
    # trigger first, then the alert's own order; missing listed, never silent
    check([e["siem"]["ingest_id"] for e in a1["contributing_events"]] == ["e1", "e2"],
          f"contributing event order wrong: {a1['contributing_events']}")
    check(a1["missing_event_ids"] == ["e-missing"],
          f"missing_event_ids wrong: {a1['missing_event_ids']}")
    check(a1["event_ids_total"] == 3, "event_ids_total wrong")
    # dedicated event_ids ordering for a plain list without trigger
    a2 = out[1]
    check([e["siem"]["ingest_id"] for e in a2["contributing_events"]] == ["e1"],
          f"a2 join wrong: {a2['contributing_events']}")


def test_write_review_header_and_readback():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        target = lab.write_review(d / "review",
                                  [alert("a1", "r1", ["e1"], trigger="e1")],
                                  Path("alerts.ndjson"), Path("events.ndjson"))
        text = target.read_text(encoding="utf-8")
        header = json.loads(text.splitlines()[0])
        check(header.get("kind") == "review-export" and "alerts_digest" in header,
              f"review header wrong: {header}")
        back = lab.read_review_file(target)
        check(len(back) == 1 and back[0]["alert_id"] == "a1", "readback failed")


def test_label_append_duplicate_and_verdicts():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "labels.jsonl"
        rc = lab.label_append(p, "a1", "fp", note="benign scanner")
        check(rc == 0, "first label must succeed")
        rc = lab.label_append(p, "a1", "tp")  # duplicate, no --override
        check(rc == 1, "duplicate without --override must return 1")
        rc = lab.label_append(p, "a1", "tp", override=True)
        check(rc == 0, "--override must succeed")
        try:
            lab.label_append(p, "a2", "maybe")
            check(False, "invalid verdict must raise")
        except ValueError:
            pass
        lines = [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()]
        check(len(lines) == 1 and lines[0]["verdict"] == "tp",
              f"override must replace, got {lines}")


def test_scrub_is_deterministic_and_stamped():
    doc = alert("a1", "r1", ["e1"], src="198.51.100.7")
    doc["actor"] = {"user": {"name": "jdoe"}}
    doc["message"] = "login from 198.51.100.7 user=root host=dc01.bankcorp.example"
    m1 = lab.scrub_map("s1")
    m2 = lab.scrub_map("s1")
    s1 = lab.scrub_doc(doc, m1, "s1")
    s2 = lab.scrub_doc(doc, m2, "s1")
    check(s1 == s2, "scrub must be deterministic for the same seed")
    dump = json.dumps(s1)
    check("198.51.100.7" not in dump and "jdoe" not in dump,
          "private values survived scrubbing")
    check("dc01" not in dump and "bankcorp" not in dump,
          "host/domain survived scrubbing")
    # different seed -> different pseudonyms (unlinkability across runs)
    s3 = lab.scrub_doc(doc, lab.scrub_map("s2"), "s2")
    check(s1 != s3, "different seeds must not produce identical scrubs")
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "alerts.jsonl"
        src.write_text(json.dumps(doc), encoding="utf-8")
        dst = lab.scrub_file(src, Path(d) / "out", lab.scrub_map("s1"), "s1")
        back = json.loads(dst.read_text(encoding="utf-8"))
        check(back.get("scrubbed") is True and isinstance(back.get("scrub_digest"), str),
              "scrub_file must stamp the output")


def test_publish_refuses_unscrubbed():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        raw = d / "raw"
        raw.mkdir()
        (raw / "alerts.jsonl").write_text(json.dumps(
            alert("a1", "r1", ["e1"])), encoding="utf-8")
        scrubbed = d / "scrubbed"
        scrubbed.mkdir()
        lab.scrub_file(raw / "alerts.jsonl", scrubbed, lab.scrub_map("s1"), "s1")
        dst = d / "dst"
        n = lab.publish_dir(scrubbed, dst)
        check(n == 1 and (dst / "alerts.jsonl").exists(), "scrubbed publish must copy")
        try:
            lab.publish_dir(raw, d / "dst2")
            check(False, "publish must REFUSE unscrubbed data")
        except ValueError as exc:
            check("refuses to publish" in str(exc), "refusal message must be explicit")
        # labels.jsonl must also be scrubbed before publishing
        lab.label_append(raw / "labels.jsonl", "a1", "fp")
        lab.scrub_file(raw / "labels.jsonl", scrubbed, lab.scrub_map("s1"), "s1")
        n2 = lab.publish_dir(scrubbed, d / "dst3")
        check(n2 == 2, f"labels must publish after scrubbing, got {n2}")


def test_grade_precision_and_marker():
    labels = [
        {"alert_id": "a1", "verdict": "tp"},
        {"alert_id": "a2", "verdict": "fp"},
        {"alert_id": "a3", "verdict": "fp"},
        {"alert_id": "a4", "verdict": "unknown"},
        {"alert_id": "ghost", "verdict": "fp"},  # orphan
        {"alert_id": "b1", "verdict": "tp"},
    ]
    review = {"a1": {"rule_id": "r1", "rule_title": "R1"},
              "a2": {"rule_id": "r1", "rule_title": "R1"},
              "a3": {"rule_id": "r1", "rule_title": "R1"},
              "a4": {"rule_id": "r1", "rule_title": "R1"},
              "b1": {"rule_id": "r2", "rule_title": "R2"}}
    result = real_grade.grade(labels, review)
    check(result["marker"] == "single-site, owner-labelled", "marker missing")
    r1 = next(r for r in result["per_rule"] if r["rule_id"] == "r1")
    # tp=1, fp=2, unknown=1 -> precision 1/3; unknown NOT in the denominator
    check(r1["precision"] == round(1 / 3, 4), f"r1 precision wrong: {r1}")
    check(r1["unknown"] == 1, "unknown must be reported separately")
    check(result["verdicts"] == {"tp": 2, "fp": 3, "unknown": 1},
          f"verdict distribution wrong: {result['verdicts']}")
    check(result["orphan_labels"] == 1, "orphan label must be surfaced")
    ghost = next(r for r in result["per_rule"] if r["rule_id"] == "(unmatched rule)")
    check(ghost["fp"] == 1, "orphan must land in the unmatched bucket")
    md = real_grade.render_markdown(result)
    check("single-site, owner-labelled" in md and "33.33%" in md,
          "markdown must carry the marker and precision")


def main() -> int:
    tests = [test_export_join, test_write_review_header_and_readback,
             test_label_append_duplicate_and_verdicts,
             test_scrub_is_deterministic_and_stamped,
             test_publish_refuses_unscrubbed,
             test_grade_precision_and_marker]
    for t in tests:
        t()
    if FAILS:
        print(f"[FAIL] alert_labeller: {len(FAILS)} problem(s)")
        for f in FAILS[:30]:
            print("  -", f)
        return 1
    print(f"[OK] alert_labeller: {len(tests)} test groups — export join, labels, "
          "deterministic scrub + stamp, publish refusal, per-rule precision")
    return 0


if __name__ == "__main__":
    sys.exit(main())