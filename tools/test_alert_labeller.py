"""Contract tests for tools/alert_labeller.py + eval/real/grade.py (WP-2.2).

The WP-2.2 lane: export alerts with contributing events for review, record
tp/fp/unknown verdicts to a local (git-ignored) labels file, scrub before
anything is shared, and refuse to publish unscrubbed data. The grader
computes per-rule precision from the labels + review with an explicit
"single-site, owner-labelled" marker. All fixtures are synthetic; nothing
touches the bus, Redis or OpenSearch.

Output-path guard tests need git-ignored scratch dirs, so they live under
eval/real/out/ (ignored) and are removed afterwards.

Run: python tools/test_alert_labeller.py
"""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "eval" / "real"))

import alert_labeller as lab  # noqa: E402
import grade as real_grade  # noqa: E402

FAILS: list[str] = []
SCRATCH = lab.REAL / "out" / "_test_scratch"


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


def scratch() -> Path:
    d = SCRATCH / f"t{len(list(SCRATCH.glob('t*'))) if SCRATCH.exists() else 0}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def run(fn, argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = fn(argv)
    return rc, out.getvalue(), err.getvalue()


def jl(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_export_join_and_omitted():
    alerts = [alert("a1", "r1", ["e2", "e1", "e-missing"], trigger="e1"),
              alert("a2", "r2", ["e1"])]
    events = [event("e1"), event("e2")]
    out = lab.export_alerts(alerts, events)
    check(len(out) == 2, f"2 records expected, got {len(out)}")
    a1 = out[0]
    check([e["siem"]["ingest_id"] for e in a1["contributing_events"]] == ["e1", "e2"],
          f"contributing event order wrong: {a1['contributing_events']}")
    check(a1["missing_event_ids"] == ["e-missing"], "missing_event_ids wrong")
    check(a1["event_ids_total"] == 3 and a1["event_ids_omitted"] == 0, "totals wrong")
    check([e["siem"]["ingest_id"] for e in out[1]["contributing_events"]] == ["e1"], "a2 join")
    # finding 6: make_alert's cap marker must reach the record and the CLI output
    capped = alert("a3", "r1", ["e1"])
    capped["event_ids_omitted"] = 40
    rec = lab.export_alerts([capped], events)[0]
    check(rec["event_ids_omitted"] == 40 and rec["event_ids_total"] == 41,
          f"event_ids_omitted lost: {rec}")
    d = scratch()
    (d / "a.ndjson").write_text(json.dumps(capped) + "\n", encoding="utf-8")
    (d / "e.ndjson").write_text(json.dumps(event("e1")) + "\n", encoding="utf-8")
    rc, so, _ = run(lab.main, ["export", "--alerts", str(d / "a.ndjson"),
                               "--events", str(d / "e.ndjson"), "--out", str(d / "rev")])
    check(rc == 0 and "TRUNCATED" in so and "40" in so, f"truncation not rendered: {so!r}")


def test_write_review_header_and_readback():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        target = lab.write_review(d / "review",
                                  [alert("a1", "r1", ["e1"], trigger="e1")],
                                  Path("alerts.ndjson"), Path("events.ndjson"))
        header = json.loads(target.read_text(encoding="utf-8").splitlines()[0])
        check(header.get("kind") == "review-export" and "alerts_digest" in header,
              f"review header wrong: {header}")
        back = lab.read_review_file(target)
        check(len(back) == 1 and back[0]["alert_id"] == "a1", "readback failed")


def test_label_append_duplicate_and_verdicts():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "labels.jsonl"
        check(lab.label_append(p, "a1", "fp", note="benign scanner") == 0, "first label")
        check(lab.label_append(p, "a1", "tp") == 1, "duplicate without --override must return 1")
        check(lab.label_append(p, "a1", "tp", override=True) == 0, "--override must succeed")
        try:
            lab.label_append(p, "a2", "maybe")
            check(False, "invalid verdict must raise")
        except ValueError:
            pass
        lines = jl(p)
        check(len(lines) == 1 and lines[0]["verdict"] == "tp", f"override must replace, got {lines}")


def test_label_corrupt_line_refuses_and_preserves():
    # finding 1: a malformed line used to wipe every label and bypass the dup guard
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "labels.jsonl"
        lab.label_append(p, "a1", "fp")
        lab.label_append(p, "a2", "tp")
        p.write_text(p.read_text(encoding="utf-8") + "{garbage\n", encoding="utf-8")
        before = p.read_bytes()
        for aid, ov in (("a1", False), ("a3", False), ("a1", True)):
            try:
                lab.label_append(p, aid, "tp", override=ov)
                check(False, f"corrupt labels file must refuse ({aid}, override={ov})")
            except ValueError as exc:
                check("malformed" in str(exc), f"unclear refusal: {exc}")
        check(p.read_bytes() == before, "corrupt labels file was modified")
        check(not (Path(d) / "labels.jsonl.tmp").exists(), "temp file left behind")
        rc, _, err = run(lab.main, ["label", "--jsonl", str(p), "--alert-id", "a9",
                                    "--verdict", "fp"])
        check(rc == 2, f"CLI must exit 2 on corrupt/unguarded path, got {rc}")
    # CLI exit 2 on corrupt file inside an ignored dir (so the failure is the parse, not the guard)
    p2 = scratch() / "labels.jsonl"
    p2.write_text('{"alert_id": "a1", "verdict": "fp"}\n{bad\n', encoding="utf-8")
    before = p2.read_bytes()
    rc, _, err = run(lab.main, ["label", "--jsonl", str(p2), "--alert-id", "a1",
                                "--verdict", "tp", "--override"])
    check(rc == 2 and "malformed" in err and p2.read_bytes() == before,
          f"CLI corrupt-line: rc={rc} err={err!r}")


def test_scrub_recurses_all_leaves():
    # finding 2: username + hostname, NO ip, nested in contributing_events
    ev = {"siem": {"ingest_id": "e1"}, "actor": {"user": {"name": "jdoe", "domain": "ACMECORP"}},
          "device": {"hostname": "fileserver9", "labels": ["jdoe-laptop"]},
          "message": "Failed password for jdoe on fileserver9 from ACMECORP",
          "unmapped": {"deep": {"er": {"note": "contact jdoe@acme.example"}}}}
    rec = {"alert_id": "ssh.brute:198.51.100.7:123", "rule_id": "linux.ssh.bruteforce",
           "rule_title": "SSH brute force", "level": "high", "score": 0.9, "time": 1,
           "src_endpoint": {"ip": "198.51.100.7"}, "contributing_events": [ev],
           "missing_event_ids": [], "event_ids_omitted": 3, "event_ids_total": 4}
    s = lab.Scrubber(b"k1")
    out = s.scrub_doc(rec)
    dump = json.dumps(out)
    for secret in ("jdoe", "fileserver9", "ACMECORP", "acme.example", "198.51.100.7"):
        check(secret not in dump, f"{secret!r} survived scrubbing: {dump}")
    check(out["rule_id"] == "linux.ssh.bruteforce" and out["event_ids_omitted"] == 3,
          "public rule facts must stay readable")
    check(out["alert_id"].startswith("alert-"), "alert_id embeds ip/user: must be pseudonymised")
    check(not lab.find_private(lab._stamp(out)), f"rescan flags clean output: {lab.find_private(out)}")
    # same record in two runs/keys
    check(lab.Scrubber(b"k1").scrub_doc(rec) == out, "same secret must be deterministic")
    check(lab.Scrubber(b"k2").scrub_doc(rec) != out, "different secret must differ")


def test_pseudonyms_keyed_not_dictionary_reversible():
    # finding 4: unsalted sha256(value)[:8] is reversible by dictionary
    import hashlib
    s = lab.Scrubber(b"owner-secret")
    pseudo = s.name("user", "jdoe")
    check(pseudo != "user-" + hashlib.sha256(b"jdoe").hexdigest()[:8], "pseudonym is unsalted sha256")
    check(lab.Scrubber(b"other").name("user", "jdoe") != pseudo, "name pseudonym ignores the secret")
    doc = {"alert_id": "a", "actor": {"user": {"name": "jdoe"}}}
    check(b"owner-secret".decode() not in json.dumps(s.scrub_doc(doc)), "secret leaked into output")
    r = lab.Scrubber()  # default: random per run, never stored
    check(r.name("user", "jdoe") != lab.Scrubber().name("user", "jdoe"), "default secret not random")


def test_ip_pseudonyms_consistent_and_collision_free():
    # finding 5: one map per run; no sharing past 16 distinct IPs
    s = lab.Scrubber(b"k")
    ips = [f"10.1.{i // 250}.{i % 250 + 1}" for i in range(600)]
    mapped = [s.text(ip) for ip in ips]
    check(len(set(mapped)) == 600, "two real IPs share a pseudonym")
    check(s.text("x 10.1.0.1 y") == "x " + mapped[0] + " y", "IP pseudonym not stable across calls")
    check(all(lab._text_hits(m) == [] for m in mapped), "pseudonyms must pass the publish rescan")


def test_scrub_file_multiline_labels_and_note():
    # finding 3 + 7: JSONL per line; label note dropped; every line stamped
    d = scratch()
    rev = d / "review"
    rev.mkdir()
    recs = [{"deck": "fengarde-labeller-v1", "kind": "review-export", "alerts_source": "corp-dc01.ndjson",
             "events_source": "e.ndjson", "alerts_digest": "abc"},
            {"alert_id": "r:10.0.0.5:1", "rule_id": "r", "contributing_events": [event("e1", user="bob")]},
            {"alert_id": "r:10.0.0.6:1", "rule_id": "r", "contributing_events": [event("e2", user="bob")]}]
    (rev / "alerts.jsonl").write_text("".join(json.dumps(x) + "\n" for x in recs), encoding="utf-8")
    labels = d / "labels.jsonl"
    labels.write_text(json.dumps({"alert_id": "r:10.0.0.5:1", "verdict": "fp",
                                  "note": "it is bob at 10.0.0.5 on dc01.corp.example"}) + "\n"
                      + json.dumps({"alert_id": "r:10.0.0.6:1", "verdict": "tp", "note": ""}) + "\n",
                      encoding="utf-8")
    out = d / "scrubbed"
    rc, so, err = run(lab.main, ["scrub", "--dir", str(rev), "--labels", str(labels), "--out", str(out)])
    check(rc == 0, f"multi-line scrub with --labels failed: rc={rc} {err!r}")
    sr, sl = jl(out / "alerts.jsonl"), jl(out / "labels.jsonl")
    check(len(sr) == 3 and len(sl) == 2, f"line counts wrong: {len(sr)} {len(sl)}")
    check(all(x.get("scrubbed") is True and lab.is_scrubbed(x) for x in sr + sl), "every line must be stamped")
    check(all(set(x) <= {"alert_id", "verdict", "scrubbed", "scrub_digest"} for x in sl),
          f"label note/extra fields must be dropped: {sl}")
    check("alerts_source" not in sr[0], "provenance filename must be dropped")
    blob = (out / "alerts.jsonl").read_text(encoding="utf-8") + (out / "labels.jsonl").read_text(encoding="utf-8")
    check("bob" not in blob and "10.0.0.5" not in blob and "corp" not in blob, f"leak: {blob}")
    check({x["alert_id"] for x in sr[1:]} == {x["alert_id"] for x in sl},
          "review and labels must pseudonymise alert_id identically in one run")
    # malformed line must fail loudly, not be copied raw
    (rev / "alerts.jsonl").write_text(json.dumps(recs[1]) + "\n{broken\n", encoding="utf-8")
    rc, _, err = run(lab.main, ["scrub", "--dir", str(rev), "--out", str(d / "bad")])
    check(rc == 2 and not (d / "bad" / "alerts.jsonl").exists(), f"broken line must fail: rc={rc}")


def stamped_dir(d: Path, recs: list[dict]) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    (d / "alerts.jsonl").write_text("".join(json.dumps(lab._stamp(r)) + "\n" for r in recs),
                                    encoding="utf-8")
    return d


def test_publish_gate():
    d = scratch()
    clean = lab.Scrubber(b"k").scrub_doc({"alert_id": "a1", "rule_id": "r1",
                                           "contributing_events": [event("e1")]})
    good = stamped_dir(d / "good", [clean])
    dst = d / "pub"
    check(lab.publish_dir(good, dst) == 1 and (dst / "alerts.jsonl").exists(), "clean must publish")
    raw = d / "raw"
    raw.mkdir()
    (raw / "alerts.jsonl").write_text(json.dumps(alert("a1", "r1", ["e1"])) + "\n", encoding="utf-8")
    for label, srcdir in (("unstamped", raw),
                          ("self-declared stamp w/ live ip", stamped_dir(d / "f1", [alert("a1", "r1", [])])),
                          ("stamped note with host", stamped_dir(d / "f2", [{"alert_id": "alert-0123456789ab", "verdict": "fp",
                                                                            "note": "dc01.corp.example"}])),
                          ("stamped user", stamped_dir(d / "f3", [{"alert_id": "alert-0123456789ab",
                                                                   "actor": {"user": {"name": "jdoe"}}}])),
                          ("stamped free-text user=", stamped_dir(d / "f4", [{"alert_id": "alert-0123456789ab",
                                                                              "message": "login user=jdoe"}]))):
        try:
            lab.publish_dir(srcdir, d / "dst_x")
            check(False, f"publish must REFUSE: {label}")
        except ValueError as exc:
            check("refuses to publish" in str(exc), f"{label}: refusal message not explicit: {exc}")
            check("jdoe" not in str(exc) and "corp.example" not in str(exc) and "203.0.113" not in str(exc),
                  f"{label}: refusal echoes the private value: {exc}")
    # forged digest
    bad = stamped_dir(d / "tamper", [clean])
    rec = jl(bad / "alerts.jsonl")[0]
    rec["rule_id"] = "other"
    (bad / "alerts.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
    try:
        lab.publish_dir(bad, d / "dst_t")
        check(False, "tampered digest must refuse")
    except ValueError:
        pass
    # all-or-nothing: a bad second file must not leave a partial copy
    mix = stamped_dir(d / "mix", [clean])
    (mix / "z.jsonl").write_text(json.dumps(alert("a1", "r1", [])) + "\n", encoding="utf-8")
    try:
        lab.publish_dir(mix, d / "dst_m")
        check(False, "mixed dir must refuse")
    except ValueError:
        check(not (d / "dst_m").exists(), "partial publish happened")


def test_output_paths_must_be_ignored():
    # finding 9 (+7 --dst): refuse targets git check-ignore does not cover
    d = scratch()
    (d / "a.ndjson").write_text(json.dumps(alert("a1", "r1", ["e1"])) + "\n", encoding="utf-8")
    (d / "e.ndjson").write_text(json.dumps(event("e1")) + "\n", encoding="utf-8")
    rev = d / "rev"
    run(lab.main, ["export", "--alerts", str(d / "a.ndjson"), "--events", str(d / "e.ndjson"),
                   "--out", str(rev)])
    lbl = d / "labels.jsonl"
    run(lab.main, ["label", "--jsonl", str(lbl), "--alert-id", "a1", "--verdict", "fp"])
    tracked = ROOT / "tools" / "_labeller_guard_probe"
    outside = Path(tempfile.mkdtemp())
    try:
        for bad in (tracked, outside / "x"):
            for argv in (["export", "--alerts", str(d / "a.ndjson"), "--events", str(d / "e.ndjson"), "--out", str(bad)],
                         ["label", "--jsonl", str(bad / "l.jsonl"), "--alert-id", "z", "--verdict", "fp"],
                         ["scrub", "--dir", str(rev), "--out", str(bad)],
                         ["publish", "--src", str(rev), "--dst", str(bad)]):
                rc, _, err = run(lab.main, argv)
                check(rc == 2 and "refusing to write" in err, f"{argv[0]} -> {bad}: rc={rc} err={err!r}")
                check(not bad.exists(), f"{argv[0]} created {bad}")
            rc, _, err = run(real_grade.main, ["--review-dir", str(rev), "--labels", str(lbl), "--out", str(bad)])
            check(rc == 2 and not bad.exists(), f"grade wrote to unignored {bad}: rc={rc}")
    finally:
        shutil.rmtree(outside, ignore_errors=True)
        shutil.rmtree(tracked, ignore_errors=True)


def test_lane_end_to_end_and_grade_cli():
    d = scratch()
    alerts = [alert(f"r1:10.0.0.{i}:1", "r1", [f"e{i}"]) for i in range(1, 4)]
    (d / "a.ndjson").write_text("".join(json.dumps(a) + "\n" for a in alerts), encoding="utf-8")
    (d / "e.ndjson").write_text("".join(json.dumps(event(f"e{i}", user="alice")) + "\n" for i in range(1, 4)),
                                encoding="utf-8")
    lbl = d / "labels.jsonl"
    rev, scr, pub, res = d / "rev", d / "scr", d / "pub", d / "res"
    steps = [["export", "--alerts", str(d / "a.ndjson"), "--events", str(d / "e.ndjson"), "--out", str(rev)]]
    for a, v in zip(alerts, ("tp", "fp", "fp")):
        steps.append(["label", "--jsonl", str(lbl), "--alert-id", a["alert_id"], "--verdict", v,
                      "--note", "alice 10.0.0.1"])
    steps += [["scrub", "--dir", str(rev), "--labels", str(lbl), "--out", str(scr)],
              ["publish", "--src", str(scr), "--dst", str(pub)]]
    for st in steps:
        rc, _, err = run(lab.main, st)
        check(rc == 0, f"lane step {st[0]} failed: {err!r}")
    rc, so, err = run(real_grade.main, ["--review-dir", str(pub), "--labels", str(pub / "labels.jsonl"),
                                        "--out", str(res)])
    check(rc == 0 and "n = tp+fp" in so and "LOW-N" in so, f"grade CLI: rc={rc} {err!r} {so!r}")
    check((res / "latest.json").exists(), "grade must write latest.json to the ignored dir")
    r1 = next(r for r in json.loads((res / "latest.json").read_text(encoding="utf-8"))["per_rule"] if r["rule_id"] == "r1")
    check(r1["n"] == 3 and r1["tp"] == 1 and r1["fp"] == 2, f"joined scrubbed labels wrong: {r1}")


def test_grade_precision_n_ci_orphans_dupes():
    labels = [
        {"alert_id": "a1", "verdict": "tp"},
        {"alert_id": "a2", "verdict": "fp"},
        {"alert_id": "a3", "verdict": "fp"},
        {"alert_id": "a4", "verdict": "unknown"},
        {"alert_id": "ghost", "verdict": "fp"},  # orphan
        {"alert_id": "b1", "verdict": "tp"},
        {"alert_id": "b1", "verdict": "fp"},     # duplicate: last wins
    ]
    review = {k: {"rule_id": "r1" if k[0] == "a" else "r2", "rule_title": "T"}
              for k in ("a1", "a2", "a3", "a4", "b1")}
    result = real_grade.grade(labels, review)
    check(result["marker"] == "single-site, owner-labelled", "marker missing")
    r1 = next(r for r in result["per_rule"] if r["rule_id"] == "r1")
    check(r1["precision"] == round(1 / 3, 4) and r1["n"] == 3 and r1["unknown"] == 1, f"r1 wrong: {r1}")
    lo, hi = r1["ci95"]
    check(lo is not None and 0 < lo < 1 / 3 < hi < 1, f"wilson interval wrong: {r1['ci95']}")
    check(r1["low_n"] is True, "n=3 must be flagged LOW-N")
    r2 = next(r for r in result["per_rule"] if r["rule_id"] == "r2")
    check(r2["fp"] == 1 and r2["tp"] == 0, f"duplicate must collapse last-wins: {r2}")
    check(all(r["rule_id"] != "(unmatched rule)" for r in result["per_rule"]), "orphans must not form a rule row")
    check(result["orphan_labels"] == 1 and result["duplicates_collapsed"] == 1, "orphan/dupe counts wrong")
    check(result["verdicts"] == {"tp": 1, "fp": 3, "unknown": 1}, f"verdicts wrong: {result['verdicts']}")
    one = real_grade.grade([{"alert_id": "x", "verdict": "tp"}], {"x": {"rule_id": "r"}})["per_rule"][0]
    check(one["precision"] == 1.0 and one["low_n"] and one["ci95"][0] < 0.5,
          f"1 label must not look like certainty: {one}")
    big = real_grade.grade([{"alert_id": str(i), "verdict": "tp"} for i in range(12)],
                           {str(i): {"rule_id": "r"} for i in range(12)})["per_rule"][0]
    check(big["low_n"] is False, "n=12 is not low-n")
    md = real_grade.render_markdown(result)
    check("single-site, owner-labelled" in md and "33.33%" in md and "LOW-N" in md, "markdown must show n/flag")


def test_grade_fails_loudly():
    d = scratch()
    rev = d / "grev"
    rev.mkdir()
    (rev / "alerts.jsonl").write_text(json.dumps({"alert_id": "a1", "rule_id": "r"}) + "\n", encoding="utf-8")
    rc, _, err = run(real_grade.main, ["--review-dir", str(rev), "--labels", str(d / "nope.jsonl"),
                                       "--out", str(d / "gres")])
    check(rc == 2 and "nope.jsonl" in err, f"missing labels file must exit 2: rc={rc} {err!r}")
    empty = d / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    rc, _, _ = run(real_grade.main, ["--review-dir", str(rev), "--labels", str(empty), "--out", str(d / "gres")])
    check(rc == 2, "no usable labels must exit 2")
    try:
        real_grade.load_labels(d / "nope.jsonl")
        check(False, "load_labels must raise on a missing file")
    except OSError:
        pass
    rc, _, _ = run(real_grade.main, ["--review-dir", str(d / "nodir"), "--labels", str(empty), "--out", str(d / "gres")])
    check(rc == 2, "missing review must exit 2")


def main() -> int:
    shutil.rmtree(SCRATCH, ignore_errors=True)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    tests = [test_export_join_and_omitted, test_write_review_header_and_readback,
             test_label_append_duplicate_and_verdicts,
             test_label_corrupt_line_refuses_and_preserves,
             test_scrub_recurses_all_leaves,
             test_pseudonyms_keyed_not_dictionary_reversible,
             test_ip_pseudonyms_consistent_and_collision_free,
             test_scrub_file_multiline_labels_and_note,
             test_publish_gate, test_output_paths_must_be_ignored,
             test_lane_end_to_end_and_grade_cli,
             test_grade_precision_n_ci_orphans_dupes, test_grade_fails_loudly]
    try:
        for t in tests:
            t()
    finally:
        shutil.rmtree(SCRATCH, ignore_errors=True)
    if FAILS:
        print(f"[FAIL] alert_labeller: {len(FAILS)} problem(s)")
        for f in FAILS[:30]:
            print("  -", f)
        return 1
    print(f"[OK] alert_labeller: {len(tests)} test groups - export+omitted, corrupt-label safety, "
          "recursive keyed scrub, publish re-scan gate, ignored-output guard, per-rule precision with n/CI")
    return 0


if __name__ == "__main__":
    sys.exit(main())
