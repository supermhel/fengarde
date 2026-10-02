"""Contract tests for tools/dns_cardinality_report.py (zero-infra, deterministic, no timing).

The tool replays a resolver query log through the window semantics of
contracts/rules/common_dns_tunnel_by_domain.yml and reports which parent domains would trip
it, so an operator can vet contracts/allowlists/dns_high_cardinality_parents.yml on real
traffic. All fixtures are generated in code.
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "services" / "ws2-normalization"))

import dns_cardinality_report as dcr  # noqa: E402
from parsers.dns_query import parent_domain  # noqa: E402

FAILS: list[str] = []
BASE = 1_790_000_000      # whole seconds, so every format (syslog is 1 s resolution) agrees
ALLOWLISTED = "akamaiedge.net"

Rec = tuple[int, str, str]    # (epoch seconds, qname, client)


def check(cond: object, msg: str) -> None:
    if not cond:
        FAILS.append(msg)


# --------------------------------------------------------------------------- fixtures

def cdn_like() -> list[Rec]:
    """60 distinct names under an UNLISTED parent in 30 s from 5 clients."""
    return [(BASE + i // 2, f"obj{i:03d}.edge.cdn-vendor.net", f"10.0.0.{1 + i % 5}") for i in range(60)]


def normal() -> list[Rec]:
    return [(BASE + 3 * i, f"host{i}.normal-site.org", "10.0.1.7") for i in range(10)]


def attacker() -> list[Rec]:
    """chunk000..chunk099 in 45 s from 2 clients."""
    return [(BASE + (i * 45) // 100, f"chunk{i:03d}.t.evil-zone.com", f"10.0.2.{1 + i % 2}") for i in range(100)]


def allowlisted() -> list[Rec]:
    return [(BASE + i // 3, f"e{i}.{ALLOWLISTED}", f"10.0.3.{1 + i % 4}") for i in range(60)]


def everything() -> list[Rec]:
    return sorted(cdn_like() + normal() + attacker() + allowlisted(), key=lambda r: (r[0], r[1]))


def _utc(ts: int) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def render(fmt: str, recs: list[Rec], *, timestamps: bool = True) -> str:
    lines: list[str] = []
    if fmt == "zeek":
        lines += ["#separator \\x09", "#set_separator\t,", "#path\tdns",
                  "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\tquery\tqtype_name",
                  "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tstring\tstring"]
        for ts, name, cl in recs:
            t = f"{ts}.000000" if timestamps else "-"
            lines.append(f"{t}\tC1\t{cl}\t5353\t10.0.0.53\t53\tudp\t1\t{name}\tA")
    elif fmt == "bind":
        for ts, name, cl in recs:
            prefix = _utc(ts).strftime("%d-%b-%Y %H:%M:%S.000 ") if timestamps else ""
            lines.append(f"{prefix}queries: info: client @0x7f1c {cl}#5353 ({name}): query: {name} IN A +")
    elif fmt == "dnsmasq":
        for ts, name, cl in recs:
            prefix = _utc(ts).strftime("%b %d %H:%M:%S ") if timestamps else ""
            lines.append(f"{prefix}host dnsmasq[123]: query[A] {name} from {cl}")
    elif fmt == "csv":
        lines.append("ts,client,qname" if timestamps else "client,qname")
        for ts, name, cl in recs:
            lines.append(f"{ts},{cl},{name}" if timestamps else f"{cl},{name}")
    elif fmt == "jsonl":
        for ts, name, cl in recs:
            obj = {"qname": name, "client": cl}
            if timestamps:
                obj["ts"] = ts
            lines.append(json.dumps(obj))
    else:
        raise AssertionError(fmt)
    return "\n".join(lines) + "\n"


def run(text: str, *extra: str) -> tuple[int, dict]:
    """Run the CLI on `text` via a temp file with --json; return (exit code, report)."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "dns.log"
        p.write_text(text, encoding="utf-8", newline="")
        out = io.StringIO()
        rc = dcr.main([str(p), "--json", *extra], stdout=out)
    return rc, (json.loads(out.getvalue()) if out.getvalue() else {})


def run_text(text: str, *extra: str) -> str:
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "dns.log"
        p.write_text(text, encoding="utf-8", newline="")
        out = io.StringIO()
        dcr.main([str(p), *extra], stdout=out)
    return out.getvalue()


def by_parent(rep: dict) -> dict:
    return {f["parent"]: f for f in rep["flagged"]}


# --------------------------------------------------------------------------- tests

def test_rule_params_come_from_rule_yaml() -> None:
    p = dcr.load_rule_params(dcr.DEFAULT_RULE)
    check(p["threshold"] == 40 and p["window_seconds"] == 60, f"rule params not read from the YAML: {p}")
    check(p["allowlist_name"] == "dns_high_cardinality_parents", f"allowlist name not read: {p}")
    al = dcr.load_allowlist_entries(dcr.ALLOWLISTS_DIR / "dns_high_cardinality_parents.yml")
    check(al is not None and ALLOWLISTED in al, "the real starter allowlist could not be loaded")


def test_reports_cdn_attacker_and_not_normal() -> None:
    rc, rep = run(render("zeek", everything()))
    check(rc == 0, f"exit code {rc}")
    flagged = by_parent(rep)
    check(rep["rule"] == {"threshold": 40, "window_seconds": 60}, f"rule: {rep['rule']}")
    cdn, evil = flagged.get("cdn-vendor.net"), flagged.get("evil-zone.com")
    check(cdn is not None, "CDN-like parent (60 names / 30 s / 5 clients) not reported")
    check(evil is not None, "attacker-style parent (100 names / 45 s / 2 clients) not reported")
    check("normal-site.org" not in flagged, "10-name parent was reported")
    if cdn:
        check(cdn["max_distinct_names_in_window"] == 60 and cdn["distinct_clients"] == 5
              and cdn["total_queries"] == 60, f"CDN row wrong: {cdn}")
        check(cdn["first_seen"] and cdn["last_seen"], "first/last seen missing")
    if evil:
        check(evil["max_distinct_names_in_window"] == 100 and evil["distinct_clients"] == 2,
              f"attacker row wrong: {evil}")
    # suggestions: both unlisted flagged parents, as COMMENTED yaml, never an active entry
    check(rep["suggested_allowlist_entries"] == ["cdn-vendor.net", "evil-zone.com"],
          f"suggestions: {rep['suggested_allowlist_entries']}")
    y = rep["suggested_yaml"]
    check('# - "cdn-vendor.net"' in y and '# - "evil-zone.com"' in y, "suggestion snippet missing an entry")
    check(all(ln.lstrip().startswith("#") for ln in y.splitlines() if ln.strip()),
          "suggestion yaml contains an un-commented (active) line")
    # the unlisted attacker parent must carry the warning, in JSON and in the text table
    check("tunnel" in rep["tunnel_warning"].lower() and "do not allowlist" in rep["tunnel_warning"].lower(),
          "tunnel warning missing")
    text = run_text(render("zeek", everything()))
    check("may be a DNS TUNNEL" in text and "REVIEW" in text, "text report lacks the review/tunnel warning")
    check("Allowlist admission test" in text and "authoritative" in text, "admission test not printed next to suggestions")
    check("never edits the allowlist" in text, "text report does not state the allowlist is never auto-written")


def test_allowlisted_parent_is_marked() -> None:
    _, rep = run(render("zeek", everything()))
    row = by_parent(rep).get(ALLOWLISTED)
    check(row is not None, "allowlisted parent above threshold should still be listed")
    if row:
        check(row["on_allowlist"] is True, "allowlisted parent not marked on_allowlist")
    check(ALLOWLISTED not in rep["suggested_allowlist_entries"], "an already-listed parent was suggested again")
    check("ALREADY ON ALLOWLIST" in run_text(render("zeek", everything())), "text status missing")
    # negative control: a parent not on the list is NOT marked
    check(by_parent(rep)["cdn-vendor.net"]["on_allowlist"] is False, "unlisted parent marked as allowlisted")
    # an explicit allowlist override is honoured
    with tempfile.TemporaryDirectory() as td:
        alp = Path(td) / "al.yml"
        alp.write_text('entries:\n  - "cdn-vendor.net"\n', encoding="utf-8")
        _, rep2 = run(render("zeek", everything()), "--allowlist", str(alp))
    f2 = by_parent(rep2)
    check(f2["cdn-vendor.net"]["on_allowlist"] and not f2[ALLOWLISTED]["on_allowlist"], "--allowlist override ignored")


def test_deny_list_parents_never_suggested() -> None:
    recs = [(BASE + i // 3, f"c{i:03d}.victim.duckdns.org", "10.0.4.1") for i in range(60)]
    _, rep = run(render("zeek", recs))
    row = by_parent(rep).get("duckdns.org")
    check(row is not None and row["deny_list"] and row["deny_list"]["tier"] == "never", f"deny-list row: {row}")
    check("duckdns.org" not in rep["suggested_allowlist_entries"], "a dynamic-DNS zone was suggested for allowlisting")
    check(any("dynamic-DNS" in w for w in rep["warnings"]), "no dynamic-DNS warning")
    # cloudfront.net is deliberately not on the deny list (it passes the admission test)
    check("cloudfront.net" not in dcr.DENY_LIST, "cloudfront.net must not be on the deny list")


def test_window_semantics() -> None:
    # 39 names -> below threshold; 40 -> at threshold (>=), exactly like the rule
    for n, expect in ((39, False), (40, True)):
        recs = [(BASE, f"n{i}.edge-check.net", "10.0.5.1") for i in range(n)]
        _, rep = run(render("zeek", recs))
        check(("edge-check.net" in by_parent(rep)) is expect, f"{n} names in one window: flagged={not expect}")
    # 60 distinct names spread over 600 s (one per 10 s) never exceed 6 in any 60 s window: negative control
    spread = [(BASE + 10 * i, f"s{i}.slow-spread.net", "10.0.5.2") for i in range(60)]
    _, rep = run(render("zeek", spread))
    check("slow-spread.net" not in by_parent(rep), "names spread over 10 minutes were flagged (window not applied)")
    top = {b["parent"]: b for b in rep["highest_below_threshold"]}
    check(top.get("slow-spread.net", {}).get("max_distinct_names_in_window") == 7,
          f"max distinct in a sliding 60 s window should be 7 (ts >= newest-60): {top}")
    # repeated queries for the SAME name do not inflate the distinct count
    repeat = [(BASE + i // 10, "same.repeat-name.net", "10.0.5.3") for i in range(500)]
    _, rep = run(render("zeek", repeat))
    check("repeat-name.net" not in by_parent(rep), "500 queries for one name were counted as 500 distinct names")
    # --threshold / --window overrides
    _, rep = run(render("zeek", normal()), "--threshold", "5")
    check("normal-site.org" in by_parent(rep), "--threshold override ignored")
    _, rep = run(render("zeek", spread), "--window", "600")
    check("slow-spread.net" in by_parent(rep), "--window override ignored")


def test_format_parity() -> None:
    recs = everything()
    results = {}
    for fmt in ("zeek", "bind", "dnsmasq", "csv", "jsonl"):
        for forced in ("auto", fmt):
            rc, rep = run(render(fmt, recs), "--format", forced)
            check(rc == 0, f"{fmt} (--format {forced}) exit {rc}")
            check(rep["input"]["format"] == fmt, f"{fmt} detected as {rep['input']['format']} (--format {forced})")
            check(rep["input"]["malformed"] == 0, f"{fmt}: malformed lines on clean data: {rep['input']}")
            check(rep["timestamps"]["single_window"] is False, f"{fmt}: wrongly reported as single window")
        results[fmt] = rep

    def key(rep: dict, with_times: bool) -> list:
        rows = []
        for f in rep["flagged"]:
            row = [f["parent"], f["max_distinct_names_in_window"], f["total_queries"], f["distinct_names"],
                   f["distinct_clients"], f["on_allowlist"]]
            if with_times:
                row += [f["first_seen"], f["last_seen"]]
            rows.append(row)
        return rows

    ref = key(results["zeek"], True)
    check(len(ref) == 3, f"reference run should flag 3 parents, got {ref}")
    for fmt in ("bind", "csv", "jsonl"):
        check(key(results[fmt], True) == ref, f"{fmt} result differs from zeek on identical data")
    # dnsmasq syslog stamps carry no year, so absolute first/last seen legitimately differ
    check(key(results["dnsmasq"], False) == key(results["zeek"], False), "dnsmasq result differs from zeek")
    check(results["bind"]["suggested_allowlist_entries"] == results["zeek"]["suggested_allowlist_entries"],
          "suggestions differ across formats")


def test_no_timestamps_is_loud() -> None:
    recs = [(0, f"slow{i}.untimed-zone.net", "10.0.6.1") for i in range(60)]
    for fmt in ("zeek", "bind", "dnsmasq", "csv", "jsonl"):
        rc, rep = run(render(fmt, recs, timestamps=False))
        check(rc == 0, f"{fmt} no-timestamp run exit {rc}")
        check(rep["timestamps"]["single_window"] is True, f"{fmt}: no-timestamp file not flagged as single window")
        check(any("NO TIMESTAMPS" in w and "ONE" in w for w in rep["warnings"]), f"{fmt}: loud warning missing")
        check("untimed-zone.net" in by_parent(rep), f"{fmt}: single-window upper bound should still list the parent")
        text = run_text(render(fmt, recs, timestamps=False))
        check("NO TIMESTAMPS" in text and "ONE window" in text and text.count("!!") >= 1, f"{fmt}: text banner missing")
    # negative control: a timestamped file carries no such warning
    _, rep = run(render("zeek", cdn_like()))
    check(not any("NO TIMESTAMPS" in w for w in rep["warnings"]), "timestamped file got the single-window warning")
    check("NO TIMESTAMPS" not in run_text(render("zeek", cdn_like())), "timestamped text report got the banner")


def test_malformed_lines_counted_not_fatal() -> None:
    zeek = render("zeek", cdn_like()).splitlines()
    zeek.insert(6, "this line is garbage")
    zeek.insert(9, "1790000000.000000\tonly\ttwo-cols")
    zeek.insert(12, "notatime\tC1\t10.0.0.1\t1\t10.0.0.53\t53\tudp\t1\tbad.cdn-vendor.net\tA")
    rc, rep = run("\n".join(zeek) + "\n")
    check(rc == 0, f"malformed zeek lines were fatal (exit {rc})")
    check(rep["input"]["malformed"] == 3, f"malformed count: {rep['input']['malformed']}")
    check("cdn-vendor.net" in by_parent(rep), "good lines were lost around malformed ones")
    check(any("malformed" in w for w in rep["warnings"]), "no malformed-line warning")
    for fmt, junk in (("bind", "garbage not a query line"), ("csv", "justonefield"), ("jsonl", "{not json")):
        lines = render(fmt, cdn_like()).splitlines()
        lines.insert(5, junk)
        rc, rep = run("\n".join(lines) + "\n")
        check(rc == 0 and rep["input"]["malformed"] == 1, f"{fmt}: malformed handling rc={rc} {rep.get('input')}")
        check("cdn-vendor.net" in by_parent(rep), f"{fmt}: good lines lost")
    # negative control: clean data has zero malformed lines
    _, rep = run(render("zeek", cdn_like()))
    check(rep["input"]["malformed"] == 0, "clean data counted malformed lines")
    # an unrecognisable file is a usage error (exit 2), not a crash or a silent empty report
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "x.log"
        p.write_text("hello world\nnot dns\n", encoding="utf-8")
        check(dcr.main([str(p)], stdout=io.StringIO()) == 2, "unrecognisable format should exit 2")


def test_same_parent_as_ws2_parser() -> None:
    # the tool must group exactly as the ws2 parser does (imported, not reimplemented)
    check(dcr.parent_domain is parent_domain, "tool does not use parsers.dns_query.parent_domain")
    recs = [(BASE, f"a{i}.shop.example.co.uk", "10.0.7.1") for i in range(45)]
    _, rep = run(render("zeek", recs))
    check("example.co.uk" in by_parent(rep), f"two-label public suffix not honoured: {list(by_parent(rep))}")


def test_stdin_and_memory_bound() -> None:
    out = io.StringIO()
    rc = dcr.main(["-", "--json"], stdin=io.StringIO(render("jsonl", cdn_like())), stdout=out)
    check(rc == 0 and "cdn-vendor.net" in by_parent(json.loads(out.getvalue())), "stdin ('-') input failed")
    # one hour of steady traffic: the retained window must stay bounded by the window, not the file
    n = 7200
    recs = [(BASE + i // 2, f"q{i}.big-zone.net", "10.0.8.1") for i in range(n)]
    an = dcr.Analyzer(60, sweep_every=500)
    for ts, name, cl in recs:
        an.add(float(ts), name, cl)
    check(an.max_window_entries <= 125, f"window not bounded: {an.max_window_entries} entries retained of {n}")
    # a parent that went quiet is swept once the clock moves on
    an2 = dcr.Analyzer(60, sweep_every=10)
    for i in range(50):
        an2.add(float(BASE), f"x{i}.old-zone.net", "10.0.8.2")
    for i in range(100):
        an2.add(float(BASE + 600 + i), f"y{i}.new-zone.net", "10.0.8.3")
    check(an2.live_windows == 1, f"expired parent window not freed: {an2.live_windows}")
    check(an2.parents["old-zone.net"].max_distinct == 50, "sweeping lost the recorded peak")
    # late (badly out-of-order) records are excluded and reported, never silently mixed in
    an3 = dcr.Analyzer(60)
    an3.add(float(BASE + 1000), "a.zone-late.net", "c")
    an3.add(float(BASE), "b.zone-late.net", "c")
    check(an3.late == 1, f"late record not reported: {an3.late}")


def test_cli_never_writes_allowlist() -> None:
    al = dcr.ALLOWLISTS_DIR / "dns_high_cardinality_parents.yml"
    before = al.read_bytes()
    run(render("zeek", everything()))
    check(al.read_bytes() == before, "the tool modified the allowlist")


def test_allowlist_header_documents_the_tool() -> None:
    head = (dcr.ALLOWLISTS_DIR / "dns_high_cardinality_parents.yml").read_text(encoding="utf-8").split("entries:")[0]
    check("UNVERIFIED" in head, "allowlist header does not say UNVERIFIED")
    check("tools/dns_cardinality_report.py" in head, "allowlist header does not name the measuring tool")
    rule = dcr.DEFAULT_RULE.read_text(encoding="utf-8")
    check("tools/dns_cardinality_report.py" in rule, "rule description does not mention the measuring tool")


def main() -> None:
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    if FAILS:
        print(f"[FAIL] dns_cardinality_report: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] dns_cardinality_report")


if __name__ == "__main__":
    main()
