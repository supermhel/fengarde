#!/usr/bin/env python3
"""Alert false-positive tuning report — WP-2.3.

Replays ALERT documents (the exact ``make_alert`` shape WS-4 produces on
``alerts`` — see services/ws4-detection/main.py) from a JSONL dump and prints:

  1. alerts per rule per day (UTC) — the "how loud is every rule" table;
  2. per-rule totals over the window;
  3. top noisy sources (alerts by ``src_endpoint.ip``) — the operators that
     would drown a threshold if you tuned it from the aggregate.

Purpose: tune thresholds (contracts/rules/*.yml) from REAL traffic instead of
synthetic bursts. Zero infrastructure — the input is a plain dump, e.g. a
scroll of the ``alerts`` topic or an OpenSearch ``alerts-*`` export (one
document per line). The report never mutates anything.

Contract behaviour (tested in tools/test_alert_fp_report.py, zero-infra):
- malformed lines are counted and skipped, never fatal (mirrors ws1/ws2);
- alerts with no usable ``time`` are aggregated into "undated" and never
  dropped silently;
- alerts whose ``src_endpoint.ip`` is absent land in a "no source" bucket;
- output ordering is deterministic: rules and days sorted, sources by
  (count desc, ip asc) — stable report diffs for threshold tuning.

Run:
    python tools/alert_fp_report.py --jsonl alerts.ndjson
    python tools/alert_fp_report.py --jsonl alerts.ndjson --since 2026-10-01 --rule common_bruteforce
    ... | tee docs/fp-report.md
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional


def day_of(epoch_ms: Any) -> Optional[str]:
    """UTC calendar day of an alert's ``time`` (epoch MILLISECONDS), or None."""
    if isinstance(epoch_ms, bool):
        return None
    try:
        ms = int(epoch_ms)
        if ms <= 0:
            return None
    except (TypeError, ValueError, OverflowError):
        return None
    # A raw epoch-SECONDS timestamp (someone's hand-cut dump) is >10^12 too
    # small to be ms — accept it rather than silently bucketing wrong: the
    # day boundary for 32-bit seconds values dated before 2001 is a rounding
    # artifact nobody tunes thresholds against.
    if ms < 100_000_000_000:  # < 1973 in seconds
        ms *= 1000
    try:
        dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return dt.strftime("%Y-%m-%d")


def parse_alerts(lines: list[str]) -> tuple[list[dict], int]:
    """One dict per JSONL line (or one JSON ARRAY document); malformed counted.

    A line that is neither an object nor a line inside an array document is
    skipped and counted — the report must survive a poisoned dump line, the
    same contract ws1's HTTP ingest keeps for malformed NDJSON records.
    """
    alerts: list[dict] = []
    malformed = 0
    for line in lines:
        text = line.strip()
        if not text:
            continue
        if text.startswith("["):  # a whole JSON array as one document
            try:
                arr = json.loads(text)
            except (ValueError, TypeError):
                malformed += 1
                continue
            if not isinstance(arr, list):
                malformed += 1
                continue
            for item in arr:
                if isinstance(item, dict):
                    alerts.append(item)
                else:
                    malformed += 1
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            malformed += 1
            continue
        if isinstance(obj, dict):
            alerts.append(obj)
        else:
            malformed += 1
    return alerts, malformed


def source_ip(alert: dict) -> str:
    """src_endpoint.ip of an alert, or the honest "no source" bucket key."""
    se = alert.get("src_endpoint")
    ip = se.get("ip") if isinstance(se, dict) else None
    if isinstance(ip, str) and ip:
        return ip
    return "(no source)"


def aggregate(alerts: list[dict],
              rule_filter: Optional[str] = None,
              since: Optional[str] = None,
              until: Optional[str] = None) -> dict:
    """Counts only — no output formatting (the testable core).

    ``since``/``until`` are inclusive ``YYYY-MM-DD`` day bounds applied to the
    UTC alert day; alerts outside are not counted anywhere (and are reported
    as ``excluded_by_window`` so an operator sees the filter took effect).
    An alert with NO usable time cannot be windowed: it counts toward the
    rule total and the noisy-sources table (it IS real noise) and is surfaced
    in ``undated`` — never dropped. An alert without a rule_id still counts
    toward noisy sources; there is no honest per-rule bucket for it.
    """
    per_day: Counter = Counter()            # (rule_id, day) -> count
    per_rule: Counter = Counter()           # rule_id -> count
    per_source: Counter = Counter()         # src ip -> count
    undated = 0
    no_source = 0
    excluded = 0
    titles: dict[str, str] = {}
    for alert in alerts:
        rid = alert.get("rule_id")
        rid = rid if isinstance(rid, str) and rid else None
        d = day_of(alert.get("time"))
        if d is None:
            undated += 1
            if rid:
                per_rule[rid] += 1
                if isinstance(alert.get("rule_title"), str):
                    titles[rid] = alert["rule_title"]
        else:
            if since and d < since:
                excluded += 1
                continue
            if until and d > until:
                excluded += 1
                continue
            if rid:
                per_day[(rid, d)] += 1
                per_rule[rid] += 1
                if isinstance(alert.get("rule_title"), str):
                    titles[rid] = alert["rule_title"]
        ip = source_ip(alert)
        if ip == "(no source)":
            no_source += 1
        else:
            per_source[ip] += 1
    return {
        "per_day": dict(per_day),
        "per_rule": dict(per_rule),
        "per_source": dict(per_source),
        "titles": titles,
        "undated": undated,
        "no_source": no_source,
        "excluded_by_window": excluded,
        "total": len(alerts),
    }


def render_markdown(agg: dict, top_n: int,
                    since: Optional[str], until: Optional[str]) -> str:
    """Deterministic markdown: rules/days sorted, sources (count desc, ip asc)."""
    out: list[str] = []
    window = "all time"
    if since and until and since == until:
        window = since
    elif since or until:
        window = f"{since or '…'} .. {until or '…'}"
    out.append(f"# Alert FP-tuning report — window: {window}")
    out.append("")
    out.append(f"- total alerts read: {agg['total']}")
    out.append(f"- undated (no usable time, counted in rule totals): {agg['undated']}")
    out.append(f"- sources without an ip: {agg['no_source']}")
    out.append(f"- excluded by the day window: {agg['excluded_by_window']}")
    out.append("")
    per_day = agg["per_day"]
    if per_day:
        out.append("## Alerts per rule per day (UTC)")
        out.append("")
        out.append("| rule_id | day | alerts |")
        out.append("|---|---|---|")
        for (rid, day), n in sorted(per_day.items(), key=lambda kv: (kv[0][0], kv[0][1])):
            out.append(f"| {rid} | {day} | {n} |")
        out.append("")
    per_rule = agg["per_rule"]
    if per_rule:
        out.append("## Per-rule totals")
        out.append("")
        out.append("| rule_id | title | alerts |")
        out.append("|---|---|---|")
        for rid in sorted(per_rule):
            out.append(f"| {rid} | {agg['titles'].get(rid, '')} | {per_rule[rid]} |")
        out.append("")
    per_source = agg["per_source"]
    if per_source:
        out.append(f"## Top {top_n} noisy sources (alerts by src_endpoint.ip)")
        out.append("")
        out.append("| src_endpoint.ip | alerts |")
        out.append("|---|---|")
        ranked = sorted(per_source.items(), key=lambda kv: (-kv[1], kv[0]))
        for ip, n in ranked[:top_n]:
            out.append(f"| {ip} | {n} |")
        out.append("")
    if not per_day and not per_rule and not per_source:
        out.append("_No counted alerts in the window._")
        out.append("")
    return "\n".join(out)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--jsonl", required=True,
                    help="alert JSONL file, or - for stdin (make_alert shape)")
    ap.add_argument("--since", help="inclusive lower day bound YYYY-MM-DD (UTC)")
    ap.add_argument("--until", help="inclusive upper day bound YYYY-MM-DD (UTC)")
    ap.add_argument("--rule", help="only this rule_id (filters before aggregation)")
    ap.add_argument("--top", type=int, default=10, help="top-N noisy sources (default 10)")
    ap.add_argument("--json", action="store_true", help="emit the aggregates as JSON")
    ap.add_argument("--out", help="write the report to a file instead of stdout")
    args = ap.parse_args(argv)

    if args.jsonl == "-":
        lines = sys.stdin.read().splitlines()
    else:
        try:
            with open(args.jsonl, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except OSError as exc:
            print(f"error: cannot read {args.jsonl}: {exc}", file=sys.stderr)
            return 2

    alerts, malformed = parse_alerts(lines)
    filtered = [a for a in alerts
                if not args.rule or a.get("rule_id") == args.rule]
    agg = aggregate(filtered, since=args.since, until=args.until)
    agg["malformed_lines"] = malformed

    if args.json:
        payload = json.dumps(agg, indent=2, sort_keys=True)
    else:
        payload = render_markdown(agg, args.top, args.since, args.until)
        if malformed:
            payload += f"\n_({malformed} malformed line(s) skipped)_\n"

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(payload)
        except OSError as exc:
            print(f"error: cannot write {args.out}: {exc}", file=sys.stderr)
            return 2
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())