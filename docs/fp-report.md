# Alert false-positive tuning report (WP-2.3)

`tools/alert_fp_report.py` replays ALERT documents — the exact `make_alert`
shape WS-4 produces on the `alerts` topic (`services/ws4-detection/main.py`) —
from a JSONL dump and prints:

1. **alerts per rule per day (UTC)** — how loud every rule is;
2. **per-rule totals** over the window;
3. **top noisy sources** (alerts by `src_endpoint.ip`) — the individual hosts
   that would drown a threshold if you tuned the rule from the aggregate.

Purpose: tune `contracts/rules/*.yml` thresholds against REAL traffic instead
of synthetic bursts. Zero infrastructure — the input is a plain dump
(e.g. an OpenSearch `alerts-*` scroll, one document per line, or a `bus`
replay of the `alerts` topic). The tool never mutates anything.

## Produce the input

```bash
# OpenSearch scroll -> NDJSON (search_after until empty):
#   GET alerts-*/_search {"query":{"match_all":{}},"sort":[{"time":"asc"},{"_id":"asc"}],"size":1000}
# then append each hit._source on its own line to alerts.ndjson.

# Or replay the bus topic (redis-cli, verbose output):
#   docker exec siem-bus redis-cli xrange alerts - + | \
#     awk '/^payload$/{getline; print}' > alerts.ndjson
# (for the actual storage doc incl. ws3-indexer envelope fields, prefer the
#  OpenSearch export — the aggregates only read rule_id/time/src_endpoint.*)
```

## Run

```bash
python tools/alert_fp_report.py --jsonl alerts.ndjson
python tools/alert_fp_report.py --jsonl alerts.ndjson --since 2026-10-01 --until 2026-10-07
python tools/alert_fp_report.py --jsonl alerts.ndjson --rule common_bruteforce --json
python tools/alert_fp_report.py --jsonl alerts.ndjson --out eval/real/out/fp-report.md
```

**Never commit live output.** A report built from real traffic contains raw
source IPs; write it under the git-ignored `eval/real/out/` (never `docs/` and
never `| tee docs/fp-report.md`). The sample below is the only committed report
and is SYNTHETIC.

`--since`/`--until` (inclusive, strict zero-padded `YYYY-MM-DD`, UTC day;
anything else, a bad calendar date, or since > until exits 2), `--rule` (filter before
aggregation), `--top N` (default 10), `--json` (machine-readable aggregates),
`-` reads stdin. Days are UTC calendar days of `time` (epoch ms), so an alert
at 23:59:59.999Z and one at 00:00:00.000Z fall on different days. `--json`
emits `per_day` as `{rule_id: {day: n}}`. Malformed lines are counted and
skipped. Without a window, alerts with no usable `time` are surfaced as
"undated" (still counted in rule totals and sources — never dropped); with
`--since`/`--until` they cannot be placed in the window, so they are excluded
from every table and counted in "excluded by the day window (of which
undated)". Alerts repeating an `alert_id` (the bus replay is at-least-once)
are counted once and reported as "duplicate alert_id dropped"; alerts with no
`alert_id` cannot be deduped and are flagged; alerts without a source IP land in a "(no source)"
bucket. Output ordering is deterministic (rules/days sorted; sources by
count desc, ip asc) so report diffs are stable for tuning.

## Sample output

SYNTHETIC sample (seeded generator, 60 dated alerts + 1 undated over two
days, two deliberately noisy hosts `10.0.0.9`/`10.0.0.41`) — the shape is
what a real dump produces; the numbers are not from a real network:

```markdown
# Alert FP-tuning report — window: all time

- total alerts read: 61
- undated (no usable time, counted in rule totals): 1
- sources without an ip: 0
- excluded by the day window: 0 (of which undated: 0)
- duplicate alert_id dropped (bus redelivery): 0
- alerts without an alert_id (cannot be deduped): 0

## Alerts per rule per day (UTC)

| rule_id | day | alerts |
|---|---|---|
| common_bruteforce | 2026-10-01 | 6 |
| common_bruteforce | 2026-10-02 | 6 |
| common_impossible_travel | 2026-10-01 | 6 |
| common_impossible_travel | 2026-10-02 | 6 |
| common_dns_tunnel_by_domain | 2026-10-01 | 6 |
| ... (every rule, both days) ... |

## Per-rule totals

| rule_id | title | alerts |
|---|---|---|
| common_bruteforce | SSH brute force | 13 |
| common_impossible_travel | Impossible travel | 12 |
| m365_inbox_rule_external_forward | M365 external forward rule | 12 |
| common_dns_tunnel_by_domain | DNS tunnel by parent domain | 12 |
| email_macro_attachment_delivered | Email macro attachment | 12 |

## Top 8 noisy sources (alerts by src_endpoint.ip)

| src_endpoint.ip | alerts |
|---|---|
| 10.0.0.9 | 11 |
| 10.0.0.41 | 10 |
| 10.1.0.114 | 1 |
| 10.1.0.144 | 1 |
```

Reading it: `common_bruteforce` is the loudest rule and `10.0.0.9` alone
accounts for a fifth of the corpus — before raising the per-source window
threshold, check whether `10.0.0.9` is a real scanner (triage statuses, the
contributing events in the alert's `event_ids`). That decision is the owner's;
the report only exposes the numbers.

## Contract

`tools/test_alert_fp_report.py` (wired into the fast tier) covers: day
bucketing (epoch ms and raw seconds), malformed-line tolerance, per-rule
per-day counts, source ranking with deterministic tie-breaks, window bounds,
undated/no-source honesty (incl. exclusion under a window), `alert_id`
dedupe, the UTC day boundary, `--rule`, `--json`, strict `--since`/`--until`
validation (exit 2), and the CLI round-trip including the exit-2 path on a
missing input.