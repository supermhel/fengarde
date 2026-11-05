# Labelling tool and the real-data lane (WP-2.2)

The owner labels alerts from their own network once and gets per-rule
precision — instead of the synthetic-benchmark recall/precision on the
scorecard. Nothing from a private network is ever committed; everything that
may contain live traffic lives in git-ignored directories.

## The lane

```
1. dump          alerts.ndjson (make_alert shape, e.g. OpenSearch alerts-*
                 scroll) + events.ndjson (normalized.events docs)
2. export        python tools/alert_labeller.py export \
                   --alerts alerts.ndjson --events events.ndjson \
                   --out eval/real/review/
3. review+label  look at the exported records (each carries the alert facts
                 + contributing_events joined from the event dump), then
                 python tools/alert_labeller.py label \
                   --jsonl eval/real/labels.jsonl \
                   --alert-id <id> --verdict fp --note "office port scan"
4. scrub         python tools/alert_labeller.py scrub \
                   --dir eval/real/review/ ... also scrub labels.jsonl \
                   --out eval/real/out/scrubbed/
5. publish       python tools/alert_labeller.py publish \
                   --src eval/real/out/scrubbed/ --dst eval/real/out/published/
                 (REFUSES any file without the scrub stamp)
6. grade         python eval/real/grade.py \
                   --review-dir eval/real/out/scrubbed/ \
                   --labels eval/real/out/scrubbed/labels.jsonl \
                   --out eval/real/out/
```

The result (`latest.json` / `latest.md`) is explicitly marked
**"single-site, owner-labelled"** — it is deliberately NOT comparable with
the synthetic benchmarks and is never merged into `SCORECARD.md`.

## Export semantics

- contributing events = the alert's `event_ids` that exist in the event dump,
  joined by `siem.ingest_id`, in the alert's own order (the triggering event
  first when `trigger_event_id` is present);
- unknown ids are listed under `missing_event_ids` with the original
  `event_ids_total` — a truncated list is shown, never silently dropped;
- malformed lines in either dump are counted and skipped (same contract as
  the parsers).

## Labels

`labels.jsonl` records one object per line:

```json
{"alert_id": "…", "verdict": "fp", "note": "…"}
```

Verdicts: `tp` | `fp` | `unknown`. A duplicate `alert_id` is refused unless
`--override` is passed. `unknown` is reported separately by the grader and
NEVER folded into the precision denominator (an unlabelled alert is not a
false positive).

## Scrubbing (the publish gate)

`scrub` rewrites deterministically (same seed → same output; different seed
→ different pseudonyms):

- IPs → `10.0.0.0/8` pseudonyms from the seed;
- hostnames/domains → `host-<hash8>`;
- usernames (regex-visible `user=…` forms AND bare values under
  name/domain/uid keys) → `user-<hash8>`;
- every output carries `"scrubbed": true` + the scrub digest.

`publish` copies ONLY stamped files; any unstamped file aborts the whole
publish with an explicit refusal — the lane cannot leak an unscrubbed leak.

## Grading

Per rule: `precision = tp / (tp + fp)` (None when nothing labelled), tp/fp/
unknown counts, plus the verdict distribution and the number of orphan
labels (verdicts whose alert_id is not in the review export — surfaced, not
dropped).

## Git hygiene

`.gitignore` covers `eval/real/review/`, `eval/real/labels.jsonl`,
`eval/real/out/`, `eval/real/latest.{json,md}`. The committed code
(`tools/alert_labeller.py`, `eval/real/grade.py`) is fully synthetic-testable:
`python tools/test_alert_labeller.py` (wired into the fast tier) exercises
the export join, label semantics, deterministic scrubbing and the publish
refusal on code-generated fixtures.

## Workflow note

Steps 1–3 run against a LIVE stack the owner operates (the same dumps the
WP-2.3 report takes). Step 4+ can run anywhere — the scrub makes the
artifacts shareable, which is the only way a labelled file ever leaves the
box.