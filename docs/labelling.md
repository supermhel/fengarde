# Labelling tool and the real-data lane (WP-2.2)

The owner labels alerts from their own network once and gets per-rule
precision — instead of the synthetic-benchmark recall/precision on the
scorecard. Nothing from a private network is ever committed; everything that
may contain live traffic lives in git-ignored directories.

## The lane

All default paths below are under the git-ignored `eval/real/` area.

```
1. dump          alerts.ndjson (make_alert shape, e.g. OpenSearch alerts-*
                 scroll) + events.ndjson (normalized.events docs)
2. export        python tools/alert_labeller.py export \
                   --alerts alerts.ndjson --events events.ndjson
                 (-> eval/real/review/alerts.jsonl)
3. review+label  look at the exported records (each carries the alert facts
                 + contributing_events joined from the event dump), then
                 python tools/alert_labeller.py label \
                   --alert-id <id> --verdict fp --note "office port scan"
                 (-> eval/real/labels.jsonl)
4. scrub         python tools/alert_labeller.py scrub \
                   --dir eval/real/review/ --labels eval/real/labels.jsonl
                 (-> eval/real/out/scrubbed/)
5. publish       python tools/alert_labeller.py publish
                 (eval/real/out/scrubbed/ -> eval/real/out/published/;
                  re-scans every line and REFUSES on any unstamped, tampered
                  or private-looking record)
6. grade         python eval/real/grade.py \
                   --review-dir eval/real/out/published/ \
                   --labels eval/real/out/published/labels.jsonl
                 (-> eval/real/out/latest.{json,md})
```

The result (`latest.json` / `latest.md`) is explicitly marked
**"single-site, owner-labelled"** — it is deliberately NOT comparable with
the synthetic benchmarks and is never merged into `SCORECARD.md`.

## Output paths are guarded

Every command that writes (`export --out`, `label --jsonl`, `scrub --out`,
`publish --dst`, `grade --out`) first asks `git check-ignore` and **refuses
(exit 2, nothing written)** any target the repo's `.gitignore` does not cover —
a tracked location, a path outside the repo, or a machine without `git`. Live
data cannot be written to a tracked path by accident.

## Export semantics

- contributing events = the alert's `event_ids` that exist in the event dump,
  joined by `siem.ingest_id`, in the alert's own order (the triggering event
  first when `trigger_event_id` is present);
- unknown ids are listed under `missing_event_ids`;
- `make_alert` caps `event_ids` and records the cut as `event_ids_omitted`.
  Export carries it into the record, `event_ids_total` = listed + omitted,
  and the export command prints a `TRUNCATED:` line. A capped alert never
  looks like a complete review;
- malformed lines in either dump are counted and skipped (same contract as
  the parsers).

## Labels

`labels.jsonl` records one object per line:

```json
{"alert_id": "…", "verdict": "fp", "note": "…"}
```

Verdicts: `tp` | `fp` | `unknown`. A duplicate `alert_id` is refused unless
`--override` is passed. A **malformed line makes `label` exit 2 without
writing**: the file is never rewritten from a partial read, so a corrupt line
cannot wipe your labels or bypass the duplicate guard (fix or remove the line
by hand). Writes go through a temp file and `os.replace`.

`unknown` is reported separately by the grader and NEVER folded into the
precision denominator.

## Scrubbing (the publish gate)

`scrub` reads every `.jsonl` file line by line (a malformed line aborts; other
files in the directory are skipped and counted) and, in ONE run with ONE
mapping:

- recurses into **every** string leaf and key, including all of
  `contributing_events`; nothing is assumed public. Only the rule facts
  (`rule_id`, `rule_title`, `level`, `score`, `time`, counts, `verdict`) stay
  readable;
- IPv4/IPv6 → collision-free pseudonyms (IPv4 in `198.18.0.0/15`, one map per
  run, never two real IPs on one pseudonym);
- hostnames/domains, emails, usernames (regex-visible `user=…` forms AND bare
  values under `name`/`user`/`hostname`/`domain`/… keys) → `host-<h>` /
  `user-<h>`; every value found under such a key is also replaced wherever it
  occurs inside free text (`message`, etc.) of every file in the run. Scrubbing
  is deliberately aggressive (e.g. `process.name` is also hashed): the scrubbed
  copy exists for rule-level grading, not forensics;
- `alert_id` → `alert-<h>` (make_alert ids are `rule:group:bucket`, so they
  embed the source IP/user). Review and labels must therefore be scrubbed in
  the **same run** (`--labels`) so their ids line up;
- the label `note` and the export header's source file names are dropped;
- every output line carries `"scrubbed": true` + a digest.

Pseudonyms are HMAC-SHA256 under a secret that is **never written to the
output** (unsalted hashes of short names are dictionary-reversible). By
default the secret is random per run, so pseudonyms differ between runs and
are not linkable across them. Pass `--secret-file` to get stable pseudonyms
across runs; whoever holds that file can confirm guesses, so keep it private
and outside the repo.

`publish` does **not** trust the stamp (it is self-declared and the digest is
an integrity check, not authenticity). It validates every line of every file
first (stamp + digest + an independent re-scan for IPs, hostnames, emails,
`user=` forms and un-pseudonymised name fields), reports where and what kind
of hit — never the value — and copies nothing unless everything passes.

## Grading

Per rule: `n = tp + fp`, `precision = tp / n` (None when n = 0), a 95% Wilson
interval, and a `LOW-N` flag when n < 10 (one label is not "100%"). Labels are
deduplicated by `alert_id` (last wins). Orphan labels (alert_id not in the
review) are counted and **excluded** from every rule row and the verdict
distribution. `grade.py` exits 2 on a missing/empty labels file or an empty
review instead of printing an empty table.

## Git hygiene

`.gitignore` covers `eval/real/review/`, `eval/real/labels.jsonl`,
`eval/real/out/`, `eval/real/latest.{json,md}`. The committed code
(`tools/alert_labeller.py`, `eval/real/grade.py`) is fully synthetic-testable:
`python tools/test_alert_labeller.py` (wired into the fast tier) exercises the
export join, label safety, scrubbing, the publish gate, the output-path guard
and grading on code-generated fixtures.

## Workflow note

Steps 1–3 run against a LIVE stack the owner operates (the same dumps the
WP-2.3 report takes). Step 4+ can run anywhere — the scrub makes the
artifacts shareable, which is the only way a labelled file ever leaves the
box. Known limit: the scrub is pattern- and key-based, so free text carrying a
private value that is neither under a name key nor regex-shaped (a bare
nickname in prose) is not caught; skim the published files before sharing.
