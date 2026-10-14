# P2, first pass — the first real third-party number (2026-10-14)

Plan §P2 exists to answer the harness's own worst question: **independence** — *"does it catch attacks nobody on
the team wrote or labelled?"* Until now the honest answer was **no**: every corpus in the blocking lane was
synthetic, written by the same authors as the rules. This is the first measurement against data neither the
authors nor the rules produced.

Command (run once, on 2026-10-14, from a networked machine):

```sh
python3 eval/detection_accuracy/fetch_corpora.py          # FETCH_RC=0
python3 eval/detection_accuracy/blind_recall.py --require-corpus \
        --out eval/detection_accuracy/blind_recall_results.json
```

Nothing is vendored: the corpora land in gitignored directories (`splunk-attack-data/` 755 MB,
`evtx-to-mitre/` 78 MB) and the results file is itself gitignored (`.gitignore:59`), so **"commit nothing from
it" is enforced by structure, not by discipline**. What is committed is this record and the funnel below.

## The corpora, pinned

| corpus | checked out | pin | licence |
|---|---|---|---|
| `splunk/attack_data` | `800ef65739e6d2ed61043ccb313623441a3778ae` | **matches the manifest pin exactly** | Apache-2.0 |
| `mdecrevoisier/EVTX-to-MITRE-Attack` | `474856008f037ccd42753f02a631b42690195829` | `null` (unpinned — this first fetch records the HEAD it got) | CC0-1.0 |

## The funnel

```
scenarios=1508  units=1509  fetched_units=325  rules_indexed=26
funnel buckets: NOT_FETCHED=1184  UNLABELLED=14  NO_PARSER=184  NO_RULE=79
                MISS=36  HIT_EXACT=10  HIT_FAMILY=2  READER_UNAVAILABLE=0
technique funnel: techniques_in_corpus=342  techniques_fetched=78
                  techniques_with_ingestible_dataset=54  techniques_with_rule=26
                  techniques_with_hit=4
partial_parse_units=60  scoreable_units=48
```

Three numbers, and only one of them is a detection statement:

- **12 hits of 1509 labelled units (0.8 %)** — this is *not* a detection quality figure. 1184 of the 1509 units
  (78 %) were never fetched, because the manifest's sparse selection defines the denominator. Reporting 0.8 %
  as "recall" would be dishonest.
- **12 hit of 325 fetched units (3.7 %)** — still dominated by units FENGARDE could not have caught for
  structural reasons: 184 fetched units had **no parser at all** and 79 had **no rule** for their technique.
- **12 hits of 48 scoreable units (25 %)** — the fair denominator: fetched, labelled, a parser exists that can
  ingest the data, and a rule exists for the technique. *Of the cases FENGARDE could in principle see on
  third-party data, it caught 12 of 48.* That is the number to carry forward, and it is a small one.

Where the hits are: `T1098` account manipulation **6/33** end-to-end (6 of 8 reachable), `T1110` family
**2/12** (2 of 6 reachable), `T1110.003` **2/2 family-level** (2 of 2 reachable). Only **4 of the 342 labelled
techniques** in the corpus are hit at all.

Where the misses are, on units that had both a parser and a rule — this is the part worth acting on:
`T1046` network service discovery **0/4 reachable**, `T1021.002` SMB admin shares **0/3**, `T1021.001`/`003`/
`004` 0/2, 0/1, 0/1, `T1078`/`001`/`002` 0/1, 0/1, 0/1, `T1133` 0/1. 36 units in total missed while reachable.

## The gap lists, published rather than hidden (which is the point of P2)

- **`NO_RULE` — 52 techniques** with a parser but no enterprise-ATT&CK rule in the family. Head:
  `T1003` (n=19), `T1543.003` (17), `T1562.002` (13), `T1546` (11), `T1562.001` (9), `T1087` (8), `T1574` (8),
  `T1069` (7), `T1053.005` (6), `T1222.001` (6), `T1562.004` (6), `T1016` (5). Credential dumping, service
  creation, and defence evasion by disabling logging/tools sit at the top — exactly the class the plan warned
  about ("FENGARDE has no process-creation, registry, persistence-by-execution or credential-dumping rule").
- **`gap_no_exact_rule` — 16 sub-techniques** where a *family* rule exists but the exact technique is uncovered,
  each with the family rule ids attached. Head: `T1021.002` (7), `T1021.004` (4), `T1021.001` (3),
  `T1548.002` (3), `T1021.003` (2), `T1021.006` (2), `T1078.002` (2), **`T1110.003` (2)**, `T1552.004` (2).
- **`NO_PARSER` — 184 fetched units**, the largest structural bucket among the units that were fetched. This is
  the parser backlog, and it has never before been quantified against real data.

## What this changes in the honest ledger

1. **A documented gap is now confirmed by third-party labels.** The handoff records *"T1110.003 stays a
   documented gap; `common_password_spray` is deliberately T1110.004"*. The real corpus fetched 2 units labelled
   `T1110.003`, both of which the family rule caught — so the family works and the exact sub-technique is still
   uncovered. The declared gap and the measurement agree; that is the first time a rule-intent claim here has
   been checked against data the authors did not write.
2. **The independence answer moves from "no" to "partly, and the first number is small."** Four of 342 labelled
   techniques hit; 25 % of scoreable units. That is the truth about an early-stage pipeline, and it is now
   measured rather than assumed.
3. **The parser gap is bigger than the rule gap on real data** (184 vs 79 fetched units). Any backlog ordering
   that treats "add a rule" as the default action is wrong for this corpus.

## Limits — what this does not establish

- **One fetch, one pin set.** `evtx-to-mitre` is unpinned (the first fetch records its HEAD); the numbers move
  if that repository does. `splunk-attack-data` is pinned exactly, so its half is reproducible.
- **The sparse selection defines everything.** 78 % of units were not fetched, and which ones were fetched is the
  manifest's choice, not a neutral sample. The funnel prints `NOT_FETCHED` separately for exactly this reason.
- **Labels are the dataset authors', folder- and YAML-derived**, with `UNLABELLED=14` units and a recorded
  `label_dir_disagree` flag per row. A label disagreement is not a FENGARDE failure.
- **`partial_parse_units=60`** — units where the parser read some but not all of the input; they are counted
  separately and are neither hits nor clean misses.
- **No committed ratchet yet.** The plan proposes the regression rule *"a technique that was HIT may not become
  MISS/NO_RULE; no absolute threshold"*. The results file that would carry it is gitignored, so the ratchet needs
  a committed baseline of the **hit/miss map only** (no corpus, no records) before it can gate. Not built here.
- **This is not in the gate** and must not be: the corpora are third-party, large and fetched on demand. The
  blocking lane keeps its synthetic controls.

## Reproduction

`fetch_corpora.py --dry-run` prints the exact git plan and LFS selection without fetching. The run above is
reproducible for `splunk-attack-data` by checking out `800ef65739e6d2ed61043ccb313623441a3778ae`; for
`evtx-to-mitre` the checked-out commit is recorded above but was not pinned.
