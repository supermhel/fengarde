# Detection Quality: precision / recall / F1 for the FENGARDE engine

This document describes `tools/detection_quality_eval.py` — the machine-checkable
harness that measures how well the WS-4 detection engine agrees with a small,
hand-authored, **labeled corpus** of normalized events. It is a *regression
canary*, not a claim about real-world detection capability.

## Why this metric set, and what the words mean here

For every rule, each event in the corpus lands in exactly one of four buckets,
computed by comparing the corpus label (the detection a human judge *expects*)
with what the engine actually fired (what `Rule.evaluate()` returned):

| bucket | label says the rule fires | engine actually fired the rule |
|--------|:---:|:---:|
| True Positive  (TP) | yes | yes |
| False Positive (FP) | no  | yes |
| False Negative (FN)| yes | no  |
| True Negative  (TN) | no  | no  |

From those counts, per rule:

- **Precision** = TP / (TP + FP). Of everything the rule fired on, how much
  was *supposed* to fire. Low precision = the rule over-alerts (noise).
- **Recall** = TP / (TP + FN). Of everything the label says the rule *should*
  have fired on, how much it actually caught. Low recall = the rule misses
  detections.
- **F1** = 2 · (precision · recall) / (precision + recall). The harmonic mean —
  a single number that is only high when *both* precision and recall are high,
  so it cannot be gamed by a rule that fires on everything (P=0) or nothing
  (R=0).

The **overall macro-F1** is the unweighted mean of the per-rule F1 scores. It
treats every rule equally regardless of how many corpus events it happens to
have, which is the right stance for a small canary corpus.

**Important**: precision and recall as measured here are *engine–vs–labels*
agreement. They say nothing about how often the engine detects real attacks in
production, evades an actor, or trades false alarms against the org's actual
tolerances. A perfect 1.0 here would only prove the engine matches our hand
labels on ~12 events — a tiny, curated sample. That is a deliberate, bounded
claim. See [Honest caveats](#honest-caveats).

## How the labeled corpus is structured

The corpus lives in `tools/detection_quality_eval.py` as `CORPUS`, a list of
dictionaries; each entry is one normalized OCSF event:

```python
{
    "name": "ah_pos",              # human-readable case id (shown in output)
    "note": "off-hours Sunday admin logon",  # what the case represents
    "event": { ... },              # a normalized OCSF event dict
    "expected_rules": ["9b5f2d18-..."],  # rule ids a human judge expects to fire
}
```

- `event` is **not** raw log text. It is the normalized, post-parse,
  post-enrichment OCSF shape the engine evaluates — the dotted field paths
  (`class_uid`, `activity_id`, `actor.user.name`, `time`, …) come straight from
  what the real parsers emit. Keeping it minimal (only the fields a case needs)
  is what lets a single event be a clean positive *or* clean negative.
- `expected_rules` is the human ground truth for the case. `[]` means "no rule
  should fire".
- The corpus deliberately covers **stateless** rules, one event per case, so a
  case either fires or it does not, unambiguously. Stateful rules (thresholds
  over a window) are out of scope for the built-in corpus — reproducing one
  would mean replaying many events through a shared window counter, which is a
  different harness than fire_check.py, not this canary.

## How the harness loads the engine and rules

`tools/detection_quality_eval.py` reuses the **same import path the engine
runs under** (`services/ws2-normalization`, `services/ws4-detection`,
`services/`), then:

1. Calls `engine.load_rules(contracts/rules, contracts/allowlists)` — the real
   loader that reads every `contracts/rules/*.yml`, runs the poison-pill rule
   validation, and constructs real `Rule` objects with the real allowlist dir.
2. For each corpus entry, deep-copies the event and calls the real
   `Rule.evaluate(event)` on every rule in the loaded set (skipping stateful
   rules, which are not in the corpus).
3. Counts TP/FP/FN/TN per rule across the whole corpus, prints a table, and
   computes the macro-F1.

Using `evaluate()` on the real rules (rather than re-deriving conditions) means
the harness degrades exactly when the engine degrades: a broken `evaluate()`,
a dead `load_rules`, or a rule whose condition silently stopped matching all
move the metrics away from the current baseline.

## Honest caveats

1. **This measures engine-versus-labels agreement, not real-world detection
   fidelity.** A high score only shows the engine agrees with our hand labels on
   the handful of events in the corpus. It is *not* evidence of precision/recall
   against real traffic, does not measure evasion, and does not validate the
   labels themselves (the labels are a human judgment, possibly wrong).
2. **The corpus is intentionally imperfect, and that is the point.** The
   `common_after_hours_admin` cases include two deliberately adversarial labels
   that the real engine "gets wrong" relative to the ideal, so precision and
   recall are *not* trivially 1.0 and the gate actually measures something:
   - `ah_no_time` is labeled as an off-hours admin act with **no usable `time`**.
     The engine's `outside_hours` predicate is fail-closed (a missing/non-numeric
     timestamp never matches), so it stays silent → a **false negative**. This is
     the engine's anti-poisoning/safety posture, not a bug: it refuses to fire on
     an event it cannot safely timestamp.
   - `ah_svcacct` is an off-hours admin logon from a *service account* under a
     **shipped-empty** `service_accounts` allowlist (FIX L2: nothing is suppressed
     by default, so the rule is intentionally noisy until an operator populates
     it). A judge who would suppress service accounts labels it `[]`, but the
     engine fires → a **false positive**. Again real, documented engine behavior,
     not a defect to "fix" by changing the harness.
   These two are the cheapest honest way to make a real detection engine's
   metrics non-trivial without fabricating a bug.
3. **The floor is deliberately low (macro-F1 ≥ 0.5** — not a claim of quality).**
   It exists only to turn a *catastrophic regression* red (an engine that stops
   firing entirely collapses recall to 0 and the macro-F1 to 0, failing the
   gate) while staying green through the normal, intentional imperfections above.
   It is a trip-wire, not a quality target, and it must not be used as "FENGARDE
   is 87.5% accurate" evidence.
4. **Stateful and boundary behavior is out of scope here.** Threshold/window
   semantics, distinct-count, periodicity, and off-by-one boundary probes are
   covered by `eval/attack/fire_check.py` and `services/ws4-detection/test_engine_*`.
   This harness is a complementary, coarse, corpus-driven canary.

## Running it

```sh
export PYTHON=python
python tools/detection_quality_eval.py      # gate: exit 0 iff macro-F1 >= 0.5
python tools/test_detection_quality.py      # self-test of the metric math + floor
```

Both are wired into `run_all_tests.sh`. The gate never runs in-engine network
state or a live broker; it reads only `contracts/rules/`, `contracts/allowlists/`,
and the in-file corpus — deterministic and fast.
