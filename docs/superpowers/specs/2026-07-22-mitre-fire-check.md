# MITRE empirical firing check (M7, 2026-07-22)

## Context

SSOT.md's M7 forward-roadmap row lists "MITRE metadata + eval harness" as a
continuous track. The metadata half was already done: every rule can carry
an optional `mitre: {tactic, technique}` block (C3, v0.5), and
`eval/attack/coverage_layer.py` turns those blocks into a scorecard + ATT&CK
Navigator layer, CI-wired via `make attack-scorecard`.

What that scorecard does NOT prove, by its own module docstring: a rule
*claiming* a technique isn't the same as the rule actually *firing*. This
doc records the narrow, deliberate scope of the tool that closes that gap
(`eval/attack/fire_check.py`) and — just as important — what it still does
not prove, so the distinction doesn't get flattened in a future status line.

## Three separate claims, kept separate on purpose

1. **Declared** (`coverage_layer.py`): the rule YAML carries a `mitre:`
   block. Zero infra, pure metadata parsing.
2. **Fired-on-its-own-fixture** (`fire_check.py`, this doc): the rule's
   condition/threshold logic actually evaluates to `True` when replayed
   against the same real parser -> enrich pipeline output that
   `tools/check_rule_producers.py`'s anti-dormancy gate already proves is
   satisfiable. Zero infra, no external dataset — every producer fixture
   already lives in this repo.
3. **Fired-on-real-world-traffic** (`eval/detection_accuracy/`, unchanged):
   independent-oracle replay against real EVTX-ATTACK-SAMPLES / Splunk
   `attack_data` corpora. Dataset-gated, opt-in (`make eval-detection`),
   deliberately not run in CI by default.

`fire_check.py` sits strictly between 1 and 3. It catches "the rule is dead
code — a typo in a field name, a threshold that can never be reached by the
rule's own documented producer, a condition that's always false" — the same
class of bug the anti-dormancy gate catches for *field satisfiability*, but
one layer deeper (actual boolean/threshold evaluation, not just "the field
exists"). It does **not** catch: evasion (an attacker who knows the
threshold and stays one event under it), real-world log noise/malformed
input shapes the synthetic fixture doesn't have, or window-counter behavior
under concurrent multi-replica load (that's `RedisWindowCounter`'s own live
test lane, unrelated).

## Why timestamps step backward from wall-clock "now"

The first implementation stepped a stateful rule's synthetic repetitions
FORWARD from the fixture's own timestamp (which, since these fixtures are
built fresh on every run, is already close to "now"). That silently tripped
`engine.py`'s `_MAX_CLOCK_SKEW_MS` anti-poisoning guard (P0, 5-minute
tolerance) on every repetition past the first — two real rules
(`common_beaconing`, `common_rapid_account_lifecycle`) came back SILENT not
because they're broken, but because the harness itself was feeding them
implausible far-future timestamps. Fixed by anchoring the last repetition at
wall-clock "now" and stepping earlier repetitions backward into the past —
legitimate historical replay always passes the guard, matching how a real
event stream actually looks.

## Result (2026-07-22, first run)

25/25 MITRE-tagged rules fire on their own real producer fixture (26/26 as
of PR#24's Modbus rule). Wired into `make attack-scorecard` (alongside
`coverage_layer.py`), CI's `attack-scorecard` job (blocking — a tagged rule
that stops firing is a real regression), and `run_all_tests.sh`'s zero-infra
gate.

## Boundary (negative) probes — 2026-07-28 follow-up

Everything above proves a rule fires AT its threshold. That is only half the
claim. A rule that is too LOOSE — off-by-one on the count, a window wider
than declared — fires at threshold too, passes the anti-dormancy gate too,
and is invisible to both. It never shows up as a dormant rule; it shows up
months later as false-positive volume nobody traces back to the threshold.

So every stateful rule that fires is now also replayed:

* `under_threshold` — `threshold - 1` events in-window, must stay silent.
* `window_overrun` — a full `threshold` events spread so their total span
  lands just past `window_seconds`, must stay silent. Spacing them
  `window + 1s` apart instead — the obvious construction, and the one this
  started as — only fires when the engine's window is roughly `threshold`
  times too wide, so it cannot see a small window error on a high-threshold
  rule at all. That flaw was caught by the sensitivity test below, not by
  reading the code.

**Result: 12 of 12 stateful rules hold their boundary.** The 14 stateless
rules are reported NOT boundary-tested rather than counted as passing: the
near-miss of a single-event field match is the entire rest of the value
space, so no near-miss fixture is generatable and each needs a hand-authored
one. That is a real remaining gap, listed here rather than averaged into a
headline number.

Two properties of the negative half are load-bearing:

1. **It shares `_replay` with the positive check.** "Did not fire" and "was
   never exercised" are the same observation from outside, so a harness that
   silently drops events reports GREEN on a negative assertion — which is
   exactly the failure mode of this tool's own clock-skew bug two sections
   up, where dropped events made two healthy rules look dead. In a positive
   check that bug was loud; inside a negative probe the identical breakage
   would have looked like a pass. The positive replay is therefore the
   control for the negative ones and must not be a separate code path that
   can drift from them.
2. **Silence is only scored as a pass when it is unambiguous.** A probe that
   would drag an `outside_hours` rule's replay across its business-hours
   boundary reports `skipped`, not a boundary it did not test. Likewise a
   rule whose every probe was skipped reports no held boundary at all, so an
   untestable rule cannot inflate the headline count.

`eval/attack/test_fire_check.py` is what licenses any of this being cited:
it mutates real rules until they ARE too loose (engine fires one event
early; window 10% wider than declared) and asserts each probe goes red. A
negative assertion that cannot fail is not a test.

### What the boundary probes still do not prove

`under_threshold` passing is not a security property — it is the *proof
that the evasion gap listed above is real*. An attacker who knows the
threshold and stays one event under it is not detected, and this gate now
demonstrates that on every run rather than leaving it as prose. Closing that
gap needs different machinery (decay/scoring across windows), not a tighter
threshold.

## Known limitation, disclosed not hidden

`fire_check.py` reuses `tools/check_rule_producers.py`'s `FIXTURES` dict
directly rather than maintaining a second, drifting fixture set — but that
means a rule whose producer fixture is itself wrong (satisfies the
anti-dormancy gate's field-existence check but not the rule's actual
semantic condition) would still show FIRED here only if the condition
genuinely evaluates true; a rule with NO real producer at all is already
caught by the anti-dormancy gate before this tool would even see it run.
The two gates are complementary, not redundant.
