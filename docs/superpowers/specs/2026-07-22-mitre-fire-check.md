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

> **Superseded 2026-08-11 — the "no near-miss is generatable" reasoning above
> was wrong.** Every shipped stateless rule's condition is a pure conjunction
> of field predicates, so violating exactly ONE declared predicate must
> silence the rule, which IS generatable per predicate. `fire_check.py`'s
> `_near_miss_probe` does that; 15 of 15 stateless rules hold across 46
> predicate near-misses, none skipped. The rule count also moved (14 → 15) as
> rules were added after this spec was written. See `SSOT.md` for the current
> claim and its scope; the paragraph above is kept as the historical record of
> what this spec concluded at the time.

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
2. **Silence is only scored as a pass when it is unambiguous.** Off-hours
   anchoring is span-aware: the harness searches for an anchor that keeps a
   replay off-hours for its whole length, rather than anchoring an instant
   and discovering afterwards that the oldest event drifted into business
   hours. When no such anchor exists the probe reports `skipped`, and a rule
   is counted as having held its boundary only when EVERY probe ran and held
   — one held plus one skipped is its own category, because the headline
   sentence claims both probes stayed silent.

`eval/attack/test_fire_check.py` is what licenses any of this being cited:
it mutates real rules until they ARE too loose (engine fires one event
early; window 10% wider than declared) and asserts the gate **exits 1
through `main()`**, with a control asserting it exits 0 unmutated. A
negative assertion that cannot fail is not a test.

### What the second review caught that the first did not

The first (self-) review fixed four issues and declared the work solid. An
adversarial re-review, briefed to hunt what that review missed, found four
more — all confirmed by reproduction, all fixed:

* **The gate's failing path was unfalsifiable.** `held` was matched with
  `startswith("held")` but `too_loose` with `== "FIRED"`, and nothing
  exercised `main()`'s exit code. Editing the failure verdict's prose left
  every test green while the gate exited 0 on a genuinely too-loose rule.
  The fragile comparison was guarding the wrong side. Verdicts are now
  `{"status": ..., "detail": ...}` and the exit code is asserted end to end.
* **Partial coverage counted as full.** One probe held + one skipped was
  reported as a held boundary, falsifying this doc's own claim that an
  untestable rule cannot inflate the count.
* **The positive replay was unguarded.** `_hours_confound` protected both
  negative probes but not `_try_fire`, so the first stateful `outside_hours`
  rule would have been reported `[FAIL] ... dead-on-arrival` — loud, but
  blaming a healthy rule for a harness limitation. Anchoring is span-aware
  now, and an unconstructable replay is reported as a HARNESS failure.
* **The isolation test tested the wrong mechanism.** It reused one tag for
  both replays, so `DequeWindowCounter`'s `ingest_id` redelivery guard
  flattened the second run; it proved the dedup path while its docstring
  described tenant isolation. It now uses distinct tags.

Two lower-severity findings were also fixed: `_replay` reported only the
LAST event's verdict (an intermediate fire inside a negative probe was
discarded — reachable in principle for `periodicity` rules, whose
coefficient of variation is not monotone), and a 1s floor on the positive
step silently broke any rule with `threshold > window_seconds + 1`. The step
arithmetic is pinned by property tests over a grid of (window, threshold)
shapes; the any-fired semantics are pinned by a separate test that replays a
rule firing only on event 3 of 5. (A third review pass caught that sentence
originally claiming the grid covered both: reverting `_replay` to last-fired
left the whole suite green.)

### Third pass: the fix for one flake introduced another

Re-reviewing the fixes above found that span-aware anchoring stepped its
candidate search backward in whole HOURS, holding minute-of-hour fixed for
the entire 8-day search. For a rule whose off-hours span is close to its
replay span, whether an anchor exists then depends on what minute the gate
happens to run at — measured on a synthetic 2h-window rule in a 1h off-hours
span: blocked at minutes 0–27, fine at 30–57. A deterministic 50% CI
coin-flip, i.e. the false dead-rule report of finding 3 traded for a
wall-clock flake in the same function. The search now steps by 60s (0/60
minutes blocked, verified by sweep).

The same lock had quietly disabled the test guarding the partial-coverage
fix: for 48 of 60 minutes both its probes came back `skipped`, so it
degenerated into a duplicate of the all-skipped test and still passed,
because it only asserted the skip and not the hold. It now asserts both, and
is non-degenerate at all 60 minutes. Worth recording as the file's own
stated failure mode — a probe that stopped being exercised looks exactly
like a probe that passed — reappearing inside the test written to prevent it.

### What the boundary probes still do not prove

`under_threshold` passing is not a security property — it is the *proof
that the evasion gap listed above is real*. An attacker who knows the
threshold and stays one event under it is not detected, and this gate now
demonstrates that on every run rather than leaving it as prose. Closing that
gap needs different machinery (decay/scoring across windows), not a tighter
threshold.

They also do not say a threshold is well CHOSEN. The probes take their event
count from `rule.threshold` — the same declared number the engine compares
against — so they prove the engine and the declaration agree, and nothing
more. Lower a rule's declared threshold and this gate stays green; whether
that threshold is too permissive for real traffic is `eval/detection_accuracy/`'s
question, on real corpora, not this one.

Finally, three of the twelve stateful rules have `threshold: 2`, so their
`under_threshold` probe replays exactly one event. "1 event did not fire a
threshold-2 rule" is true but nearly vacuous; those rules' `window_overrun`
probes carry the real weight. The scorecard prints the degenerate case
explicitly rather than letting it read as equivalent to the 39-event probe
on `common_dns_exfil`.

## Known limitation, disclosed not hidden

`fire_check.py` reuses `tools/check_rule_producers.py`'s `FIXTURES` dict
directly rather than maintaining a second, drifting fixture set — but that
means a rule whose producer fixture is itself wrong (satisfies the
anti-dormancy gate's field-existence check but not the rule's actual
semantic condition) would still show FIRED here only if the condition
genuinely evaluates true; a rule with NO real producer at all is already
caught by the anti-dormancy gate before this tool would even see it run.
The two gates are complementary, not redundant.
