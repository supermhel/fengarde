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

25/25 MITRE-tagged rules fire on their own real producer fixture. Wired
into `make attack-scorecard` (alongside `coverage_layer.py`), CI's
`attack-scorecard` job (blocking — a tagged rule that stops firing is a
real regression), and `run_all_tests.sh`'s zero-infra gate.

## Known limitation, disclosed not hidden

`fire_check.py` reuses `tools/check_rule_producers.py`'s `FIXTURES` dict
directly rather than maintaining a second, drifting fixture set — but that
means a rule whose producer fixture is itself wrong (satisfies the
anti-dormancy gate's field-existence check but not the rule's actual
semantic condition) would still show FIRED here only if the condition
genuinely evaluates true; a rule with NO real producer at all is already
caught by the anti-dormancy gate before this tool would even see it run.
The two gates are complementary, not redundant.
