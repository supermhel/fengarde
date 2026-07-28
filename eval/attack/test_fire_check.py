"""fire_check.py boundary-probe sensitivity tests.

The positive half of fire_check ("the rule fires on its own fixture") fails
loudly when it breaks -- you get a red gate and go read it. The negative half
("the rule does NOT fire one under its threshold") has the opposite failure
mode: a harness that silently stops exercising the rule reports the same
"did not fire" as a correctly-held boundary, and the gate goes GREEN. That is
not hypothetical here -- fire_check's own clock-skew bug (synthetic
repetitions stamped into the future, eaten by the engine's anti-poisoning
guard) made two healthy rules look dead, and the identical breakage inside a
negative probe would have looked like a pass.

So the negative probes need their own control: mutate a real rule until it IS
too loose (fires one event early / carries a window wider than declared) and
assert each probe goes red. A negative assertion that cannot fail is not a
test, and these tests are what license the boundary line in the scorecard.

Zero infra: real contracts/rules/*.yml, real parsers, real Detector. Rule
mutations are made on the in-memory Rule object and restored immediately;
nothing on disk is touched.

Run: python eval/attack/test_fire_check.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import fire_check as fc  # noqa: E402

# One plain-count rule and one distinct-count rule -- the two stateful
# counting paths (hit / hit_distinct) the probes have to work against.
RULE_BRUTE = "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01"     # count, threshold 10
RULE_MASS_CARD = "d4e5f607-8192-4a31-8b4c-5d6e7f809104"  # distinct-count, threshold 20

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _fixture_for(rule, events):
    """The real fixture event this rule actually fires on, plus its
    outside_hours anchors -- the positive control every probe below is
    measured against."""
    oh = [(f, fc._outside_hours_anchor(s)) for f, s in fc._outside_hours_specs(rule)]
    fired, note, fixture = fc._try_fire(rule, events, oh)
    check(fired and fixture is not None,
          f"{rule.id}: positive control did not fire ({note}) -- every boundary "
          f"result below is meaningless until this passes")
    return fixture, oh


def test_under_threshold_probe_catches_an_off_by_one_rule(rules, events):
    """threshold-1 events must stay silent on an honest rule and FIRE once the
    engine is made to trigger one event early."""
    for rid in (RULE_BRUTE, RULE_MASS_CARD):
        rule = rules[rid]
        fixture, oh = _fixture_for(rule, events)
        if fixture is None:
            continue
        declared = rule.threshold
        step = fc._positive_step_ms(rule, declared)

        honest = fc._replay(rule, fixture, declared - 1, step, oh, "test-honest")
        check(honest is False,
              f"{rid}: {declared - 1} events fired a threshold-{declared} rule")

        rule.threshold = declared - 1  # off-by-one: too loose
        try:
            mutant = fc._replay(rule, fixture, declared - 1, step, oh, "test-mutant")
        finally:
            rule.threshold = declared
        check(mutant is True,
              f"{rid}: under_threshold probe stayed silent on a rule mutated to "
              f"fire one event early -- the probe cannot detect a too-loose count")


def test_window_overrun_probe_catches_a_window_wider_than_declared(rules, events):
    """A run spanning just past window_seconds must stay silent on an honest
    rule and FIRE when the engine's window is only 10% wider than declared.

    The 10% is the point: the earlier construction here spaced events
    window+1s apart, which only fires when the real window is ~threshold times
    too wide, so it could not see a small window error on a high-threshold
    rule at all."""
    for rid in (RULE_BRUTE, RULE_MASS_CARD):
        rule = rules[rid]
        fixture, oh = _fixture_for(rule, events)
        if fixture is None:
            continue
        declared_window = rule.window_seconds
        step = fc._overrun_step_ms(rule, rule.threshold)

        honest = fc._replay(rule, fixture, rule.threshold, step, oh, "test-w-honest")
        check(honest is False,
              f"{rid}: events spanning past window_seconds={declared_window} "
              f"still fired")

        rule.window_seconds = declared_window * 1.1
        try:
            mutant = fc._replay(rule, fixture, rule.threshold, step, oh, "test-w-mutant")
        finally:
            rule.window_seconds = declared_window
        check(mutant is True,
              f"{rid}: window_overrun probe stayed silent on a rule whose window "
              f"is 10% wider than declared -- the probe is too blunt to be cited")


def test_probes_are_isolated_from_each_other(rules, events):
    """Re-running the same sub-threshold probe must give the same answer.

    The engine's window counter lives on the Rule instance and is keyed
    {rule}:{tenant}:{group}, so probes that shared a tenant would accumulate
    each other's events and the second run would fire on leaked state. This is
    the one way the probes could report a defect that isn't in the rule."""
    rule = rules[RULE_BRUTE]
    fixture, oh = _fixture_for(rule, events)
    if fixture is None:
        return
    step = fc._positive_step_ms(rule, rule.threshold)
    first = fc._replay(rule, fixture, rule.threshold - 1, step, oh, "test-iso")
    second = fc._replay(rule, fixture, rule.threshold - 1, step, oh, "test-iso")
    check(first is False and second is False,
          f"{RULE_BRUTE}: repeated sub-threshold replay changed answer "
          f"({first} then {second}) -- counter state is leaking between probes")


def test_stateless_rules_are_reported_untested_not_passing(rules, events):
    """A stateless rule has no generatable near-miss, so it must be reported
    as not boundary-tested rather than counted as having held a boundary."""
    stateless = next((r for r in rules.values()
                      if not r.stateful and isinstance(r.raw.get("mitre"), dict)), None)
    check(stateless is not None, "no stateless MITRE-tagged rule found to check")
    if stateless is None:
        return
    probe = fc._boundary_probe(stateless, {"time": 0}, [])
    check(probe.get("applicable") is False,
          f"{stateless.id}: stateless rule reported as boundary-tested")
    check("probes" not in probe,
          f"{stateless.id}: stateless rule produced probe verdicts it cannot support")


def main():
    events = fc._real_events()
    detector = fc.Detector(plugin_rule_dirs=[])
    rules = {r.id: r for r in detector.rules}

    for rid in (RULE_BRUTE, RULE_MASS_CARD):
        if rid not in rules:
            print(f"[FAIL] eval/attack/fire_check.py: rule {rid} not loaded")
            sys.exit(1)

    test_under_threshold_probe_catches_an_off_by_one_rule(rules, events)
    test_window_overrun_probe_catches_a_window_wider_than_declared(rules, events)
    test_probes_are_isolated_from_each_other(rules, events)
    test_stateless_rules_are_reported_untested_not_passing(rules, events)

    if FAILS:
        print(f"[FAIL] eval/attack/fire_check.py boundary probes: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] fire_check boundary probes are sensitive: silent on honest rules, "
          "red on a rule mutated to fire one event early or to carry a window 10% "
          "wider than declared; probe runs are isolated from each other and "
          "stateless rules are reported untested rather than passing")


if __name__ == "__main__":
    main()
