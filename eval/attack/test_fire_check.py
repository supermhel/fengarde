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
assert the gate goes red -- END TO END, through `main()`'s exit code, not
just at the `_replay` level. An adversarial review found the earlier version
of this file stopped at `_replay` returning True, which left the entire
verdict-and-exit path unexercised: a cosmetic edit to the failure string
disarmed the gate while every test here stayed green.

Zero infra: real contracts/rules/*.yml, real parsers, real Detector. Every
test gets a FRESH Detector -- the engine's window counter lives on the Rule
instance and is never reset, so sharing one across tests makes results depend
on execution order and on how many times a tag was reused.

Run: python eval/attack/test_fire_check.py
"""
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import fire_check as fc  # noqa: E402

# One plain-count rule and one distinct-count rule -- the two stateful
# counting paths (hit / hit_distinct) the probes have to work against.
RULE_BRUTE = "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01"     # count, threshold 10
RULE_MASS_CARD = "d4e5f607-8192-4a31-8b4c-5d6e7f809104"  # distinct-count, threshold 20

FAILS: list[str] = []
_EVENTS: list[dict] | None = None


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def fresh_rules() -> dict:
    """A Detector nobody else has replayed through. Rules carry their own
    sliding-window counter and nothing clears it, so a shared Detector makes
    every test order-dependent -- re-running this suite twice in one process
    against shared rules fails on leaked window state, not on a real defect."""
    return {r.id: r for r in fc.Detector(plugin_rule_dirs=[]).rules}


def events() -> list[dict]:
    global _EVENTS
    if _EVENTS is None:
        _EVENTS = fc._real_events()
    return _EVENTS


def _fixture_for(rule):
    """The real fixture event this rule actually fires on -- the positive
    control every probe below is measured against."""
    fired, note, fixture, blocked = fc._try_fire(rule, events())
    check(fired and fixture is not None,
          f"{rule.id}: positive control did not fire ({note}) -- every boundary "
          f"result below is meaningless until this passes")
    return fixture


def _make_too_loose(rule):
    """Make ``rule``'s ENGINE fire one event early while its DECLARED
    threshold is unchanged -- i.e. a genuinely too-loose rule, which is not
    the same as a rule with a lower threshold (lowering the declaration moves
    the probe's own event count with it and stays self-consistent)."""
    declared = rule.threshold
    original = rule.evaluate

    def loose(event, _o=original, _r=rule, _d=declared):
        _r.threshold = _d - 1
        try:
            return _o(event)
        finally:
            _r.threshold = _d

    rule.evaluate = loose
    return original


def test_under_threshold_probe_catches_an_off_by_one_rule():
    """threshold-1 events must stay silent on an honest rule and FIRE once the
    engine is made to trigger one event early."""
    for rid in (RULE_BRUTE, RULE_MASS_CARD):
        rules = fresh_rules()
        rule = rules[rid]
        fixture = _fixture_for(rule)
        if fixture is None:
            continue
        declared = rule.threshold
        step = fc._positive_step_ms(rule, declared)

        honest = fc._replay(rule, fixture, declared - 1, step, "test-honest")
        check(honest is False,
              f"{rid}: {declared - 1} events fired a threshold-{declared} rule")

        _make_too_loose(rule)
        mutant = fc._replay(rule, fixture, declared - 1, step, "test-mutant")
        check(mutant is True,
              f"{rid}: under_threshold probe stayed silent on a rule mutated to "
              f"fire one event early -- the probe cannot detect a too-loose count")


def test_window_overrun_probe_catches_a_window_wider_than_declared():
    """A run spanning just past window_seconds must stay silent on an honest
    rule and FIRE when the engine's window is only 10% wider than declared.

    The 10% is the point: an earlier construction spaced events window+1s
    apart, which only fires when the real window is ~threshold times too
    wide, so it could not see a small window error on a high-threshold rule
    at all. That flaw was caught by this test, not by reading the code."""
    for rid in (RULE_BRUTE, RULE_MASS_CARD):
        rules = fresh_rules()
        rule = rules[rid]
        fixture = _fixture_for(rule)
        if fixture is None:
            continue
        declared_window = rule.window_seconds
        step = fc._overrun_step_ms(rule, rule.threshold)

        honest = fc._replay(rule, fixture, rule.threshold, step, "test-w-honest")
        check(honest is False,
              f"{rid}: events spanning past window_seconds={declared_window} "
              f"still fired")

        rule.window_seconds = declared_window * 1.1
        mutant = fc._replay(rule, fixture, rule.threshold, step, "test-w-mutant")
        check(mutant is True,
              f"{rid}: window_overrun probe stayed silent on a rule whose window "
              f"is 10% wider than declared -- the probe is too blunt to be cited")


def test_probe_reports_fired_status_on_a_too_loose_rule():
    """`_boundary_probe` must translate a firing negative probe into a
    machine-readable "fired" status and a non-empty `too_loose`.

    `_replay` returning True is not the same claim: everything between that
    and the gate's exit code used to be untested."""
    rules = fresh_rules()
    rule = rules[RULE_BRUTE]
    fixture = _fixture_for(rule)
    if fixture is None:
        return
    _make_too_loose(rule)
    probe = fc._boundary_probe(rule, fixture)
    # Both probes trip, not just the sub-threshold one: an engine that fires
    # one event early also fires on the overrun replay, whose in-window count
    # is threshold-1 by construction. Assert the specific probe rather than
    # the exact set, so this stays true if a third probe is added.
    check("under_threshold" in probe.get("too_loose", []),
          f"{RULE_BRUTE}: too-loose rule reported too_loose={probe.get('too_loose')}")
    check(probe["probes"]["under_threshold"]["status"] == "fired",
          f"{RULE_BRUTE}: expected status 'fired', got "
          f"{probe['probes']['under_threshold']}")
    check(probe.get("fully_held") is False,
          f"{RULE_BRUTE}: a too-loose rule reported fully_held")


def test_gate_exits_nonzero_end_to_end_on_a_too_loose_rule():
    """The whole point of the boundary probes is that CI goes red. Assert the
    exit code of `main()` itself, with a real too-loose rule loaded.

    Without this, every layer below can be correct while the gate still exits
    0 -- which is exactly what an adversarial review demonstrated by editing
    only the failure verdict string."""
    real_detector = fc.Detector

    def mutated_detector(*args, **kwargs):
        detector = real_detector(*args, **kwargs)
        for r in detector.rules:
            if r.id == RULE_BRUTE:
                _make_too_loose(r)
        return detector

    buf = io.StringIO()
    with tempfile.TemporaryDirectory() as tmp:
        # Keep the mutated run's JSON out of eval/attack/out/ -- CI uploads
        # that directory as an artifact after this test runs.
        real_out, fc.OUT_DIR = fc.OUT_DIR, Path(tmp)
        fc.Detector = mutated_detector
        try:
            with contextlib.redirect_stdout(buf):
                rc = fc.main()
        finally:
            fc.Detector = real_detector
            fc.OUT_DIR = real_out

    out = buf.getvalue()
    check(rc == 1, f"gate exited {rc} with a genuinely too-loose rule loaded; "
                   f"expected 1")
    check("fire BELOW their declared boundary" in out,
          "gate did not report the too-loose rule in its failure output")
    check(RULE_BRUTE in out.split("fire BELOW their declared boundary")[-1],
          f"gate failure output did not name {RULE_BRUTE}")


def test_gate_exits_zero_on_the_real_rule_set():
    """Control for the test above: the same end-to-end path must exit 0 when
    nothing is mutated. A gate that exits 1 unconditionally would satisfy the
    previous test on its own."""
    buf = io.StringIO()
    with tempfile.TemporaryDirectory() as tmp:
        real_out, fc.OUT_DIR = fc.OUT_DIR, Path(tmp)
        try:
            with contextlib.redirect_stdout(buf):
                rc = fc.main()
        finally:
            fc.OUT_DIR = real_out
    check(rc == 0, f"gate exited {rc} on the unmodified rule set; expected 0")


def test_probes_are_isolated_by_tenant_not_by_ingest_id():
    """Two DIFFERENT probes on one rule must not pool their events.

    Deliberately uses two different tags. An earlier version reused one tag
    for both replays, so `DequeWindowCounter.hit()`'s ingest_id redelivery
    guard flattened the second run and the test passed without ever
    exercising tenant isolation -- it proved the dedup path, not the thing
    its own docstring described."""
    rules = fresh_rules()
    rule = rules[RULE_BRUTE]
    fixture = _fixture_for(rule)
    if fixture is None:
        return
    step = fc._positive_step_ms(rule, rule.threshold)
    reps = rule.threshold - 1
    first = fc._replay(rule, fixture, reps, step, "test-iso-a")
    second = fc._replay(rule, fixture, reps, step, "test-iso-b")
    check(first is False and second is False,
          f"{RULE_BRUTE}: two distinct sub-threshold probes pooled their counts "
          f"({first} then {second}) -- {reps} + {reps} events crossed the "
          f"threshold-{rule.threshold} boundary, so tenant isolation is not holding")


def test_partly_skipped_rule_is_not_counted_as_having_held():
    """One probe held + one probe skipped is NOT a held boundary.

    The headline sentence claims both probes ran and stayed silent, so a
    half-probed rule counted there makes that sentence false. Constructed
    with the shape that produces it: a stateful rule whose off-hours span is
    too short for the overrun replay but long enough for the sub-threshold
    one. (The injected spec is read by `_outside_hours_specs` for anchoring;
    the rule's compiled condition is untouched, which is what isolates this
    test to the accounting path.)"""
    rules = fresh_rules()
    rule = rules[RULE_BRUTE]
    fixture = _fixture_for(rule)
    if fixture is None:
        return
    # Off-hours = a single hour per day; the overrun span (>window) cannot fit.
    rule.raw.setdefault("detection", {})["firecheck_synthetic"] = {
        "time": {"outside_hours": {"start": "00:00", "end": "23:00",
                                   "days": ["mon", "tue", "wed", "thu", "fri",
                                            "sat", "sun"],
                                   "tz_offset_minutes": 0}}}
    rule.window_seconds = 7200  # 2h window vs a 1h off-hours span
    probe = fc._boundary_probe(rule, fixture)
    statuses = {n: v["status"] for n, v in probe.get("probes", {}).items()}
    check(statuses.get("window_overrun") == "skipped",
          f"expected window_overrun skipped for a 2h span in a 1h off-hours "
          f"window, got {statuses}")
    check(probe.get("fully_held") is False,
          f"partly-skipped rule reported fully_held with statuses {statuses}")


def test_all_probes_skipped_is_not_counted_as_held():
    """A rule whose every probe was skipped has NOT been boundary-tested and
    must not report a held boundary."""
    rules = fresh_rules()
    rule = rules[RULE_BRUTE]
    fixture = _fixture_for(rule)
    if fixture is None:
        return
    rule.threshold = 1  # every probe becomes inapplicable
    probe = fc._boundary_probe(rule, fixture)
    check(probe.get("held") == [],
          f"{RULE_BRUTE}: threshold-1 rule reported a held boundary "
          f"{probe.get('held')} when every probe was skipped")
    check(probe.get("fully_held") is False,
          f"{RULE_BRUTE}: threshold-1 rule reported fully_held")


def test_positive_replay_always_fits_inside_its_own_window():
    """The positive replay must span LESS than the rule's window for every
    plausible (window, threshold) shape.

    A 1s floor on the step used to break this for any rule with
    `threshold > window_seconds + 1`: the replay would span past the window
    and a healthy rule would be reported dead-on-arrival, with the blame
    landing on the rule. No shipped rule is that dense, so only a property
    test over synthetic shapes catches it."""
    class Shape:
        def __init__(self, w, t):
            self.window_seconds, self.threshold = w, t

    for window in (1, 5, 10, 20, 30, 60, 120, 300, 3600):
        for threshold in (2, 3, 5, 10, 12, 22, 40, 100, 500):
            step = fc._positive_step_ms(Shape(window, threshold), threshold)
            span_ms = (threshold - 1) * step
            check(span_ms < window * 1000,
                  f"positive replay for window={window}s threshold={threshold} "
                  f"spans {span_ms}ms >= its own {window * 1000}ms window -- a "
                  f"healthy rule of this shape would be reported dead")


def test_overrun_replay_always_lands_past_its_window():
    """Mirror property for the negative side: the overrun span must exceed
    the window for every shape, or the probe is vacuous (it would be testing
    a run that legitimately fits, and 'held' would mean nothing)."""
    class Shape:
        def __init__(self, w, t):
            self.window_seconds, self.threshold = w, t

    for window in (1, 5, 10, 20, 30, 60, 120, 300, 3600):
        for threshold in (2, 3, 5, 10, 12, 22, 40, 100, 500):
            step = fc._overrun_step_ms(Shape(window, threshold), threshold)
            span_ms = (threshold - 1) * step
            check(span_ms > window * 1000,
                  f"overrun replay for window={window}s threshold={threshold} "
                  f"spans {span_ms}ms, inside its own {window * 1000}ms window")


def test_stateless_rules_are_reported_untested_not_passing():
    """A stateless rule has no generatable near-miss, so it must be reported
    as not boundary-tested rather than counted as having held a boundary."""
    rules = fresh_rules()
    stateless = next((r for r in rules.values()
                      if not r.stateful and isinstance(r.raw.get("mitre"), dict)), None)
    check(stateless is not None, "no stateless MITRE-tagged rule found to check")
    if stateless is None:
        return
    probe = fc._boundary_probe(stateless, {"time": 0})
    check(probe.get("applicable") is False,
          f"{stateless.id}: stateless rule reported as boundary-tested")
    check("probes" not in probe,
          f"{stateless.id}: stateless rule produced probe verdicts it cannot support")


def main():
    rules = fresh_rules()
    for rid in (RULE_BRUTE, RULE_MASS_CARD):
        if rid not in rules:
            print(f"[FAIL] eval/attack/fire_check.py: rule {rid} not loaded")
            sys.exit(1)

    test_under_threshold_probe_catches_an_off_by_one_rule()
    test_window_overrun_probe_catches_a_window_wider_than_declared()
    test_probe_reports_fired_status_on_a_too_loose_rule()
    test_gate_exits_nonzero_end_to_end_on_a_too_loose_rule()
    test_gate_exits_zero_on_the_real_rule_set()
    test_probes_are_isolated_by_tenant_not_by_ingest_id()
    test_partly_skipped_rule_is_not_counted_as_having_held()
    test_all_probes_skipped_is_not_counted_as_held()
    test_positive_replay_always_fits_inside_its_own_window()
    test_overrun_replay_always_lands_past_its_window()
    test_stateless_rules_are_reported_untested_not_passing()

    if FAILS:
        print(f"[FAIL] eval/attack/fire_check.py boundary probes: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] fire_check boundary probes: sensitive to a one-event and a 10% "
          "window error, the gate exits 1 end-to-end on a genuinely too-loose "
          "rule and 0 on the real rule set, probes are tenant-isolated, and "
          "partly/fully skipped rules are reported untested rather than held")


if __name__ == "__main__":
    main()
