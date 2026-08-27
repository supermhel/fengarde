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
import copy
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

# Stateless rules for the near-miss (single-predicate necessity) probes. Two
# shapes, not one: a plain multi-equality rule, and a rule carrying an
# `outside_hours` predicate -- the case the positive fire check cannot see at
# all, since a rule that ignores time-of-day fires on its own off-hours
# fixture exactly like a healthy one.
RULE_ROOT_LOGIN = "c3d4e5f6-7081-4920-9a3b-4c5d6e7f8093"       # cloud_root_console_login
RULE_N8N_AFTER_HOURS = "92a3b4c5-d627-4f05-ad6f-7a8b9c0d1e24"  # n8n_workflow_modified_after_hours

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
    # BOTH assertions matter. Without the `held` one this test silently
    # degenerates into a duplicate of the all-skipped test whenever the
    # sub-threshold span also fails to find an anchor -- it would still pass,
    # while no longer testing the partial-vs-full distinction it exists for.
    # That is this file's own stated failure mode (a probe that stopped being
    # exercised looks exactly like a probe that passed) reappearing inside
    # the test written to prevent it, so the degeneration must be loud.
    check(statuses.get("under_threshold") == "held",
          f"expected under_threshold to still RUN and hold (its span fits the "
          f"off-hours window) -- got {statuses}; this test is no longer "
          f"exercising the partial-coverage case it was written for")
    check(statuses.get("window_overrun") == "skipped",
          f"expected window_overrun skipped for a 2h span in a 1h off-hours "
          f"window, got {statuses}")
    check(probe.get("fully_held") is False,
          f"partly-skipped rule reported fully_held with statuses {statuses}")
    check(probe.get("held") == ["under_threshold"],
          f"partly-skipped rule reported held={probe.get('held')}")


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
    (window, threshold) shape a rule can actually express.

    A 1s floor on the step used to break this for any rule with
    `threshold > window_seconds + 1`: the replay would span past the window
    and a healthy rule would be reported dead-on-arrival, with the blame
    landing on the rule. No shipped rule is that dense, so only a property
    test over synthetic shapes catches it.

    The bound is explicit, not "every plausible shape": with a 1ms floor the
    property necessarily fails once a rule demands more events than its
    window has milliseconds (threshold > window_seconds * 1000), because the
    replay cannot place them at distinct integer-ms timestamps at all. The
    grid below stays inside that representable region and the boundary case
    is asserted separately, rather than the docstring claiming a coverage
    the grid does not have."""
    class Shape:
        def __init__(self, w, t):
            self.window_seconds, self.threshold = w, t

    for window in (1, 5, 10, 20, 30, 60, 120, 300, 3600):
        for threshold in (2, 3, 5, 10, 12, 22, 40, 100, 500):
            if threshold > window * 1000:
                continue  # more events than the window has milliseconds
            step = fc._positive_step_ms(Shape(window, threshold), threshold)
            span_ms = (threshold - 1) * step
            check(span_ms < window * 1000,
                  f"positive replay for window={window}s threshold={threshold} "
                  f"spans {span_ms}ms >= its own {window * 1000}ms window -- a "
                  f"healthy rule of this shape would be reported dead")

    # The representable boundary itself: densest shape that must still work.
    for window in (1, 5, 60):
        threshold = window * 1000 // 2
        step = fc._positive_step_ms(Shape(window, threshold), threshold)
        check(step >= 1 and (threshold - 1) * step < window * 1000,
              f"positive replay degenerates at the density boundary "
              f"window={window}s threshold={threshold}: step={step}")


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


def test_replay_reports_a_fire_on_any_event_not_just_the_last():
    """`_replay` must return True when ANY event in the replay fires, not
    only the final one.

    A rule that fires partway through a replay meant to stay silent is the
    too-loose defect being hunted; reporting only the last verdict discards
    it. Reachable in principle for `periodicity` rules, whose coefficient of
    variation is not monotone in the way an in-window count is.

    Pinned here because reverting `_replay` to last-fired left the entire
    rest of this suite green -- the spec claimed this behaviour was covered
    by the (window, threshold) grid tests, which only pin step arithmetic."""
    rules = fresh_rules()
    rule = rules[RULE_BRUTE]
    fixture = _fixture_for(rule)
    if fixture is None:
        return
    calls = {"n": 0}

    def fires_only_in_the_middle(_event):
        calls["n"] += 1
        return calls["n"] == 3

    rule.evaluate = fires_only_in_the_middle
    outcome = fc._replay(rule, fixture, 5, 1000, "test-any-fired")
    check(calls["n"] == 5, f"expected 5 evaluate() calls, got {calls['n']}")
    check(outcome is True,
          "a rule that fired on event 3 of 5 was reported as not having fired "
          "-- an intermediate fire inside a negative probe is being discarded")


def test_stateless_rules_are_near_miss_probed_not_threshold_probed():
    """A stateless rule has no threshold to step under, so `_boundary_probe`
    must decline it -- but declining is not the end of the story any more: the
    same rule must come back APPLICABLE from `_near_miss_probe` with real
    verdicts. Asserting only the decline (as this test once did) would keep
    passing if the near-miss half were deleted tomorrow."""
    rules = fresh_rules()
    stateless = next((r for r in rules.values()
                      if not r.stateful and isinstance(r.raw.get("mitre"), dict)), None)
    check(stateless is not None, "no stateless MITRE-tagged rule found to check")
    if stateless is None:
        return
    probe = fc._boundary_probe(stateless, {"time": 0})
    check(probe.get("applicable") is False,
          f"{stateless.id}: stateless rule reported as threshold/window-tested")
    check("probes" not in probe,
          f"{stateless.id}: stateless rule produced probe verdicts it cannot support")

    fixture = _fixture_for(stateless)
    if fixture is None:
        return
    near = fc._near_miss_probe(stateless, fixture)
    check(near.get("applicable") is True,
          f"{stateless.id}: stateless rule got no near-miss probe either "
          f"({near.get('reason')}) -- it would be negatively unverified")
    check(bool(near.get("probes")),
          f"{stateless.id}: near-miss probe ran but produced no predicate verdicts")


def _make_predicate_ignored(rule, dotted_field) -> bool:
    """Drop one DECLARED predicate from the rule's COMPILED selections, leaving
    the declaration in `rule.selections` untouched.

    That asymmetry is the whole point, and it is a real defect shape rather
    than a contrived one: the rule file still says the field is required, the
    engine no longer checks it, and the positive fire check passes happily
    because a rule with fewer constraints fires on its own fixture exactly as
    the honest one does. Nothing except a near-miss can see it."""
    parts = tuple(dotted_field.split("."))
    dropped = False
    for name, compiled in rule._compiled_selections.items():
        kept = [(p, e) for p, e in compiled if p != parts]
        if len(kept) != len(compiled):
            rule._compiled_selections[name] = kept
            dropped = True
    return dropped


def test_near_miss_probe_catches_a_predicate_that_is_not_load_bearing():
    """Perturbing a declared field must silence an honest rule and FIRE once
    the engine stops consulting that field."""
    for rid, field, key in (
        (RULE_ROOT_LOGIN, "unmapped.cloud.identity_type",
         "root_login_no_mfa.unmapped.cloud.identity_type"),
        (RULE_ROOT_LOGIN, "unmapped.cloud.mfa_used",
         "root_login_no_mfa.unmapped.cloud.mfa_used"),
    ):
        rules = fresh_rules()
        rule = rules[rid]
        fixture = _fixture_for(rule)
        if fixture is None:
            continue

        honest = fc._near_miss_probe(rule, fixture)
        check(honest.get("probes", {}).get(key, {}).get("status") == "held",
              f"{rid}: honest rule did not hold its {key} near-miss "
              f"({honest.get('probes', {}).get(key)})")

        check(_make_predicate_ignored(rule, field),
              f"{rid}: test could not drop {field} from the compiled selections")
        mutant = fc._near_miss_probe(rule, fixture)
        check(mutant.get("probes", {}).get(key, {}).get("status") == "fired",
              f"{rid}: near-miss probe stayed silent on a rule that no longer "
              f"consults its declared {field} -- the probe cannot detect a "
              f"predicate that is not load-bearing")
        check(key in mutant.get("too_loose", []),
              f"{rid}: {key} fired but was not reported in too_loose")


def test_near_miss_probe_catches_an_ignored_outside_hours_predicate():
    """The time-of-day case, called out separately because it is the one the
    POSITIVE check is structurally blind to: a rule that ignores its
    `outside_hours` predicate entirely still fires on its own off-hours
    fixture, indistinguishably from a healthy one. Only stamping an in-hours
    timestamp and demanding silence separates them."""
    rules = fresh_rules()
    rule = rules[RULE_N8N_AFTER_HOURS]
    fixture = _fixture_for(rule)
    if fixture is None:
        return
    key = "workflow_change.time[outside_hours]"

    honest = fc._near_miss_probe(rule, fixture)
    check(honest.get("probes", {}).get(key, {}).get("status") == "held",
          f"{RULE_N8N_AFTER_HOURS}: honest rule fired on an in-hours timestamp "
          f"({honest.get('probes', {}).get(key)})")

    check(_make_predicate_ignored(rule, "time"),
          f"{RULE_N8N_AFTER_HOURS}: test could not drop the time predicate")
    mutant = fc._near_miss_probe(rule, fixture)
    check(mutant.get("probes", {}).get(key, {}).get("status") == "fired",
          f"{RULE_N8N_AFTER_HOURS}: an in-hours event did not fire a rule that "
          f"stopped consulting its outside_hours predicate -- the probe cannot "
          f"detect an ignored time-of-day window")


def test_near_miss_probe_declines_a_non_conjunctive_condition():
    """Under `or`, violating one predicate legitimately leaves the rule firing.
    Probing anyway would report a healthy rule as too loose, so the probe must
    decline -- and say why, since 'inapplicable' is what a reader sees later."""
    rules = fresh_rules()
    rule = rules[RULE_ROOT_LOGIN]
    fixture = _fixture_for(rule)
    if fixture is None:
        return
    rule._condition_tokens = ["root_login_no_mfa", "or", "root_login_no_mfa"]
    probe = fc._near_miss_probe(rule, fixture)
    check(probe.get("applicable") is False,
          f"{RULE_ROOT_LOGIN}: near-miss probe ran on an OR condition, where "
          f"single-predicate necessity does not hold")
    check("conjunction" in (probe.get("reason") or ""),
          f"{RULE_ROOT_LOGIN}: declined an OR condition without saying why "
          f"({probe.get('reason')})")


def test_near_miss_probe_declines_an_or_condition_named_like_a_selection():
    """The unsafe direction of `_is_pure_conjunction`, pinned.

    A selection literally named `or` makes the `or` TOKEN satisfy a plain
    `token in rule.selections` test, so a genuinely disjunctive condition
    classifies as a conjunction and the probe demands silence from a rule
    whose other disjunct legitimately still matches -- reporting a healthy
    rule as too loose. No shipped rule has that shape, which is exactly why
    it needs a test rather than an assumption."""
    rules = fresh_rules()
    rule = rules[RULE_ROOT_LOGIN]
    fixture = _fixture_for(rule)
    if fixture is None:
        return
    rule.selections = dict(rule.selections)
    rule.selections["or"] = {"class_uid": 3002}
    rule._condition_tokens = ["root_login_no_mfa", "or", "or"]
    check(fc._is_pure_conjunction(rule) is False,
          f"{RULE_ROOT_LOGIN}: a condition joined by OR was classified as a pure "
          f"conjunction because a selection is named 'or'")


def test_near_miss_probe_requires_its_positive_control():
    """Silence is only evidence when this harness can demonstrably fire the
    rule. A rule that never matches would otherwise report every predicate as
    'held' -- all-green from a rule that does nothing at all, the exact
    vacuous pass the stateful probes share `_replay` to avoid."""
    rules = fresh_rules()
    rule = rules[RULE_ROOT_LOGIN]
    fixture = _fixture_for(rule)
    if fixture is None:
        return
    rule.evaluate = lambda event: False
    probe = fc._near_miss_probe(rule, fixture)
    check(probe.get("applicable") is False,
          f"{RULE_ROOT_LOGIN}: near-miss probe reported verdicts for a rule that "
          f"cannot fire at all -- every 'held' below would be vacuous")
    check("positive control" in (probe.get("reason") or ""),
          f"{RULE_ROOT_LOGIN}: declined without naming the positive control "
          f"({probe.get('reason')})")


def test_gate_exits_nonzero_end_to_end_on_a_stateless_rule_ignoring_a_predicate():
    """Same end-to-end argument as the stateful too-loose test: every layer
    below can be right while `main()` still exits 0. The near-miss verdicts
    have to reach the exit code and the failure output."""
    real_detector = fc.Detector

    def mutated_detector(*args, **kwargs):
        detector = real_detector(*args, **kwargs)
        for r in detector.rules:
            if r.id == RULE_ROOT_LOGIN:
                _make_predicate_ignored(r, "unmapped.cloud.mfa_used")
        return detector

    fc.Detector = mutated_detector
    try:
        rc, out = _run_main_capturing()
    finally:
        fc.Detector = real_detector

    check(rc == 1, f"gate exited {rc} with a stateless rule that ignores a "
                   f"declared predicate; expected 1")
    check("fire BELOW their declared boundary" in out,
          "gate did not report the near-miss failure in its failure output")
    tail = out.split("fire BELOW their declared boundary")[-1]
    check(RULE_ROOT_LOGIN in tail, f"gate failure output did not name {RULE_ROOT_LOGIN}")
    check("not load-bearing" in tail,
          "gate failure output did not attribute the failure to a near-miss probe")


def _run_main_capturing() -> tuple[int, str]:
    """main() with stdout captured and the JSON artifact redirected to a temp
    dir, so a test can never overwrite eval/attack/out/fire_check.json."""
    buf = io.StringIO()
    with tempfile.TemporaryDirectory() as tmp:
        real_out, fc.OUT_DIR = fc.OUT_DIR, Path(tmp)
        try:
            with contextlib.redirect_stdout(buf):
                rc = fc.main()
        finally:
            fc.OUT_DIR = real_out
    return rc, buf.getvalue()


def test_gate_fails_when_zero_rules_are_checked():
    """The real 'the suite silently stopped testing anything' failure.

    Every check in main() is vacuously true over an empty result list, so
    without a count floor the run prints "all 0 MITRE-tagged rules fire" and
    exits 0 -- and the liveness canary is GREEN throughout, because the
    fixtures and the evaluate() path are both fine. It is the rule set that
    vanished. Reachable in practice: load_rules() on a missing directory
    returns [] without raising, and a rename of the `mitre:` key would make
    every rule skip the tagged-rule filter."""
    real_detector = fc.Detector

    class NoRules(real_detector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.rules = []

    fc.Detector = NoRules
    try:
        rc, out = _run_main_capturing()
    finally:
        fc.Detector = real_detector
    check(rc == 1,
          f"gate exited {rc} having checked ZERO rules -- a suite that tests "
          f"nothing must not pass")
    check("ZERO MITRE-tagged rules were checked" in out,
          "gate did not explain that zero rules were checked")


def test_gate_fails_when_every_rule_loses_its_mitre_block():
    """Same blind spot by a different route: the rules load fine but no longer
    carry a `mitre:` block (schema key renamed), so every one is skipped by
    the tagged-rule filter and the results list is empty."""
    real_detector = fc.Detector

    class Untagged(real_detector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            for r in self.rules:
                r.raw = {k: v for k, v in r.raw.items() if k != "mitre"}

    fc.Detector = Untagged
    try:
        rc, out = _run_main_capturing()
    finally:
        fc.Detector = real_detector
    check(rc == 1,
          f"gate exited {rc} when no rule carried a mitre: block -- zero rules "
          f"were actually checked")
    check("ZERO MITRE-tagged rules were checked" in out,
          "gate did not explain that zero rules were checked")


def test_unverified_and_untagged_rules_are_warned_not_claimed_passing():
    """R3-#39 + NEW-hunt (2026-08-27): a rule negatively verified by NEITHER
    half, and a rule with NO mitre.technique, used to be silently invisible
    under an `[OK] n rule(s)` line -- the exact 'nothing tested, looks green'
    shape this repo keeps killing. Both must now surface as [WARN] and be
    counted UNVERIFIED, never claimed *passing*, while the positive fire check
    still holds (rc stays 0 on the real set -- these are open gaps, not
    failures, and the gate's exit-0 pinning makes that explicit)."""
    rc, out = _run_main_capturing()
    check(rc == 0, f"real rule set must still exit 0 (unverified != failed), got {rc}")
    check("[WARN]" in out, "unverified/untagged rules must be [WARN]ed, not [OK]ed")
    check("UNVERIFIED" in out.upper(),
          "unverified rules must be labelled UNVERIFIED, not claimed passing")
    # The old bug line opened with "[OK] {n} rule(s) negatively verified by
    # NEITHER half" -- its exact wording must be gone.
    check("negatively verified by NEITHER half -- untested, not passing -- see"
          not in out, "the old [OK]-under-unverified phrasing must be gone")
    check("NO mitre.technique" in out,
          "rules without a mitre.technique must be named as UNVERIFIED, not "
          "silently `continue`d past")


def test_canary_is_green_while_zero_rules_are_checked():
    """Pins the canary's real scope, so nobody re-derives the claim this
    replaced: the canary passes in the zero-rule scenario. It probes the
    EVENT side of the harness, never the rule side. The count floor is what
    catches that failure; the canary is for attribution."""
    ok, _ = fc._canary_check(events())
    check(ok is True,
          "canary should be green with a healthy fixture pipeline regardless "
          "of how many rules loaded -- if this changed, the scope note in "
          "_canary_check's docstring is now wrong")


def test_canary_does_not_mutate_the_shared_template():
    """`Rule(dict(template))` is a SHALLOW copy sharing `detection`/`siem`.
    Nothing mutates them today, but this repo already contains the write
    pattern that would (rule.raw.setdefault("detection", {})[...] = ...), and
    a poisoned template would silently change the canary for the whole
    process."""
    before = copy.deepcopy(fc._CANARY_RULE_RAW)
    r = fc.Rule(copy.deepcopy(fc._CANARY_RULE_RAW))
    r.raw.setdefault("detection", {})["injected"] = {"x": 1}
    check(fc._CANARY_RULE_RAW == before,
          f"constructing a canary and writing to its raw mutated the shared "
          f"template: {fc._CANARY_RULE_RAW}")


def test_canary_fires_on_the_real_fixture_set():
    """The liveness canary must pass on the tree as it stands -- otherwise it
    is not a canary, it is a permanently-red light nobody will look at."""
    ok, note = fc._canary_check(events())
    check(ok is True, f"canary failed on the real fixture set: {note}")


def test_canary_detects_an_empty_fixture_pipeline():
    """The failure this exists for: the fixture loader silently returns
    nothing. Every rule would then be 'untested' or 'silent' and look exactly
    like today's honest 14-stateless-untested result."""
    ok, note = fc._canary_check([])
    check(ok is False,
          "canary passed on an EMPTY fixture set -- it cannot detect the "
          "fixture pipeline going dark, which is its entire purpose")
    check("no real fixture events" in note,
          f"canary gave a misleading reason for an empty fixture set: {note}")


def test_canary_detects_a_broken_evaluate_path():
    """The other failure: fixtures load fine but Rule.evaluate() regressed.
    Constructed by making the canary's own evaluate() return False, which is
    what a regression below the rule layer would look like from here."""
    real_rule_cls = fc.Rule

    class DeadRule(real_rule_cls):
        def evaluate(self, event):
            return False

    fc.Rule = DeadRule
    try:
        ok, note = fc._canary_check(events())
    finally:
        fc.Rule = real_rule_cls
    check(ok is False,
          "canary passed while Rule.evaluate() returned False for everything "
          "-- it cannot detect the evaluation path going dark")
    check("canary rule did not fire" in note,
          f"canary gave a misleading reason for a dead evaluate(): {note}")


def test_canary_is_independent_of_event_content():
    """A canary that depends on fixture shape would flake as parsers evolve
    and get misread as 'a rule broke'. It must fire on anything, including an
    empty dict -- no field, no timestamp, no tenant."""
    canary = fc.Rule(dict(fc._CANARY_RULE_RAW))
    for shape in ({}, {"x": 1}, {"time": 0}, {"src_endpoint": {"ip": "1.2.3.4"}}):
        check(canary.evaluate(shape) is True,
              f"canary failed to fire on {shape!r} -- it has an accidental "
              f"dependency on event content and will flake")
    check(canary.stateful is False,
          "canary became stateful -- it would then depend on window/threshold "
          "state and stop being a pure liveness signal")


def test_canary_is_not_mistaken_for_a_real_tagged_rule():
    """It must never be counted in the MITRE numbers it exists to protect."""
    check(not isinstance(fc._CANARY_RULE_RAW.get("mitre"), dict),
          "canary carries a mitre: block and would be counted as a real "
          "tagged rule in the scorecard")
    rules = fresh_rules()
    check(fc._CANARY_RULE_RAW["id"] not in rules,
          "canary id collides with a real rule loaded from contracts/rules/")


def main():
    rules = fresh_rules()
    for rid in (RULE_BRUTE, RULE_MASS_CARD, RULE_ROOT_LOGIN, RULE_N8N_AFTER_HOURS):
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
    test_replay_reports_a_fire_on_any_event_not_just_the_last()
    test_stateless_rules_are_near_miss_probed_not_threshold_probed()
    test_near_miss_probe_catches_a_predicate_that_is_not_load_bearing()
    test_near_miss_probe_catches_an_ignored_outside_hours_predicate()
    test_near_miss_probe_declines_a_non_conjunctive_condition()
    test_near_miss_probe_declines_an_or_condition_named_like_a_selection()
    test_near_miss_probe_requires_its_positive_control()
    test_gate_exits_nonzero_end_to_end_on_a_stateless_rule_ignoring_a_predicate()
    test_gate_fails_when_zero_rules_are_checked()
    test_gate_fails_when_every_rule_loses_its_mitre_block()
    test_unverified_and_untagged_rules_are_warned_not_claimed_passing()
    test_canary_is_green_while_zero_rules_are_checked()
    test_canary_does_not_mutate_the_shared_template()
    test_canary_fires_on_the_real_fixture_set()
    test_canary_detects_an_empty_fixture_pipeline()
    test_canary_detects_a_broken_evaluate_path()
    test_canary_is_independent_of_event_content()
    test_canary_is_not_mistaken_for_a_real_tagged_rule()

    if FAILS:
        print(f"[FAIL] eval/attack/fire_check.py boundary probes: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] fire_check negative probes: stateful half is sensitive to a "
          "one-event and a 10% window error; stateless half catches a declared "
          "predicate (including an outside_hours window) the engine stops "
          "consulting, declines OR conditions and rules with no positive "
          "control; the gate exits 1 end-to-end on either kind of too-loose "
          "rule and 0 on the real rule set, probes are tenant-isolated, and "
          "partly/fully skipped rules are reported untested rather than held")


if __name__ == "__main__":
    main()
