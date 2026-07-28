"""P3-2 follow-up (M7, 2026-07-22) -- empirical MITRE firing proof.

``coverage_layer.py`` (in this same directory) proves a rule CLAIMS a
technique (parses its `mitre:` block). It says nothing about whether the
rule actually FIRES. This tool closes that specific, narrow gap: for every
rule carrying a `mitre:` tag, replay its own anti-dormancy producer fixture
(the same real parser -> enrich pipeline `tools/check_rule_producers.py`
already proves is satisfiable) through the real WS-4 `Rule.evaluate()` and
record whether it actually fires.

**What this proves, and what it does not** (read before citing this
anywhere): a rule firing on ITS OWN fixture proves the rule's condition/
threshold logic is not dead code. It does NOT prove the rule fires on real-
world attack traffic, evasive variants, or a live-Docker/Redis-backed
window counter under concurrent load -- that empirical, corpus-driven
validation is `eval/detection_accuracy/`'s job (EVTX/Splunk oracle replay),
unchanged and not conflated with this tool.

It also does not exercise the ROUTING that reaches `evaluate()`. `Detector`
is used here as a rule loader; `Rule.evaluate()` is called directly, so
`Detector.process()`'s `class_uid` prefilter buckets and per-tenant rule
disable are bypassed. A rule mis-bucketed into a `class_uid` no event
carries -- the exact defect class `engine.py`'s `_bucketable_class_uid()`
records as found-in-review -- still reports FIRED here. Say "its condition
fires", not "it fires in the pipeline". See
`docs/superpowers/specs/2026-07-22-mitre-fire-check.md` for the full design
note and this distinction stated in one place.

Stateful rules (window_seconds+threshold, optionally distinct_field or
periodicity) are fed the same-shaped event `threshold` times with a fresh
`ingest_id` (window dedup is keyed on it) and, for `distinct_field` rules, a
distinct value per repetition; timestamps step backward evenly inside the
rule's window so `periodicity` rules (coefficient-of-variation) see a
low-jitter cadence, mirroring `test_v05_beaconing.py`'s own fixture shape.

**Boundary (negative) probes.** Firing AT the threshold only proves the rule
is not dead. A rule that is too LOOSE -- off-by-one on the count, a window
wider than declared -- fires at threshold too, passes the satisfiability
gate too, and is invisible to both; it surfaces months later as unexplained
false-positive volume that nobody traces back to the rule. So every stateful
rule that fires is also replayed at `threshold - 1` events in-window, and at
a full `threshold` events spaced past `window_seconds`, and must stay silent
for both.

Two properties of that negative half are load-bearing:

  * It shares `_replay` with the positive check. A negative assertion is
    only meaningful when the same harness demonstrably CAN fire the rule --
    otherwise a harness that silently drops events (exactly the clock-skew
    bug noted above, which made two healthy rules look dead) reports GREEN,
    because "did not fire" is indistinguishable from "was never exercised".
    The positive replay is the control; keep them on one code path.
  * A silent negative is only scored as a pass when it is unambiguous. For
    an `outside_hours` rule whose replay would drift across its business-
    hours boundary, silence has two possible causes and the probe reports
    "skipped" rather than claiming a boundary it did not test.

Stateless rules are NOT boundary-tested: the near-miss of a single-event
field match is the entire rest of the value space, so no near-miss fixture
is generatable and each one has to be hand-authored. They are reported as
untested rather than counted as passing.

Run: python eval/attack/fire_check.py
     make attack-scorecard   (fire_check runs alongside coverage_layer.py)
"""
from __future__ import annotations

import copy
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVICES = ROOT / "services"
sys.path.insert(0, str(SERVICES / "ws2-normalization"))
sys.path.insert(0, str(SERVICES / "ws4-detection"))
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(ROOT / "tools"))

from parsers import _REGISTRY  # noqa: E402
from enrichment import enrich  # noqa: E402
from main import Detector  # noqa: E402  -- ws4-detection's real Detector
from engine import _time_outside_hours  # noqa: E402  -- reuse the engine's own predicate
import check_rule_producers as crp  # noqa: E402  -- reuse the same FIXTURES

OUT_DIR = Path(__file__).resolve().parent / "out"


def _set_path(event: dict, dotted: str, value: object) -> None:
    """Write ``value`` at a dotted path, creating intermediate dicts as
    needed -- the write-side counterpart to engine.get_path's read-only
    traversal, used only to vary a distinct_field's value per repetition."""
    node = event
    parts = dotted.split(".")
    for part in parts[:-1]:
        nxt = node.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            node[part] = nxt
        node = nxt
    node[parts[-1]] = value


def _real_events() -> list[dict]:
    """One real (post-parse, post-enrich) event per fixture, same source as
    check_rule_producers.py's own ground truth -- not a separate, drifting
    fixture set."""
    events = []
    for source_type, raws in crp.FIXTURES.items():
        parser = _REGISTRY.get(source_type)
        if parser is None:
            continue
        for raw in raws:
            event = parser.parse({"source_type": source_type, **raw})
            if event is not None:
                events.append(enrich(event))
    return events


def _outside_hours_specs(rule) -> list[tuple[str, dict]]:
    """[(dotted_field, spec)] for every ``outside_hours`` predicate in the
    rule's selections -- empty for rules with no time-of-day predicate.

    Such a rule ONLY fires when its driving field falls OUTSIDE the configured
    business-hours window, so the harness must stamp an off-hours timestamp
    deterministically. Otherwise a stateless rule inherits the fixture's
    parse-time "now" and the whole gate flips green/red by the wall clock:
    fire on a weekend/night CI run, "SILENT" (false defect) on a weekday-
    daytime run. That is exactly the flake this function exists to kill."""
    specs: list[tuple[str, dict]] = []
    detection = rule.raw.get("detection", {})
    if isinstance(detection, dict):
        for name, sel in detection.items():
            if name == "condition" or not isinstance(sel, dict):
                continue
            for field, ops in sel.items():
                if isinstance(ops, dict) and "outside_hours" in ops:
                    specs.append((field, ops["outside_hours"]))
    return specs


def _outside_hours_anchor(spec: dict) -> int:
    """A deterministic epoch-ms instant that is BOTH in the past (accepted by
    the engine's P0 anti-poisoning guard -- past timestamps always pass) AND
    outside ``spec``'s window, verified with the engine's OWN
    ``_time_outside_hours`` so it can never drift from the predicate it must
    satisfy. Steps back hour by hour from now; any business-hours window
    leaves most of the week outside, so this resolves within a few days."""
    now = int(time.time() * 1000)
    for hours_back in range(1, 8 * 24 + 1):
        ts = now - hours_back * 3_600_000
        if _time_outside_hours(spec, ts):
            return ts
    return now - 3 * 24 * 3_600_000  # unreachable for any real window; safe past fallback


def _oh_anchors(rule, span_ms: int) -> list[tuple[str, int]] | None:
    """[(dotted_field, epoch_ms)] to stamp for this rule's ``outside_hours``
    predicates, or None if no anchor exists that keeps a ``span_ms``-long
    replay off-hours for its whole length.

    The span matters because a replay is not an instant. An anchor that is
    itself off-hours can still have its OLDEST event land back inside
    business hours, and then the rule legitimately does not match -- which,
    in a negative probe, is indistinguishable from the threshold correctly
    holding, and in the POSITIVE replay looks like a dead rule. Searching for
    an anchor whose entire span stays off-hours removes that ambiguity at the
    source instead of detecting it afterwards.

    Sampled every 60s across the span: `_time_outside_hours` specs are
    expressed in whole hours, so a minute-granularity sweep cannot step over
    a business-hours sliver. Returning None is a HARNESS limitation (the
    rule's off-hours span is shorter than the replay needs), never evidence
    about the rule -- callers must report it as such."""
    anchors: list[tuple[str, int]] = []
    for field, spec in _outside_hours_specs(rule):
        # Only the `time` field is stepped across a replay; every other
        # outside_hours field is stamped identically on each event, so it
        # needs no span clearance.
        needed = span_ms if field == "time" else 0
        now = int(time.time() * 1000)
        found = None
        for hours_back in range(1, 8 * 24 + 1):
            ts = now - hours_back * 3_600_000
            offsets = list(range(0, needed + 1, 60_000))
            if needed and offsets[-1] != needed:
                offsets.append(needed)
            if all(_time_outside_hours(spec, ts - o) for o in offsets):
                found = ts
                break
        if found is None:
            return None
        anchors.append((field, found))
    return anchors


def _replay(rule, base_event: dict, reps: int, step_ms: int,
            tag: str) -> bool | None:
    """Feed ``reps`` copies of ``base_event`` through the real
    ``Rule.evaluate()`` at ``step_ms`` spacing; return whether ANY of them
    fired, or None if an off-hours anchor for the whole span could not be
    constructed (a harness limitation, not a result about the rule).

    ANY, not the last one: a rule that fires partway through a replay that
    was supposed to stay silent is exactly the too-loose defect being hunted,
    and reporting only the final verdict would discard it. In-window counts
    are monotone for count/distinct rules so the two agree there, but a
    `periodicity` rule gates on a coefficient of variation that is NOT
    monotone, so an intermediate fire is reachable in principle.

    Every check in this file -- the positive one and both negative ones --
    goes through this one function, varying only ``reps``/``step_ms``. That
    is deliberate: a negative check ("did NOT fire") is only meaningful if
    the identical harness demonstrably CAN make this rule fire, so the
    positive replay is the control for the negative ones and must not be a
    separate code path that could drift from them. Note the limit of that
    argument: it makes the two share a FUNCTION, not a call site, so it
    cannot protect against a caller that stops invoking a probe at all --
    `test_fire_check.py` covers that separately by requiring the gate to go
    red end-to-end on a mutated rule.

    ``tag`` namespaces the replay via the synthetic ``siem.tenant``. The
    engine's window counter is keyed ``{rule id}:{tenant}:{group}`` and lives
    on the Rule instance, so without this every check would inherit the
    previous check's in-window events -- the under-threshold probe would see
    the positive probe's counts and "fire", reporting a defect that is purely
    harness state leakage. Tenant is used by the engine ONLY for that key and
    for alert_id; it never participates in condition evaluation, so isolating
    on it cannot change whether the rule's condition matches."""
    anchors = _oh_anchors(rule, (reps - 1) * step_ms)
    if anchors is None:
        return None
    time_anchor = next((a for f, a in anchors if f == "time"), None)
    # Engine._valid_window_time fail-closes any timestamp more than 5min
    # ahead of wall-clock (P0 anti-poisoning guard) -- an earlier version of
    # this loop stepped FORWARD from the fixture's own (already "now")
    # timestamp and silently tripped that guard on every rep past the first,
    # which is why this comment exists. Step BACKWARD so every synthetic
    # timestamp is in the past (always accepted).
    base_ms = time_anchor if time_anchor is not None else int(time.time() * 1000)
    fired = False
    for i in range(reps):
        ev = copy.deepcopy(base_event)
        siem = ev.setdefault("siem", {})
        siem["ingest_id"] = f"firecheck:{rule.id}:{tag}:{i}"
        siem["tenant"] = f"firecheck-{tag}"
        ev["time"] = base_ms - (reps - 1 - i) * step_ms
        for field, anchor in anchors:
            if field != "time":
                _set_path(ev, field, anchor)
        if rule.distinct_field:
            _set_path(ev, rule.distinct_field, f"firecheck-value-{i}")
        fired = rule.evaluate(ev) or fired
    return fired


def _positive_step_ms(rule, reps: int) -> int:
    """Spacing that packs ``reps`` events well inside the rule's own window,
    evenly enough that a periodicity rule sees a low-jitter cadence.

    Deliberately NOT floored at 1s. A 1s floor silently breaks any rule with
    `threshold > window_seconds + 1` (e.g. 12 events in a 10s window): the
    replay would span past the rule's own window, the positive check would
    report a healthy rule as dead-on-arrival, and the failure would be
    attributed to the rule rather than to this line. No shipped rule is that
    dense -- the tightest is 40-in-60s -- but the trap costs nothing to
    remove and `test_fire_check.py` pins the span-fits-in-window property
    over a grid of (window, threshold) shapes."""
    window_ms = int((rule.window_seconds or 60) * 1000)
    return max(1, window_ms // (2 * max(reps, 1)))


def _overrun_step_ms(rule, reps: int) -> int:
    """Spacing that puts ``reps`` events' TOTAL span just past the rule's
    window, so an honest rule sees the oldest fall out and counts one short.

    The margin is 1% of the window (min 1s), i.e. deliberately small: this is
    a boundary probe, and a rule whose window is off by a little is the case
    worth catching. The ``+ 1`` guarantees the span strictly exceeds the
    window after integer division, so the probe can never accidentally sit
    exactly ON the horizon, where the counter's ``<`` comparison keeps the
    oldest event and an honest rule would fire."""
    window_ms = int((rule.window_seconds or 60) * 1000)
    span_ms = window_ms + max(1000, window_ms // 100)
    return span_ms // (reps - 1) + 1


def _try_fire(rule, events: list[dict]) -> tuple[bool, str, dict | None, bool]:
    """(fired, note, fixture_event, harness_blocked) -- replay real events
    against one rule until it fires or the fixtures are exhausted. The
    returned event is the one that fired, so the boundary probes can re-use
    the exact fixture the positive result was established on.

    ``harness_blocked`` distinguishes "this rule does not fire" (a real
    dead-on-arrival defect) from "this harness could not construct a replay
    that would let it fire" -- for an outside_hours rule whose off-hours span
    is shorter than its own window, every replay drifts into business hours
    and the rule cannot match no matter how healthy it is. Both are failures,
    but attributing the second to the rule would send someone hunting a bug
    that is in this file."""
    blocked = False
    for idx, base_event in enumerate(events):
        if not rule.stateful:
            anchors = _oh_anchors(rule, 0)
            if anchors is None:
                blocked = True
                continue
            ev = copy.deepcopy(base_event)
            for field, anchor in anchors:
                _set_path(ev, field, anchor)
            if rule.evaluate(ev):
                return True, "fired on a single real event (stateless rule)", base_event, False
            continue

        reps = rule.threshold or 1
        outcome = _replay(rule, base_event, reps, _positive_step_ms(rule, reps), f"pos{idx}")
        if outcome is None:
            blocked = True
            continue
        if outcome:
            kind = ("periodicity" if rule.periodicity else
                    "distinct-count" if rule.distinct_field else "count")
            return True, f"fired within {reps} events on its own window ({kind}, stateful)", base_event, False
    if blocked:
        return (False, "HARNESS could not construct an off-hours replay that stays "
                       "off-hours for this rule's whole window -- no evidence about "
                       "the rule either way", None, True)
    return False, "never fired on any of its own real fixture events", None, False


def _boundary_probe(rule, base_event: dict | None) -> dict:
    """Negative half of the gate: the rule fires AT its threshold (proven by
    _try_fire) -- prove it does NOT fire just below it.

    Two probes, both replayed through the same ``_replay`` as the positive:

      * under_threshold -- ``threshold - 1`` events inside the window. Catches
        a rule that is too LOOSE (off-by-one on the count), which the
        satisfiability gate and the positive fire check both pass silently
        and which surfaces months later as unexplained false-positive volume
        rather than as a dead rule.
      * window_overrun -- a full ``threshold`` events spread so their total
        span lands JUST past ``window_seconds``, putting the oldest one a
        hair outside the horizon when the newest arrives, so an honest rule
        counts ``threshold - 1``. Catches a window wider than declared.
        Spacing them ``window + 1s`` apart instead (the obvious construction)
        is a far blunter instrument: the run then only fits inside the window
        if the engine's window is roughly ``threshold`` times too wide, so it
        cannot see the off-by-a-little case at all on a high-threshold rule.

    Each probe reports a structured ``{"status": ..., "detail": ...}`` with
    status one of "held" (correctly silent), "fired" (defect), "skipped"
    (could not be run). Status is a machine field precisely so the gate's
    FAILING path is not selected by matching human-readable prose -- an
    earlier version compared the failure verdict against the exact string
    "FIRED" while the passing verdict used a prefix match, so editing the
    failure message would have quietly disarmed the gate while every test
    stayed green. The fragile comparison was guarding the wrong side.

    Stateless rules get no probe at all -- the near-miss of a single-event
    field match is the whole rest of the value space, so there is no
    generatable near-miss fixture; that needs a hand-authored one per rule
    and is honestly reported as untested rather than counted as passing."""
    if not rule.stateful:
        return {"applicable": False,
                "reason": "stateless rule -- near-miss undefined without a "
                          "hand-authored fixture; not boundary-tested"}
    if base_event is None:
        return {"applicable": False,
                "reason": "rule never fired -- no fixture to probe the boundary with"}

    reps = rule.threshold or 1
    probes: dict[str, dict] = {}

    if reps < 2:
        probes["under_threshold"] = {
            "status": "skipped",
            "detail": "threshold is 1, no sub-threshold count exists"}
    else:
        step_ms = _positive_step_ms(rule, reps)
        outcome = _replay(rule, base_event, reps - 1, step_ms, "under")
        if outcome is None:
            probes["under_threshold"] = {
                "status": "skipped",
                "detail": "no off-hours anchor holds for the sub-threshold span"}
        else:
            probes["under_threshold"] = {
                "status": "fired" if outcome else "held",
                "detail": f"{reps - 1} event(s) in-window vs a threshold-{reps} rule"
                          + (" -- degenerate: a threshold-2 rule's sub-threshold "
                             "case is a single event" if reps == 2 else "")}

    if reps < 2:
        probes["window_overrun"] = {
            "status": "skipped",
            "detail": "threshold is 1, a single event needs no window"}
    else:
        overrun_ms = _overrun_step_ms(rule, reps)
        outcome = _replay(rule, base_event, reps, overrun_ms, "overrun")
        if outcome is None:
            probes["window_overrun"] = {
                "status": "skipped",
                "detail": "no off-hours anchor holds for the overrun span"}
        else:
            span_s = overrun_ms * (reps - 1) / 1000
            probes["window_overrun"] = {
                "status": "fired" if outcome else "held",
                "detail": f"{reps} events spanning {span_s:g}s vs a "
                          f"window_seconds={rule.window_seconds} rule"}

    held = [n for n, v in probes.items() if v["status"] == "held"]
    skipped = [n for n, v in probes.items() if v["status"] == "skipped"]
    # A rule counts as having held its boundary only when EVERY probe ran and
    # held. Partial coverage (one held, one skipped) is its own category: the
    # headline sentence claims both probes stayed silent, so counting a
    # half-probed rule there would make the sentence false for that rule --
    # the quiet way a coverage number drifts away from what it says.
    return {"applicable": True, "probes": probes,
            "held": held, "skipped": skipped,
            "fully_held": bool(held) and not skipped,
            "too_loose": [n for n, v in probes.items() if v["status"] == "fired"]}


def main() -> int:
    events = _real_events()
    detector = Detector(plugin_rule_dirs=[])

    results = []
    for rule in detector.rules:
        mitre = rule.raw.get("mitre")
        if not isinstance(mitre, dict) or not mitre.get("technique"):
            continue  # coverage_layer.py already reports undeclared rules
        fired, note, fixture, blocked = _try_fire(rule, events)
        results.append({
            "id": rule.id, "title": rule.title,
            "framework": mitre.get("framework", "attack"),
            "tactic": mitre.get("tactic"), "technique": mitre["technique"],
            "fired": fired, "note": note, "harness_blocked": blocked,
            "boundary": _boundary_probe(rule, fixture),
        })

    tagged_not_firing = [r for r in results if not r["fired"] and not r["harness_blocked"]]
    harness_blocked = [r for r in results if r["harness_blocked"]]
    too_loose = [r for r in results if r["boundary"].get("too_loose")]
    fully_held = [r for r in results if r["boundary"].get("fully_held")]
    # Partly probed = at least one probe held and at least one was skipped.
    # Not counted as having held its boundary: the headline sentence claims
    # BOTH probes stayed silent, and for a half-probed rule that is false.
    partly_held = [r for r in results
                   if r["boundary"].get("held") and r["boundary"].get("skipped")]
    untested = len(results) - len(fully_held)

    print(f"MITRE empirical firing check -- {len(results)} tagged rule(s) checked "
          f"against their own real producer fixtures (declared-vs-fired, not "
          f"real-world validation -- see this file's module docstring)")
    for r in sorted(results, key=lambda r: r["id"] or ""):
        mark = "FIRED " if r["fired"] else "SILENT"
        print(f"  [{mark}] {r['technique']:<10} {r['id']}: {r['note']}")
        for name, verdict in r["boundary"].get("probes", {}).items():
            print(f"           |- {name}: {verdict['status']} -- {verdict['detail']}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "fire_check.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nwrote {out_path}")

    if harness_blocked:
        print(f"\n[FAIL] {len(harness_blocked)} rule(s) could not be exercised by "
              f"THIS HARNESS -- the defect is in fire_check.py, not in the rule; "
              f"do not go hunting the rule:")
        for r in harness_blocked:
            print(f"    {r['id']} ({r['technique']}): {r['note']}")
        return 1

    if tagged_not_firing:
        print(f"\n[FAIL] {len(tagged_not_firing)} rule(s) declare a MITRE technique "
              f"but never fire on their own producer fixture -- a real defect "
              f"(dead-on-arrival detection), not silently passed:")
        for r in tagged_not_firing:
            print(f"    {r['id']} ({r['technique']}): {r['note']}")
        return 1

    if too_loose:
        print(f"\n[FAIL] {len(too_loose)} rule(s) fire BELOW their declared "
              f"boundary -- too loose, which the satisfiability gate and the "
              f"positive fire check both pass silently:")
        for r in too_loose:
            for name in r["boundary"]["too_loose"]:
                print(f"    {r['id']} ({r['technique']}): {name} fired when it must not")
        return 1

    print(f"\n[OK] all {len(results)} MITRE-tagged rules fire on their own real "
          f"producer fixture")
    print(f"[OK] {len(fully_held)} stateful rule(s) also held their boundary "
          f"(threshold-1 AND window-overrun both ran and stayed silent); "
          f"{untested} rule(s) NOT boundary-tested -- untested, not passing"
          + (f", of which {len(partly_held)} had one probe held and one skipped"
             if partly_held else "")
          + " -- see 'boundary' in the JSON")
    return 0


if __name__ == "__main__":
    sys.exit(main())
