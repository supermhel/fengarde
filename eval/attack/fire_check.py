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

Stateless rules get a DIFFERENT negative probe, because they have no
threshold or window to step under. Earlier versions of this file claimed no
near-miss was generatable for them and reported all 15 as untested. That
claim was too strong, and `_near_miss_probe` replaces it: every shipped
stateless rule's condition is a pure conjunction of field predicates, so
violating exactly ONE declared predicate on the fixture that fired must
silence the rule. That is generatable per predicate, not hand-authored.

Read the resulting claim narrowly -- it is single-predicate NECESSITY, not
well-scopedness. It proves each predicate the rule declares is load-bearing
at evaluation time, which catches the too-loose defects that the positive
check passes silently: a condition evaluated as `or` where `and` was
declared, a `not_in` allowlist that is never consulted, an `outside_hours`
window ignored (a rule that ignores time-of-day fires on its own fixture
perfectly), and a compile step that drops a selection field. It proves
nothing about whether the declared predicate SET is the right one -- exactly
the same limit the stateful probes carry on declared thresholds. A predicate
with no constructible violation (an empty `not_in` list, an unknown
operator) is reported skipped, and a rule with any skipped predicate is not
counted as having fully held.

**Two harness-integrity guards, doing different jobs.**

`main()` refuses to report `[OK]` over an empty result set (the count floor).
Every check in this file is vacuously true over zero rules, so a rule set
that failed to load would otherwise print "all 0 MITRE-tagged rules fire"
and exit 0. That is the real "the suite silently stopped testing anything"
failure, and only a count floor catches it -- the canary below is GREEN
throughout it, because the fixtures and the evaluate() path are both healthy;
it is the rules that vanished.

`_canary_check` is about ATTRIBUTION, not detection. A dead fixture pipeline
already turned this gate red before it existed (all 27 tagged rules must
fire, including the 15 stateless ones -- so those DO have a blocking positive
replay of their own, contrary to this docstring's first version). What the
canary changes is that the failure reads "the harness is broken" instead of
"27 rules are dead-on-arrival". See its own docstring for what it does not
cover -- notably partial harness death, where it stays green.

Run: python eval/attack/fire_check.py
     make attack-scorecard   (fire_check runs alongside coverage_layer.py)
"""
from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
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
# Reuse the engine's OWN predicate helpers rather than reimplementing them: a
# near-miss constructor that decided "this value violates the operator" by its
# own logic could disagree with the engine and assert silence for a case the
# engine never considered a match in the first place -- a vacuous probe that
# reports "held". Asking the same functions the engine asks keeps the two from
# drifting.
from engine import (  # noqa: E402
    _contains,
    _glob_match,
    _in_list,
    _time_outside_hours,
    get_path,
    Rule,
)
import check_rule_producers as crp  # noqa: E402  -- reuse the same FIXTURES

OUT_DIR = Path(__file__).resolve().parent / "out"

# Gap-hunt fix (2026-08-26): which distinct values a rule's replays were
# stamped with, per rule id -- "real" (the distinct values really produced by
# the fixture pipeline) or "synthetic" (per-iteration fabricated values, the
# fallback when the real fixtures cannot supply enough distinct values). See
# _distinct_values_for / _replay. Populated only when a distinct_pool was
# passed to the replay, i.e. from main(); direct test calls leave it alone.
_DISTINCT_REPLAY_SOURCE: dict[str, str] = {}


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


def _del_path(event: dict, dotted: str) -> None:
    """Delete a dotted path (the write-removal counterpart to _set_path),
    used by the `exists` near-miss (`{exists: true}` violated by REMOVING the
    field -- PR #80 review finding 5). No-op if an intermediate dict is absent."""
    node = event
    parts = dotted.split(".")
    for part in parts[:-1]:
        nxt = node.get(part)
        if not isinstance(nxt, dict):
            return
        node = nxt
    node.pop(parts[-1], None)


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


# A synthetic rule, never loaded from contracts/rules/*.yml, that exists only
# to answer one question: is this HARNESS still alive? An empty selection
# (`{}`) matches unconditionally in Rule._selection_matches -- the for loop
# over its (zero) keys never runs, so it returns True regardless of the
# event's shape or content. No field, no time-of-day, no fixture-specific
# dependency of any kind: this must fire on every event, on every run,
# forever, or something below Rule.evaluate() itself has broken.
#
# KNOWN COUPLING, deliberate: this shape depends on the engine's empty-dict
# asymmetry -- an empty SELECTION matches everything (fail open) while an
# empty OPERATOR dict returns False (fail closed, _operator_matches). The
# repo's own tools/validate_rules.py rejects this shape for real rule files
# ("an empty selection matches EVERY event") and documents itself as
# "deliberately stricter than the runtime here", i.e. the runtime behaviour
# this canary relies on is already flagged as unintended. If the engine is
# ever hardened to fail closed on an empty selection -- a defensible change
# -- this canary goes permanently red and blocks the whole attack-scorecard
# job. That is loud and correctly attributed, not silent, but whoever makes
# that change must update this fixture (give it a selection that matches a
# field every fixture provably emits) rather than deleting the canary.
_CANARY_RULE_RAW = {
    "id": "firecheck-canary-0000-not-a-real-rule",
    "title": "[internal] fire_check liveness canary -- not a MITRE-tagged rule",
    "level": "info",
    "detection": {"always": {}, "condition": "always"},
    "siem": {},
}


def _canary_check(events: list[dict]) -> tuple[bool, str]:
    """ATTRIBUTION probe for the harness itself, independent of any real
    rule's condition or threshold.

    **What this is and is not.** An adversarial review corrected the original
    claim here, which was wrong and is worth recording: this does NOT close a
    detection blind spot, because there was no blind spot of that shape. Every
    one of the 27 tagged rules -- including all 15 stateless ones -- must fire
    on its own fixture or `main()` returns 1 at `tagged_not_firing`. So the
    stateless rules DO have a blocking positive replay of their own, and a
    dead fixture pipeline or a broken `Rule.evaluate()` already turned the
    gate red before this function existed. Verified by bypassing the canary
    and re-running: exit 1, no "N/N held" line, in every such scenario.

    What it actually buys is ATTRIBUTION, the same class of fix as
    `harness_blocked`: without it a dead harness reports "26 rule(s) declare a
    MITRE technique but never fire -- a real defect (dead-on-arrival
    detection)", sending someone to hunt 26 rule bugs that do not exist. With
    it, the run says the harness is broken and refuses to print rule results
    at all. Cheaper to read, and it cannot be mistaken for a rule regression.

    **It does not catch partial harness death, and that is the likelier
    regression.** If `enrich()` degrades events instead of raising, or one
    parser drops out of `_REGISTRY` while the rest still work, this canary
    stays GREEN (it fires on any event, by design -- that is what keeps it
    flake-free) while real rules are falsely accused of being dead. In that
    scenario the report is arguably worse than without it: a confident
    all-clear beside false accusations. The genuine "suite tested nothing"
    failure -- zero rules reaching the loop -- is caught by the non-zero
    count floor in `main()`, not by this function.

    Two failure conditions, both real and both distinct from "a rule is
    dead": the fixture loader returned nothing (`_real_events()` empty --
    total registry death, fixtures dict empty, enrich() raising), or the
    canary itself did not fire on some real event (Rule construction changed
    shape, `_selection_matches`/`_eval_condition` regressed, `evaluate()`
    itself broke). Either one invalidates every other result in this run,
    which is why main() checks this FIRST and refuses to report rule results
    if it fails -- a "12/12 held" printed alongside a dead harness is worse
    than no number at all.

    Deliberately independent of `_oh_anchors`/wall-clock machinery. A canary
    that could itself flake on the wrong minute would just relocate the exact
    confusion (real defect vs. harness artifact) it exists to eliminate --
    see this file's own clock-skew history above for why that risk is not
    theoretical here."""
    if not events:
        return False, "no real fixture events were loaded at all -- the fixture pipeline itself is broken"
    # deepcopy, not dict(): a shallow copy shares `detection`/`siem` with the
    # module-level template, and this repo already contains the write pattern
    # that would poison it for the rest of the process (test_fire_check.py
    # does rule.raw.setdefault("detection", {})[...] = ... on a real rule).
    canary = Rule(copy.deepcopy(_CANARY_RULE_RAW))
    if not all(canary.evaluate(ev) for ev in events):
        return False, ("the unconditionally-satisfiable canary rule did not fire on every "
                       "real fixture event -- Rule.evaluate() or the fixture pipeline has "
                       "regressed, independent of any real MITRE-tagged rule")
    return True, f"canary fired on all {len(events)} real fixture event(s)"


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

    Both the candidate search and the span sweep step by 60s, and neither
    number is arbitrary:

    * The SEARCH must step by minutes, not hours. Stepping back whole hours
      holds minute-of-hour fixed for the entire search, so for a rule whose
      off-hours span is close to its replay span an anchor exists only if
      the wall clock happens to sit in the right part of the hour -- the
      gate would pass at :35 and report the same healthy rule blocked at
      :05. A 50% CI coin-flip is a worse failure than the false dead-rule
      report this function was written to remove.
    * The SWEEP steps by 60s because specs are `HH:MM` (`_parse_hhmm`) with
      a minute-resolution `tz_offset_minutes` -- NOT whole hours, as an
      earlier version of this comment wrongly claimed. Minute resolution is
      what makes the sweep exact: 60_000ms steps preserve the millisecond
      remainder, so every consecutive minute-of-day inside the span is
      visited and no business-hours sliver can be stepped over. Coarsening
      this to hours would silently hand back anchors whose span crosses a
      window like `09:00-09:30`.

    Returning None is a HARNESS limitation (the rule's off-hours span is
    shorter than the replay needs), never evidence about the rule -- callers
    must report it as such."""
    anchors: list[tuple[str, int]] = []
    for field, spec in _outside_hours_specs(rule):
        # Only the `time` field is stepped across a replay; every other
        # outside_hours field is stamped identically on each event, so it
        # needs no span clearance.
        needed = span_ms if field == "time" else 0
        now = int(time.time() * 1000)
        offsets = list(range(0, needed + 1, 60_000))
        if needed and offsets[-1] != needed:
            offsets.append(needed)
        found = None
        for minutes_back in range(1, 8 * 24 * 60 + 1):
            ts = now - minutes_back * 60_000
            if all(_time_outside_hours(spec, ts - o) for o in offsets):
                found = ts
                break
        if found is None:
            return None
        anchors.append((field, found))
    return anchors


def _distinct_values_for(rule, events: list[dict]) -> list:
    """Distinct REAL values of ``rule.distinct_field`` across the real fixture
    events, first-seen order.

    Gap-hunt fix (2026-08-26): ``_replay`` used to stamp a fresh synthetic
    value per repetition for every distinct-field rule, so the 'fires, fully
    covered' green result was guaranteed by construction -- the distinct
    counter could never be the thing that failed, no matter how wrong the
    rule's ``distinct_field`` was. Where the real fixtures genuinely hold at
    least ``threshold`` distinct values of the field, the replay now uses
    these real values instead. Values are deduped by (type name, value) so a
    bool ``True`` never masquerades as the int ``1`` for counting purposes.
    """
    ordered: list = []
    seen: set = set()
    for e in events:
        v = get_path(e, rule.distinct_field)
        if v is None:
            continue
        try:
            key = (type(v).__name__, v)
        except TypeError:  # unhashable container (list/dict) -- repr it
            key = repr(v)
        if key not in seen:
            seen.add(key)
            ordered.append(v)
    return ordered


def _replay(rule, base_event: dict, reps: int, step_ms: int,
            tag: str, distinct_pool: list | None = None) -> bool | None:
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
            # Gap-hunt fix (2026-08-26): when the caller supplied a pool of
            # REAL distinct values big enough for this replay, stamp the real
            # values (one per repetition; len(pool) >= reps guarantees reps
            # DISTINCT values, which is exactly the counting the rule's
            # threshold is written against). Otherwise fall back to synthetic
            # per-iteration values and record the fallback in
            # _DISTINCT_REPLAY_SOURCE so a caller can report the check as
            # weaker than a fully-real replay instead of a full pass. Direct
            # test calls (distinct_pool=None) keep the historical synthetic
            # behavior and record nothing.
            if distinct_pool is not None and len(distinct_pool) >= reps:
                _set_path(ev, rule.distinct_field,
                          distinct_pool[i % len(distinct_pool)])
                _DISTINCT_REPLAY_SOURCE[rule.id] = "real"
            else:
                _set_path(ev, rule.distinct_field, f"firecheck-value-{i}")
                if distinct_pool is not None:
                    _DISTINCT_REPLAY_SOURCE[rule.id] = "synthetic"
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


def _try_fire(rule, events: list[dict],
              distinct_pool: list | None = None) -> tuple[bool, str, dict | None, bool]:
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
        outcome = _replay(rule, base_event, reps, _positive_step_ms(rule, reps),
                          f"pos{idx}", distinct_pool)
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


def _boundary_probe(rule, base_event: dict | None, blocked: bool = False,
                    distinct_pool: list | None = None) -> dict:
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

    Stateless rules get no probe HERE -- they have no threshold to step under
    and no window to overrun. Their negative half is `_near_miss_probe`
    (single-predicate necessity), reported separately so the two claims are
    never summed into one number that means neither."""
    if not rule.stateful:
        return {"applicable": False,
                "reason": "stateless rule -- no threshold/window to probe; "
                          "see this rule's `near_miss` entry instead"}
    if base_event is None:
        # Both cases arrive here with no fixture, but they mean opposite
        # things and the JSON is what a reader consults after the fact --
        # recording "the rule never fired" for a rule the HARNESS could not
        # exercise sends someone hunting a rule bug that does not exist.
        return {"applicable": False,
                "reason": ("harness could not construct a replay for this rule -- "
                           "no evidence about the rule either way" if blocked else
                           "rule never fired -- no fixture to probe the boundary with")}

    reps = rule.threshold or 1
    probes: dict[str, dict] = {}

    if reps < 2:
        probes["under_threshold"] = {
            "status": "skipped",
            "detail": "threshold is 1, no sub-threshold count exists"}
    else:
        step_ms = _positive_step_ms(rule, reps)
        outcome = _replay(rule, base_event, reps - 1, step_ms, "under",
                          distinct_pool)
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
        outcome = _replay(rule, base_event, reps, overrun_ms, "overrun",
                          distinct_pool)
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


# Perturbation used wherever a predicate needs "some value that is not the one
# declared". Deliberately not a plausible-looking value: a near-miss probe is
# an assertion about the ENGINE's evaluation of a declared predicate, and a
# realistic-looking substitute invites the reader to think the probe says
# something about real-world traffic. It does not.
_NEAR_MISS_SENTINEL = "__firecheck_near_miss__"


def _is_pure_conjunction(rule) -> bool:
    """True when the condition is selections joined ONLY by ``and``.

    The whole near-miss argument rests on this: under pure conjunction every
    declared predicate is individually necessary, so violating exactly one
    must silence the rule. Under `or` it must not (the other disjunct still
    matches), and under `not` the polarity inverts -- asserting silence there
    would be asserting a defect. Such rules are reported inapplicable rather
    than probed, because a wrong negative assertion is worse than none.

    Reads the engine's own precomputed token list rather than re-parsing the
    condition string, so a tokenizer change cannot leave this helper agreeing
    with a grammar the engine no longer implements.

    Boolean keywords are excluded from the selection-name test before it runs.
    Without that, a rule carrying a selection literally NAMED `or` makes the
    `or` token satisfy `t in rule.selections`, and a genuinely disjunctive
    condition is classified as a conjunction -- the one direction that is
    unsafe, since the probe would then demand silence from a rule whose other
    disjunct legitimately still matches and report a healthy rule as too
    loose. No shipped rule has such a selection; the guard costs a set
    lookup and removes the failure mode rather than relying on that."""
    keywords = {"and", "or", "not"}
    tokens = rule._condition_tokens
    return bool(tokens) and all(
        t == "and" or (t not in keywords and t in rule.selections) for t in tokens)


def _conjuncts(rule):
    """Parse the condition into conjuncts ``[(sel_name, negated), ...]``, or
    None when the condition is not a probeable conjunction.

    Extends ``_is_pure_conjunction`` (PR #80 review finding 5): a probeable
    conjunction is selections joined ONLY by ``and``, where each conjunct is a
    single selection, optionally negated (``<sel>`` or ``not <sel>``). A rule
    like ``unauthorized_write and not authorized_change`` is probeable: the
    `not`-term's load-bearing requirement is that SATISFYING the negated
    selection must silence the rule. ``or``, parentheses, or multi-token
    conjuncts are NOT probeable (violating one predicate need not silence,
    and asserting silence would assert a defect) -- those are reported
    inapplicable, exactly as ``_is_pure_conjunction`` always did.
    """
    keywords = {"and", "or", "not"}
    tokens = rule._condition_tokens
    if not tokens:
        return None
    conjuncts: list[list[str]] = []
    cur: list[str] = []
    for t in tokens:
        if t == "and":
            if cur:
                conjuncts.append(cur)
                cur = []
        elif t in ("or", "(", ")"):
            return None
        else:
            cur.append(t)
    if cur:
        conjuncts.append(cur)
    out: list[tuple[str, bool]] = []
    for c in conjuncts:
        if len(c) == 1 and c[0] in rule.selections:
            out.append((c[0], False))
        elif len(c) == 2 and c[0] == "not" and c[1] in rule.selections:
            out.append((c[1], True))
        else:
            return None
    return out


def _satisfy_selection(rule, fire_ev: dict, sel_name: str) -> dict | None:
    """Return a copy of ``fire_ev`` in which selection ``sel_name`` is
    guaranteed to MATCH (True) -- the near-miss construction for a
    ``not <sel_name>`` conjunct: satisfying the negated selection must silence
    the rule. Returns None (honest skip) when no satisfying event is
    constructible."""
    sel = rule.selections.get(sel_name)
    if not isinstance(sel, dict) or not sel:
        return None
    ev = copy.deepcopy(fire_ev)
    for field, expected in sel.items():
        if isinstance(expected, dict):
            # Only a single {exists: bool} operator is constructible here.
            if len(expected) == 1 and "exists" in expected:
                if expected["exists"] is True:
                    _set_path(ev, field, _NEAR_MISS_SENTINEL)
                else:
                    _del_path(ev, field)
            else:
                return None
        else:
            _set_path(ev, field, expected)
    return ev


def _inside_hours_ts(spec) -> int | None:
    """An epoch-ms that is INSIDE ``spec``'s business-hours window -- the exact
    mirror of `_oh_anchors`, and the near-miss for an ``outside_hours``
    predicate.

    This is the predicate whose violation the positive check is blindest to: a
    rule that ignored time-of-day entirely would fire on its own off-hours
    fixture exactly as a healthy one does. Only feeding it an in-hours
    timestamp and demanding silence tells the two apart.

    Steps back by minutes for the same reason `_oh_anchors` does (specs carry
    minute resolution), and searches a full 8 days so a window configured for
    weekdays only still finds an in-hours instant from any starting weekend."""
    now = int(time.time() * 1000)
    for minutes_back in range(1, 8 * 24 * 60 + 1):
        ts = now - minutes_back * 60_000
        if not _time_outside_hours(spec, ts):
            return ts
    return None


def _operator_near_miss(op, arg, actual) -> dict:
    """How to violate ONE operator predicate: ``{"kind": "value", ...}`` to
    overwrite the field, ``{"kind": "allowlist", ...}`` for the ``not_in``
    special case, or ``{"kind": "skip", "reason": ...}`` when no violation is
    constructible.

    Skipping is a first-class outcome, not a failure to try. A constructor
    that guessed at a value it could not prove violates the predicate would
    produce a probe whose silence means nothing -- and would report it as
    "held" alongside the real ones."""
    if op == "not_in":
        # Inverted case. Every other operator is violated by changing the
        # EVENT; `not_in` is violated by changing the ALLOWLIST, because the
        # suppression fires when the value IS listed. Mutating the event
        # instead would just swap one non-allowlisted value for another and
        # the rule would correctly keep firing -- a probe that reads as a
        # defect while testing nothing.
        if not isinstance(arg, str):
            return {"kind": "skip", "reason": "malformed not_in reference (engine fails closed here)"}
        if actual is None:
            return {"kind": "skip", "reason": "field is absent on the firing fixture -- nothing to allowlist"}
        return {"kind": "allowlist", "name": arg, "value": actual}
    if op == "outside_hours":
        ts = _inside_hours_ts(arg)
        if ts is None:
            return {"kind": "skip", "reason": "no in-hours instant found in an 8-day sweep"}
        return {"kind": "value", "value": ts, "label": "timestamp stamped INSIDE business hours"}
    if op in ("gt", "gte", "lt", "lte", "ne"):
        if not isinstance(arg, (int, float)) or isinstance(arg, bool):
            return {"kind": "skip", "reason": f"non-numeric {op} argument"}
        flipped = {"gt": arg, "gte": arg - 1, "lt": arg, "lte": arg + 1, "ne": arg}[op]
        return {"kind": "value", "value": flipped,
                "label": f"{op}:{arg!r} violated by exactly one step ({flipped!r})"}
    if op == "in":
        if not isinstance(arg, list):
            return {"kind": "skip", "reason": "malformed in-list (engine fails closed here)"}
        if _in_list(_NEAR_MISS_SENTINEL, arg):
            return {"kind": "skip", "reason": "the sentinel is itself a member of the declared list"}
        return {"kind": "value", "value": _NEAR_MISS_SENTINEL, "label": "value outside the declared in-list"}
    if op == "contains":
        if _contains(_NEAR_MISS_SENTINEL, arg):
            return {"kind": "skip", "reason": "the sentinel itself contains the declared needle"}
        return {"kind": "value", "value": _NEAR_MISS_SENTINEL, "label": "declared needle absent"}
    if op == "glob":
        if _glob_match(_NEAR_MISS_SENTINEL, arg):
            return {"kind": "skip", "reason": "the sentinel itself matches the declared pattern"}
        return {"kind": "value", "value": _NEAR_MISS_SENTINEL, "label": "value outside the declared glob"}
    if op == "exists":
        # PR #80 review (finding 5): field-presence predicate. `exists: true`
        # is violated by REMOVING the field; `exists: false` by ADDING it. A
        # field already absent under `exists: true` is the rule's own firing
        # state, so no near-miss exists there (honest skip, not a guessed one).
        if arg is True:
            if actual is None:
                return {"kind": "skip", "reason": "field is absent on the firing fixture -- exists:true is already the firing state; no near-miss"}
            return {"kind": "remove", "label": "field removed (exists:true violated)"}
        return {"kind": "value", "value": _NEAR_MISS_SENTINEL,
                "label": "field populated (exists:false violated)"}
    return {"kind": "skip", "reason": f"no near-miss constructor for operator {op!r}"}


def _equality_near_miss(expected) -> dict:
    """Violate a plain equality selection (``class_uid: 6003``).

    Bools are checked before numbers on purpose: ``bool`` is an ``int``
    subtype in Python, so the numeric branch would turn ``True`` into ``2``,
    which is still truthy-looking in a report and, worse, is a value no parser
    emits -- the perturbation would be testing a type change rather than the
    declared value. ``not expected`` is the actual near-miss."""
    if isinstance(expected, bool):
        return {"kind": "value", "value": not expected, "label": f"{expected!r} -> {(not expected)!r}"}
    if isinstance(expected, (int, float)):
        return {"kind": "value", "value": expected + 1, "label": f"{expected!r} -> {expected + 1!r}"}
    if isinstance(expected, str):
        return {"kind": "value", "value": expected + _NEAR_MISS_SENTINEL,
                "label": f"{expected!r} perturbed"}
    return {"kind": "skip",
            "reason": f"no near-miss constructor for a {type(expected).__name__} literal"}


def _fires_with_value_allowlisted(rule, event: dict, name: str, value) -> bool:
    """Rebuild ``rule`` against a throwaway allowlists dir in which ``value`` IS
    listed, and report whether it still fires. Silence is the pass.

    A fresh temp dir per probe rather than editing `contracts/allowlists/`:
    `load_allowlist` caches on the RESOLVED dir path, so a unique directory
    cannot poison the real allowlist's cached entry for the rest of the
    process (or for any other probe). The directory holds only the targeted
    list -- any other list the rule references is missing here and therefore
    fails OPEN by the engine's documented `not_in` posture, i.e. keeps
    matching, so an untargeted allowlist can never be the reason this probe
    sees silence."""
    tmp = Path(tempfile.mkdtemp(prefix="firecheck-allowlist-"))
    try:
        (tmp / f"{name}.yml").write_text(
            "entries:\n  - " + json.dumps(str(value)) + "\n", encoding="utf-8")
        probe_rule = Rule(copy.deepcopy(rule.raw), allowlists_dir=tmp)
        return probe_rule.evaluate(copy.deepcopy(event))
    finally:
        # Safe to remove immediately: the engine caches the parsed Allowlist
        # object, not the file handle, so nothing reads this path again.
        shutil.rmtree(tmp, ignore_errors=True)


def _near_miss_probe(rule, base_event: dict | None, blocked: bool = False) -> dict:
    """Negative half of the gate for STATELESS rules: the rule fires on its own
    fixture (proven by `_try_fire`) -- prove it stops firing when any single
    declared predicate is violated.

    Structure mirrors `_boundary_probe` deliberately, including the `status`
    machine field and the "any skipped probe means not fully held" rule, so
    the two negative halves cannot drift into reporting the same word with
    different strictness.

    Four inapplicable cases, each recorded with its own reason because they
    mean different things to whoever reads the JSON later: the rule is
    stateful (wrong probe), no fixture exists (the rule never fired, or the
    harness could not exercise it -- opposite meanings, same empty input), the
    condition is not a pure conjunction (see `_is_pure_conjunction`), or the
    positive control does not reproduce here.

    That last one is the same load-bearing property `_replay` documents for
    the stateful probes: silence only means something if this exact harness
    demonstrably CAN make this rule fire. `_try_fire` establishes the fire on
    an anchored copy it does not return, so the anchoring is reconstructed and
    re-asserted here rather than assumed -- otherwise a reconstruction bug
    would report every predicate as "held" on a rule that was never firing in
    the first place, which is precisely the vacuous-green failure the whole
    probe exists to avoid."""
    if rule.stateful:
        return {"applicable": False,
                "reason": "stateful rule -- probed on its threshold/window instead"}
    if base_event is None:
        return {"applicable": False,
                "reason": ("harness could not construct a replay for this rule -- "
                           "no evidence about the rule either way" if blocked else
                           "rule never fired -- no fixture to build a near-miss from")}
    conjuncts = _conjuncts(rule)
    if conjuncts is None:
        return {"applicable": False,
                "reason": f"condition {rule.condition!r} is not a probeable "
                          f"and/not-conjunction -- violating one predicate need "
                          f"not silence the rule, so asserting silence would "
                          f"assert a defect (see _conjuncts / _is_pure_conjunction)"}

    anchors = _oh_anchors(rule, 0)
    if anchors is None:
        return {"applicable": False,
                "reason": "harness could not construct an off-hours anchor -- "
                          "no evidence about the rule either way"}
    fire_ev = copy.deepcopy(base_event)
    for field, anchor in anchors:
        _set_path(fire_ev, field, anchor)
    if not rule.evaluate(fire_ev):
        return {"applicable": False,
                "reason": "positive control did not reproduce on the reconstructed "
                          "fixture -- every near-miss below would be vacuously silent"}

    probes: dict[str, dict] = {}
    # PR #80 review (finding 5): iterate the CONJUNCTS, not raw selections, so
    # a `not <sel>` term is probed by SATISFYING the negated selection (making
    # it match must silence the rule) instead of wrongly trying to violate it.
    for sel_name, negated in conjuncts:
        selection = rule.selections.get(sel_name)
        if negated:
            ev = _satisfy_selection(rule, fire_ev, sel_name)
            if ev is None:
                probes[f"not {sel_name}"] = {
                    "status": "skipped",
                    "detail": "no constructor to satisfy the negated selection"}
                continue
            ev.setdefault("siem", {})["ingest_id"] = (
                f"firecheck:{rule.id}:nearmiss:not-{sel_name}")
            fired = rule.evaluate(ev)
            probes[f"not {sel_name}"] = {
                "status": "fired" if fired else "held",
                "detail": (f"negated selection {sel_name} SATISFIED -- the "
                           "rule must silence when the 'not' guard matches")}
            continue
        if not isinstance(selection, dict):
            continue
        for field, expected in selection.items():
            if isinstance(expected, dict):
                # One probe per OPERATOR, not per field: a field carrying
                # {gt: 5, lt: 90} declares two independent constraints and a
                # single probe would leave one of them unexercised while the
                # report implied the field was covered.
                cases = [(f"{sel_name}.{field}[{op}]",
                          _operator_near_miss(op, arg, get_path(fire_ev, field)))
                         for op, arg in expected.items()]
            else:
                cases = [(f"{sel_name}.{field}", _equality_near_miss(expected))]

            for key, case in cases:
                if case["kind"] == "skip":
                    probes[key] = {"status": "skipped", "detail": case["reason"]}
                    continue
                if case["kind"] == "allowlist":
                    fired = _fires_with_value_allowlisted(
                        rule, fire_ev, case["name"], case["value"])
                    detail = (f"{field}={case['value']!r} placed IN allowlist "
                              f"{case['name']!r} -- suppression must apply")
                elif case["kind"] == "remove":
                    ev = copy.deepcopy(fire_ev)
                    _del_path(ev, field)
                    ev.setdefault("siem", {})["ingest_id"] = (
                        f"firecheck:{rule.id}:nearmiss:{key}:rm")
                    fired = rule.evaluate(ev)
                    detail = f"{field}: {case['label']}"
                else:
                    ev = copy.deepcopy(fire_ev)
                    _set_path(ev, field, case["value"])
                    ev.setdefault("siem", {})["ingest_id"] = f"firecheck:{rule.id}:nearmiss:{key}"
                    fired = rule.evaluate(ev)
                    detail = f"{field}: {case['label']}"
                probes[key] = {"status": "fired" if fired else "held", "detail": detail}

    held = [n for n, v in probes.items() if v["status"] == "held"]
    skipped = [n for n, v in probes.items() if v["status"] == "skipped"]
    return {"applicable": True, "probes": probes,
            "held": held, "skipped": skipped,
            "fully_held": bool(held) and not skipped,
            "too_loose": [n for n, v in probes.items() if v["status"] == "fired"]}


def main() -> int:
    events = _real_events()

    canary_ok, canary_note = _canary_check(events)
    print(f"harness liveness canary -- {canary_note}")
    if not canary_ok:
        print(f"\n[FAIL] HARNESS ITSELF is broken, not any real rule: {canary_note}")
        print("       Every result below would be meaningless -- not reported.")
        # Overwrite the artifact rather than leaving the previous run's green
        # JSON on disk to be read as current. "Refuses to report" has to mean
        # the stale report stops being believable, not just that we skip a
        # print -- a developer with a red terminal and a green fire_check.json
        # is exactly the ambiguity this whole file exists to remove.
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        (OUT_DIR / "fire_check.json").write_text(json.dumps(
            {"harness_ok": False, "reason": canary_note, "results": []}, indent=2))
        return 1
    print()

    detector = Detector(plugin_rule_dirs=[])

    results = []
    untagged: list[dict] = []
    for rule in detector.rules:
        mitre = rule.raw.get("mitre")
        if not isinstance(mitre, dict) or not mitre.get("technique"):
            # R3-#39 (2026-08-27): this was a silent `continue` -- a rule with
            # no `mitre.technique` fell out of the verdict entirely, invisible
            # in the very "unverified" accounting this file exists to surface.
            # It is now counted explicitly as UNVERIFIED (it can't be
            # empirically checked without a declared technique to key the
            # fixture on), reported at the end, not silently dropped.
            untagged.append({"id": rule.id, "title": rule.title})
            continue  # coverage_layer.py independently reports undeclared rules
        fired, note, fixture, blocked = _try_fire(rule, events)
        results.append({
            "id": rule.id, "title": rule.title,
            "framework": mitre.get("framework", "attack"),
            "tactic": mitre.get("tactic"), "technique": mitre["technique"],
            "fired": fired, "note": note, "harness_blocked": blocked,
            "boundary": _boundary_probe(rule, fixture, blocked),
            "near_miss": _near_miss_probe(rule, fixture, blocked),
        })

    tagged_not_firing = [r for r in results if not r["fired"] and not r["harness_blocked"]]
    harness_blocked = [r for r in results if r["harness_blocked"]]
    # Both negative halves feed ONE too-loose gate. They answer the same
    # question (does this rule fire when it must not?) by different
    # constructions, and a rule that fails either one is equally shipped-broken.
    too_loose = [r for r in results
                 if r["boundary"].get("too_loose") or r["near_miss"].get("too_loose")]
    fully_held = [r for r in results if r["boundary"].get("fully_held")]
    # Partly probed = at least one probe held and at least one was skipped.
    # Not counted as having held its boundary: the headline sentence claims
    # BOTH probes stayed silent, and for a half-probed rule that is false.
    partly_held = [r for r in results
                   if r["boundary"].get("held") and r["boundary"].get("skipped")]
    nm_fully_held = [r for r in results if r["near_miss"].get("fully_held")]
    nm_partly_held = [r for r in results
                      if r["near_miss"].get("held") and r["near_miss"].get("skipped")]
    nm_predicates = sum(len(r["near_miss"].get("held", [])) for r in results)
    # A rule counts as negatively verified when EITHER half fully held -- the
    # two are mutually exclusive by construction (stateful vs. stateless), so
    # this cannot double-count, and anything in neither list is genuinely
    # unverified rather than merely probed by the other half.
    untested = len(results) - len(fully_held) - len(nm_fully_held)

    print(f"MITRE empirical firing check -- {len(results)} tagged rule(s) checked "
          f"against their own real producer fixtures (declared-vs-fired, not "
          f"real-world validation -- see this file's module docstring)")
    for r in sorted(results, key=lambda r: r["id"] or ""):
        mark = "FIRED " if r["fired"] else "SILENT"
        print(f"  [{mark}] {r['technique']:<10} {r['id']}: {r['note']}")
        for name, verdict in r["boundary"].get("probes", {}).items():
            print(f"           |- {name}: {verdict['status']} -- {verdict['detail']}")
        for name, verdict in r["near_miss"].get("probes", {}).items():
            print(f"           |- near-miss {name}: {verdict['status']} -- {verdict['detail']}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "fire_check.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nwrote {out_path}")

    # The actual "the suite silently stopped testing anything" failure, and
    # the one the canary does NOT catch: zero rules reached the loop at all.
    # Reachable without anyone noticing -- main.py::_contracts_dir() falls
    # through to a path that need not exist, load_rules() on a missing
    # directory returns [] without raising, and a rename of the `mitre:` key
    # would make every rule skip the `continue` above. Every downstream check
    # is vacuously true over an empty list, so the run prints "all 0 rules
    # fire" and exits 0. A count floor is the only thing that catches it.
    if not results:
        print("\n[FAIL] ZERO MITRE-tagged rules were checked -- every result below "
              "is vacuously true over an empty set. The rule set did not load, or "
              "no rule carries a `mitre:` block any more (schema rename?). This is "
              "the suite having stopped testing anything, which passes every other "
              "check in this file.")
        return 1

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
            for name in r["boundary"].get("too_loose", []):
                print(f"    {r['id']} ({r['technique']}): {name} fired when it must not")
            for name in r["near_miss"].get("too_loose", []):
                print(f"    {r['id']} ({r['technique']}): near-miss {name} fired with "
                      f"that predicate violated -- the predicate is not load-bearing")
        return 1

    print(f"\n[OK] all {len(results)} MITRE-tagged rules fire on their own real "
          f"producer fixture")
    print(f"[OK] {len(fully_held)} stateful rule(s) held their declared boundary "
          f"(threshold-1 AND window-overrun both ran and stayed silent)"
          + (f", of which {len(partly_held)} had one probe held and one skipped"
             if partly_held else ""))
    print(f"[OK] {len(nm_fully_held)} stateless rule(s) held single-predicate "
          f"necessity ({nm_predicates} predicate near-miss(es) ran and stayed "
          f"silent) -- necessity of each DECLARED predicate, not well-scopedness"
          + (f"; {len(nm_partly_held)} rule(s) had at least one predicate with no "
             f"constructible near-miss" if nm_partly_held else ""))
    unverified = untested + len(untagged)
    if untested:
        print(f"[WARN] {untested} MITRE-tagged rule(s) negatively verified by "
              f"NEITHER half -- UNVERIFIED, NOT passing (NEW-hunt): a rule with "
              f"no held near-miss/boundary is silently negative until one is "
              f"constructed. See 'boundary'/'near_miss' in the JSON.")
    if untagged:
        print(f"[WARN] {len(untagged)} rule(s) have NO mitre.technique and are "
              f"therefore UNVERIFIED by this empirical check (R3-#39) -- not "
              f"silently dropped, not counted as passing: "
              f"{', '.join(str(r['id']) for r in untagged)}")
    if unverified:
        print(f"      ({unverified} total rule(s) remain UNVERIFIED by this "
              f"gate's negative half -- declared-coverage and positive-fire "
              f"checks above still hold for the {len(results)} tagged rule(s); "
              f"an unverified rule is an open gap, not a pass.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
