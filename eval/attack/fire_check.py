"""P3-2 follow-up (M7, 2026-07-22) -- empirical MITRE firing proof.

``coverage_layer.py`` (in this same directory) proves a rule CLAIMS a
technique (parses its `mitre:` block). It says nothing about whether the
rule actually FIRES. This tool closes that specific, narrow gap: for every
rule carrying a `mitre:` tag, replay its own anti-dormancy producer fixture
(the same real parser -> enrich pipeline `tools/check_rule_producers.py`
already proves is satisfiable) through the real WS-4 `Detector`/`Rule.
evaluate()` path and record whether it actually fires.

**What this proves, and what it does not** (read before citing this
anywhere): a rule firing on ITS OWN fixture proves the rule's condition/
threshold logic is not dead code. It does NOT prove the rule fires on real-
world attack traffic, evasive variants, or a live-Docker/Redis-backed
window counter under concurrent load -- that empirical, corpus-driven
validation is `eval/detection_accuracy/`'s job (EVTX/Splunk oracle replay),
unchanged and not conflated with this tool. See
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


def _base_ms(rule, oh: list[tuple[str, int]]) -> int:
    """The instant the newest synthetic event in a replay is stamped with.

    Engine._valid_window_time fail-closes any timestamp more than 5min ahead
    of wall-clock (P0 anti-poisoning guard) -- an earlier version of the
    replay loop stepped FORWARD from the fixture's own (already "now")
    timestamp and silently tripped that guard on every rep past the first,
    which is why this comment exists. Every replay steps BACKWARD from this
    anchor, so all synthetic timestamps are in the past (always accepted).
    When the rule keys outside_hours on `time`, anchor the whole window
    inside an off-hours span rather than at wall-clock now."""
    time_anchor = next((a for f, a in oh if f == "time"), None)
    return time_anchor if time_anchor is not None else int(time.time() * 1000)


def _replay(rule, base_event: dict, reps: int, step_ms: int,
            oh: list[tuple[str, int]], tag: str) -> bool:
    """Feed ``reps`` copies of ``base_event`` through the real
    ``Rule.evaluate()`` at ``step_ms`` spacing; return whether the LAST one
    fired.

    Every check in this file -- the positive one and both negative ones --
    goes through this one function, varying only ``reps``/``step_ms``. That
    is deliberate: a negative check ("did NOT fire") is only meaningful if
    the identical harness demonstrably CAN make this rule fire, so the
    positive replay is the control for the negative ones and must not be a
    separate code path that could drift from them.

    ``tag`` namespaces the replay via the synthetic ``siem.tenant``. The
    engine's window counter is keyed ``{rule id}:{tenant}:{group}`` and lives
    on the Rule instance, so without this every check would inherit the
    previous check's in-window events -- the under-threshold probe would see
    the positive probe's counts and "fire", reporting a defect that is purely
    harness state leakage. Tenant is used by the engine ONLY for that key and
    for alert_id; it never participates in condition evaluation, so isolating
    on it cannot change whether the rule's condition matches."""
    base_ms = _base_ms(rule, oh)
    fired = False
    for i in range(reps):
        ev = copy.deepcopy(base_event)
        siem = ev.setdefault("siem", {})
        siem["ingest_id"] = f"firecheck:{rule.id}:{tag}:{i}"
        siem["tenant"] = f"firecheck-{tag}"
        ev["time"] = base_ms - (reps - 1 - i) * step_ms
        for field, anchor in oh:
            if field != "time":
                _set_path(ev, field, anchor)
        if rule.distinct_field:
            _set_path(ev, rule.distinct_field, f"firecheck-value-{i}")
        fired = rule.evaluate(ev)
    return fired


def _positive_step_ms(rule, reps: int) -> int:
    """Spacing that packs ``reps`` events well inside the rule's own window,
    evenly enough that a periodicity rule sees a low-jitter cadence."""
    return max(1000, int((rule.window_seconds or 60) * 1000 / max(reps, 1) / 2))


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


def _hours_confound(rule, oh: list[tuple[str, int]], reps: int,
                    step_ms: int) -> bool:
    """True if a replay at this spacing would drag some events out of the
    off-hours span its anchor sits in.

    Only matters for the NEGATIVE checks, and the asymmetry is the point: a
    replay that FIRES is decisive whatever the timestamps did, but a replay
    that stays silent is ambiguous -- "the threshold correctly held" and "the
    events drifted into business hours so the condition never matched" look
    identical from outside. Rather than score an ambiguous silence as a pass,
    the caller skips the check and says so.

    Unreachable on the rule set as it ships today: all three `outside_hours`
    rules (after-hours admin, n8n after-hours workflow edit, OT write outside
    maintenance) are stateless, so none reaches a boundary probe at all. This
    guard exists for the first STATEFUL outside_hours rule -- at which point
    a silent probe would otherwise be scored as a pass on a rule the harness
    had quietly stopped exercising. Do not delete it as dead code without
    re-checking that predicate."""
    specs = [s for f, s in _outside_hours_specs(rule) if f == "time"]
    if not specs:
        return False
    base_ms = _base_ms(rule, oh)
    return any(not _time_outside_hours(spec, base_ms - (reps - 1 - i) * step_ms)
               for spec in specs for i in range(reps))


def _try_fire(rule, events: list[dict], oh: list[tuple[str, int]]) -> tuple[bool, str, dict | None]:
    """(fired, note, fixture_event) -- replay real events against one rule
    until it fires or the fixtures are exhausted. The returned event is the
    one that fired, so the boundary probes can re-use the exact fixture the
    positive result was established on."""
    for idx, base_event in enumerate(events):
        if not rule.stateful:
            ev = copy.deepcopy(base_event)
            for field, anchor in oh:
                _set_path(ev, field, anchor)
            if rule.evaluate(ev):
                return True, "fired on a single real event (stateless rule)", base_event
            continue

        reps = rule.threshold or 1
        if _replay(rule, base_event, reps, _positive_step_ms(rule, reps), oh, f"pos{idx}"):
            kind = ("periodicity" if rule.periodicity else
                    "distinct-count" if rule.distinct_field else "count")
            return True, f"fired after {reps} events on its own window ({kind}, stateful)", base_event
    return False, "never fired on any of its own real fixture events", None


def _boundary_probe(rule, base_event: dict | None,
                    oh: list[tuple[str, int]]) -> dict:
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

    Returns a per-probe verdict: "held" (correctly silent), "FIRED" (defect),
    or "skipped" with a reason. Stateless rules get no probe at all -- the
    near-miss of a single-event field match is the whole rest of the value
    space, so there is no generatable near-miss fixture; that needs a
    hand-authored one per rule and is honestly reported as untested rather
    than counted as passing."""
    if not rule.stateful:
        return {"applicable": False,
                "reason": "stateless rule -- near-miss undefined without a "
                          "hand-authored fixture; not boundary-tested"}
    if base_event is None:
        return {"applicable": False,
                "reason": "rule never fired -- no fixture to probe the boundary with"}

    reps = rule.threshold or 1
    probes: dict[str, str] = {}

    if reps < 2:
        probes["under_threshold"] = "skipped: threshold is 1, no sub-threshold count exists"
    else:
        step_ms = _positive_step_ms(rule, reps)
        if _hours_confound(rule, oh, reps - 1, step_ms):
            probes["under_threshold"] = "skipped: sub-threshold replay crosses its business-hours boundary"
        else:
            probes["under_threshold"] = (
                "FIRED" if _replay(rule, base_event, reps - 1, step_ms, oh, "under")
                else f"held ({reps - 1} events in-window did not fire a threshold-{reps} rule)")

    if reps < 2:
        probes["window_overrun"] = "skipped: threshold is 1, a single event needs no window"
    else:
        overrun_ms = _overrun_step_ms(rule, reps)
        if _hours_confound(rule, oh, reps, overrun_ms):
            probes["window_overrun"] = "skipped: window-overrun replay crosses its business-hours boundary"
        else:
            span_s = overrun_ms * (reps - 1) / 1000
            probes["window_overrun"] = (
                "FIRED" if _replay(rule, base_event, reps, overrun_ms, oh, "overrun")
                else f"held ({reps} events spanning {span_s:g}s did not fire a "
                     f"window_seconds={rule.window_seconds} rule)")

    # "held" counts only probes that actually ran. A rule whose probes were
    # ALL skipped has not been boundary-tested and must not be reported as
    # having held one -- that is the difference between a measured result and
    # a number that merely looks like one.
    return {"applicable": True, "probes": probes,
            "held": [n for n, v in probes.items() if v.startswith("held")],
            "too_loose": [n for n, v in probes.items() if v == "FIRED"]}


def main() -> int:
    events = _real_events()
    detector = Detector(plugin_rule_dirs=[])

    results = []
    for rule in detector.rules:
        mitre = rule.raw.get("mitre")
        if not isinstance(mitre, dict) or not mitre.get("technique"):
            continue  # coverage_layer.py already reports undeclared rules
        # Time-of-day rules only fire off-hours: stamp a deterministic
        # off-hours-and-past timestamp on each driving field so the result
        # never depends on what time this gate happens to run (_outside_hours_*).
        oh = [(f, _outside_hours_anchor(s)) for f, s in _outside_hours_specs(rule)]
        fired, note, fixture = _try_fire(rule, events, oh)
        results.append({
            "id": rule.id, "title": rule.title,
            "framework": mitre.get("framework", "attack"),
            "tactic": mitre.get("tactic"), "technique": mitre["technique"],
            "fired": fired, "note": note,
            "boundary": _boundary_probe(rule, fixture, oh),
        })

    tagged_not_firing = [r for r in results if not r["fired"]]
    too_loose = [r for r in results if r["boundary"].get("too_loose")]
    held = [r for r in results if r["boundary"].get("held")]
    # Applicable but every probe skipped -> not boundary-tested either. Zero
    # today (no stateful rule has threshold 1, the only skip a non-
    # outside_hours rule can hit), but counted separately so that a rule
    # added tomorrow cannot quietly inflate the "held" number.
    skipped_only = [r for r in results
                    if r["boundary"].get("applicable") and not r["boundary"].get("held")]
    untested = len(results) - len(held)

    print(f"MITRE empirical firing check -- {len(results)} tagged rule(s) checked "
          f"against their own real producer fixtures (declared-vs-fired, not "
          f"real-world validation -- see this file's module docstring)")
    for r in sorted(results, key=lambda r: r["id"] or ""):
        mark = "FIRED " if r["fired"] else "SILENT"
        print(f"  [{mark}] {r['technique']:<10} {r['id']}: {r['note']}")
        for name, verdict in r["boundary"].get("probes", {}).items():
            print(f"           |- {name}: {verdict}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "fire_check.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nwrote {out_path}")

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
    print(f"[OK] {len(held)} stateful rule(s) also held their boundary "
          f"(threshold-1 and window-overrun stayed silent); {untested} rule(s) "
          f"NOT boundary-tested -- untested, not passing"
          + (f", of which {len(skipped_only)} stateful rule(s) had every probe "
             f"skipped" if skipped_only else "")
          + " -- see 'boundary' in the JSON")
    return 0


if __name__ == "__main__":
    sys.exit(main())
