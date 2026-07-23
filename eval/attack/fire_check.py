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
distinct value per repetition; timestamps step forward evenly inside the
rule's window so `periodicity` rules (coefficient-of-variation) see a
low-jitter cadence, mirroring `test_v05_beaconing.py`'s own fixture shape.

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


def _try_fire(rule, events: list[dict]) -> tuple[bool, str]:
    """(fired, note) -- replay real events against one rule until it fires
    or the fixtures are exhausted."""
    for base_event in events:
        if not rule.stateful:
            if rule.evaluate(copy.deepcopy(base_event)):
                return True, "fired on a single real event (stateless rule)"
            continue

        reps = rule.threshold or 1
        # Engine._valid_window_time fail-closes any timestamp more than 5min
        # ahead of wall-clock (P0 anti-poisoning guard) -- an earlier version
        # of this loop stepped FORWARD from the fixture's own (already
        # "now") timestamp and silently tripped that guard on every rep past
        # the first, which is why this comment exists. Step backward from
        # wall-clock "now" instead, so every synthetic timestamp is in the
        # past (always accepted) and the last rep lands at "now".
        now_ms = int(time.time() * 1000)
        step_ms = max(1000, int((rule.window_seconds or 60) * 1000 / max(reps, 1) / 2))
        fired = False
        for i in range(reps):
            ev = copy.deepcopy(base_event)
            ev.setdefault("siem", {})["ingest_id"] = f"firecheck:{rule.id}:{i}"
            ev["time"] = now_ms - (reps - 1 - i) * step_ms
            if rule.distinct_field:
                _set_path(ev, rule.distinct_field, f"firecheck-value-{i}")
            fired = rule.evaluate(ev)
        if fired:
            kind = ("periodicity" if rule.periodicity else
                    "distinct-count" if rule.distinct_field else "count")
            return True, f"fired after {reps} events on its own window ({kind}, stateful)"
    return False, "never fired on any of its own real fixture events"


def main() -> int:
    events = _real_events()
    detector = Detector(plugin_rule_dirs=[])

    results = []
    for rule in detector.rules:
        mitre = rule.raw.get("mitre")
        if not isinstance(mitre, dict) or not mitre.get("technique"):
            continue  # coverage_layer.py already reports undeclared rules
        fired, note = _try_fire(rule, events)
        results.append({
            "id": rule.id, "title": rule.title,
            "framework": mitre.get("framework", "attack"),
            "tactic": mitre.get("tactic"), "technique": mitre["technique"],
            "fired": fired, "note": note,
        })

    tagged_not_firing = [r for r in results if not r["fired"]]

    print(f"MITRE empirical firing check -- {len(results)} tagged rule(s) checked "
          f"against their own real producer fixtures (declared-vs-fired, not "
          f"real-world validation -- see this file's module docstring)")
    for r in sorted(results, key=lambda r: r["id"] or ""):
        mark = "FIRED " if r["fired"] else "SILENT"
        print(f"  [{mark}] {r['technique']:<10} {r['id']}: {r['note']}")

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

    print(f"\n[OK] all {len(results)} MITRE-tagged rules fire on their own real "
          f"producer fixture")
    return 0


if __name__ == "__main__":
    sys.exit(main())
