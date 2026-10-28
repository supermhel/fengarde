"""Build the WS-5 triage-verdict labelled set (eval/llm_triage/labelled_cases.json).

Every case is an alert the REAL pipeline raises: raw envelope -> ws2 `normalize_one`
-> a fresh ws4 `Detector.process()` (which stamps `siem.score` and picks the funnel
tier) -> the `ai.requests` payload WS-4 would enqueue (`event`, `reason` = matched rule
titles). Nothing is hand-written into the event.

LABELS come from material the repo already owns, never from model or stub output:

  true_positive   a fired alert on an ATTACK step of a twin storyline
                  (`eval/twin/scenario_registry`, oracle-graded chains), or a hard-positive
                  case of the curated adversarial corpus (`eval/adversarial/corpus_b`).
  false_positive  a fired alert on benign activity built to look like the attack:
                  the storylines' `decoy` builders (disjoint benign entities that DO trip
                  rules) and the twin's `negative_controls` (an approved-maintenance write).

`needs_review` is deliberately NOT a ground-truth label: the repo has no ground truth
for "ambiguous", so it exists only as a model output (an abstention) in the scorer.

`expected_level` is the highest `level` declared by the rules that fired (true_positive)
or `low` (false_positive). It is rule-declared severity, not analyst-judged severity.

Alerts that fire no rule never reach WS-5, so they are not cases (reported in `excluded`).
One case per (group, step, rule-set): a 40-event brute-force burst is one case, not 40.

Regenerate:  python eval/llm_triage/build_labelled_set.py   (the contract test fails if the
committed file drifts from what the current rules/parsers produce).
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for p in (ROOT / "eval" / "twin", ROOT / "eval" / "adversarial", ROOT / "services"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import report  # noqa: E402  (eval/twin/report.py: loads the real ws2/ws4 modules)
import negative_controls as nc  # noqa: E402
import corpus_b  # noqa: E402
import scenario_registry  # noqa: E402

OUT = HERE / "labelled_cases.json"
SEED = 7
_OPT_IN = ["e7a14b6d-3c52-4d90-8f1b-5a9c0d2e6b47"]  # same deterministic rule set as the twin
_LEVEL_ORDER = ["low", "medium", "high", "critical"]
_LEAK_WORDS = ("decoy", "negative_control", "twin_step", "true_positive", "false_positive")


_EVENT_SEQ = [0]  # ingest ids are label-neutral and GLOBALLY unique (WS-5 dedups on event id)


def _ws2():
    return report.scenario._get_ws2()


def _detector():
    return report._WS4_MOD.Detector(plugin_rule_dirs=[], opt_in_rules=_OPT_IN)


def _level(rule_levels: list[str]) -> str:
    """Highest declared rule level, clamped into WS-5's low..critical scale
    (`informational` has no WS-5 equivalent -> low)."""
    idx = max((_LEVEL_ORDER.index(l) for l in rule_levels if l in _LEVEL_ORDER), default=0)
    return _LEVEL_ORDER[idx]


def _run(items, group: str, label: str, source: str, cases: list, excluded: list):
    """items: [(step_label, envelope)] processed in order by ONE fresh Detector (stateful
    windows need the burst). Appends one case per distinct (step, matched-rule-set)."""
    ws2, det, seen = _ws2(), _detector(), set()
    for i, (step, env) in enumerate(items):
        event, errors = ws2.normalize_one(copy.deepcopy(env))
        if event is None or errors:
            excluded.append({"group": group, "step": step, "why": "did not normalize"})
            continue
        _EVENT_SEQ[0] += 1
        event.setdefault("siem", {}).update({"tenant": "llm-eval", "ingest_id": f"llmeval:{_EVENT_SEQ[0]:04d}"})
        if "trace_id" in event["siem"]:  # some parsers mint a random uuid; pin it so the file is reproducible
            event["siem"]["trace_id"] = f"trace-{event['siem']['ingest_id']}"
        event, matched, tier = det.process(event)
        if not matched:
            excluded.append({"group": group, "step": step, "why": "no rule fired (never reaches WS-5)"})
            continue
        key = (step, tuple(sorted(r.id for r in matched)))
        if key in seen:
            continue
        seen.add(key)
        blob = json.dumps(event).lower()
        leaks = [w for w in _LEAK_WORDS if w in blob]
        cases.append({
            "case_id": f"{group}:{step}:{len(seen):02d}",
            "label": label,
            "expected_level": _level([r.level for r in matched]) if label == "true_positive" else "low",
            "provenance": {"source": source, "group": group, "step": step,
                           "seed": SEED, "rules": sorted(r.id for r in matched)},
            "prod_tier": tier,
            "label_leak_words": leaks,
            "request": {"event_id": event["siem"]["ingest_id"], "event": event,
                        "reason": [r.title for r in matched]},
        })


def build() -> dict:
    _EVENT_SEQ[0] = 0
    cases: list = []
    excluded: list = []

    for sdef in scenario_registry.ALL:
        payloads = sdef.build(SEED)[0]
        _run([(spec.label, p) for spec, p in payloads], f"twin-{sdef.name}", "true_positive",
             f"eval/twin storyline `{sdef.name}` (oracle {Path(sdef.oracle_path).name}); fired alert on an attack step",
             cases, excluded)
        if sdef.decoy:
            _run([(spec.label, p) for spec, p in sdef.decoy(SEED)], f"decoy-{sdef.name}", "false_positive",
                 f"eval/twin storyline `{sdef.name}` decoy builder: benign look-alike, disjoint entities",
                 cases, excluded)

    for c in corpus_b.CORPUS:
        if not c.get("hard_positive"):
            excluded.append({"group": "corpus-b", "step": c["id"], "why": "documented evasion / non-hard-positive"})
            continue
        env = {"source_type": c["source_type"], "raw": c["raw"], "meta": c.get("meta") or {}}
        _run([(c["id"], env)], "corpus-b", "true_positive",
             "eval/adversarial/corpus_b.CORPUS hard_positive case (curated attack payload)", cases, excluded)

    captured: list = []
    orig = nc.run_pipeline
    nc.run_pipeline = lambda raw, tenant: (captured.append((tenant, raw)), orig(raw, tenant))[1]
    try:
        for fn in (nc.scenario_maintenance_window, nc.scenario_authorized_operator,
                   nc.scenario_unrelated_writes, nc.scenario_benign_n8n_edits):
            fn(SEED)
    finally:
        nc.run_pipeline = orig
    for tenant, raw in captured:
        items = [("benign_write", {"source_type": e[0], "raw": e[1], "meta": (e[2] if len(e) > 2 and isinstance(e[2], dict) else {})})
                 for e in raw]
        _run(items, f"negctl-{tenant}", "false_positive",
             "eval/twin/negative_controls: benign operational write the maintainers assert is NOT an incident",
             cases, excluded)

    return {
        "schema_version": 1,
        "seed": SEED,
        "label_space": ["true_positive", "false_positive"],
        "note": "needs_review is a model output (abstention) only; no ground truth exists for it.",
        "counts": {
            "n": len(cases),
            "true_positive": sum(c["label"] == "true_positive" for c in cases),
            "false_positive": sum(c["label"] == "false_positive" for c in cases),
            "reach_llm_tier_in_prod": sum(c["prod_tier"] == "llm" for c in cases),
        },
        "excluded": excluded,
        "cases": cases,
    }


def main(argv=None) -> int:
    check = "--check" in (argv if argv is not None else sys.argv[1:])
    doc = build()
    text = json.dumps(doc, indent=1, sort_keys=True) + "\n"
    if check:  # drift guard: committed file must equal what today's rules/parsers produce
        have = OUT.read_bytes().decode("utf-8").replace("\r\n", "\n")
        if have != text:
            print("labelled_cases.json is STALE vs the current rules/parsers/storylines: "
                  "run python eval/llm_triage/build_labelled_set.py and re-run the eval", file=sys.stderr)
            return 1
        print(f"labelled_cases.json up to date: {doc['counts']}")
        return 0
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(ROOT)}: {doc['counts']}  excluded={len(doc['excluded'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
