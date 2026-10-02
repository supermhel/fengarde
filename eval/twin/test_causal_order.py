"""causal_order -- acceptance test for the causal-order metrics (eval/twin/causal_order.py,
wired into eval/twin/report.py).

Standalone (NOT pytest), matching the repo twin-test style: ``if __name__`` guard,
``[OK]``/``[FAIL]`` lines, exit 0 only when every check passes.

Run:  python eval/twin/test_causal_order.py

What this proves (every instrument has a positive AND a negative control):

  (a) UNIT, constructed graphs -- the grader can say yes AND no:
        linear chain ......... concordance 1.0 / fidelity 1.0 / forbidden realised 0.0
        time-mirrored chain .. concordance 0.0 / fidelity 0.0 / forbidden realised 1.0,
                               while the LEGACY join (report._grade_chain_fidelity) gives
                               the SAME chain_fidelity on both (it never reads a clock)
        late edge ............ order holds but the edge's evidence instant is after the
                               to-step: edge_available_rate 0.0; legacy fidelity unchanged
        typed-kind winner .... a later 'caused_by' edge displaces the earlier one in ONE
                               incident, an earlier edge in ANOTHER incident rescues it, in
                               EITHER incident order (per-incident min ts_ms, not the deduped
                               union)
        unattributed edges ... unknown event_id, a time-fallback digest ts_ms and an
                               ambiguous (two-step) edge earn no credit
        DAG .................. a two-parent step is graded per parent (a linear order check
                               cannot name which parent failed)
        ties ................. counted ordered, but temporal_discrimination exposes them
        no-edge / no-pair .... fidelity None (never a fabricated 0), concordance still real
  (b) MUTATION-SOUNDNESS -- flipping ``ordered`` or removing the ``ts_ms`` bound makes the
      checks above fail (mutated copies, restored).
  (c) REAL STORYLINES (all 3, seed 7) -- an independent from-scratch reference agrees
      exactly; identity run has concordance 1.0, forbidden realised 0.0, story/parser
      checks true, zero unattributed edges; same seed -> byte-identical output.
  (d) report.py WIRING -- run() emits the three metrics, every key in the FROZEN baseline
      is still emitted, the new keys never enter delta_vs_baseline, baseline.json is
      byte-identical (sha256), the legacy numbers are unchanged, the invariant label is
      present, and main()'s order floors trip on a broken order (and pass on the real one).
  (e) policy / helpers -- reporting_policy never relabels (mode stays co_reported),
      story_order_ok and parser_time_agreement can say yes and no.

Like test_chain_fidelity.py this imports ``report`` (module-collision discipline lives in
report.py); causal_order itself is import-pure.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
for _p in (str(TWIN), str(SERVICES)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import report  # noqa: E402  (pre-seeds sys.modules['main'] -- must come first)
import causal_order as co  # noqa: E402
import scenario_registry as reg  # noqa: E402

SEED = 7
#: sha256 of eval/twin/baseline.json (LF-normalised). The baseline is FROZEN; if this
#: changes, the baseline was edited, which its own header forbids.
BASELINE_SHA256 = "f07c0df2491f328c2f38f871462df686b7188c85fbb7e701489c330f0930f279"

_FAILURES: list = []


def _check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        _FAILURES.append(name)


# ---------------------------------------------------------------------------
# constructed fixtures
# ---------------------------------------------------------------------------
def _join(edges, from_side, to_side):
    """The test's OWN direction predicate (independent of report._fidelity_join)."""
    return any(e.get("from") in from_side and e.get("to") in to_side for e in edges)


def _alert(step, aid, ev, t):
    return {"step": step, "alert": {"alert_id": aid, "event_ids": [ev], "time": t}}


STEP_ORDER = ["a", "b", "c"]
ENT = {"a": {"A1"}, "b": {"B1"}, "c": {"C1"}}
RELS = [{"from": "a", "to": "b", "allowed": True},
        {"from": "b", "to": "c", "allowed": True},
        {"from": "c", "to": "a", "allowed": False}]
ITEMS = [_alert("b", "al-b", "ev-b", 200), _alert("c", "al-c", "ev-c", 300)]
E_AB = {"from": "A1", "to": "B1", "kind": "same_ip", "event_id": "ev-b", "ts_ms": 200}
E_BC = {"from": "B1", "to": "C1", "kind": "same_ip", "event_id": "ev-c", "ts_ms": 300}
TIMES_FWD = {"a": (100, 100), "b": (200, 200), "c": (300, 300)}
TIMES_REV = {"a": (300, 300), "b": (200, 200), "c": (100, 100)}


def _grade(graphs, times, items=ITEMS, ent=ENT, rels=RELS, order=STEP_ORDER):
    return co.grade_causal_order(graphs, ent, rels, order, times, items, join_fn=_join)


def _test_unit() -> None:
    fwd = _grade([{"edges": [E_AB, E_BC]}], TIMES_FWD)
    _check("(a) linear chain: concordance 1.0, fidelity 1.0, forbidden realised 0.0",
           fwd["order_concordance"] == 1.0 and fwd["causal_order_fidelity"] == 1.0
           and fwd["forbidden_order_realised_rate"] == 0.0 and fwd["graded"] == 2
           and fwd["edge_available_rate"] == 1.0 and fwd["temporal_discrimination"] == 1.0,
           f"{fwd['order_concordance']}/{fwd['causal_order_fidelity']}/{fwd['forbidden_order_realised_rate']}")

    rev = _grade([{"edges": [E_AB, E_BC]}], TIMES_REV)
    _check("(a) time-MIRRORED chain: concordance 0.0, fidelity 0.0, forbidden realised 1.0",
           rev["order_concordance"] == 0.0 and rev["causal_order_fidelity"] == 0.0
           and rev["forbidden_order_realised_rate"] == 1.0 and rev["temporal_discrimination"] == 0.0,
           f"{rev['order_concordance']}/{rev['causal_order_fidelity']}/{rev['forbidden_order_realised_rate']}")

    # The legacy join takes NO times: same edges + same entities -> same fidelity, so it
    # is blind to the mirror by construction (the finding this module exists for).
    legacy = report._grade_chain_fidelity([E_AB, E_BC], ENT, RELS, STEP_ORDER)
    legacy_again = report._grade_chain_fidelity([E_AB, E_BC], ENT, RELS, STEP_ORDER)
    _check("(a) LEGACY chain_fidelity/FCR cannot tell forward from mirrored (no clock input)",
           legacy == legacy_again and legacy["chain_fidelity"] is not None
           and "times" not in inspect.signature(report._grade_chain_fidelity).parameters,
           f"chain_fidelity={legacy['chain_fidelity']}")

    # Late edge: order holds, but the only edge joining b->c is evidenced AFTER c's last event.
    late_bc = dict(E_BC, ts_ms=350)
    late_items = [ITEMS[0], _alert("c", "al-c", "ev-c", 350)]
    late = _grade([{"edges": [E_AB, late_bc]}], TIMES_FWD, items=late_items)
    legacy_late = report._grade_chain_fidelity([E_AB, late_bc], ENT, RELS, STEP_ORDER)
    _check("(a) late edge: concordance 1.0 but edge_available_rate 0.5, fidelity 0.5; "
           "legacy chain_fidelity is unchanged",
           late["order_concordance"] == 1.0 and late["edge_available_rate"] == 0.5
           and late["causal_order_fidelity"] == 0.5
           and legacy_late["chain_fidelity"] == legacy["chain_fidelity"],
           f"co={late['causal_order_fidelity']} legacy={legacy_late['chain_fidelity']}")

    # Typed-kind winner: within ONE incident the winning edge is chosen by kind rank before
    # time, so a later 'caused_by' edge can displace the earlier field-pair edge.
    typed = dict(E_BC, kind="caused_by", ts_ms=350)
    early = dict(E_BC, ts_ms=300)
    inc_typed = {"edges": [E_AB, typed]}
    inc_early = {"edges": [dict(E_AB), early]}
    items2 = [ITEMS[0], _alert("c", "al-c", "ev-c", 350), _alert("c", "al-c2", "ev-c", 300)]
    only_typed = _grade([inc_typed], TIMES_FWD, items=items2)
    both_1 = _grade([inc_typed, inc_early], TIMES_FWD, items=items2)
    both_2 = _grade([inc_early, inc_typed], TIMES_FWD, items=items2)
    _check("(a) typed-kind winner pushes the edge past the to-step -> no credit on its own; "
           "an earlier edge in another incident rescues it, in EITHER incident order",
           only_typed["causal_order_fidelity"] == 0.5 and both_1["causal_order_fidelity"] == 1.0
           and both_1["causal_order_fidelity"] == both_2["causal_order_fidelity"]
           and json.dumps(both_1, sort_keys=True) == json.dumps(both_2, sort_keys=True),
           f"typed-only={only_typed['causal_order_fidelity']} both={both_1['causal_order_fidelity']}"
           f"/{both_2['causal_order_fidelity']}")

    # Unattributed edges earn nothing.
    ghost = dict(E_BC, event_id="no-such-event")
    digest = dict(E_BC, ts_ms=int("9" * 18))  # a time_fallback-style digest ts: matches no alert time
    for label, bad in (("unknown event_id", ghost), ("time-fallback digest ts_ms", digest)):
        g = _grade([{"edges": [E_AB, bad]}], TIMES_FWD)
        _check(f"(a) unattributed edge ({label}) earns no credit",
               g["causal_order_fidelity"] == 0.5 and g["edge_stats"]["unattributed"] == 1
               and g["order_concordance"] == 1.0,
               f"fidelity={g['causal_order_fidelity']} stats={g['edge_stats']}")
    amb_items = ITEMS + [_alert("a", "al-a", "ev-c", 300)]  # same (event_id, time) on two steps
    g = _grade([{"edges": [E_AB, E_BC]}], TIMES_FWD, items=amb_items)
    _check("(a) ambiguous attribution (one edge, two steps) earns no credit",
           g["edge_stats"]["ambiguous"] == 1 and g["causal_order_fidelity"] == 0.5,
           f"stats={g['edge_stats']}")

    # DAG: d has two parents; only the p2 -> d relation is inverted.
    ent = {"p1": {"P1"}, "p2": {"P2"}, "d": {"D1"}}
    rels = [{"from": "p1", "to": "p2", "allowed": True},
            {"from": "p1", "to": "d", "allowed": True},
            {"from": "p2", "to": "d", "allowed": True}]
    edges = [{"from": "P1", "to": "P2", "kind": "k", "event_id": "e2", "ts_ms": 300},
             {"from": "P1", "to": "D1", "kind": "k", "event_id": "e3", "ts_ms": 200},
             {"from": "P2", "to": "D1", "kind": "k", "event_id": "e3", "ts_ms": 200}]
    items = [_alert("p2", "x2", "e2", 300), _alert("d", "x3", "e3", 200)]
    times = {"p1": (100, 100), "p2": (300, 300), "d": (200, 200)}
    g = co.grade_causal_order([{"edges": edges}], ent, rels, ["p1", "p2", "d"], times, items, join_fn=_join)
    failed = sorted((r["from"], r["to"]) for r in g["per_pair"] if r.get("graded") and not r["ordered"])
    _check("(a) DAG: exactly the inverted parent->child pair fails (p2->d), concordance 2/3",
           failed == [("p2", "d")] and g["order_concordance"] == round(2 / 3, 4),
           f"failed={failed} concordance={g['order_concordance']}")

    # Ties are lenient on concordance but visible.
    g = _grade([{"edges": [E_AB, E_BC]}], {"a": (100, 100), "b": (100, 100), "c": (300, 300)})
    _check("(a) ties count as ordered but temporal_discrimination exposes them",
           g["order_concordance"] == 1.0 and g["tie_pairs"] == 1 and g["temporal_discrimination"] == 0.5,
           f"ties={g['tie_pairs']} td={g['temporal_discrimination']}")

    # Honest nulls.
    g = _grade([], TIMES_FWD, items=[])
    _check("(a) no edges -> fidelity None (never a fabricated 0) while concordance is still real",
           g["causal_order_fidelity"] is None and g["order_concordance"] == 1.0
           and g["edge_available_rate"] is None)
    g = _grade([{"edges": [E_AB, E_BC]}], {"a": (100, 100)})
    _check("(a) no timed pair -> concordance None and fidelity None, not 0",
           g["order_concordance"] is None and g["causal_order_fidelity"] is None and g["graded"] == 0)
    g = _grade([{"edges": [E_AB, E_BC]}], TIMES_FWD, ent={"a": {"A1"}, "b": set(), "c": {"C1"}})
    _check("(a) a step with no entities is not graded (same denominator rule as chain_fidelity)",
           g["graded"] == 0 and all(r["reason"] == "step-not-entity-bearing" for r in g["per_pair"]))


def _test_mutations() -> None:
    base = _grade([{"edges": [E_AB, E_BC]}], TIMES_FWD)["order_concordance"]
    src = inspect.getsource(co.ordered)
    ns: dict = {}
    exec(compile(src.replace("t_from <= t_to", "t_from >= t_to"), "<mut-ordered>", "exec"), ns)  # noqa: S102
    saved = co.ordered
    co.ordered = ns["ordered"]
    try:
        mutated = _grade([{"edges": [E_AB, E_BC]}], TIMES_FWD)["order_concordance"]
    finally:
        co.ordered = saved
    _check("(b) flipping `<=` in ordered() drops the true chain's concordance (check is load-bearing)",
           base == 1.0 and mutated is not None and mutated < 1.0, f"{base} -> {mutated}")

    late_bc = dict(E_BC, ts_ms=350)
    late_items = [ITEMS[0], _alert("c", "al-c", "ev-c", 350)]
    good = _grade([{"edges": [E_AB, late_bc]}], TIMES_FWD, items=late_items)["edge_available_rate"]
    src = inspect.getsource(co.edge_known_by)
    ns = {}
    exec(compile(src.replace("return ts_ms <= t_last", "return True"), "<mut-known>", "exec"), ns)  # noqa: S102
    saved = co.edge_known_by
    co.edge_known_by = ns["edge_known_by"]
    try:
        mutated = _grade([{"edges": [E_AB, late_bc]}], TIMES_FWD, items=late_items)["edge_available_rate"]
    finally:
        co.edge_known_by = saved
    _check("(b) removing the ts_ms bound makes the late-edge graph look available (bound is load-bearing)",
           good == 0.5 and mutated == 1.0, f"{good} -> {mutated}")

    # ... and the real-pipeline join predicate is what decides A: mutate report._fidelity_join
    # (the SAME mutation test_chain_fidelity.py uses) and the identity run's fidelity moves.
    sdef = reg.get("it_intrusion")
    base_cof = reg.grade(sdef, SEED)["causal_order_fidelity"]
    srcj = inspect.getsource(report._fidelity_join)
    nsj: dict = {}
    exec(compile(srcj.replace("if f in from_side and t in to_side:", "if t in from_side and f in to_side:"),
                 "<mut-join>", "exec"), nsj)  # noqa: S102
    savedj = report._fidelity_join
    report._fidelity_join = nsj["_fidelity_join"]
    try:
        mut_cof = reg.grade(sdef, SEED)["causal_order_fidelity"]
    finally:
        report._fidelity_join = savedj
    _check("(b) reversing from/to in report._fidelity_join moves causal_order_fidelity "
           "(the edge term really uses the shared predicate)",
           base_cof is not None and mut_cof is not None and mut_cof < base_cof, f"{base_cof} -> {mut_cof}")


# ---------------------------------------------------------------------------
# real storylines
# ---------------------------------------------------------------------------
def _reference(grade: dict, result, oracle: dict) -> dict:
    """From-scratch pair formula, independent of causal_order.py: O from the parser's event
    times; A from the report's own edges (direction + ts_ms bound)."""
    first: dict = {}
    last: dict = {}
    for ev in result.events:
        t = (ev.event or {}).get("time")
        if ev.event is None or not isinstance(t, (int, float)):
            continue
        first[ev.step] = min(first.get(ev.step, t), t)
        last[ev.step] = max(last.get(ev.step, t), t)
    ent = report._step_entity_ids(result, report._CHAIN_TENANT)
    seq = oracle["expected_sequence"]
    rank = {s: i for i, s in enumerate(seq)}
    n = o_ok = both = 0
    for rel in oracle["allowed_relationships"]:
        if not rel.get("allowed"):
            continue
        f, t = rel["from"], rel["to"]
        if not ent.get(f) or not ent.get(t) or f not in first or t not in first:
            continue
        n += 1
        ordered = first[f] <= first[t]
        side = set().union(*[ent.get(s, set()) for s in seq[:rank[f] + 1]])
        avail = any(e["from"] in side and e["to"] in ent[t] and e["ts_ms"] <= last[t]
                    for e in grade["graph_edges"])
        o_ok += ordered
        both += ordered and avail
    return {"graded": n, "order_concordance": round(o_ok / n, 4) if n else None,
            "causal_order_fidelity": round(both / n, 4) if n and grade["graph_edges"] else None}


def _test_real() -> dict:
    out = {}
    for sdef in reg.ALL:
        oracle = report._load_oracle(sdef.oracle_path)
        result = reg.run(sdef, SEED)
        g = report._grade_chain(result, oracle)
        c = g["causal_order"]
        ref = _reference(g, result, oracle)
        out[sdef.name] = g
        _check(f"(c) {sdef.name}: independent reference agrees (graded, concordance, fidelity)",
               ref["graded"] == c["graded"] and ref["order_concordance"] == c["order_concordance"]
               and ref["causal_order_fidelity"] == c["causal_order_fidelity"],
               f"ref={ref} module=({c['graded']}, {c['order_concordance']}, {c['causal_order_fidelity']})")
        _check(f"(c) {sdef.name}: identity run - concordance 1.0, alert_order_ok True, forbidden realised 0.0, "
               "WS-3 story order ok, parser time agreement 1.0",
               c["order_concordance"] == 1.0 and g["alert_order_ok"] is True
               and c["forbidden_order_realised_rate"] == 0.0 and c["story_order_ok"] is True
               and c["parser_time_agreement"] == 1.0,
               f"concordance={c['order_concordance']} forbidden={c['forbidden_order_realised_rate']} "
               f"story={c['story_order_ok']} parser={c['parser_time_agreement']}")
        _check(f"(c) {sdef.name}: every graph edge is attributed to an attack alert (0 unattributed/ambiguous)",
               c["edge_stats"]["unattributed"] == 0 and c["edge_stats"]["ambiguous"] == 0
               and c["edge_stats"]["edges_in"] > 0, str(c["edge_stats"]))
        a = json.dumps(c, sort_keys=True)
        b = json.dumps(report._grade_chain(reg.run(sdef, SEED), oracle)["causal_order"], sort_keys=True)
        _check(f"(c) {sdef.name}: same seed -> byte-identical causal_order output, no wall-clock field",
               a == b and "elapsed" not in a and "wall" not in a)
    expect = {"ai_to_ot": (5, 1.0), "it_intrusion": (6, 0.8333), "infra_takeover": (2, 1.0)}
    got = {n: (g["causal_order"]["graded"], g["causal_order"]["causal_order_fidelity"]) for n, g in out.items()}
    _check("(c) identity causal_order_fidelity / graded-pair counts (seed 7) match the measured values",
           got == expect, f"{got}")
    it = {(r["from"], r["to"]): r for r in out["it_intrusion"]["causal_order"]["per_pair"] if r.get("graded")}
    failing = sorted(k for k, r in it.items() if not r["passed"])
    _check("(c) it_intrusion: the one failing pair is the one with NO joining edge (recon -> brute force), "
           "and it fails on the edge term, not on order",
           failing == [("recon_port_scan", "ssh_bruteforce")] and it[failing[0]]["ordered"] is True
           and it[failing[0]]["edge_available"] is False, str(failing))
    _check("(c) the DAG is graded: it_intrusion dns_exfil has two graded parents",
           sum(1 for k in it if k[1] == "dns_exfil") == 2, str(sorted(k for k in it if k[1] == "dns_exfil")))
    return out


def _test_report_wiring() -> None:
    r = report.run(seed=SEED)
    m, ctx = r["metrics"], r["context"]
    _check("(d) run() emits causal_order_fidelity, order_concordance, alert_order_ok",
           m.get("causal_order_fidelity") == 1.0 and m.get("order_concordance") == 1.0
           and m.get("alert_order_ok") is True,
           str({k: m.get(k) for k in ("causal_order_fidelity", "order_concordance", "alert_order_ok")}))
    with open(report.BASELINE_PATH, "rb") as fh:
        raw = fh.read().replace(b"\r\n", b"\n")
    base = json.loads(raw.decode("utf-8"))
    _check("(d) eval/twin/baseline.json is byte-identical (sha256 of the frozen file)",
           hashlib.sha256(raw).hexdigest() == BASELINE_SHA256)
    _check("(d) every key in the frozen baseline is still emitted",
           set(base["metrics"]) <= set(m), str(sorted(set(base["metrics"]) - set(m))))
    cmp_keys = set(r["delta_vs_baseline"]["key_comparison"])
    _check("(d) the new keys are absent from delta_vs_baseline (schema drift: only shared keys compare)",
           not ({"causal_order_fidelity", "order_concordance", "alert_order_ok"} & cmp_keys)
           and cmp_keys <= set(base["metrics"]), str(sorted(cmp_keys - set(base["metrics"]))))
    kc = r["delta_vs_baseline"]["key_comparison"]
    _check("(d) legacy numbers unchanged: tpr 1.0, chain_fidelity 0.6, FCR 1.0, mttd 60.0 "
           "(and the baseline deltas for shared numeric keys are 0.0)",
           m["tpr"] == 1.0 and m["chain_fidelity"] == 0.6 and m["false_correlation_rate"] == 1.0
           and m["mttd_seconds"] == 60.0
           and all(v["delta"] in (0.0, "n/a") for v in kc.values()),
           f"tpr={m['tpr']} cf={m['chain_fidelity']} fcr={m['false_correlation_rate']} mttd={m['mttd_seconds']}")
    det = ctx["causal_order_details"]
    _check("(d) context carries the invariant label, the per-pair table and the co-reported policy",
           "timestamp invariant" in det["order_concordance_basis"] and len(det["per_pair"]) >= 1
           and det["reporting_policy"]["mode"] == "co_reported"
           and "timestamp invariant" in r["finding"],
           det["reporting_policy"]["mode"])

    # main()'s order floors: pass on the real report, trip on a broken order.
    saved_run, saved_trend = report.run, report._append_trend
    outs = []
    try:
        for label, tweak in (("real", None), ("broken concordance", ("order_concordance", 0.5)),
                             ("broken alert order", ("alert_order_ok", False))):
            rr = copy.deepcopy(r)
            if tweak:
                rr["metrics"][tweak[0]] = tweak[1]
            report.run = lambda seed=SEED, _rr=rr: _rr
            with tempfile.TemporaryDirectory() as td:
                outs.append((label, report.main(["--seed", str(SEED), "--out", str(Path(td) / "r.json"),
                                                 "--no-trend"])))
    finally:
        report.run, report._append_trend = saved_run, saved_trend
    _check("(d) main(): order floors pass on the real report and fail when concordance or alert order breaks",
           outs == [("real", 0), ("broken concordance", 1), ("broken alert order", 1)], str(outs))


def _test_policy_and_helpers() -> None:
    for dd in (0.0, None, 0.49):
        p = co.reporting_policy(dd)
        _check(f"(e) reporting_policy(dd={dd}): co_reported, legacy pair flagged order-blind, order metric "
               "would lead only if ratified",
               p["mode"] == "co_reported" and p["legacy_pair_discriminates_direction"] is False
               and p["would_lead_if_ratified"] == "causal_order_fidelity")
    p = co.reporting_policy(1.0)
    _check("(e) reporting_policy(dd=1.0): legacy pair would be re-promoted to co-headline; still co_reported",
           p["mode"] == "co_reported" and p["legacy_pair_discriminates_direction"] is True
           and "chain_fidelity" in p["would_lead_if_ratified"])

    seq = ["a", "b", "c"]
    _check("(e) story_order_ok: chronological and oracle-ordered -> True",
           co.story_order_ok([("a", 100), ("b", 200), ("c", 300)], seq) is True)
    _check("(e) story_order_ok: a package that presents the attack backwards -> False",
           co.story_order_ok([("c", 100), ("b", 200), ("a", 300)], seq) is False)
    _check("(e) story_order_ok: times that decrease inside the package -> False",
           co.story_order_ok([("a", 200), ("b", 100)], seq) is False)
    _check("(e) story_order_ok: simultaneous steps in either rank order -> True; <2 steps -> None",
           co.story_order_ok([("b", 100), ("a", 100)], seq) is True
           and co.story_order_ok([("a", 100), ("a", 200)], seq) is None
           and co.story_order_ok([], seq) is None)

    evs = [SimpleNamespace(step="a", event={"time": 1000}, raw=1000),
           SimpleNamespace(step="b", event={"time": 2000}, raw=2000)]
    _check("(e) parser_time_agreement: 1.0 when the parser keeps the raw clock",
           co.parser_time_agreement(evs, lambda e: e.raw) == 1.0)
    evs[1].event["time"] = 2  # a seconds-vs-milliseconds style WS-2 bug
    _check("(e) parser_time_agreement: drops below 1.0 on a unit/clock bug; None with no data",
           co.parser_time_agreement(evs, lambda e: e.raw) == 0.5
           and co.parser_time_agreement([], lambda e: None) is None)

    evs = [SimpleNamespace(step="a", event={"time": 5}), SimpleNamespace(step="a", event={"time": 9}),
           SimpleNamespace(step="b", event=None), SimpleNamespace(step="c", event={"time": "x"})]
    _check("(e) step_times: first/last over a burst; gapped and non-numeric steps are absent",
           co.step_times(evs) == {"a": (5, 9)})


def main() -> int:
    print("== FENGARDE twin: causal-order metrics (eval/twin/causal_order.py) ==")
    _test_unit()
    _test_mutations()
    _test_real()
    _test_report_wiring()
    _test_policy_and_helpers()
    print("-" * 60)
    if _FAILURES:
        print(f"[FAIL] {len(_FAILURES)} check(s) failed: {', '.join(_FAILURES)}")
        return 1
    print("[OK] all causal-order checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
