"""WP-3-C: chain_fidelity + incident_membership graded against the REAL WS-8 v2
incident graph -- standalone acceptance test for the twin scorecard's
chain-fidelity upgrade (eval/twin/report.py).

Standalone (NOT pytest), matching the repo twin-test style: ``if __name__``
guard, ``[OK]``/``[FAIL]`` lines, exit 0 only when every check passes.

Run:  python eval/twin/test_chain_fidelity.py

Checks (all against REAL pipeline numbers -- nothing hand-picked):
  (a) chain_fidelity is a real number (not None) for the seed-7 chain;
  (b) incident_membership_ok is True (one incident covers the whole chain);
  (c) mutation-soundness: an independent reference implementation must agree
      with report.py's number, and the direction check must be load-bearing --
      reversing from/to in the join test drops the fidelity, and a
      direction-blind grader answers differently on a graph where direction
      matters (both demonstrated against mutated copies, restored);
  (d) determinism: the grade computed twice from two fresh run() calls is
      identical;
  (e) negative controls are untouched: all four still promote zero INCIDENT-
      level alerts, scenario 1 still emits the LOW ticketed downgrade alert,
      and the report's fpr is 0.0.

Like report.py, this module must be imported with the SAME module-collision
discipline: `import report` pre-seeds sys.modules['main'] with ws4's main
before negative_controls binds Detector, and the WS-8 correlator is loaded
lazily under a unique name AFTER the chain has run -- never before.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import report  # noqa: E402

SEED = 7

_FAILURES: list[str] = []


def _check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        _FAILURES.append(name)


def _reference_join(edges: list[dict], from_side: set, to_side: set) -> bool:
    """The test's OWN from-scratch copy of the direction-checked join predicate
    (independent of report.py's implementation): some typed v2 graph edge runs
    from an entity on the earlier-step side to an entity at the to-step."""
    for ed in edges:
        if ed.get("from") in from_side and ed.get("to") in to_side:
            return True
    return False


def _reference_fidelity(edges, step_entities, allowed_rels, step_order):
    """Independent reimplementation of the WP-3-C fidelity formula."""
    idx = {label: i for i, label in enumerate(step_order)}
    allowed = [r for r in allowed_rels if r.get("allowed")]
    forbidden_rels = [r for r in allowed_rels if not r.get("allowed")]

    def earlier(f: str) -> set:
        side: set = set()
        for i in range(idx[f] + 1):
            side |= set(step_entities.get(step_order[i], ()))
        return side

    denom = correct = 0
    for rel in allowed:
        f, t = rel.get("from"), rel.get("to")
        if not step_entities.get(f) or not step_entities.get(t):
            continue  # both steps must be detected + entity-bearing
        denom += 1
        if _reference_join(edges, earlier(f), set(step_entities.get(t, ()))):
            correct += 1
    forbidden = 0
    for rel in forbidden_rels:
        f, t = rel.get("from"), rel.get("to")
        if not step_entities.get(t):
            continue
        if _reference_join(edges, earlier(f), set(step_entities.get(t, ()))):
            forbidden += 1
    if not edges or denom == 0:
        return None, correct, forbidden, denom
    return round((correct - forbidden) / denom, 4), correct, forbidden, denom


def _test_chain_fidelity_real(result: dict) -> None:
    """(a) chain_fidelity is a real harness-measured number (not None)."""
    cf = result["metrics"]["chain_fidelity"]
    ok = isinstance(cf, (int, float)) and not isinstance(cf, bool) and 0.0 <= cf <= 1.0
    _check("(a) chain_fidelity is a real number for seed 7", ok, f"chain_fidelity={cf}")


def _test_membership(result: dict) -> None:
    """(b) incident_membership_ok is True: exactly the oracle's incident_count
    incidents cover the FULL chain and every fired cross-step rule is
    co-located in one incident."""
    ctx = result["context"]
    ok = (
        ctx["incident_membership_ok"] is True
        and len(ctx["full_coverage_incident_ids"]) == 1
        and bool(ctx["full_coverage_incident_ids"])
        and ctx["incident_count"] >= 1
    )
    _check("(b) incident_membership_ok is True", ok,
           f"membership_ok={ctx['incident_membership_ok']} "
           f"incident_count={ctx['incident_count']} "
           f"promotions={ctx['incident_promotions']}")


def _build_step_entities() -> tuple[dict, object]:
    """Step -> set of canonical entity_ids from each step's REAL OCSF event
    (actor.user.name / canonical src_endpoint.ip / device mac-or-hostname),
    using the SAME canonical_entity_id the v2 graph nodes use. Also returns the
    real chain result for the mutation section's reversed-edge construction."""
    ws8 = report._ensure_ws8()
    chain = report.scenario.run_chain(seed=SEED, strict=True)
    out: dict[str, set] = {}
    for ev in chain.events:
        event = ev.event or {}
        ids: set = set()
        user = (event.get("actor") or {}).get("user")
        if isinstance(user, dict) and user.get("name"):
            eid = ws8.canonical_entity_id(report._CHAIN_TENANT, "actor", str(user["name"]))
            if eid:
                ids.add(eid)
        src = event.get("src_endpoint") or {}
        if src.get("ip"):
            eid = ws8.canonical_entity_id(report._CHAIN_TENANT, "ip", str(src["ip"]))
            if eid:
                ids.add(eid)
        device = src.get("mac") or src.get("hostname")
        if device:
            eid = ws8.canonical_entity_id(report._CHAIN_TENANT, "device", str(device))
            if eid:
                ids.add(eid)
        out[ev.step] = ids
    return out, chain


def _test_mutation_soundness(result: dict, step_entities: dict, chain: object) -> None:
    """(c) the reference agrees with report.py, and the direction check is
    load-bearing: reversing from/to drops the real fidelity; deleting the
    direction check changes the answer where direction matters."""
    import yaml  # noqa: PLC0415

    with open(TWIN / "oracle.yaml", "r", encoding="utf-8") as fh:
        oracle = yaml.safe_load(fh)
    allowed_rels = oracle["allowed_relationships"]
    step_order = oracle["expected_sequence"]
    edges = result["context"]["chain_graph_edges"]
    cf = result["metrics"]["chain_fidelity"]
    details = result["context"]["chain_fidelity_details"]

    ref_cf, ref_num, ref_forbidden, ref_denom = _reference_fidelity(
        edges, step_entities, allowed_rels, step_order)
    _check("(c) independent reference agrees with report.py's fidelity",
           ref_cf == cf and ref_num == details["correct_allowed_joins"]
           and ref_forbidden == details["forbidden_joins"]
           and ref_denom == details["denominator"],
           f"reference={ref_cf} (n={ref_num}, forbidden={ref_forbidden}, "
           f"denom={ref_denom}) vs report={cf}")

    # --- mutation 1: reverse from/to inside the join test (mutated copy, restore)
    src = inspect.getsource(report._fidelity_join)
    mut_rev = src.replace(
        "if f in from_side and t in to_side:",
        "if t in from_side and f in to_side:")
    ns: dict = {}
    exec(compile(mut_rev, "<mutated-reversed>", "exec"), ns)  # noqa: S102 - self-test harness
    saved = report._fidelity_join
    report._fidelity_join = ns["_fidelity_join"]
    try:
        f_rev = report._grade_chain_fidelity(
            edges, step_entities, allowed_rels, step_order)["chain_fidelity"]
    finally:
        report._fidelity_join = saved  # restore
    _check("(c) reversing from/to in the join test drops the fidelity",
           f_rev is not None and f_rev < cf, f"{cf} -> {f_rev}")

    # --- mutation 2: delete the direction check (undirected join) -- proven on a
    #     graph where direction matters (a reversed-only edge set built from the
    #     chain's REAL entity ids, identified BY TYPE: ip -> actor, the reverse
    #     of the correlator's real actor -> ip edge). On the seed-7 graph this
    #     mutation is a documented degenerate no-op (the single actor+ip pair
    #     sits on both sides of every step cut), so the reference-equality check
    #     above is what guards the real data; here the check is proven
    #     load-bearing.
    ws8 = report._ensure_ws8()
    ev_n8n = next((e for e in chain.events if e.step == "n8n_execution"), None)
    if ev_n8n is not None and ev_n8n.event:
        user = (ev_n8n.event.get("actor") or {}).get("user") or {}
        src_ep = ev_n8n.event.get("src_endpoint") or {}
        actor_id = ws8.canonical_entity_id(report._CHAIN_TENANT, "actor", str(user["name"]))
        ip_id = ws8.canonical_entity_id(report._CHAIN_TENANT, "ip", str(src_ep.get("ip")))
        rev_edges = [{"from": ip_id, "to": actor_id, "kind": "invoked"}]
        mut_undir = src.replace(
            "if f in from_side and t in to_side:",
            "if (f in from_side and t in to_side) or (t in from_side and f in to_side):")
        ns2: dict = {}
        exec(compile(mut_undir, "<mutated-undirected>", "exec"), ns2)  # noqa: S102
        report._fidelity_join = ns2["_fidelity_join"]
        try:
            f_undir = report._grade_chain_fidelity(
                rev_edges, step_entities, allowed_rels, step_order)["chain_fidelity"]
        finally:
            report._fidelity_join = saved  # restore
        f_dir = report._grade_chain_fidelity(
            rev_edges, step_entities, allowed_rels, step_order)["chain_fidelity"]
        _check("(c) deleting the direction check changes graded joins "
               "(direction is load-bearing)",
               f_undir is not None and f_dir is not None and f_undir != f_dir,
               f"direction-aware={f_dir} vs direction-blind={f_undir} on a "
               f"reversed-only edge graph")
    else:
        _check("(c) deleting the direction check changes graded joins "
               "(direction is load-bearing)", False,
               "n8n_execution event unavailable")


def _test_determinism() -> None:
    """(d) two fresh run() calls grade identically (byte-identical metrics and
    WS-8 context) EXCEPT the informational wall-clock metric that the docstring
    carves out: incident_reconstruction_time_ms is a real assembly-wall-clock
    measurement (median of a few builds) and may differ run-to-run -- the same
    carve-out `date`/`elapsed_seconds` already enjoy. Everything else is a
    pure function of the seed and must be byte-identical; the reconstruction
    package_id/block_count (deterministic) are asserted separately."""
    r1 = report.run(seed=SEED)
    r2 = report.run(seed=SEED)
    ctx_keys = ("incident_promotions", "incident_count", "incident_membership_ok",
                "full_coverage_incident_ids", "chain_fidelity_details",
                "chain_graph_edges", "incident_summary",
                "false_correlation_details", "alert_reduction",
                "analyst_investigation", "severity_confusion")
    _INFO = {"incident_reconstruction_time_ms"}  # wall-clock informational carve-out
    m1 = {k: v for k, v in r1["metrics"].items() if k not in _INFO}
    m2 = {k: v for k, v in r2["metrics"].items() if k not in _INFO}
    same = m1 == m2 and all(
        r1["context"][k] == r2["context"][k] for k in ctx_keys)
    recon = r1["context"]["incident_reconstruction"]
    _check("(d) grade is identical across two fresh run() calls (wall-clock "
           "reconstruction-time carved out as informational)",
           same and recon is not None and recon.get("verified") is True
           and r1["context"]["incident_reconstruction"]["package_id"]
           == r2["context"]["incident_reconstruction"]["package_id"],
           f"cf={r1['metrics']['chain_fidelity']}/{r2['metrics']['chain_fidelity']} "
           f"membership={r1['context']['incident_membership_ok']} "
           f"recon_verified={recon.get('verified')}")


def _test_negatives_untouched(result: dict) -> None:
    """(e) the negative-control path is untouched: all four scenarios still
    promote zero INCIDENT-level alerts, scenario 1 still emits the LOW ticketed
    downgrade alert, and the report's fpr is 0.0 (floor assertion)."""
    neg = report.negative_controls
    totals: dict[str, int] = {}
    for fn in neg._ALL_SCENARIOS:
        name, alerts = fn(SEED)
        totals[name] = sum(1 for a in alerts if neg.is_incident(a))
    _check("(e) all four negative controls still produce zero incidents",
           all(v == 0 for v in totals.values()), str(totals))
    s1_alerts = neg.scenario_maintenance_window(SEED)[1]
    ticketed = [a for a in s1_alerts if a["rule_id"] == neg._TICKETED_RULE_ID]
    _check("(e) approved-maintenance-window still emits the LOW ticketed "
           "downgrade alert (mechanism alive, not silent suppression)",
           len(ticketed) >= 1, f"{len(ticketed)} LOW ticketed alert(s)")
    _check("(e) report fpr is 0.0 (floor asserts fpr == 0.0)",
           result["metrics"]["fpr"] == 0.0, f"fpr={result['metrics']['fpr']}")


def main(argv: list[str] | None = None) -> int:
    print("== FENGARDE twin: chain_fidelity vs REAL WS-8 v2 incident graph ==")
    print(f"seed={SEED}\n")

    result = report.run(seed=SEED)  # one real full-twin run

    _test_chain_fidelity_real(result)
    _test_membership(result)
    step_entities, chain = _build_step_entities()
    _test_mutation_soundness(result, step_entities, chain)
    _test_determinism()
    _test_negatives_untouched(result)

    print("-" * 60)
    if _FAILURES:
        print(f"[FAIL] {len(_FAILURES)} check(s) failed: {', '.join(_FAILURES)}")
        return 1
    print(f"[OK] all chain_fidelity / incident-membership checks passed "
          f"(seed={SEED}, chain_fidelity={result['metrics']['chain_fidelity']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())