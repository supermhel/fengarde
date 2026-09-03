"""WP-3.5-A: Phase 3.5 operational-outcome metrics graded against the REAL
WS-8 artifacts -- standalone acceptance test for eval/twin/report.py's
operational-outcome upgrade (alert reduction ratio, false correlation rate,
incident reconstruction time, analyst investigation time, severity
calibration -- the roadmap's Phase 3.5 metric set).

Standalone (NOT pytest), matching the repo twin-test style: ``if __name__``
guard, ``[OK]``/``[FAIL]`` lines, exit 0 only when every check passes.

Run:  python eval/twin/test_phase3_5.py

Checks (all against REAL pipeline numbers, never hand-picked):
  (a) alert_reduction_ratio == 1 - (incidents/alerts) cross-checked against
      the report's canonical top-level context.alert_count/
      incident_promotions (not the alert_reduction sub-block being tested);
      also checks that sub-block never silently diverges from those counts.
  (b) false_correlation_rate == an INDEPENDENT reference recomputation of
      oracle-DECLARED forbidden relationships joined by the real graph edges
      (same denominator rule: both from- and to-step must be entity-bearing);
      mutation-soundness: neutering the forbidden-denominator count in
      _grade_chain_fidelity must flip the report to None / disagree.
  (c) incident reconstruction: the report built the REAL WS-3 evidence
      package (package_id prefix, block_count >= incident+2, verified True),
      and -- mutation probe -- if the REAL verifier is forced to report
      tampering, report.verified must flip to False (proves the report calls
      the real hash-chain verifier, never hardcodes True).
  (d) analyst investigation (MTTI): investigation_steps == the reference walk
      count (1 open + members + entities + edges + 1) over the real incident;
      mtti_seconds == steps x the documented _ANALYST_STEP_SECONDS;
      api_round_trips == 1 + members + entities; member_alert_count/
      incident_id cross-checked against incident_summary and reconstruction.
  (e) severity confusion: totals equal the real fired-alert count, the
      correct+over+under+unexpected+unrecognized tally matches the per-alert
      rows, and the per-expected-level matrix breakdown matches an
      independent rebuild from those same rows.
  (f) mttr stays an HONEST null with the documented reason present.

Like report.py / test_chain_fidelity.py, this module must be imported with
the SAME module-collision discipline: `import report` pre-seeds
sys.modules['main'] with ws4's main before negative_controls binds Detector,
and the WS-8 correlator is loaded lazily under a unique name AFTER the chain
has run -- never before.
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


def _load_oracle():
    import yaml  # noqa: PLC0415

    with open(TWIN / "oracle.yaml", "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ---------------------------------------------------------------------------
# (b) independent reference: forbidden pairs joined by the real edges.
# ---------------------------------------------------------------------------
def _reference_false_correlation(edges, step_entities, oracle, step_order):
    """From-scratch reimplementation (independent of report.py): fraction of
    oracle-DECLARED forbidden relationships (allowed: false) that a real
    graph edge joins, with the SAME denominator rule report.py uses (BOTH the
    from-step and the to-step must be entity-bearing -- the same rule the
    allowed-pair loop applies). Returns (rate, joined, denominator)."""
    idx = {label: i for i, label in enumerate(step_order)}

    def earlier(f: str) -> set:
        side: set = set()
        if f not in idx:
            return side
        for i in range(idx[f] + 1):
            side |= set(step_entities.get(step_order[i], ()))
        return side

    forbidden_rels = [r for r in oracle.get("allowed_relationships") or []
                      if not r.get("allowed")]
    denom = joined = 0
    for rel in forbidden_rels:
        f, t = rel.get("from"), rel.get("to")
        from_set = set(step_entities.get(f, ()))
        to_set = set(step_entities.get(t, ()))
        if not from_set or not to_set:
            continue
        denom += 1
        if any(ed.get("from") in earlier(f) and ed.get("to") in to_set
               for ed in edges):
            joined += 1
    rate = round(joined / denom, 4) if denom else None
    return rate, joined, denom


def _reference_investigation_steps(inv_ctx: dict) -> int:
    """Independent recomputation of the scripted-walk step count from the
    walk's own documented components (open + members + entities + edges +
    assemble) -- the same definition the report declares, recomputed from
    the inv_ctx's real counts rather than trusting its summary number."""
    return (1 + inv_ctx["member_alert_count"] + inv_ctx["entity_count"]
            + inv_ctx["edge_count"] + 1)


# ---------------------------------------------------------------------------
# (a) alert reduction ratio
# ---------------------------------------------------------------------------
def _test_alert_reduction(result: dict) -> None:
    ctx = result["context"]
    m = result["metrics"]
    # Independent of context.alert_reduction (the sub-block under test):
    # context.alert_count / incident_promotions are built by a different
    # code path in run() (the report's canonical top-level counts), not
    # copied from the same alert_reduction dict this check verifies.
    raw_alerts = ctx["alert_count"]
    incidents = ctx["incident_promotions"]
    ref = round(1 - (incidents / raw_alerts), 4) if raw_alerts else None
    ok = (m["alert_reduction_ratio"] == ref
          and isinstance(m["alert_reduction_ratio"], float))
    _check("(a) alert_reduction_ratio == 1 - incidents/alerts, cross-checked "
           "against the canonical context.alert_count/incident_promotions",
           ok,
           f"report={m['alert_reduction_ratio']} reference={ref} "
           f"({raw_alerts} alerts / {incidents} incidents)")

    # context.alert_reduction must not silently diverge from those same
    # canonical counts -- this is exactly the failure mode of two
    # independently-sourced "total alerts" numbers drifting apart.
    _check("(a) context.alert_reduction mirrors the canonical "
           "alert_count/incident_promotions, not a second independent count",
           ctx["alert_reduction"]["raw_alert_count"] == raw_alerts
           and ctx["alert_reduction"]["incident_count"] == incidents,
           f"alert_reduction={ctx['alert_reduction']}")


# ---------------------------------------------------------------------------
# (b) false correlation rate + mutation
# ---------------------------------------------------------------------------
def _test_false_correlation(result: dict) -> None:
    oracle = _load_oracle()
    edges = result["context"]["chain_graph_edges"]
    step_order = oracle["expected_sequence"]
    step_entities = _build_step_entities()
    ref_rate, ref_joined, ref_denom = _reference_false_correlation(
        edges, step_entities, oracle, step_order)
    m_rate = result["metrics"]["false_correlation_rate"]
    details = result["context"]["false_correlation_details"]
    ok = (m_rate == ref_rate
          and details["forbidden_joins"] == ref_joined
          and details["forbidden_denominator"] == ref_denom)
    _check("(b) false_correlation_rate == reference recomputation over real "
           "edges + oracle-declared forbidden pairs",
           ok, f"report={m_rate} ({details['forbidden_joins']}/"
               f"{details['forbidden_denominator']}) reference={ref_rate} "
               f"({ref_joined}/{ref_denom})")

    # Mutation probe: neuter the forbidden-denominator count -> the report's
    # rate must disagree with the independent reference (denominator -> 0 ->
    # None). Mutated copy compiled from source, then restored.
    src = inspect.getsource(report._grade_chain_fidelity)
    mut = src.replace(
        "forbidden_denominator += 1", "pass  # neutered by test")
    ns: dict = {"_fidelity_join": report._fidelity_join}
    exec(compile(mut, "<mutated-fcr-denominator>", "exec"), ns)  # noqa: S102 - self-test
    saved = report._grade_chain_fidelity
    report._grade_chain_fidelity = ns["_grade_chain_fidelity"]
    try:
        r_mut = report.run(seed=SEED)
        mut_rate = r_mut["metrics"]["false_correlation_rate"]
        mut_denom = r_mut["context"]["false_correlation_details"]["forbidden_denominator"]
    finally:
        report._grade_chain_fidelity = saved  # restore
    _check("(b) mutation: neutering the forbidden-denominator count "
           "disagrees with the reference (rate is not a silently stable "
           "constant)",
           (mut_rate is None or mut_rate != ref_rate) and mut_denom != ref_denom,
           f"reference={ref_rate} ({ref_denom}) -> mutated rate={mut_rate} "
           f"denom={mut_denom}")


# ---------------------------------------------------------------------------
# (c) incident reconstruction (real WS-3 evidence package)
# ---------------------------------------------------------------------------
def _test_reconstruction(result: dict) -> None:
    recon = result["context"]["incident_reconstruction"]
    m = result["metrics"]
    ok_real = (recon is not None
               and recon.get("verified") is True
               and (recon.get("package_id") or "").startswith("twin-recon:")
               and isinstance(recon.get("block_count"), int)
               and recon["block_count"] >= 3  # incident + >=1 alert + >=1 event
               and isinstance(m["incident_reconstruction_time_ms"], (int, float)))
    _check("(c) incident reconstruction: REAL WS-3 evidence package built, "
           "hash-chain verified, deterministic package_id, wall-clock "
           "assembly latency reported",
           ok_real,
           f"package_id={recon.get('package_id')} blocks={recon.get('block_count')} "
           f"verified={recon.get('verified')} "
           f"recon_ms={m['incident_reconstruction_time_ms']}")

    # Mutation probe: force the REAL verifier to report tampering -> the
    # report must flip verified to False (proves it calls the real verifier
    # rather than hardcoding True).
    evpkg = report._ensure_evidence()
    real_verify = evpkg.verify_evidence_package
    evpkg.verify_evidence_package = lambda pkg: ["forced tamper"]  # type: ignore[assignment]
    try:
        r_mut = report.run(seed=SEED)
        mut_verified = r_mut["context"]["incident_reconstruction"]["verified"]
    finally:
        evpkg.verify_evidence_package = real_verify  # restore
    _check("(c) mutation: forcing the real verifier to fail flips the "
           "report's verified flag to False",
           mut_verified is False, f"mutated verified={mut_verified}")


# ---------------------------------------------------------------------------
# (d) analyst investigation time (MTTI) -- scripted walk
# ---------------------------------------------------------------------------
def _test_investigation(result: dict) -> None:
    ctx = result["context"]
    inv = ctx["analyst_investigation"]
    m = result["metrics"]
    ref_steps = _reference_investigation_steps(inv)
    ok = (inv is not None
          and inv["investigation_steps"] == ref_steps
          and inv["investigation_steps"] > 0
          and m["mtti"] == round(ref_steps * report._ANALYST_STEP_SECONDS, 3))
    _check("(d) analyst investigation walk: steps == reference count "
           "(open + members + entities + edges + assemble), mtti == "
           "steps x documented analyst model",
           ok,
           f"steps={inv['investigation_steps']} reference={ref_steps} "
           f"mtti={m['mtti']} model={inv['analyst_step_seconds_model']}s")

    _check("(d) api_round_trips == 1 (open) + member alerts + entities",
           inv["api_round_trips"] == 1 + inv["member_alert_count"] + inv["entity_count"],
           f"api_round_trips={inv['api_round_trips']} "
           f"members={inv['member_alert_count']} entities={inv['entity_count']}")

    # Independent cross-check: member_alert_count must agree with the SAME
    # incident's member_count in incident_summary -- a value computed by a
    # different code path (_grade_ws8's incident_summary list, straight off
    # the promoted incident dict) than _investigation_walk's own
    # len(members). Also ties investigation and reconstruction to the SAME
    # picked incident, proving _pick_full_coverage_incident is genuinely
    # shared rather than two copies that could silently diverge.
    summary_row = next((s for s in ctx["incident_summary"]
                        if s["incident_id"] == inv["incident_id"]), None)
    recon_incident_id = (ctx["incident_reconstruction"] or {}).get("incident_id")
    _check("(d) investigation's incident_id/member_alert_count agree with "
           "the independently-built incident_summary and reconstruction",
           summary_row is not None
           and summary_row["member_count"] == inv["member_alert_count"]
           and recon_incident_id == inv["incident_id"],
           f"incident_id={inv['incident_id']} summary_member_count="
           f"{summary_row['member_count'] if summary_row else None} "
           f"inv_member_count={inv['member_alert_count']} "
           f"recon_incident_id={recon_incident_id}")


# ---------------------------------------------------------------------------
# (e) severity confusion matrix
# ---------------------------------------------------------------------------
def _test_severity_confusion(result: dict) -> None:
    sev = result["context"]["severity_confusion"]
    rows = sev["per_alert"]
    by_verdict: dict[str, int] = {}
    for row in rows:
        by_verdict[row["verdict"]] = by_verdict.get(row["verdict"], 0) + 1
    tally_ok = (by_verdict.get("correct", 0) == sev["correct"]
                and by_verdict.get("over-alert", 0) == sev["over_alerting"]
                and by_verdict.get("under-alert", 0) == sev["under_alerting"]
                and by_verdict.get("unexpected", 0) == sev["unexpected"]
                and by_verdict.get("unrecognized-level", 0)
                    == sev.get("unrecognized_level", 0))
    # every fired alert must appear exactly once; total equals the real
    # fired-alert count reported by the chain context
    fired_total = result["context"]["alert_count"]
    _check("(e) severity confusion: per-alert tally matches the matrix "
           "counts and every real fired alert is classified once",
           tally_ok and len(rows) == sev["total_alerts"] == fired_total,
           f"correct={sev['correct']} over={sev['over_alerting']} "
           f"under={sev['under_alerting']} unexpected={sev['unexpected']} "
           f"unrecognized={sev.get('unrecognized_level', 0)} "
           f"total={sev['total_alerts']} fired={fired_total}")

    # Independent cross-check of the per-expected-level `matrix` breakdown
    # (previously untested): rebuild it from per_alert rows and compare
    # cell-by-cell -- a bucketing bug in the matrix specifically would now
    # fail this check even though the flat correct/over/under counters above
    # stayed right.
    ref_matrix: dict = {}
    for row in rows:
        if row["verdict"] in ("unexpected", "unrecognized-level"):
            continue
        level = str(row["expected_level"])
        ref_matrix.setdefault(level, {})
        ref_matrix[level][row["verdict"]] = ref_matrix[level].get(row["verdict"], 0) + 1
    _check("(e) severity confusion matrix matches an independent rebuild "
           "from per_alert rows",
           sev["matrix"] == ref_matrix,
           f"matrix={sev['matrix']} reference={ref_matrix}")


# ---------------------------------------------------------------------------
# (f) MTTR honest null
# ---------------------------------------------------------------------------
def _test_mttr_null(result: dict) -> None:
    m = result["metrics"]
    reason = result["context"].get("mttr_null_reason")
    ok = m["mttr"] is None and bool(reason) and "remediation" in reason
    _check("(f) mttr is an honest null with a documented reason (no "
           "remediation/closure event in the twin harness)",
           ok, f"mttr={m['mttr']} reason_present={bool(reason)}")


# ---------------------------------------------------------------------------
# shared fixtures
# ---------------------------------------------------------------------------
def _build_step_entities() -> dict:
    """Step -> set of canonical entity_ids from each step's REAL OCSF event
    (actor.user.name / canonical src_endpoint.ip / device mac-or-hostname),
    using the SAME canonical_entity_id the v2 graph nodes use."""
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
    return out


def main(argv: list[str] | None = None) -> int:
    print("== FENGARDE twin: Phase 3.5 operational outcome metrics ==")
    print(f"seed={SEED}\n")

    result = report.run(seed=SEED)  # one real full-twin run

    _test_alert_reduction(result)
    _test_false_correlation(result)
    _test_reconstruction(result)
    _test_investigation(result)
    _test_severity_confusion(result)
    _test_mttr_null(result)

    print("-" * 60)
    if _FAILURES:
        print(f"[FAIL] {len(_FAILURES)} check(s) failed: {', '.join(_FAILURES)}")
        return 1
    m = result["metrics"]
    print(f"[OK] all Phase 3.5 operational-metric checks passed "
          f"(seed={SEED}, fcr={m['false_correlation_rate']} "
          f"arr={m['alert_reduction_ratio']} mtti={m['mtti']} "
          f"recon_ms={m['incident_reconstruction_time_ms']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())