"""WP-1-F: the FENGARDE twin scorecard (`eval/twin/report.py`).

Runs the FULL AI-to-OT twin (WP-1-A..E) in one pass and emits a machine-readable
scorecard (`report.json`) carrying every metric the harness spec + Phase 3.5
operational set demand. This is the integration package that turns the twin's
individual modules into a single, longitudinal, honest measurement.

METRIC HONESTY (the whole point of this file)
---------------------------------------------
Every metric is emitted with a `basis` of ``"harness-measured"`` (simulation /
replay numbers, never field numbers — Phase 3.5 discipline). Metrics the twin
genuinely cannot measure today are emitted with their true value, never a
fabricated one:

  * chain_fidelity             = 0.6 for seed 7 (WP-3-C, 2026-09-02): measured
                                       against the REAL WS-8 v2 incident graph.
                                       The chain's real alerts are run through
                                       the real Correlator (fixed now_fn); the
                                       v2 graph's typed edges are graded against
                                       every oracle allowed_relationship that
                                       has both steps detected and entity-
                                       bearing. Explicit non-edges (allowed:
                                       false) that a graph edge joins count
                                       AGAINST the fraction (a false
                                       correlation, never hidden). Stays None
                                       when no incident promotes or no
                                       denominator exists -- never fabricated.
                                       The seed-7 graph carries ONE typed edge
                                       (actor:ot-engineer -> ip:10.20.0.50,
                                       kind invoked, evidenced by the
                                       agent_mcp_tool_call egress alert), which
                                       satisfies all 5 graded allowed joins AND
                                       2 of the 2 forbidden pairs (the actor+ip
                                       pair is present on both sides of every
                                       step cut, so entity-presence joins cannot
                                       discriminate direction): fidelity =
                                       (5 correct - 2 forbidden) / 5 = 0.6,
                                       with the breakdown reported in context.
  * fpr                        = 0.0 (measured: an INCIDENT count, i.e.,
                                       medium+ alerts only — see
                                       negative_controls.is_incident(). The
                                       approved-maintenance-window write still
                                       fires an alert (the parser has no
                                       signal to discriminate it from the
                                       real attack chain's identical coil
                                       address + source IP), but at LOW
                                       severity via the ticketed-write
                                       companion rule, so it's not counted
                                       as an incident. See negative_controls.py.)
  * mtti / mttr                = mtti is now REAL (WP-3.5-A, 2026-09-03): a
                                       scripted investigation walk over the
                                       REAL incident graph (member alerts +
                                       entities + causal edges counted), at
                                       the documented _ANALYST_STEP_SECONDS
                                       per step. mttr stays honest null: the
                                       twin harness has no remediation/closure
                                       event (no triage-API replay; incidents
                                       never close in the sim) -- fabricating
                                       a remediation time would lie about what
                                       the twin measures (see
                                       context.mttr_null_reason)
  * false_correlation_rate /
    alert_reduction_ratio      = NOW REAL (WP-3.5-A, 2026-09-03), computed
                                       from the SAME real WS-8 artifacts
                                       chain_fidelity grades: FCR is the
                                       fraction of oracle-DECLARED forbidden
                                       (allowed: false) relationships that a
                                       real graph edge joined (the negative-
                                       control half of chain fidelity); ARR
                                       is 1 - (incidents/alerts) over the
                                       same window. Both None only when no
                                       denominator exists -- not a fabricated
                                       zero. (Before this, null: not
                                       implemented.)
  * incident_reconstruction_time_ms = NOW REAL (WP-3.5-A, 2026-09-03): the
                                       assembly wall-clock (median of N
                                       samples) of building the REAL WS-3
                                       evidence package from the chain's real
                                       incident/alerts/events/graph, verified
                                       (hash chain intact). Wall-clock is
                                       informational (date carve-out --
                                       excluded from the byte-determinism
                                       assertion); package_id/block_count are
                                       deterministic. None when no incident.
  * mttd_seconds                = real: (first chain step whose oracle-expected
                                       rule fired) minus (chain start), both
                                       pulled from the actual raw-payload
                                       timestamps of the real chain run
  * mutation_robustness        = null (Phase 4 wires mutation; not measured yet)
  * evidence_completeness      = fraction of oracle per-step evidence fields
                                 present on real-parsed steps; gapped steps
                                 (external_content has no parser) count against
                                 it honestly
  * attribution_accuracy       = computed on ACTOR-BEARING steps only
                                 (OT alerts carry `actor={}` today — crediting
                                 them would fabricate attribution)

Determinism: same seed -> byte-identical report *except* the informational
wall-clock fields: ``date``, ``elapsed_seconds``, and WP-3.5-A's
``incident_reconstruction_time_ms`` (a real assembly-latency measurement --
reported as measured; excluded from the byte-determinism assertion by the
same carve-out ``date`` enjoys). All graded times are seed-derived fixed
constants, never wall-clock; the correlator is given a fixed ``now_fn``
(a constant 1h after the chain's last alert, so every chain alert is
in-window and no entry falls back to a wall-clock processing time).

Safety: this is a SIMULATION harness. No real control action is ever issued;
everything runs in-process on the memory bus against the loopback twin.

Usage:
    python eval/twin/report.py [--seed N] [--out PATH]
Wired as `make twin` (see Makefile) and as the twin lane of the nightly
evaluation workflow (.github/workflows/nightly-eval.yml).
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[2]
TWIN = ROOT / "eval" / "twin"
APPROOT_SERVICES = ROOT / "services"
# NOTE: do NOT insert ws2-normalization onto sys.path here. scenario.py manages
# its own ws2 path (its _get_ws2() pops 'main' and re-imports ws2's own main).
# Inserting ws2 at module top then importing negative_controls (which loads ws4's
# Detector as module 'main') corrupts 'main' resolution later. ws4 is loaded via
# spec_from_file_location below, exactly as the WP-1-F exploration verified.
sys.path.insert(0, str(TWIN))
sys.path.insert(0, str(APPROOT_SERVICES))

import importlib.util  # noqa: E402
import yaml  # noqa: E402

import degradation  # noqa: E402
import scenario  # noqa: E402

# ---------------------------------------------------------------------------
# Module-name collision guard (WP-1-F exploration verified this exact trap):
# scenario.py loads ws2's `main` module; negative_controls.py imports ws4's
# `Detector` as module `main`. Both share the bare name `main`, so whichever is
# cached in sys.modules["main"] first wins and the other ImportError's. The
# chain must run FIRST (ws2 main cached), and ws4's main must be injected as
# sys.modules["main"] BEFORE negative_controls imports it — so ws4's Detector
# is bound, not ws2's normalize_one. This is the same ordering discipline the
# exploration proved: run chain first; pre-seed sys.modules["main"] with ws4.
_WS4_MAIN = (ROOT / "services" / "ws4-detection" / "main.py")
_WS4_SPEC = importlib.util.spec_from_file_location("main", _WS4_MAIN)
_WS4_MOD = importlib.util.module_from_spec(_WS4_SPEC)
sys.modules["main"] = _WS4_MOD  # ws4's main must be what `from main import Detector` sees
if _WS4_SPEC and _WS4_SPEC.loader:
    _WS4_SPEC.loader.exec_module(_WS4_MOD)

import negative_controls  # noqa: E402

ORACLE_PATH = TWIN / "oracle.yaml"
REPORT_PATH = TWIN / "report.json"
# WP-1-G frozen baseline: the delta contract in baseline.json's header says
# new runs must emit the SAME metric keys and report a documented delta vs it.
# `run()` loads it (if present) and emits `report["delta_vs_baseline"]`.
BASELINE_PATH = TWIN / "baseline.json"
TREND_PATH = ROOT / "eval" / "trend.jsonl"

# ---------------------------------------------------------------------------
# Phase 3.5 constants (WP-3.5-A). Every number below is either a REAL
# measurement of the harness or a DOCUMENTED SIMULATION constant. Nothing is
# fabricated: the step latency below is the harness's declared analyst model
# (the roadmap's own Phase 3.5 cell: "wall-clock on a human run once a design
# partner exists" -- until then the twin reports a stated per-step model).
# ---------------------------------------------------------------------------
# Scripted analyst walk latency model: each investigation step (a graph edge
# traversed, an entity resolved, a member alert fetched) is modeled at this
# many seconds. Real step COUNTS are the measured quantity; seconds is the
# conversion the twin must use until a design partner supplies wall-clock
# data (roadmap Phase 3.5 "analyst investigation time").
_ANALYST_STEP_SECONDS = 30.0
# Informational wall-clock: how many times the REAL evidence package is
# rebuilt to measure assembly latency (median). Not part of the determinism
# contract -- same reason `date`/`elapsed_seconds` are exempt.
_RECONSTRUCTION_SAMPLES = 3

# The tenant the twin stamps on the chain's normalized events before detection
# (negative_controls.run_pipeline) -- the correlator's track/incident/canonical
# ids all key off it, so the WS-8 grading MUST use the identical tenant or the
# canonical entity ids would not match the graph nodes.
_CHAIN_TENANT = "twin-chain"

# ---------------------------------------------------------------------------
# WS-8 Correlator loading (WP-3-C). CRITICAL MODULE-COLLISION TRAP: loading
# the correlator file executes ITS OWN `sys.path.insert(0, str(HERE))` (HERE =
# services/ws8-correlation, which contains a top-level `main.py`), so loading
# it BEFORE scenario.run_chain would hijack scenario's bare `import main`
# (ws2 resolution) and crash with "module 'main' has no attribute
# 'normalize_one'". It is therefore loaded LAZILY, under a UNIQUE module name
# ("ws8_correlator_mod"), only after the chain has already been run in-process:
# scenario._get_ws2() caches ws2's module on first use, so later path
# pollution cannot re-resolve `main` to the wrong module. The unique name also
# means the correlator is never cached under a bare name another workstream
# might collide with.
_WS8_PATH = APPROOT_SERVICES / "ws8-correlation" / "correlator.py"
_WS8_MOD_NAME = "ws8_correlator_mod"


def _ensure_ws8():
    """Load the REAL WS-8 Correlator (spec_from_file_location, unique module
    name) once; return the module. See the trap note above for why this is
    lazy and why the name is unique."""
    mod = sys.modules.get(_WS8_MOD_NAME)
    if mod is not None:
        return mod
    spec = importlib.util.spec_from_file_location(_WS8_MOD_NAME, _WS8_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot locate {_WS8_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_WS8_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# WP-3.5-A: the REAL WS-3 evidence package as the incident-reconstruction
# artifact. Loaded the same way as WS-8 (spec_from_file_location, unique
# module name) -- evidence_package.py is stdlib-only (copy/hashlib/json/
# Counter), so it cannot hijack any bare module name, but the unique-name +
# lazy discipline is kept for consistency with the correlator.
# ---------------------------------------------------------------------------
_EVIDENCE_PATH = APPROOT_SERVICES / "ws3-indexer" / "evidence_package.py"
_EVIDENCE_MOD_NAME = "ws3_evidence_mod"


def _ensure_evidence():
    """Load the REAL WS-3 evidence_package module once; return the module."""
    mod = sys.modules.get(_EVIDENCE_MOD_NAME)
    if mod is not None:
        return mod
    spec = importlib.util.spec_from_file_location(_EVIDENCE_MOD_NAME, _EVIDENCE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot locate {_EVIDENCE_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_EVIDENCE_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


def _evidence_reconstruction(alerts_by_step: list[dict], by_id: dict,
                             graph_fn, now_ms: int) -> Optional[dict]:
    """WP-3.5-A incident reconstruction time: build the REAL WS-3 evidence
    package for the chain's full-coverage incident from the REAL chain
    artifacts the Correlator already produced, verify its hash chain, and
    measure REAL wall-clock assembly latency (median of a few builds).

    Determinism: ``now_ms`` is injected (the same fixed ``now`` the
    correlator used), so the package CONTENT and package_id are
    byte-identical across rebuilds; the measured assembly ms is wall-clock
    and is *informational* -- the exact carve-out ``date`` already enjoys
    (see the module docstring's determinism note). Returns None when no
    incident promoted (no artifact to reconstruct -- never fabricated).
    """
    if not by_id:
        return None
    chain_ids = {a["alert"]["alert_id"] for a in alerts_by_step}
    pick = next(
        (iid for iid, inc in by_id.items()
         if chain_ids <= set(inc.get("member_alert_ids") or [])),
        None)
    if pick is None:
        pick = sorted(by_id)[0]
    incident = by_id[pick]
    member_ids = set(incident.get("member_alert_ids") or [])
    alerts = [a["alert"] for a in alerts_by_step
              if a["alert"].get("alert_id") in member_ids]
    # Underlying normalized events: the chain's real parsed OCSF events,
    # carrying the same siem.ingest_id stamp the detection path gave them so
    # the provenance join has a handle to resolve (unresolved ids are listed
    # honestly by _build_provenance, never dropped).
    events = []
    for a in alerts_by_step:
        ev = a.get("event")
        if not ev:
            continue
        ev_copy = copy.deepcopy(ev)
        siem = ev_copy.setdefault("siem", {})
        siem.setdefault("ingest_id", f"twin:{a['step']}")
        events.append(ev_copy)
    graph = graph_fn(pick)

    evpkg = _ensure_evidence()
    samples = []
    pkg = None
    for _ in range(_RECONSTRUCTION_SAMPLES):
        t0 = time.perf_counter()
        pkg = evpkg.build_evidence_package(
            incident, alerts, events, graph,
            now_ms=now_ms, package_id_prefix="twin-recon")
        samples.append(round((time.perf_counter() - t0) * 1000.0, 4))
    samples_sorted = sorted(samples)
    median_ms = samples_sorted[len(samples_sorted) // 2] if samples_sorted else None
    failures = evpkg.verify_evidence_package(pkg) if pkg is not None else ["no package"]
    provenance = (pkg or {}).get("provenance") or []
    unresolved = sum(len(p.get("unresolved_event_ids") or []) for p in provenance)
    return {
        "basis": "harness-measured (wall-clock, informational like date)",
        "package_id": (pkg or {}).get("package_id"),
        "incident_id": pick,
        "block_count": ((pkg or {}).get("chain") or {}).get("block_count"),
        "verified": not failures,
        "verification_failures": failures,
        "assembly_median_ms": median_ms,
        "assembly_samples_ms": samples,
        "provenance_unresolved_event_ids": unresolved,
    }


# Level ranks for the severity confusion matrix (OCSF-ish ordering used by
# the rules: informational < low < medium < high < critical). Over/under are
# counted in rank space -- a HIGH firing where the oracle expected MEDIUM is
# an over-alert; a LOW where the oracle expected HIGH is an under-alert.
_LEVEL_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _investigation_walk(alerts_by_step: list[dict], by_id: dict,
                        edges: list[dict]) -> Optional[dict]:
    """WP-3.5-A analyst investigation time: a SCRIPTED walk over the REAL
    incident graph, counting the steps + API round-trips a scripted analyst
    needs to reach the causal answer.

    Walk model (documented, deterministic, all counts from real data):
      1  open the incident (1 API round-trip: list member alerts)
      + member alerts fetched (one per incident member)
      + distinct entities resolved (each graph node = 1 entity lookup)
      + causal edges traversed (each graph edge = 1 step)
      + 1  assemble the causal answer (the graph)
    `investigation_steps` is the REAL counted quantity; `mtti_seconds`
    converts it with the documented per-step analyst latency model
    (_ANALYST_STEP_SECONDS). Returns None when no incident promoted (no
    graph to investigate -- never fabricated).
    """
    if not by_id:
        return None
    full = next(
        (iid for iid, inc in by_id.items()
         if {a["alert"]["alert_id"] for a in alerts_by_step}
         <= set(inc.get("member_alert_ids") or [])), None)
    if full is None:
        full = sorted(by_id)[0]
    incident = by_id[full]
    members = incident.get("member_alert_ids") or []
    node_ids: set = set()
    for ed in edges:
        if ed.get("from"):
            node_ids.add(ed["from"])
        if ed.get("to"):
            node_ids.add(ed["to"])
    steps = 1 + len(members) + len(node_ids) + len(edges) + 1
    return {
        "basis": "harness-measured (step count real; seconds = documented "
                 "analyst latency model until a design partner supplies "
                 "wall-clock)",
        "incident_id": full,
        "member_alert_count": len(members),
        "entity_count": len(node_ids),
        "edge_count": len(edges),
        "investigation_steps": steps,
        "api_round_trips": 1 + len(members) + len(node_ids),
        "analyst_step_seconds_model": _ANALYST_STEP_SECONDS,
        "mtti_seconds": round(steps * _ANALYST_STEP_SECONDS, 3),
    }


def _severity_confusion(oracle: dict, alerts_by_step: list[dict]) -> dict:
    """WP-3.5-A severity calibration: confusion matrix of EXPECTED level
    (oracle detection_points, per step) vs ACTUAL fired-alert level.

    Each fired alert's rule_id is looked up in the oracle's
    detection_points[step].expected_rules to find its declared level; the
    actual level is the real fired alert's level. The matrix counts
    correct / over-alerting / under-alerting in rank space, plus a
    per-rule row. A rule the oracle does not declare at its step is counted
    as ``unexpected`` (an alert the oracle never expected -- a signal, not
    silently folded into correct). Real data both sides.
    """
    dp = oracle.get("detection_points") or {}
    expected_by_step_rule: dict[str, dict] = {}
    for step, spec in dp.items():
        for r in (spec.get("expected_rules") or []):
            expected_by_step_rule.setdefault(step, {})[r.get("rule_id")] = r.get("level")
    matrix: dict[str, dict] = {}
    over = under = correct = unexpected = 0
    rows = []
    for item in alerts_by_step:
        step = item["step"]
        alert = item["alert"]
        actual = alert.get("level")
        exp = (expected_by_step_rule.get(step) or {}).get(alert.get("rule_id"))
        if exp is None:
            unexpected += 1
            rows.append({"step": step, "rule_id": alert.get("rule_id"),
                         "expected_level": None, "actual_level": actual,
                         "verdict": "unexpected"})
            continue
        matrix.setdefault(str(exp), {})
        a_rank = _LEVEL_RANK.get(actual, 0)
        e_rank = _LEVEL_RANK.get(exp, 0)
        if a_rank == e_rank:
            verdict = "correct"
            correct += 1
        elif a_rank > e_rank:
            verdict = "over-alert"
            over += 1
        else:
            verdict = "under-alert"
            under += 1
        matrix[str(exp)][verdict] = matrix[str(exp)].get(verdict, 0) + 1
        rows.append({"step": step, "rule_id": alert.get("rule_id"),
                     "expected_level": exp, "actual_level": actual,
                     "verdict": verdict})
    total = correct + over + under + unexpected
    return {
        "basis": "harness-measured",
        "correct": correct,
        "over_alerting": over,
        "under_alerting": under,
        "unexpected": unexpected,
        "total_alerts": total,
        "matrix": matrix,
        "per_alert": rows,
    }


def _event_ts(ev: "scenario.ChainEvent") -> Optional[int]:
    """Epoch-ms this chain step's RAW payload was emitted at (works for gapped
    steps too, since raw_payload is always recorded -- see scenario.ChainEvent).
    """
    raw = (ev.raw_payload or {}).get("raw") or {}
    ts = raw.get("ts")
    return ts if ts is not None else raw.get("time")


def _load_oracle() -> dict:
    with open(ORACLE_PATH, "r", encoding="utf-8") as fh:
        oracle = yaml.safe_load(fh)
    return oracle


def _run_chain(seed: int) -> scenario.ChainResult:
    """Run the full chain through the real parsers (strict integrity)."""
    return scenario.run_chain(seed=seed, strict=True)


def _run_negatives(seed: int) -> tuple[dict, dict]:
    """Run all four negative controls; return (INCIDENT count per scenario,
    LOW-explained-alert count per scenario).

    A low/informational-severity alert (e.g. the ticketed-write companion
    rule firing instead of the HIGH one) is not an incident -- see
    negative_controls.is_incident(). Counting it as a false positive would
    misreport the fixed FPR as still nonzero. The explained dict is surfaced
    so the gate's floor can assert scenario 1 still emits the LOW ticketed
    alert (PR #80 finding 2: zero incidents alone cannot distinguish a clean
    FPR from a regression back to silent suppression).
    """
    per_scenario: dict[str, int] = {}
    explained: dict[str, int] = {}
    for fn in negative_controls._ALL_SCENARIOS:
        name, alerts = fn(seed)
        per_scenario[name] = sum(1 for a in alerts if negative_controls.is_incident(a))
        explained[name] = sum(1 for a in alerts if not negative_controls.is_incident(a))
    return per_scenario, explained


def _grade_chain(result: scenario.ChainResult, oracle: dict) -> dict:
    """Grade the chain against the oracle; return the metric sub-table.

    Honest by construction: TPR is computed from a REAL detection run (the
    scenario's raw payloads are fed through negative_controls.run_pipeline's
    genuine WS-2 -> WS-4 cascade), and evidence completeness from the REAL
    parsed OCSF events. Nothing is estimated.
    """
    expected_seq: list[str] = oracle["expected_sequence"]
    chain_labels = {e.step for e in result.events}
    seq_ok = all(label in chain_labels for label in expected_seq)

    parsed = [e for e in result.events if e.parsed]
    gaps = [e for e in result.events if e.gap]

    # Real detection run over the chain's own raw payloads (same shape the
    # negative controls use). Returns fired {rule_id, rule_title,
    # source_type, step}. Step labels are threaded through so a fired rule is
    # attributed to the EXACT chain step that triggered it -- not pooled by
    # source_type (plausible-A of the PR #80 review: two chain steps share
    # source_type `mcp_agent`, so source_type-pooling could credit a rule to
    # the wrong step).
    raw_pairs = [(e.source_type, (e.raw_payload or {}).get("raw", {}),
                  (e.raw_payload or {}).get("meta"), e.step) for e in parsed]
    fired = _real_detection(raw_pairs)

    # TPR: fraction of real-parsed chain steps whose oracle-expected rule fired.
    # Also track the RAW timestamp of the first step whose expected rule fired
    # (chain steps are emitted in strictly increasing time order -- see
    # scenario._build_chain_payloads -- so the first match encountered here is
    # the earliest), for an honest, sourced MTTD (see run()).
    matched_steps = 0
    first_matched_ts: Optional[int] = None
    for ev in parsed:
        pt = (oracle.get("detection_points") or {}).get(ev.step) or {}
        expected_ids = {r.get("rule_id") for r in (pt.get("expected_rules") or [])}
        if not expected_ids:
            continue  # no expected rule (oracle gap) -> not counted against TPR
        # PR #80 review (plausible-A): attribute fired rules by STEP, not by
        # source_type -- two chain steps can share a source_type (mcp_agent),
        # and source_type-pooling would let a rule fired on one step credit
        # another step sharing the same source.
        step_fired = {a["rule_id"] for a in fired if a.get("step") == ev.step}
        if step_fired & expected_ids:
            matched_steps += 1
            if first_matched_ts is None:
                first_matched_ts = _event_ts(ev)
    tpr_numer = matched_steps
    tpr_denom = sum(
        1 for ev in parsed if (oracle.get("detection_points") or {}).get(ev.step, {})
        .get("expected_rules")
    )
    # No denominator (every parsed step is an oracle gap) -> null, not a
    # fabricated 0.0 -- same discipline as chain_fidelity below.
    tpr = (tpr_numer / tpr_denom) if tpr_denom else None

    # Evidence completeness: oracle per-step evidence fields present on the real
    # parsed OCSF event for that step; gapped steps count against honestly.
    total_fields = 0
    present_fields = 0
    ev_by_step = {e.step: e for e in result.events}
    per_step = (oracle.get("evidence") or {}).get("per_step") or {}
    for step, meta in per_step.items():
        fields = meta.get("fields") or []
        total_fields += len(fields)
        # Every CHAIN_STEPS label is always a key in ev_by_step (scenario.py
        # emits exactly one ChainEvent per step, gapped or not) -- a gapped
        # step's .event is None, so `.event or {}` is `{}` and every field
        # lookup below correctly returns None -> counts against honestly,
        # with no separate "missing step" branch needed.
        the_event = ev_by_step[step].event or {} if step in ev_by_step else {}
        for f in fields:
            present_fields += 1 if _dot_get(the_event, f) is not None else 0
    evidence_completeness = present_fields / total_fields if total_fields else None

    chain_start_ts = _event_ts(result.events[0]) if result.events else None
    mttd_seconds = (
        round((first_matched_ts - chain_start_ts) / 1000.0, 3)
        if first_matched_ts is not None and chain_start_ts is not None
        else None  # nothing matched (or no timestamped events) -> honest null,
                   # never a fabricated "detected instantly" 0
    )

    # WP-3-C: grade the chain against the REAL WS-8 v2 incident graph (real
    # make_alert-shaped alerts -> real Correlator -> real v2 graph). Runs AFTER
    # the chain (so scenario's ws2 main resolution is already cached) and
    # lazily loads the WS-8 module (whose sys.path inserts would otherwise
    # hijack a later bare `import main`). None when nothing promotes -- never
    # a fabricated number.
    ws8_grade = _grade_ws8(result, oracle)

    return {
        "tpr": round(tpr, 4) if tpr is not None else None,
        "tpr_numerator": tpr_numer,
        "tpr_denominator": tpr_denom,
        "sequence_present": bool(seq_ok),
        "parsed_steps": len(parsed),
        "gap_steps": len(gaps),
        "fired_alerts": len(fired),
        "fired": fired,  # the real fired-alert dicts, so run() need not re-detect
        "mttd_seconds": mttd_seconds,
        "evidence_completeness": (
            round(evidence_completeness, 4) if evidence_completeness is not None else None
        ),
        # WP-3-C: now measured against the REAL WS-8 v2 incident graph (see
        # _grade_ws8 / _grade_chain_fidelity). A real fraction with the
        # numerator / forbidden-join breakdown reported in context; None only
        # when no incident promoted (no graph evidence) or no denominator.
        "chain_fidelity": ws8_grade["chain_fidelity"],
        "fidelity_numerator": ws8_grade["fidelity_numerator"],
        "forbidden_joins": ws8_grade["forbidden_joins"],
        "forbidden_denominator": ws8_grade["forbidden_denominator"],
        "fidelity_denominator": ws8_grade["fidelity_denominator"],
        "per_allowed_pair": ws8_grade["per_allowed_pair"],
        "per_forbidden_pair": ws8_grade["per_forbidden_pair"],
        "incident_promotions": ws8_grade["incident_promotions"],
        "incident_count": ws8_grade["incident_count"],
        "incident_membership_ok": ws8_grade["incident_membership_ok"],
        "full_coverage_incident_ids": ws8_grade["full_coverage_incident_ids"],
        "cross_step_rule_co_location": ws8_grade["cross_step_rule_co_location"],
        "incident_summary": ws8_grade["incident_summary"],
        "graph_edges": ws8_grade["graph_edges"],
        "chain_alert_count": ws8_grade["chain_alert_count"],
        # WP-3.5-A operational outcomes (real data, see _grade_ws8)
        "false_correlation_rate": ws8_grade["false_correlation_rate"],
        "alert_reduction_ratio": ws8_grade["alert_reduction_ratio"],
        "incident_reconstruction": ws8_grade["incident_reconstruction"],
        "investigation": ws8_grade["investigation"],
        "severity_confusion": ws8_grade["severity_confusion"],
        "attribution_accuracy": _attribution(parsed),
    }


def _real_detection(raw_pairs: list[tuple]) -> list[dict]:
    """Run raw (source_type, record, meta, step) pairs through the REAL detector cascade."""
    try:
        return negative_controls.run_pipeline(raw_pairs, tenant=_CHAIN_TENANT)
    except Exception as exc:  # pragma: no cover - defensive
        sys.stderr.write(f"[warn] detection run failed: {exc!r}\n")
        return []


# ---------------------------------------------------------------------------
# WP-3-C: grade the chain against the REAL WS-8 v2 incident graph.
# ---------------------------------------------------------------------------
def _build_chain_alerts(parsed: list["scenario.ChainEvent"]) -> list[dict]:
    """Re-run the chain's REAL parsed OCSF events through a fresh real Detector
    and build the FULL production alert shape (ws4-detection/main.py::make_alert)
    for every fired rule -- the exact alerts a production WS-4 would emit.

    This mirrors negative_controls.run_pipeline's detection leg byte-for-byte
    (fresh Detector(plugin_rule_dirs=[]), the same siem.tenant / ingest_id /
    twin_step stamping, events processed in chain order so stateful windows see
    the same hits) but keeps the (event, rule) pairs so make_alert -- NOT a
    hand-rolled reduced alert -- can be called. The Correlator needs
    actor/src_endpoint/mitre/event_ids on the alert for its tracks + typed
    signals, which run_pipeline's reduced dicts don't carry.

    Returns [{step, alert}] in detection (== chain) order. Deterministic: a
    fresh detector per call + all chain timestamps fixed in the past.
    """
    detector = _WS4_MOD.Detector(plugin_rule_dirs=[])
    out: list[dict] = []
    for ev in parsed:
        event = copy.deepcopy(ev.event or {})
        siem = event.setdefault("siem", {})
        siem.update({"tenant": _CHAIN_TENANT, "ingest_id": f"twin:{ev.step}"})
        siem["twin_step"] = ev.step
        event, matched, _action = detector.process(event)
        score = (event.get("siem") or {}).get("score")
        for rule in matched:
            alert = _WS4_MOD.make_alert(event, rule, score)
            # WP-3.5-A: the alert carries its underlying OCSF event so the
            # evidence-package reconstruction can join provenance to a REAL
            # normalized event (the report's other grading paths re-derive
            # events from chain.events themselves).
            out.append({"step": ev.step, "alert": alert, "event": event})
    return out


def _step_entity_ids(result: "scenario.ChainResult", tenant: str) -> dict:
    """Map each chain step to the canonical entity_ids its OCSF event evidences,
    using the SAME canonical identity the v2 graph nodes use
    (services/ws8-correlation/correlator.py::canonical_entity_id -- sha256 of
    the pipe-joined tenant/entity_type/canonical_value).

    Entities per step: actor.user.name, canonical src_endpoint.ip, and device
    (src_endpoint.mac falling back to hostname). A gapped/unparsed step (no
    event) contributes no entities -- it can never be graded, honestly.
    """
    ws8 = _ensure_ws8()
    out: dict[str, set] = {}
    for ev in result.events:
        event = ev.event or {}
        ids: set = set()
        actor = event.get("actor") or {}
        user = actor.get("user") if isinstance(actor.get("user"), dict) else {}
        if user.get("name"):
            eid = ws8.canonical_entity_id(tenant, "actor", str(user["name"]))
            if eid:
                ids.add(eid)
        src = event.get("src_endpoint") or {}
        if src.get("ip"):
            eid = ws8.canonical_entity_id(tenant, "ip", str(src["ip"]))
            if eid:
                ids.add(eid)
        device = src.get("mac") or src.get("hostname")
        if device:
            eid = ws8.canonical_entity_id(tenant, "device", str(device))
            if eid:
                ids.add(eid)
        out[ev.step] = ids
    return out


def _fidelity_join(edges: list[dict], from_side: set, to_side: set) -> bool:
    """True iff some typed v2 graph edge joins the earlier-step side to the
    to-step: the edge's ``from`` entity must belong to the earlier side and its
    ``to`` entity to the to-step -- the DIRECTION check (from-entity belongs to
    the earlier step side). Kept tiny + pure so test_chain_fidelity.py can
    mutate it and prove the check is load-bearing."""
    for ed in edges:
        f = ed.get("from")
        t = ed.get("to")
        if f in from_side and t in to_side:
            return True
    return False


def _grade_chain_fidelity(edges: list[dict], step_entities: dict,
                          allowed_rels: list[dict], step_order: list[str]) -> dict:
    """PURE grader: score the oracle's allowed_relationships against the REAL v2
    graph edges.

    For each oracle relationship (from-step -> to-step, allowed: true): the
    graph must contain at least one typed edge from an entity evidenced at the
    from-step OR AN EARLIER step (the union of the from-step's entity set and
    every earlier step's, per the chain's causal order) to an entity evidenced
    AT the to-step, in the right direction (from-entity on the earlier side).
    Explicit non-edges (allowed: false) MUST NOT be joined: a graph edge
    satisfying the same predicate for a forbidden pair is a FALSE CORRELATION
    and counts AGAINST the fraction -- never hidden.

    chain_fidelity = (correct allowed joins - forbidden joins) / denominator,
    where the denominator is the number of allowed relationships whose BOTH
    steps are detected (parsed) and entity-bearing. Unclamped: if
    ``forbidden`` exceeds ``correct`` (more false correlations than genuine
    joins) the score goes NEGATIVE -- intentional, not a bug, per "counts
    AGAINST the fraction, never hidden" above; a floor at 0 would silently
    launder a graph that is mostly false correlations into a merely-mediocre
    score. No denominator, or no incident evidence at all (empty ``edges``
    from an unpromoted chain) -> fidelity None, never a fabricated number."""
    idx = {label: i for i, label in enumerate(step_order)}
    allowed = [r for r in allowed_rels if r.get("allowed")]
    forbidden_rels = [r for r in allowed_rels if not r.get("allowed")]

    def _earlier_side(f: str) -> set:
        side: set = set()
        if f not in idx:
            return side
        for i in range(idx[f] + 1):
            side |= set(step_entities.get(step_order[i], ()))
        return side

    denominator = 0
    correct = 0
    per_pair: list[dict] = []
    for rel in allowed:
        f, t = rel.get("from"), rel.get("to")
        from_set = set(step_entities.get(f, ()))
        to_set = set(step_entities.get(t, ()))
        if not from_set or not to_set:
            # a step with no parsed event / no entity can never be joined --
            # excluded from the denominator honestly (spec: both steps
            # detected and entity-bearing)
            per_pair.append({"from": f, "to": t, "graded": False,
                             "reason": "step-not-entity-bearing"})
            continue
        denominator += 1
        joined = _fidelity_join(edges, _earlier_side(f), to_set)
        correct += 1 if joined else 0
        per_pair.append({"from": f, "to": t, "graded": True, "joined": bool(joined)})

    forbidden = 0
    forbidden_denominator = 0
    per_forbidden: list[dict] = []
    for rel in forbidden_rels:
        f, t = rel.get("from"), rel.get("to")
        to_set = set(step_entities.get(t, ()))
        if not to_set:
            # a forbidden pair whose to-step has no parsed event / no entity
            # can never be falsely joined -- excluded from the denominator
            # honestly (same both-steps-entity-bearing rule as allowed joins)
            per_forbidden.append({"from": f, "to": t, "graded": False,
                                  "reason": "to-step-not-entity-bearing"})
            continue
        forbidden_denominator += 1
        joined = _fidelity_join(edges, _earlier_side(f), to_set)
        forbidden += 1 if joined else 0
        per_forbidden.append({"from": f, "to": t, "graded": True, "joined": bool(joined)})

    if not edges or denominator == 0:
        fidelity = None  # nothing promoted / no graded joins -> honest null
    else:
        fidelity = (correct - forbidden) / denominator
    return {
        "chain_fidelity": round(fidelity, 4) if fidelity is not None else None,
        "fidelity_numerator": correct,
        "forbidden_joins": forbidden,
        "forbidden_denominator": forbidden_denominator,
        "fidelity_denominator": denominator,
        "per_allowed_pair": per_pair,
        "per_forbidden_pair": per_forbidden,
    }


def _incident_membership_grade(alerts_by_step: list[dict], incidents: list[dict],
                               membership: dict) -> dict:
    """Grade the oracle's incident_membership against the REAL promoted
    incidents:

      * incident_count        -- real number of DISTINCT incidents the chain's
                                 alerts promoted (the ip + actor tracks both
                                 promote for this chain: each track is an
                                 independent real incident).
      * incident_membership_ok -- exactly ``incident_count`` (oracle) incidents
                                 carry the FULL chain (every chain alert is a
                                 member), and every fired cross_step_rule_ids
                                 rule has all its alerts co-located in ONE
                                 incident (a rule whose alerts were split
                                 across incidents would violate "all in the
                                 same incident").
    """
    chain_ids = [item["alert"]["alert_id"] for item in alerts_by_step]
    chain_set = set(chain_ids)
    by_id: dict[str, dict] = {inc["incident_id"]: inc for inc in incidents}

    if not by_id or not chain_set:
        return {"incident_count": 0, "incident_membership_ok": False,
                "full_coverage_incident_ids": [],
                "reason": "no chain alerts promoted an incident"}

    full_coverage = [iid for iid, inc in by_id.items()
                     if chain_set <= set(inc["member_alert_ids"])]

    cross_ok = True
    cross_details: dict[str, object] = {}
    for rule_id in membership.get("cross_step_rule_ids") or []:
        rule_alerts = {a["alert"]["alert_id"] for a in alerts_by_step
                       if a["alert"]["rule_id"] == rule_id}
        if not rule_alerts:
            cross_details[rule_id] = "not-fired"  # a listed rule that never fired has no alerts to co-locate
            continue
        co_located = any(set(inc["member_alert_ids"]) >= rule_alerts
                         for inc in by_id.values())
        cross_details[rule_id] = bool(co_located)
        cross_ok = cross_ok and co_located

    _expected_raw = membership.get("incident_count", 1)
    expected = int(_expected_raw) if _expected_raw is not None else 1
    ok = len(full_coverage) == expected and cross_ok
    return {
        "incident_count": len(by_id),
        "incident_membership_ok": bool(ok),
        "full_coverage_incident_ids": sorted(full_coverage),
        "cross_step_rule_co_location": cross_details,
    }


def _grade_ws8(result: "scenario.ChainResult", oracle: dict) -> dict:
    """Run the chain's real alerts through the REAL WS-8 Correlator and grade
    chain_fidelity + incident membership against the REAL v2 incident graphs.

    Determinism: Correlator is constructed with a FIXED now_fn -- a constant
    1h after the chain's last alert (all chain timestamps are fixed past
    values, so every member stays in-window and no entry falls back to a
    wall-clock processing time). Everything else is a pure function of the
    same deterministic inputs as the rest of the report.
    """
    ws8 = _ensure_ws8()
    parsed = [e for e in result.events if e.parsed]
    alerts_by_step = _build_chain_alerts(parsed)
    last_ts = max((a["alert"].get("time") or 0) for a in alerts_by_step) if alerts_by_step else 0
    now_ms = last_ts + 3_600_000  # fixed seed-derived "now" (see above)
    corr = ws8.Correlator(now_fn=lambda: now_ms / 1000.0)

    incidents: list[dict] = []
    for item in alerts_by_step:
        incidents.extend(corr.ingest_alert(item["alert"]))
    by_id: dict[str, dict] = {inc["incident_id"]: inc for inc in incidents}

    # Union of the REAL v2 graphs across every promoted incident: every edge
    # any chain alert's incident evidence carries.
    edges: list[dict] = []
    seen: set = set()
    for iid in sorted(by_id):
        graph = corr.incident_graph(iid)
        for ed in (graph or {}).get("edges") or []:
            key = (ed.get("from"), ed.get("to"), ed.get("kind"))
            if key not in seen:
                seen.add(key)
                edges.append(ed)

    step_entities = _step_entity_ids(result, _CHAIN_TENANT)
    fidelity = _grade_chain_fidelity(
        edges, step_entities, oracle.get("allowed_relationships") or [],
        oracle.get("expected_sequence") or list(step_entities))
    membership = _incident_membership_grade(
        alerts_by_step, list(by_id.values()),
        oracle.get("incident_membership") or {})

    chain_alerts = [a["alert"]["alert_id"] for a in alerts_by_step]
    chain_set = set(chain_alerts)
    incident_summary = [
        {
            "incident_id": iid,
            "entity": f"{inc['entity_type']}:{inc['entity_value']}",
            "tactics": inc["tactics"],
            "member_count": inc["member_count"],
            "covers_full_chain": bool(chain_set <= set(inc["member_alert_ids"])),
        }
        for iid, inc in sorted(by_id.items())
    ]

    # ------------------------------------------------------------------
    # WP-3.5-A: the operational-outcome metric set, all computed from the
    # SAME real WS-8 artifacts graded above (nothing hand-picked).
    # ------------------------------------------------------------------
    # 1) False correlation rate: fraction of oracle-DECLARED forbidden
    #    relationships (allowed: false) that a real graph edge joined. The
    #    negative-control half of chain fidelity -- the metric that keeps
    #    the causal graph honest. Denominator = forbidden relationships
    #    whose to-step is entity-bearing (a forbidden pair whose to-step has
    #    no parsed event can never be falsely joined). None when no
    #    denominator exists.
    fcr_denom = fidelity["forbidden_denominator"]
    false_correlation_rate = (
        round(fidelity["forbidden_joins"] / fcr_denom, 4) if fcr_denom else None
    )
    # 2) Alert reduction ratio: raw WS-4 alerts in vs WS-8 incidents out
    #    over the same window -- 1 - (incidents/alerts) is the fraction of
    #    alert volume correlation absorbed. None when no alerts or no
    #    incidents.
    alert_count = len(chain_alerts)
    incident_promotions = len(by_id)
    if alert_count and incident_promotions:
        alert_reduction_ratio = round(
            1 - (incident_promotions / alert_count), 4)
    else:
        alert_reduction_ratio = None
    # 3) Incident reconstruction time: build the REAL WS-3 evidence package
    #    from the chain's real incident/alerts/events/graph and measure REAL
    #    assembly wall-clock (median of a few builds). Wall-clock is
    #    informational (date carve-out); package_id/block_count are
    #    deterministic. None when no incident promoted.
    reconstruction = _evidence_reconstruction(
        alerts_by_step, by_id, corr.incident_graph, now_ms)
    # 4) Analyst investigation time (MTTI): scripted walk over the REAL
    #    graph, counting steps + API round-trips; seconds = steps x the
    #    documented analyst latency model.
    investigation = _investigation_walk(alerts_by_step, by_id, edges)
    # 5) Severity calibration: confusion matrix (expected level from the
    #    oracle detection_points vs actual fired-alert level).
    severity_confusion = _severity_confusion(oracle, alerts_by_step)

    return {
        "chain_fidelity": fidelity["chain_fidelity"],
        "fidelity_numerator": fidelity["fidelity_numerator"],
        "forbidden_joins": fidelity["forbidden_joins"],
        "forbidden_denominator": fidelity["forbidden_denominator"],
        "fidelity_denominator": fidelity["fidelity_denominator"],
        "per_allowed_pair": fidelity["per_allowed_pair"],
        "per_forbidden_pair": fidelity["per_forbidden_pair"],
        "incident_promotions": len(by_id),
        "incident_count": membership["incident_count"],
        "incident_membership_ok": membership["incident_membership_ok"],
        "full_coverage_incident_ids": membership["full_coverage_incident_ids"],
        "cross_step_rule_co_location": membership["cross_step_rule_co_location"],
        "incident_summary": incident_summary,
        "graph_edges": edges,
        "chain_alert_count": len(chain_alerts),
        # WP-3.5-A operational outcomes
        "false_correlation_rate": false_correlation_rate,
        "alert_reduction_ratio": alert_reduction_ratio,
        "incident_reconstruction": reconstruction,
        "investigation": investigation,
        "severity_confusion": severity_confusion,
    }


def _raw_identity(ev: "scenario.ChainEvent") -> Optional[str]:
    """The actor identity the RAW payload declares for this step (the only
    ground truth INDEPENDENT of parser output -- the oracle for attribution)."""
    raw = (ev.raw_payload or {}).get("raw")
    if not isinstance(raw, dict):
        return None
    return raw.get("agent") or raw.get("user")


def _attribution(parsed: list[scenario.ChainEvent]) -> Optional[float]:
    """Attribution accuracy on ACTOR-BEARING steps only: the fraction whose
    parsed actor identity MATCHES the identity the step's RAW input declared.

    PR #80 review (finding 6): the old check compared every parsed identity
    against ``identities[0]`` -- the FIRST identity *of the same run's parser
    output*. That is a self-comparison: if parsing/enrichment mangled the
    actor name uniformly on every step, it reads 1.0 even when nothing
    matches the true actor. The honest oracle is the RAW payload's own
    identity field (`agent` for mcp steps, `user` for n8n steps) -- what the
    pipeline SHOULD have preserved. A mismatch here means enrichment/parsing
    lost or corrupted the actor between the input and the OCSF event.

    Steps whose raw input declares no identity (e.g. OT modbus frames, which
    carry no actor) are not attributable and are not credited.
    """
    correct = 0
    total = 0
    for ev in parsed:
        expected = _raw_identity(ev)
        if not expected:
            continue  # raw input declares no actor -> not attributable
        ocsf = ev.event or {}
        actor = ocsf.get("actor") or {}
        user = actor.get("user") if isinstance(actor.get("user"), dict) else {}
        process = actor.get("process") if isinstance(actor.get("process"), dict) else {}
        ident = user.get("name") or process.get("name")
        if not ident:
            continue  # actor dropped entirely -> not credited
        total += 1
        correct += 1 if ident == expected else 0
    if not total:
        return None  # no actor-bearing steps at all -> no denominator, honest null
    return round(correct / total, 4)


def _dot_get(d: dict, dotted: str):
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _severity_band_check(oracle: dict, fired: list[dict]) -> dict:
    """Check the REAL fired alerts' score_weight sits inside the oracle band.

    ``fired`` is the real fired-alert list from the chain's own detector run
    (see _grade_chain / _real_detection) -- peak_score is the actual max
    score_weight observed, never a hand-picked constant.
    """
    band = (oracle.get("severity_band") or {}).get("score") or {}
    lo, hi = band.get("min"), band.get("max")
    scores = [a.get("score_weight") for a in fired if a.get("score_weight") is not None]
    peak_score = max(scores) if scores else None
    in_band = (
        peak_score is not None and lo is not None and hi is not None
        and lo <= peak_score <= hi
    )
    return {
        "severity_calibration_error": (
            None if peak_score is None else (0.0 if in_band else 1.0)
        ),
        "peak_alert_score": peak_score,
        "in_band": in_band,
        "band": {"min": lo, "max": hi},
    }


def _degradation_behavior() -> dict:
    """Run degradation.py's own selfcheck and report its REAL pass/fail per
    property, rather than asserting determinism/subset-ness without proof."""
    import contextlib
    import io

    with contextlib.redirect_stdout(io.StringIO()):
        ok = degradation.selfcheck() == 0
    return {
        "delay": "deterministic" if ok else "unverified",
        "duplicate": "deterministic" if ok else "unverified",
        "reorder": "deterministic" if ok else "unverified",
        "loss": "deterministic" if ok else "unverified",
        "loss_is_strict_subset": ok,  # degradation.selfcheck() proves this on real output
        "basis": "harness-measured",
    }


def _baseline_delta(metrics: dict, path: Path = BASELINE_PATH) -> Optional[dict]:
    """Compare this run's metrics against the frozen baseline (WP-1-G delta
    contract: baseline.json's header requires new runs to emit the SAME metric
    keys and report a documented delta vs it -- previously UNIMPLEMENTED).

    Honest null-vs-0.0 handling: only keys present in BOTH are compared; a
    null on either side means "no denominator / not measured", reported as
    ``"n/a"``, never coerced into a numeric 0.0 that would read as
    "measured and zero" (same discipline as the metrics themselves -- e.g.
    chain_fidelity is null on both sides today: WS-8 has no causal-edge
    graph, so 0.0 would be fabricated). Non-numeric values (bools, the
    degradation_behavior dict) that are byte-equal get delta 0.0 ("no change");
    if they ever differ they are reported as ``"n/a"`` rather than given a
    made-up numeric. Returns None when no baseline file exists.
    """
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as fh:
        baseline = json.load(fh)
    base_metrics = baseline.get("metrics") or {}

    def _is_num(v) -> bool:
        return isinstance(v, (int, float)) and not isinstance(v, bool)

    key_comparison: dict = {}
    for key, cur in metrics.items():
        if key not in base_metrics:
            continue  # schema drift: only keys present in both are compared
        prev = base_metrics[key]
        if cur is None or prev is None:
            delta: object = "n/a"  # null on either side: not compared, not coerced
        elif _is_num(cur) and _is_num(prev):
            delta = round(float(cur) - float(prev), 4)
        elif cur == prev:
            delta = 0.0  # byte-equal non-numeric (e.g. degradation_behavior)
        else:
            delta = "n/a"  # unequal non-numeric: no honest numeric delta exists
        key_comparison[key] = {"baseline": prev, "current": cur, "delta": delta}
    return {
        "baseline": path.relative_to(ROOT).as_posix(),  # repo-relative, e.g. eval/twin/baseline.json
        "frozen_at": baseline.get("frozen_at"),
        "seed": baseline.get("seed"),
        "basis": baseline.get("basis"),
        "key_comparison": key_comparison,
    }


def run(seed: int = 7) -> dict:
    """Run the full twin and return the complete metric dict (the report)."""
    started = time.time()
    oracle = _load_oracle()
    chain = _run_chain(seed)
    negatives, negatives_explained = _run_negatives(seed)

    grade = _grade_chain(chain, oracle)  # single real detection run; every
                                          # metric below is sliced from this
    tpr = grade["tpr"]
    evidence = grade["evidence_completeness"]
    fired = grade["fired"]

    # alerts_total/incident_promotions from the SAME real run graded above,
    # never a separately-asserted constant. incident_promotions is the REAL
    # count of distinct incidents the chain's alerts promoted through the REAL
    # WS-8 Correlator (WP-3-C: the actor + ip tracks both promote for this
    # chain -- each track is an independent, real incident).
    alerts_total = len(fired)
    incident_promotions = grade["incident_promotions"]
    incident_count = grade["incident_count"]

    # No denominator for FPR only if there are no negative scenarios at all
    # (there always are four, but guard rather than assume).
    fpr = (sum(1 for n in negatives.values() if n) / len(negatives)) if negatives else None

    severity = _severity_band_check(oracle, fired)

    report = {
        "report": {
            "schema_version": "1",
            "run_type": "twin",
            "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "seed": seed,
            "basis": "harness-measured",  # Phase 3.5 discipline: sim/replay, not field
        },
        "metrics": {
            "tpr": tpr,          # already rounded (or None) by _grade_chain
            "fpr": round(fpr, 4) if fpr is not None else None,
            "mttd_seconds": grade["mttd_seconds"],  # real: first-matched-step ts minus chain-start ts
            # WP-3.5-A: analyst investigation time (MTTI) -- a REAL scripted
            # walk count over the real incident graph x the documented analyst
            # latency model; None only when no incident promoted.
            "mtti": (grade["investigation"] or {}).get("mtti_seconds"),
            # WP-3.5-A: MTTR stays an honest null -- the twin harness has no
            # remediation/closure event (no triage-API status transition is
            # replayed; incidents never close in the sim). Fabricating a
            # remediation time would be a lie about what the twin measures.
            # See context.mttr_null_reason.
            "mttr": None,
            # WP-3-C: a REAL fraction measured against the REAL WS-8 v2 incident
            # graph (see _grade_chain_fidelity); None only when no incident
            # promoted or no denominator exists -- never a fabricated number.
            "chain_fidelity": grade["chain_fidelity"],
            "evidence_completeness": evidence,  # already rounded (or None) by _grade_chain
            # WP-3.5-A: real ratio of oracle-forbidden relationships that a
            # real graph edge joined (the negative-control half of chain
            # fidelity). None only when no forbidden pair is gradeable.
            "false_correlation_rate": grade["false_correlation_rate"],
            # WP-3.5-A: 1 - (incidents/alerts) over the same window -- the
            # fraction of raw alert volume correlation absorbed. None when no
            # alerts or no incidents.
            "alert_reduction_ratio": grade["alert_reduction_ratio"],
            # WP-3.5-A: REAL wall-clock assembly of the REAL WS-3 evidence
            # package (median of a few builds). Wall-clock is informational
            # (date carve-out), so it is excluded from the byte-determinism
            # assertion -- package_id/block_count ARE deterministic.
            "incident_reconstruction_time_ms": (
                (grade["incident_reconstruction"] or {}).get("assembly_median_ms")),
            "severity_calibration_error": severity["severity_calibration_error"],
            "peak_alert_score": severity["peak_alert_score"],  # the real max score_weight observed, not discarded
            "severity_in_band": severity["in_band"],
            "mutation_robustness": None,    # Phase 4 wires mutation; not measured yet
            "degradation_behavior": _degradation_behavior(),
            "attribution_accuracy": grade["attribution_accuracy"],
        },
        "context": {
            "chain_steps": [e.step for e in chain.events],
            "parsed_count": chain.parsed_count(),
            "gap_count": chain.gap_count(),
            "gap_steps": [e.step for e in chain.events if e.gap],
            "negative_controls": negatives,  # per-scenario INCIDENT count (see _run_negatives)
            # PR #80 finding 2: per-scenario LOW-explained alert count, so the
            # FPR floor can prove scenario 1 still emits the ticketed downgrade
            # alert (zero incidents alone cannot distinguish clean FPR from a
            # regression to silent suppression).
            "negative_explained_low": negatives_explained,
            "oracle_expected_sequence": oracle["expected_sequence"],
            "alert_count": alerts_total,
            # WP-3-C: real numbers from the REAL WS-8 Correlator run on the
            # chain's real alerts -- nothing hand-picked.
            "incident_promotions": incident_promotions,
            "incident_count": incident_count,
            "incident_membership_ok": grade["incident_membership_ok"],
            "full_coverage_incident_ids": grade["full_coverage_incident_ids"],
            "cross_step_rule_co_location": grade["cross_step_rule_co_location"],
            "incident_summary": grade["incident_summary"],
            "chain_fidelity_details": {
                "correct_allowed_joins": grade["fidelity_numerator"],
                "forbidden_joins": grade["forbidden_joins"],
                "forbidden_denominator": grade["forbidden_denominator"],
                "denominator": grade["fidelity_denominator"],
                "per_allowed_pair": grade["per_allowed_pair"],
                "per_forbidden_pair": grade["per_forbidden_pair"],
            },
            "chain_graph_edges": [
                {"from": e["from"], "to": e["to"], "kind": e["kind"],
                 "event_id": e["event_id"], "ts_ms": e["ts_ms"]}
                for e in grade["graph_edges"]
            ],
            # WP-3.5-A operational-outcome context (all real data from the
            # SAME WS-8 run graded above; see each block's own basis field).
            "false_correlation_details": {
                "rate": grade["false_correlation_rate"],
                "forbidden_joins": grade["forbidden_joins"],
                "forbidden_denominator": grade["forbidden_denominator"],
                "per_forbidden_pair": grade["per_forbidden_pair"],
            },
            "alert_reduction": {
                "ratio": grade["alert_reduction_ratio"],
                "raw_alert_count": grade["chain_alert_count"],
                "incident_count": incident_promotions,
            },
            "incident_reconstruction": grade["incident_reconstruction"],
            "analyst_investigation": grade["investigation"],
            "severity_confusion": grade["severity_confusion"],
            # WP-3.5-A: MTTR is honestly null because the twin harness has no
            # remediation/closure event -- no triage-API status transition is
            # replayed and incidents never close in the simulation. The
            # roadmap's Phase 3.5 MTTR cell says \"triage-API status
            # transitions on real replays\", which is a live-replay measure,
            # not a twin measure; fabricating a remediation time here would
            # lie about what the twin measures.
            "mttr_null_reason": (
                "no remediation/closure event exists in the twin harness "
                "(no triage-API status transition is replayed; incidents "
                "never close in the simulation) -- MTTR requires a "
                "live-replay or design-partner measure per the roadmap's "
                "own Phase 3.5 cell; an honest null, never a fabricated 0"),
        },
        "finding": (
            f"FPR={round(fpr, 4) if fpr is not None else 'null'}: "
            f"{sum(1 for n in negatives.values() if n)}/"
            f"{len(negatives)} negative control(s) produced an INCIDENT-level "
            f"(medium+) alert: "
            + (", ".join(name for name, n in negatives.items() if n) or "none")
            + ". A low-severity ticketed alert doesn't count as an incident -- "
              "see negative_controls.is_incident(). See eval/twin/"
              "negative_controls.py for the per-scenario cause."
            + (  # WP-3-C: the chain_fidelity finding is now measured (never fabricated)
                " chain_fidelity=" + str(grade["chain_fidelity"])
                + " measured against the REAL WS-8 v2 incident graph: "
                + str(grade["fidelity_numerator"]) + " correct allowed join(s), "
                + str(grade["forbidden_joins"]) + " forbidden-pair join(s), "
                + "denominator " + str(grade["fidelity_denominator"])
                + "; incident_membership_ok=" + str(grade["incident_membership_ok"])
                + " with " + str(incident_count) + " real incident(s) promoted ("
                + (", ".join(f"{s['entity']} = {s['member_count']} alerts"
                             for s in grade["incident_summary"])
                   if grade["incident_summary"] else "no incident")
                + ")."
            )
        ),
        "elapsed_seconds": round(time.time() - started, 3),
    }
    # WP-1-G delta contract: compare this run against the frozen baseline
    # (only when the baseline file exists; emit the section into the report).
    delta = _baseline_delta(report["metrics"])
    if delta is not None:
        report["delta_vs_baseline"] = delta
    return report


def _append_trend(report: dict, path: Path = TREND_PATH) -> None:
    """Append one twin row to eval/trend.jsonl (JSON Lines, schema-stable).

    The file's first line is a `#` header comment and later `#` NOTE lines
    annotate history (e.g. the pre-fix fabricated pilot row) -- append-only
    discipline: rows are never rewritten or deleted, and any reader MUST skip
    lines starting with ``#`` before json.loads per line.
    """
    row = {
        "_schema": report["report"]["schema_version"],
        "run_type": report["report"]["run_type"],
        "date": report["report"]["date"],
        "seed": report["report"]["seed"],
        "basis": report["report"]["basis"],
        "twin_metrics": report["metrics"],
    }
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="FENGARDE twin scorecard (WP-1-F)")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", type=Path, default=REPORT_PATH)
    ap.add_argument("--no-trend", action="store_true",
                    help="do not append a row to eval/trend.jsonl")
    args = ap.parse_args(argv)

    report = run(seed=args.seed)

    # Floor assertions -- this is a PR-gate step (run_all_tests.sh). A smoke
    # run whose only failure mode is a Python exception isn't gate coverage:
    # _real_detection() swallows every exception and returns [], which would
    # otherwise silently produce TPR=0/alert_count=0 and still print [OK].
    m, ctx = report["metrics"], report["context"]
    floor_failures = []
    if ctx["alert_count"] == 0:
        floor_failures.append("alert_count == 0 -- the WS-2->WS-4 cascade produced no alerts at all")
    if m["tpr"] != 1.0:
        floor_failures.append(f"tpr == {m['tpr']!r}, expected 1.0 on this deterministic chain")
    if m["fpr"] != 0.0:
        floor_failures.append(f"fpr == {m['fpr']!r}, expected 0.0 (see negative_controls.is_incident())")
    # PR #80 finding 2: FPR 0.0 alone cannot distinguish a clean run from a
    # regression to silent suppression. Scenario 1 must STILL emit the LOW
    # ticketed downgrade alert -- prove the downgrade mechanism is alive.
    neg_explained = (ctx.get("negative_explained_low") or {}).get(
        negative_controls._MAINTENANCE_NAME, 0)
    if neg_explained == 0:
        floor_failures.append(
            f"{negative_controls._MAINTENANCE_NAME} produced 0 LOW explained "
            "alerts -- the ticketed downgrade mechanism has silently regressed "
            "to suppression (see negative_controls.py / SECURITY.md 12)")
    if floor_failures:
        for f in floor_failures:
            print(f"[FAIL] twin report floor assertion: {f}")
        print(f"[FAIL] twin report (seed={args.seed}) is below its known-good floor -- "
              f"treat as a regression, not a metric fluctuation.")
        return 1

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    if not args.no_trend:
        _append_trend(report)
    # print a human summary line for the gate
    summary = (f"[OK] twin report (seed={args.seed}): TPR={m['tpr']} FPR={m['fpr']} "
               f"chain_fidelity={m['chain_fidelity']} "
               f"evidence={m['evidence_completeness']} "
               f"fcr={m['false_correlation_rate']} "
               f"arr={m['alert_reduction_ratio']} "
               f"mtti={m['mtti']} mttr={m['mttr']} "
               f"recon_ms={m['incident_reconstruction_time_ms']} "
               f"basis={report['report']['basis']}")
    db = report.get("delta_vs_baseline")
    if db is not None:
        parts = []
        for k, cmp in db["key_comparison"].items():
            if isinstance(cmp.get("current"), dict) or isinstance(cmp.get("baseline"), dict):
                continue  # dict values live in the report's delta section, not the terse line
            if cmp["delta"] == "n/a":
                parts.append(f"{k} n/a")
            else:
                parts.append(f"{k} {cmp['baseline']}->{cmp['current']} ({cmp['delta']})")
        summary += f" | delta: {', '.join(parts)}"
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())