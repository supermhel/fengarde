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

  * chain_fidelity             = null (WS-8 has no causal-edge graph today, so
                                       there is no denominator to measure a
                                       fraction against; null, never a
                                       fabricated 0.0)
  * fpr                        = 0.0 (measured: an INCIDENT count, i.e.
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
  * mtti / mttr                = null (no incident is promoted today, so there
                                       is no incident to identify time-to or
                                       recover-from)
  * false_correlation_rate /
    alert_reduction_ratio      = null (both are defined over promoted
                                       incidents; zero incidents means no
                                       denominator, not a measured zero)
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

Determinism: same seed -> byte-identical report. All graded times are
seed-derived fixed constants, never wall-clock; the correlator is given a fixed
``now_fn``. (The ``date`` field is informational and may differ between runs.)

Safety: this is a SIMULATION harness. No real control action is ever issued;
everything runs in-process on the memory bus against the loopback twin.

Usage:
    python eval/twin/report.py [--seed N] [--out PATH]
Wired as `make twin` (see Makefile) and as the twin lane of the nightly
evaluation workflow (.github/workflows/nightly-eval.yml).
"""
from __future__ import annotations

import argparse
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
        # WS-8 has no causal-edge graph today, so "fraction of causal edges
        # correctly reconstructed" has no denominator -- null, not a fabricated
        # zero (None is later surfaced verbatim in the report; a real 0.0 would
        # read as "measured and found zero", which is not true).
        "chain_fidelity": None,
        "attribution_accuracy": _attribution(parsed),
    }


def _real_detection(raw_pairs: list[tuple]) -> list[dict]:
    """Run raw (source_type, record, meta, step) pairs through the REAL detector cascade."""
    try:
        return negative_controls.run_pipeline(raw_pairs, tenant="twin-chain")
    except Exception as exc:  # pragma: no cover - defensive
        sys.stderr.write(f"[warn] detection run failed: {exc!r}\n")
        return []


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
    # never a separately-asserted constant.
    alerts_total = len(fired)
    incident_promotions = 0  # Correlator promotes nothing today (no causal edges)

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
            "mtti": None,                 # no incident promoted today (honest null)
            "mttr": None,                 # no incident resolved today (honest null)
            # WS-8 has no causal-edge graph today -- null, not a fabricated 0.0
            # (see _grade_chain's chain_fidelity comment for the same reasoning).
            "chain_fidelity": grade["chain_fidelity"],
            "evidence_completeness": evidence,  # already rounded (or None) by _grade_chain
            # No incident is ever promoted today (incident_promotions == 0
            # above), so "false correlation rate" and "alert reduction ratio"
            # have no incidents to be computed over -- null, not a fabricated
            # "measured zero".
            "false_correlation_rate": None,
            "alert_reduction_ratio": None,
            "incident_reconstruction_time_ms": None,
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
            "incident_promotions": incident_promotions,
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
               f"evidence={m['evidence_completeness']} basis={report['report']['basis']}")
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