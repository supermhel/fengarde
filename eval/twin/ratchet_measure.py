"""Atom builders for the Phase 6 score ratchet.

This module reads the deterministic lane artifacts written by the existing
Phase-4/5 instruments. It does not rerun the expensive lanes except for the
small, explicit quality canary computation.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TWIN = ROOT / "eval" / "twin"
ADVERSARIAL_OUT = ROOT / "eval" / "adversarial" / "out"
ATTACK_OUT = ROOT / "eval" / "attack" / "out"


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _put(out: dict[str, Any], key: str, value: Any) -> None:
    if value is not None or key not in out:
        out[key] = value


def _bool_field(row: dict, out: dict, prefix: str, field: str) -> None:
    if field in row:
        out[f"{prefix}/{field}"] = bool(row[field])


def atoms_from_scenario_result(result: dict) -> dict[str, Any]:
    """Build per-scenario baseline, mutation, and sub-criterion atoms."""
    scenario = result["scenario"]
    out: dict[str, Any] = {}
    base = result.get("baseline") or {}
    base_fields = {
        "tpr": "higher", "alert_order_ok": "higher", "incident_membership_ok": "higher",
        "directional_discrimination": "higher", "mttd_seconds": "lower",
        "chain_fidelity": "pinned", "false_correlation_rate": "pinned",
        "incident_count": "pinned", "fired_alerts": "pinned", "campaign_count": "pinned",
        "campaign_full_coverage": "higher",
    }
    for field in base_fields:
        if field in base:
            out[f"scn/{scenario}/base/{field}"] = base[field]
    for row in result.get("rows") or []:
        prefix = f"scn/{scenario}/mut/{row['axis']}/{row['variant']}"
        value = "pass" if row.get("applicable") and row.get("pass") else (
            "fail" if row.get("applicable") else "n/a")
        out[prefix] = value
        for field in ("detection_retained", "fidelity_retained", "fcr_unchanged",
                      "order_retained", "decoy_clean", "causal_join_broken"):
            _bool_field(row, out, prefix, field)
        if row.get("applicable"):
            out[f"{prefix}/expected_rule_lost_steps"] = len(row.get("expected_rule_lost_steps") or [])
            out[f"{prefix}/steps_lost"] = len(row.get("steps_lost") or [])
            out[f"{prefix}/tactic_lost"] = len(row.get("tactic_lost") or [])
            out[f"{prefix}/collateral_lost_steps"] = len(row.get("collateral_lost_steps") or [])
    return out


def atoms_from_layer_a(matrix: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    base = matrix.get("baseline") or {}
    for field in ("tpr", "chain_fidelity", "false_correlation_rate"):
        if field in base:
            out[f"lane_a/base/{field}"] = base[field]
    for row in matrix.get("rows") or []:
        prefix = f"lane_a/mut/{row['axis']}/{row['variant']}"
        out[prefix] = "pass" if row.get("pass") else "fail"
        for field in ("detection_retained", "fidelity_retained", "fcr_unchanged",
                      "order_retained", "decoy_clean", "causal_join_broken"):
            _bool_field(row, out, prefix, field)
        out[f"{prefix}/expected_rule_lost_steps"] = len(row.get("expected_rule_lost_steps") or [])
    return out


def atoms_from_evasion(result: dict) -> dict[str, Any]:
    """Build atoms from one seed's evasion envelope."""
    if "scenarios" not in result and isinstance(result, dict):
        # Multi-seed output is not a baseline input; use the explicitly selected
        # seed only when the producer wrote a single-seed envelope.
        return {}
    out: dict[str, Any] = {}
    for scenario, data in sorted((result.get("scenarios") or {}).items()):
        for row in data.get("rows") or []:
            if not row.get("searched"):
                continue
            for axis in ("loss", "stretch_pct", "ip_k", "account_k"):
                if axis in row.get("measured", {}):
                    out[f"scn/{scenario}/evasion/{row['step']}/{axis}"] = row["measured"][axis]
                if axis in row.get("agree", {}):
                    out[f"scn/{scenario}/evasion/{row['step']}/{axis}/agree"] = row["agree"][axis]
    return out


def atoms_from_twin(report: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    metrics = report.get("metrics") or {}
    fields = ("tpr", "fpr", "evidence_completeness", "mttd_seconds", "mtti",
              "alert_reduction_ratio", "severity_calibration_error", "attribution_accuracy")
    for field in fields:
        if field in metrics:
            out[f"twin/{field}"] = metrics[field]
    for name, value in sorted((report.get("context") or {}).get("negative_controls", {}).items()):
        out[f"twin/negative_controls/{name}"] = value
    return out


def atoms_from_fire_check(entries: list | dict) -> dict[str, Any]:
    """Read the legacy list-shaped fire_check output without changing it."""
    if isinstance(entries, dict):
        entries = entries.get("results") or []
    out: dict[str, Any] = {}
    for entry in entries:
        framework = entry.get("framework", "attack")
        technique = entry.get("technique") or f"unmapped:{Path(entry.get('title', 'unknown')).stem}"
        prefix = f"tech/{framework}:{technique}/rule/{entry.get('id')}"
        out[f"{prefix}/fires"] = bool(entry.get("fired"))
        near = entry.get("near_miss") or {}
        boundary = entry.get("boundary") or {}
        out[f"{prefix}/near_miss_held"] = bool(near.get("fully_held"))
        out[f"{prefix}/boundary_too_loose_n"] = len(near.get("too_loose") or []) + len(boundary.get("too_loose") or [])
    return out


def atoms_from_corpus(result: dict) -> dict[str, Any]:
    out: dict[str, Any] = {"corpus_b/cross_case_merge_clean": bool(result.get("cross_case_merge_clean"))}
    for row in result.get("per_case") or []:
        case = row["id"]
        out[f"corpus_b/{case}/missed_n"] = len(row.get("missed") or [])
        out[f"corpus_b/{case}/fired_n"] = len(row.get("fired_rules") or [])
    return out


def _quality_module():
    path = ROOT / "tools" / "detection_quality_eval.py"
    name = "fengarde_detection_quality_for_ratchet"
    mod = sys.modules.get(name)
    if mod is not None:
        return mod
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def atoms_from_quality() -> dict[str, Any]:
    mod = _quality_module()
    rules = mod.load_engine_rules()
    results = mod.entry_results(mod.CORPUS, rules)
    scored = mod.references(mod.CORPUS)
    metrics = {rid: mod.rule_metrics(results, rid) for rid in sorted(scored)}
    out = {"quality/macro_f1": round(mod.macro_f1(metrics), 4)}
    for rid, metric in metrics.items():
        out[f"quality/{rid[:8]}/f1"] = round(metric["f1"], 4)
    return out


def _rule_catalogue() -> dict[str, dict]:
    import yaml  # lazy: guard does not need PyYAML
    out: dict[str, dict] = {}
    for path in sorted((ROOT / "contracts" / "rules").glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict) or not data.get("id"):
            continue
        mitre: dict = data["mitre"] if isinstance(data.get("mitre"), dict) else {}
        siem: dict = data["siem"] if isinstance(data.get("siem"), dict) else {}
        out[str(data["id"])] = {
            "stem": path.stem,
            "framework": mitre.get("framework", "attack"),
            "technique": mitre.get("technique"),
            "tactic": mitre.get("tactic"),
            "companion_of": siem.get("companion_of"),
        }
    by_stem = {v["stem"]: v for v in out.values()}
    for rid, info in out.items():
        if not info["technique"] and info.get("companion_of") in out:
            sibling = out[info["companion_of"]]
            info["framework"], info["technique"] = sibling["framework"], sibling["technique"]
        if not info["technique"]:
            info["technique"] = f"unmapped:{info['stem']}"
    return out


def _tech_for_rule(rule_id: str, catalogue: dict[str, dict]) -> tuple[str, str]:
    info = catalogue.get(rule_id) or {"framework": "attack", "technique": f"unmapped:{rule_id}"}
    return str(info.get("framework") or "attack"), str(info["technique"])


def technique_cells(name: str, oracle: dict, base: dict, rows: list[dict],
                    catalogue: dict[str, dict], prefix: str = "") -> dict[str, Any]:
    """Build step-level technique cells from expected-rule attribution.

    ``tactic_covered`` is deliberately separate from ``expected_rule_fired``;
    a tactic can be covered by a sibling rule and that is not proof that the
    oracle's expected rule fired.
    """
    out: dict[str, Any] = {}
    base_fired = {(a[0], a[1]) for a in base.get("fired_pairs") or []}
    covered = set(base.get("tactic_covered_steps") or [])
    points = oracle.get("detection_points") or {}
    for step, point in sorted(points.items()):
        expected = [r.get("rule_id") for r in point.get("expected_rules") or [] if r.get("rule_id")]
        if not expected:
            gap = point.get("gap") or {}
            tech = gap.get("attack_technique")
            if tech:
                framework = gap.get("framework", "attack")
                out[f"tech/{framework}:{tech}/cell/{name}/{step}/base"] = "gap"
            continue
        by_tech: dict[tuple[str, str], list[str]] = {}
        for rid in expected:
            by_tech.setdefault(_tech_for_rule(rid, catalogue), []).append(rid)
        for (framework, tech), rule_ids in sorted(by_tech.items()):
            root = f"{prefix}tech/{framework}:{tech}/cell/{name}/{step}"
            tactic_ok = step in covered
            expected_fired = any((step, rid) in base_fired for rid in rule_ids)
            out[f"{root}/base"] = "tactic_covered" if tactic_ok else "tactic_missed"
            out[f"{root}/base/tactic_covered"] = tactic_ok
            out[f"{root}/base/expected_rule_fired"] = expected_fired
            for row in rows:
                axis, variant = row["axis"], row["variant"]
                if axis == "loss" and variant == f"drop_{step}":
                    continue
                key = f"{root}/{axis}/{variant}"
                if not row.get("applicable"):
                    out[key] = "n/a"
                    continue
                lost = (step in set(row.get("steps_lost") or []) or
                        step in set(row.get("tactic_lost") or []) or
                        step in set(row.get("expected_rule_lost_steps") or []))
                out[key] = "lost" if lost else "retained"
    return out


def _scenario_oracles():
    import scenario_registry as reg
    return {s.name: reg.load_oracle(s) for s in reg.ALL}


def _artifact_stamp(kind: str, data: Any) -> str | None:
    if kind == "report":
        return (data.get("report") or {}).get("system_fingerprint")
    return data.get("system_fingerprint") if isinstance(data, dict) else None


def measure_artifacts() -> tuple[dict[str, Any], list[str], dict[str, Any]]:
    """Return ``(atoms, errors, metadata)`` and refuse missing/stale artifacts."""
    from fingerprint import system_fingerprint
    expected_fp = system_fingerprint(ROOT)
    files = {
        "layer_a": ADVERSARIAL_OUT / "matrix.latest.json",
        "scenario_matrix": ADVERSARIAL_OUT / "scenario_matrix.latest.json",
        "evasion": ADVERSARIAL_OUT / "evasion_search.latest.json",
        "corpus": ADVERSARIAL_OUT / "corpus.latest.json",
        "report": TWIN / "report.latest.json",
        "fire_check": ATTACK_OUT / "fire_check.json",
    }
    errors: list[str] = []
    data: dict[str, Any] = {}
    for kind, path in files.items():
        if not path.exists():
            errors.append(f"missing artifact: {path.relative_to(ROOT).as_posix()}")
            continue
        try:
            data[kind] = _read(path)
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"invalid artifact {path.relative_to(ROOT).as_posix()}: {exc}")
    for kind, value in data.items():
        stamp = _artifact_stamp(kind, value)
        if kind == "fire_check":
            sidecar = ATTACK_OUT / "fire_check.fingerprint.json"
            if sidecar.exists():
                try:
                    stamp = _read(sidecar).get("system_fingerprint")
                except (OSError, json.JSONDecodeError):
                    stamp = None
            else:
                stamp = None
        if stamp != expected_fp:
            errors.append(f"stale artifact: {files[kind].relative_to(ROOT).as_posix()} (re-run its lane)")
    atoms: dict[str, Any] = {}
    if "layer_a" in data:
        atoms.update(atoms_from_layer_a(data["layer_a"]))
    if "scenario_matrix" in data:
        scenario_data = data["scenario_matrix"]
        atoms.update({k: v for name, result in (scenario_data.get("scenarios") or {}).items()
                      for k, v in atoms_from_scenario_result(result).items()})
        try:
            oracles = _scenario_oracles()
            catalogue = _rule_catalogue()
            for name, result in sorted((scenario_data.get("scenarios") or {}).items()):
                atoms.update(technique_cells(name, oracles[name], result.get("baseline") or {},
                                             result.get("rows") or [], catalogue))
            # Layer A is the AI-to-OT catalogue and gets a distinct namespace.
            if "layer_a" in data:
                import report
                oracle = report._load_oracle()
                catalogue = _rule_catalogue()
                matrix = data["layer_a"]
                atoms.update(technique_cells("ai_to_ot", oracle, matrix.get("baseline") or {},
                                             matrix.get("rows") or [], catalogue, prefix="lane_a/"))
        except Exception as exc:
            errors.append(f"technique atom build failed: {exc}")
    if "evasion" in data:
        atoms.update(atoms_from_evasion(data["evasion"]))
    if "corpus" in data:
        atoms.update(atoms_from_corpus(data["corpus"]))
    if "report" in data:
        atoms.update(atoms_from_twin(data["report"]))
    if "fire_check" in data:
        atoms.update(atoms_from_fire_check(data["fire_check"]))
    try:
        atoms.update(atoms_from_quality())
    except Exception as exc:
        errors.append(f"quality atoms failed: {exc}")
    return dict(sorted(atoms.items())), errors, {"system_fingerprint": expected_fp, "artifacts": data}
