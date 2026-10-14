"""Phase 6 atom-level score ratchet and PR integrity guard.

The guard path is stdlib-only. Artifact measurement is lazy so a PR can run
``guard`` without installing PyYAML or executing any evaluation lane.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = ROOT / "eval" / "twin" / "baseline_scenarios.json"
WAIVERS_PATH = ROOT / "eval" / "twin" / "ratchet_waivers.json"
HISTORY_PATH = ROOT / "eval" / "twin" / "ratchet_history.jsonl"
REPORT_PATH = ROOT / "eval" / "twin" / "ratchet_report.latest.json"
TREND_PATH = ROOT / "eval" / "trend_layer_c.jsonl"

# Ordered and explicit. Unknown namespaces intentionally fall back to pinned,
# but every atom in the committed baseline must match one of these patterns.
DIRECTION_RULES: tuple[tuple[str, str], ...] = (
    (r"^scn/[^/]+/base/(tpr|alert_order_ok|incident_membership_ok|directional_discrimination|campaign_full_coverage)$", "higher"),
    (r"^scn/[^/]+/base/mttd_seconds$", "lower"),
    (r"^scn/[^/]+/base/(chain_fidelity|false_correlation_rate|incident_count|fired_alerts|campaign_count)$", "pinned"),
    (r"^scn/[^/]+/mut/[^/]+/[^/]+$", "higher"),
    (r"^scn/[^/]+/mut/[^/]+/[^/]+/(detection_retained|fidelity_retained|fcr_unchanged|order_retained|decoy_clean)$", "higher"),
    (r"^scn/[^/]+/mut/[^/]+/[^/]+/(causal_join_broken)$", "lower"),
    (r"^scn/[^/]+/mut/[^/]+/[^/]+/(expected_rule_lost_steps|steps_lost|tactic_lost|collateral_lost_steps)$", "lower"),
    (r"^scn/[^/]+/evasion/[^/]+/(loss|stretch_pct|ip_k|account_k)$", "higher"),
    (r"^scn/[^/]+/evasion/[^/]+/(loss|stretch_pct|ip_k|account_k)/agree$", "higher"),
    (r"^lane_a/base/(tpr)$", "higher"),
    (r"^lane_a/base/(chain_fidelity|false_correlation_rate)$", "pinned"),
    (r"^lane_a/mut/[^/]+/[^/]+$", "higher"),
    (r"^lane_a/mut/[^/]+/[^/]+/(detection_retained|fidelity_retained|fcr_unchanged|order_retained|decoy_clean)$", "higher"),
    (r"^lane_a/mut/[^/]+/[^/]+/causal_join_broken$", "lower"),
    (r"^lane_a/mut/[^/]+/[^/]+/expected_rule_lost_steps$", "lower"),
    (r"^(lane_a/)?tech/[^/]+/cell/[^/]+/[^/]+/base$", "higher"),
    (r"^(lane_a/)?tech/[^/]+/cell/[^/]+/[^/]+/base/(tactic_covered|expected_rule_fired)$", "higher"),
    (r"^(lane_a/)?tech/[^/]+/cell/[^/]+/[^/]+/[^/]+/[^/]+$", "higher"),
    (r"^tech/[^/]+/rule/[^/]+/(fires|near_miss_held)$", "higher"),
    (r"^tech/[^/]+/rule/[^/]+/boundary_too_loose_n$", "lower"),
    (r"^twin/(tpr|evidence_completeness|alert_reduction_ratio|attribution_accuracy)$", "higher"),
    (r"^twin/(fpr|mttd_seconds|mtti|severity_calibration_error)$", "lower"),
    (r"^twin/negative_controls/[^/]+$", "lower"),
    (r"^corpus_b/[^/]+/missed_n$", "lower"),
    (r"^corpus_b/[^/]+/fired_n$", "pinned"),
    (r"^corpus_b/cross_case_merge_clean$", "higher"),
    (r"^quality/(macro_f1|[^/]+/f1)$", "higher"),
)
_COMPILED_DIRECTIONS = tuple((re.compile(p), d) for p, d in DIRECTION_RULES)


@dataclass(frozen=True)
class Finding:
    atom: str
    kind: str
    baseline: Any
    current: Any
    message: str


@dataclass
class CompareResult:
    failures: list[Finding]
    waived: list[str]
    regressed: list[str]
    improved: list[str]
    new: list[str]

    @property
    def status(self) -> str:
        return "GREEN" if not self.failures else "RED"


def direction_for(atom: str) -> str:
    for pattern, direction in _COMPILED_DIRECTIONS:
        if pattern.fullmatch(atom):
            return direction
    return "pinned"


def unmatched_direction_atoms(atoms: dict[str, Any]) -> list[str]:
    """Return atoms that do not match an explicit rule (unknown stays pinned)."""
    known_prefixes = ("scn/", "lane_a/", "tech/", "twin/", "corpus_b/", "quality/")
    return sorted(a for a in atoms if a.startswith(known_prefixes) and
                  direction_for(a) == "pinned" and
                  not any(p.fullmatch(a) for p, _ in _COMPILED_DIRECTIONS))


def _today(value: str | None = None) -> str:
    if value:
        return value
    if os.environ.get("RATCHET_TODAY"):
        return os.environ["RATCHET_TODAY"]
    return _dt.datetime.now(_dt.timezone.utc).date().isoformat()


def _date(value: Any) -> _dt.date | None:
    try:
        return _dt.date.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _rank(value: Any, direction: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        number = 1.0 if value else 0.0
    elif isinstance(value, (int, float)):
        number = float(value)
    else:
        text = str(value)
        # Status ranks are deliberately closed and ordered.
        maps = {
            "n/a": 0.0, "gap": 0.0, "lost": 1.0, "fail": 1.0,
            "missed": 1.0, "tactic_missed": 1.0, "retained": 2.0, "pass": 2.0,
            "tactic_covered": 2.0,
            "detected": 2.0, "immune": float("inf"),
        }
        number = maps.get(text, 0.0)
    return number if direction == "higher" else -number if direction == "lower" else number


def _equal(a: Any, b: Any) -> bool:
    if isinstance(a, float) or isinstance(b, float):
        try:
            return abs(float(a) - float(b)) <= 1e-9
        except (TypeError, ValueError):
            pass
    return a == b


def _scope_matches(scope: str, atom: str) -> bool:
    if scope.endswith("/*"):
        return atom.startswith(scope[:-1])
    return scope == atom


def _valid_evidence(value: Any) -> bool:
    text = str(value or "")
    if re.match(r"^https?://\S+$", text):
        return True
    return (ROOT / text).is_file() if text and not Path(text).is_absolute() else False


def validate_waivers(doc: dict, today: str, atoms: dict[str, Any] | None = None) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    waivers = doc.get("waivers") or []
    for waiver in waivers:
        wid = waiver.get("id")
        scope = str(waiver.get("scope", ""))
        if not wid or wid in seen:
            errors.append(f"duplicate or missing waiver id: {wid!r}")
        seen.add(wid)
        if scope == "*" or "*" in scope[:-1] or ("*" in scope and not scope.endswith("/*")):
            errors.append(f"invalid waiver scope: {scope!r}")
        if scope.endswith("/*"):
            body = scope[:-2]
            parts = body.split("/")
            if not (body.startswith("scn/") and len(parts) >= 2 or body.startswith("tech/") and len(parts) >= 2):
                errors.append(f"waiver prefix must be confined to one scenario or technique: {scope!r}")
        opened, expires = _date(waiver.get("opened")), _date(waiver.get("expires"))
        if opened is None or expires is None:
            errors.append(f"waiver {wid!r} has invalid opened/expires date")
        elif expires < opened or (expires - opened).days > 45:
            errors.append(f"waiver {wid!r} exceeds the 45-day window")
        elif expires < (_date(today) or _dt.date.min):
            errors.append(f"waiver {wid!r} is expired")
        if len(str(waiver.get("reason", ""))) < 20:
            errors.append(f"waiver {wid!r} reason must be at least 20 characters")
        if not _valid_evidence(waiver.get("evidence")):
            errors.append(f"waiver {wid!r} evidence must be an issue/PR URL or existing repo path")
        if atoms is not None and not any(_scope_matches(scope, atom) for atom in atoms):
            errors.append(f"waiver {wid!r} names no known atom")
    return errors


def _waivers_for(atom: str, doc: dict) -> list[dict]:
    return [w for w in (doc.get("waivers") or []) if _scope_matches(str(w.get("scope", "")), atom)]


def compare(baseline: dict[str, Any], current: dict[str, Any], waivers: dict,
            today: str | None = None, restrict: str | None = None) -> CompareResult:
    """Compare atom maps, including coverage, null, pinned, and waiver rules."""
    today = _today(today)
    scope = restrict.rstrip("*") if restrict else None
    if scope:
        baseline = {k: v for k, v in baseline.items() if k.startswith(scope)}
        current = {k: v for k, v in current.items() if k.startswith(scope)}
    errors = validate_waivers(waivers, today, set(baseline) | set(current))
    failures: list[Finding] = [Finding("<waivers>", "INVALID-WAIVER", None, None, e) for e in errors]
    waived: list[str] = []
    regressed: list[str] = []
    improved: list[str] = []
    new_atoms: list[str] = []
    for atom in sorted(set(baseline) | set(current)):
        if atom not in baseline:
            new_atoms.append(atom)
            failures.append(Finding(atom, "NEW", None, current[atom],
                                    "new atom is unrecorded; run ratchet.py refresh"))
            continue
        if atom not in current:
            regressed.append(atom)
            failures.append(Finding(atom, "REGRESSED-COVERAGE", baseline[atom], None,
                                    "baseline atom disappeared; use refresh --retire with evidence"))
            continue
        old, new, direction = baseline[atom], current[atom], direction_for(atom)
        if _equal(old, new):
            continue
        if direction == "pinned":
            failures.append(Finding(atom, "PINNED-CHANGED", old, new,
                                    "pinned atom changed; record a reason and evidence"))
            continue
        old_rank, new_rank = _rank(old, direction), _rank(new, direction)
        if old is not None and new is None:
            bad = True
            kind = "REGRESSED"
        elif old is None and new is not None:
            bad = False
            kind = "IMPROVED-UNRECORDED"
        elif old_rank is None or new_rank is None:
            bad = new != old
            kind = "REGRESSED" if bad else "OK"
        elif new_rank < old_rank:
            bad, kind = True, "REGRESSED"
        else:
            bad, kind = False, "IMPROVED-UNRECORDED"
        if kind == "IMPROVED-UNRECORDED":
            improved.append(atom)
            failures.append(Finding(atom, kind, old, new,
                                    "improvement is unrecorded; run: python eval/twin/ratchet.py refresh --reason '...'"))
            continue
        if bad:
            regressed.append(atom)
            matches = _waivers_for(atom, waivers)
            accepted = False
            for waiver in matches:
                floor = waiver.get("floor")
                floor_rank = _rank(floor, direction)
                if floor_rank is not None and new_rank is not None and new_rank >= floor_rank:
                    accepted = True
                    waived.append(atom)
                    break
            if not accepted:
                failures.append(Finding(atom, kind, old, new,
                                        "unwaived regression"))
    # A syntactically valid waiver must be used by at least one regression.
    for waiver in waivers.get("waivers") or []:
        if not any(_scope_matches(str(waiver.get("scope", "")), atom) for atom in waived):
            failures.append(Finding(str(waiver.get("scope", "<missing>")), "STALE-WAIVER",
                                    None, None, "waiver does not cover a currently accepted regression"))
    # Waived regressions are not failures; remove only the exact accepted finding.
    failures = [f for f in failures if not (f.atom in waived and f.kind == "REGRESSED")]
    return CompareResult(failures, sorted(set(waived)), sorted(set(regressed)),
                         sorted(set(improved)), sorted(set(new_atoms)))


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_history(path: Path = HISTORY_PATH) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        rows.append(json.loads(line))
    return rows


def _append_history(entry: dict) -> None:
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not HISTORY_PATH.exists():
        HISTORY_PATH.write_text("# Append-only ratchet history; merge=union.\n", encoding="utf-8")
    with HISTORY_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")


def _measure() -> tuple[dict, list[str], dict]:
    import ratchet_measure
    return ratchet_measure.measure_artifacts()


def _baseline_doc(atoms: dict, fingerprint: str, retired: list[str] | None = None) -> dict:
    return {
        "_comment": [
            "Frozen atom-level baseline; generated only by ratchet.py refresh --init.",
            "Known fail atoms are measured gaps, not accepted quality. Never edit by hand.",
            "Use ratchet.py refresh --reason to record improvements; use a dated waiver for drops.",
        ],
        "schema": "fengarde-scenario-ratchet-v1",
        "seed": 7,
        "basis": "harness-measured",
        "fingerprint": {"system_fingerprint": fingerprint},
        "atoms": dict(sorted(atoms.items())),
        "retired": sorted(retired or []),
    }


def _report_for(atoms: dict, baseline: dict, result: CompareResult, fp: str) -> dict:
    scenarios: dict[str, dict] = {}
    for key, value in atoms.items():
        m = re.match(r"^scn/([^/]+)/mut/([^/]+)/([^/]+)$", key)
        if m:
            name = m.group(1)
            item = scenarios.setdefault(name, {"passed": 0, "applicable": 0, "frozen": {}})
            if value != "n/a":
                item["applicable"] += 1
                item["passed"] += int(value == "pass")
        m = re.match(r"^scn/([^/]+)/base/(.+)$", key)
        if m:
            scenarios.setdefault(m.group(1), {"passed": 0, "applicable": 0, "frozen": {}})["frozen"][m.group(2)] = baseline.get(key)
    techniques: dict[str, dict] = {}
    for key, value in atoms.items():
        m = re.match(r"^(?:lane_a/)?tech/([^/]+)/cell/([^/]+)/([^/]+)/base$", key)
        if m:
            techniques.setdefault(m.group(1), {"detected": 0, "cells": 0, "frozen": []})["frozen"].append(value)
        m = re.match(r"^(?:lane_a/)?tech/([^/]+)/cell/([^/]+)/([^/]+)/[^/]+/[^/]+$", key)
        if m and value != "n/a":
            item = techniques.setdefault(m.group(1), {"detected": 0, "cells": 0, "frozen": []})
            item["cells"] += 1
            item["detected"] += int(value == "retained")
    return {
        "schema": "fengarde-ratchet-report-v1", "system_fingerprint": fp,
        "status": result.status, "atoms": len(atoms),
        "scenarios": dict(sorted(scenarios.items())),
        "techniques": dict(sorted(techniques.items())),
        "waived": result.waived, "regressed": result.regressed,
        "improved_unrecorded": result.improved, "new": result.new,
        "failures": [f.__dict__ for f in result.failures],
    }


def _print_result(result: CompareResult, atoms: dict, baseline: dict) -> None:
    for name in sorted({k.split("/")[1] for k in atoms if k.startswith("scn/")}):
        keys = [k for k in atoms if k.startswith(f"scn/{name}/mut/") and k.count("/") == 4]
        applicable = [k for k in keys if atoms[k] != "n/a"]
        passed = sum(atoms[k] == "pass" for k in applicable)
        frozen = baseline.get(f"scn/{name}/base/tpr", "n/a")
        print(f"scenario {name}: {passed}/{len(applicable)} (frozen tpr={frozen})")
    for atom, value in sorted(atoms.items()):
        if "/cell/" in atom and atom.endswith("/base"):
            print(f"technique {atom.split('/cell/', 1)[0].split('tech/', 1)[-1]}: {value} (frozen={baseline.get(atom)!r})")
    for finding in result.failures:
        print(f"[FAIL] {finding.kind} {finding.atom}: {finding.message} "
              f"baseline={finding.baseline!r} current={finding.current!r}")
    print(f"WAIVED={len(result.waived)} REGRESSED={len(result.regressed)} "
          f"IMPROVED-UNRECORDED={len(result.improved)} NEW={len(result.new)}")


def cmd_check(args: argparse.Namespace) -> int:
    atoms, errors, meta = _measure()
    if errors:
        for error in errors:
            print(f"[FAIL] {error}")
        return 1
    if not BASELINE_PATH.exists():
        print("[NOTICE] no committed baseline; run ratchet.py refresh --init after the full gate")
        return 0
    baseline_doc = _load_json(BASELINE_PATH)
    baseline = baseline_doc.get("atoms") or {}
    waivers = _load_json(WAIVERS_PATH) if WAIVERS_PATH.exists() else {"waivers": []}
    result = compare(baseline, atoms, waivers, restrict=args.scope)
    _write_json(REPORT_PATH, _report_for(atoms, baseline, result, meta["system_fingerprint"]))
    _print_result(result, atoms, baseline)
    return 0 if not result.failures else 1


def _parse_value(value: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def cmd_refresh(args: argparse.Namespace) -> int:
    atoms, errors, meta = _measure()
    if errors:
        for error in errors:
            print(f"[FAIL] {error}")
        return 1
    today = _today()
    if args.init:
        if BASELINE_PATH.exists():
            print("[FAIL] --init refuses to overwrite an existing baseline")
            return 1
        _write_json(BASELINE_PATH, _baseline_doc(atoms, meta["system_fingerprint"]))
        _append_history({"date": today, "kind": "init", "reason": args.reason,
                         "added": sorted(atoms), "improved": [], "retired": [],
                         "lowered": [], "fingerprint": meta["system_fingerprint"]})
        print(f"[OK] initialized {BASELINE_PATH.relative_to(ROOT)} with {len(atoms)} measured atoms")
        return 0
    if not BASELINE_PATH.exists():
        print("[FAIL] baseline absent; use refresh --init once after the full gate")
        return 1
    baseline_doc = _load_json(BASELINE_PATH)
    baseline = dict(baseline_doc.get("atoms") or {})
    waivers = _load_json(WAIVERS_PATH) if WAIVERS_PATH.exists() else {"waivers": []}
    result = compare(baseline, atoms, waivers, today=today)
    lower_names = {item.split("=", 1)[0] for item in (args.lower or []) if "=" in item}
    retire_prefixes = [str(prefix) for prefix in (args.retire or [])]
    def is_retired(atom: str) -> bool:
        return any(atom == prefix or atom.startswith(prefix.rstrip("*") + ("" if prefix.endswith("*") else "/"))
                   for prefix in retire_prefixes)
    hard = [f for f in result.failures if f.kind not in {"IMPROVED-UNRECORDED", "NEW"}
            and not (f.kind == "PINNED-CHANGED" and f.atom in lower_names)
            and not (f.kind == "REGRESSED-COVERAGE" and is_retired(f.atom))]
    if hard:
        _print_result(result, atoms, baseline)
        print("[FAIL] refresh refuses to write while a regression or invalid waiver exists")
        return 1
    changed = sorted(set(result.improved) | set(result.new))
    retired: list[str] = []
    for prefix in args.retire or []:
        matches = [k for k in list(baseline) if k == prefix or k.startswith(prefix.rstrip("*") + ("" if prefix.endswith("*") else "/"))]
        for key in matches:
            baseline.pop(key, None)
        retired.append(prefix)
    lowered: list[dict] = []
    if args.lower:
        if len(args.reason or "") < 20 or not _valid_evidence(args.evidence):
            print("[FAIL] --lower requires a >=20 character --reason and URL/existing-path --evidence")
            return 1
        for item in args.lower:
            if "=" not in item:
                print(f"[FAIL] invalid --lower {item!r}; use ATOM=VALUE")
                return 1
            atom, raw = item.split("=", 1)
            if atom not in baseline:
                print(f"[FAIL] --lower names unknown baseline atom {atom}")
                return 1
            value = _parse_value(raw)
            baseline[atom] = value
            lowered.append({"atom": atom, "value": value,
                            "reason": args.reason, "evidence": args.evidence})
            changed.append(atom)
    if not changed and not retired and not lowered:
        print("[OK] nothing to refresh; baseline is already current")
        return 0
    for key in changed:
        if key in atoms and key not in {x["atom"] for x in lowered}:
            baseline[key] = atoms[key]
    all_retired = sorted(set(baseline_doc.get("retired") or []) | set(retired))
    _write_json(BASELINE_PATH, _baseline_doc(baseline, meta["system_fingerprint"], all_retired))
    _append_history({"date": today, "kind": "refresh", "reason": args.reason,
                     "added": sorted(set(result.new)), "improved": sorted(set(result.improved)),
                     "retired": retired, "lowered": lowered,
                     "fingerprint": meta["system_fingerprint"]})
    print(f"[OK] refreshed {len(changed)} atom(s); history appended")
    return 0


def _git_show(ref: str, path: str) -> tuple[str | None, bool]:
    proc = subprocess.run(["git", "show", f"{ref}:{path}"], cwd=ROOT,
                          text=True, capture_output=True)
    if proc.returncode == 0:
        return proc.stdout, True
    if "does not exist" in proc.stderr or "exists on disk, but not in" in proc.stderr:
        return None, False
    raise RuntimeError(proc.stderr.strip() or f"git show failed for {ref}:{path}")


def guard_compare(base_doc: dict | None, head_doc: dict | None,
                  base_history: list[dict], head_history: list[dict], waivers: dict,
                  today: str | None = None) -> list[str]:
    problems: list[str] = []
    if head_doc is None:
        return ["baseline file deleted"]
    if base_doc is None:
        return []
    if head_doc.get("schema") != base_doc.get("schema") or head_doc.get("seed") != base_doc.get("seed"):
        problems.append("baseline schema or seed changed")
    if head_history[:len(base_history)] != base_history:
        problems.append("ratchet history was truncated or rewritten (must be append-only)")
    base_atoms, head_atoms = base_doc.get("atoms") or {}, head_doc.get("atoms") or {}
    valid_waiver_errors = validate_waivers(waivers, _today(today), set(head_atoms))
    problems.extend(valid_waiver_errors)
    entries = head_history
    def justified(atom: str, value: Any, pinned: bool = False) -> bool:
        # Pinned atoms have no rank/floor semantics. A waiver cannot silently
        # bless a change; the append-only history must carry explicit reason
        # and evidence (the same reviewable shape as --lower).
        if not pinned and any(_scope_matches(str(w.get("scope", "")), atom) for w in waivers.get("waivers") or []):
            return True
        for entry in entries:
            for low in entry.get("lowered") or []:
                if isinstance(low, str) and low == atom:
                    return True
                if isinstance(low, dict) and low.get("atom") == atom and low.get("reason") and low.get("evidence"):
                    return True
            for pin in entry.get("pinned") or []:
                if isinstance(pin, dict) and pin.get("atom") == atom and pin.get("reason") and pin.get("evidence"):
                    return True
        return False
    for atom, old in base_atoms.items():
        if atom not in head_atoms:
            if not any(atom == p or atom.startswith(p.rstrip("*") + "/") for p in (head_doc.get("retired") or [])):
                problems.append(f"baseline atom deleted without retirement: {atom}")
            continue
        new, direction = head_atoms[atom], direction_for(atom)
        changed = not _equal(old, new)
        if not changed:
            continue
        lower = direction == "pinned"
        if direction != "pinned":
            old_rank, new_rank = _rank(old, direction), _rank(new, direction)
            lower = (old is not None and new is None) or (old_rank is not None and new_rank is not None and new_rank < old_rank)
        if lower and not justified(atom, new, pinned=direction == "pinned"):
            problems.append(f"baseline atom lowered without waiver or evidence: {atom}")
    return problems


def cmd_guard(args: argparse.Namespace) -> int:
    try:
        base_text, exists = _git_show(args.base, "eval/twin/baseline_scenarios.json")
    except RuntimeError as exc:
        print(f"[FAIL] {exc}")
        return 1
    if not exists:
        print(f"[OK] baseline absent at {args.base}; introducing PR is green")
        return 0
    if not BASELINE_PATH.exists():
        print("[FAIL] current baseline file is absent")
        return 1
    try:
        base_hist_text, _ = _git_show(args.base, "eval/twin/ratchet_history.jsonl")
    except RuntimeError:
        base_hist_text = None
    base_doc = json.loads(base_text or "{}")
    head_doc = _load_json(BASELINE_PATH)
    base_history = [json.loads(x) for x in (base_hist_text or "").splitlines() if x and not x.startswith("#")]
    head_history = _load_history()
    waivers = _load_json(WAIVERS_PATH) if WAIVERS_PATH.exists() else {"waivers": []}
    problems = guard_compare(base_doc, head_doc, base_history, head_history, waivers)
    for problem in problems:
        print(f"[FAIL] {problem}")
    if problems:
        return 1
    print(f"[OK] ratchet guard: {args.base} -> HEAD")
    return 0


def _trend_rows(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        rows.append(json.loads(line))
    return rows


def trend_append(layer_c: Path, path: Path = TREND_PATH) -> int:
    try:
        source = _load_json(layer_c)
        cases = source.get("cases") or source.get("results") or []
        row = {
            "_schema": "layer-c-trend-v1",
            "date": _today(),
            "seed": source.get("seed", 7),
            "producer": source.get("producer", "stub"),
            "comparable": source.get("producer", "stub") == "stub",
            "n_cases": len(cases),
            "n_pass": sum(bool(c.get("pass")) for c in cases if isinstance(c, dict)),
            "n_detection_lost": sum(not bool(c.get("detection_retained", True)) for c in cases if isinstance(c, dict)),
            "n_join_broken": sum(bool(c.get("causal_join_broken")) for c in cases if isinstance(c, dict)),
            "cases": [{k: c.get(k) for k in ("composition", "pass", "detection_retained", "causal_join_broken")}
                      for c in cases if isinstance(c, dict)],
            "ratchet_snapshot": source.get("ratchet_snapshot", {}),
            "system_fingerprint": source.get("system_fingerprint"),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
        print(f"[OK] advisory Layer C trend appended to {path}")
    except Exception as exc:
        print(f"::warning::Layer C trend append unavailable: {exc}")
    return 0


def trend_diff(path: Path = TREND_PATH, summary_path: Path | None = None) -> int:
    rows = _trend_rows(path)
    warnings = []
    comparable = [r for r in rows if r.get("comparable") and r.get("producer") == "stub"]
    for left, right in zip(comparable, comparable[1:]):
        if left.get("system_fingerprint") == right.get("system_fingerprint") and left.get("ratchet_snapshot") != right.get("ratchet_snapshot"):
            warnings.append("::error::Layer C stub determinism changed with an equal system fingerprint")
    llm = [r for r in rows if r.get("producer") == "llm"]
    if llm:
        warnings.append(f"Layer C advisory: {len(llm)} LLM row(s) are not compared with a baseline")
    for line in warnings:
        print(line)
    if summary_path:
        summary_path.write_text("\n".join(warnings) + ("\n" if warnings else ""), encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ratchet.py")
    sub = ap.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check")
    check.add_argument("--advisory", action="store_true")
    check.add_argument("--scope")
    check.add_argument("--report", type=Path, default=REPORT_PATH)
    check.set_defaults(func=cmd_check)
    refresh = sub.add_parser("refresh")
    refresh.add_argument("--reason", required=True)
    refresh.add_argument("--init", action="store_true")
    refresh.add_argument("--scope")
    refresh.add_argument("--retire", action="append")
    refresh.add_argument("--lower", action="append")
    refresh.add_argument("--evidence")
    refresh.set_defaults(func=cmd_refresh)
    guard = sub.add_parser("guard")
    guard.add_argument("--base", required=True)
    guard.set_defaults(func=cmd_guard)
    explain = sub.add_parser("explain")
    explain.add_argument("atom")
    explain.set_defaults(func=lambda a: (print(f"{a.atom}: direction={direction_for(a.atom)}"), 0)[1])
    ta = sub.add_parser("trend-append")
    ta.add_argument("--layer-c", type=Path, required=True)
    ta.set_defaults(func=lambda a: trend_append(a.layer_c))
    td = sub.add_parser("trend-diff")
    td.add_argument("--path", type=Path, default=TREND_PATH)
    td.add_argument("--summary", type=Path)
    td.set_defaults(func=lambda a: trend_diff(a.path, a.summary))
    args = ap.parse_args(argv)
    if args.command == "check" and args.advisory:
        # Advisory mode must never block a nightly job.
        rc = cmd_check(args)
        return 0 if rc else 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
