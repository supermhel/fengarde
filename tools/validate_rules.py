#!/usr/bin/env python3
"""B4 (v0.3 plan): rule validation gate.

A single command a rule contributor runs before opening a PR: proves every
`contracts/rules/*.yml` is well-formed, its `condition` parses safely under the
real T4 evaluator (no eval, no crash), every operator it uses is one the engine
actually implements, and every allowlist / time-window it references is valid.

This is the SAFETY + CORRECTNESS gate for the open-source rule flywheel: a
community rule that's malformed, references an undefined selection, uses an
operator the engine doesn't know, or points at a missing allowlist should be
rejected at contribution time with a clear message -- not silently fail-closed
to "never matches" at runtime (a rule that quietly never fires is worse than a
build error, because nobody notices).

It deliberately REUSES the engine's own tokenizer/parser and operator set
(imported from services/ws4-detection/engine.py) so "valid here" means exactly
"the runtime will evaluate this," never a drifting second implementation.

Complements `tools/check_rule_producers.py` (which proves a rule's fields are
actually PRODUCED by some parser -- the anti-dormancy check). Both run in
`run_all_tests.sh` / CI. This one needs no parsers; it is pure static analysis
of the rule files.

Run: python tools/validate_rules.py            (exit 0 = all rules valid)
     python tools/validate_rules.py path.yml   (validate one file)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "contracts" / "rules"
ALLOWLISTS_DIR = ROOT / "contracts" / "allowlists"
sys.path.insert(0, str(ROOT / "services" / "ws4-detection"))

# Reuse the REAL engine internals so the gate can never drift from runtime.
from engine import (  # noqa: E402
    _NUMERIC_OPS, _parse_or, _parse_hhmm, _time_outside_hours,
)

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_LEVELS = {"informational", "low", "medium", "high", "critical"}
_SECTORS = {"common", "bank", "dc", "datacenter"}
_KNOWN_OPS = set(_NUMERIC_OPS) | {"not_in", "outside_hours", "in", "contains"}
_CONDITION_TOKEN_RE = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|[\w.]+")
_KEYWORDS = {"and", "or", "not", "(", ")"}
_DAY_NAMES = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}


def _validate_outside_hours(spec, errors: list[str], where: str) -> None:
    """Static shape check for the outside_hours operator arg -- catch a broken
    window (which would silently never/always match at runtime) at gate time.
    Then cross-check against the real _time_outside_hours to be certain."""
    if not isinstance(spec, dict):
        errors.append(f"{where}: outside_hours arg must be a mapping, got {type(spec).__name__}")
        return
    allowed = {"start", "end", "days", "tz_offset_minutes"}
    unknown = set(spec) - allowed
    if unknown:
        errors.append(f"{where}: outside_hours has unknown key(s) {sorted(unknown)}")
    for key in ("start", "end"):
        if key not in spec:
            errors.append(f"{where}: outside_hours missing '{key}'")
        elif _parse_hhmm(spec[key]) is None:
            errors.append(f"{where}: outside_hours {key}={spec[key]!r} is not a valid 'HH:MM'")
    if _parse_hhmm(spec.get("start")) is not None and spec.get("start") == spec.get("end"):
        errors.append(f"{where}: outside_hours start == end (empty window)")
    days = spec.get("days", ["mon"])
    if not isinstance(days, list) or not days or any(
            not isinstance(d, str) or d.lower() not in _DAY_NAMES for d in days):
        errors.append(f"{where}: outside_hours days must be a non-empty list of "
                      f"mon..sun, got {days!r}")
    tz = spec.get("tz_offset_minutes", 0)
    if isinstance(tz, bool) or not isinstance(tz, int) or not -14 * 60 <= tz <= 14 * 60:
        errors.append(f"{where}: outside_hours tz_offset_minutes must be an int in "
                      f"[-840, 840], got {tz!r}")
    # Belt-and-suspenders: if the shape looked ok, prove the real evaluator
    # accepts it on a known timestamp without raising (fails closed by design,
    # but a spec that can NEVER return True on any input is a dead rule).
    if not any(where in e for e in errors):
        sample_true = _time_outside_hours(spec, 0)  # epoch 0 = Thu 1970-01-01 00:00 UTC
        sample_false = _time_outside_hours(spec, 12 * 3600 * 1000)  # Thu 12:00 UTC
        if sample_true == sample_false and sample_true is False:
            errors.append(f"{where}: outside_hours window never matches any time "
                          f"(both probe timestamps returned False) -- likely a mistake")


def _validate_selection(name: str, sel, errors: list[str]) -> None:
    where = f"selection '{name}'"
    if not isinstance(sel, dict):
        errors.append(f"{where}: must be a mapping of ocsf.path -> value, got "
                      f"{type(sel).__name__}")
        return
    if not sel:
        # The engine returns True for an empty selection (`for` over zero items),
        # so it doesn't match NOTHING -- it matches EVERY event and fires the rule
        # on all traffic. That is a footgun, essentially never intended, so the
        # gate is deliberately stricter than the runtime here and rejects it.
        errors.append(f"{where}: is empty -- an empty selection matches EVERY event "
                      f"(fires the rule on all traffic); add a discriminating field "
                      f"or remove the selection")
    for path, expected in sel.items():
        if not isinstance(path, str) or not path:
            errors.append(f"{where}: field key {path!r} is not a non-empty string")
            continue
        if isinstance(expected, dict):
            if not expected:
                errors.append(f"{where}.{path}: empty operator mapping")
                continue
            for op, arg in expected.items():
                if op not in _KNOWN_OPS:
                    errors.append(f"{where}.{path}: unknown operator {op!r} "
                                  f"(engine knows {sorted(_KNOWN_OPS)})")
                elif op in _NUMERIC_OPS:
                    if isinstance(arg, bool) or not isinstance(arg, (int, float)):
                        errors.append(f"{where}.{path}: operator {op} needs a number, "
                                      f"got {arg!r}")
                elif op == "not_in":
                    if not isinstance(arg, str):
                        errors.append(f"{where}.{path}: not_in needs an allowlist name "
                                      f"(string), got {arg!r}")
                    elif not (ALLOWLISTS_DIR / f"{arg}.yml").exists():
                        errors.append(f"{where}.{path}: not_in references allowlist "
                                      f"'{arg}' but contracts/allowlists/{arg}.yml is missing")
                elif op == "outside_hours":
                    _validate_outside_hours(arg, errors, f"{where}.{path}")
                elif op == "in":
                    if not isinstance(arg, list) or not arg:
                        errors.append(f"{where}.{path}: 'in' needs a non-empty list, "
                                      f"got {arg!r}")
                elif op == "contains":
                    if not isinstance(arg, str) or not arg:
                        errors.append(f"{where}.{path}: 'contains' needs a non-empty "
                                      f"string, got {arg!r}")
        # A non-dict value (scalar OR list) is an EQUALITY match: engine's
        # _selection_matches does `actual != expected`, so a list value like
        # `some.array.field: ["a", "b"]` legitimately matches an event whose
        # field equals that exact list. Accept it -- only dicts are operators.


def _validate_condition(condition, selection_names: set[str], errors: list[str]) -> None:
    if not isinstance(condition, str) or not condition.strip():
        errors.append("detection.condition: missing or empty")
        return
    tokens = _CONDITION_TOKEN_RE.findall(condition)
    if not tokens:
        errors.append(f"detection.condition: {condition!r} tokenizes to nothing")
        return
    # Every non-keyword token is a selection name and must be defined.
    for tok in tokens:
        if tok not in _KEYWORDS and tok not in selection_names:
            errors.append(f"detection.condition references undefined selection {tok!r} "
                          f"(defined: {sorted(selection_names)})")
    # Parse under the REAL evaluator to reject malformed boolean expressions
    # (unbalanced parens, dangling operators) at gate time.
    matched = {n: False for n in selection_names}
    try:
        value, end = _parse_or(tokens, 0, matched)
        if end != len(tokens):
            errors.append(f"detection.condition: {condition!r} has trailing tokens "
                          f"after a complete expression (unbalanced parens/operators?)")
    except (ValueError, IndexError, RecursionError) as exc:
        errors.append(f"detection.condition: {condition!r} does not parse "
                      f"({type(exc).__name__}: {exc})")


def validate_rule(rule: dict) -> list[str]:
    errors: list[str] = []
    if not isinstance(rule, dict):
        return [f"top level must be a mapping, got {type(rule).__name__}"]

    title = rule.get("title")
    if not isinstance(title, str) or not title.strip():
        errors.append("missing/empty 'title'")

    rid = rule.get("id")
    if not isinstance(rid, str) or not _UUID_RE.match(rid):
        errors.append(f"'id' must be a canonical UUID, got {rid!r}")

    level = rule.get("level")
    if level not in _LEVELS:
        errors.append(f"'level' must be one of {sorted(_LEVELS)}, got {level!r}")

    detection = rule.get("detection")
    selection_names: set[str] = set()
    if not isinstance(detection, dict):
        errors.append("'detection' must be a mapping")
    else:
        selections = {k: v for k, v in detection.items() if k != "condition"}
        selection_names = set(selections)
        if not selections:
            errors.append("'detection' has no selections")
        for name, sel in selections.items():
            _validate_selection(name, sel, errors)
        _validate_condition(detection.get("condition"), selection_names, errors)

    siem = rule.get("siem", {})
    if not isinstance(siem, dict):
        errors.append("'siem' must be a mapping")
    else:
        sw = siem.get("score_weight", 0)
        if isinstance(sw, bool) or not isinstance(sw, int) or not 0 <= sw <= 100:
            errors.append(f"siem.score_weight must be an int in [0, 100], got {sw!r}")
        sector = siem.get("sector", "common")
        if sector not in _SECTORS:
            errors.append(f"siem.sector must be one of {sorted(_SECTORS)}, got {sector!r}")
        win, thr = siem.get("window_seconds"), siem.get("threshold")
        if (win is None) != (thr is None):
            errors.append("siem.window_seconds and siem.threshold must be set together "
                          "(a stateful rule needs both) or neither")
        for f in ("window_seconds", "threshold"):
            v = siem.get(f)
            if v is not None and (isinstance(v, bool) or not isinstance(v, int) or v <= 0):
                errors.append(f"siem.{f} must be a positive int, got {v!r}")
        for f in ("group_by", "distinct_field"):
            v = siem.get(f)
            if v is not None and (not isinstance(v, str) or not v):
                errors.append(f"siem.{f} must be a non-empty dotted path, got {v!r}")
    return errors


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        paths = [Path(argv[1])]
    else:
        paths = sorted(RULES_DIR.glob("*.yml"))

    seen_ids: dict[str, str] = {}
    failures: list[tuple[str, list[str]]] = []
    for path in paths:
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            failures.append((path.name, [f"invalid YAML: {exc}"]))
            continue
        if not rule:
            failures.append((path.name, ["file is empty"]))
            continue
        errors = validate_rule(rule)
        # Global invariant: rule ids must be unique (a duplicate id collapses two
        # rules' dedup/alert identity -- T7 keys on rule id).
        rid = rule.get("id")
        if isinstance(rid, str):
            if rid in seen_ids:
                errors.append(f"duplicate id {rid} (also in {seen_ids[rid]})")
            else:
                seen_ids[rid] = path.name
        if errors:
            failures.append((path.name, errors))

    if failures:
        print("[FAIL] rule validation found problems:")
        for name, errors in failures:
            print(f"  {name}:")
            for e in errors:
                print(f"      {e}")
        return 1

    print(f"[OK] all {len(paths)} rule(s) valid (schema, condition parse, operator "
          f"safety, allowlist + time-window references, unique ids)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
