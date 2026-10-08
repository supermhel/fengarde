"""oracle_derive -- an INDEPENDENT second reading of what each storyline SHOULD fire.

WHY THIS EXISTS (2026-10-02)
    Every oracle under eval/twin/ (oracle.yaml, oracle_it_intrusion.yaml,
    oracle_infra_takeover.yaml) is hand-written by the project that wrote the
    detector. ``oracle_consistency.py`` already checks it against what the pipeline
    DID. That is one direction only: if the oracle and the pipeline drift together, or
    if the oracle was authored to match the output, nothing notices. This module
    derives the same answers a second way -- from ``contracts/rules/*.yml`` plus the
    events the REAL parsers produce -- WITHOUT running the detector, and diffs the
    result against the hand answer key.

    It is a re-implementation of the rule semantics, written from the rule files and
    the documented grammar (and cross-checked against ``engine.Rule`` by a seeded
    fidelity fuzz in ``test_oracle_crosscheck.py``). It deliberately imports none of
    engine / window / report / negative_controls / oracle_consistency
    (``test_oracle_crosscheck.py`` enforces that with an AST scan).

WHAT IT DERIVES (per storyline step)
    * which rules can fire (a tri-state True / False / UNDECIDED selector evaluator and
      a sliding-window volume simulator over the attack events, with the engine's
      per-EVENT companion suppression),
    * the step's gap status, tactic set, first/last event time, evidence entities.

WHAT IT CHECKS (findings; FAIL unless waived with a dated reason)
    F1  rule_not_derivable    hand expects R at a step; the rule files cannot fire it there.
    F2  rule_undecided        hand expects R; the static model cannot decide (WARN, capped).
    F3  rule_underdeclared    R fires at a step the hand oracle does not declare.
    F4  gap_stale             hand says gap, a rule fires.
    F5  gap_flag_inconsistent gap flag and expected_rules disagree (gap:false with no rules, or both).
    F6  expected_rule_no_tactic  an expected rule carries no mitre.tactic, so the tactic-coverage
                              grader silently falls back to rule identity (a lint on the rule, not
                              a hand/derived diff: no oracle declares tactics).
    F7  edge_no_shared_observable  an allowed edge with no entity shared on any time-ordered path
                              (authoring rule 2, checked mechanically).
    F8  edge_direction_vs_time  an allowed edge that points backwards in event time, or a forbidden
                              edge that is chronologically forward.
    F9  sequence_not_time_ordered  expected_sequence is not sorted by event time (``strict_order``
                              claims it; no grader enforces it).
    F10 logsource_class_mismatch   rule logsource.category incompatible with its class_uid
                              (static OCSF map from contracts/ocsf-classes.md).
    F12 evidence_missing_group_key  evidence.per_step.fields omits the group_by / distinct_field of
                              an expected stateful rule.
    F13 level_mismatch        hand level differs from the rule YAML level.
    F14 membership_unattainable_under_track_model  no single canonical entity appears at EVERY step
                              that raises an alert, so no single entity track (tracks never merge:
                              services/ws8-correlation/INTERFACE.md:186, campaigns.py header) can
                              carry the whole chain while the oracle demands incident_count >= 1.
    (F11, "rule siem.sector must match the event sector", was DROPPED: no event carries a sector
    value and the engine never filters on it, so there is nothing to compare.)

WHAT IT CANNOT CATCH (stated in its own output, not only here)
    It SHARES the rule YAML, the parsers and the scenario builders with the thing it checks.
    So it detects SKEW and DRIFT (a rule edit, an oracle edit, a builder edit that the other
    side did not follow), NOT original error: a rule that is wrong about the technique, a parser
    that misclassifies, a builder whose timestamps/entities are unrealistic, or a misreading of
    the grammar shared by this interpreter and engine.py are all invisible. It cannot say which
    techniques ought to have a rule (a behaviour no rule targets is invisible, so the hand ``gap``
    declarations stay the only record of coverage gaps), whether a threshold is sensible, or what
    severity an analyst expects beyond the rule YAML's own level. Closing that needs a third-party
    labelled corpus, which is a different step.

Stdlib + PyYAML. Deterministic: same (rules, scenario, seed) -> same output.
"""
from __future__ import annotations

import argparse
import ast
import ipaddress
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
for _p in (str(TWIN), str(SERVICES), str(ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import yaml  # noqa: E402

import scenario_registry as reg  # noqa: E402

RULES_DIR = ROOT / "contracts" / "rules"
ALLOWLISTS_DIR = ROOT / "contracts" / "allowlists"

# Modules this file may NOT import (checked by ``independence_violations``): a derived oracle
# that reuses the engine's own evaluator would just agree with the engine by construction.
FORBIDDEN_IMPORTS = ("engine", "window", "report", "negative_controls", "oracle_consistency",
                     "allowlist")

LIMITS = (
    "LIMIT: this derived oracle SHARES the rule YAML, the parsers and the scenario builders with the "
    "thing it checks. It detects skew and drift, not original error: it cannot see a rule that is "
    "wrong about the technique, a parser that misclassifies, an unrealistic builder, or a "
    "misreading of the grammar common to this interpreter and engine.py. Hand `gap` declarations "
    "remain the only record of techniques that ought to have a rule. A third-party labelled corpus "
    "is the remedy and is out of scope here."
)

# Static OCSF map (contracts/ocsf-classes.md; the repo uses 4002 for DNS and proxy/WAF logs).
_CATEGORY_CLASSES = {
    "authentication": {3002},
    "account_change": {3003},
    "network_activity": {4001, 4002},
    "application_activity": {6003},
    "api_activity": {6003},
    "datastore_activity": {6005},
    "privilege_use": {1002},
    "file_activity": {1001},
}

# Dated, closed waiver table: (scenario, kind, step, item) -> "YYYY-MM-DD reason". A stale entry
# (one that no longer reproduces) FAILS, so the table cannot quietly outlive the disagreement.
_WAIVED: dict = {
    ("it_intrusion", "F14", "-", "incident_count"): (
        "2026-10-02 known and measured, not resolved: no single entity spans all five alert-raising "
        "steps (attacker address -> stolen account -> foothold address), and WS-8 tracks never merge, "
        "so incident_membership_ok=False / incident_count=3 is the correct reading of an "
        "`incident_count: 1` that this correlator cannot meet. Owner decision pending (retarget "
        "onto campaign_full_coverage, lower the target, or keep as a flagged gap); the WS-8 "
        "invariant is not touched."),
}
# F2 (rule undecidable by the static model) is a WARN, but capped per scenario so it cannot grow.
# 2026-10-03 phishing_bec: 1 -- common_beaconing's periodicity bound (coefficient of variation of the
# inter-arrival times) is not modelled by this static interpreter, so c2_beacon is reported UNDECIDED
# rather than guessed. The engine and the negative twins (5-of-6 beats, irregular interval) cover it.
_F2_CAP: dict = {"phishing_bec": 1}

_REASON_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \S.{8,}")

# Findings that never gate on their own (they are counted and printed).
_WARN_KINDS = {"F2"}


# ---------------------------------------------------------------------------
# tri-state logic (True / False / None == UNDECIDED)
# ---------------------------------------------------------------------------
def _tri_not(v):
    return None if v is None else (not v)


def _tri_and(a, b):
    if a is False or b is False:
        return False
    if a is None or b is None:
        return None
    return True


def _tri_or(a, b):
    if a is True or b is True:
        return True
    if a is None or b is None:
        return None
    return False


# ---------------------------------------------------------------------------
# rule model
# ---------------------------------------------------------------------------
class DRule:
    """One rule file as this module reads it (not engine.Rule)."""

    def __init__(self, raw: dict, source: str = ""):
        self.raw = raw
        self.source = source
        self.id = raw.get("id")
        self.title = raw.get("title", "untitled")
        self.level = raw.get("level", "medium")
        det = raw.get("detection") or {}
        self.condition = (det.get("condition") or "").strip()
        self.selections = {k: v for k, v in det.items() if k != "condition"}
        expr = self.condition or " and ".join(self.selections)
        self.tokens = _TOKEN_RE.findall(expr)
        siem = raw.get("siem") or {}
        self.window_seconds = siem.get("window_seconds")
        self.threshold = siem.get("threshold")
        self.stateful = self.window_seconds is not None and self.threshold is not None
        self.group_by = siem.get("group_by", "src_endpoint.ip")
        self.distinct_field = siem.get("distinct_field")
        self.periodicity = siem.get("periodicity")
        co = siem.get("companion_of")
        self.companion_of = co if isinstance(co, str) and co else None
        mitre = raw.get("mitre") or {}
        self.tactic = str(mitre["tactic"]) if mitre.get("tactic") else None
        self.category = (raw.get("logsource") or {}).get("category")

    def meta(self) -> dict:
        return {"title": self.title, "level": self.level, "tactic": self.tactic,
                "stateful": self.stateful, "group_by": self.group_by if self.stateful else None,
                "distinct_field": self.distinct_field if self.stateful else None,
                "companion_of": self.companion_of, "periodic": bool(self.periodicity)}


_TOKEN_RE = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|[\w.]+")


def load_rules(rules_dir: Path | None = None) -> dict:
    """``{rule_id: DRule}`` from ``<rules_dir>/*.yml`` (default: contracts/rules)."""
    out: dict = {}
    for f in sorted(Path(rules_dir or RULES_DIR).glob("*.yml")):
        raw = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        if raw.get("id"):
            out[raw["id"]] = DRule(raw, f.name)
    return out


class _Allow:
    """contracts/allowlists/<name>.yml ``entries``: exact string or CIDR membership. A missing or
    unreadable file matches NOTHING (so a ``not_in`` clause keeps the selection true)."""

    def __init__(self, entries):
        self.exact = {e for e in (entries or []) if isinstance(e, str)}
        self.nets = []
        for e in self.exact:
            try:
                self.nets.append(ipaddress.ip_network(e, strict=False))
            except ValueError:
                pass

    def matches(self, value) -> bool:
        if value is None:
            return False
        s = str(value)
        if s in self.exact:
            return True
        try:
            addr = ipaddress.ip_address(s)
        except ValueError:
            return False
        return any(addr.version == n.version and addr in n for n in self.nets)


_ALLOW_CACHE: dict = {}


def _allowlist(name: str, allowlists_dir: Path | None = None) -> _Allow:
    d = Path(allowlists_dir or ALLOWLISTS_DIR)
    key = (str(d), name)
    if key not in _ALLOW_CACHE:
        try:
            doc = yaml.safe_load((d / f"{name}.yml").read_text(encoding="utf-8")) or {}
            _ALLOW_CACHE[key] = _Allow(doc.get("entries"))
        except Exception:  # noqa: BLE001 - missing/malformed -> matches nothing (rule keeps firing)
            _ALLOW_CACHE[key] = _Allow([])
    return _ALLOW_CACHE[key]


# ---------------------------------------------------------------------------
# selector evaluation
# ---------------------------------------------------------------------------
def _get(doc, dotted: str):
    cur = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


_DAYS = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


def _outside_hours(spec, actual):
    """Tri-state ``outside_hours``: True when epoch-ms ``actual`` is outside the window, False when
    inside, None when the spec is malformed (this reader will not guess)."""
    if not isinstance(spec, dict) or not spec:
        return None
    if not _is_num(actual):
        return False  # a non-numeric time never matches (documented fail-closed)
    try:
        sh, sm = (int(x) for x in str(spec["start"]).split(":"))
        eh, em = (int(x) for x in str(spec["end"]).split(":"))
    except (KeyError, ValueError):
        return None
    start, end = sh * 60 + sm, eh * 60 + em
    if start == end:
        return None
    tz = spec.get("tz_offset_minutes", 0)
    if isinstance(tz, bool) or not isinstance(tz, int):
        return None
    days_raw = spec.get("days", ["mon", "tue", "wed", "thu", "fri"])
    if not isinstance(days_raw, list) or not all(isinstance(d, str) and d.lower() in _DAYS for d in days_raw):
        return None
    if set(spec) - {"start", "end", "days", "tz_offset_minutes"}:
        return None
    local = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=int(actual), minutes=tz)
    if local.weekday() not in {_DAYS[d.lower()] for d in days_raw}:
        return True
    minute = local.hour * 60 + local.minute
    inside = (start <= minute < end) if start < end else (minute >= start or minute < end)
    return not inside


def _in_list(actual, choices) -> bool:
    for c in choices:
        if isinstance(actual, bool) != isinstance(c, bool):
            continue
        if actual == c:
            return True
    return False


def _field_match(expected, actual, allowlists_dir=None):
    """Tri-state: does ``actual`` satisfy one selector clause ``expected``?"""
    if not isinstance(expected, dict):
        return actual == expected
    if not expected:
        return False
    result = True
    for op, arg in expected.items():
        if op == "in":
            v = isinstance(arg, list) and _in_list(actual, arg)
        elif op == "exists":
            v = isinstance(arg, bool) and ((actual is not None) == arg)
        elif op == "not_in":
            v = isinstance(arg, str) and not _allowlist(arg, allowlists_dir).matches(actual)
        elif op == "outside_hours":
            v = _outside_hours(arg, actual)
        else:
            v = None  # gt/lt/contains/glob/... are not modelled: say UNDECIDED, never guess
        result = _tri_and(result, v)
    return result


def selection_value(sel: dict, event: dict, allowlists_dir=None):
    result = True
    for path, expected in sel.items():
        result = _tri_and(result, _field_match(expected, _get(event, path), allowlists_dir))
    return result


def eval_condition(rule: DRule, event: dict, allowlists_dir=None):
    """Tri-state value of the rule's boolean condition on one event (selector level only; no
    window state). ``and`` / ``or`` / ``not`` / parentheses; an undefined name is False."""
    values = {name: selection_value(sel, event, allowlists_dir) if isinstance(sel, dict) else None
              for name, sel in rule.selections.items()}
    toks = rule.tokens
    pos = [0]

    def parse_or():
        val = parse_and()
        while pos[0] < len(toks) and toks[pos[0]] == "or":
            pos[0] += 1
            val = _tri_or(val, parse_and())
        return val

    def parse_and():
        val = parse_not()
        while pos[0] < len(toks) and toks[pos[0]] == "and":
            pos[0] += 1
            val = _tri_and(val, parse_not())
        return val

    def parse_not():
        if pos[0] < len(toks) and toks[pos[0]] == "not":
            pos[0] += 1
            return _tri_not(parse_not())
        return parse_atom()

    def parse_atom():
        if pos[0] >= len(toks):
            raise ValueError("unexpected end")
        t = toks[pos[0]]
        pos[0] += 1
        if t == "(":
            val = parse_or()
            if pos[0] >= len(toks) or toks[pos[0]] != ")":
                raise ValueError("missing )")
            pos[0] += 1
            return val
        if t in ("and", "or", "not", ")"):
            raise ValueError(f"unexpected {t}")
        return values.get(t, False)

    try:
        val = parse_or()
        if pos[0] != len(toks):
            return None
        return val
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# volume simulation
# ---------------------------------------------------------------------------
def _num_time(ev) -> int | None:
    t = (ev or {}).get("time")
    return int(t) if _is_num(t) else None


def entities_of(event: dict) -> set:
    """Canonical-ish observable entities one event evidences: account, source address, device."""
    out = set()
    if not isinstance(event, dict):
        return out
    actor = event.get("actor") or {}
    user = actor.get("user") if isinstance(actor.get("user"), dict) else {}
    if user.get("name"):
        out.add("actor:" + str(user["name"]).strip().lower())
    src = event.get("src_endpoint") or {}
    if src.get("ip"):
        out.add("ip:" + str(src["ip"]).strip().lower())
    dev = src.get("mac") or src.get("hostname")
    if dev:
        out.add("device:" + str(dev).strip().lower())
    return out


def _raw_ms(payload: dict) -> int | None:
    raw = (payload or {}).get("raw")
    if isinstance(raw, dict):
        t = raw.get("ts") if raw.get("ts") is not None else raw.get("time")
        if _is_num(t):
            return int(t)
    r = ((payload or {}).get("meta") or {}).get("received_at")
    return int(r) if _is_num(r) else None


def derive(sdef, seed: int = 7, *, rules: dict | None = None, result=None,
           allowlists_dir: Path | None = None) -> dict:
    """Derive, per step of ``sdef``, what the rule files say fires -- without running the detector."""
    rules = rules if rules is not None else load_rules()
    result = result if result is not None else reg.run(sdef, seed)
    order = sorted(rules)
    steps: dict = {}
    for spec in sdef.steps:
        steps[spec.label] = {"events": 0, "parsed_events": 0, "first_ms": None, "last_ms": None,
                             "entities": set(), "fires": {}, "suppressed": {}, "undecided": set(),
                             "tactics": set()}
    windows: dict = {}  # (rule_id, group) -> [(t, member_or_value)]
    ordinal = 0
    for ev in result.events:
        st = steps.setdefault(ev.step, {"events": 0, "parsed_events": 0, "first_ms": None, "last_ms": None,
                                        "entities": set(), "fires": {}, "suppressed": {},
                                        "undecided": set(), "tactics": set()})
        st["events"] += 1
        t_ms = _num_time(ev.event) if ev.parsed else _raw_ms(ev.raw_payload)
        if t_ms is not None:
            st["first_ms"] = t_ms if st["first_ms"] is None else min(st["first_ms"], t_ms)
            st["last_ms"] = t_ms if st["last_ms"] is None else max(st["last_ms"], t_ms)
        if not ev.parsed or not ev.event:
            continue
        event = ev.event
        st["parsed_events"] += 1
        st["entities"] |= entities_of(event)
        matched: set = set()
        for rid in order:
            rule = rules[rid]
            cond = eval_condition(rule, event, allowlists_dir)
            if cond is None:
                st["undecided"].add(rid)
                continue
            if cond is not True:
                continue
            if not rule.stateful:
                matched.add(rid)
                continue
            if rule.periodicity:
                st["undecided"].add(rid)  # periodicity (CV over inter-arrival times) is not modelled
                continue
            group = _get(event, rule.group_by)
            now = _num_time(event)
            if group is None or now is None:
                continue
            window_ms = int(rule.window_seconds) * 1000
            if rule.distinct_field:
                member = _get(event, rule.distinct_field)
                if member is None:
                    continue
            else:
                member = ordinal
            buf = windows.setdefault((rid, str(group)), [])
            buf.append((now, member))
            buf.sort(key=lambda e: e[0])
            while buf and buf[0][0] < now - window_ms:
                buf.pop(0)
            count = len({m for _, m in buf}) if rule.distinct_field else len(buf)
            if count >= rule.threshold:
                matched.add(rid)
        # per-EVENT companion suppression (services/ws4-detection/main.py): a companion is dropped only
        # when its sibling matched THIS event; on a burst it can still fire on an earlier/later event.
        kept = {r for r in matched if rules[r].companion_of not in matched}
        for rid in sorted(matched):
            bucket = st["fires"] if rid in kept else st["suppressed"]
            bucket.setdefault(rid, []).append(ordinal)
        for rid in kept:
            if rules[rid].tactic:
                st["tactics"].add(rules[rid].tactic)
        ordinal += 1
    out_steps: dict = {}
    for label, st in steps.items():
        suppressed_only = {r: v for r, v in st["suppressed"].items() if r not in st["fires"]}
        undecided = sorted(st["undecided"] - set(st["fires"]) - set(suppressed_only))
        out_steps[label] = {
            "events": st["events"], "parsed_events": st["parsed_events"],
            "first_ms": st["first_ms"], "last_ms": st["last_ms"],
            "entities": sorted(st["entities"]),
            "fires": {r: v for r, v in sorted(st["fires"].items())},
            "suppressed_companions": {r: v for r, v in sorted(suppressed_only.items())},
            "suppressed_events": {r: v for r, v in sorted(st["suppressed"].items())},
            "undecided": undecided,
            "tactics": sorted(st["tactics"]),
            "gap": not st["fires"] and not suppressed_only and not undecided,
        }
    return {"scenario": sdef.name, "seed": seed,
            "rules": {rid: rules[rid].meta() for rid in sorted(rules)},
            "steps": out_steps}


def cannot_match(derived: dict, step: str, rule_id: str) -> bool:
    """True when the rule files say ``rule_id`` can NOT fire at ``step`` (neither firing, nor a
    suppressed companion, nor undecided). Used to pick a guaranteed-wrong decoy rule."""
    st = derived["steps"].get(step) or {}
    return (rule_id not in (st.get("fires") or {})
            and rule_id not in (st.get("suppressed_companions") or {})
            and rule_id not in (st.get("undecided") or []))


def pick_decoy(derived: dict, step: str, true_rule_id: str, rules_meta: dict | None = None) -> str | None:
    """The lowest-sorted rule id that cannot match ``step`` and whose tactic differs from the true
    rule's (and is known). UNDECIDED rules are never chosen: a decoy must not secretly fire."""
    meta = rules_meta or derived["rules"]
    want = (meta.get(true_rule_id) or {}).get("tactic")
    fired_somewhere = {r for s in derived["steps"].values() for r in s["fires"]}
    here = set((derived["steps"].get(step) or {}).get("fires") or {})
    for rid in sorted(meta):
        tac = meta[rid].get("tactic")
        if rid == true_rule_id or not tac or tac == want or meta[rid].get("periodic"):
            continue
        if meta[rid].get("companion_of") in here:
            continue  # a companion of a rule that fires here would read as "silenced", not "wrong"
        if not cannot_match(derived, step, rid):
            continue
        # prefer a rule that never fires anywhere in this chain, so the decoy is wrong EVERYWHERE
        if rid in fired_somewhere:
            continue
        return rid
    return None


# ---------------------------------------------------------------------------
# the hand oracle, normalised
# ---------------------------------------------------------------------------
def hand_view(oracle: dict) -> dict:
    """Per step: expected rule ids/levels, gap flag, evidence fields -- tolerant of both shapes."""
    dp = oracle.get("detection_points") or {}
    ev = (oracle.get("evidence") or {}).get("per_step") or {}
    out: dict = {}
    for step in oracle.get("expected_sequence") or []:
        entry = dp.get(step) or {}
        rules = {}
        for r in entry.get("expected_rules") or []:
            rid = r.get("rule_id") if isinstance(r, dict) else r
            if rid:
                rules[rid] = (r.get("level") if isinstance(r, dict) else None)
        out[step] = {"rules": rules,
                     "gap": bool((entry.get("gap") or {}).get("no_rule_exists")),
                     "fields": list((ev.get(step) or {}).get("fields") or [])}
    return out


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------
def _finding(scenario, kind, step, item, detail) -> dict:
    return {"scenario": scenario, "kind": kind, "step": step, "item": item, "detail": detail,
            "level": "WARN" if kind in _WARN_KINDS else "FAIL", "waived": None}


def lint_rules(rules: dict) -> list:
    """F10: a rule's logsource.category must be compatible with every class_uid its selectors name."""
    out = []
    for rid in sorted(rules):
        rule = rules[rid]
        classes = {sel.get("class_uid") for sel in rule.selections.values()
                   if isinstance(sel, dict) and isinstance(sel.get("class_uid"), int)}
        allowed = _CATEGORY_CLASSES.get(rule.category)
        if allowed is None:
            out.append(_finding("*", "F10", "-", rid,
                                f"{rule.source}: logsource.category {rule.category!r} is not in the static OCSF map"))
        elif classes - allowed:
            out.append(_finding("*", "F10", "-", rid,
                                f"{rule.source}: class_uid {sorted(classes - allowed)} is not valid for "
                                f"category {rule.category!r} (allowed {sorted(allowed)})"))
    return out


def diff(derived: dict, oracle: dict, rules: dict, *, scenario: str | None = None) -> list:
    """All raw findings (F1-F14 except the global F10) for one storyline, before waivers."""
    scenario = scenario or derived["scenario"]
    hand = hand_view(oracle)
    seq = list(oracle.get("expected_sequence") or [])
    steps = derived["steps"]
    out: list = []
    for step in seq:
        h = hand[step]
        d = steps.get(step) or {"fires": {}, "suppressed_companions": {}, "undecided": [], "entities": [],
                                "first_ms": None, "last_ms": None}
        fires, supp, undec = set(d["fires"]), set(d["suppressed_companions"]), set(d["undecided"])
        for rid in sorted(h["rules"]):
            if rid in fires or rid in supp:
                continue
            if rid in undec:
                out.append(_finding(scenario, "F2", step, rid,
                                    f"{rid}: the static model cannot decide whether it fires here"))
            else:
                out.append(_finding(scenario, "F1", step, rid,
                                    f"hand oracle expects {rid} but the rule files cannot fire it at this step"))
        if not h["gap"]:
            for rid in sorted(fires - set(h["rules"])):
                out.append(_finding(scenario, "F3", step, rid,
                                    f"{rid} fires here per the rule files but the oracle does not declare it"))
        if h["gap"] and (fires or supp):
            out.append(_finding(scenario, "F4", step, ",".join(sorted(fires | supp)),
                                "oracle declares no_rule_exists but rules match this step's events"))
        if h["gap"] == bool(h["rules"]):
            out.append(_finding(scenario, "F5", step, "gap",
                                f"gap={h['gap']} with {len(h['rules'])} expected rule(s): exactly one of "
                                "(a gap, expected rules) must hold"))
        for rid in sorted(h["rules"]):
            meta = rules.get(rid)
            if meta is not None and not meta.tactic:
                out.append(_finding(scenario, "F6", step, rid,
                                    f"{rid} has no mitre.tactic; tactic-coverage falls back to rule identity"))
            if meta is not None and h["rules"][rid] is not None and h["rules"][rid] != meta.level:
                out.append(_finding(scenario, "F13", step, rid,
                                    f"hand level {h['rules'][rid]!r} != rule YAML level {meta.level!r}"))
            if meta is not None and meta.stateful:
                need = [meta.group_by] + ([meta.distinct_field] if meta.distinct_field else [])
                missing = [f for f in need if f not in h["fields"]]
                if missing:
                    out.append(_finding(scenario, "F12", step, rid,
                                        f"evidence.per_step.{step}.fields omits {missing}, the group/distinct "
                                        f"key of expected stateful rule {rid}"))
    # ---- ordering (F9)
    timed = [(s, steps[s]["first_ms"], steps[s]["last_ms"]) for s in seq
             if s in steps and steps[s]["first_ms"] is not None]
    for (a, fa, la), (b, fb, _lb) in zip(timed, timed[1:]):
        if fb < fa:
            out.append(_finding(scenario, "F9", b, f"{a}>{b}",
                                f"expected_sequence has {a} before {b} but {b} starts earlier in event time"))
    # ---- relationships (F7, F8)
    idx = {s: i for i, s in enumerate(seq)}

    def earlier_side(step):
        side: set = set()
        for s in seq[: idx[step] + 1]:
            side |= set((steps.get(s) or {}).get("entities") or [])
        return side

    for rel in oracle.get("allowed_relationships") or []:
        f, t = rel.get("from"), rel.get("to")
        if f not in idx or t not in idx:
            continue
        key = f"{f}->{t}"
        ff, ft = (steps.get(f) or {}).get("first_ms"), (steps.get(t) or {}).get("first_ms")
        if rel.get("allowed"):
            if ff is not None and ft is not None and ft < ff:
                out.append(_finding(scenario, "F8", f, key, f"allowed edge {key} points backwards in event time"))
            to_ents = set((steps.get(t) or {}).get("entities") or [])
            from_ents = set((steps.get(f) or {}).get("entities") or [])
            if from_ents and to_ents and not (earlier_side(f) & to_ents):
                out.append(_finding(scenario, "F7", f, key,
                                    f"allowed edge {key} has no shared observable between {f} (or any "
                                    f"earlier step) and {t}"))
        else:
            if ff is not None and ft is not None and ff < ft:
                out.append(_finding(scenario, "F8", f, key,
                                    f"forbidden edge {key} is chronologically forward (the earlier step is "
                                    "the source): the oracle forbids a lawful direction"))
    # ---- membership under the track model (F14)
    want = (oracle.get("incident_membership") or {}).get("incident_count")
    if isinstance(want, int) and want >= 1:
        alerting = [s for s in seq if (steps.get(s) or {}).get("fires")]
        if alerting:
            common = None
            for s in alerting:
                ents = set(steps[s]["entities"])
                common = ents if common is None else (common & ents)
            if not common:
                out.append(_finding(scenario, "F14", "-", "incident_count",
                                    f"no single entity appears at every alert-raising step {alerting}; with "
                                    f"per-entity tracks that never merge, incident_count={want} (one incident "
                                    "carrying the whole chain) is unattainable"))
    return out


def apply_waivers(findings: list, scenario: str, waived: dict | None = None,
                  f2_cap: dict | None = None) -> dict:
    """Attach dated waivers; report stale ones and the F2 cap. ``unwaived`` is what fails the gate."""
    waived = _WAIVED if waived is None else waived
    f2_cap = _F2_CAP if f2_cap is None else f2_cap
    seen = set()
    bad_reasons = []
    for f in findings:
        k = (f["scenario"], f["kind"], f["step"], f["item"])
        if k in waived:
            f["waived"] = waived[k]
            seen.add(k)
    for k, reason in waived.items():
        if not _REASON_RE.match(reason or ""):
            bad_reasons.append(k)
    mine = {k for k in waived if k[0] == scenario}
    stale = sorted(mine - seen)
    f2 = [f for f in findings if f["kind"] == "F2" and f["scenario"] == scenario]
    f2_over = len([f for f in f2 if not f["waived"]]) > f2_cap.get(scenario, 0)
    unwaived = [f for f in findings if f["waived"] is None and
                (f["level"] == "FAIL" or (f["kind"] == "F2" and f2_over))]
    return {"unwaived": unwaived, "stale_waivers": stale, "bad_reasons": bad_reasons,
            "f2_count": len(f2), "f2_over_cap": f2_over}


def run_checks(sdef, seed: int = 7, *, rules: dict | None = None, oracle: dict | None = None,
               waived: dict | None = None, f2_cap: dict | None = None, derived: dict | None = None,
               include_global: bool = False) -> dict:
    rules = rules if rules is not None else load_rules()
    oracle = oracle if oracle is not None else yaml.safe_load(Path(sdef.oracle_path).read_text(encoding="utf-8"))
    derived = derived if derived is not None else derive(sdef, seed, rules=rules)
    findings = diff(derived, oracle, rules, scenario=sdef.name)
    if include_global:
        findings = lint_rules(rules) + findings
    verdict = apply_waivers(findings, sdef.name, waived, f2_cap)
    return {"scenario": sdef.name, "seed": seed, "derived": derived, "findings": findings, **verdict,
            "ok": not verdict["unwaived"] and not verdict["stale_waivers"] and not verdict["bad_reasons"]}


# ---------------------------------------------------------------------------
# independence lint
# ---------------------------------------------------------------------------
def independence_violations(source: str | None = None, path: Path | None = None) -> list:
    """Names this module (or a given source text) imports that it must not."""
    if source is None:
        source = Path(path or __file__).read_text(encoding="utf-8")
    bad = []
    for node in ast.walk(ast.parse(source)):
        mods = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            mods = [node.module or ""] + [(node.module or "") + "." + a.name for a in node.names]
        elif (isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant)
              and isinstance(node.args[0].value, str)):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name in ("import_module", "__import__"):
                mods = [node.args[0].value]
        for m in mods:
            if set(m.split(".")) & set(FORBIDDEN_IMPORTS):
                bad.append(m)
    return sorted(set(bad))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _short(rid: str, rules_meta: dict) -> str:
    return rid[:8]


def _print_table(res: dict, oracle: dict) -> None:
    hand = hand_view(oracle)
    d = res["derived"]
    print(f"  {'step':<22}{'hand (expects)':<24}{'derived (fires)':<24}{'suppressed':<14}"
          f"{'undecided':<11}gap h/d")
    for step in oracle.get("expected_sequence") or []:
        ds = d["steps"].get(step) or {}
        print(f"  {step:<22}{','.join(sorted(r[:8] for r in hand[step]['rules'])) or '-':<24}"
              f"{','.join(sorted(r[:8] for r in ds.get('fires', {}))) or '-':<24}"
              f"{','.join(sorted(r[:8] for r in ds.get('suppressed_companions', {}))) or '-':<14}"
              f"{','.join(sorted(r[:8] for r in ds.get('undecided', []))) or '-':<11}"
              f"{'Y' if hand[step]['gap'] else 'n'}/{'Y' if ds.get('gap') else 'n'}")


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(prog="oracle_derive")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--scenario", action="append", default=None)
    ap.add_argument("--out", type=Path, default=None, help="write the derivation as JSON")
    args = ap.parse_args(argv)
    sdefs = [reg.get(n) for n in args.scenario] if args.scenario else list(reg.ALL)
    rules = load_rules()
    rc = 0
    dump: dict = {}
    print(f"== derived oracle vs hand oracle (seed={args.seed}) ==")
    glob_f = apply_waivers(lint_rules(rules), "*")
    for f in glob_f["unwaived"]:
        print(f"  [FAIL] {f['kind']} {f['item']}: {f['detail']}")
        rc = 1
    for k in glob_f["stale_waivers"]:
        if k[0] == "*":
            print(f"  [STALE WAIVER] {list(k)} no longer reproduces -- delete it")
            rc = 1
    for sdef in sdefs:
        oracle = yaml.safe_load(Path(sdef.oracle_path).read_text(encoding="utf-8"))
        res = run_checks(sdef, args.seed, rules=rules, oracle=oracle)
        dump[sdef.name] = {"derived": {**res["derived"], "rules": "(see rule files)"},
                           "findings": res["findings"]}
        print(f"-- {sdef.name} --")
        _print_table(res, oracle)
        for f in res["findings"]:
            tag = f"WAIVED {f['waived'][:10]}" if f["waived"] else f["level"]
            print(f"  [{tag}] {f['kind']} {f['step']} {f['item']}: {f['detail']}")
        for k in res["stale_waivers"]:
            if k[0] != "*":
                print(f"  [STALE WAIVER] {list(k)} no longer reproduces -- delete it")
        for k in res["bad_reasons"]:
            print(f"  [BAD WAIVER] {list(k)}: a waiver needs 'YYYY-MM-DD <reason>'")
        if res["ok"]:
            print(f"  [OK] no unwaived finding ({sum(1 for f in res['findings'] if f['waived'])} waived, "
                  f"{res['f2_count']} undecided)")
        else:
            print(f"  [FAIL] {len(res['unwaived'])} unwaived finding(s), {len(res['stale_waivers'])} stale waiver(s)")
            rc = 1
    print("  NOTE: observed (pipeline) column: python eval/twin/oracle_consistency.py --triangulate")
    print(f"  {LIMITS}")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(dump, indent=2, sort_keys=True, default=list), encoding="utf-8")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
