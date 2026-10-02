"""oracle_mutate -- mutation testing of the three hand-written grading oracles.

WHY THIS EXISTS (2026-10-02)
    Every twin / adversarial number is scored against an oracle the project wrote itself
    (``oracle.yaml``, ``oracle_it_intrusion.yaml``, ``oracle_infra_takeover.yaml``). Nobody had ever
    asked the obvious question of an answer key: *if it were wrong, would anything notice?* This
    module answers it empirically. It applies a catalogue of small in-memory edits to COPIES of each
    oracle and grades every edited oracle against the same observed pipeline run:

      WRONG   mutants state something false by construction (a rule that cannot fire at the step, a
              swapped step order, a reversed or flipped relationship, a bogus evidence field, a wrong
              incident count, a tightened severity band, a "no rule exists" claim where one fires...).
              A sound grader must score the wrong oracle WORSE than the true one.
      WEAKER  mutants state less (drop a rule, a step, a relationship; "gap" -> "has rules"). They
              cannot lower recall, so the requirement is only that the change is NOTICED.

    No oracle file is ever written. ``eval/twin/oracle_strength.json`` is the committed ratchet and is
    written ONLY by ``--update-baseline``, never by the gate.

WHAT COUNTS AS A KILL (the honest part)
    A mutant is killed through a CHANNEL. HEADLINE channels are the graded metrics themselves (TPR,
    tactic coverage, evidence completeness, chain fidelity / false-correlation / direction, incident
    membership, alert order, decoy and campaign metrics). COUPLED channels (severity confusion,
    oracle_consistency findings) only measure how tightly the oracle is welded to the CURRENT pipeline
    output: a decoy rule that cannot fire is *always* "decorative" to the reconciler, and dropping a
    rule that does fire is *always* "unexpected" -- true by construction, not evidence that the oracle
    is right. Those kills are reported as ``KILLED_COUPLED`` ("pipeline coupling"), kept apart from
    ``KILLED_HEADLINE`` ("strength"), and only headline kills enter the headline mutation score.

OUTCOMES
    KILLED_HEADLINE  a headline component got strictly worse (WRONG) / changed (WEAKER).
    KILLED_COUPLED   only severity / reconcile moved (pipeline coupling, not strength).
    SURVIVED         nothing moved: the grader cannot tell this oracle from the true one.
    IMPROVED         the wrong oracle scored strictly BETTER than the true one (hard fail unless waived).
    SATURATED        the targeted component is already at its worst in the base grade (reported, not counted).
    CRASH            the grader raised on the edited oracle (a finding).
    Survivors and IMPROVED mutants must sit in ``_EQUIVALENT`` with a dated reason and a cap; a waiver that
    no longer reproduces fails as stale. The unread-oracle-key report (``_INERT_KEYS``) is the same idea
    for keys no grader reads.

WHAT THIS CANNOT PROVE
    It measures how well the GRADER notices a wrong oracle. It cannot say the true oracle is right, and
    because the pipeline is the reference for "observed", a mutant that agrees with the pipeline but is
    semantically wrong (two rules that both fire at the step, swapped) survives by construction.

Stdlib + PyYAML. Deterministic: sorted mutant ids, no wall-clock in the output or the ratchet file.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
for _p in (str(TWIN), str(SERVICES), str(ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import report  # noqa: E402  (must come first: it pins ws4's `main` module before anything imports one)
import oracle_consistency  # noqa: E402
import oracle_derive  # noqa: E402
import scenario_registry as reg  # noqa: E402

STRENGTH_PATH = TWIN / "oracle_strength.json"

_LEVELS = ["informational", "low", "medium", "high", "critical"]

# ---------------------------------------------------------------------------
# the verdict vector: every oracle-dependent output of the grader, with a direction and a channel
# ---------------------------------------------------------------------------
# direction: "up" higher is better, "down" lower is better, "neutral" a scope / size (any change is a change)
COMPONENTS: dict = {
    "tpr": ("up", "tpr"), "tpr_numerator": ("up", "tpr"), "tpr_denominator": ("neutral", "tpr"),
    "sequence_present": ("up", "tpr"), "mttd_seconds": ("neutral", "tpr"),
    "tactic_covered_steps": ("up", "tactic"), "tactic_covered_list": ("neutral", "tactic"),
    "evidence_completeness": ("up", "evidence"),
    "chain_fidelity": ("up", "fidelity"), "fidelity_numerator": ("up", "fidelity"),
    "fidelity_denominator": ("neutral", "fidelity"), "forbidden_joins": ("down", "fidelity"),
    "forbidden_denominator": ("neutral", "fidelity"), "false_correlation_rate": ("down", "fidelity"),
    "directional_discrimination": ("up", "fidelity"),
    "incident_membership_ok": ("up", "membership"), "incident_count": ("neutral", "membership"),
    "cross_step_rule_co_location": ("neutral", "membership"),
    "alert_order_ok": ("up", "order"),
    "chain_alert_count": ("neutral", "decoy"), "decoy_alert_count": ("neutral", "decoy"),
    "decoy_contamination": ("down", "decoy"), "investigation_steps": ("neutral", "decoy"),
    "campaign_count": ("neutral", "campaign"), "campaign_full_coverage": ("up", "campaign"),
    "campaign_decoy_contamination": ("down", "campaign"),
    "sev_correct": ("up", "severity"), "sev_over_alerting": ("down", "severity"),
    "sev_under_alerting": ("down", "severity"), "sev_unexpected": ("down", "severity"),
    "sev_unrecognized_level": ("down", "severity"), "in_band": ("up", "severity"),
}
HEADLINE_CHANNELS = {"tpr", "tactic", "evidence", "fidelity", "membership", "order", "decoy", "campaign"}
COUPLED_CHANNELS = {"severity", "reconcile"}

OUTCOMES = ("KILLED_HEADLINE", "KILLED_COUPLED", "SURVIVED", "IMPROVED", "SATURATED", "CRASH")
# ratchet rank: lower is a worse oracle-strength outcome
_RANK = {"KILLED_HEADLINE": 3, "KILLED_COUPLED": 2, "SATURATED": 1, "SURVIVED": 1, "IMPROVED": 0, "CRASH": 0}

# ---------------------------------------------------------------------------
# observation cache (the chain's detection and WS-8 passes do not depend on the oracle)
# ---------------------------------------------------------------------------
CACHE_STATS = {"hits": 0, "misses": 0}


@contextlib.contextmanager
def memoize_observation():
    """Cache ``report._real_detection`` and ``report._build_chain_alerts`` for the duration.

    Both are pure functions of the chain's events and neither reads the oracle, yet they dominate a
    ``_grade_chain`` call; every mutant grades the SAME observed run, so replaying hundreds of
    mutants would otherwise repeat identical detection work. The key is the sha256 of the arguments'
    repr (a changed raw payload is a different key -> a miss); hits return a deep copy so a caller
    can never poison the cache. No report.py edit is needed -- ``_grade_chain`` and ``_grade_ws8``
    resolve both names through module globals at call time."""
    real_detect, real_build = report._real_detection, report._build_chain_alerts
    cache: dict = {}

    def keyed(tag, real):
        def wrapper(arg):
            k = hashlib.sha256(repr((tag, arg)).encode("utf-8")).hexdigest()
            if k in cache:
                CACHE_STATS["hits"] += 1
            else:
                CACHE_STATS["misses"] += 1
                cache[k] = real(arg)
            return copy.deepcopy(cache[k])
        return wrapper

    report._real_detection = keyed("detect", real_detect)
    report._build_chain_alerts = keyed("alerts", real_build)
    try:
        yield cache
    finally:
        report._real_detection, report._build_chain_alerts = real_detect, real_build


def default_grader(result, oracle: dict) -> dict:
    return report._grade_chain(result, oracle)


# ---------------------------------------------------------------------------
# verdict vector
# ---------------------------------------------------------------------------
def verdict(grade: dict, oracle: dict, sdef, seed: int) -> dict:
    """The oracle-dependent outputs of one graded run as a flat, JSON-able dict (plus ``rec_keys``).
    ``incident_reconstruction`` is excluded entirely (wall-clock fields; ``verified`` flaps)."""
    sc = grade.get("severity_confusion") or {}
    band = report._severity_band_check(oracle, grade.get("fired") or [])
    rec = oracle_consistency.reconcile(seed, sdef, oracle=oracle, grade=grade)
    inv = grade.get("investigation") or {}
    v = {
        "tpr": grade.get("tpr"), "tpr_numerator": grade.get("tpr_numerator"),
        "tpr_denominator": grade.get("tpr_denominator"),
        "sequence_present": grade.get("sequence_present"), "mttd_seconds": grade.get("mttd_seconds"),
        "tactic_covered_steps": len(grade.get("tactic_covered_steps") or []),
        "tactic_covered_list": list(grade.get("tactic_covered_steps") or []),
        "evidence_completeness": grade.get("evidence_completeness"),
        "chain_fidelity": grade.get("chain_fidelity"), "fidelity_numerator": grade.get("fidelity_numerator"),
        "fidelity_denominator": grade.get("fidelity_denominator"),
        "forbidden_joins": grade.get("forbidden_joins"),
        "forbidden_denominator": grade.get("forbidden_denominator"),
        "false_correlation_rate": grade.get("false_correlation_rate"),
        "directional_discrimination": grade.get("directional_discrimination"),
        "incident_membership_ok": grade.get("incident_membership_ok"),
        "incident_count": grade.get("incident_count"),
        "cross_step_rule_co_location": json.loads(json.dumps(grade.get("cross_step_rule_co_location") or {},
                                                             sort_keys=True)),
        "alert_order_ok": grade.get("alert_order_ok"),
        "chain_alert_count": grade.get("chain_alert_count"),
        "decoy_alert_count": grade.get("decoy_alert_count"),
        "decoy_contamination": grade.get("decoy_contamination"),
        "investigation_steps": inv.get("investigation_steps"),
        "campaign_count": grade.get("campaign_count"),
        "campaign_full_coverage": grade.get("campaign_full_coverage"),
        "campaign_decoy_contamination": grade.get("campaign_decoy_contamination"),
        "sev_correct": sc.get("correct"), "sev_over_alerting": sc.get("over_alerting"),
        "sev_under_alerting": sc.get("under_alerting"), "sev_unexpected": sc.get("unexpected"),
        "sev_unrecognized_level": sc.get("unrecognized_level"),
        "in_band": band.get("in_band"),
        "rec_keys": sorted(rec["finding_keys"]),
    }
    return v


def fingerprint(v: dict) -> str:
    return hashlib.sha256(json.dumps(v, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _num(x):
    if x is None:
        return -1e9
    if isinstance(x, bool):
        return int(x)
    if isinstance(x, (int, float)):
        return x
    return 0


def compare(base: dict, mut: dict) -> dict:
    """Component-wise comparison of two verdict vectors."""
    worse, better, changed = [], [], []
    for name, (direction, channel) in COMPONENTS.items():
        a, b = base.get(name), mut.get(name)
        if a == b:
            continue
        changed.append((name, channel))
        if direction == "neutral":
            continue
        if direction == "up":
            (worse if _num(b) < _num(a) else better).append((name, channel))
        else:
            (worse if _num(b) > _num(a) else better).append((name, channel))
    new_rec = sorted(set(mut["rec_keys"]) - set(base["rec_keys"]))
    gone_rec = sorted(set(base["rec_keys"]) - set(mut["rec_keys"]))
    for k in new_rec:
        worse.append((f"rec:{k}", "reconcile"))
        changed.append((f"rec:{k}", "reconcile"))
    for k in gone_rec:
        better.append((f"rec:{k}", "reconcile"))
        changed.append((f"rec:{k}", "reconcile"))
    return {"worse": worse, "better": better, "changed": changed}


def classify(kind: str, base: dict, mut: dict, saturated_if: tuple = ()) -> tuple:
    """-> (outcome, detail dict). ``kind`` is WRONG, WEAKER or NEUTRAL (identity)."""
    cmp_ = compare(base, mut)
    worse_h = [c for c, ch in cmp_["worse"] if ch in HEADLINE_CHANNELS]
    better_h = [c for c, ch in cmp_["better"] if ch in HEADLINE_CHANNELS]
    worse_c = [c for c, ch in cmp_["worse"] if ch in COUPLED_CHANNELS]
    better_c = [c for c, ch in cmp_["better"] if ch in COUPLED_CHANNELS]
    changed_h = [c for c, ch in cmp_["changed"] if ch in HEADLINE_CHANNELS]
    changed_c = [c for c, ch in cmp_["changed"] if ch in COUPLED_CHANNELS]
    detail = {"worse_headline": sorted(worse_h), "better_headline": sorted(better_h),
              "worse_coupled": sorted(worse_c), "better_coupled": sorted(better_c),
              "changed_headline": sorted(changed_h), "changed_coupled": sorted(changed_c)}
    if kind == "NEUTRAL":
        return ("SURVIVED" if not cmp_["changed"] else "KILLED_HEADLINE"), detail
    if kind == "WEAKER":
        if changed_h:
            return "KILLED_HEADLINE", detail
        if changed_c:
            return "KILLED_COUPLED", detail
        return "SURVIVED", detail
    # WRONG
    if worse_h:
        return "KILLED_HEADLINE", detail
    if better_h:
        return "IMPROVED", detail
    if worse_c:
        return "KILLED_COUPLED", detail
    if better_c:
        return "IMPROVED", detail
    if saturated_if and all(base.get(c) == worst for c, worst in saturated_if):
        return "SATURATED", detail
    return "SURVIVED", detail


# ---------------------------------------------------------------------------
# mutants
# ---------------------------------------------------------------------------
class Mutant:
    def __init__(self, mid, operator, kind, fn, selector="", saturated_if=()):
        self.id, self.operator, self.kind, self.fn = mid, operator, kind, fn
        self.selector, self.saturated_if = selector, tuple(saturated_if)


def _rules_of(o, step):
    return ((o.get("detection_points") or {}).get(step) or {}).get("expected_rules") or []


def catalogue(oracle: dict, derived: dict, base_grade: dict) -> list:
    """Every mutant for one storyline, in a deterministic order. ``derived`` supplies guaranteed-wrong
    decoy rules; ``base_grade`` supplies the observed peak score for the severity-band mutant."""
    seq = list(oracle.get("expected_sequence") or [])
    dp = oracle.get("detection_points") or {}
    rels = list(oracle.get("allowed_relationships") or [])
    meta = derived["rules"]
    out: list = [Mutant("identity", "identity", "NEUTRAL", lambda m: None)]

    def decoy_entry(rid):
        info = meta[rid]
        return {"rule_id": rid, "title": info["title"], "level": info["level"], "role": "mutation decoy"}

    # ---- WRONG: swap an expected rule for one that cannot fire at the step
    for step in seq:
        for i, r in enumerate(_rules_of(oracle, step)):
            rid = r.get("rule_id") if isinstance(r, dict) else None
            decoy = oracle_derive.pick_decoy(derived, step, rid) if rid else None
            if not decoy:
                continue
            out.append(Mutant(f"swap_expected_rule:{step}:{rid[:8]}->{decoy[:8]}", "swap_expected_rule", "WRONG",
                              (lambda m, s=step, i=i, d=decoy: m["detection_points"][s]["expected_rules"][i]
                               .update({"rule_id": d})), selector=step))
    # ---- WRONG: add a second, never-firing expected rule (TPR cannot see it)
    for step in seq:
        first = next((r.get("rule_id") for r in _rules_of(oracle, step) if isinstance(r, dict)), None)
        decoy = oracle_derive.pick_decoy(derived, step, first or "")
        if not decoy:
            continue
        out.append(Mutant(f"add_expected_rule:{step}:{decoy[:8]}", "add_expected_rule", "WRONG",
                          (lambda m, s=step, d=decoy: m["detection_points"][s].setdefault("expected_rules", [])
                           .append(decoy_entry(d))), selector=step))
    # ---- WRONG: swap two adjacent steps of the expected sequence
    for i in range(len(seq) - 1):
        out.append(Mutant(f"swap_adjacent_steps:{seq[i]}<>{seq[i + 1]}", "swap_adjacent_steps", "WRONG",
                          (lambda m, i=i: m["expected_sequence"].__setitem__(
                              slice(i, i + 2), [m["expected_sequence"][i + 1], m["expected_sequence"][i]])),
                          selector=seq[i]))
    # ---- WRONG: reverse / flip a relationship
    for j, rel in enumerate(rels):
        tag = f"{rel.get('from')}->{rel.get('to')}[{'allowed' if rel.get('allowed') else 'forbidden'}]"
        out.append(Mutant(f"reverse_relationship:{tag}", "reverse_relationship", "WRONG",
                          (lambda m, j=j: m["allowed_relationships"][j].update(
                              {"from": m["allowed_relationships"][j]["to"],
                               "to": m["allowed_relationships"][j]["from"]})), selector=tag))
        out.append(Mutant(f"flip_relationship:{tag}", "flip_relationship", "WRONG",
                          (lambda m, j=j: m["allowed_relationships"][j].update(
                              {"allowed": not m["allowed_relationships"][j].get("allowed")})), selector=tag))
    # ---- WRONG: shift an expected rule's declared level by one rank
    for step in seq:
        for i, r in enumerate(_rules_of(oracle, step)):
            lvl = r.get("level") if isinstance(r, dict) else None
            if lvl not in _LEVELS:
                continue
            for delta in (+1, -1):
                k = _LEVELS.index(lvl) + delta
                if 0 <= k < len(_LEVELS):
                    out.append(Mutant(f"shift_level:{step}:{r['rule_id'][:8]}:{delta:+d}", "shift_level", "WRONG",
                                      (lambda m, s=step, i=i, lv=_LEVELS[k]: m["detection_points"][s]
                                       ["expected_rules"][i].update({"level": lv})), selector=step))
    # ---- WRONG: claim an evidence field no event carries
    for step in sorted((oracle.get("evidence") or {}).get("per_step") or {}):
        out.append(Mutant(f"add_missing_evidence_field:{step}", "add_missing_evidence_field", "WRONG",
                          (lambda m, s=step: m["evidence"]["per_step"][s].setdefault("fields", [])
                           .append("unmapped.mutation.absent_field")), selector=step))
    # ---- WRONG: change the incident count
    im = oracle.get("incident_membership") or {}
    if isinstance(im.get("incident_count"), int):
        base_n = im["incident_count"]
        out.append(Mutant(f"change_incident_count:{base_n}->{base_n + 1}", "change_incident_count", "WRONG",
                          (lambda m, n=base_n + 1: m["incident_membership"].__setitem__("incident_count", n)),
                          saturated_if=(("incident_membership_ok", False),)))
        if base_n >= 1:
            out.append(Mutant(f"change_incident_count:{base_n}->{base_n - 1}", "change_incident_count", "WRONG",
                              (lambda m, n=base_n - 1: m["incident_membership"].__setitem__("incident_count", n))))
    # ---- WRONG: a severity band the real alerts fall outside
    peaks = [a.get("score_weight") for a in base_grade.get("fired") or [] if a.get("score_weight") is not None]
    if peaks and (oracle.get("severity_band") or {}).get("score"):
        out.append(Mutant("tighten_severity_band:min>peak", "tighten_severity_band", "WRONG",
                          (lambda m, p=max(peaks) + 1: m["severity_band"]["score"].__setitem__("min", p))))
    # ---- WRONG: declare "no rule exists" where one fires
    for step in seq:
        gap = (dp.get(step) or {}).get("gap") or {}
        if not gap.get("no_rule_exists") and _rules_of(oracle, step):
            out.append(Mutant(f"flip_gap_to_true:{step}", "flip_gap_to_true", "WRONG",
                              (lambda m, s=step: m["detection_points"][s].setdefault("gap", {})
                               .__setitem__("no_rule_exists", True)), selector=step))
    # ---- WEAKER
    for step in seq:
        gap = (dp.get(step) or {}).get("gap") or {}
        if gap.get("no_rule_exists"):
            out.append(Mutant(f"flip_gap_to_false:{step}", "flip_gap_to_false", "WEAKER",
                              (lambda m, s=step: m["detection_points"][s]["gap"].__setitem__("no_rule_exists", False)),
                              selector=step))
        for i, r in enumerate(_rules_of(oracle, step)):
            rid = r.get("rule_id") if isinstance(r, dict) else None
            if rid:
                out.append(Mutant(f"drop_expected_rule:{step}:{rid[:8]}", "drop_expected_rule", "WEAKER",
                                  (lambda m, s=step, rid=rid: m["detection_points"][s].__setitem__(
                                      "expected_rules", [x for x in m["detection_points"][s]["expected_rules"]
                                                         if x.get("rule_id") != rid])), selector=step))
    for step in seq:
        out.append(Mutant(f"drop_step:{step}", "drop_step", "WEAKER", (lambda m, s=step: _drop_step(m, s)),
                          selector=step))
    for j, rel in enumerate(rels):
        tag = f"{rel.get('from')}->{rel.get('to')}[{'allowed' if rel.get('allowed') else 'forbidden'}]"
        out.append(Mutant(f"delete_relationship:{tag}", "delete_relationship", "WEAKER",
                          (lambda m, j=j: m["allowed_relationships"].pop(j)), selector=tag))
    ids = [m.id for m in out]
    assert len(ids) == len(set(ids)), "mutant ids must be unique"
    return out


def _drop_step(m: dict, step: str) -> None:
    m["expected_sequence"] = [s for s in m["expected_sequence"] if s != step]
    (m.get("detection_points") or {}).pop(step, None)
    ((m.get("evidence") or {}).get("per_step") or {}).pop(step, None)
    inc = m.get("incident_membership") or {}
    if isinstance(inc.get("include"), list):
        inc["include"] = [s for s in inc["include"] if s != step]
    m["allowed_relationships"] = [r for r in (m.get("allowed_relationships") or [])
                                  if step not in (r.get("from"), r.get("to"))]


def predict_reversal(base_grade: dict, frm: str, to: str) -> str:
    """Predict, from the base ``per_allowed_pair`` table alone, what reversing the allowed relationship
    ``frm -> to`` does to the fidelity numerator: IMPROVED / KILLED / UNCHANGED. (The reversed edge is
    graded as ``to -> frm``; its forward join is the original pair's ``reverse_joined``.)"""
    for p in base_grade.get("per_allowed_pair") or []:
        if p.get("from") == frm and p.get("to") == to and p.get("graded"):
            d = int(bool(p.get("reverse_joined"))) - int(bool(p.get("joined")))
            return "IMPROVED" if d > 0 else ("KILLED" if d < 0 else "UNCHANGED")
    return "UNGRADED"


# ---------------------------------------------------------------------------
# running a storyline
# ---------------------------------------------------------------------------
def run_scenario(sdef, seed: int = 7, *, grader=None, mutants_filter=None) -> dict:
    """Grade every mutant of ``sdef``'s oracle against ONE observed run. Returns a JSON-able dict."""
    grader = grader or default_grader
    oracle = oracle_derive.yaml.safe_load(Path(sdef.oracle_path).read_text(encoding="utf-8"))
    result = reg.run(sdef, seed)
    base_grade = grader(result, copy.deepcopy(oracle))
    base_v = verdict(base_grade, oracle, sdef, seed)
    derived = oracle_derive.derive(sdef, seed, result=result)
    muts = catalogue(oracle, derived, base_grade)
    if mutants_filter is not None:
        muts = [m for m in muts if mutants_filter(m)]
    rows = []
    for mu in muts:
        mo = copy.deepcopy(oracle)
        try:
            mu.fn(mo)
            g = grader(result, mo)
            v = verdict(g, mo, sdef, seed)
            outcome, detail = classify(mu.kind, base_v, v, mu.saturated_if)
            row = {"id": mu.id, "operator": mu.operator, "kind": mu.kind, "outcome": outcome,
                   "fingerprint": fingerprint(v), **detail}
        except Exception as exc:  # noqa: BLE001 - a crashing grader on an edited oracle is a finding
            row = {"id": mu.id, "operator": mu.operator, "kind": mu.kind, "outcome": "CRASH",
                   "error": f"{type(exc).__name__}: {exc}"[:200]}
        rows.append(row)
    return {"scenario": sdef.name, "seed": seed, "base_fingerprint": fingerprint(base_v), "base": base_v,
            "base_grade": {k: base_grade.get(k) for k in ("per_allowed_pair", "per_forbidden_pair")},
            "rows": rows}


# ---------------------------------------------------------------------------
# waivers
# ---------------------------------------------------------------------------
_DATED = re.compile(r"^\d{4}-\d{2}-\d{2} \S.{12,}")

# (scenario, operator, outcome) -> {"max": cap, "reason": "YYYY-MM-DD ..."}.  CLOSED: an outcome class that is
# not here fails; a class that exceeds its cap fails (growth); a class with no member fails (stale). Every
# entry below is a MEASURED survivor (seeds 7 and 11 agree), not a prediction. None of them says the oracle is
# right: each says the GRADER cannot tell this wrong oracle from the true one, and why.
_NO_EVENT = ("the edge starts at external_content, a step with no parsed event (pre-log by design: the declared "
             "gap), so the grader excludes it from every denominator (step-not-entity-bearing)")
_ORDER_BLIND_M = ("directional_discrimination=0.0 (SSOT 2026-10-01): the pair is graded and joined, and the "
                  "reverse direction is joined too (reverse_joined=True), so the legacy join predicate cannot tell a "
                  "relation from its reverse; the WS-8 tracks never merge and share entities at both ends")
_COMPANION = ("the rule is a suppressed companion (siem.companion_of): WS-4 drops it whenever its sibling matched the "
              "same event, so it never raises an alert here; TPR's any-intersection rule, the reconciler's "
              "companion exemption and the severity matrix (one row per fired alert) all ignore it")
_NO_ALERT_STEP = ("one of the two swapped steps raises no alert (and the entities are shared across the chain), so "
                  "neither alert order nor the entity-bridge fidelity predicate has anything to disagree about")
_EQUIVALENT: dict = {
    ("ai_to_ot", "delete_relationship", "SURVIVED"): {"max": 2, "reason": "2026-10-02 " + _NO_EVENT},
    ("ai_to_ot", "drop_step", "SURVIVED"): {"max": 1, "reason": (
        "2026-10-02 external_content raises no alert and carries no entity (pre-log by design), so dropping it "
        "from the sequence changes no graded output")},
    ("ai_to_ot", "flip_gap_to_false", "SURVIVED"): {"max": 2, "reason": (
        "2026-10-02 the steps (external_content, plc_state_change) declare no expected rule and no rule fires "
        "there, so nothing reads the gap flag; only a firing rule makes it observable")},
    ("ai_to_ot", "flip_relationship", "SURVIVED"): {"max": 2, "reason": "2026-10-02 " + _NO_EVENT},
    ("ai_to_ot", "flip_relationship", "IMPROVED"): {"max": 2, "reason": (
        "2026-10-02 forbidden->allowed flip on a pair the graph joins in both directions: the wrong oracle "
        "scores BETTER (the false-correlation count falls) because " + _ORDER_BLIND_M)},
    ("ai_to_ot", "reverse_relationship", "SURVIVED"): {"max": 7, "reason": (
        "2026-10-02 two reversals start at external_content (" + _NO_EVENT + "); the other five are graded and "
        "unobservable because " + _ORDER_BLIND_M)},
    ("ai_to_ot", "swap_adjacent_steps", "SURVIVED"): {"max": 3, "reason": "2026-10-02 " + _NO_ALERT_STEP},
    ("it_intrusion", "change_incident_count", "IMPROVED"): {"max": 1, "reason": (
        "2026-10-02 lowering incident_count 1->0 turns incident_membership_ok from False to True: the oracle can be "
        "retargeted onto the pipeline's output. The same fact F14 reports in oracle_derive.py (no single "
        "entity spans every alert-raising step); owner decision pending, WS-8 tracks-never-merge untouched")},
    ("it_intrusion", "drop_expected_rule", "SURVIVED"): {"max": 4, "reason": "2026-10-02 " + _COMPANION},
    ("it_intrusion", "flip_gap_to_false", "SURVIVED"): {"max": 1, "reason": (
        "2026-10-02 initial_access declares no expected rule and no rule fires there, so nothing reads the gap flag")},
    ("it_intrusion", "flip_relationship", "IMPROVED"): {"max": 3, "reason": (
        "2026-10-02 two forbidden->allowed flips on pairs the graph joins (" + _ORDER_BLIND_M + "), and the "
        "allowed->forbidden flip of recon_port_scan->ssh_bruteforce, the one allowed pair the graph does NOT join "
        "(joined=False): re-labelling an unmet requirement as a met non-edge raises chain_fidelity")},
    ("it_intrusion", "reverse_relationship", "IMPROVED"): {"max": 1, "reason": (
        "2026-10-02 recon_port_scan->ssh_bruteforce is the one allowed pair with joined=False, "
        "reverse_joined=True; reversing it makes the requirement MET. Predicted from per_allowed_pair "
        "before it was measured (predict_reversal), then measured")},
    ("it_intrusion", "reverse_relationship", "SURVIVED"): {"max": 5, "reason": "2026-10-02 " + _ORDER_BLIND_M},
    ("it_intrusion", "shift_level", "SURVIVED"): {"max": 8, "reason": "2026-10-02 " + _COMPANION},
    ("it_intrusion", "swap_adjacent_steps", "SURVIVED"): {"max": 2, "reason": "2026-10-02 " + _NO_ALERT_STEP},
    ("infra_takeover", "drop_expected_rule", "SURVIVED"): {"max": 1, "reason": "2026-10-02 " + _COMPANION},
    ("infra_takeover", "flip_relationship", "IMPROVED"): {"max": 1, "reason": (
        "2026-10-02 forbidden->allowed flip on a pair the graph joins: the wrong oracle scores BETTER because "
        + _ORDER_BLIND_M)},
    ("infra_takeover", "reverse_relationship", "SURVIVED"): {"max": 2, "reason": "2026-10-02 " + _ORDER_BLIND_M},
    ("infra_takeover", "shift_level", "SURVIVED"): {"max": 1, "reason": "2026-10-02 " + _COMPANION},
}

# normalised oracle key path -> "label: YYYY-MM-DD reason". ``declared-but-unenforced``: the oracle states it as a
# requirement and no grader reads it (owner decision pending: enforce, delete, or keep documented-inert).
# ``doc-only``: prose / identifiers that were never meant to be graded. ``cross_step_rule_ids`` is NOT here: it is
# read (report._incident_membership_grade) and the probe proves it.
_UNENFORCED = ("declared-but-unenforced: 2026-10-02 stated as a requirement by the oracle, read by no grader "
               "(measured: perturbing every occurrence changes no graded output); enforce it, delete it, or keep it "
               "as documented-inert -- an owner decision, not made here")
_DOC = "doc-only: 2026-10-02 prose or an identifier; no grader is meant to read it"
_INERT_KEYS: dict = {
    "sequence_constraints.strict_order": _UNENFORCED,
    "sequence_constraints.allow_extra_steps": _UNENFORCED,
    "sequence_constraints.max_clock_span_seconds": _UNENFORCED,
    "allowed_relationships[].causal_kind": _UNENFORCED,
    "incident_membership.incident_key": _UNENFORCED,
    "incident_membership.include[]": _UNENFORCED,
    "severity_band.severity_id.min": _UNENFORCED,
    "severity_band.severity_id.max": _UNENFORCED,
    "severity_band.dominant_band": _UNENFORCED,
    "evidence.correlation_key[]": _UNENFORCED,
    "detection_points.*.expected_event_source": _UNENFORCED,
    "detection_points.*.role": _UNENFORCED,
    "detection_points.*.expected_rules[].role": _UNENFORCED,
    "detection_points.*.expected_rules[].title": _UNENFORCED,
    "schema_version": _DOC, "oracle_id": _DOC, "kind": _DOC, "scope": _DOC, "description": _DOC,
    "detection_points.*.step": _DOC, "detection_points.*.gap.reason": _DOC,
    "detection_points.*.resolved_inconsistency": _DOC, "evidence.per_step.*.note": _DOC,
    "severity_band.rationale": _DOC,
}


# ---------------------------------------------------------------------------
# inert-key probe
# ---------------------------------------------------------------------------
_STEP_CONTAINERS = {("detection_points",), ("evidence", "per_step")}


def _leaves(node, path=()):
    """Yield (path, value) for every scalar leaf; list indices are kept as ints."""
    if isinstance(node, dict):
        for k in node:
            yield from _leaves(node[k], path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _leaves(v, path + (i,))
    else:
        yield path, node


def normalise_path(path: tuple) -> str:
    out = []
    for i, part in enumerate(path):
        if isinstance(part, int):
            out.append("[]")
        elif tuple(p for p in path[:i] if not isinstance(p, int)) in _STEP_CONTAINERS:
            out.append("*")
        else:
            out.append(str(part))
    s = ".".join(out)
    return s.replace(".[]", "[]")


def _perturbations(v) -> list:
    """Every way a leaf is perturbed. A key is only called inert when NONE of them moves any graded
    output (one direction is not enough: a band maximum raised 1000 higher changes nothing, lowered it does)."""
    if isinstance(v, bool):
        return [not v]
    if isinstance(v, (int, float)):
        return [v + 1000, v - 1000]
    if v is None:
        return ["x"]
    return ["", "mutation-probe"]


def _set_path(root, path, value):
    cur = root
    for part in path[:-1]:
        cur = cur[part]
    cur[path[-1]] = value


def inert_probe(sdef, seed: int, *, grader=None) -> dict:
    """Which oracle keys, perturbed in EVERY place they occur, change no graded output at all?"""
    grader = grader or default_grader
    oracle = oracle_derive.yaml.safe_load(Path(sdef.oracle_path).read_text(encoding="utf-8"))
    result = reg.run(sdef, seed)
    base_v = verdict(grader(result, copy.deepcopy(oracle)), oracle, sdef, seed)
    groups: dict = {}
    for path, val in _leaves(oracle):
        groups.setdefault(normalise_path(path), []).append((path, val))
    read, inert, crashed = [], [], []
    for norm in sorted(groups):
        n_variants = max(len(_perturbations(val)) for _p, val in groups[norm])
        moved = False
        for k in range(n_variants):
            mo = copy.deepcopy(oracle)
            for path, val in groups[norm]:
                opts = _perturbations(val)
                _set_path(mo, path, opts[min(k, len(opts) - 1)])
            try:
                v = verdict(grader(result, mo), mo, sdef, seed)
            except Exception:  # noqa: BLE001 - a key whose perturbation crashes the grader is certainly READ
                crashed.append(norm)
                moved = True
                break
            if fingerprint(v) != fingerprint(base_v):
                moved = True
                break
        (read if moved else inert).append(norm)
    return {"scenario": sdef.name, "read": sorted(read), "inert": sorted(inert), "crashed": sorted(crashed)}


# ---------------------------------------------------------------------------
# evaluation: waivers + ratchet
# ---------------------------------------------------------------------------
def summarise(run: dict) -> dict:
    ops: dict = {}
    for r in run["rows"]:
        o = ops.setdefault(r["operator"], {k: 0 for k in OUTCOMES})
        o[r["outcome"]] += 1
    return ops


def evaluate(run: dict, equivalent: dict | None = None) -> dict:
    """Apply the closed waiver table to one storyline's rows."""
    equivalent = _EQUIVALENT if equivalent is None else equivalent
    scen = run["scenario"]
    classes: dict = {}
    for r in run["rows"]:
        if r["outcome"] in ("SURVIVED", "IMPROVED", "CRASH") and r["kind"] != "NEUTRAL":
            classes.setdefault((scen, r["operator"], r["outcome"]), []).append(r["id"])
        if r["kind"] == "NEUTRAL" and r["outcome"] != "SURVIVED":
            classes.setdefault((scen, r["operator"], "IDENTITY_CHANGED"), []).append(r["id"])
    unwaived, over_cap, bad_reasons = [], [], []
    for key, ids in sorted(classes.items()):
        w = equivalent.get(key)
        if w is None or key[2] in ("CRASH", "IDENTITY_CHANGED"):
            unwaived.append({"class": list(key), "ids": ids})
        elif len(ids) > w["max"]:
            over_cap.append({"class": list(key), "count": len(ids), "max": w["max"], "ids": ids})
    mine = {k for k in equivalent if k[0] == scen}
    stale = sorted(mine - set(classes))
    for k in sorted(mine):
        if not _DATED.match(equivalent[k].get("reason", "")) or not isinstance(equivalent[k].get("max"), int):
            bad_reasons.append(list(k))
    waived_ids = {i for k, ids in classes.items() if k in equivalent and k[2] not in ("CRASH", "IDENTITY_CHANGED")
                  for i in ids}
    rows = [r for r in run["rows"] if r["kind"] in ("WRONG", "WEAKER")]
    sat = [r for r in rows if r["outcome"] == "SATURATED"]
    waived = [r for r in rows if r["id"] in waived_ids]
    eligible = [r for r in rows if r["outcome"] != "SATURATED" and r["id"] not in waived_ids]
    kh = [r for r in eligible if r["outcome"] == "KILLED_HEADLINE"]
    kc = [r for r in eligible if r["outcome"] == "KILLED_COUPLED"]
    score = {
        "mutants": len(rows), "saturated": len(sat), "waived": len(waived), "eligible": len(eligible),
        "killed_headline": len(kh), "killed_coupled": len(kc),
        "headline_score": round(len(kh) / len(eligible), 4) if eligible else None,
        "any_kill_score": round((len(kh) + len(kc)) / len(eligible), 4) if eligible else None,
    }
    channels: dict = {}
    for r in kh + kc:
        ch = sorted({c for _n, c in _channels_of(r)})
        for c in ch:
            channels[c] = channels.get(c, 0) + 1
    return {"unwaived": unwaived, "over_cap": over_cap, "stale_waivers": [list(k) for k in stale],
            "bad_reasons": bad_reasons, "score": score, "kill_channels": dict(sorted(channels.items())),
            "ok": not (unwaived or over_cap or stale or bad_reasons)}


def _channels_of(row: dict):
    # reconstruct channel names for the breakdown from the detail lists
    out = []
    for key in ("worse_headline", "changed_headline", "worse_coupled", "changed_coupled"):
        for comp in row.get(key) or []:
            name = comp.split(":")[0] if not comp.startswith("rec:") else "rec"
            ch = COMPONENTS.get(comp, (None, "reconcile" if comp.startswith("rec:") else "?"))[1]
            out.append((name, ch))
    return out


def ratchet_diff(current: dict, committed: dict | None) -> dict:
    """``current`` / ``committed``: {scenario: {mutant_id: outcome}}. A regression is a mutant whose
    outcome rank fell. ANY other difference (improvement, new or removed mutant) means the committed file
    lags reality and must be regenerated deliberately."""
    if committed is None:
        return {"regressions": [], "stale": [], "missing_file": True}
    regress, stale = [], []
    for scen in sorted(set(current) | set(committed)):
        cur, old = current.get(scen), committed.get(scen)
        if cur is None or old is None:
            stale.append({"scenario": scen, "why": "scenario missing from " + ("run" if cur is None else "file")})
            continue
        for mid in sorted(set(cur) | set(old)):
            a, b = cur.get(mid), old.get(mid)
            if a == b:
                continue
            if a is None or b is None:
                stale.append({"scenario": scen, "id": mid, "was": b, "now": a})
            elif _RANK[a] < _RANK[b]:
                regress.append({"scenario": scen, "id": mid, "was": b, "now": a})
            else:
                stale.append({"scenario": scen, "id": mid, "was": b, "now": a})
    return {"regressions": regress, "stale": stale, "missing_file": False}


def load_strength(path: Path | None = None) -> dict | None:
    p = Path(path or STRENGTH_PATH)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def baseline_section(runs: dict, inert: dict) -> dict:
    return {
        "outcomes": {name: {r["id"]: r["outcome"] for r in sorted(run["rows"], key=lambda r: r["id"])}
                     for name, run in sorted(runs.items())},
        "operators": {name: dict(sorted(summarise(run).items())) for name, run in sorted(runs.items())},
        "inert_keys": {name: v["inert"] for name, v in sorted(inert.items())},
    }


def evaluate_inert(inert: dict, inert_keys: dict | None = None) -> dict:
    """Closed table of oracle keys no grader reads. Unknown inert key -> FAIL; a table entry that is READ
    in every storyline carrying it (or in none) -> stale FAIL."""
    inert_keys = _INERT_KEYS if inert_keys is None else inert_keys
    all_read = {k for v in inert.values() for k in v["read"]}
    # inert in one storyline but read in another (incident_count on it_intrusion, where membership is already
    # False) is a SATURATED read, not an unread key
    all_inert = {k for v in inert.values() for k in v["inert"]} - all_read
    unknown = sorted(k for k in all_inert if k not in inert_keys)
    stale = sorted(k for k in inert_keys if k not in all_inert)
    bad = sorted(k for k, v in inert_keys.items()
                 if not re.match(r"^(declared-but-unenforced|doc-only): \d{4}-\d{2}-\d{2} \S", v or ""))
    return {"unknown": unknown, "stale": stale, "bad_labels": bad,
            "declared_unenforced": sorted(k for k in all_inert if (inert_keys.get(k) or "").startswith("declared")),
            "doc_only": sorted(k for k in all_inert if (inert_keys.get(k) or "").startswith("doc-only")),
            "read_somewhere": sorted(all_read), "ok": not (unknown or stale or bad)}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def run_all(seed: int, scenarios, *, grader=None, with_inert: bool = True, timing: dict | None = None):
    runs, inert = {}, {}
    with memoize_observation():
        for sdef in scenarios:
            t0 = time.time()
            runs[sdef.name] = run_scenario(sdef, seed, grader=grader)
            t1 = time.time()
            if with_inert:
                inert[sdef.name] = inert_probe(sdef, seed, grader=grader)
            if timing is not None:
                timing[sdef.name] = {"mutants": len(runs[sdef.name]["rows"]),
                                     "mutation_s": round(t1 - t0, 2), "inert_s": round(time.time() - t1, 2)}
    return runs, inert


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(prog="oracle_mutate")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--scenario", action="append", default=None)
    ap.add_argument("--update-baseline", action="store_true",
                    help="write this seed's section of eval/twin/oracle_strength.json (never done by the gate)")
    ap.add_argument("--accept-regressions", metavar="REASON", default=None,
                    help="with --update-baseline: also record mutants whose outcome got WORSE (needs a reason)")
    ap.add_argument("--timing", action="store_true", help="print measured wall-clock to stderr (not in stdout)")
    ap.add_argument("--list", action="store_true", help="list every survivor / improved / crash mutant id")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    scenarios = [reg.get(n) for n in args.scenario] if args.scenario else list(reg.ALL)
    timing: dict = {}
    t_start = time.time()
    runs, inert = run_all(args.seed, scenarios, timing=timing)
    total_s = time.time() - t_start

    committed = load_strength()
    sec = ((committed or {}).get("seeds") or {}).get(str(args.seed)) or {}
    cur_outcomes = {n: {r["id"]: r["outcome"] for r in run["rows"]} for n, run in runs.items()}
    rd = ratchet_diff(cur_outcomes, {n: sec["outcomes"][n] for n in cur_outcomes if n in (sec.get("outcomes") or {})}
                      if sec else None)

    rc = 0
    print(f"== oracle mutation testing (seed={args.seed}) ==")
    print("   WRONG mutants must score worse; WEAKER mutants must be noticed. KILLED_COUPLED = pipeline coupling, "
          "not strength.")
    for name, run in runs.items():
        ev = evaluate(run)
        print(f"-- {name}: {ev['score']['mutants']} mutants (observed run graded once, oracle edited in memory) --")
        print(f"   {'operator':<28}" + "".join(f"{o[:9]:>11}" for o in OUTCOMES))
        for op, c in sorted(summarise(run).items()):
            print(f"   {op:<28}" + "".join(f"{c[o]:>11}" for o in OUTCOMES))
        s = ev["score"]
        print(f"   headline mutation score {s['headline_score']} (killed by a graded metric: {s['killed_headline']}"
              f" of {s['eligible']} eligible); pipeline-coupled kills: {s['killed_coupled']}; any-channel score "
              f"{s['any_kill_score']}; saturated {s['saturated']}; waived {s['waived']}")
        print(f"   kills by channel: {ev['kill_channels']}")
        if args.list:
            for r in run["rows"]:
                if r["outcome"] in ("SURVIVED", "IMPROVED", "CRASH", "SATURATED"):
                    print(f"     [{r['outcome']}] {r['id']} {r.get('error', '')}")
        for u in ev["unwaived"]:
            print(f"   [FAIL] unwaived {u['class'][2]}: {u['class'][1]} x{len(u['ids'])} -> {u['ids'][:4]}")
        for u in ev["over_cap"]:
            print(f"   [FAIL] waiver cap exceeded {u['class']}: {u['count']} > {u['max']}")
        for k in ev["stale_waivers"]:
            print(f"   [FAIL] stale waiver {k}: it no longer reproduces -- delete it")
        for k in ev["bad_reasons"]:
            print(f"   [FAIL] waiver {k} needs an int max and a 'YYYY-MM-DD <reason>' string")
        if not ev["ok"]:
            rc = 1
    ei = evaluate_inert(inert)
    print(f"-- oracle keys no grader reads (perturbing every occurrence changes nothing) --")
    print(f"   declared-but-unenforced ({len(ei['declared_unenforced'])}): {ei['declared_unenforced']}")
    print(f"   doc-only ({len(ei['doc_only'])}): {ei['doc_only']}")
    for k in ei["unknown"]:
        print(f"   [FAIL] inert key {k!r} is not in _INERT_KEYS -- wire it, delete it, or label it (dated)")
    for k in ei["stale"]:
        print(f"   [FAIL] _INERT_KEYS entry {k!r} is no longer inert -- delete the waiver")
    for k in ei["bad_labels"]:
        print(f"   [FAIL] _INERT_KEYS entry {k!r} needs 'declared-but-unenforced|doc-only: YYYY-MM-DD <reason>'")
    if not ei["ok"]:
        rc = 1

    if rd["missing_file"]:
        print(f"   [FAIL] no committed ratchet for seed {args.seed} in eval/twin/oracle_strength.json "
              "(run --update-baseline once, deliberately)")
        rc = 1
    else:
        for r in rd["regressions"]:
            print(f"   [FAIL] ratchet regression {r['scenario']}: {r['id']} was {r['was']} now {r['now']}")
        for r in rd["stale"]:
            print(f"   [FAIL] ratchet file lags reality: {r}")
        if rd["regressions"] or rd["stale"]:
            rc = 1
    cache = CACHE_STATS
    if args.timing:
        print(f"[timing] {json.dumps(timing)} total={total_s:.1f}s cache hits={cache['hits']} "
              f"misses={cache['misses']}", file=sys.stderr)

    if args.update_baseline:
        hard = [n for n, run in runs.items() if any(
            (evaluate(run)[k]) for k in ("unwaived", "over_cap", "stale_waivers", "bad_reasons"))]
        crashes = [r["id"] for run in runs.values() for r in run["rows"] if r["outcome"] == "CRASH"]
        if hard or crashes or not ei["ok"]:
            print("[REFUSED] --update-baseline: fix unwaived survivors / IMPROVED / CRASH / stale or unlabelled "
                  "waivers first; the ratchet is not a place to park them.")
            return 1
        if rd["regressions"] and not args.accept_regressions:
            print("[REFUSED] --update-baseline: mutants regressed; pass --accept-regressions '<reason>' to record that")
            return 1
        data = committed or {"schema": 1, "seeds": {}}
        data["note"] = ("Generated by `python eval/twin/oracle_mutate.py --update-baseline`; never written by the "
                        "gate. Per seed and scenario: the outcome of every oracle mutant. A mutant that was "
                        "killed and now survives, or any difference from this file, fails the gate.")
        data["seeds"][str(args.seed)] = baseline_section(runs, inert)
        if args.accept_regressions:
            data.setdefault("accepted_regressions", []).append(
                {"seed": args.seed, "reason": args.accept_regressions, "ids": [r["id"] for r in rd["regressions"]]})
        STRENGTH_PATH.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[WROTE] {STRENGTH_PATH.relative_to(ROOT)} (seed {args.seed})")
        return 0
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({"runs": runs, "inert": inert}, indent=1, sort_keys=True, default=str),
                            encoding="utf-8")
    print("[OK] every wrong oracle is noticed or sits in a dated, capped waiver; the ratchet holds."
          if rc == 0 else "[FAIL] oracle mutation gate failed (see above)")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
