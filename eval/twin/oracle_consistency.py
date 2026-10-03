"""oracle_consistency -- reconcile the GRADING ORACLE against observed reality.

WHY THIS EXISTS
    ``eval/twin/oracle.yaml`` is the answer key every twin/adversarial number
    is scored against, and it is written by the same project that wrote the
    detector. That is not automatically wrong -- somebody has to state what
    the chain is SUPPOSED to do -- but it means the answer key can DRIFT away
    from what the pipeline actually does, and nothing notices, because the
    grader reads the oracle and the oracle is never read back against the
    pipeline.

    Drift was not hypothetical when this module was written (2026-09-11). The
    oracle carried, in both directions:

      - a STALE GAP: ``process_anomaly`` declared ``no_rule_exists: true``
        ("no log line") while ``scenario.py`` emits a real Modbus FC6 write
        at that step which fires ``ot_modbus_unauthorized_write``. The
        oracle documented this contradiction in prose and left it standing.
      - DECORATIVE EXPECTATIONS, which nothing documented at all:
        ``agent_mcp_tool_call`` declares FOUR expected rules; exactly two
        fire on the real pipeline. ``agent_destructive_command`` and
        ``agent_tool_call_burst`` never fire on this chain.

    The second kind survived because of how TPR is computed
    (``report.py``: ``if step_fired & expected_ids: matched_steps += 1``) --
    ANY intersection marks the step matched, so over-declaring rules costs
    nothing and is invisible in the headline. ``TPR=1.0`` therefore means
    "every step with an expectation had at least ONE expectation met", NOT
    "every expected rule fired". Those are very different claims and only
    one of them is what the number looks like.

WHAT IT CHECKS (all against a real WS-2 -> WS-4 -> WS-8 run, nothing mocked)
    1. STALE GAP        -- a step declared ``no_rule_exists`` where a rule
                           really fires. The oracle is understating coverage.
    2. DECORATIVE       -- a rule in ``expected_rules`` that never fires at
                           its step. The oracle is overstating coverage, and
                           TPR cannot see it.
    3. UNEXPECTED       -- a rule firing at a step whose oracle entry neither
                           expects it nor declares a gap.
    4. FORBIDDEN EDGE   -- an ``allowed: false`` relationship the real
                           incident graph actually claims. (2026-10-02: this
                           channel was DEAD until now -- it looked for
                           ``from_step`` / ``to_step`` on graph edges, which no
                           edge carries. It now reads the grader's own
                           ``per_forbidden_pair`` (``joined=True``).)

    5. FORBIDDEN RULE   -- a rule listed in a step's ``must_not_fire`` that fires there
                           (2026-10-03). The oracle's built-in negative control: it states what
                           a step must stay SILENT on (a slow spray must not trip the per-IP
                           brute force; a single-country login must not trip impossible travel).
                           An id in ``must_not_fire`` that is not a shipped rule is itself a
                           finding (a typo would make the control vacuous).
    6. GAP WITHOUT TECHNIQUE -- a ``no_rule_exists`` gap that names no ``attack_technique`` and is
                           not a ``context`` step. The technique matrix's "demonstrated but
                           undetected" table is built from these, so an untagged gap would be a
                           silent hole in it. The two oldest oracles pre-date the key and are on a
                           closed, dated waiver list.
    7. CAMPAIGN MISMATCH -- the oracle's ``campaign_membership`` (count / full coverage over the
                           read-side campaign view) differs from the graded run. REPORTED, never
                           gated (owner decision 2026-10-03: ADR-009/010 are untouched, so whether
                           a pivoting attack is ONE campaign is a measurement, not a pass/fail).

    None of the gating ones can be fixed by editing this file: each is a genuine
    disagreement between the answer key and the system, and the repair is to
    change whichever one is wrong -- deliberately, because both feed frozen
    baseline numbers.

    ``--triangulate`` adds the THREE-WAY view: the hand oracle vs the oracle
    DERIVED independently from the rule files (``oracle_derive.py``) vs what the
    pipeline actually fired. Any derived-vs-observed difference is a finding:
    it is the cross-check on the derived reader itself.

STDLIB ONLY (PyYAML via the neighbours). Deterministic: same seed -> same findings.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
for p in (str(TWIN), str(SERVICES), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

import report  # noqa: E402
import scenario_registry as reg  # noqa: E402


# ---------------------------------------------------------------------------
# ACCEPTED DISAGREEMENTS (the frozen baseline)
# ---------------------------------------------------------------------------
# Every disagreement below was real and known on the date in its reason. They are NOT
# waived because they are harmless -- they are recorded because resolving
# them changes numbers the frozen baseline contract depends on
# (eval/twin/baseline.json, the Phase 3.5 delta report, the severity-confusion
# matrix), so each needs its own decision rather than a drive-by edit by
# whoever happened to run this check.
#
# The point of the allowlist is that it is CLOSED: anything not on it fails
# the gate. A new drift cannot hide behind these entries. Same shape as the
# project's accepted-Scorecard-alert list -- accept knowingly, block silently
# growing.
#
# Removing an entry here is the correct way to close one for real.
_ORDER_BLIND = (
    "2026-10-02 directional_discrimination=0.0 (SSOT 2026-10-01): the WS-8 graph joins every forbidden "
    "pair because the entities at both ends overlap (per-entity tracks never merge, so a shared "
    "address/account yields an edge in BOTH directions). The oracle's anti-causal non-edges are "
    "therefore not enforceable by this correlator. Waived by class, not hidden: closing it means "
    "grading edge direction by event time or by WS-8 typed caused_by edges, a separate ratified step."
)
_ACCEPTED: dict = {
    # The forbidden-edge channel read ``edge['from_step']`` / ``edge['to_step']``, which no WS-8 graph
    # edge carries (they carry from / to / kind / event_id / ts_ms), so it could never fire. It now reads
    # the grader's own ``per_forbidden_pair`` (joined=True). Opening it surfaces what
    # ``forbidden_denominator == forbidden_joins`` on every storyline already said: all five forbidden
    # pairs ARE joined by the graph. One entry per pair, one shared reason; an entry that stops
    # reproducing fails as a stale waiver, and a sixth forbidden join fails the gate.
    ("ai_to_ot", "forbidden", "process_anomaly", "modbus_write"): _ORDER_BLIND,
    ("ai_to_ot", "forbidden", "credential_use", "agent_mcp_tool_call"): _ORDER_BLIND,
    ("it_intrusion", "forbidden", "dns_exfil", "initial_access"): _ORDER_BLIND,
    ("it_intrusion", "forbidden", "priv_grant", "ssh_bruteforce"): _ORDER_BLIND,
    ("infra_takeover", "forbidden", "mass_vm_delete", "cloud_root_login"): _ORDER_BLIND,
    # 2026-10-03 phishing_bec: the same class on a fourth storyline. Both anti-causal pairs share the
    # compromised account with the steps they must not precede, so the actor track joins them in
    # both directions. Measured on the first run, not tuned: the rules all fired as the
    # intent-first oracle said they would; only this known order-blind channel disagreed.
    ("phishing_bec", "forbidden", "payment_redirect", "proxy_pool_logins"): _ORDER_BLIND,
    ("phishing_bec", "forbidden", "foreign_login", "user_execution"): _ORDER_BLIND,
}
# History. The map was EMPTY from 2026-10-01: the three AI-to-OT disagreements that used to live here
# (a stale process_anomaly gap; agent_tool_call_burst and agent_destructive_command
# declared at agent_mcp_tool_call but never fired) were RESOLVED in oracle.yaml, not
# waived: the process_anomaly step now declares the rule that really fires there, and
# the two rules this storyline never triggers were dropped from its answer key. The
# mechanism stays -- an entry is ``(scenario, kind, step_or_from, rule_or_to): reason``;
# anything not on the list fails the gate, and an entry that stops reproducing fails
# as a stale waiver -- so the next deliberate disagreement can be recorded rather than
# ignored. The five entries above (2026-10-02) are the only ones, and they are accepted
# because the correlator cannot do better today, not because the oracle is wrong.

# Gaps that pre-date the ``attack_technique`` key. A closed list: new oracles must tag every
# non-context gap. ``(scenario, step) -> "YYYY-MM-DD reason"``. Tagging these would edit oracle
# files that the step-4 oracle-strength ratchet hashes, so it is left to that step's owner.
_GAP_TECHNIQUE_WAIVED: dict = {
    ("ai_to_ot", "external_content"):
        "2026-10-03 oracle.yaml pre-dates the attack_technique key (pre-log ingress content)",
    ("ai_to_ot", "plc_state_change"):
        "2026-10-03 oracle.yaml pre-dates the attack_technique key (post-write process-side state change)",
    ("it_intrusion", "initial_access"):
        "2026-10-03 oracle_it_intrusion.yaml pre-dates the attack_technique key (T1078 candidate)",
}

# Three-way (hand / derived / observed) differences that are known: (scenario, step, rule_id) -> reason.
# EMPTY: derived and observed agree on every step of every storyline. A reason must be dated.
_TRIANGULATION_WAIVED: dict = {}

_DATED_REASON = re.compile(r"^\d{4}-\d{2}-\d{2} \S")


_COMPANION_OF: dict = {}


def _companion_sibling(rule_id: str):
    """``siem.companion_of`` of ``rule_id`` (the sibling's rule id), or None."""
    if not _COMPANION_OF:
        import yaml  # noqa: PLC0415
        for f in sorted((ROOT / "contracts" / "rules").glob("*.yml")):
            try:
                d = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            except Exception:  # noqa: BLE001 - validate_rules.py owns broken rule files
                continue
            if d.get("id"):
                _COMPANION_OF[d["id"]] = (d.get("siem") or {}).get("companion_of")
    return _COMPANION_OF.get(rule_id)


def _key(scenario_name: str, kind: str, item: dict) -> tuple:
    """The identity of a finding in ``_ACCEPTED``: ``(scenario, kind, a, b)``. Every kind maps to
    two item fields so the waiver table has one shape. An unknown kind raises: it used to fall
    through to ``item['from'], item['to']`` and KeyError on the first kind that had no such fields."""
    if kind == "stale_gap":
        return (scenario_name, kind, item["step"],
                item["observed_rules"][0] if item["observed_rules"] else "")
    if kind in ("decorative", "unexpected", "forbidden_rule", "unknown_rule"):
        return (scenario_name, kind, item["step"], item["rule_id"])
    if kind == "gap_technique":
        return (scenario_name, kind, item["step"], "")
    if kind == "forbidden":
        return (scenario_name, kind, item["from"], item["to"])
    raise KeyError(f"unknown finding kind {kind!r}")


_RULE_IDS: set = set()


def _known_rule_ids() -> set:
    if not _RULE_IDS:
        import yaml  # noqa: PLC0415
        for f in sorted((ROOT / "contracts" / "rules").glob("*.yml")):
            try:
                d = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            except Exception:  # noqa: BLE001 - validate_rules.py owns broken rule files
                continue
            if d.get("id"):
                _RULE_IDS.add(d["id"])
    return _RULE_IDS


def _campaign_report(oracle: dict, grade: dict) -> list:
    """``campaign_membership`` vs the graded run. REPORTED ONLY (see the module docstring)."""
    want = oracle.get("campaign_membership")
    if not want:
        return []
    out = []
    if want.get("campaign_count") is not None and grade.get("campaign_count") != want["campaign_count"]:
        out.append({"field": "campaign_count", "expected": want["campaign_count"],
                    "observed": grade.get("campaign_count")})
    if want.get("full_coverage") is not None \
            and bool(grade.get("campaign_full_coverage")) != bool(want["full_coverage"]):
        out.append({"field": "full_coverage", "expected": bool(want["full_coverage"]),
                    "observed": bool(grade.get("campaign_full_coverage"))})
    return out


def reconcile(seed: int = 7, sdef=None, *, oracle: dict | None = None, grade: dict | None = None) -> dict:
    """Run one storyline's real chain and diff its oracle's declarations
    against what the pipeline did. ``sdef`` defaults to the AI-to-OT chain.

    ``oracle`` / ``grade`` are optional so a caller that already holds a graded run (the oracle
    mutation suite grades hundreds of edited oracles against ONE observed run) can reconcile an
    oracle without re-running the chain. Behaviour is unchanged when both are omitted."""
    sdef = sdef or reg.BY_NAME["ai_to_ot"]
    oracle = oracle if oracle is not None else reg.load_oracle(sdef)
    if grade is None:
        grade = report._grade_chain(reg.run(sdef, seed), oracle)

    fired_by_step: dict = {}
    for alert in grade.get("fired", []):
        fired_by_step.setdefault(alert.get("step"), set()).add(alert.get("rule_id"))

    detection_points = oracle.get("detection_points") or {}
    stale_gaps, decorative, unexpected = [], [], []
    forbidden_rules, unknown_rules, gaps_untagged = [], [], []

    for step in oracle.get("expected_sequence") or []:
        entry = detection_points.get(step) or {}
        declared_gap = bool((entry.get("gap") or {}).get("no_rule_exists"))
        expected = {r.get("rule_id") for r in (entry.get("expected_rules") or [])}
        observed = fired_by_step.get(step, set())

        if declared_gap and observed:
            stale_gaps.append({
                "step": step,
                "declared": "no_rule_exists: true",
                "observed_rules": sorted(observed),
                "why_it_matters": "the oracle understates coverage; the fired alert is graded "
                                   "as 'unexpected' severity noise instead of a real detection",
            })
        for rule_id in sorted(expected - observed):
            # A companion rule restates its sibling on another group key and is dropped when
            # the sibling alerted on the same event (ws4 main.py), so on the baseline run --
            # where the sibling fires -- silence is its designed behaviour, not decoration.
            # It is still decorative if the sibling did NOT fire either: then nothing covers
            # the step and the declaration is genuinely unbacked.
            if _companion_sibling(rule_id) in observed:
                continue
            decorative.append({
                "step": step,
                "rule_id": rule_id,
                "why_it_matters": "declared expected but never fires; TPR's any-intersection "
                                   "rule makes this invisible, so the oracle can overstate "
                                   "coverage at no cost to the headline",
            })
        if not declared_gap and expected:
            for rule_id in sorted(observed - expected):
                unexpected.append({"step": step, "rule_id": rule_id,
                                    "why_it_matters": "fires but is not declared at this step"})
        # the oracle's built-in negative control (2026-10-03)
        for rule_id in sorted(set(entry.get("must_not_fire") or [])):
            if rule_id not in _known_rule_ids():
                unknown_rules.append({"step": step, "rule_id": rule_id,
                                      "why_it_matters": "must_not_fire names an id that is not a shipped "
                                                         "rule, so the control could never fail"})
            elif rule_id in observed:
                forbidden_rules.append({"step": step, "rule_id": rule_id,
                                        "why_it_matters": "the oracle says this step must stay silent on "
                                                           "this rule, and it fired"})
        if declared_gap and not entry.get("context") \
                and not (entry.get("gap") or {}).get("attack_technique") \
                and (sdef.name, step) not in _GAP_TECHNIQUE_WAIVED:
            gaps_untagged.append({"step": step,
                                  "why_it_matters": "a declared coverage gap names no ATT&CK technique, so "
                                                     "the technique matrix cannot list it as demonstrated "
                                                     "but undetected"})

    forbidden_claimed = []
    forbidden = {(r.get("from"), r.get("to"))
                 for r in (oracle.get("allowed_relationships") or [])
                 if r.get("allowed") is False}
    claimed: set = set()
    # (a) the grader's own verdict on each forbidden pair (the channel that actually carries data)
    for pf in grade.get("per_forbidden_pair") or []:
        pair = (pf.get("from"), pf.get("to"))
        if pf.get("graded") and pf.get("joined") and pair in forbidden and pair not in claimed:
            claimed.add(pair)
            forbidden_claimed.append({"from": pair[0], "to": pair[1], "basis": "per_forbidden_pair",
                                       "why_it_matters": "the oracle forbids this causal "
                                                          "direction; the graph claims it"})
    # (b) an edge that names its steps explicitly (a synthetic or future graph shape). Real WS-8
    #     edges carry only entity ids, so this stays empty on a real run.
    for edge in grade.get("graph_edges") or []:
        pair = (edge.get("from_step"), edge.get("to_step"))
        if pair in forbidden and pair not in claimed:
            claimed.add(pair)
            forbidden_claimed.append({"from": pair[0], "to": pair[1], "basis": "edge from_step/to_step",
                                       "why_it_matters": "the oracle forbids this causal "
                                                          "direction; the graph claims it"})

    findings = {
        "scenario": sdef.name,
        "seed": seed,
        "basis": "harness-measured",
        "stale_gaps": stale_gaps,
        "decorative_expectations": decorative,
        "unexpected_firings": unexpected,
        "forbidden_edges_claimed": forbidden_claimed,
        "forbidden_rules_fired": forbidden_rules,
        "unknown_must_not_fire": unknown_rules,
        "gaps_without_technique": gaps_untagged,
        # REPORTED, never gated (owner decision 2026-10-03; ADR-009/010 untouched)
        "campaign_report": _campaign_report(oracle, grade),
        "tpr_semantics": (
            "report.py counts a step matched when ANY expected rule fires "
            "(step_fired & expected_ids), so TPR is step COVERAGE, not "
            "expected-rule completeness. TPR=1.0 does not mean every declared "
            "rule fired."
        ),
    }
    findings["total"] = (len(stale_gaps) + len(decorative) + len(unexpected) + len(forbidden_claimed)
                         + len(forbidden_rules) + len(unknown_rules) + len(gaps_untagged))

    # Split every finding into accepted (on the frozen list) vs NEW. Only new
    # ones gate -- and a stale allowlist entry is itself reported, so the list
    # cannot quietly outlive the disagreement it was written for.
    seen, new = set(), []
    for kind, items in (("stale_gap", stale_gaps), ("decorative", decorative),
                        ("unexpected", unexpected), ("forbidden", forbidden_claimed),
                        ("forbidden_rule", forbidden_rules), ("unknown_rule", unknown_rules),
                        ("gap_technique", gaps_untagged)):
        for item in items:
            k = _key(sdef.name, kind, item)
            seen.add(k)
            if k not in _ACCEPTED:
                new.append({"kind": kind, **item})
    findings["new"] = new
    findings["accepted_count"] = len(seen & set(_ACCEPTED))
    # a waiver is "stale" only for ITS OWN scenario -- another storyline's
    # waivers are simply not in scope for this run
    mine = {k for k in _ACCEPTED if k[0] == sdef.name}
    findings["stale_allowlist_entries"] = [
        {"key": list(k), "reason": _ACCEPTED[k]} for k in sorted(mine - seen)
    ]
    # a gap-technique waiver is stale once its step is tagged (or stops being a gap): the table is closed
    for (sc, step), reason in sorted(_GAP_TECHNIQUE_WAIVED.items()):
        if sc != sdef.name:
            continue
        entry = detection_points.get(step) or {}
        still_untagged = (bool((entry.get("gap") or {}).get("no_rule_exists")) and not entry.get("context")
                          and not (entry.get("gap") or {}).get("attack_technique"))
        if not still_untagged:
            findings["stale_allowlist_entries"].append(
                {"key": ["gap_technique_waiver", sc, step], "reason": reason})
    findings["finding_keys"] = sorted("|".join(map(str, k)) for k in seen)
    return findings


def triangulate(seed: int = 7, sdef=None, *, oracle: dict | None = None, grade: dict | None = None,
                derived: dict | None = None, waived: dict | None = None) -> dict:
    """Three-way table for one storyline: HAND (the oracle) vs DERIVED (``oracle_derive``, from the rule
    files alone) vs OBSERVED (the rules the real pipeline fired, per step).

    A difference between DERIVED and OBSERVED is a finding in its own right: it means the independent
    interpreter and the engine disagree about the same rules on the same events (or a scenario/rule
    changed under one of them). Steps where the derived reader is UNDECIDED are excluded from the
    comparison and listed. HAND-vs-observed is ``reconcile``'s job and is not repeated."""
    import oracle_derive  # noqa: PLC0415 - only this check needs it

    sdef = sdef or reg.BY_NAME["ai_to_ot"]
    oracle = oracle if oracle is not None else reg.load_oracle(sdef)
    if grade is None:
        grade = report._grade_chain(reg.run(sdef, seed), oracle)
    if derived is None:
        derived = oracle_derive.derive(sdef, seed)
    waived = _TRIANGULATION_WAIVED if waived is None else waived

    observed: dict = {}
    for alert in grade.get("fired", []):
        observed.setdefault(alert.get("step"), set()).add(alert.get("rule_id"))
    hand = oracle_derive.hand_view(oracle)
    rows, diffs = [], []
    for step in oracle.get("expected_sequence") or []:
        ds = derived["steps"].get(step) or {}
        d_fire = set((ds.get("fires") or {}))
        undec = set(ds.get("undecided") or [])
        obs = observed.get(step, set())
        only_derived = sorted((d_fire - obs) - undec)
        only_observed = sorted((obs - d_fire) - undec)
        rows.append({"step": step, "hand": sorted(hand[step]["rules"]), "derived": sorted(d_fire),
                     "suppressed_companions": sorted(ds.get("suppressed_companions") or {}),
                     "observed": sorted(obs), "undecided": sorted(undec)})
        for rid in only_derived:
            diffs.append({"step": step, "rule_id": rid, "side": "derived-only"})
        for rid in only_observed:
            diffs.append({"step": step, "rule_id": rid, "side": "observed-only"})
    keys = {(sdef.name, d["step"], d["rule_id"]) for d in diffs}
    new = [d for d in diffs if (sdef.name, d["step"], d["rule_id"]) not in waived]
    mine = {k for k in waived if k[0] == sdef.name}
    stale = sorted(mine - keys)
    bad = sorted(k for k in waived if not _DATED_REASON.match(waived[k] or ""))
    return {"scenario": sdef.name, "seed": seed, "rows": rows, "differences": diffs, "new": new,
            "stale_waivers": [list(k) for k in stale], "bad_reasons": [list(k) for k in bad],
            "ok": not new and not stale and not bad}


def _report_one(f: dict, warn_only: bool) -> int:
    for item in f["stale_gaps"]:
        print(f"  [STALE GAP]   {item['step']}: declared {item['declared']}, but "
              f"{', '.join(item['observed_rules'])} actually fires")
    for item in f["decorative_expectations"]:
        print(f"  [DECORATIVE]  {item['step']}: expects {item['rule_id']} -- never fires")
    for item in f["unexpected_firings"]:
        print(f"  [UNEXPECTED]  {item['step']}: {item['rule_id']} fires but is not declared")
    for item in f["forbidden_edges_claimed"]:
        print(f"  [FORBIDDEN]   graph claims {item['from']} -> {item['to']}, oracle forbids it")
    for item in f["forbidden_rules_fired"]:
        print(f"  [MUST-NOT-FIRE] {item['step']}: {item['rule_id']} fired, the oracle forbids it")
    for item in f["unknown_must_not_fire"]:
        print(f"  [UNKNOWN RULE] {item['step']}: must_not_fire names {item['rule_id']}, not a shipped rule")
    for item in f["gaps_without_technique"]:
        print(f"  [GAP NO TECHNIQUE] {item['step']}: no_rule_exists gap without attack_technique")
    for item in f["campaign_report"]:
        print(f"  [REPORTED campaign_membership] {item['field']}: oracle expects {item['expected']}, "
              f"run produced {item['observed']} (not gated)")
    for entry in f["stale_allowlist_entries"]:
        print(f"  [STALE WAIVER] {entry['key']} is on the accepted list but no longer "
              "reproduces -- delete the entry, the disagreement is gone")

    if f["total"] == 0 and not f["stale_allowlist_entries"]:
        print("  [OK] oracle and pipeline agree on every step, rule and forbidden edge.")
        return 0
    print(f"  accepted (known, dated, on the frozen list): {f['accepted_count']}")
    if not f["new"] and not f["stale_allowlist_entries"]:
        print(f"  [OK] {f['total']} disagreement(s), ALL of them known and accepted. "
              "No new drift. Each accepted entry names what resolving it would move.")
        return 0
    for item in f["new"]:
        print(f"  [NEW DRIFT]   {item['kind']}: {item}")
    print(f"  [{'WARN' if warn_only else 'FAIL'}] {len(f['new'])} NEW oracle/reality "
          f"disagreement(s) + {len(f['stale_allowlist_entries'])} stale waiver(s) -- the "
          "answer key and the system disagree in a way nobody has accepted. Fix whichever "
          "is wrong, deliberately (both feed frozen baseline numbers), or add a dated entry.")
    return 0 if warn_only else 1


def _report_triangulation(t: dict) -> int:
    print(f"  {'step':<22}{'hand':<20}{'derived':<20}{'suppressed':<13}{'observed':<20}undecided")
    for r in t["rows"]:
        def s(ids):
            return ",".join(i[:8] for i in ids) or "-"
        print(f"  {r['step']:<22}{s(r['hand']):<20}{s(r['derived']):<20}{s(r['suppressed_companions']):<13}"
              f"{s(r['observed']):<20}{s(r['undecided'])}")
    for d in t["new"]:
        print(f"  [DERIVED<>OBSERVED] {d['step']}: {d['rule_id']} is {d['side']}")
    for k in t["stale_waivers"]:
        print(f"  [STALE WAIVER] {k} no longer reproduces -- delete it")
    for k in t["bad_reasons"]:
        print(f"  [BAD WAIVER] {k}: a waiver needs 'YYYY-MM-DD <reason>'")
    if t["ok"]:
        print("  [OK] derived (rule files alone) and observed (the real engine) agree on every step.")
        return 0
    print("  [FAIL] the independent interpreter and the engine disagree -- one of them (or a rule/scenario "
          "edit) is wrong; fix it deliberately.")
    return 1


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(prog="oracle_consistency")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--scenario", action="append", default=None,
                    help="restrict to one registered scenario (repeatable); default: all")
    ap.add_argument("--warn-only", action="store_true",
                     help="report findings but exit 0 (for recording a known, "
                          "deliberately-unresolved disagreement)")
    ap.add_argument("--triangulate", action="store_true",
                    help="also print the three-way table: hand vs derived (oracle_derive) vs observed")
    args = ap.parse_args(argv)

    sdefs = [reg.get(n) for n in args.scenario] if args.scenario else list(reg.ALL)
    rc = 0
    all_findings = {}
    for sdef in sdefs:
        print(f"== oracle <-> reality reconciliation: {sdef.name} (seed={args.seed}) ==")
        f = reconcile(args.seed, sdef)
        all_findings[sdef.name] = f
        rc |= _report_one(f, args.warn_only)
        if args.triangulate:
            print(f"-- three-way: hand / derived / observed: {sdef.name} (seed={args.seed}) --")
            t = triangulate(args.seed, sdef)
            all_findings[sdef.name]["triangulation"] = t
            rc |= _report_triangulation(t)
    print(f"  NOTE: {next(iter(all_findings.values()))['tpr_semantics']}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(all_findings, fh, indent=2)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
