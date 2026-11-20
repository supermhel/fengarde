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

import known_gaps  # noqa: E402
import report  # noqa: E402
import scenario_registry as reg  # noqa: E402


# ---------------------------------------------------------------------------
# ACCEPTED DISAGREEMENTS live in each storyline's OWN oracle (``known_gaps:``, schema and failure
# modes in known_gaps.py; owner decision 2026-11-20). They used to be name-keyed tables here
# (_ACCEPTED, _GAP_TECHNIQUE_WAIVED, _TRIANGULATION_WAIVED). The list is still CLOSED: an
# observed disagreement with no declaration fails, a declaration of the wrong kind fails, and a
# declaration that no longer reproduces fails as stale. Removing a declaration is how one is
# closed for real (the ADR-011/012 ratchet).
# ---------------------------------------------------------------------------

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
    gaps = known_gaps.load(oracle, sdef.name)
    accepted = known_gaps.accepted_map(gaps, sdef.name)
    gap_technique_waived = known_gaps.gap_technique_map(gaps, sdef.name)

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
        # UNEXPECTED: a rule fires at a step whose entry neither expects it nor declares a gap.
        # ``expected`` may be EMPTY (a step whose last expected rule was removed, or one that never
        # declared rules and is not a declared gap): the step is then a silent hole and every firing
        # rule here is unexpected. Scope out the false positives: context steps and declared gaps are
        # handled by their own channels (a context step's telemetry is the staircase the dependent
        # step is judged against -- e.g. victim_session for impossible travel -- so it is tracked by
        # must_not_fire, not by expected_rules).
        if not declared_gap:
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
                and (sdef.name, step) not in gap_technique_waived:
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

    # Split every finding into accepted (declared in the oracle, of the right kind) vs NEW. Only
    # new ones gate -- and a stale or wrong-kind declaration is itself reported, so a declaration
    # cannot quietly outlive (or mislabel) the disagreement it was written for.
    seen, matched, new = set(), set(), []
    for kind, items in (("stale_gap", stale_gaps), ("decorative", decorative),
                        ("unexpected", unexpected), ("forbidden", forbidden_claimed),
                        ("forbidden_rule", forbidden_rules), ("unknown_rule", unknown_rules),
                        ("gap_technique", gaps_untagged)):
        for item in items:
            k = _key(sdef.name, kind, item)
            seen.add(k)
            decl = accepted.get(k)
            # an order_blind_join is only the right kind for a pair joined purely through entity edges
            # (the grader's per_forbidden_pair); a pair claimed by an explicit step-named edge is not that
            if decl is not None and not (decl["kind"] == "order_blind_join"
                                         and item.get("basis") != "per_forbidden_pair"):
                matched.add(k)
            else:
                new.append({"kind": kind, **item})
    findings["new"] = new
    findings["accepted_count"] = len(matched)
    observed_ab: dict = {}
    for k in seen:
        observed_ab.setdefault((k[2], k[3]), []).append(k[1])
    findings["stale_allowlist_entries"] = []
    for k in sorted(set(accepted) - matched):
        entry = {"key": list(k), "reason": accepted[k]["reason"]}
        other = sorted(x for x in observed_ab.get((k[2], k[3]), []) if x != k[1])
        if k in seen:
            entry["why"] = ("kind_mismatch: declared order_blind_join but the pair is claimed by an explicit "
                            "step edge, not only through shared entities")
        elif other:
            entry["why"] = f"kind_mismatch: declared {k[1]} but observed as {other}"
        findings["stale_allowlist_entries"].append(entry)
    # a gap-technique waiver is stale once its step is tagged (or stops being a gap): the list is closed
    for (sc, step), reason in sorted(gap_technique_waived.items()):
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
    if waived is None:
        waived = known_gaps.triangulation_map(known_gaps.load(oracle, sdef.name), sdef.name)

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
        if entry.get("why"):
            print(f"  [WRONG KIND]  {entry['key']} is declared in known_gaps but {entry['why']}")
        else:
            print(f"  [STALE WAIVER] {entry['key']} is declared in the oracle's known_gaps but no longer "
                  "reproduces -- delete the declaration, the disagreement is gone")

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
          "is wrong, deliberately (both feed frozen baseline numbers), or declare it in the oracle's known_gaps.")
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
