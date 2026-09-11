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
                           incident graph actually claims.

    None of these can be fixed by editing this file: each is a genuine
    disagreement between the answer key and the system, and the repair is to
    change whichever one is wrong -- deliberately, because both feed frozen
    baseline numbers.

STDLIB ONLY. Deterministic: same seed -> same findings.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
for p in (str(TWIN), str(SERVICES), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

import report  # noqa: E402
import scenario  # noqa: E402


# ---------------------------------------------------------------------------
# ACCEPTED DISAGREEMENTS (the frozen baseline)
# ---------------------------------------------------------------------------
# Every disagreement below was real and known on 2026-09-11. They are NOT
# waived because they are harmless -- they are recorded because resolving
# them changes numbers the frozen baseline contract depends on
# (eval/twin/baseline.json, the Phase 3.5 delta report, the severity-confusion
# matrix), so each needs its own decision rather than a drive-by edit by
# whoever happened to run this check.
#
# The point of the allowlist is that it is CLOSED: anything not on it fails
# the gate. A new drift cannot hide behind these three. Same shape as the
# project's accepted-Scorecard-alert list -- accept knowingly, block silently
# growing.
#
# Removing an entry here is the correct way to close one for real.
_ACCEPTED = {
    ("stale_gap", "process_anomaly", "9c1d2e3f-4a5b-4c6d-8e7f-1a2b3c4d5e6f"):
        "2026-09-11: oracle declares this step a no_rule_exists gap ('no log line'), but "
        "scenario.py emits a real Modbus FC6 write to _ANOMALY_ADDR which the real parser "
        "classifies as unauthorized_write. Documented in oracle.yaml's own "
        "known_inconsistency block since 2026-09-03. Resolving it means either declaring "
        "the rule at this step (changes the expected detection-point set AND the severity "
        "score) or changing what the scenario emits -- both move frozen baseline numbers.",
    ("decorative", "agent_mcp_tool_call", "2b3c4d5e-6f70-4899-8a1b-2c3d4e5f6a7c"):
        "2026-09-11: agent_tool_call_burst is declared expected but the chain issues too few "
        "tool calls in-window to trip its threshold. Either the scenario should issue a real "
        "burst (changes the event count and every downstream count) or the oracle should stop "
        "claiming it. NOT previously documented anywhere -- found by this checker.",
    ("decorative", "agent_mcp_tool_call", "5e6f7081-92a3-4bc4-ad2e-4f5a6b7c8d9e"):
        "2026-09-11: agent_destructive_command is declared expected but the chain's tool-call "
        "arguments carry an injection + egress URL, no destructive command pattern. Same "
        "choice as above: emit one, or stop declaring it. NOT previously documented -- found "
        "by this checker.",
}


def _key(kind: str, item: dict) -> tuple:
    if kind == "stale_gap":
        return (kind, item["step"], item["observed_rules"][0] if item["observed_rules"] else "")
    if kind in ("decorative", "unexpected"):
        return (kind, item["step"], item["rule_id"])
    return (kind, item["from"], item["to"])


def reconcile(seed: int = 7) -> dict:
    """Run the real chain and diff the oracle's declarations against it."""
    oracle = report._load_oracle()
    grade = report._grade_chain(scenario.run_chain(seed, strict=True), oracle)

    fired_by_step: dict = {}
    for alert in grade.get("fired", []):
        fired_by_step.setdefault(alert.get("step"), set()).add(alert.get("rule_id"))

    detection_points = oracle.get("detection_points") or {}
    stale_gaps, decorative, unexpected = [], [], []

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

    forbidden_claimed = []
    forbidden = {(r.get("from"), r.get("to"))
                 for r in (oracle.get("allowed_relationships") or [])
                 if r.get("allowed") is False}
    for edge in grade.get("graph_edges") or []:
        pair = (edge.get("from_step"), edge.get("to_step"))
        if pair in forbidden:
            forbidden_claimed.append({"from": pair[0], "to": pair[1],
                                       "why_it_matters": "the oracle forbids this causal "
                                                          "direction; the graph claims it"})

    findings = {
        "seed": seed,
        "basis": "harness-measured",
        "stale_gaps": stale_gaps,
        "decorative_expectations": decorative,
        "unexpected_firings": unexpected,
        "forbidden_edges_claimed": forbidden_claimed,
        "tpr_semantics": (
            "report.py counts a step matched when ANY expected rule fires "
            "(step_fired & expected_ids), so TPR is step COVERAGE, not "
            "expected-rule completeness. TPR=1.0 does not mean every declared "
            "rule fired."
        ),
    }
    findings["total"] = (len(stale_gaps) + len(decorative)
                         + len(unexpected) + len(forbidden_claimed))

    # Split every finding into accepted (on the frozen list) vs NEW. Only new
    # ones gate -- and a stale allowlist entry is itself reported, so the list
    # cannot quietly outlive the disagreement it was written for.
    seen, new = set(), []
    for kind, items in (("stale_gap", stale_gaps), ("decorative", decorative),
                        ("unexpected", unexpected), ("forbidden", forbidden_claimed)):
        for item in items:
            k = _key(kind, item)
            seen.add(k)
            if k not in _ACCEPTED:
                new.append({"kind": kind, **item})
    findings["new"] = new
    findings["accepted_count"] = len(seen & set(_ACCEPTED))
    findings["stale_allowlist_entries"] = [
        {"key": list(k), "reason": _ACCEPTED[k]} for k in sorted(set(_ACCEPTED) - seen)
    ]
    return findings


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(prog="oracle_consistency")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--warn-only", action="store_true",
                     help="report findings but exit 0 (for recording a known, "
                          "deliberately-unresolved disagreement)")
    args = ap.parse_args(argv)

    print(f"== twin oracle <-> reality reconciliation (seed={args.seed}) ==")
    f = reconcile(args.seed)

    for item in f["stale_gaps"]:
        print(f"  [STALE GAP]   {item['step']}: declared {item['declared']}, but "
              f"{', '.join(item['observed_rules'])} actually fires")
    for item in f["decorative_expectations"]:
        print(f"  [DECORATIVE]  {item['step']}: expects {item['rule_id']} -- never fires")
    for item in f["unexpected_firings"]:
        print(f"  [UNEXPECTED]  {item['step']}: {item['rule_id']} fires but is not declared")
    for item in f["forbidden_edges_claimed"]:
        print(f"  [FORBIDDEN]   graph claims {item['from']} -> {item['to']}, oracle forbids it")

    print(f"  NOTE: {f['tpr_semantics']}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(f, fh, indent=2)

    for entry in f["stale_allowlist_entries"]:
        print(f"  [STALE WAIVER] {entry['key']} is on the accepted list but no longer "
              "reproduces -- delete the entry, the disagreement is gone")

    if f["total"] == 0 and not f["stale_allowlist_entries"]:
        print("[OK] oracle and pipeline agree on every step, rule and forbidden edge.")
        return 0

    print(f"  accepted (known, dated, on the frozen list): {f['accepted_count']}")
    if not f["new"] and not f["stale_allowlist_entries"]:
        print(f"[OK] {f['total']} disagreement(s), ALL of them known and accepted. "
              "No new drift. Each accepted entry names what resolving it would move.")
        return 0

    for item in f["new"]:
        print(f"  [NEW DRIFT]   {item['kind']}: {item}")
    print(f"[{'WARN' if args.warn_only else 'FAIL'}] {len(f['new'])} NEW oracle/reality "
          f"disagreement(s) + {len(f['stale_allowlist_entries'])} stale waiver(s) -- the "
          "answer key and the system disagree in a way nobody has accepted. Fix whichever "
          "is wrong, deliberately (both feed frozen baseline numbers), or add a dated entry.")
    return 0 if args.warn_only else 1


if __name__ == "__main__":
    raise SystemExit(main())
