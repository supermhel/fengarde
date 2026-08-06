"""Detection-quality canary for the FENGARDE WS-4 detection engine.

Measures how well the real engine (``engine.Rule.evaluate`` on the real rules
in ``contracts/rules/*.yml``) agrees with a small hand-authored labeled corpus
of normalized OCSF events. Reports per-rule precision / recall / F1 and an
overall macro-F1, and exits non-zero if the macro-F1 drops below a deliberately
low floor (0.5) — a trip-wire for catastrophic regressions, not a quality bar.

This is *engine-versus-labels* agreement, NOT real-world detection fidelity.
See ``docs/detection-quality.md`` for the full method and the honest caveats
(especially the two intentionally adversarial ``common_after_hours_admin``
labels that keep precision/recall from being trivially 1.0).

Run:  python tools/detection_quality_eval.py
      python tools/test_detection_quality.py   (self-test of the metric math)
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
sys.path.insert(0, str(SERVICES / "ws2-normalization"))
sys.path.insert(0, str(SERVICES / "ws4-detection"))
sys.path.insert(0, str(SERVICES))

from engine import load_rules  # noqa: E402

RULES_DIR = ROOT / "contracts" / "rules"
ALLOWLISTS_DIR = ROOT / "contracts" / "allowlists"

# The macro-F1 below which the gate goes red. Deliberately low and honest (see
# docs/detection-quality.md): it only exists to catch a catastrophic regression
# (e.g. evaluate() or load_rules silently breaking so nothing fires -> recall 0
# -> macro-F1 0), not to assert a quality level.
FLOOR = 0.5

# Real rule ids from contracts/rules/ (must exist in the loaded rule set).
AFTER_HOURS_ADMIN = "9b5f2d18-3c7a-4e61-8f24-5a1d7c3e9b06"   # common_after_hours_admin.yml
PRIV_GRANT = "7d3e9a52-1f6c-4a88-9b3d-2e5c8f1a6d40"           # common_priv_grant.yml
PROMPT_INJECTION = "3c4d5e6f-7081-48a9-9b1c-3d4e5f6a7b8d"     # agent_prompt_injection_indicator.yml
ROOT_CONSOLE_LOGIN = "c3d4e5f6-7081-4920-9a3b-4c5d6e7f8093"   # cloud_root_console_login.yml

# Fixed, past, deterministic timestamps (UTC epoch-ms) so the after-hours
# predicate picks a stable weekday/hour regardless of when CI runs.
# Sunday 2026-08-09 03:00 UTC (off-hours) and Monday 2026-08-10 10:00 UTC (in-hours).
_OFF_HOURS_MS = 1786244400000
_IN_HOURS_MS = 1786356000000

# The labeled corpus. Each entry is one normalized OCSF event (the shape the
# parsers emit + the dotted field paths the engine evaluates), plus the rule
# id(s) a human judge expects to fire. [] means "nothing should fire".
CORPUS: list[dict] = [
    # --- common_after_hours_admin ------------------------------------------
    {
        "name": "ah_pos",
        "note": "off-hours (Sunday 03:00) Windows 4672 privileged logon -> should fire",
        "event": {"class_uid": 1002, "activity_id": 2,
                  "actor": {"user": {"name": "alice"}},
                  "time": _OFF_HOURS_MS},
        "expected_rules": [AFTER_HOURS_ADMIN],
    },
    {
        "name": "ah_inhours",
        "note": "in-hours (Monday 10:00) 4672 -> within business hours, should NOT fire",
        "event": {"class_uid": 1002, "activity_id": 2,
                  "actor": {"user": {"name": "alice"}},
                  "time": _IN_HOURS_MS},
        "expected_rules": [],
    },
    {
        # Deliberately adversarial label #1 (false negative): an off-hours admin
        # act with NO usable `time`. The engine's outside_hours predicate is
        # fail-closed -> stays silent, so the engine disagrees with this label by
        # design. Keeps recall < 1.0. See docs/detection-quality.md.
        "name": "ah_no_time",
        "note": "off-hours admin logon but timestamp missing -> engine fail-closed, FN by design",
        "event": {"class_uid": 1002, "activity_id": 2,
                  "actor": {"user": {"name": "alice"}}},
        "expected_rules": [AFTER_HOURS_ADMIN],
    },
    {
        # Deliberately adversarial label #2 (false positive): an off-hours admin
        # logon from a service account. The service_accounts allowlist ships
        # EMPTY, so the engine (no suppression by default) fires. The reference
        # label would suppress service accounts. Keeps precision < 1.0.
        "name": "ah_svcacct",
        "note": "off-hours service-account 4672 -> empty allowlist, engine fires, FP by design",
        "event": {"class_uid": 1002, "activity_id": 2,
                  "actor": {"user": {"name": "svc_backup"}},
                  "time": _OFF_HOURS_MS},
        "expected_rules": [],
    },
    # --- common_priv_grant --------------------------------------------------
    {
        "name": "pg_pos",
        "note": "privileged group membership grant (3003/5) -> should fire",
        "event": {"class_uid": 3003, "activity_id": 5,
                  "actor": {"user": {"name": "admin"}},
                  "unmapped": {"target_user": {"name": "bob"}}},
        "expected_rules": [PRIV_GRANT],
    },
    {
        "name": "pg_neg",
        "note": "account change but not a privilege grant (3003/6) -> should NOT fire",
        "event": {"class_uid": 3003, "activity_id": 6},
        "expected_rules": [],
    },
    # --- agent_prompt_injection_indicator -----------------------------------
    {
        "name": "pi_pos",
        "note": "MCP tool call carries injection indicator -> should fire",
        "event": {"class_uid": 6003, "siem": {"source_type": "mcp_agent"},
                  "unmapped": {"mcp": {"injection_indicator": True}}},
        "expected_rules": [PROMPT_INJECTION],
    },
    {
        "name": "pi_neg",
        "note": "MCP tool call without injection indicator -> should NOT fire",
        "event": {"class_uid": 6003, "siem": {"source_type": "mcp_agent"},
                  "unmapped": {"mcp": {"injection_indicator": False}}},
        "expected_rules": [],
    },
    # --- cloud_root_console_login -------------------------------------------
    {
        "name": "root_pos",
        "note": "root console login without MFA -> should fire",
        "event": {"class_uid": 3002, "activity_id": 1,
                  "siem": {"source_type": "cloudtrail"},
                  "unmapped": {"cloud": {"identity_type": "Root", "mfa_used": "No"}}},
        "expected_rules": [ROOT_CONSOLE_LOGIN],
    },
    {
        "name": "root_neg",
        "note": "non-root (IAM user) console login without MFA -> should NOT fire",
        "event": {"class_uid": 3002, "activity_id": 1,
                  "siem": {"source_type": "cloudtrail"},
                  "unmapped": {"cloud": {"identity_type": "IAMUser", "mfa_used": "No"}}},
        "expected_rules": [],
    },
]


def load_engine_rules() -> dict[str, object]:
    """Load the real rules from contracts/rules via engine.load_rules.

    Returns {rule_id: Rule}. Uses the genuine loader path (poison-pill
    validation + allowlist dir) exactly as services/ws4-detection does.
    """
    rules = load_rules(RULES_DIR, ALLOWLISTS_DIR)
    return {r.id: r for r in rules}


def fired_rule_ids(event: dict, rules: dict[str, object]) -> set[str]:
    """Run one event through the real Rule.evaluate() on every loaded rule.

    Only stateless rules are considered (the corpus drives single events, so a
    stateful threshold rule legitimately cannot fire on one event); stateful
    rules are skipped so they never masquerade as false negatives.
    """
    fired: set[str] = set()
    for rid, rule in rules.items():
        if getattr(rule, "stateful", False):
            continue
        if rule.evaluate(copy.deepcopy(event)):
            fired.add(rid)
    return fired


def entry_results(corpus: list[dict], rules: dict[str, object]) -> list[dict]:
    """[(name, expected:set, fired:set)] for every corpus entry."""
    return [{"name": e["name"],
             "expected": set(e["expected_rules"]),
             "fired": fired_rule_ids(e["event"], rules)}
            for e in corpus]


def rule_metrics(results: list[dict], rule_id: str) -> dict:
    """Precision/recall/F1 (and the 4 counts) for one rule over the corpus."""
    tp = fp = fn = tn = 0
    for r in results:
        wanted = rule_id in r["expected"]
        hit = rule_id in r["fired"]
        if wanted and hit:
            tp += 1
        elif not wanted and hit:
            fp += 1
        elif wanted and not hit:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    return {"precision": precision, "recall": recall, "f1": f1,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def macro_f1(per_rule: dict[str, dict]) -> float:
    """Unweighted mean of per-rule F1. Empty set -> 0.0."""
    if not per_rule:
        return 0.0
    return sum(m["f1"] for m in per_rule.values()) / len(per_rule)


def references(corpus: list[dict]) -> set[str]:
    """The set of rule ids the corpus actually labels (the scored rules)."""
    return {rid for e in corpus for rid in e["expected_rules"]}


def main(argv: list[str] | None = None) -> int:
    rules = load_engine_rules()
    scored = references(CORPUS)
    missing = scored - set(rules)
    if missing:
        print(f"[detection-quality] ERROR: corpus references rule ids not found "
              f"in contracts/rules/: {sorted(missing)}")
        return 2
    results = entry_results(CORPUS, rules)
    per_rule = {rid: rule_metrics(results, rid) for rid in sorted(scored)}
    overall = macro_f1(per_rule)

    print("FENGARDE detection-quality canary")
    print(f"  rules loaded : {len(rules)}  corpus events : {len(CORPUS)}  "
          f"scored rules : {len(scored)}")
    print(f"  {'rule id':<40} {'P':>6} {'R':>6} {'F1':>6}   TP FP FN TN")
    for rid, m in per_rule.items():
        print(f"  {rid:<40} {m['precision']:>6.2f} {m['recall']:>6.2f} "
              f"{m['f1']:>6.2f}   {m['tp']} {m['fp']} {m['fn']} {m['tn']}")
    print(f"  macro-F1: {overall:.3f}   (floor: >= {FLOOR})")

    ok = overall >= FLOOR
    if not ok:
        print("[detection-quality] FAIL: macro-F1 below floor "
              f"({overall:.3f} < {FLOOR})")
        return 1
    print("[detection-quality] OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
