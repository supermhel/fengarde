"""Unit tests for rules_view.py (M4.3 rule-summary read model).

Covers list_rule_summaries() over the REAL shipped rules, the tenant
disable path (_disabled_for_tenant), the malformed/path-traversal tenant
reject, and _contracts_dir()'s host-vs-container path probe (the v0.5 fix
for GET /rules returning nothing on live Docker deployments).

Run: python services/ws3-indexer/test_rules_view.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import rules_view  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_contracts_dir_resolves_to_a_real_rules_dir():
    d = rules_view._contracts_dir()
    check((d / "rules").is_dir(),
          f"_contracts_dir() must resolve to a dir containing rules/, got {d}")


def test_list_all_rules_no_tenant():
    summaries = rules_view.list_rule_summaries()
    check(len(summaries) > 0, "expected the shipped rules to produce summaries")
    # sorted by id, every entry has the summary shape, condition never leaked.
    ids = [s["id"] for s in summaries]
    check(ids == sorted(ids), "summaries must be sorted by id")
    for s in summaries:
        for key in ("id", "title", "level", "sector", "score_weight",
                    "stateful", "mitre", "enabled"):
            check(key in s, f"summary missing key {key!r}: {s}")
        check("condition" not in s, "summary must NEVER leak the raw condition")
        check(s["enabled"] is True, "no tenant context -> every rule enabled")
    # a stateful rule (brute-force) reports stateful=True; a single-shot one False.
    by_id = {s["id"]: s for s in summaries}
    bf = by_id.get("6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01")
    check(bf is not None and bf["stateful"] is True,
          "brute-force rule should report stateful=True")


def test_malformed_tenant_id_disables_nothing():
    # A path-traversal-shaped tenant id must be rejected at the edge (never
    # normalized) -> _disabled_for_tenant returns empty -> every rule enabled,
    # no exception, no read outside TENANTS_DIR.
    summaries = rules_view.list_rule_summaries("../../etc/passwd")
    check(len(summaries) > 0, "malformed tenant must still return the rule set")
    check(all(s["enabled"] for s in summaries),
          "a rejected tenant id must disable nothing (fail closed on suppression)")


def test_unknown_tenant_disables_nothing():
    # A well-formed but unknown tenant (no contracts/tenants/<id>.yml) ->
    # nothing disabled, same fail-open-on-detection convention.
    summaries = rules_view.list_rule_summaries("nonexistent-tenant")
    check(all(s["enabled"] for s in summaries),
          "an unknown tenant must leave every rule enabled")


def main():
    test_contracts_dir_resolves_to_a_real_rules_dir()
    test_list_all_rules_no_tenant()
    test_malformed_tenant_id_disables_nothing()
    test_unknown_tenant_disables_nothing()
    if FAILS:
        print(f"[FAIL] rules_view: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] rules_view: list_rule_summaries over real rules (sorted, summary "
          "shape, condition never leaked), malformed + unknown tenant disable "
          "nothing, _contracts_dir() resolves to a real rules dir")


if __name__ == "__main__":
    main()
