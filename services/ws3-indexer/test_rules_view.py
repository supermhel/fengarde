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


OPCUA = "e7a14b6d-3c52-4d90-8f1b-5a9c0d2e6b47"   # ships siem.default_enabled: false


def _only_default_off(summaries):
    """Every rule that is not enabled must be a default-off rule (nothing else
    may be silently off)."""
    return {s["id"] for s in summaries if not s["enabled"]}


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
                    "stateful", "mitre", "enabled", "default_enabled", "opt_in"):
            check(key in s, f"summary missing key {key!r}: {s}")
        check("condition" not in s, "summary must NEVER leak the raw condition")
        if s["id"] != OPCUA:
            check(s["enabled"] is True, "no tenant context -> every default-on rule enabled")
    # a stateful rule (brute-force) reports stateful=True; a single-shot one False.
    by_id = {s["id"]: s for s in summaries}
    # the default-off rule is reported OFF with the reason visible (positive control
    # for the new fields), and every other rule reports default_enabled True
    op = by_id.get(OPCUA)
    check(op is not None and op["enabled"] is False and op["default_enabled"] is False
          and op["opt_in"] is False,
          f"ot_opcua_write_unauthorized_node must list as off-by-default, got {op}")
    check(_only_default_off(summaries) == {OPCUA},
          f"only the default-off rule may be off with no tenant, got {_only_default_off(summaries)}")
    bf = by_id.get("6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01")
    check(bf is not None and bf["stateful"] is True,
          "brute-force rule should report stateful=True")


def test_malformed_tenant_id_disables_nothing():
    # A path-traversal-shaped tenant id must be rejected at the edge (never
    # normalized) -> _disabled_for_tenant returns empty -> every rule enabled,
    # no exception, no read outside TENANTS_DIR.
    summaries = rules_view.list_rule_summaries("../../etc/passwd")
    check(len(summaries) > 0, "malformed tenant must still return the rule set")
    check(_only_default_off(summaries) == {OPCUA},
          "a rejected tenant id must disable nothing and opt nothing in")


def test_unknown_tenant_disables_nothing():
    # A well-formed but unknown tenant (no contracts/tenants/<id>.yml) ->
    # nothing disabled, same fail-open-on-detection convention.
    summaries = rules_view.list_rule_summaries("nonexistent-tenant")
    check(_only_default_off(summaries) == {OPCUA},
          "an unknown tenant must leave every default-on rule enabled and opt nothing in")


def test_contracts_dir_container_layout():
    """Fixes the nagging zero-coverage gap on the CONTAINER branch of
    _contracts_dir(). On a Docker deployment _HERE = /app/ws3-indexer (only
    ONE parent up) and contracts live at /app/contracts; before the v0.5 fix
    GET /rules silently returned 0 rules on every live deployment because the
    two-parents-up host math didn't match. Simulate that layout in a temp dir
    and confirm _contracts_dir() resolves via the _SERVICES (=/app) probe and
    list_rule_summaries() actually reads the rule from it."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        app = Path(td) / "app"
        rules_dir = app / "contracts" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "container.yml").write_text(
            "id: ctr-rule\ntitle: container-rule\nlevel: medium\n",
            encoding="utf-8")
        # container math: _HERE=/app/ws3-indexer -> _SERVICES=/app,
        # _ROOT=_SERVICES.parent (in a real container that's /, no contracts).
        save = (rules_view._SERVICES, rules_view._ROOT,
                rules_view.RULES_DIR, rules_view.TENANTS_DIR)
        try:
            rules_view._SERVICES = app
            rules_view._ROOT = app.parent
            d = rules_view._contracts_dir()
            check(d == app / "contracts",
                  f"container layout must resolve to {app / 'contracts'}, got {d}")
            rules_view.RULES_DIR = d / "rules"
            rules_view.TENANTS_DIR = d / "tenants"
            summaries = rules_view.list_rule_summaries()
            check(any(s["id"] == "ctr-rule" for s in summaries),
                  "the container rule must be listed via the /app contracts dir")
        finally:
            (rules_view._SERVICES, rules_view._ROOT,
             rules_view.RULES_DIR, rules_view.TENANTS_DIR) = save


def test_companion_of_must_be_a_str_to_participate():
    """A list-valued siem.companion_of (a typo tools/validate_rules.py rejects,
    but this read model must not depend on the gate having run) is unhashable:
    `list in frozenset` raised TypeError and crashed the whole /rules listing.
    Only a non-empty str may name a sibling; a str companion still follows its
    sibling's tenant-disable (positive control)."""
    import tempfile
    sib = "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01"
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "rules").mkdir()
        (root / "tenants").mkdir()
        for name, extra in (("sib", ""),
                            ("comp", f"  companion_of: {sib}\n"),
                            ("listy", f"  companion_of: [{sib}]\n"),
                            ("dicty", f"  companion_of: {{a: {sib}}}\n"),
                            ("empty", "  companion_of: ''\n"),
                            ("nulled", "  companion_of:\n")):
            rid = sib if name == "sib" else f"00000000-0000-4000-8000-{name:0>12}"
            (root / "rules" / f"{name}.yml").write_text(
                f"id: {rid}\ntitle: {name}\nlevel: high\nsiem:\n  sector: common\n{extra}",
                encoding="utf-8")
        (root / "tenants" / "acme.yml").write_text(
            f"disabled_rules:\n  - {sib}\n", encoding="utf-8")
        save = (rules_view.RULES_DIR, rules_view.TENANTS_DIR)
        try:
            rules_view.RULES_DIR = root / "rules"
            rules_view.TENANTS_DIR = root / "tenants"
            try:
                everyone = {s["title"]: s for s in rules_view.list_rule_summaries()}
                acme = {s["title"]: s for s in rules_view.list_rule_summaries("acme")}
            except TypeError as exc:
                check(False, f"list_rule_summaries crashed on a non-str companion_of: {exc}")
                return
        finally:
            rules_view.RULES_DIR, rules_view.TENANTS_DIR = save
    check(len(everyone) == 6, f"all 6 rules must be listed, got {sorted(everyone)}")
    check(all(s["enabled"] for s in everyone.values()), "no tenant -> all enabled")
    check(not acme["comp"]["enabled"],
          "a str companion must follow its sibling's tenant-disable")
    check(not acme["sib"]["enabled"], "the disabled sibling itself is disabled")
    for odd in ("listy", "dicty", "empty", "nulled"):
        check(acme[odd]["enabled"],
              f"{odd}: a non-str/empty companion_of names no sibling -> stays enabled")


def test_default_off_and_opt_in_per_tenant():
    """siem.default_enabled: false -> enabled only for a tenant that lists the
    rule in enabled_rules (or via FENGARDE_OPT_IN_RULES); disabled wins; a broken
    tenant file opts nothing in; a companion of a default-off sibling is
    default-off itself."""
    import os
    import tempfile
    off = "11111111-1111-4111-8111-111111111111"
    on = "22222222-2222-4222-8222-222222222222"
    comp = "33333333-3333-4333-8333-333333333333"
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "rules").mkdir()
        (root / "tenants").mkdir()
        for name, rid, extra in (("off", off, "  default_enabled: false\n"),
                                 ("on", on, "  default_enabled: true\n"),
                                 ("typo", "44444444-4444-4444-8444-444444444444", "  default_enabled: 'false'\n"),
                                 ("comp", comp, f"  companion_of: {off}\n")):
            (root / "rules" / f"{name}.yml").write_text(
                f"id: {rid}\ntitle: r-{name}\nlevel: high\nsiem:\n  sector: common\n{extra}", encoding="utf-8")
        (root / "tenants" / "acme.yml").write_text(f"enabled_rules: [{off}]\n", encoding="utf-8")
        (root / "tenants" / "both.yml").write_text(
            f"enabled_rules: [{off}]\ndisabled_rules: [{off}]\n", encoding="utf-8")
        (root / "tenants" / "broken.yml").write_text("enabled_rules: [unclosed\n", encoding="utf-8")
        (root / "tenants" / "weird.yml").write_text("enabled_rules: 42\n", encoding="utf-8")
        (root / "tenants" / "compin.yml").write_text(f"enabled_rules: [{comp}]\n", encoding="utf-8")
        save = (rules_view.RULES_DIR, rules_view.TENANTS_DIR)
        saved_env = os.environ.pop("FENGARDE_OPT_IN_RULES", None)
        try:
            rules_view.RULES_DIR = root / "rules"
            rules_view.TENANTS_DIR = root / "tenants"

            def view(tenant):
                return {s["title"][2:]: s for s in rules_view.list_rule_summaries(tenant)}  # strip "r-"

            none, acme, other = view(None), view("acme"), view("globex")
            both, broken, weird, compin = view("both"), view("broken"), view("weird"), view("compin")
            os.environ["FENGARDE_OPT_IN_RULES"] = f" {off} , "
            env_view = view("globex")
        finally:
            rules_view.RULES_DIR, rules_view.TENANTS_DIR = save
            os.environ.pop("FENGARDE_OPT_IN_RULES", None)
            if saved_env is not None:
                os.environ["FENGARDE_OPT_IN_RULES"] = saved_env
    check(none["off"]["enabled"] is False and none["off"]["default_enabled"] is False
          and none["off"]["opt_in"] is False, f"no tenant: default-off rule is off, got {none['off']}")
    check(acme["off"]["enabled"] is True and acme["off"]["opt_in"] is True
          and acme["off"]["default_enabled"] is False, f"acme opted in: on with the reason kept, got {acme['off']}")
    check(other["off"]["enabled"] is False, "opt-in must not leak to another tenant")
    check(both["off"]["enabled"] is False, "disabled wins over enabled_rules")
    check(broken["off"]["enabled"] is False and weird["off"]["enabled"] is False,
          "a broken / wrong-shape tenant file must not opt anything in")
    check(broken["on"]["enabled"] and weird["on"]["enabled"], "...and must not turn a default-on rule off")
    check(none["on"]["enabled"] and none["on"]["default_enabled"] is True, "explicit default_enabled: true is on")
    check(none["typo"]["enabled"] is True and none["typo"]["default_enabled"] is True,
          "a non-bool default_enabled keeps the rule ON (engine convention; the validator rejects it)")
    check(none["comp"]["default_enabled"] is False and none["comp"]["enabled"] is False,
          "a companion of a default-off sibling is default-off")
    check(acme["comp"]["enabled"] is False, "opting the sibling in does not opt the companion in")
    check(compin["comp"]["enabled"] is True and compin["off"]["enabled"] is False,
          "opting the companion in does not opt the sibling in")
    check(env_view["off"]["enabled"] is True, "FENGARDE_OPT_IN_RULES opts the rule in for the view too")


def main():
    test_default_off_and_opt_in_per_tenant()
    test_companion_of_must_be_a_str_to_participate()
    test_contracts_dir_resolves_to_a_real_rules_dir()
    test_list_all_rules_no_tenant()
    test_malformed_tenant_id_disables_nothing()
    test_unknown_tenant_disables_nothing()
    test_contracts_dir_container_layout()
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
