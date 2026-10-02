"""F3 (adversarial repo-wide bug hunt, 2026-07-16) — tenant_id validation
in tenants.py::load_disabled_rules.

Before this fix, `tenant_id` flowed straight into `Path(tenants_dir) /
f"{tenant_id}.yml"` with no validation -- a malformed tenant_id containing
path-traversal sequences (e.g. "../../../etc/passwd") could construct a
path outside contracts/tenants/ entirely. This asserts a malformed
tenant_id is now treated exactly like a missing config file: fail open
(empty frozenset, nothing disabled, full detection coverage), no
exception, and -- provably -- no file is ever read from outside
tenants_dir.

Run: python services/ws4-detection/test_tenants.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

import tenants  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _fresh_dir_and_secret() -> tuple[Path, Path]:
    """A tenants_dir plus a sibling 'secret' file a path-traversal payload
    would try to reach -- e.g. tenants_dir/../secret.yml."""
    base = Path(tempfile.mkdtemp())
    tenants_dir = base / "tenants"
    tenants_dir.mkdir()
    secret = base / "secret.yml"
    secret.write_text("disabled_rules: [common_bruteforce]\n", encoding="utf-8")
    return tenants_dir, secret


def test_path_traversal_tenant_id_fails_open_no_exception():
    tenants_dir, secret = _fresh_dir_and_secret()
    tenants._CACHE.clear()

    for bad in ("../secret", "../../secret", "..%2Fsecret", "a/../../secret"):
        disabled = tenants.load_disabled_rules(tenants_dir, bad)
        check(disabled == frozenset(), f"path-traversal tenant_id={bad!r} must fail open, got {disabled!r}")


def test_path_traversal_tenant_id_never_reads_outside_tenants_dir():
    tenants_dir, secret = _fresh_dir_and_secret()
    tenants._CACHE.clear()

    # If the guard were missing, "../secret" would resolve to tenants_dir/../secret.yml
    # == secret.yml, and its disabled_rules entry (common_bruteforce) would leak in.
    disabled = tenants.load_disabled_rules(tenants_dir, "../secret")
    check("common_bruteforce" not in disabled,
          "a path-traversal tenant_id must never read the sibling secret.yml's contents")


def test_malformed_tenant_id_shapes_fail_open():
    tenants_dir, _ = _fresh_dir_and_secret()
    tenants._CACHE.clear()

    for bad in ("UPPER", "has space", "-leading", "trailing-", "", "a" * 64):
        disabled = tenants.load_disabled_rules(tenants_dir, bad)
        check(disabled == frozenset(), f"malformed tenant_id={bad!r} must fail open, got {disabled!r}")


def test_valid_tenant_and_default_still_load_normally():
    tenants_dir, _ = _fresh_dir_and_secret()
    tenants._CACHE.clear()

    (tenants_dir / "acme-corp.yml").write_text("disabled_rules: [common_bruteforce]\n", encoding="utf-8")
    disabled = tenants.load_disabled_rules(tenants_dir, "acme-corp")
    check(disabled == frozenset({"common_bruteforce"}),
          f"a valid tenant_id's real config must still load, got {disabled!r}")

    default_disabled = tenants.load_disabled_rules(tenants_dir, "default")
    check(default_disabled == frozenset(), f"default tenant with no config file must be empty, got {default_disabled!r}")


def test_invalid_tenant_id_never_cached():
    """P2-1 (2026-07-21 audit): an invalid tenant_id must NOT be written to
    _CACHE -- caching it would let an attacker grow the dict for free with
    unlimited distinct garbage strings, defeating the LRU cap's purpose."""
    tenants_dir, _ = _fresh_dir_and_secret()
    tenants._CACHE.clear()

    tenants.load_disabled_rules(tenants_dir, "../secret")
    cache_key = f"{Path(tenants_dir).resolve()}::../secret"
    check(cache_key not in tenants._CACHE,
          "invalid tenant_id must not be written to _CACHE at all")


def test_cache_is_bounded_under_many_distinct_tenants():
    """P2-1: valid-shaped but distinct tenant_id values must not grow
    _CACHE past _CACHE_MAXSIZE (LRU eviction caps memory)."""
    tenants_dir, _ = _fresh_dir_and_secret()
    tenants._CACHE.clear()

    n = tenants._CACHE_MAXSIZE + 200
    for i in range(n):
        tenants.load_disabled_rules(tenants_dir, f"tenant{i:06d}")

    check(len(tenants._CACHE) <= tenants._CACHE_MAXSIZE,
          f"_CACHE grew to {len(tenants._CACHE)}, expected <= {tenants._CACHE_MAXSIZE}")


# ---------------------------------------------------------------------------
# Default-off rules + per-tenant opt-in (2026-10-02, owner decision for
# ot_opcua_write_unauthorized_node).
#
#   siem.default_enabled: false   -> the rule is NOT evaluated for a tenant
#                                    unless that tenant opts in
#   contracts/tenants/<t>.yml     -> enabled_rules: [<rule id>, ...]
#   Detector(opt_in_rules=[...])  -> opts a rule in for ALL tenants
#   FENGARDE_OPT_IN_RULES=a,b     -> same, read once in Detector.__init__
#
# Fail-safe direction: opt-in is EXPLICIT. A missing/broken tenant config never
# turns a default-off rule ON and never turns a default-on rule off; a rule
# listed in both disabled_rules and enabled_rules is OFF (disabled wins).
# ---------------------------------------------------------------------------
OFF_RULE = "11111111-1111-4111-8111-111111111111"     # default_enabled: false
ON_RULE = "22222222-2222-4222-8222-222222222222"      # ordinary rule, same class
COMP_OF_OFF = "33333333-3333-4333-8333-333333333333"  # companion of OFF_RULE
COMP_OF_ON = "44444444-4444-4444-8444-444444444444"   # companion of ON_RULE
SHIPPED_OPCUA = "e7a14b6d-3c52-4d90-8f1b-5a9c0d2e6b47"


def _rule_yaml(rid: str, title: str, siem_extra: str = "", cls: int = 9999,
               activity: int | None = None) -> str:
    # a stateless, single-selection rule: matches any event of class `cls`
    act = f"    activity_id: {activity}\n" if activity is not None else ""
    return (f"title: {title}\nid: {rid}\nlevel: medium\n"
            f"detection:\n  sel:\n    class_uid: {cls}\n{act}  condition: sel\n"
            f"siem:\n  sector: common\n  score_weight: 0\n{siem_extra}")


def _synthetic_rules_dir(base: Path) -> Path:
    rules = base / "rules"
    rules.mkdir()
    # activity 1 is matched by the two siblings, 7 only by the default-off sibling's
    # companion, 8 only by the default-on sibling's companion: a companion therefore
    # matches ALONE (the sibling does not), so companion suppression cannot mask
    # whether the opt-in gate works.
    (rules / "off.yml").write_text(
        _rule_yaml(OFF_RULE, "off", "  default_enabled: false\n", activity=1), encoding="utf-8")
    (rules / "on.yml").write_text(_rule_yaml(ON_RULE, "on", activity=1), encoding="utf-8")
    (rules / "comp_of_off.yml").write_text(
        _rule_yaml(COMP_OF_OFF, "comp-off", f"  companion_of: {OFF_RULE}\n", activity=7),
        encoding="utf-8")
    (rules / "comp_of_on.yml").write_text(
        _rule_yaml(COMP_OF_ON, "comp-on", f"  companion_of: {ON_RULE}\n", activity=8),
        encoding="utf-8")
    (base / "allowlists").mkdir()
    return rules


def _detector(base: Path, tenants_dir: Path, **kw):
    import main as ws4main
    return ws4main.Detector(tenants_dir=tenants_dir, rules_dir=_synthetic_rules_dir(base),
                            allowlists_dir=base / "allowlists", plugin_rule_dirs=[], **kw)


def _matched_ids(det, tenant: str | None, activity: int = 1) -> set:
    event = {"class_uid": 9999, "activity_id": activity,
             "siem": {"ingest_id": f"i-{tenant}-{activity}"}}
    if tenant is not None:
        event["siem"]["tenant"] = tenant
    _ev, matched, _action = det.process(event)
    return {r.id for r in matched}


def _opt_in_setup():
    tenants._CACHE.clear()
    base = Path(tempfile.mkdtemp())
    tdir = base / "tenants"
    tdir.mkdir()
    return base, tdir


def test_rule_default_enabled_attribute():
    import yaml
    from engine import Rule
    off = Rule(yaml.safe_load(_rule_yaml(OFF_RULE, "off", "  default_enabled: false\n")))
    on = Rule(yaml.safe_load(_rule_yaml(ON_RULE, "on")))
    explicit = Rule(yaml.safe_load(_rule_yaml(ON_RULE, "on", "  default_enabled: true\n")))
    check(off.default_enabled is False, "default_enabled: false must load as False")
    check(on.default_enabled is True, "an absent default_enabled must default to True")
    check(explicit.default_enabled is True, "default_enabled: true must load as True")
    # a typo'd non-bool value keeps the rule ON (llm_gate convention: `is not False`);
    # tools/validate_rules.py rejects it at the gate, the engine never crashes on it
    typo = Rule(yaml.safe_load(_rule_yaml(ON_RULE, "on", "  default_enabled: 'false'\n")))
    check(typo.default_enabled is True, "a non-bool default_enabled must not silently switch a rule off")


def test_enabled_rules_loader_shape_and_fail_safe():
    base, tdir = _opt_in_setup()
    check(tenants.load_enabled_rules(tdir, "acme") == frozenset(),
          "missing tenant file -> nothing opted in")
    (tdir / "acme.yml").write_text(f"enabled_rules:\n  - {OFF_RULE}\n  - 7\n  - null\n", encoding="utf-8")
    tenants.invalidate_cache()
    check(tenants.load_enabled_rules(tdir, "acme") == frozenset({OFF_RULE}),
          "enabled_rules keeps only string ids (same shape rule as disabled_rules)")
    # only disabled_rules present -> enabled empty (and vice versa)
    (tdir / "globex.yml").write_text("disabled_rules: [aaa]\n", encoding="utf-8")
    check(tenants.load_enabled_rules(tdir, "globex") == frozenset(), "no enabled_rules key -> empty")
    check(tenants.load_disabled_rules(tdir, "acme") == frozenset(), "no disabled_rules key -> empty")
    # wrong shapes fail safe: nothing opted in
    for body in ("enabled_rules: not-a-list\n", "enabled_rules: {a: b}\n", "[1, 2]\n",
                 "enabled_rules: [unclosed\n", ""):
        (tdir / "weird.yml").write_text(body, encoding="utf-8")
        tenants.invalidate_cache()
        check(tenants.load_enabled_rules(tdir, "weird") == frozenset(),
              f"malformed tenant config {body!r} must opt nothing in")
    # invalid tenant ids (path traversal etc.) never read a file and never opt in
    secret = tdir.parent / "secret.yml"
    secret.write_text(f"enabled_rules: [{OFF_RULE}]\n", encoding="utf-8")
    for bad in ("../secret", "UPPER", "", "a/../../secret"):
        check(tenants.load_enabled_rules(tdir, bad) == frozenset(),
              f"invalid tenant_id {bad!r} must opt nothing in")
    check(f"{Path(tdir).resolve()}::../secret" not in tenants._CACHE,
          "an invalid tenant_id must never be cached by the enabled loader either")


def test_enabled_and_disabled_share_one_cache_correctly():
    """The two loaders read the SAME file. Whichever runs first must not leave a
    half-populated cache entry that makes the other return a wrong (empty) set,
    and invalidate_cache() must drop both."""
    base, tdir = _opt_in_setup()
    path = tdir / "acme.yml"
    path.write_text(f"disabled_rules: [{ON_RULE}]\nenabled_rules: [{OFF_RULE}]\n", encoding="utf-8")
    check(tenants.load_disabled_rules(tdir, "acme") == frozenset({ON_RULE}), "disabled first: disabled ok")
    check(tenants.load_enabled_rules(tdir, "acme") == frozenset({OFF_RULE}),
          "enabled after a disabled-first load must still see enabled_rules (shared cache entry)")
    tenants.invalidate_cache()
    check(tenants.load_enabled_rules(tdir, "acme") == frozenset({OFF_RULE}), "enabled first: enabled ok")
    check(tenants.load_disabled_rules(tdir, "acme") == frozenset({ON_RULE}),
          "disabled after an enabled-first load must still see disabled_rules")
    # cached: an on-disk edit is NOT seen until invalidate_cache() ...
    path.write_text(f"enabled_rules: [{ON_RULE}]\n", encoding="utf-8")
    check(tenants.load_enabled_rules(tdir, "acme") == frozenset({OFF_RULE}), "cached until invalidated")
    check(tenants.load_disabled_rules(tdir, "acme") == frozenset({ON_RULE}), "disabled cached too")
    # ... and invalidate_cache() drops BOTH lists
    tenants.invalidate_cache()
    check(tenants.load_enabled_rules(tdir, "acme") == frozenset({ON_RULE}), "enabled reloaded after invalidate")
    check(tenants.load_disabled_rules(tdir, "acme") == frozenset(), "disabled reloaded after invalidate")


def test_default_off_rule_needs_opt_in_in_the_detector():
    base, tdir = _opt_in_setup()
    (tdir / "acme.yml").write_text(f"enabled_rules:\n  - {OFF_RULE}\n", encoding="utf-8")
    det = _detector(base, tdir)
    # negative controls: no tenant / unconfigured tenant -> the default-off rule is OFF
    # (the default-on rule is the control proving the event does match rules at all)
    check(_matched_ids(det, None) == {ON_RULE}, f"default tenant: only the ON rule, got {_matched_ids(det, None)}")
    check(_matched_ids(det, "globex") == {ON_RULE}, "unconfigured tenant: default-off rule stays OFF")
    # positive control: the opted-in tenant gets it, and ONLY that tenant
    check(_matched_ids(det, "acme") == {ON_RULE, OFF_RULE}, "acme opted in: default-off rule fires")
    check(_matched_ids(det, "globex") == {ON_RULE}, "opt-in must not leak to another tenant")
    # a companion of a default-off sibling is off unless opted in ITSELF
    check(COMP_OF_OFF not in _matched_ids(det, "acme", activity=7),
          "companion of a default-off sibling must stay off even when the sibling is opted in")
    # (activity 8 hits the default-on companion's own selection: it is not affected)
    check(COMP_OF_ON in _matched_ids(det, "globex", activity=8),
          "a companion of a default-ON sibling is unaffected by this feature")


def test_companion_of_default_off_sibling_opt_in_itself():
    base, tdir = _opt_in_setup()
    (tdir / "acme.yml").write_text(f"enabled_rules: [{COMP_OF_OFF}]\n", encoding="utf-8")
    det = _detector(base, tdir)
    check(COMP_OF_OFF in _matched_ids(det, "acme", activity=7),
          "a companion opted in itself fires")
    check(OFF_RULE not in _matched_ids(det, "acme"),
          "opting the companion in must not opt the sibling in")
    check(COMP_OF_OFF not in _matched_ids(det, "globex", activity=7),
          "the companion is still off for a tenant that did not opt in")


def test_opt_in_kwarg_enables_for_every_tenant():
    base, tdir = _opt_in_setup()
    det = _detector(base, tdir, opt_in_rules=[OFF_RULE])
    for tenant in (None, "acme", "globex"):
        check(OFF_RULE in _matched_ids(det, tenant), f"opt_in_rules kwarg must enable tenant={tenant!r}")
    check(_matched_ids(_detector(Path(tempfile.mkdtemp()), tdir), "acme") == {ON_RULE},
          "negative control: without the kwarg the rule stays off")
    # kwarg accepts any iterable, ignores blanks, and an unknown id is harmless
    det2 = _detector(Path(tempfile.mkdtemp()), tdir, opt_in_rules=iter(["", "  ", "no-such-rule"]))
    check(_matched_ids(det2, "acme") == {ON_RULE}, "blank / unknown opt-in ids opt nothing in")


def test_opt_in_env_var_for_single_tenant_installs():
    import os
    base, tdir = _opt_in_setup()
    saved = os.environ.get("FENGARDE_OPT_IN_RULES")
    try:
        os.environ["FENGARDE_OPT_IN_RULES"] = f" {OFF_RULE} , ,{COMP_OF_OFF}"
        det = _detector(base, tdir)
        check(OFF_RULE in _matched_ids(det, None), "FENGARDE_OPT_IN_RULES must opt the rule in (default tenant)")
        check(OFF_RULE in _matched_ids(det, "acme"), "FENGARDE_OPT_IN_RULES applies to every tenant")
        os.environ.pop("FENGARDE_OPT_IN_RULES")
        det2 = _detector(Path(tempfile.mkdtemp()), tdir)
        check(OFF_RULE not in _matched_ids(det2, None), "negative control: env var unset -> rule stays off")
        os.environ["FENGARDE_OPT_IN_RULES"] = ""
        det3 = _detector(Path(tempfile.mkdtemp()), tdir)
        check(OFF_RULE not in _matched_ids(det3, None), "empty env var opts nothing in")
    finally:
        if saved is None:
            os.environ.pop("FENGARDE_OPT_IN_RULES", None)
        else:
            os.environ["FENGARDE_OPT_IN_RULES"] = saved


def test_disabled_wins_over_every_opt_in():
    base, tdir = _opt_in_setup()
    (tdir / "acme.yml").write_text(
        f"disabled_rules: [{OFF_RULE}]\nenabled_rules: [{OFF_RULE}]\n", encoding="utf-8")
    det = _detector(base, tdir, opt_in_rules=[OFF_RULE])
    check(OFF_RULE not in _matched_ids(det, "acme"),
          "a rule in BOTH lists (and in the kwarg) is OFF: disabled wins")
    check(OFF_RULE in _matched_ids(det, "globex"), "control: the kwarg still opts it in for another tenant")
    # disabled-only on a default-ON rule still works (nothing else changed)
    (tdir / "initech.yml").write_text(f"disabled_rules: [{ON_RULE}]\n", encoding="utf-8")
    check(ON_RULE not in _matched_ids(det, "initech"), "tenant-disabling a default-on rule still works")


def test_broken_tenant_config_never_flips_a_rule():
    base, tdir = _opt_in_setup()
    (tdir / "acme.yml").write_text("enabled_rules: [unclosed\n  - : :\n", encoding="utf-8")
    (tdir / "globex.yml").write_text("enabled_rules: 42\ndisabled_rules: nope\n", encoding="utf-8")
    det = _detector(base, tdir)
    for tenant in ("acme", "globex"):
        got = _matched_ids(det, tenant)
        check(OFF_RULE not in got, f"{tenant}: a broken config must never turn a default-OFF rule on")
        check(ON_RULE in got, f"{tenant}: a broken config must never turn a default-ON rule off")


def test_hot_reload_picks_up_a_tenant_opt_in_edit():
    base, tdir = _opt_in_setup()
    det = _detector(base, tdir)
    check(OFF_RULE not in _matched_ids(det, "acme"), "before the edit the rule is off")
    (tdir / "acme.yml").write_text(f"enabled_rules: [{OFF_RULE}]\n", encoding="utf-8")
    check(OFF_RULE not in _matched_ids(det, "acme"), "cached: not visible until the watcher invalidates")
    # what start_rule_reload_watcher does on a changed fingerprint:
    import main as ws4main
    before = ws4main.rules_fingerprint(det.rules_dir, det.allowlists_dir, tdir)
    check(any(n == "acme.yml" for n, _ in before), "the tenants dir is part of the reload fingerprint")
    tenants.invalidate_cache()
    det.reload()
    check(OFF_RULE in _matched_ids(det, "acme"), "after invalidate + reload the opt-in is live")
    # and a rules-dir edit that flips default_enabled is picked up by reload() itself
    (det.rules_dir / "off.yml").write_text(_rule_yaml(OFF_RULE, "off", activity=1), encoding="utf-8")  # now default-on
    det.reload()
    check(OFF_RULE in _matched_ids(det, "globex"), "reload() re-reads siem.default_enabled from the rule file")


def test_shipped_opcua_rule_is_default_off_and_opt_in_works():
    """The product default for ot_opcua_write_unauthorized_node: OFF. Positive and
    negative controls on a REAL parsed+enriched OPC UA write."""
    import copy
    sys.path.insert(0, str(SERVICES / "ws2-normalization"))
    from parsers import _REGISTRY
    from enrichment import enrich
    import main as ws4main
    in_hours = 1_751_536_800_000          # Thu 2025-07-03 10:00:00 UTC (no time-based OT rule sees it)
    raw = {"eventType": "AuditWriteUpdateEventType", "clientUserId": "ot-engineer",
           "clientAddress": "10.20.0.50", "serverId": "opcua-line3",
           "nodeId": "ns=2;s=Line3/PumpEnable", "status": "Success", "time": in_hours}
    meta = {"received_at": in_hours, "ingest_id": "opt-in-opcua-0", "tenant_id": "acme"}
    parsed = _REGISTRY["opcua_audit"].parse({"source_type": "opcua_audit", "raw": raw, "meta": meta})
    base_event = enrich(parsed)

    def fired(det) -> bool:
        _ev, matched, _a = det.process(copy.deepcopy(base_event))
        return SHIPPED_OPCUA in {r.id for r in matched}

    tenants._CACHE.clear()
    tdir = Path(tempfile.mkdtemp())
    check(fired(ws4main.Detector(tenants_dir=tdir, plugin_rule_dirs=[])) is False,
          "PRODUCT DEFAULT: a default Detector must NOT fire ot_opcua_write_unauthorized_node")
    check(fired(ws4main.Detector(tenants_dir=tdir, plugin_rule_dirs=[], opt_in_rules=[SHIPPED_OPCUA])) is True,
          "opt-in via the kwarg fires it")
    # control: the rule itself is healthy (loaded, evaluates True) -- only the gate keeps it off
    det = ws4main.Detector(tenants_dir=tdir, plugin_rule_dirs=[])
    rule = next(r for r in det.rules if r.id == SHIPPED_OPCUA)
    check(rule.default_enabled is False, "the shipped rule must declare siem.default_enabled: false")
    check(rule.evaluate(copy.deepcopy(base_event)) is True, "control: the rule matches this event when evaluated directly")
    (tdir / "acme.yml").write_text(f"enabled_rules: [{SHIPPED_OPCUA}]\n", encoding="utf-8")
    tenants._CACHE.clear()
    check(fired(ws4main.Detector(tenants_dir=tdir, plugin_rule_dirs=[])) is True,
          "opt-in via contracts/tenants/<tenant>.yml enabled_rules fires it for that tenant")
    (tdir / "acme.yml").write_text(
        f"enabled_rules: [{SHIPPED_OPCUA}]\ndisabled_rules: [{SHIPPED_OPCUA}]\n", encoding="utf-8")
    tenants._CACHE.clear()
    check(fired(ws4main.Detector(tenants_dir=tdir, plugin_rule_dirs=[], opt_in_rules=[SHIPPED_OPCUA])) is False,
          "disabled wins over both opt-ins")
    # a different tenant is unaffected by acme's opt-in
    other = copy.deepcopy(base_event)
    other["siem"]["tenant"] = "globex"
    (tdir / "acme.yml").write_text(f"enabled_rules: [{SHIPPED_OPCUA}]\n", encoding="utf-8")
    tenants._CACHE.clear()
    _ev, matched, _a = ws4main.Detector(tenants_dir=tdir, plugin_rule_dirs=[]).process(other)
    check(SHIPPED_OPCUA not in {r.id for r in matched}, "acme's opt-in must not enable the rule for globex")


def test_never_fired_gauge_skips_unopted_default_off_rules():
    """rule_never_fired flags DEAD rules; a rule that is off by design is not dead."""
    base, tdir = _opt_in_setup()
    off_gauge = f"rule_never_fired:{OFF_RULE}"
    check(off_gauge not in _detector(base, tdir).rule_health_metrics(),
          "a default-off, un-opted-in rule must not be reported as a dead rule")
    opted = _detector(Path(tempfile.mkdtemp()), tdir, opt_in_rules=[OFF_RULE])
    check(opted.rule_health_metrics().get(off_gauge) == 1,
          "once opted in, a never-fired rule IS reported (control)")


def run():
    test_path_traversal_tenant_id_fails_open_no_exception()
    test_path_traversal_tenant_id_never_reads_outside_tenants_dir()
    test_malformed_tenant_id_shapes_fail_open()
    test_valid_tenant_and_default_still_load_normally()
    test_invalid_tenant_id_never_cached()
    test_cache_is_bounded_under_many_distinct_tenants()
    test_rule_default_enabled_attribute()
    test_enabled_rules_loader_shape_and_fail_safe()
    test_enabled_and_disabled_share_one_cache_correctly()
    test_default_off_rule_needs_opt_in_in_the_detector()
    test_companion_of_default_off_sibling_opt_in_itself()
    test_opt_in_kwarg_enables_for_every_tenant()
    test_opt_in_env_var_for_single_tenant_installs()
    test_disabled_wins_over_every_opt_in()
    test_broken_tenant_config_never_flips_a_rule()
    test_hot_reload_picks_up_a_tenant_opt_in_edit()
    test_shipped_opcua_rule_is_default_off_and_opt_in_works()
    test_never_fired_gauge_skips_unopted_default_off_rules()


def main():
    run()
    if FAILS:
        print(f"[FAIL] tenants (disable + default-off opt-in): {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] F3: tenants.load_disabled_rules fails open (no exception, empty frozenset, "
          "no read outside tenants_dir) for a malformed/path-traversal-shaped tenant_id; "
          "valid tenants and the default sentinel still load normally. Default-off rules "
          "(siem.default_enabled: false) run only for a tenant that opts in "
          "(enabled_rules / opt_in_rules kwarg / FENGARDE_OPT_IN_RULES); a broken config "
          "never flips a rule, disabled wins, ot_opcua_write_unauthorized_node is OFF by default")


if __name__ == "__main__":
    main()
