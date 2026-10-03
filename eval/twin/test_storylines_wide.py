"""Acceptance test for the wave-2 storyline infrastructure and the phishing_bec storyline (2026-10-03).

Standalone (NOT pytest): ``[OK]``/``[FAIL]`` lines, exit 0 only when every check passes. Run:

    python eval/twin/test_storylines_wide.py

Every instrument added here is tested with a POSITIVE and a NEGATIVE control:

  (a) registry discovery      a storyline module is found and registered; a broken one (no STORYLINE) and a
                              duplicate name FAIL LOUDLY instead of being skipped
  (b) oracle provenance       the oracle matches the rule text it was authored from; a changed rule threshold,
                              an unlisted rule and a "pipeline already run" claim each fail the check
  (c) reconciler kinds        must_not_fire, unknown rule ids, untagged gaps, the stale-gap/decorative tripwire
                              and campaign_membership (REPORTED, never gated); an unknown finding kind raises
  (d) negative twins          every twin differs from the attack by exactly one attribute, is silent while its
                              attribute restored fires; a deaf harness / a leaking negative are both caught
  (e) step_dependencies       evasion_search subset equivalence holds with them and FAILS without; an unmodelled
                              source is caught as adapter-missing; a periodic rule is searched:false
  (f) FastProbe parity        phishing_bec, including the jittered stream; a leaky counter fails parity
  (g) matrix attribution      a detection displaced onto its context step is not scored as lost; without the
                              oracle's step_dependencies it is
  (h) phishing_bec            parses on its real parsers (two declared gaps), deterministic, structure varies with
                              the seed, alerts follow the oracle order, decoys stay out of the attack's incident
                              (and a decoy moved onto the victim's account IS absorbed)
"""
from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TWIN = Path(__file__).resolve().parent
ADVERSARIAL = ROOT / "eval" / "adversarial"
SERVICES = ROOT / "services"
for _p in (str(ADVERSARIAL), str(TWIN), str(SERVICES)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import layer_a  # noqa: E402  (import order: report.py collision guard, as test_scenario_harness)
import evasion_search  # noqa: E402
import mutate_generic as mg  # noqa: E402
import oracle_consistency as oc  # noqa: E402
import oracle_provenance as prov  # noqa: E402
import probe_session  # noqa: E402
import scenario  # noqa: E402
import scenario_matrix  # noqa: E402
import scenario_registry as reg  # noqa: E402

SEED = 7
SD = reg.BY_NAME["phishing_bec"]
_FAILURES: list = []


def _check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        _FAILURES.append(name)


# --------------------------------------------------------------------------
def test_registry_discovery() -> None:
    names = [s.name for s in reg.ALL]
    _check("(a) the registry lists the three built-ins first, in their historical order, then the discovered "
           "storylines", names[:3] == ["ai_to_ot", "it_intrusion", "infra_takeover"] and "phishing_bec" in names[3:],
           str(names))
    tmp = Path(tempfile.mkdtemp(prefix="storydisc_"))
    try:
        (tmp / "storyline_ok.py").write_text(
            "from pathlib import Path\nimport sys\nsys.path.insert(0, %r)\nimport scenario\n"
            "STORYLINE = scenario.ScenarioDef(name='disc_ok', steps=(), build=lambda s: ([], {}, {}, None),\n"
            "                                 oracle_path=Path('x.yaml'))\n" % str(TWIN), encoding="utf-8")
        found = reg._discover(tmp)
        _check("(a) POSITIVE: a storyline_*.py exporting STORYLINE is discovered", [s.name for s in found] == ["disc_ok"])
        (tmp / "storyline_broken.py").write_text("X = 1\n", encoding="utf-8")
        try:
            reg._discover(tmp)
            raised = False
        except RuntimeError as exc:
            raised = "must export STORYLINE" in str(exc)
        _check("(a) NEGATIVE: a storyline module with no STORYLINE fails LOUDLY (never silently skipped)", raised)
    finally:
        for mod in ("storyline_ok", "storyline_broken"):
            sys.modules.pop(mod, None)
        if str(tmp) in sys.path:
            sys.path.remove(str(tmp))
        shutil.rmtree(tmp, ignore_errors=True)
    _check("(a) the real registry has unique names", len(names) == len(set(names)))


# --------------------------------------------------------------------------
def test_provenance() -> None:
    oracle = reg.load_oracle(SD)
    _check("(b) POSITIVE: phishing_bec's oracle still matches the rule text it was authored from",
           prov.check(oracle) == [], str(prov.check(oracle)))
    _check("(b) an oracle with no provenance block has nothing to check (None, not a pass)",
           prov.check({"detection_points": {}}) is None)
    tmp = Path(tempfile.mkdtemp(prefix="provrules_"))
    try:
        for f in (ROOT / "contracts" / "rules").glob("*.yml"):
            shutil.copy(f, tmp / f.name)
        spray = tmp / "common_password_spray.yml"
        spray.write_text(spray.read_text(encoding="utf-8").replace("threshold: 8", "threshold: 9"), encoding="utf-8")
        probs = prov.check(oracle, rules_dir=tmp)
        _check("(b) NEGATIVE: a rule whose threshold changed since the oracle was authored FAILS the check, "
               "naming the rule", any("common_password_spray" in p and "changed" in p for p in probs), str(probs))
        beac = tmp / "common_beaconing.yml"
        txt = beac.read_text(encoding="utf-8")
        rewrapped = txt.replace("of inter-arrival times", "of\n  inter-arrival   times")
        beac.write_text(rewrapped, encoding="utf-8")
        probs = prov.check(oracle, rules_dir=tmp)
        _check("(b) re-wrapping a description's whitespace does NOT change the digest (and the file really "
               "was rewritten, so this is not vacuous)",
               rewrapped != txt and not any("common_beaconing" in p for p in probs), str(probs))
        beac.write_text(txt.replace("max_cv: 0.25", "max_cv: 0.30"), encoding="utf-8")
        probs = prov.check(oracle, rules_dir=tmp)
        _check("(b) NEGATIVE: loosening the periodicity bound changes the digest (the siem block is pinned)",
               any("common_beaconing" in p for p in probs), str(probs))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    o2 = copy.deepcopy(oracle)
    del o2["provenance"]["rules_read"]["common_impossible_travel"]
    _check("(b) NEGATIVE: an oracle relying on a rule it does not list as read FAILS",
           any("common_impossible_travel" in p for p in prov.check(o2)))
    o3 = copy.deepcopy(oracle)
    o3["provenance"]["pipeline_run_before_authoring"] = True
    _check("(b) NEGATIVE: an oracle that admits the pipeline was run before it was authored FAILS",
           any("pipeline_run_before_authoring" in p for p in prov.check(o3)))
    o4 = copy.deepcopy(oracle)
    o4["detection_points"]["c2_beacon"]["must_not_fire"] = ["00000000-0000-4000-8000-00000000dead"]
    _check("(b) NEGATIVE: a must_not_fire id that is not a shipped rule FAILS the provenance check",
           any("not a shipped rule" in p for p in prov.check(o4)))


# --------------------------------------------------------------------------
def test_reconciler_kinds() -> None:
    oracle = reg.load_oracle(SD)
    grade = reg.grade(SD, SEED)
    base = oc.reconcile(SEED, SD, oracle=oracle, grade=grade)
    _check("(c) POSITIVE: the intent-first oracle agrees with the pipeline (only the accepted order-blind "
           "forbidden edges remain)", not base["new"] and not base["stale_allowlist_entries"]
           and not base["stale_gaps"] and not base["decorative_expectations"] and not base["unexpected_firings"]
           and not base["forbidden_rules_fired"] and not base["gaps_without_technique"],
           f"new={base['new']} stale={base['stale_allowlist_entries']}")
    _check("(c) POSITIVE: the oracle's campaign_membership agrees with the run (nothing to report)",
           base["campaign_report"] == [], str(base["campaign_report"]))

    spray = "4f8a2c61-9e3d-4b57-8a1c-6d2e5f7a8b90"
    o = copy.deepcopy(oracle)
    o["detection_points"]["proxy_pool_logins"]["must_not_fire"] = [spray]
    f = oc.reconcile(SEED, SD, oracle=o, grade=grade)
    _check("(c) NEGATIVE: a rule listed in must_not_fire that fires -> a gating forbidden_rule finding",
           [x["rule_id"] for x in f["forbidden_rules_fired"]] == [spray] and f["new"]
           and f["new"][0]["kind"] == "forbidden_rule", str(f["new"]))
    o = copy.deepcopy(oracle)
    o["detection_points"]["c2_beacon"]["must_not_fire"] = ["00000000-0000-4000-8000-00000000dead"]
    f = oc.reconcile(SEED, SD, oracle=o, grade=grade)
    _check("(c) NEGATIVE: a must_not_fire id that is not a shipped rule is itself a finding "
           "(a typo would make the control vacuous)", len(f["unknown_must_not_fire"]) == 1 and f["new"])
    o = copy.deepcopy(oracle)
    del o["detection_points"]["payment_redirect"]["gap"]["attack_technique"]
    f = oc.reconcile(SEED, SD, oracle=o, grade=grade)
    _check("(c) NEGATIVE: a non-context gap with no attack_technique -> gating gap_technique finding",
           [x["step"] for x in f["gaps_without_technique"]] == ["payment_redirect"])
    _check("(c) ...while the CONTEXT step (victim_session) needs no technique", "victim_session" not in
           [x["step"] for x in base["gaps_without_technique"]])
    # the stale-gap / decorative tripwire: a declared gap that the pipeline contradicts
    o = copy.deepcopy(oracle)
    o["detection_points"]["phish_delivery"]["expected_rules"] = [{"rule_id": spray, "level": "high"}]
    o["detection_points"]["phish_delivery"]["gap"] = {"no_rule_exists": False}
    f = oc.reconcile(SEED, SD, oracle=o, grade=grade)
    _check("(c) NEGATIVE (tripwire): expecting a rule at a step where nothing fires is reported DECORATIVE",
           any(d["step"] == "phish_delivery" and d["rule_id"] == spray for d in f["decorative_expectations"]))
    o = copy.deepcopy(oracle)
    o["detection_points"]["proxy_pool_logins"]["gap"] = {"no_rule_exists": True, "attack_technique": "T1110.004",
                                                         "reason": "pretend it is a gap"}
    f = oc.reconcile(SEED, SD, oracle=o, grade=grade)
    _check("(c) NEGATIVE (tripwire): declaring a gap where a rule really fires is reported as a STALE GAP",
           any(s["step"] == "proxy_pool_logins" for s in f["stale_gaps"]))
    # campaign_membership: reported, never gated
    o = copy.deepcopy(oracle)
    o["campaign_membership"] = {"campaign_count": 5, "full_coverage": False}
    f = oc.reconcile(SEED, SD, oracle=o, grade=grade)
    _check("(c) campaign_membership that disagrees with the run is REPORTED ...",
           {x["field"] for x in f["campaign_report"]} == {"campaign_count", "full_coverage"}, str(f["campaign_report"]))
    _check("(c) ... and is NEVER a gating finding (owner decision: ADR-009/010 untouched)",
           f["total"] == base["total"] and f["new"] == base["new"])
    try:
        oc._key("x", "no_such_kind", {})
        raised = False
    except KeyError:
        raised = True
    _check("(c) an unknown finding kind raises (it used to fall through to from/to and KeyError by accident)", raised)
    _check("(c) every new kind has a waiver key shape",
           oc._key("s", "forbidden_rule", {"step": "a", "rule_id": "r"}) == ("s", "forbidden_rule", "a", "r")
           and oc._key("s", "gap_technique", {"step": "a"}) == ("s", "gap_technique", "a", ""))
    _check("(c) the gap-technique waiver table is CLOSED and dated",
           all(oc._DATED_REASON.match(v) for v in oc._GAP_TECHNIQUE_WAIVED.values()))


# --------------------------------------------------------------------------
def _by_step(payloads, label):
    return [json.dumps(p, sort_keys=True) for s, p in payloads if s.label == label]


def test_negative_twins() -> None:
    twins = SD.negatives
    _check("(d) phishing_bec declares a twin for each rule threshold its oracle leans on "
           "(spray 8 addresses, beacon 6 beats, beacon periodicity, impossible travel countries)",
           {t.name for t in twins} == {"spray_7_of_8_addresses", "beacon_5_of_6_beats", "beacon_irregular_interval",
                                       "login_same_country"}, str([t.name for t in twins]))
    res = scenario_matrix.run_negative_twins(SD, SEED)
    for r in res:
        _check(f"(d) {r['name']}: silent with the attribute reduced, fires with it restored "
               f"({r['negative_fired']} / {r['restored_fired']})", r["ok"] is True)
    for tw in twins:
        neg, pos = tw.build(SEED, False)[0], tw.build(SEED, True)[0]
        other = {s.label for s, _p in neg} | {s.label for s, _p in pos}
        diff = sorted(lab for lab in other if _by_step(neg, lab) != _by_step(pos, lab))
        _check(f"(d) {tw.name}: the negative and positive twins differ ONLY in step {tw.step!r} "
               "(one asserted attribute, same builder path)", diff == [tw.step], str(diff))
    # NEGATIVE controls for the consumer itself
    sp = next(t for t in twins if t.name == "spray_7_of_8_addresses")
    leaky = scenario.NegativeTwin(sp.name, sp.step, sp.rule_ids, "leaks: ignores the switch",
                                  lambda seed, restored: sp.build(seed, True))
    deaf = scenario.NegativeTwin(sp.name, sp.step, sp.rule_ids, "deaf: never restores",
                                 lambda seed, restored: sp.build(seed, False))

    class _Fake:
        negatives = (leaky, deaf)

    r_leaky, r_deaf = scenario_matrix.run_negative_twins(_Fake, SEED)
    _check("(d) NEGATIVE: a twin whose 'negative' secretly keeps the attribute (the rule fires) is NOT ok",
           r_leaky["negative_silent"] is False and r_leaky["ok"] is False)
    _check("(d) NEGATIVE: a harness deaf to the rule (the 'restored' twin stays silent) is NOT ok, so a silent "
           "negative alone proves nothing", r_deaf["restored_fires"] is False and r_deaf["ok"] is False)
    fake_result = {"scenarios": {"x": {"baseline": {"tpr": 1.0}, "rows": [
        {"axis": "timing", "variant": "shift_1h", "applicable": True, "pass": True},
        {"axis": "loss", "variant": "drop_a", "applicable": True, "pass": True, "steps_lost": ["a"]}],
        "overall": {"applicable": 2}, "negative_twins": [r_leaky]}}}
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()):
        gate_ok = scenario_matrix._selfcheck(fake_result)
    _check("(d) the matrix self-check FAILS on a failing twin (the consumer is a gate, not a printout)", gate_ok is False)


# --------------------------------------------------------------------------
def test_step_dependencies_and_vacuity() -> None:
    _check("(e) POSITIVE: with the oracle's step_dependencies, step-subset scoring equals full-stream scoring on "
           "phishing_bec (foreign_login keeps its context)", evasion_search.verify_subset_equivalence(SD, SEED) == [])
    real = evasion_search.step_dependencies
    try:
        evasion_search.step_dependencies = lambda oracle, step: ()
        bad = evasion_search.verify_subset_equivalence(SD, SEED)
    finally:
        evasion_search.step_dependencies = real
    _check("(e) NEGATIVE: WITHOUT them the check goes RED on foreign_login (this is what would have turned "
           "test_scenario_harness's subset-equivalence check red on landing)", bad == ["foreign_login"], str(bad))
    out = evasion_search.search_scenario(SD, SEED)
    rows = {r["step"]: r for r in out["rows"]}
    _check("(e) c2_beacon (a periodic rule) is searched:false with the reason 'periodic rule'",
           rows["c2_beacon"]["searched"] is False and rows["c2_beacon"]["reason"] == "periodic rule",
           str(rows["c2_beacon"]))
    pl = rows["proxy_pool_logins"]
    _check("(e) the credential-stuffing burst IS searched and the measured boundary equals the rule's declared "
           "parameters", pl["searched"] is True and pl["all_agree"] is True, str(pl.get("measured")))
    _check("(e) its account axis is genuinely probed (a vacuous 'immune' would be listed in vacuous_axes)",
           "account_k" not in pl["vacuous_axes"], str(pl["vacuous_axes"]))
    payloads = SD.build(SEED)[0]
    _check("(e) spread_vacuity: a cef burst is perturbed on the address axis (None == probed)",
           evasion_search.spread_vacuity(payloads, "proxy_pool_logins", "ip") is None)
    saved = mg._STR_IP_RX.pop("cef")
    try:
        vac = evasion_search.spread_vacuity(payloads, "proxy_pool_logins", "ip")
        broken = evasion_search.search_scenario(SD, SEED)
        broken_row = {r["step"]: r for r in broken["rows"]}["proxy_pool_logins"]
    finally:
        mg._STR_IP_RX["cef"] = saved
    _check("(e) NEGATIVE: with the cef address adapter removed the spread changes nothing although the parsed "
           "events DO carry an address -> 'adapter-missing', and the row FAILS instead of reading 'immune'",
           vac == "adapter-missing" and broken_row["all_agree"] is False and broken_row["agree"]["ip_k"] is False,
           f"vac={vac} agree={broken_row['agree']}")
    cisco = reg.BY_NAME["it_intrusion"].build(SEED)[0]
    _check("(e) a source with genuinely no such field (a port scan has no account) is 'field-absent', not an error",
           evasion_search.spread_vacuity(cisco, "recon_port_scan", "account") == "field-absent")


# --------------------------------------------------------------------------
def test_probe_parity() -> None:
    bad = probe_session.verify_parity(SD, SEED)
    _check("(f) FastProbe == report._real_detection on phishing_bec: baseline + thin / ip_rotate_2 / stretch_6x / "
           "jitter_100pct", bad == [], str(bad))
    _check("(f) state-leak A,B,A on one session is clean", probe_session.state_leak_check(SD, SEED))
    leaky = probe_session.FastProbe(strict_clock=False, reset_counter=False)
    _check("(f) NEGATIVE: a probe that never resets its counter FAILS parity on this storyline",
           bool(probe_session.verify_parity(SD, SEED, leaky)))


# --------------------------------------------------------------------------
def test_displaced_attribution() -> None:
    oracle = reg.load_oracle(SD)
    base = reg.grade(SD, SEED)
    payloads = SD.build(SEED)[0]
    mutated, _ch = mg.apply(payloads, "delivery", "reverse_arrival", seed=SEED, sdef=SD)
    grade = reg.grade(SD, SEED, payload_source=lambda _s: (mutated, {}, {}, None), strict=False)
    row = layer_a.cmp_result("delivery", "reverse_arrival", base, grade)
    row["expected_rule_lost_steps"] = scenario_matrix._expected_lost(oracle, base, grade)
    before = copy.deepcopy(row)
    _check("(g) the raw comparison reads reversed delivery as a LOST step (impossible travel is raised by the "
           "account's own earlier login, one step away)", before["steps_lost"] == ["foreign_login"]
           and before["pass"] is False, f"{before['steps_lost']}")
    scenario_matrix._reattribute_displaced(row, oracle, base, grade)
    _check("(g) POSITIVE: with the oracle's step_dependencies the detection is DISPLACED, not lost "
           "(reported, never silent)", row["steps_displaced"] == ["foreign_login"] and row["steps_lost"] == []
           and row["detection_retained"] is True, str({k: row.get(k) for k in ("steps_displaced", "steps_lost")}))
    row2 = copy.deepcopy(before)
    no_deps = {k: v for k, v in oracle.items() if k != "step_dependencies"}
    scenario_matrix._reattribute_displaced(row2, no_deps, base, grade)
    _check("(g) NEGATIVE: without step_dependencies nothing is reattributed (every pre-existing storyline is "
           "untouched)", row2 == before)
    _check("(g) dropping the CONTEXT step blinds its dependents by design (negative control for the context step)",
           scenario_matrix._dependents(oracle, "victim_session") == {"foreign_login"}
           and scenario_matrix._dependents(no_deps, "victim_session") == set())


# --------------------------------------------------------------------------
def test_phishing_bec() -> None:
    r1, r2 = reg.run(SD, SEED), reg.run(SD, SEED)
    expect = {s.label: s.parse_expected for s in SD.steps}
    gaps = sorted(s for s, ok in expect.items() if not ok)
    _check("(h) every parse_expected step parses on its REAL parser; exactly the two chained gaps are the "
           "no-parser steps", not r1.check_failures and all(e.parsed == expect[e.step] for e in r1.events)
           and gaps == ["inbox_rule", "phish_delivery"], f"gaps={gaps} failures={r1.check_failures[:2]}")
    _check("(h) same seed -> byte-identical chain", r1.canonical() == r2.canonical())
    _check("(h) the dead-letter integrity: exactly the two unparseable records dead-letter",
           r1.stats.get("dropped") == 2, str(r1.stats))
    sigs = []
    for seed in (7, 11, 13, 17):
        pl = SD.build(seed)[0]
        sigs.append((sum(1 for s, _ in pl if s.label == "proxy_pool_logins"),
                     sum(1 for s, _ in pl if s.label == "c2_beacon"),
                     next(mg.get_actor(p) for s, p in pl if s.label == "foreign_login")))
    _check("(h) the seed varies STRUCTURE (pool size, beat count), not only identifiers",
           len({(a, b) for a, b, _ in sigs}) > 1, str(sigs))
    _check("(h) pool size stays above the rule's 8 and beats above its 6 on every seed (margin for the twins)",
           all(a >= 9 and b >= 7 for a, b, _ in sigs))
    pl = SD.build(SEED)[0]
    _check("(h) the account is spelled identically on every parsed source (one WS-8 actor track)",
           len({mg.get_actor(p) for s, p in pl if s.parse_expected and mg.get_actor(p)}) == 1)
    g = reg.grade(SD, SEED)
    _check("(h) every expected rule fires at its step and the order of alerts follows the oracle",
           g["tpr"] == 1.0 and g["alert_order_ok"] is True and g["incident_membership_ok"] is True
           and g["incident_count"] == 1, f"tpr={g['tpr']} order={g['alert_order_ok']} incidents={g['incident_count']}")
    first = {}
    for a in g["fired"]:
        first.setdefault(a["step"], a["time"])
    seq = [s for s in reg.load_oracle(SD)["expected_sequence"] if s in first]
    _check("(h) first-alert times are MONOTONE in expected_sequence order",
           [first[s] for s in seq] == sorted(first[s] for s in seq), str({s: first[s] for s in seq}))
    # decoys
    def with_decoys(retarget_actor=None):
        def src(seed):
            p, sr, nt, b = SD.build(seed)
            extra = copy.deepcopy(SD.decoy(seed))
            if retarget_actor:
                for _s, e in extra:
                    mg.set_actor(e, retarget_actor)
            return sorted(list(p) + extra, key=lambda x: mg.get_time(x[1]) or 0), sr, nt, b
        return src

    gd = reg.grade(SD, SEED, payload_source=with_decoys())
    _check("(h) the benign VPN-roaming decoy FIRES (it is the documented false-positive shape of impossible "
           "travel) so there is something to contaminate", gd["decoy_alert_count"] > 0, f"{gd['decoy_alert_count']}")
    _check("(h) POSITIVE: a decoy on its own account is NOT absorbed into the attack's incident or campaign",
           gd["decoy_contamination"] == 0.0 and gd["campaign_decoy_contamination"] == 0.0,
           f"{gd['decoy_contamination']} {gd['campaign_decoy_contamination']}")
    victim = next(mg.get_actor(p) for s, p in pl if s.label == "foreign_login")
    gc = reg.grade(SD, SEED, payload_source=with_decoys(retarget_actor=victim))
    _check("(h) NEGATIVE CONTROL: the same decoy moved onto the VICTIM's account IS absorbed (the metric can go "
           "non-zero)", (gc["decoy_contamination"] or 0) > 0, f"{gc['decoy_contamination']}")
    # the honest-gap register
    gaps_t = sorted((s, pt["gap"]["attack_technique"]) for s, pt in reg.load_oracle(SD)["detection_points"].items()
                    if pt["gap"].get("no_rule_exists") and not pt.get("context"))
    _check("(h) the missing-rule register is exactly the four gaps the oracle declares, each with its ATT&CK id",
           gaps_t == [("inbox_rule", "T1114.003"), ("payment_redirect", "T1565.001"), ("phish_delivery", "T1566.001"),
                      ("user_execution", "T1204.002")], str(gaps_t))
    _check("(h) no invented rule: every rule the oracle expects is a shipped rule file",
           all(r["rule_id"] in oc._known_rule_ids()
               for pt in reg.load_oracle(SD)["detection_points"].values() for r in pt.get("expected_rules") or []))
    yaml.safe_load(Path(SD.oracle_path).read_text(encoding="utf-8"))


def main() -> int:
    test_registry_discovery()
    test_provenance()
    test_reconciler_kinds()
    test_negative_twins()
    test_step_dependencies_and_vacuity()
    test_probe_parity()
    test_displaced_attribution()
    test_phishing_bec()
    if _FAILURES:
        print(f"\n[FAIL] {len(_FAILURES)} check(s) failed:")
        for f in _FAILURES:
            print(f"   - {f}")
        return 1
    print("\n[OK] wide storylines: every new instrument passed its positive AND negative control.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
