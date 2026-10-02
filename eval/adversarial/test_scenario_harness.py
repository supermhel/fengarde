"""Acceptance test for the multi-storyline harness (2026-10-01).

Standalone (NOT pytest), same style as test_layer_a.py: ``[OK]``/``[FAIL]``
lines, exit 0 only when every check passes. Run:

    python eval/adversarial/test_scenario_harness.py

Every NEW measuring instrument added in this change is tested with a POSITIVE
and a NEGATIVE control -- a metric that has never been seen to go red is not
evidence of anything:

  (a) registry + scenario integrity     each storyline parses end to end on its
                                        REAL parsers, deterministically; the
                                        seed varies STRUCTURE for the new ones
  (b) burst MTTD                        measured to the event the rule fired on
  (c) directional discrimination        1.0 on a genuinely directional graph,
                                        0.0 when entities are shared (control)
  (d) alert order                       in-order True / swapped False / <2 None
  (e) decoy contamination               0.0 for disjoint decoys; > 0 when a
                                        decoy shares the attacker's address
  (f) generic operators                 honest about N/A; do what they say; never
                                        mutate their input
  (g) _cmp criteria                     order and decoys can fail a variant
  (h) matrix gate                       passes on a real scenario; cannot pass
                                        without its own controls
  (i) evasion search                    agrees with declared rule parameters AND
                                        flags a deliberate mismatch
  (j) oracle reconciliation             every storyline's oracle agrees with its
                                        own pipeline run (rule fix regression)
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADVERSARIAL = Path(__file__).resolve().parent
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
for _p in (str(ADVERSARIAL), str(TWIN), str(SERVICES)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import layer_a  # noqa: E402
import mutate_generic as mg  # noqa: E402
import oracle_consistency  # noqa: E402
import report  # noqa: E402
import scenario_matrix  # noqa: E402
import scenario_registry as reg  # noqa: E402
import evasion_search  # noqa: E402

SEED = 7
_FAILURES: list = []


def _check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        _FAILURES.append(name)


def _canon(result) -> str:
    return result.canonical()


# --------------------------------------------------------------------------
def test_registry_and_integrity() -> None:
    names = [s.name for s in reg.ALL]
    _check("(a) registry lists every storyline, names unique",
           len(names) == len(set(names)) >= 3, f"{names}")
    for sd in reg.ALL:
        oracle = reg.load_oracle(sd)
        _check(f"(a) {sd.name}: oracle expected_sequence == the scenario's step order",
               oracle["expected_sequence"] == [s.label for s in sd.steps],
               f"oracle={oracle['expected_sequence']} steps={[s.label for s in sd.steps]}")
        r1 = reg.run(sd, SEED)
        r2 = reg.run(sd, SEED)
        expect = {s.label: s.parse_expected for s in sd.steps}
        _check(f"(a) {sd.name}: every raw event parses on its REAL parser, and exactly the "
               "DECLARED gaps (steps with no registered parser) are the ones that don't",
               not r1.check_failures and all(e.parsed == expect[e.step] for e in r1.events),
               f"events={len(r1.events)} failures={r1.check_failures[:2]}")
        _check(f"(a) {sd.name}: same seed -> byte-identical chain", _canon(r1) == _canon(r2))
    # seed varies STRUCTURE for the new storylines (it does NOT for ai_to_ot --
    # that limitation is disclosed in layer_a.run_multi_seed, not hidden here)
    it = reg.BY_NAME["it_intrusion"]
    shapes = {tuple(sorted({s.label: sum(1 for x, _ in it.build(sd)[0] if x.label == s.label)
                            for s in it.steps}.items())) for sd in (7, 11, 13, 17)}
    _check("(a) it_intrusion: different seeds produce different burst SIZES (structure, not ids)",
           len(shapes) > 1, f"distinct shapes across 4 seeds: {len(shapes)}")
    ips = {it.build(sd)[0][0][1]["meta"]["ip"] for sd in (7, 11, 13, 17)}
    _check("(a) it_intrusion: the attacker address varies with the seed", len(ips) > 1, f"{sorted(ips)}")


def test_burst_mttd() -> None:
    it = reg.BY_NAME["it_intrusion"]
    g = reg.grade(it, SEED)
    # recon_port_scan is the first step; rule threshold 15 distinct ports, 2 s apart
    _check("(b) burst MTTD is the threshold-crossing event, not the step's first event",
           g["mttd_seconds"] == (15 - 1) * 2.0, f"mttd={g['mttd_seconds']} expected={(15 - 1) * 2.0}")
    ai = reg.grade(reg.BY_NAME["ai_to_ot"], SEED)
    _check("(b) single-event chain MTTD unchanged by the fix (frozen baseline)",
           ai["mttd_seconds"] == 60.0, f"{ai['mttd_seconds']}")


def test_directional_discrimination() -> None:
    fid = report._grade_chain_fidelity
    allowed = [{"from": "A", "to": "B", "allowed": True}]
    # POSITIVE: genuinely directional evidence -- x only at A, y only at B, edge x->y
    out = fid([{"from": "x", "to": "y", "kind": "k"}], {"A": {"x"}, "B": {"y"}}, allowed, ["A", "B"])
    _check("(c) directional graph -> directional_discrimination == 1.0 (forward joined, reverse not)",
           out["directional_discrimination"] == 1.0, f"{out['directional_discrimination']}")
    # NEGATIVE CONTROL: the shared-entity case -- both steps carry both entities
    out = fid([{"from": "x", "to": "y", "kind": "k"}], {"A": {"x", "y"}, "B": {"x", "y"}}, allowed, ["A", "B"])
    _check("(c) shared-entity graph -> directional_discrimination == 0.0 "
           "(the legacy predicate cannot tell a relation from its reverse)",
           out["directional_discrimination"] == 0.0, f"{out['directional_discrimination']}")
    _check("(c) ...while the legacy chain_fidelity still reports a perfect join for it "
           "(the number that was being trusted)",
           out["chain_fidelity"] == 1.0, f"chain_fidelity={out['chain_fidelity']}")
    for sd in reg.ALL:
        g = reg.grade(sd, SEED)
        _check(f"(c) {sd.name}: real graph's directional_discrimination is measured and < 0.5 "
               "(fidelity/FCR are entity-bridge checks here, and the baseline says so)",
               g["directional_discrimination"] is not None and g["directional_discrimination"] < 0.5,
               f"{g['directional_discrimination']}")
        bq = layer_a._baseline_quality(g)
        _check(f"(c) {sd.name}: baseline_quality carries the directional caveat",
               any("directional_discrimination" in c for c in bq["caveats"]),
               f"caveats={len(bq['caveats'])}")


def test_campaign_view() -> None:
    # the per-incident grade fails for a pivoting attack; the read-side campaign view
    # covers it. Both are reported -- neither replaces the other.
    it = reg.grade(reg.BY_NAME["it_intrusion"], SEED)
    _check("(k) it_intrusion: per-incident membership FAILS (no single entity spans a pivot) ...",
           it["incident_membership_ok"] is False and it["incident_promotions"] > 1,
           f"incidents={it['incident_promotions']}")
    _check("(k) ... but ONE campaign (incidents linked by a shared member alert) covers the whole attack",
           it["campaign_count"] == 1 and it["campaign_full_coverage"] is True,
           f"campaigns={it['campaign_count']}")
    for sd in reg.ALL:
        g = reg.grade(sd, SEED)
        _check(f"(k) {sd.name}: a campaign covers the full attack", g["campaign_full_coverage"] is True)


def test_alert_order() -> None:
    ok = report._alert_order_ok
    seq = ["a", "b", "c"]
    mk = lambda step, t: {"step": step, "alert": {"time": t}}  # noqa: E731
    _check("(d) in-order alerts -> True", ok([mk("a", 1), mk("b", 2), mk("c", 3)], seq) is True)
    _check("(d) swapped alerts -> False (negative control: the check CAN fail)",
           ok([mk("a", 2), mk("b", 1), mk("c", 3)], seq) is False)
    _check("(d) fewer than two alerting steps -> None (nothing to order)", ok([mk("a", 1)], seq) is None)
    _check("(d) simultaneous steps are not read as out-of-order",
           ok([mk("a", 5), mk("b", 5), mk("c", 6)], seq) is True)
    _check("(d) several alerts of one step: its FIRST alert time is used",
           ok([mk("a", 1), mk("a", 99), mk("b", 2), mk("c", 3)], seq) is True)


def _with_decoys(sd, retarget_ip=None):
    def src(seed):
        pl, sr, nt, b = sd.build(seed)
        extra = copy.deepcopy(sd.decoy(seed))
        if retarget_ip:
            for _s, p in extra:
                mg.set_src_ip(p, retarget_ip)
        merged = sorted(list(pl) + extra, key=lambda x: mg.get_time(x[1]) or 0)
        return merged, sr, nt, b
    return src


def test_decoy_contamination() -> None:
    for name in ("it_intrusion", "infra_takeover"):
        sd = reg.BY_NAME[name]
        g = reg.grade(sd, SEED, payload_source=_with_decoys(sd))
        _check(f"(e) {name}: benign decoys FIRED alerts (the test has something to contaminate)",
               g["decoy_alert_count"] > 0, f"decoy alerts={g['decoy_alert_count']}")
        _check(f"(e) {name}: disjoint decoys are NOT absorbed into the attack incident",
               g["decoy_contamination"] == 0.0, f"contamination={g['decoy_contamination']}")
    # NEGATIVE CONTROL: put the decoy on the attacker's own address. It now shares
    # an entity with the attack, so the incident MUST swallow it; if this reads 0.0
    # the metric is incapable of going red and the 0.0 above means nothing.
    sd = reg.BY_NAME["infra_takeover"]
    attacker = sd.build(SEED)[0][0][1]["meta"]["ip"]
    g = reg.grade(sd, SEED, payload_source=_with_decoys(sd, retarget_ip=attacker))
    _check("(e) CONTROL: a decoy that shares the attacker's address IS absorbed (metric can go non-zero)",
           (g["decoy_contamination"] or 0) > 0, f"contamination={g['decoy_contamination']}")
    base = reg.grade(sd, SEED)
    # DOCUMENTED TRADE-OFF of the pooled rules: a benign scanner that hits the SAME target
    # as the attacker is pooled with it by common_port_scan_by_target (it keys on the
    # target, not the source), so the two share one alert and the decoy is absorbed.
    # Measured, not hoped: this is the false-positive cost the rule's description names.
    it_sd = reg.BY_NAME["it_intrusion"]

    def _same_target(seed):
        pl, sr, nt, b = it_sd.build(seed)
        extra = copy.deepcopy(it_sd.decoy(seed))
        for sp, p in extra:
            if sp.label == "decoy_scanner":
                p["raw"] = p["raw"].replace("10.0.0.77", "10.0.0.10")
        return sorted(list(pl) + extra, key=lambda x: mg.get_time(x[1]) or 0), sr, nt, b

    gt = reg.grade(it_sd, SEED, payload_source=_same_target)
    _check("(e) TRADE-OFF (documented): a benign scanner on the attacker's own TARGET is pooled "
           "by the target-keyed rule and absorbed (the price of closing the 2-address evasion)",
           (gt["decoy_contamination"] or 0) > 0, f"contamination={gt['decoy_contamination']}")
    _check("(e) CONTROL: ...and the campaign view absorbs it too (campaign-level contamination > 0)",
           (g["campaign_decoy_contamination"] or 0) > 0, f"{g['campaign_decoy_contamination']}")
    for name in ("it_intrusion", "infra_takeover"):
        sdx = reg.BY_NAME[name]
        gx = reg.grade(sdx, SEED, payload_source=_with_decoys(sdx))
        _check(f"(e) {name}: disjoint decoys stay out of the CAMPAIGN as well",
               gx["campaign_decoy_contamination"] == 0.0, f"{gx['campaign_decoy_contamination']}")
    _check("(e) no decoys -> contamination is None, not a fabricated 0.0",
           base["decoy_contamination"] is None and base["decoy_alert_count"] == 0)


def test_generic_operators() -> None:
    ai = reg.BY_NAME["ai_to_ot"]
    ai_payloads = ai.build(SEED)[0]
    for axis, var in (("volume", "thin_25pct"), ("pacing", "stretch_2x"),
                      ("distribution", "ip_rotate_2"), ("identity", "account_split_2"),
                      ("noise", "benign_decoys")):
        _out, changed = mg.apply(ai_payloads, axis, var, seed=SEED, sdef=ai)
        _check(f"(f) ai_to_ot {axis}/{var}: changes nothing -> reported N/A, never a free pass",
               changed == 0, f"changed={changed}")

    it = reg.BY_NAME["it_intrusion"]
    base = it.build(SEED)[0]
    frozen = copy.deepcopy(base)
    n_scan = sum(1 for s, _ in base if s.label == "recon_port_scan")
    out, ch = mg.apply(base, "volume", "thin_25pct", seed=SEED, sdef=it)
    _check("(f) operators never mutate their input", frozen == base)
    _check("(f) thin_25pct removes events from every burst step",
           ch > 0 and len(out) == len(base) - ch, f"removed={ch}")
    out, ch = mg.apply(base, "distribution", "ip_rotate_2", seed=SEED, sdef=it)
    scan_ips = {mg.get_src_ip(p) for s, p in out if s.label == "recon_port_scan"}
    _check("(f) ip_rotate_2 spreads a burst over exactly two addresses",
           len(scan_ips) == 2, f"{sorted(scan_ips)}")
    out, ch = mg.apply(base, "identity", "account_split_2", seed=SEED, sdef=it)
    ssh_users = {mg.get_actor(p) for s, p in out if s.label == "ssh_bruteforce"}
    _check("(f) account_split_2 gives a burst exactly two account names", len(ssh_users) == 2, f"{ssh_users}")
    out, _ = mg.apply(base, "pacing", "stretch_6x", seed=SEED, sdef=it)
    t = sorted(mg.get_time(p) for s, p in out if s.label == "recon_port_scan")
    t0 = sorted(mg.get_time(p) for s, p in base if s.label == "recon_port_scan")
    _check("(f) stretch_6x multiplies the burst's gaps by 6 (first event fixed)",
           t[0] == t0[0] and (t[-1] - t[0]) == 6 * (t0[-1] - t0[0]) and n_scan >= 3)
    out, _ = mg.apply(base, "delivery", "reverse_arrival", seed=SEED, sdef=it)
    _check("(f) reverse_arrival changes delivery ORDER only (same timestamps, same multiset)",
           sorted(mg.get_time(p) for _s, p in out) == sorted(mg.get_time(p) for _s, p in base)
           and [mg.get_time(p) for _s, p in out] != [mg.get_time(p) for _s, p in base])
    a, _ = mg.apply(base, "delivery", "shuffle_arrival", seed=SEED, sdef=it)
    b, _ = mg.apply(base, "delivery", "shuffle_arrival", seed=SEED, sdef=it)
    _check("(f) shuffle_arrival is deterministic for a fixed seed", a == b)


def test_cmp_criteria() -> None:
    base = {"tpr": 1.0, "fired": [{"step": "a", "rule_id": "r"}], "chain_fidelity": 0.5,
            "false_correlation_rate": 1.0, "alert_order_ok": True, "decoy_contamination": None}
    good = dict(base)
    row = layer_a.cmp_result("x", "y", base, good)
    _check("(g) identical mutated grade passes (positive control)", row["pass"] is True, f"{row}")
    bad_order = dict(base, alert_order_ok=False)
    row = layer_a.cmp_result("x", "y", base, bad_order)
    _check("(g) an in-order baseline turning out-of-order FAILS the variant",
           row["pass"] is False and row["order_retained"] is False)
    dirty = dict(base, decoy_contamination=0.5)
    row = layer_a.cmp_result("x", "y", base, dirty)
    _check("(g) a variant that lets decoys into the attack incident FAILS",
           row["pass"] is False and row["decoy_clean"] is False)
    clean = dict(base, decoy_contamination=0.0)
    _check("(g) decoys present but not absorbed (0.0) passes",
           layer_a.cmp_result("x", "y", base, clean)["pass"] is True)


def test_matrix_gate() -> None:
    sd = reg.BY_NAME["infra_takeover"]
    res = scenario_matrix.run_all(SEED, ["infra_takeover"])
    m = res["scenarios"]["infra_takeover"]
    _check("(h) matrix self-check passes on a real storyline",
           scenario_matrix._selfcheck(res) is True)
    rows = {(r["axis"], r["variant"]): r for r in m["rows"]}
    first = sd.steps[0].label
    drop = rows[("loss", f"drop_{first}")]
    _check("(h) negative control: dropping a detected step turns THAT step dark",
           first in drop["steps_lost"], f"steps_lost={drop['steps_lost']}")
    _check("(h) ...and that is graceful degradation (no collateral), so the row PASSES",
           drop["collateral_lost_steps"] == [] and drop["pass"] is True)
    _check("(h) positive control: a pure replay offset passes", rows[("timing", "shift_1h")]["pass"] is True)
    _check("(h) out-of-order ARRIVAL does not defeat detection (event-time keyed windows)",
           all(rows[("delivery", v)]["pass"] for v in ("reverse_arrival", "shuffle_arrival")))
    # a broken baseline must fail the gate
    broken = copy.deepcopy(res)
    broken["scenarios"]["infra_takeover"]["baseline"]["tpr"] = 0.5
    import contextlib
    import io as _io
    with contextlib.redirect_stdout(_io.StringIO()):     # the self-check prints its own [FAIL] line
        broken_result = scenario_matrix._selfcheck(broken)
    _check("(h) a matrix over a broken baseline FAILS its own self-check", broken_result is False)
    # determinism: the whole result is a pure function of (scenario, seed)
    again = scenario_matrix.run_all(SEED, ["infra_takeover"])
    _check("(h) two same-seed matrix runs are byte-identical",
           repr(res) == repr(again))


def test_evasion_search() -> None:
    sd = reg.BY_NAME["infra_takeover"]
    out = evasion_search.search_scenario(sd, SEED)
    searched = [r for r in out["rows"] if r["searched"]]
    _check("(i) infra_takeover: the burst step was actually searched", len(searched) == 1)
    r = searched[0]
    _check("(i) measured evasion boundaries match the rule's DECLARED parameters",
           r["all_agree"] is True, f"measured={r['measured']} predicted={r['predicted']}")
    _check("(i) loss tolerance is exactly events - threshold (dc_mass_vm_delete T=5)",
           r["measured"]["loss"] == r["events"] - 5, f"{r['measured']['loss']} vs {r['events'] - 5}")
    _check("(i) with the account-keyed rule AND its source-keyed companion, the step cannot be "
           "evaded by splitting accounts alone OR addresses alone (before the companion, 2 accounts sufficed)",
           r["measured"]["account_k"] is None and r["measured"]["ip_k"] is None, f"{r['measured']}")
    _check("(i) the step's declared prediction is the combination of BOTH expected rules",
           "dc_mass_vm_delete_by_source" in r["rule"] and "dc_mass_vm_delete" in r["rule"], r["rule"])
    it = evasion_search.search_scenario(reg.BY_NAME["it_intrusion"], SEED)
    dns = next(x for x in it["rows"] if x["step"] == "dns_exfil")
    _check("(i) it_intrusion dns_exfil: the parent-domain rule closes the 2-host evasion "
           "(address spread no longer evades)", dns["measured"]["ip_k"] is None, f"{dns['measured']}")
    # NEGATIVE CONTROL: a deliberately wrong declaration must be flagged
    real_predict = evasion_search._predict
    try:
        evasion_search._predict = lambda params, times, n: real_predict(
            dict(params, threshold=params["threshold"] + 1), times, n)
        bad = evasion_search.search_scenario(sd, SEED)
        flagged = [x for x in bad["rows"] if x["searched"] and not x["all_agree"]]
    finally:
        evasion_search._predict = real_predict
    _check("(i) CONTROL: if the declared threshold were off by one the search reports a MISMATCH",
           len(flagged) == 1)
    _check("(i) step-subset scoring is equivalent to full-stream scoring on every storyline",
           all(evasion_search.verify_subset_equivalence(s, SEED) == [] for s in reg.ALL))


def test_oracle_reconciliation() -> None:
    for sd in reg.ALL:
        f = oracle_consistency.reconcile(SEED, sd)
        _check(f"(j) {sd.name}: oracle vs real pipeline has no NEW disagreement",
               not f["new"] and not f["stale_allowlist_entries"],
               f"new={len(f['new'])} stale_waivers={len(f['stale_allowlist_entries'])}")
    f = oracle_consistency.reconcile(SEED, reg.BY_NAME["it_intrusion"])
    _check("(j) it_intrusion: Impossible-travel no longer fires on the pivot "
           "(regression: RFC1918 'ZZ' must not count as a country)",
           f["total"] == 0, f"disagreements={f['total']}")


def main() -> int:
    test_registry_and_integrity()
    test_burst_mttd()
    test_directional_discrimination()
    test_alert_order()
    test_campaign_view()
    test_decoy_contamination()
    test_generic_operators()
    test_cmp_criteria()
    test_matrix_gate()
    test_evasion_search()
    test_oracle_reconciliation()
    if _FAILURES:
        print(f"\n[FAIL] {len(_FAILURES)} check(s) failed:")
        for f in _FAILURES:
            print(f"   - {f}")
        return 1
    print("\n[OK] multi-storyline harness: every instrument passed its positive AND negative control.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
