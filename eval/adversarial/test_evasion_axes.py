"""Acceptance test for the adaptive-evasion lane (2026-10-02).

Standalone (NOT pytest), same style as test_scenario_harness.py: ``[OK]`` /
``[FAIL]`` lines, exit 0 only when every check passes. Run:

    python eval/adversarial/test_evasion_axes.py

Every NEW measuring instrument is tested with a POSITIVE and a NEGATIVE control
-- an instrument that has never been seen to go red proves nothing:

  A  FastProbe             parity with the slow path (positive), a probe that
                           leaks window state MUST fail parity (negative), the
                           wall-clock refusal, a rules-dir copy changes the answer
  B  rule_probes           each of the 8 templates fires its rule, one event short
                           does not, and its setter really moves the grouping key
  C  timing                the greedy optimal schedule is exact: evades, one
                           millisecond faster is detected, and a predictor that is
                           off by one millisecond is CAUGHT as a mismatch
  D  key spread / joint    companion rules make a kind "immune"; the joint frontier
                           matches the independent prediction cell by cell
  E  obfuscation           identity respelling (F2) classified by table; the search
                           can FAIL (a canonicalising counter makes it detected);
                           attribution forgery (F3) flagged by field isolation and
                           NOT flagged by a plain rename
  F  clock authority       record vs receipt clock measured, not read (F4)
"""
from __future__ import annotations

import copy
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADVERSARIAL = Path(__file__).resolve().parent
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
for _p in (str(ADVERSARIAL), str(TWIN), str(SERVICES)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import evasion_axes as ax  # noqa: E402
import evasion_search  # noqa: E402
import mutate_generic as mg  # noqa: E402
import probe_session as ps  # noqa: E402
import rule_probes as rp  # noqa: E402
import scenario_registry as reg  # noqa: E402
from shared.window import DequeWindowCounter  # noqa: E402

SEED = 7
_FAILURES: list = []


def _check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        _FAILURES.append(name)


_SHARED_PROBE: ps.FastProbe | None = None


def _probe() -> ps.FastProbe:
    global _SHARED_PROBE
    if _SHARED_PROBE is None:
        _SHARED_PROBE = ps.FastProbe(strict_clock=True)
    return _SHARED_PROBE


def _lab(key: str, probe: ps.FastProbe | None = None) -> ax.Lab:
    sets = ax.build_rule_sets()
    return ax.Lab(probe or _probe(), sets[key], ax.reference_burst(key, SEED))


# ---------------------------------------------------------------------------
# A. FastProbe
# ---------------------------------------------------------------------------
def test_fast_probe() -> None:
    for sdef in reg.ALL:
        bad = ps.verify_parity(sdef, SEED)
        _check(f"A1 parity {sdef.name}: FastProbe == report._real_detection on baseline + 3 perturbed streams",
               not bad, str(bad) if bad else "")
        _check(f"A1 state-leak {sdef.name}: A, B, A on one session gives identical A", ps.state_leak_check(sdef, SEED))

    sd = reg.get("it_intrusion")
    leaky = ps.FastProbe(strict_clock=False, reset_counter=False)
    bad = ps.verify_parity(sd, SEED, leaky)
    _check("A2 NEGATIVE control: a probe that never resets its counter FAILS parity", bool(bad),
           f"{len(bad)} streams diverge")
    _check("A2 NEGATIVE control: the same leaky probe fails the A/B/A state-leak check",
           not ps.state_leak_check(sd, SEED, ps.FastProbe(strict_clock=False, reset_counter=False)))

    # wall-clock honesty
    p = ps.FastProbe(strict_clock=True)
    undated = ("mcp_agent", {"tool": "read_file", "arguments": {}}, {})
    try:
        p.normalized([undated])
        refused = False
    except ps.WallClockDerivedTime:
        refused = True
    _check("A3 strict FastProbe REFUSES an event whose time comes from the wall clock", refused)
    lax = ps.FastProbe(strict_clock=False)
    lax.normalized([undated])
    _check("A3 a wall-clock event is never cached", len(lax._cache) == 0 and lax.stats["wall_clock_events"] == 1)
    dated = ("mcp_agent", {"ts": 1751500000000, "tool": "read_file", "session_id": "s", "arguments": {}},
             {"received_at": 1751500000000})
    p.normalized([dated])
    p.normalized([dated])
    _check("A3 a dated event IS cached and reused", p.stats["cache_hits"] >= 1 and len(p._cache) >= 1)

    # determinism does not depend on the wall clock
    import time as _t
    pl = sd.build(SEED)[0]
    pairs = ps.payloads_to_pairs(pl)
    a = ps.FastProbe(strict_clock=True).detect(pairs)
    orig = _t.time
    try:
        _t.time = lambda: 1_900_000_123.0
        b = ps.FastProbe(strict_clock=True).detect(pairs)
    finally:
        _t.time = orig
    _check("A4 verdicts are unchanged when time.time() is monkeypatched (no hidden wall-clock dependence)", a == b)

    # a rules-dir copy changes the answer: the instrument can see a rule set change
    tmp = Path(tempfile.mkdtemp(prefix="fp_rules_"))
    try:
        shutil.copytree(ROOT / "contracts" / "rules", tmp / "rules")
        (tmp / "rules" / "common_bruteforce_by_account.yml").unlink()
        mutated, changed = mg.apply(sd.build(SEED)[0], "distribution", "ip_rotate_2", seed=SEED, sdef=sd)
        step = "ssh_bruteforce"
        sub = [x for x in mutated if x[0].label == step]
        exp = {r["rule_id"] for r in (reg.load_oracle(sd)["detection_points"][step]["expected_rules"])}
        full = ps.FastProbe(strict_clock=False)
        cut = ps.FastProbe(rules_dir=tmp / "rules", strict_clock=False)
        f_ok = any(a["step"] == step and a["rule_id"] in exp for a in full.detect(ps.payloads_to_pairs(sub)))
        c_ok = any(a["step"] == step and a["rule_id"] in exp for a in cut.detect(ps.payloads_to_pairs(sub)))
        _check("A5 rules_dir copy: with the companion, 2-address spread is still detected", changed > 0 and f_ok)
        _check("A5 rules_dir copy: without the companion the SAME stream evades (the search can see rules change)",
               not c_ok)
        _check("A5 the repo's own rule files were not touched",
               (ROOT / "contracts" / "rules" / "common_bruteforce_by_account.yml").exists())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # escape hatch + delegation
    old = os.environ.get("FENGARDE_SLOW_PROBE")
    try:
        os.environ["FENGARDE_SLOW_PROBE"] = "1"
        slow_off = not ps.fast_probe_enabled()
        slow_res = evasion_search._fired(pl)
        os.environ.pop("FENGARDE_SLOW_PROBE")
        fast_on = ps.fast_probe_enabled()
        fast_res = evasion_search._fired(pl)
    finally:
        if old is None:
            os.environ.pop("FENGARDE_SLOW_PROBE", None)
        else:
            os.environ["FENGARDE_SLOW_PROBE"] = old
    _check("A6 FENGARDE_SLOW_PROBE=1 turns the fast path off", slow_off and fast_on)
    _check("A6 evasion_search._fired returns identical lists on the fast and the slow path", slow_res == fast_res)


# ---------------------------------------------------------------------------
# B. rule_probes templates
# ---------------------------------------------------------------------------
def test_rule_probes() -> None:
    sets = ax.build_rule_sets()
    covered = set(ax.STORYLINE_BURSTS) | set(rp.all_probes())
    _check("B0 every stateful rule-set has a storyline burst or a probe template",
           set(sets) == covered, f"missing {sorted(set(sets) - covered)} extra {sorted(covered - set(sets))}")
    for key, pr in rp.all_probes().items():
        rs = sets[key]
        lab = ax.Lab(_probe(), rs, ax.reference_burst(key, SEED))
        t = min(r.threshold for r in rs.rules)
        d, q = lab.both(lab.burst.payloads)
        short = lab.burst.payloads[: max(0, t - 1)]
        sd, sq = lab.both(short)
        _check(f"B1 {key}: burst fires the rule (measured and predicted)", d and q)
        _check(f"B1 {key}: T-1 events do NOT fire it (measured and predicted)", (not sd) and (not sq),
               f"T={t}")
        for kind in rs.kinds:
            if kind is None:
                continue
            v = ax.verify_setter(lab, kind, 3)
            _check(f"B2 {key}: setter '{kind}' moves the rule's grouping field (3 keys -> 3 values)",
                   v["applicable"] and v["distinct"] == 3, str(v))
    _check("B3 common_impossible_travel is tagged production_reachable: false with a basis",
           (not rp.get("common_impossible_travel").production_reachable)
           and "SAMPLE" in rp.get("common_impossible_travel").reachability_basis)


# ---------------------------------------------------------------------------
# C. timing: the optimal schedule is exact
# ---------------------------------------------------------------------------
def test_timing() -> None:
    # pure arithmetic first
    off = ax.optimal_slow_offsets(10, [(4, 1000)])
    _check("C1 optimal_slow_offsets groups T-1 events 1 ms apart, next group W+1 ms later",
           off[:3] == [0, 1, 2] and off[3] == 1001 and off[6] == 2002, str(off))
    off2 = ax.optimal_slow_offsets(6, [(3, 1000), (5, 4000)])
    _check("C1 two constraints are both honoured (greedy minimum)",
           all(off2[i + 2] - off2[i] >= 1001 for i in range(4)) and all(off2[i + 4] - off2[i] >= 4001 for i in range(2)),
           str(off2))
    for key in ("common_lateral_movement", "ot_new_engineering_connection", "common_beaconing", "bank_mass_card_read"):
        lab = _lab(key)
        r = ax.search_schedule(lab)
        _check(f"C2 {key}: the optimal schedule evades, measured AND predicted", r["evades"] and r["predicted_evades"], str(r))
        _check(f"C2 {key}: a schedule exactly 1 ms faster IS detected (the boundary is tight)",
               r["one_ms_faster_detected"] and r["predicted_one_ms_faster_detected"])
        _check(f"C2 {key}: optimal extra seconds <= the uniform stretch's", r["optimal_le_uniform"],
               f"{r['extra_seconds']} <= {r['uniform_extra_seconds']}")
    # negative: a predictor whose window is 1 ms too long must DISAGREE with the measurement on the boundary
    lab = _lab("common_lateral_movement")
    cons = [(r.threshold, r.window_ms) for r in lab.rs.rules]
    sched = ax.apply_offsets(lab.burst.payloads, ax.optimal_slow_offsets(lab.burst.n, cons))
    events = lab.probe.normalized(ps.payloads_to_pairs(sched))
    sloppy = ax.RuleSet("x", [ax.RuleParams(**{**r.__dict__, "window_seconds": r.window_seconds + 0.001})
                              for r in lab.rs.rules])
    _check("C3 NEGATIVE control: a predictor off by +1 ms MISMATCHES the measurement on the optimal schedule",
           ax.predict_set(lab.rs, events) is False and ax.predict_set(sloppy, events) is True)
    # periodicity: jitter boundary
    jl = _lab("common_beaconing")
    j = ax.search_jitter(jl)
    _check("C4 beaconing: J=0 is detected and the boundary jitter exceeds max_cv (measured == predicted)",
           j["agree"] and j["min_jitter_permille"] is not None
           and j["min_jitter_permille"] > j["declared_max_cv_permille"] - 1, str(j))
    _check("C4 beaconing: a clearly large jitter (50x gap analogue) evades",
           not jl.detected(ax.apply_offsets(jl.burst.payloads, ax.jitter_offsets(jl.burst.n, 300_000, 900))))


# ---------------------------------------------------------------------------
# D. key spread and the joint frontier
# ---------------------------------------------------------------------------
def test_spread() -> None:
    lab = _lab("common_bruteforce")
    ip, acct = ax.search_spread(lab, "ip"), ax.search_spread(lab, "account")
    _check("D1 ssh_bruteforce: address spread alone is 'immune' (the by-account companion), measured == predicted",
           ip["min_keys"] == "immune" and ip["agree"], str(ip))
    _check("D1 ssh_bruteforce: account spread alone is 'immune' (the by-address rule)",
           acct["min_keys"] == "immune" and acct["agree"], str(acct))
    jf = ax.search_joint(lab, ["ip", "account"])
    _check("D2 ssh_bruteforce: the joint frontier is (2, 2) and matches the prediction on every cell",
           jf["frontier"] == [[2, 2]] and jf["agree"], str(jf))
    # NEGATIVE: with the companion removed the frontier collapses to a single kind
    tmp = Path(tempfile.mkdtemp(prefix="ev_rules_"))
    try:
        shutil.copytree(ROOT / "contracts" / "rules", tmp / "rules")
        (tmp / "rules" / "common_bruteforce_by_account.yml").unlink()
        sets = ax.build_rule_sets(tmp / "rules")
        cut = ax.Lab(ps.FastProbe(rules_dir=tmp / "rules", strict_clock=True), sets["common_bruteforce"],
                     ax.reference_burst("common_bruteforce", SEED))
        r = ax.search_spread(cut, "ip")
        _check("D3 NEGATIVE control: removing the companion turns 'immune' into a finite key count",
               r["min_keys"] != "immune" and r["agree"], str(r))
        _check("D3 the fingerprint of the rule-set changes when the companion is removed",
               sets["common_bruteforce"].fingerprint() != ax.build_rule_sets()["common_bruteforce"].fingerprint())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # a single-kind rule has a finite answer and the model agrees
    for key, kind in (("agent_tool_call_burst", "session"), ("ot_new_engineering_connection", "ot_server"),
                      ("common_rapid_account_lifecycle", "target_account")):
        r = ax.search_spread(_lab(key), kind)
        _check(f"D4 {key}: {kind} spread evades at a finite key count, measured == predicted",
               r["min_keys"] != "immune" and r["agree"], str(r))
    lo = ax.search_loss(_lab("common_port_scan"))
    _check("D5 port_scan: forgone events measured == predicted (n - T + 1)", lo["agree"] and lo["forgone_events"] == 8,
           str(lo))


# ---------------------------------------------------------------------------
# E. obfuscation: F2 identity respelling, F3 attribution forgery
# ---------------------------------------------------------------------------
class _CanonicalCounter(DequeWindowCounter):
    """A counter that canonicalises (strip + casefold) the GROUP part of every
    window key -- what a product fix for F2 looks like. Used only as the
    'search can fail' control."""

    @staticmethod
    def _canon(key: str) -> str:
        rid, tenant, _n, group = key.split(":", 3)
        g = group.strip().casefold()
        return f"{rid}:{tenant}:{len(g)}:{g}"

    def hit(self, key, now_ms, window_ms, member=None):
        return super().hit(self._canon(key), now_ms, window_ms, member)

    def hit_distinct(self, key, now_ms, window_ms, value=None, member=None):
        return super().hit_distinct(self._canon(key), now_ms, window_ms, value, member)


def test_obfuscation() -> None:
    tables = ax.load_tables()
    _check("E0 every table row is ratified: false (security-judgement inputs await the owner)",
           all(not r.get("ratified", False) for sec in ("attacker_control", "identity")
               for r in tables[sec].values()))
    lat = _lab("common_lateral_movement")
    res = ax.respelling_axis(lat, tables)
    by_op = {o["op"]: o for o in res["ops"]}
    _check("E1 lateral_movement: ip-split + Windows case respelling EVADES and is classified BUG (identity-preserving)",
           by_op["casefold"]["evades"] and by_op["casefold"]["class"] == "BUG" and res["respelling_evades"],
           str({k: v["class"] for k, v in by_op.items()}))
    _check("E1 ... and the same split WITHOUT a respelling is detected (the control the claim rests on)",
           all(o["control_split_without_respelling_detected"] for o in res["ops"]))
    _check("E1 ... measured == predicted on every respelling", all(o["agree"] for o in res["ops"]))
    ssh = ax.respelling_axis(_lab("common_bruteforce"), tables)
    _check("E2 NEGATIVE class: ssh case-split evades but is INHERENT (POSIX names are distinct), not BUG",
           ssh["ops"] and all(o["class"] == "INHERENT" for o in ssh["ops"]) and not ssh["respelling_evades"]
           and ssh["respelling_inherent"], str([o["class"] for o in ssh["ops"]]))
    dns = ax.respelling_axis(_lab("common_dns_exfil"), tables)
    _check("E3 ROBUST control: DNS case / trailing-dot respelling of the parent domain stays detected",
           dns["ops"] and all(o["class"] == "ROBUST" for o in dns["ops"]) and not dns["respelling_evades"],
           str([(o["op"], o["class"]) for o in dns["ops"]]))
    none = ax.respelling_axis(_lab("common_port_scan"), tables)
    _check("E4 a rule-set with no identity-valued key is reported not_searched, with a reason, and excluded",
           not none["ops"] and none["not_searched"] and "reason" in none["not_searched"][0])
    # the search can FAIL: a canonicalising counter makes the previously evading cell detected
    fixed = ax.Lab(ps.FastProbe(strict_clock=True, counter_factory=_CanonicalCounter), lat.rs, lat.burst)
    res_fixed = ax.respelling_axis(fixed, tables)
    fixed_ops = {o["op"]: o["evades"] for o in res_fixed["ops"]}
    _check("E5 SEARCH CAN FAIL: with a strip+casefold canonicalising counter (ADR-009's canonical form) the case "
           "and trailing-space respellings are no longer evasions", not fixed_ops["casefold"] and not fixed_ops["strip"],
           str(fixed_ops))
    _check("E5 ... and the report shows exactly what that fix leaves open: DOMAIN\\ prefix and UPN suffix still "
           "evade (stripping them would AMEND ADR-009 -- an owner decision)",
           fixed_ops["domain_prefix"] and fixed_ops["upn_suffix"], str(fixed_ops))
    # unratified rows never gate: nothing in the result is a hard failure by itself
    _check("E6 unratified rows are flagged ratified: false in the result", all(not o["ratified"] for o in res["ops"]))
    # a not-attacker-controlled field is NOT_REACHABLE and never searched
    forced = copy.deepcopy(tables)
    forced["identity"]["windows_eventlog.account"]["attacker_controlled"] = "no"
    nr = ax.respelling_axis(lat, forced)
    _check("E7 a field the table says the attacker cannot influence is NOT_REACHABLE: no ops, listed with its reason",
           not nr["ops"] and any(x.get("class") == "NOT_REACHABLE" for x in nr["not_searched"]))

    # F3: attribution forgery
    sshlab = _lab("common_bruteforce")
    fg = ax.forgery_axis(sshlab, tables)
    _check("E8 F3 positive: the ssh username-injection variant moves src_endpoint.ip (field isolation violated)",
           fg["isolation"]["isolated"] is False and "src_endpoint.ip" in fg["isolation"]["violations"], str(fg["isolation"]))
    _check("E8 F3 negative: renaming deploy -> deploy2 changes ONLY actor.user.name and is NOT flagged",
           fg["isolation_control_rename"]["isolated"] is True and fg["isolation_control_rename"]["moved"] == ["actor.user.name"])
    _check("E8 F3 end to end: forging the address from one real source evades; the unforged burst is detected",
           fg["forgery_evades"] and fg["honest_unsplit_detected"] and fg["agree"], str({k: fg[k] for k in
                                                                                  ("forged_detected", "honest_unsplit_detected")}))
    nf = ax.forgery_axis(lat, tables)
    _check("E9 forgery is reported not applicable (with a reason) where no source has an injectable field",
           not nf["applicable"] and nf["reason"])


# ---------------------------------------------------------------------------
# F. clock authority
# ---------------------------------------------------------------------------
def test_clock() -> None:
    win = ax.clock_authority(_probe(), ax.reference_burst("common_lateral_movement", SEED).payloads[0][1])
    ssh = ax.clock_authority(_probe(), ax.reference_burst("common_bruteforce", SEED).payloads[0][1])
    _check("F1 windows_eventlog trusts the RECORD clock (receipt clock alone does not move event time)",
           win["authority"] == "record" and not win["receipt_clock_moves_event_time"], str(win))
    _check("F1 linux_ssh trusts the RECEIPT clock (the record carries none)",
           ssh["authority"] == "receipt" and ssh["receipt_clock_moves_event_time"], str(ssh))
    cf = ax.clock_forgeable(_lab("common_lateral_movement"))
    _check("F2 positive: forging only the record clock stretches the Windows burst past the window for free",
           cf["clock_forgeable"], str(cf))
    cn = ax.clock_forgeable(_lab("common_bruteforce"))
    _check("F2 negative: the same forgery has no effect on a receipt-clock source", not cn["clock_forgeable"], str(cn))


SECTIONS = (test_fast_probe, test_rule_probes, test_timing, test_spread, test_obfuscation, test_clock)


def main(argv: list | None = None) -> int:
    for sec in SECTIONS:
        print(f"\n== {sec.__name__} ==")
        sec()
    print()
    if _FAILURES:
        print(f"[FAIL] {len(_FAILURES)} check(s) failed: {_FAILURES}")
        return 1
    print("[OK] all adaptive-evasion instrument checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
