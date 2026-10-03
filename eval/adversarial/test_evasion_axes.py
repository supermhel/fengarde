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
                           attribution forgery (F3, FIXED 2026-10-03) isolated on the shipped
                           parser; the pre-fix grammar re-installed is flagged (negative
                           control); a plain rename is never flagged
  F  clock authority       record vs receipt clock measured, not read (F4)
  G  noise / state         F1 (FIXED 2026-10-03): the shipped counter keeps the long-window key;
                           the re-introduced global sweep (negative control) loses it, idle-time
                           and no-noise negatives; end to end on the password-spray burst
                           (immune on the shipped counter; on the legacy counter the tick lands
                           inside the first post-pause event)
  H  cost vector / floor   the floor is met on the current tree; companion removed, raised
                           threshold and an uncovered stateful rule each FAIL, naming rule, axis,
                           measured value and floor; the ratchet refuses lowering; the findings
                           register fails on STALE and (once ratified) UNLISTED entries; JSON is
                           byte-identical under PYTHONHASHSEED=0/1; the generated doc table cannot
                           be read as the rule scorecard
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


def _legacy_ssh_classify(line: str):
    """The linux_ssh grammar BEFORE the F3 fix: unanchored ``.search`` for the first
    ``Accepted``/``Failed``/``Invalid user`` phrase anywhere and the first
    ``from <ip>`` after a whitespace-free name. Re-installed only as the negative control."""
    import re  # noqa: PLC0415
    ip = r"(?P<ip>[0-9A-Fa-f:.]+)(?:\s+port\s+(?P<port>\d+))?"
    failed = re.compile(r"Failed\s+\S+\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+" + ip)
    accepted = re.compile(r"Accepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+" + ip)
    invalid = re.compile(r"Invalid user\s+(?P<user>\S+)\s+from\s+" + ip)
    from parsers.base import SEV_HIGH, SEV_INFO  # noqa: PLC0415
    for rx, act, status, sev in ((accepted, 1, "Success", SEV_INFO), (failed, 4, "Failure", SEV_HIGH),
                                 (invalid, 4, "Failure", SEV_HIGH)):
        m = rx.search(line)
        if m:
            port = m.group("port")
            return (act, status, sev, m.group("user"), m.group("ip"), int(port) if port else None)
    return (None, None, None, None, None, None)


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

    # F3: attribution forgery -- FIXED 2026-10-03 (the sshd grammar is anchored at both ends).
    sshlab = _lab("common_bruteforce")
    fg = ax.forgery_axis(sshlab, tables)
    _check("E8 F3 fixed: the ssh username-injection variant no longer moves src_endpoint.ip (field isolation holds)",
           fg["applicable"] and fg["isolation"]["isolated"] is True and not fg["isolation"]["violations"], str(fg["isolation"]))
    _check("E8 F3 fixed: the forgery axis reports no evasion", fg["forgery_evades"] is False, str(fg))
    _check("E8 F3 negative: renaming deploy -> deploy2 changes ONLY actor.user.name and is NOT flagged",
           fg["isolation_control_rename"]["isolated"] is True and fg["isolation_control_rename"]["moved"] == ["actor.user.name"])
    # end to end on the shipped parser: the forged burst (every odd event carries a fake `from <ip>`) is still detected
    pl = copy.deepcopy(sshlab.burst.payloads)
    for rank, (_s, p) in enumerate(pl):
        if rank % 2:
            ax.forge_ssh_username(p, "198.18.9.9", "x")
    _check("E8 F3 end to end (shipped parser): the forged burst from one real source is detected, like the honest one",
           sshlab.detected(pl) and sshlab.detected(copy.deepcopy(sshlab.burst.payloads)))
    # the instrument can still go red: put the OLD first-match grammar back and the same forgery evades again
    import parsers.linux_ssh as _ssh_mod  # noqa: PLC0415
    saved = _ssh_mod.LinuxSshParser.__dict__["_classify"]
    _ssh_mod.LinuxSshParser._classify = staticmethod(_legacy_ssh_classify)
    try:
        # a FRESH probe: the shared one memoises normalisation, so it would replay the fixed parser's answers
        # (and a legacy parse must never be cached into the shared probe either)
        lg = ax.forgery_axis(ax.Lab(ps.FastProbe(strict_clock=True), sshlab.rs, sshlab.burst), tables)
    finally:
        _ssh_mod.LinuxSshParser._classify = saved
    _check("E8 F3 NEGATIVE CONTROL: with the pre-fix first-match grammar re-introduced the forgery moves the source "
           "and evades (the instrument still goes red)",
           lg["isolation"]["isolated"] is False and "src_endpoint.ip" in lg["isolation"]["violations"]
           and lg["forgery_evades"] and lg["honest_unsplit_detected"] and lg["agree"],
           str({k: lg.get(k) for k in ("forged_detected", "honest_unsplit_detected", "forgery_evades")}))
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


# ---------------------------------------------------------------------------
# G. noise / state exhaustion (the cheap controls; the end-to-end ones are
#    noise_dilution.py --blocking-subset)
# ---------------------------------------------------------------------------
def test_noise() -> None:
    import noise_dilution as nd  # noqa: PLC0415
    prim = nd.f1_primitive()
    _check("G1 F1 fixed: short-window noise no longer sweeps the long-window key on the shipped counter",
           not prim["state_lost"] and not nd.f1_reproduces(), str(prim))
    leg = nd.f1_primitive(nd.LegacyGlobalSweepCounter)
    _check("G1 NEGATIVE CONTROL: the re-introduced global sweep (LegacyGlobalSweepCounter) loses the state "
           "(the instrument still goes red)", leg["state_lost"], str(leg))
    _check("G2 negative: even the legacy sweep leaves the key intact while it is idle for less than the noise window",
           not nd.f1_primitive(nd.LegacyGlobalSweepCounter, noise_delay_ms=30_000)["state_lost"])
    c = DequeWindowCounter()
    c.hit_distinct("long", 1_000_000, 300_000, "h1")
    _check("G3 negative: no noise -> the second value counts 2", c.hit_distinct("long", 1_100_000, 300_000, "h2") == 2)
    sets = ax.build_rule_sets()
    w = nd.shortest_window_ms(sets)
    burst = ax.reference_burst("common_password_spray", SEED)
    lab = ax.Lab(_probe(), sets["common_password_spray"], burst)
    res = nd.state_exhaustion(lab, w)
    _check("G4 end to end, shipped counter: the password-spray burst cannot be made to forget by noise "
           "(measured == predicted == immune)",
           res.get("searched") and res["agree"] and res["noise_events"] == "immune"
           and res["predicted_noise_events"] == "immune", str(res))
    lprobe = ps.FastProbe(strict_clock=True, counter_factory=nd.LegacyGlobalSweepCounter)
    lres = nd.state_exhaustion(ax.Lab(lprobe, sets["common_password_spray"], burst), w, sweep="global")
    _check("G5 NEGATIVE CONTROL end to end: on the legacy counter the burst IS forgotten after the predicted number of "
           "noise events (the tick can land INSIDE the first post-pause event: 4 hits per event)",
           lres.get("searched") and lres["agree"] and isinstance(lres["noise_events"], int), str(lres))


# ---------------------------------------------------------------------------
# H. cost vector, floor ratchet, findings register
# ---------------------------------------------------------------------------
_SUB = ["common_bruteforce", "common_lateral_movement", "common_port_scan"]
_COST: dict = {}


def _cost():
    import evasion_cost as ec  # noqa: PLC0415
    if "res" not in _COST:
        _COST["res"] = ec.measure(SEED, only=_SUB, probe=_probe())
    return ec, copy.deepcopy(_COST["res"])


def _restrict(ec, res: dict, floor: dict, findings: list | None = None) -> tuple:
    """The full floor/stateful list narrowed to the measured subset (a subset run
    must not be failed for the rule-sets it did not measure)."""
    keys = list(res["rule_sets"])
    res["stateful_rule_sets"] = keys
    fl = copy.deepcopy(floor)
    fl["rule_sets"] = {k: v for k, v in (fl.get("rule_sets") or {}).items() if k in keys}
    return res, fl, (findings if findings is not None else ec.load_findings())


def _tmp_rules() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="ec_rules_"))
    shutil.copytree(ROOT / "contracts" / "rules", tmp / "rules")
    return tmp


def test_cost() -> None:
    ec, res = _cost()
    res, floor, findings = _restrict(ec, res, ec.load_floor())
    g = ec.check(res, floor, findings)
    _check("H1 positive: the current tree meets the committed floor, the register and coverage (open BUGs pass)",
           not g.fail, str(g.fail))
    same = all(ec.field_values(r)[n][0] == floor["rule_sets"][k]["fields"][n]["value"]
               for k, r in res["rule_sets"].items() for n in floor["rule_sets"][k]["fields"])
    _check("H1 the measurement is deterministic: every measured value EQUALS its committed floor", same)
    _check("H1 every number agrees with its independent prediction", all(r["agree"] for r in res["rule_sets"].values()))
    ssh = res["rule_sets"]["common_bruteforce"]
    _check("H2 no weighted scalar: the vector keeps events, seconds, keys and the frontier separate and tagged",
           all(r["basis"] == "harness-measured" for r in res["rule_sets"].values()) and "score" not in ssh
           and ssh["min_keys"]["ip"]["value"] == "immune" and ssh["joint_frontier"]["frontier"] == [[2, 2]])
    # coverage over the WHOLE tree (not just the subset): every stateful rule-set has a burst
    full = ec.ax.build_rule_sets()
    _check("H3 coverage: every one of the stateful rule-sets has a reference burst (storyline or probe template)",
           all(ax.reference_burst(k, SEED) is not None for k in full), f"{len(full)} rule-sets")

    # NEGATIVE A: drop the by-account companion -> the address floor breaches, named
    tmp = _tmp_rules()
    try:
        (tmp / "rules" / "common_bruteforce_by_account.yml").unlink()
        cut = ec.measure(SEED, tmp / "rules", only=["common_bruteforce"])
        cut, fl2, f2 = _restrict(ec, cut, ec.load_floor())
        g = ec.check(cut, fl2, f2)
        msg = " | ".join(g.fail)
        _check("H4 NEGATIVE A: removing the companion fails the floor, naming rule, axis, measured value and floor",
               any("FLOOR common_bruteforce.min_keys.ip" in m and "immune" in m for m in g.fail), msg[:300])
        _check("H4 ... and the parameter fingerprint trips (the companion set changed)",
               any(m.startswith("FINGERPRINT common_bruteforce") for m in g.fail))
        # NEGATIVE B: raise the threshold 10 -> 15 in a temp copy
        shutil.copytree(ROOT / "contracts" / "rules", tmp / "rules_b")
        f = tmp / "rules_b" / "common_bruteforce.yml"
        txt = f.read_text(encoding="utf-8")
        assert "threshold: 10" in txt
        f.write_text(txt.replace("threshold: 10", "threshold: 15", 1), encoding="utf-8")
        cutb = ec.measure(SEED, tmp / "rules_b", only=["common_bruteforce"])
        cutb, fl3, f3 = _restrict(ec, cutb, ec.load_floor())
        g = ec.check(cutb, fl3, f3)
        _check("H5 NEGATIVE B: a raised threshold fails with a parameter-fingerprint message AND a floor breach",
               any(m.startswith("FINGERPRINT common_bruteforce") for m in g.fail)
               and any(m.startswith("FLOOR common_bruteforce.") for m in g.fail), " | ".join(g.fail)[:300])
        # NEGATIVE C: a stateful rule with no burst and no waiver fails the coverage gate
        fake = (ROOT / "contracts" / "rules" / "common_port_scan.yml").read_text(encoding="utf-8")
        import re as _re  # noqa: PLC0415
        fake = _re.sub(r"(?m)^id:.*$", "id: zz_fake_stateful_rule", fake, count=1)
        (tmp / "rules" / "zz_fake_stateful.yml").write_text(fake, encoding="utf-8")
        fk = ec.measure(SEED, tmp / "rules", only=["zz_fake_stateful"])
        fk["stateful_rule_sets"] = ["zz_fake_stateful"]
        floor_none = {"version": 1, "rule_sets": {}, "waivers": {}}
        g = ec.check(fk, floor_none, ec.load_findings())
        _check("H6 NEGATIVE C: a stateful rule with no reference burst and no waiver fails the coverage gate",
               any("COVERAGE zz_fake_stateful" in m for m in g.fail), " | ".join(g.fail)[:200])
        floor_w = {"version": 1, "rule_sets": {}, "waivers": {"zz_fake_stateful": {"reason": "test", "date": "2026-10-02"}}}
        g = ec.check(fk, floor_w, ec.load_findings())
        _check("H6 ... and a dated waiver makes it pass (positive)", not any("COVERAGE" in m for m in g.fail))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # RATCHET (pure functions on the measured subset)
    ec2, res2 = _cost()
    res2, _fl, fnd = _restrict(ec2, res2, ec2.load_floor())
    base, refused = ec2.update_floor(res2, {"version": 1, "rule_sets": {}, "waivers": {}}, fnd, today="2026-10-02")
    _check("H7 ratchet: a first measurement is recorded as the floor", not refused and set(base["rule_sets"]) == set(_SUB))
    worse = copy.deepcopy(res2)
    worse["rule_sets"]["common_port_scan"]["forgone_events"]["value"] = 2
    new, refused = ec2.update_floor(worse, base, fnd, today="2026-10-02")
    _check("H7 ratchet NEGATIVE: lowering a floor without --allow-lower --reason is REFUSED",
           bool(refused) and new["rule_sets"]["common_port_scan"]["fields"]["forgone_events"]["value"] == 8, str(refused))
    new, refused = ec2.update_floor(worse, base, fnd, allow_lower=True, reason="tuned threshold for FP rate", today="2026-10-02")
    low = new["rule_sets"]["common_port_scan"].get("lowered") or []
    _check("H7 ratchet: --allow-lower with a reason lowers it and appends a dated 'lowered:' entry",
           not refused and low and low[0]["date"] == "2026-10-02" and low[0]["reason"] and low[0]["to"] == 2, str(low))
    better = copy.deepcopy(res2)
    better["rule_sets"]["common_port_scan"]["forgone_events"]["value"] = 12
    new, refused = ec2.update_floor(better, base, fnd, today="2026-10-02")
    _check("H7 ratchet: an improvement raises the floor automatically",
           not refused and new["rule_sets"]["common_port_scan"]["fields"]["forgone_events"]["value"] == 12)
    lower_stealth = copy.deepcopy(res2)
    lower_stealth["rule_sets"]["common_port_scan"]["schedule"]["sustained_events_per_second"] = 9.0
    _new, refused = ec2.update_floor(lower_stealth, base, fnd, today="2026-10-02")
    _check("H7 better=min: a HIGHER stealth rate (cheaper to evade) is the regression, not a lower one",
           bool(refused) and any("stealth_rate" in m for m in refused), str(refused))
    # CLI refusal and exit code
    tmpd = Path(tempfile.mkdtemp(prefix="ec_cli_"))
    try:
        tf = tmpd / "floor.yaml"
        import yaml as _y  # noqa: PLC0415
        tf.write_text(_y.safe_dump(base), encoding="utf-8")
        rc = ec2.main(["--rule-set", "common_port_scan", "--floor", str(tf), "--out", str(tmpd / "o.json"),
                       "--update-floor", "--allow-lower"])
        _check("H8 CLI: --allow-lower without --reason exits non-zero", rc == 2, f"rc={rc}")
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)

    # FINDINGS REGISTER
    ec3, res3 = _cost()
    res3, fl3, fnd3 = _restrict(ec3, res3, ec3.load_floor())
    stale = copy.deepcopy(fnd3)
    next(f for f in stale if f["id"].startswith("F2"))["rule_sets"].append("common_port_scan")
    g = ec3.check(res3, fl3, stale)
    _check("H9 register NEGATIVE: a listed rule-set where the evasion no longer reproduces is STALE and fails",
           any(m.startswith("STALE F2") and "common_port_scan" in m for m in g.fail), " | ".join(g.fail)[:200])
    fixed = copy.deepcopy(res3)
    for r in fixed["rule_sets"].values():
        r["respelling_evades"] = False
    g = ec3.check(fixed, fl3, fnd3)
    _check("H9 register: when the BUG is fixed the entry goes STALE and the gate fails until it is deleted",
           any(m.startswith("STALE F2-identity-canonicalisation") for m in g.fail))
    unl = copy.deepcopy(res3)
    unl["rule_sets"]["common_port_scan"]["forgery_evades"] = True
    g = ec3.check(unl, fl3, fnd3)
    _check("H10 an UNLISTED evasion resting on unratified table rows is a WARN (reported, not gating)",
           any("UNLISTED forgery_evades on common_port_scan" in m for m in g.warn) and not g.fail, str(g.fail))
    unl["rule_sets"]["common_port_scan"]["forgery_evades_ratified"] = True
    g = ec3.check(unl, fl3, fnd3)
    _check("H10 ... and the same evasion resting on RATIFIED rows FAILS", any("UNLISTED forgery_evades" in m for m in g.fail))
    no_f2 = [f for f in fnd3 if not f["id"].startswith("F2")]
    rt = copy.deepcopy(res3)
    rt["rule_sets"]["common_lateral_movement"]["respelling_evades_ratified"] = True
    g = ec3.check(rt, fl3, no_f2)
    _check("H10 ratified table rows turn the F2 respelling into a hard failure once it is not registered",
           any("UNLISTED respelling_evades on common_lateral_movement" in m for m in g.fail))
    # open_finding tolerance: the floor says True, the finding is open -> tolerated, not blessed
    regress = copy.deepcopy(res3)
    regress["rule_sets"]["common_port_scan"]["respelling_evades"] = True
    g = ec3.check(regress, fl3, fnd3)
    _check("H11 a boolean floor of False is breached when the evasion appears (WARN while unratified)",
           any("FLOOR common_port_scan.respelling_evades" in m for m in g.warn + g.fail))
    jf_bad = copy.deepcopy(res3)
    jf_bad["rule_sets"]["common_bruteforce"]["joint_frontier"]["frontier"] = [[1, 2]]
    g = ec3.check(jf_bad, fl3, fnd3)
    _check("H12 joint frontier regression (the attacker evades with fewer keys) fails and names the points",
           any("FLOOR common_bruteforce.joint_frontier" in m and "[[1, 2]]" in m for m in g.fail))

    # ratification end to end: ratified tables + an unregistered finding
    tabs = ax.load_tables()
    for sec in ("attacker_control", "identity"):
        for row in tabs[sec].values():
            row["ratified"] = True
    rr = ec3.measure(SEED, only=["common_lateral_movement"], tables=tabs, probe=_probe())
    _check("H13 with ratified tables the respelling finding is flagged ratified",
           rr["rule_sets"]["common_lateral_movement"]["respelling_evades_ratified"])
    rr["stateful_rule_sets"] = ["common_lateral_movement"]
    g = ec3.check(rr, {"version": 1, "rule_sets": {}, "waivers": {}}, no_f2)
    _check("H13 ... and then an unregistered F2 fails the gate", any("UNLISTED respelling_evades" in m for m in g.fail))


def test_cost_determinism_and_doc() -> None:
    import subprocess  # noqa: PLC0415
    outs = []
    for seed in ("0", "1"):
        out = Path(tempfile.mkdtemp(prefix="ec_det_")) / "o.json"
        env = dict(os.environ, PYTHONHASHSEED=seed)
        rc = subprocess.run([sys.executable, str(ADVERSARIAL / "evasion_cost.py"), "--rule-set", "common_port_scan",
                             "--out", str(out)], env=env, capture_output=True, text=True, cwd=str(ROOT)).returncode
        outs.append((rc, out.read_bytes() if out.exists() else b""))
        shutil.rmtree(out.parent, ignore_errors=True)
    _check("H14 determinism: byte-identical JSON under PYTHONHASHSEED=0 and 1, exit 0",
           outs[0][0] == 0 and outs[0] == outs[1] and outs[0][1], f"rc={[o[0] for o in outs]}")
    ec, res = _cost()
    table = ec.doc_table(res)
    _check("H15 the generated table's header does NOT start with '| Rule |' (check_lane_coverage would union it)",
           not table.splitlines()[0].startswith("| Rule |"))
    sys.path.insert(0, str(ROOT / "tools"))
    import check_lane_coverage as clc  # noqa: PLC0415
    tmpd = Path(tempfile.mkdtemp(prefix="ec_doc_"))
    try:
        orig = clc.COVERAGE_DOC
        real = ec.COVERAGE_DOC.read_text(encoding="utf-8")
        a, b = real.find(ec.DOC_BEGIN), real.find(ec.DOC_END)
        without = real[:a] + real[b + len(ec.DOC_END):] if a >= 0 else real
        p1, p2 = tmpd / "with.md", tmpd / "without.md"
        p1.write_text(real, encoding="utf-8")
        p2.write_text(without, encoding="utf-8")
        try:
            clc.COVERAGE_DOC = p1
            s1 = clc._find_coverage_doc_sources()
            clc.COVERAGE_DOC = p2
            s2 = clc._find_coverage_doc_sources()
        finally:
            clc.COVERAGE_DOC = orig
        _check("H15 the generated block does not change the rule scorecard set check_lane_coverage reads", s1 == s2 and s1,
               f"{len(s1)} vs {len(s2)}")
        # roundtrip on a temp copy
        p3 = tmpd / "rt.md"
        p3.write_text(without, encoding="utf-8")
        ec.write_doc(res, p3)
        _check("H16 doc roundtrip: write_doc then check_doc is clean", ec.check_doc(res, p3) is None)
        head, _sep, tail = p3.read_text(encoding="utf-8").partition(ec.DOC_BEGIN)
        stale = head + ec.DOC_BEGIN + tail.replace("`common_port_scan`", "`common_port_scanX`", 1)
        p3.write_text(stale, encoding="utf-8")
        _check("H16 NEGATIVE: a hand-edited generated table is reported stale", ec.check_doc(res, p3) is not None)
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


SECTIONS = (test_fast_probe, test_rule_probes, test_timing, test_spread, test_obfuscation, test_clock,
            test_noise, test_cost, test_cost_determinism_and_doc)


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
