"""Acceptance test for the oracle cross-check instruments (2026-10-02).

Standalone (NOT pytest), same style as test_layer_a.py / test_scenario_harness.py: ``[OK]`` / ``[FAIL]``
lines, exit 0 only when every check passes. Run:

    python eval/twin/test_oracle_crosscheck.py

Every instrument added here is tested with a POSITIVE and a NEGATIVE control -- a check that has never been
seen to go red proves nothing:

  (a) oracle_consistency forbidden-edge channel   was DEAD (read keys no graph edge carries); now fires on a
                                                  joined forbidden pair, stays quiet on a clean graph
  (b) oracle_derive findings                      each of F1..F14 caught on a deliberately skewed rule or
                                                  oracle; the clean tree has no unwaived finding on seeds 7/11
  (c) interpreter fidelity                        the static selector evaluator agrees with engine.Rule on
                                                  every (rule, event, perturbation); a variant that ignores
                                                  ``not`` is caught by the same fuzz
  (d) per-event companion suppression             a companion that crosses its threshold on an EARLIER event
                                                  than its sibling is NOT suppressed (checked against the
                                                  real Detector, not only against itself)
  (e) independence lint                           oracle_derive imports none of the engine it checks
  (f) three-way triangulation                     derived == observed on every step; a perturbed derivation
                                                  is caught
  (g) oracle mutation                             wrong claims lower the grade, a pipeline-coupled kill is
                                                  labelled as such, the identity mutant is never killed, an
                                                  oracle-blind grader scores ~0, the IMPROVED predictor agrees
                                                  with the measurement, saturation is excluded, the cache is
                                                  sound, waivers/ratchet have teeth
  (h) read-only                                   no oracle YAML is written; baseline.json is byte-identical
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import random
import shutil
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
for _p in (str(TWIN), str(SERVICES), str(ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import report  # noqa: E402  (first: pins ws4's `main` before anything imports one)
import yaml  # noqa: E402

import oracle_consistency as oc  # noqa: E402
import oracle_derive as od  # noqa: E402
import oracle_mutate as om  # noqa: E402
import scenario_registry as reg  # noqa: E402

FAILURES: list = []
# baseline.json is the FROZEN Phase 1 contract (its header says so); no step may touch it.
BASELINE_SHA256 = "f07c0df2491f328c2f38f871462df686b7188c85fbb7e701489c330f0930f279"


def _check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def _oracle(sdef) -> dict:
    return yaml.safe_load(Path(sdef.oracle_path).read_text(encoding="utf-8"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _kinds(findings, kind=None, item=None):
    return [f for f in findings if (kind is None or f["kind"] == kind) and (item is None or item in f["item"])]


IT = reg.BY_NAME["it_intrusion"]
AI = reg.BY_NAME["ai_to_ot"]
INFRA = reg.BY_NAME["infra_takeover"]
ORACLE_FILES = sorted(TWIN.glob("oracle*.yaml"))


# ===========================================================================
# (a) oracle_consistency: the forbidden-edge channel
# ===========================================================================
def test_forbidden_channel() -> None:
    oracle = {"expected_sequence": ["A", "B"], "detection_points": {},
              "allowed_relationships": [{"from": "A", "to": "B", "allowed": True},
                                        {"from": "B", "to": "A", "allowed": False}]}
    sd = SimpleNamespace(name="synthetic")
    joined = {"fired": [], "graph_edges": [],
              "per_forbidden_pair": [{"from": "B", "to": "A", "graded": True, "joined": True}]}
    clean = {"fired": [], "graph_edges": [],
             "per_forbidden_pair": [{"from": "B", "to": "A", "graded": True, "joined": False}]}
    f = oc.reconcile(7, sd, oracle=oracle, grade=joined)
    _check("(a) POSITIVE: a forbidden pair the grader reports joined=True is a FORBIDDEN finding",
           len(f["forbidden_edges_claimed"]) == 1 and f["forbidden_edges_claimed"][0]["basis"] == "per_forbidden_pair",
           f"{f['forbidden_edges_claimed']}")
    _check("(a) ...and, not being on the accepted list, it is NEW drift that would fail the gate",
           len(f["new"]) == 1 and f["new"][0]["kind"] == "forbidden")
    f = oc.reconcile(7, sd, oracle=oracle, grade=clean)
    _check("(a) NEGATIVE: joined=False raises no forbidden finding", not f["forbidden_edges_claimed"])
    f = oc.reconcile(7, sd, oracle=oracle, grade={"fired": [], "per_forbidden_pair": [],
                                                  "graph_edges": [{"from": "x", "to": "y", "kind": "k"}]})
    _check("(a) NEGATIVE: a real-shaped graph edge (from / to / kind only) cannot produce one",
           not f["forbidden_edges_claimed"])
    f = oc.reconcile(7, sd, oracle=oracle, grade={"fired": [], "per_forbidden_pair": [],
                                                  "graph_edges": [{"from_step": "B", "to_step": "A"}]})
    _check("(a) POSITIVE: an edge that names its steps explicitly still counts (synthetic graph shape)",
           len(f["forbidden_edges_claimed"]) == 1)
    f = oc.reconcile(7, sd, oracle=oracle, grade={"fired": [], "graph_edges": [],
                                                  "per_forbidden_pair": [{"from": "B", "to": "A", "graded": False}]})
    _check("(a) NEGATIVE: an ungraded forbidden pair (step not entity-bearing) raises nothing",
           not f["forbidden_edges_claimed"])
    # the accepted list: five order-blind entries, each real; a pair that stops joining is a STALE waiver
    real = {n: oc.reconcile(7, reg.BY_NAME[n]) for n in ("ai_to_ot", "it_intrusion", "infra_takeover")}
    counts = {n: len(r["forbidden_edges_claimed"]) for n, r in real.items()}
    _check("(a) the real pipeline joins exactly the 5 forbidden pairs (2+2+1), all on the accepted list",
           counts == {"ai_to_ot": 2, "it_intrusion": 2, "infra_takeover": 1}
           and all(not r["new"] and not r["stale_allowlist_entries"] for r in real.values()), f"{counts}")
    every_pair_unjoined = {"fired": [], "graph_edges": [], "per_forbidden_pair": [
        {"from": "process_anomaly", "to": "modbus_write", "graded": True, "joined": False},
        {"from": "credential_use", "to": "agent_mcp_tool_call", "graded": True, "joined": False}]}
    f = oc.reconcile(7, AI, oracle=_oracle(AI), grade=every_pair_unjoined)
    _check("(a) NEGATIVE: if the graph stopped joining a forbidden pair, its waiver is reported STALE",
           len(f["stale_allowlist_entries"]) == 2, f"{len(f['stale_allowlist_entries'])}")
    sixth = {"fired": [], "graph_edges": [], "per_forbidden_pair": [
        {"from": "process_anomaly", "to": "modbus_write", "graded": True, "joined": True},
        {"from": "credential_use", "to": "agent_mcp_tool_call", "graded": True, "joined": True},
        {"from": "n8n_execution", "to": "external_content", "graded": True, "joined": True}]}
    o2 = _oracle(AI)
    o2["allowed_relationships"].append({"from": "n8n_execution", "to": "external_content", "allowed": False})
    f = oc.reconcile(7, AI, oracle=o2, grade=sixth)
    _check("(a) a sixth forbidden join (not on the closed list) is NEW drift",
           [n["kind"] for n in f["new"] if n["kind"] == "forbidden"] == ["forbidden"] and f["accepted_count"] == 2)
    # reconcile(oracle=, grade=) must not change the answer of the plain call
    plain = real["infra_takeover"]
    again = oc.reconcile(7, INFRA, oracle=_oracle(INFRA),
                         grade=report._grade_chain(reg.run(INFRA, 7), _oracle(INFRA)))
    keys = ("stale_gaps", "decorative_expectations", "unexpected_firings", "forbidden_edges_claimed", "total")
    _check("(a) reconcile with a supplied oracle+grade equals the plain call (no behaviour change)",
           all(plain[k] == again[k] for k in keys))


# ===========================================================================
# (b) oracle_derive findings
# ===========================================================================
_RULES = od.load_rules()
_DERIVED: dict = {}


def derived_for(sdef, seed=7):
    k = (sdef.name, seed)
    if k not in _DERIVED:
        _DERIVED[k] = od.derive(sdef, seed, rules=_RULES)
    return _DERIVED[k]


def _run(sdef, oracle, seed=7, **kw):
    return od.run_checks(sdef, seed, rules=kw.pop("rules", _RULES), oracle=oracle,
                         derived=kw.pop("derived", derived_for(sdef, seed)), **kw)


def test_derive_clean_tree() -> None:
    glob = od.apply_waivers(od.lint_rules(_RULES), "*")
    _check("DER-NEG-1 the 35 rule files pass the static OCSF logsource lint (F10)",
           len(_RULES) == 35 and not glob["unwaived"], f"rules={len(_RULES)} bad={[f['item'] for f in glob['unwaived']]}")
    for seed in (7, 11):
        for sd in reg.ALL:
            res = _run(sd, _oracle(sd), seed)
            _check(f"DER-NEG-1 clean tree, {sd.name} seed {seed}: no unwaived finding, no stale waiver, "
                   f"0 undecided", res["ok"] and res["f2_count"] == 0,
                   f"unwaived={[(f['kind'], f['item'][:8]) for f in res['unwaived']]} "
                   f"waived={[f['kind'] for f in res['findings'] if f['waived']]}")
    it = _run(IT, _oracle(IT), 7)
    _check("DER-NEG-1 the only waived item on any storyline is it_intrusion's F14 (dated, with a reason)",
           [f["kind"] for f in it["findings"] if f["waived"]] == ["F14"]
           and all(not f["waived"] for sd in (AI, INFRA) for f in _run(sd, _oracle(sd), 7)["findings"]))
    for sd in (AI, INFRA):
        for seed in (7, 11):
            res = _run(sd, _oracle(sd), seed)
            _check(f"F14 CONTROL: {sd.name} seed {seed} (incident_membership_ok=True) does NOT trigger F14",
                   not _kinds(res["findings"], "F14"))
    _check("F14: it_intrusion triggers it on seeds 7 and 11 (observed incident_membership_ok=False, 3 incidents)",
           all(_kinds(_run(IT, _oracle(IT), s)["findings"], "F14") for s in (7, 11)))
    # F14 cites the right document
    src = (TWIN / "oracle_derive.py").read_text(encoding="utf-8")
    _check("F14 cites services/ws8-correlation/INTERFACE.md:186 (the 'tracks never merge' line), not ADR-009/010",
           "INTERFACE.md:186" in src and "ADR-009" not in src)
    _check("the amended it_intrusion oracle keeps evidence_completeness == 1.0 (F12 fix is not a loosening)",
           report._grade_chain(reg.run(IT, 7), _oracle(IT))["evidence_completeness"] == 1.0)


def test_derive_hand_skew() -> None:
    base = _oracle(IT)
    d = derived_for(IT)
    # F1: a non-matching expected rule
    decoy = od.pick_decoy(d, "priv_grant", "7d3e9a52-1f6c-4a88-9b3d-2e5c8f1a6d40")
    o = copy.deepcopy(base)
    o["detection_points"]["priv_grant"]["expected_rules"].append({"rule_id": decoy, "level": "high"})
    _check("DER-POS-2 F1: an expected rule that cannot fire at the step is caught",
           bool(_kinds(_run(IT, o)["unwaived"], "F1", decoy)))
    # F3: delete a firing one
    o = copy.deepcopy(base)
    o["detection_points"]["ssh_bruteforce"]["expected_rules"] = [
        r for r in o["detection_points"]["ssh_bruteforce"]["expected_rules"] if not r["rule_id"].startswith("6f1c8a2e")]
    _check("DER-POS-2 F3: deleting a rule that really fires is caught (the companion does not count)",
           [f["item"][:8] for f in _kinds(_run(IT, o)["unwaived"], "F3")] == ["6f1c8a2e"])
    # F4 + F5: gap flipped on a firing step
    o = copy.deepcopy(base)
    o["detection_points"]["ssh_bruteforce"]["gap"] = {"no_rule_exists": True}
    r = _run(IT, o)
    _check("DER-POS-2 F4: a `gap` declared where rules match is caught", bool(_kinds(r["unwaived"], "F4")))
    _check("DER-POS-2 F5: ...and so is a gap flag that contradicts the step's own expected_rules",
           bool(_kinds(r["unwaived"], "F5")))
    o = copy.deepcopy(base)
    o["detection_points"]["initial_access"]["gap"] = {"no_rule_exists": False}
    _check("DER-POS-2 F5: gap:false with no expected rules is caught (what the mutation suite's flip_gap_to_false "
           "survivor cannot see)", bool(_kinds(_run(IT, o)["unwaived"], "F5", "gap")))
    # F9: swap two steps
    o = copy.deepcopy(base)
    seq = o["expected_sequence"]
    i, j = seq.index("lateral_movement"), seq.index("priv_grant")
    seq[i], seq[j] = seq[j], seq[i]
    _check("DER-POS-2 F9: an expected_sequence that is not sorted by event time is caught",
           bool(_kinds(_run(IT, o)["unwaived"], "F9")))
    # F8: forbidden edge forward / allowed edge backwards
    o = copy.deepcopy(base)
    o["allowed_relationships"].append({"from": "ssh_bruteforce", "to": "dns_exfil", "allowed": False})
    _check("DER-POS-2 F8: a forbidden edge that is chronologically FORWARD is caught",
           bool(_kinds(_run(IT, o)["unwaived"], "F8", "ssh_bruteforce->dns_exfil")))
    o = copy.deepcopy(base)
    o["allowed_relationships"].append({"from": "dns_exfil", "to": "initial_access", "allowed": True})
    _check("DER-POS-2 F8: an allowed edge pointing BACKWARDS in event time is caught",
           bool(_kinds(_run(IT, o)["unwaived"], "F8", "dns_exfil->initial_access")))
    # F7: an edge between steps with disjoint entities
    o = copy.deepcopy(base)
    o["allowed_relationships"].append({"from": "recon_port_scan", "to": "priv_grant", "allowed": True})
    _check("DER-POS-2 F7: an allowed edge with no shared observable on any time-ordered path is caught",
           bool(_kinds(_run(IT, o)["unwaived"], "F7", "recon_port_scan->priv_grant")))
    _check("DER-NEG-2 F7: every real allowed edge of every storyline HAS a shared observable",
           all(not _kinds(_run(sd, _oracle(sd))["findings"], "F7") for sd in reg.ALL))
    # F12: the amended fields removed again
    o = copy.deepcopy(base)
    o["evidence"]["per_step"]["recon_port_scan"]["fields"].remove("dst_endpoint.ip")
    _check("DER-POS-2 F12: an expected stateful rule whose group_by is missing from the evidence fields is caught",
           bool(_kinds(_run(IT, o)["unwaived"], "F12", "aaa9dc23")))
    # F13
    o = copy.deepcopy(base)
    o["detection_points"]["recon_port_scan"]["expected_rules"][0]["level"] = "medium"
    _check("DER-POS-2 F13: a hand level that differs from the rule YAML is caught",
           bool(_kinds(_run(IT, o)["unwaived"], "F13")))
    # F6: an expected rule with no mitre.tactic
    no_tactic = sorted(rid for rid, r in _RULES.items() if not r.tactic)
    o = copy.deepcopy(_oracle(AI))
    o["detection_points"]["agent_mcp_tool_call"]["expected_rules"].append({"rule_id": no_tactic[0], "level": "medium"})
    _check("DER-POS-2 F6: an expected rule carrying no mitre.tactic is flagged (agent_tool_call_burst is the only one)",
           len(no_tactic) == 1 and bool(_kinds(_run(AI, o)["findings"], "F6", no_tactic[0])), f"{no_tactic}")
    _check("DER-NEG-2 F6: the shipped oracles expect no tactic-less rule",
           all(not _kinds(_run(sd, _oracle(sd))["findings"], "F6") for sd in reg.ALL))


def test_derive_rule_skew() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="derive_rules_"))
    try:
        def variant(fname, edit):
            d = tmp / fname
            if d.exists():
                shutil.rmtree(d)
            shutil.copytree(od.RULES_DIR, d)
            f = d / f"{edit[0]}.yml"
            raw = yaml.safe_load(f.read_text(encoding="utf-8"))
            edit[1](raw)
            f.write_text(yaml.safe_dump(raw), encoding="utf-8")
            return od.load_rules(d)

        r1 = variant("thr", ("common_bruteforce", lambda raw: raw["siem"].__setitem__("threshold", 50)))
        res = od.run_checks(IT, 7, rules=r1, oracle=_oracle(IT))
        _check("DER-POS-1 rule skew: raising the SSH brute-force threshold 10->50 is reported as F1 for that rule",
               bool(_kinds(res["unwaived"], "F1", "6f1c8a2e")), f"{[(f['kind'], f['item'][:8]) for f in res['unwaived']]}")
        r2 = variant("cls", ("common_bruteforce", lambda raw: raw["detection"]["failed_auth"].__setitem__("class_uid", 3003)))
        res = od.run_checks(IT, 7, rules=r2, oracle=_oracle(IT))
        _check("DER-POS-1 rule skew: changing a selector class_uid is reported as F1",
           bool(_kinds(res["unwaived"], "F1", "6f1c8a2e")))
        r3 = variant("grp", ("common_port_scan", lambda raw: raw["siem"].__setitem__("group_by", "actor.user.name")))
        res = od.run_checks(IT, 7, rules=r3, oracle=_oracle(IT))
        _check("DER-POS-1 rule skew: changing a group_by (to a field the events lack) is reported as F1",
               bool(_kinds(res["unwaived"], "F1", "1d2c3b4a")))
        r4 = variant("tac", ("common_priv_grant", lambda raw: raw["mitre"].pop("tactic")))
        res = od.run_checks(IT, 7, rules=r4, oracle=_oracle(IT))
        _check("DER-POS-1 rule skew: dropping a rule's mitre.tactic is reported as F6",
               bool(_kinds(res["findings"], "F6", "7d3e9a52")))
        r5 = variant("lvl", ("common_priv_grant", lambda raw: raw.__setitem__("level", "low")))
        res = od.run_checks(IT, 7, rules=r5, oracle=_oracle(IT))
        _check("DER-POS-1 rule skew: changing a rule's level is reported as F13",
               bool(_kinds(res["unwaived"], "F13", "7d3e9a52")))
        r6 = variant("cat", ("common_bruteforce", lambda raw: raw["logsource"].__setitem__("category", "network_activity")))
        f10 = od.lint_rules(r6)
        _check("DER-POS-1 rule skew: a logsource category incompatible with the class_uid is reported as F10",
               [f["item"][:8] for f in f10] == ["6f1c8a2e"], f"{[f['item'][:8] for f in f10]}")
        _check("DER-NEG-1 ...and the clean rules report none", not od.lint_rules(_RULES))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # F2 (undecidable) is a WARN with a cap, and an unmodelled operator is UNDECIDED, never guessed
    rule_raw = {"title": "t", "id": "00000000-0000-4000-8000-0000000000aa", "level": "high",
                "logsource": {"category": "account_change"},
                "detection": {"s": {"class_uid": 3003, "src_endpoint.ip": {"gt": 5}}, "condition": "s"},
                "mitre": {"tactic": "TA0003"}}
    undecided_rule = od.DRule(rule_raw)
    _check("DER-NEG-1 an operator the reader does not model (gt) evaluates to UNDECIDED, not True/False",
           od.eval_condition(undecided_rule, {"class_uid": 3003, "src_endpoint": {"ip": "x"}}) is None
           and od.eval_condition(undecided_rule, {"class_uid": 3002, "src_endpoint": {"ip": "x"}}) is False)
    rules2 = dict(_RULES)
    rules2[undecided_rule.id] = undecided_rule
    o = copy.deepcopy(_oracle(IT))
    o["detection_points"]["priv_grant"]["expected_rules"].append({"rule_id": undecided_rule.id, "level": "high"})
    d2 = od.derive(IT, 7, rules=rules2)
    res = od.run_checks(IT, 7, rules=rules2, oracle=o, derived=d2)
    _check("DER-POS-1 F2: an expected rule the model cannot decide is counted as F2 (WARN) and, over its cap of 0, fails",
           bool(_kinds(res["findings"], "F2")) and not res["ok"] and res["f2_over_cap"])
    res = od.run_checks(IT, 7, rules=rules2, oracle=o, derived=d2, f2_cap={"it_intrusion": 1})
    _check("DER-NEG-1 F2: raising the (closed) cap lets exactly that many through", res["ok"],
           f"unwaived={[f['kind'] for f in res['unwaived']]}")
    # waiver hygiene
    stale = {("it_intrusion", "F1", "x", "y"): "2026-10-02 this waiver no longer reproduces anything"}
    res = _run(IT, _oracle(IT), waived={**od._WAIVED, **stale})
    _check("DER-NEG-6 a waiver that no longer reproduces is a STALE waiver and fails",
           res["stale_waivers"] == [("it_intrusion", "F1", "x", "y")] and not res["ok"])
    bad = {("it_intrusion", "F14", "-", "incident_count"): "known"}
    res = _run(IT, _oracle(IT), waived=bad)
    _check("DER-NEG-6 a waiver without a dated reason fails", bool(res["bad_reasons"]) and not res["ok"])
    res = _run(IT, _oracle(IT), waived={})
    _check("DER-NEG-6 without its waiver, the day-one F14 is an unwaived FAIL",
           [f["kind"] for f in res["unwaived"]] == ["F14"])
    _check("every shipped waiver carries a dated reason",
           all(od._REASON_RE.match(v) for v in od._WAIVED.values()))


# ===========================================================================
# (c) interpreter fidelity vs engine.Rule
# ===========================================================================
def _engine():
    return sys.modules["engine"]


def _pool(rules: dict) -> dict:
    """Per field path, every scalar a rule compares it against (the values a perturbation can swap in)."""
    pool: dict = {}
    for r in rules.values():
        for sel in r.selections.values():
            for path, exp in sel.items():
                vals = pool.setdefault(path, [])
                for v in ([exp] if not isinstance(exp, dict) else
                          ([x for x in exp.get("in", [])] if isinstance(exp.get("in"), list) else [])):
                    if not isinstance(v, (dict, list)) and v not in vals:
                        vals.append(v)
    return pool


def _set_dotted(doc: dict, dotted: str, value) -> None:
    cur = doc
    parts = dotted.split(".")
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[p] = nxt
        cur = nxt
    cur[parts[-1]] = value


def _del_dotted(doc: dict, dotted: str) -> None:
    cur = doc
    parts = dotted.split(".")
    for p in parts[:-1]:
        cur = cur.get(p)
        if not isinstance(cur, dict):
            return
    cur.pop(parts[-1], None)


def fuzz_cases(seed: int = 1234) -> list:
    rng = random.Random(seed)
    cases = []
    seen: dict = {}
    for sd in reg.ALL:
        for s in (7, 11):
            for ev in reg.run(sd, s).events:
                if not (ev.parsed and ev.event):
                    continue
                shape = (ev.event.get("siem", {}).get("source_type"), ev.event.get("class_uid"),
                         ev.event.get("activity_id"))
                if seen.get(shape, 0) < 2:  # two events per distinct event shape is plenty for the selectors
                    seen[shape] = seen.get(shape, 0) + 1
                    cases.append(ev.event)
    pool = _pool(_RULES)
    out = []
    for event in cases:
        out.append(event)
        for path, vals in sorted(pool.items()):
            v = copy.deepcopy(event)
            _del_dotted(v, path)
            out.append(v)
            for alt in (rng.choice(vals) if vals else None, "zz-fuzz", 0, True, ""):
                if alt is None:
                    continue
                v = copy.deepcopy(event)
                _set_dotted(v, path, alt)
                out.append(v)
        for hour in range(0, 24 * 8, 5):  # sweep the clock across a week for outside_hours
            v = copy.deepcopy(event)
            v["time"] = 1751500000000 + hour * 3_600_000
            out.append(v)
    return out


def fidelity_mismatches(cases: list, rule_ids=None) -> tuple:
    eng = _engine()
    mismatches, undecided, compared = [], 0, 0
    for rid, rule in sorted(_RULES.items()):
        if rule_ids and rid not in rule_ids:
            continue
        real = eng.Rule(rule.raw)
        for event in cases:
            mine = od.eval_condition(rule, event)
            if mine is None:
                undecided += 1
                continue
            compared += 1
            if bool(real._eval_condition(copy.deepcopy(event))) != mine:
                mismatches.append((rid[:8], event.get("class_uid"), mine))
    return mismatches, undecided, compared


def test_interpreter_fidelity() -> None:
    cases = fuzz_cases()
    mism, undec, compared = fidelity_mismatches(cases)
    _check("DER-NEG-2 the static evaluator agrees with engine.Rule._eval_condition on every (rule, event, "
           "perturbation)", not mism and compared > 10_000, f"compared={compared} mismatches={mism[:3]}")
    _check("DER-NEG-2 ...and decides every one of them (the shipped rules use only modelled operators)",
           undec == 0, f"undecided={undec}")
    real_not = od._tri_not
    try:
        od._tri_not = lambda v: v  # a deliberately broken variant: `not` ignored
        broken, _u, _c = fidelity_mismatches(cases, rule_ids=None)
    finally:
        od._tri_not = real_not
    broken_rules = {m[0] for m in broken}
    _check("DER-NEG-2 CONTROL: a variant that ignores `not` is caught by the same fuzz (ot_modbus_unauthorized_write "
           "is the one rule whose condition uses `not`)", "9c1d2e3f" in broken_rules,
           f"mismatches={len(broken)} rules={sorted(broken_rules)}")
    _check("DER-NEG-2 ...and the unbroken evaluator is restored", od._tri_not is real_not)
    real_oh = od._outside_hours
    try:
        od._outside_hours = lambda spec, actual: False  # broken: never outside hours
        broken2, _u, _c = fidelity_mismatches(cases, rule_ids=None)
    finally:
        od._outside_hours = real_oh
    _check("DER-NEG-2 CONTROL: a variant with a broken outside_hours is caught (clock sweep)",
           len(broken2) > 0, f"mismatches={len(broken2)}")


# ===========================================================================
# (d) per-event companion suppression, against the REAL Detector
# ===========================================================================
def test_companion_per_event() -> None:
    sib, comp = "00000000-0000-4000-8000-0000000000a1", "00000000-0000-4000-8000-0000000000a2"
    base_rule = {"status": "stable", "level": "high", "logsource": {"category": "authentication"},
                 "mitre": {"tactic": "TA0006"},
                 "detection": {"failed_auth": {"class_uid": 3002, "activity_id": 4}, "condition": "failed_auth"}}
    r_sib = {**base_rule, "title": "S", "id": sib,
             "siem": {"sector": "common", "window_seconds": 60, "threshold": 3, "group_by": "src_endpoint.ip"}}
    r_comp = {**base_rule, "title": "C", "id": comp, "level": "medium",
              "siem": {"sector": "common", "window_seconds": 60, "threshold": 2, "group_by": "actor.user.name",
                       "companion_of": sib, "score_weight": 0}}
    tmp = Path(tempfile.mkdtemp(prefix="derive_comp_"))
    try:
        rules_dir = tmp / "rules"
        rules_dir.mkdir()
        (tmp / "allowlists").mkdir()
        (rules_dir / "s.yml").write_text(yaml.safe_dump(r_sib), encoding="utf-8")
        (rules_dir / "c.yml").write_text(yaml.safe_dump(r_comp), encoding="utf-8")
        drules = od.load_rules(rules_dir)
        t0 = 1751500000000
        seq = [("a", t0), ("b", t0 + 1000), ("a", t0 + 2000), ("a", t0 + 3000)]  # one account throughout
        evs = []
        for n, (ip, t) in enumerate(seq):
            evs.append(SimpleNamespace(step="s1", parsed=True, raw_payload={}, event={
                "class_uid": 3002, "activity_id": 4, "time": t, "src_endpoint": {"ip": ip},
                "actor": {"user": {"name": "u"}}}))
        sd = SimpleNamespace(name="synthetic", steps=[SimpleNamespace(label="s1")])
        derived = od.derive(sd, 7, rules=drules, result=SimpleNamespace(events=evs))
        st = derived["steps"]["s1"]
        _check("DER-POS companion: the companion that crosses its threshold on EARLIER events than its sibling "
               "is NOT suppressed there", st["fires"].get(comp) == [1, 2], f"fires={st['fires']}")
        _check("DER-POS companion: ...and IS suppressed on the event where the sibling also matched",
               st["suppressed_events"].get(comp) == [3] and st["fires"].get(sib) == [3],
               f"suppressed={st['suppressed_events']}")
        # the same events through the real Detector: per-event matched ids must be identical
        det = report._WS4_MOD.Detector(rules_dir=rules_dir, allowlists_dir=tmp / "allowlists", plugin_rule_dirs=[])
        real = []
        for n, ev in enumerate(evs):
            e = copy.deepcopy(ev.event)
            e["siem"] = {"tenant": "twin-chain", "ingest_id": f"x:{n}"}
            _e, matched, _a = det.process(e)
            real.append(sorted(r.id for r in matched))
        mine = []
        for n in range(len(evs)):
            mine.append(sorted([r for r, v in st["fires"].items() if n in v]))
        _check("DER-NEG-4 per-event firing set equals the REAL Detector's on the synthetic burst",
               real == mine, f"real={[[x[-1:] for x in m] for m in real]} derived={[[x[-1:] for x in m] for m in mine]}")
        coarse = [[]] * len(evs)  # what a per-STEP "suppressed when the sibling fires at the step" model would say
        _check("DER-NEG-4 CONTROL: a per-step suppression model would have dropped the companion everywhere "
               "and disagrees with the real Detector", coarse != real)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# (e) independence lint
# ===========================================================================
def test_independence() -> None:
    _check("DER-NEG-3 oracle_derive.py imports none of engine / window / report / negative_controls / "
           "oracle_consistency", od.independence_violations() == [], f"{od.independence_violations()}")
    for bad in ("import engine\n", "from window import DequeWindowCounter\n", "import report\n",
                "from negative_controls import run_pipeline\n", "import oracle_consistency as oc\n",
                "from shared.window import DequeWindowCounter\n", "from shared.allowlist import load_allowlist\n",
                "import importlib\nm = importlib.import_module('report')\n"):
        _check(f"DER-NEG-3 CONTROL: {bad.strip().splitlines()[-1]!r} is flagged",
               bool(od.independence_violations(source=bad)))
    _check("DER-NEG-3 a harmless import is not flagged", od.independence_violations(source="import json\nimport yaml\n") == [])


# ===========================================================================
# (f) three-way triangulation
# ===========================================================================
def test_triangulation() -> None:
    for seed in (7, 11):
        for sd in reg.ALL:
            t = oc.triangulate(seed, sd)
            _check(f"DER-NEG-4 {sd.name} seed {seed}: derived (rule files alone) == observed (the real engine) on "
                   "every step", t["ok"] and not t["differences"], f"{t['differences']}")
    sd = AI
    g = report._grade_chain(reg.run(sd, 7), _oracle(sd))
    d = copy.deepcopy(derived_for(sd))
    d["steps"]["credential_use"]["fires"]["9c1d2e3f-4a5b-4c6d-8e7f-1a2b3c4d5e6f"] = [0]
    t = oc.triangulate(7, sd, grade=g, derived=d)
    _check("DER-NEG-4 CONTROL: a perturbed derivation (a rule the engine did not fire) is reported", not t["ok"]
           and t["differences"][0]["side"] == "derived-only", f"{t['differences']}")
    g2 = copy.deepcopy(g)
    g2["fired"].append({"step": "credential_use", "rule_id": "92a3b4c5-d627-4f05-ad6f-7a8b9c0d1e24"})
    t = oc.triangulate(7, sd, grade=g2, derived=derived_for(sd))
    _check("DER-NEG-4 CONTROL: ...and so is an alert the derivation did not expect (observed-only)",
           not t["ok"] and t["differences"][0]["side"] == "observed-only")
    waived = {("ai_to_ot", "credential_use", "92a3b4c5-d627-4f05-ad6f-7a8b9c0d1e24"): "2026-10-02 synthetic waiver for the test"}
    t = oc.triangulate(7, sd, grade=g2, derived=derived_for(sd), waived=waived)
    _check("DER-NEG-6 a dated waiver admits exactly that difference", t["ok"])
    t = oc.triangulate(7, sd, grade=g, derived=derived_for(sd), waived=waived)
    _check("DER-NEG-6 ...and a waiver that stops reproducing is stale", not t["ok"] and len(t["stale_waivers"]) == 1)


# ===========================================================================
# (g) oracle mutation
# ===========================================================================
def _one(sdef, mutant_id, seed=7, grader=None, cache=True):
    oracle = _oracle(sdef)
    result = reg.run(sdef, seed)
    g = (grader or om.default_grader)
    base_grade = g(result, copy.deepcopy(oracle))
    base_v = om.verdict(base_grade, oracle, sdef, seed)
    derived = od.derive(sdef, seed, result=result)
    muts = {m.id: m for m in om.catalogue(oracle, derived, base_grade)}
    mu = muts[mutant_id]
    mo = copy.deepcopy(oracle)
    mu.fn(mo)
    v = om.verdict(g(result, mo), mo, sdef, seed)
    return om.classify(mu.kind, base_v, v, mu.saturated_if), base_v, v, base_grade


def test_mutation_controls() -> None:
    with om.memoize_observation():
        # MUT-POS-1: swap the modbus write's expected rule for one that cannot fire there
        oracle = _oracle(AI)
        derived = od.derive(AI, 7)
        decoy = od.pick_decoy(derived, "modbus_write", "9c1d2e3f-4a5b-4c6d-8e7f-1a2b3c4d5e6f")
        mid = f"swap_expected_rule:modbus_write:9c1d2e3f->{decoy[:8]}"
        (outcome, detail), base_v, mut_v, _bg = _one(AI, mid)
        _check("MUT-POS-1 swapping the AI-to-OT modbus_write rule for a decoy is KILLED by a HEADLINE metric (TPR)",
               outcome == "KILLED_HEADLINE" and "tpr" in detail["worse_headline"], f"{outcome} {detail['worse_headline']}")
        _check("MUT-POS-1 ...tpr_numerator 5->4 and tpr falls from 1.0",
               (base_v["tpr_numerator"], mut_v["tpr_numerator"]) == (5, 4) and base_v["tpr"] == 1.0 > mut_v["tpr"],
               f"{base_v['tpr_numerator']}->{mut_v['tpr_numerator']} tpr {base_v['tpr']}->{mut_v['tpr']}")
        _check("MUT-POS-1 the decoy really cannot fire there (derived says so) and has a different tactic",
               od.cannot_match(derived, "modbus_write", decoy)
               and derived["rules"][decoy]["tactic"] != derived["rules"]["9c1d2e3f-4a5b-4c6d-8e7f-1a2b3c4d5e6f"]["tactic"])
        # MUT-POS-2: a never-firing SECOND expected rule: TPR cannot see it; reconcile does
        first_n8n = oracle["detection_points"]["n8n_execution"]["expected_rules"][0]["rule_id"]
        d2 = od.pick_decoy(derived, "n8n_execution", first_n8n)
        (outcome, detail), base_v, mut_v, _bg = _one(AI, f"add_expected_rule:n8n_execution:{d2[:8]}")
        _check("MUT-POS-2 adding a never-firing second expected rule leaves TPR unchanged ...",
               base_v["tpr"] == mut_v["tpr"] and not detail["worse_headline"], f"{detail}")
        _check("MUT-POS-2 ... and is KILLED_COUPLED only, via reconcile (DECORATIVE): the suite is stronger than "
               "TPR alone but labels that strength as pipeline coupling",
               outcome == "KILLED_COUPLED" and any(c.startswith("rec:") for c in detail["worse_coupled"]),
               f"{outcome} {detail['worse_coupled']}")
        # MUT-NEG-1: the identity mutant
        for sd in reg.ALL:
            (outcome, detail), bv, mv, _bg = _one(sd, "identity")
            _check(f"MUT-NEG-1 identity mutant, {sd.name}: byte-identical verdict fingerprint, never killed",
                   outcome == "SURVIVED" and om.fingerprint(bv) == om.fingerprint(mv))
        # MUT-NEG-3: the IMPROVED predictor agrees with the measurement
        (outcome, _d), _bv, _mv, bg = _one(IT, "reverse_relationship:recon_port_scan->ssh_bruteforce[allowed]")
        pred = om.predict_reversal(bg, "recon_port_scan", "ssh_bruteforce")
        _check("MUT-NEG-3 it_intrusion recon_port_scan->ssh_bruteforce: predicted IMPROVED from per_allowed_pair "
               "(joined=False, reverse_joined=True), then measured IMPROVED",
               pred == "IMPROVED" and outcome == "IMPROVED", f"predicted={pred} measured={outcome}")
        (outcome, _d), _bv, _mv, bg = _one(IT, "reverse_relationship:ssh_bruteforce->initial_access[allowed]")
        pred = om.predict_reversal(bg, "ssh_bruteforce", "initial_access")
        _check("MUT-NEG-3 CONTROL: a pair joined in both directions is predicted UNCHANGED and survives",
               pred == "UNCHANGED" and outcome == "SURVIVED", f"predicted={pred} measured={outcome}")
        # MUT-NEG-4: saturation
        (outcome, _d), bv, _mv, _bg = _one(IT, "change_incident_count:1->2")
        _check("MUT-NEG-4 incident_count 1->2 on it_intrusion is SATURATED (membership is already False) and so "
               "excluded from the score", outcome == "SATURATED" and bv["incident_membership_ok"] is False)
        (outcome, _d), bv, _mv, _bg = _one(AI, "change_incident_count:1->2")
        _check("MUT-NEG-4 CONTROL: the same mutant on ai_to_ot (membership True) is KILLED, not saturated",
               outcome == "KILLED_HEADLINE", outcome)
        # a WEAKER mutant is held to "noticed", a WRONG one to "worse"
        (outcome, _d), _bv, _mv, _bg = _one(IT, "drop_step:dns_exfil")
        _check("MUT-POS-3 WEAKER: dropping a step is NOTICED by a headline metric", outcome == "KILLED_HEADLINE", outcome)
        (outcome, d3), _bv, _mv, _bg = _one(INFRA, "tighten_severity_band:min>peak")
        _check("MUT-POS-3 a tightened severity band is caught, but only through the COUPLED severity channel",
               outcome == "KILLED_COUPLED" and "in_band" in d3["worse_coupled"], f"{outcome} {d3['worse_coupled']}")
        (outcome, _d), _bv, _mv, _bg = _one(AI, "add_missing_evidence_field:agent_mcp_tool_call")
        _check("MUT-POS-3 claiming an evidence field no event carries lowers evidence_completeness (headline)",
               outcome == "KILLED_HEADLINE")
        (outcome, _d), _bv, _mv, _bg = _one(AI, "swap_adjacent_steps:n8n_execution<>agent_mcp_tool_call")
        _check("MUT-POS-3 swapping two alerting steps flips alert_order_ok (headline)", outcome == "KILLED_HEADLINE")


def test_mutation_blind_grader() -> None:
    sd = INFRA
    oracle = _oracle(sd)
    base_grade = om.default_grader(reg.run(sd, 7), copy.deepcopy(oracle))
    blind = lambda result, o: copy.deepcopy(base_grade)  # noqa: E731 - ignores the oracle entirely
    with om.memoize_observation():
        run = om.run_scenario(sd, 7, grader=blind)
        real = om.run_scenario(sd, 7)
    ev_blind, ev_real = om.evaluate(run), om.evaluate(real)
    _check("MUT-NEG-2 an oracle-BLIND grader scores ~0 on the headline mutation score "
           f"({ev_blind['score']['headline_score']} vs {ev_real['score']['headline_score']} for the real grader)",
           (ev_blind["score"]["headline_score"] or 0) < 0.05 and (ev_real["score"]["headline_score"] or 0) > 0.4)
    strength = om.load_strength()
    sec = ((strength or {}).get("seeds") or {}).get("7") or {}
    committed = {k: v for k, v in (sec.get("outcomes") or {}).items() if k == sd.name}
    cur = {sd.name: {r["id"]: r["outcome"] for r in run["rows"]}}
    rd = om.ratchet_diff(cur, committed or None)
    _check("MUT-NEG-2 ...and the committed ratchet turns that into a FAILURE (killed mutants now survive)",
           bool(rd["regressions"]) and not rd["missing_file"], f"regressions={len(rd['regressions'])}")
    rd_ok = om.ratchet_diff({sd.name: {r["id"]: r["outcome"] for r in real["rows"]}}, committed)
    _check("MUT-NEG-2 CONTROL: the real grader matches the committed ratchet exactly",
           not rd_ok["regressions"] and not rd_ok["stale"], f"{rd_ok['regressions'][:2]} {rd_ok['stale'][:2]}")


def test_mutation_determinism_and_cache() -> None:
    sd = INFRA
    with om.memoize_observation():
        a = om.run_scenario(sd, 7)
        b = om.run_scenario(sd, 7)
    _check("MUT-NEG-1 determinism: the same seed gives byte-identical mutation output",
           json.dumps(a, sort_keys=True, default=str) == json.dumps(b, sort_keys=True, default=str))
    with om.memoize_observation():
        a2 = om.run_scenario(sd, 7)
    _check("MUT-NEG-1 ...and the same result with a fresh cache (outcomes do not depend on cache state)",
           [r["outcome"] for r in a["rows"]] == [r["outcome"] for r in a2["rows"]])

    def plain_vs_cached(sdef, seed):
        oracle = _oracle(sdef)
        result = reg.run(sdef, seed)
        plain = report._grade_chain(result, oracle)
        with om.memoize_observation():
            first = report._grade_chain(result, oracle)
            second = report._grade_chain(result, oracle)
        strip = lambda g: json.dumps({k: v for k, v in g.items() if k != "incident_reconstruction"},  # noqa: E731
                                     sort_keys=True, default=str)
        return strip(plain) == strip(first) == strip(second)

    for sd2, seed in ((AI, 7), (IT, 7), (INFRA, 7), (IT, 11)):
        _check(f"MUT-NEG-5 cache soundness: memoized grade == plain grade byte for byte ({sd2.name}, seed {seed}; "
               "wall-clock reconstruction timings excluded)", plain_vs_cached(sd2, seed))
    om.CACHE_STATS.update(hits=0, misses=0)
    result = reg.run(INFRA, 7)
    oracle = _oracle(INFRA)
    with om.memoize_observation():
        report._grade_chain(result, oracle)
        m1 = om.CACHE_STATS["misses"]
        report._grade_chain(result, oracle)
        hits_same, miss_same = om.CACHE_STATS["hits"], om.CACHE_STATS["misses"]
        changed = reg.run(INFRA, 11)
        report._grade_chain(changed, oracle)
        miss_changed = om.CACHE_STATS["misses"]
    _check("MUT-NEG-5 the second identical grade is all hits ...", miss_same == m1 and hits_same >= 2,
           f"misses {m1}->{miss_same} hits={hits_same}")
    _check("MUT-NEG-5 ... and a changed raw payload (another seed) is a cache MISS", miss_changed > miss_same,
           f"misses {miss_same}->{miss_changed}")
    _check("MUT-NEG-5 the monkeypatch is always undone", "keyed" not in getattr(report._real_detection, "__qualname__", ""))


def _fake_run(scen, rows):
    return {"scenario": scen, "rows": [{"id": i, "operator": op, "kind": kind, "outcome": out}
                                       for i, op, kind, out in rows]}


def test_waiver_hygiene() -> None:
    reason = "2026-10-02 this class of mutant is unobservable by construction in this synthetic test"
    run = _fake_run("s", [("a1", "op", "WRONG", "SURVIVED"), ("a2", "op", "WRONG", "SURVIVED"),
                          ("b1", "op2", "WRONG", "KILLED_HEADLINE"), ("c1", "op3", "WRONG", "IMPROVED")])
    ev = om.evaluate(run, equivalent={})
    _check("MUT-NEG-6 an unwaived SURVIVED and an unwaived IMPROVED both fail",
           len(ev["unwaived"]) == 2 and not ev["ok"])
    ev = om.evaluate(run, equivalent={("s", "op", "SURVIVED"): {"max": 2, "reason": reason},
                                      ("s", "op3", "IMPROVED"): {"max": 1, "reason": reason}})
    _check("MUT-NEG-6 a capped, dated waiver admits exactly its class", ev["ok"] and ev["score"]["waived"] == 3,
           f"{ev}")
    ev = om.evaluate(run, equivalent={("s", "op", "SURVIVED"): {"max": 1, "reason": reason},
                                      ("s", "op3", "IMPROVED"): {"max": 1, "reason": reason}})
    _check("MUT-NEG-6 a class that GROWS past its cap fails", len(ev["over_cap"]) == 1 and not ev["ok"])
    ev = om.evaluate(run, equivalent={("s", "op", "SURVIVED"): {"max": 2, "reason": reason},
                                      ("s", "op3", "IMPROVED"): {"max": 1, "reason": reason},
                                      ("s", "op2", "SURVIVED"): {"max": 1, "reason": reason}})
    _check("MUT-NEG-6 a waiver that no longer reproduces is a STALE waiver and fails",
           ev["stale_waivers"] == [["s", "op2", "SURVIVED"]] and not ev["ok"])
    ev = om.evaluate(run, equivalent={("s", "op", "SURVIVED"): {"max": 2, "reason": "equivalent"},
                                      ("s", "op3", "IMPROVED"): {"max": 1, "reason": reason}})
    _check("MUT-NEG-6 a waiver without a dated reason fails", bool(ev["bad_reasons"]) and not ev["ok"])
    crash = _fake_run("s", [("x", "op", "WRONG", "CRASH")])
    ev = om.evaluate(crash, equivalent={("s", "op", "CRASH"): {"max": 1, "reason": reason}})
    _check("MUT-NEG-6 a CRASH can never be waived", not ev["ok"])
    ident = _fake_run("s", [("identity", "identity", "NEUTRAL", "KILLED_HEADLINE")])
    _check("MUT-NEG-1 an identity mutant that is 'killed' fails (a false kill)", not om.evaluate(ident, equivalent={})["ok"])
    # saturated + waived mutants leave the score denominator
    run2 = _fake_run("s", [("k", "op", "WRONG", "KILLED_HEADLINE"), ("s1", "op", "WRONG", "SATURATED"),
                           ("c", "op", "WRONG", "KILLED_COUPLED"), ("w", "op4", "WRONG", "SURVIVED")])
    ev = om.evaluate(run2, equivalent={("s", "op4", "SURVIVED"): {"max": 1, "reason": reason}})
    _check("MUT-NEG-4 SATURATED and waived mutants are excluded from the score; coupled kills do not count as "
           "headline strength", ev["score"]["eligible"] == 2 and ev["score"]["headline_score"] == 0.5
           and ev["score"]["any_kill_score"] == 1.0, f"{ev['score']}")
    # inert-key table
    inert = {"x": {"inert": ["a", "doc"], "read": ["r"]}, "y": {"inert": ["a"], "read": ["doc2"]}}
    labels = {"a": "declared-but-unenforced: 2026-10-02 unread", "doc": "doc-only: 2026-10-02 prose"}
    ei = om.evaluate_inert(inert, labels)
    _check("MUT-NEG-6 a closed inert-key table with dated labels passes", ei["ok"], f"{ei}")
    _check("MUT-NEG-6 an inert key missing from the table fails",
           om.evaluate_inert(inert, {"a": labels["a"]})["unknown"] == ["doc"])
    _check("MUT-NEG-6 a table entry that is no longer inert (stale) fails",
           om.evaluate_inert(inert, {**labels, "gone": labels["a"]})["stale"] == ["gone"])
    _check("MUT-NEG-6 a label without a date or kind fails",
           om.evaluate_inert(inert, {"a": "unread", "doc": labels["doc"]})["bad_labels"] == ["a"])
    _check("MUT-NEG-6 a key inert in one storyline but READ in another is not reported as unread",
           om.evaluate_inert({"x": {"inert": ["k"], "read": []}, "y": {"inert": [], "read": ["k"]}}, {})["ok"])
    # ratchet semantics
    cur = {"s": {"a": "KILLED_HEADLINE", "b": "SURVIVED"}}
    _check("ratchet: identical -> clean", om.ratchet_diff(cur, copy.deepcopy(cur)) ==
           {"regressions": [], "stale": [], "missing_file": False})
    d = om.ratchet_diff({"s": {"a": "SURVIVED", "b": "SURVIVED"}}, cur)
    _check("ratchet: a previously killed mutant that now survives is a REGRESSION",
           [r["id"] for r in d["regressions"]] == ["a"])
    d = om.ratchet_diff({"s": {"a": "KILLED_HEADLINE", "b": "KILLED_HEADLINE"}}, cur)
    _check("ratchet: an unrecorded improvement means the file LAGS reality (fails until regenerated)",
           not d["regressions"] and len(d["stale"]) == 1)
    d = om.ratchet_diff({"s": {"a": "KILLED_HEADLINE", "b": "SURVIVED", "n": "SURVIVED"}}, cur)
    _check("ratchet: a new mutant id lags the file too", len(d["stale"]) == 1)
    _check("ratchet: no committed file -> missing_file", om.ratchet_diff(cur, None)["missing_file"])


def test_committed_artifact_and_inert_probe() -> None:
    strength = om.load_strength()
    _check("eval/twin/oracle_strength.json is committed with seeds 7 and 11 and all three storylines",
           bool(strength) and sorted(strength["seeds"]) == ["11", "7"]
           and all(sorted(s["outcomes"]) == ["ai_to_ot", "infra_takeover", "it_intrusion"]
                   for s in strength["seeds"].values()))
    text = om.STRENGTH_PATH.read_text(encoding="utf-8")
    # structural, not a substring grep: an oracle KEY NAME such as ``max_clock_span_seconds`` (a string value
    # in the unenforced-key list) is not a measurement. Only a JSON object KEY that looks like a timing counts.
    wall_keys: list = []

    def _walk(node) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if any(w in str(k).lower() for w in ("elapsed", "seconds", "duration", "wall", "timestamp", "generated_at")):
                    wall_keys.append(k)
                _walk(v)
        elif isinstance(node, list):
            for v in node:
                _walk(v)

    _walk(json.loads(text))
    _check("...and carries no wall-clock field (deterministic)", not wall_keys, str(wall_keys[:3]))
    with om.memoize_observation():
        pr = om.inert_probe(AI, 7)
    _check("inert-key probe POSITIVE: incident_membership.cross_step_rule_ids is READ (it must stay out of the "
           "unenforced list)", "incident_membership.cross_step_rule_ids[]" in pr["read"]
           and "incident_membership.cross_step_rule_ids[]" not in pr["inert"])
    _check("inert-key probe POSITIVE: a prose key (`description`) and an unread requirement (`strict_order`) are inert",
           {"description", "sequence_constraints.strict_order"} <= set(pr["inert"]))
    _check("inert-key probe NEGATIVE: keys the graders read (rule_id, level, gap flag, allowed, fields) are not inert",
           {"detection_points.*.expected_rules[].rule_id", "detection_points.*.expected_rules[].level",
            "detection_points.*.gap.no_rule_exists", "allowed_relationships[].allowed",
            "evidence.per_step.*.fields[]", "severity_band.score.max"} <= set(pr["read"]))
    def key_name(path: str) -> str:
        parts = path.replace("[]", "").split(".")
        return "severity_id" if parts[-1] in ("min", "max") and parts[-2] == "severity_id" else parts[-1]

    names = {key_name(k) for k, v in om._INERT_KEYS.items() if v.startswith("declared")}
    _check("the declared-but-unenforced list covers exactly the TWELVE unread oracle keys (cross_step_rule_ids excluded)",
           names == {"strict_order", "allow_extra_steps", "max_clock_span_seconds", "causal_kind", "incident_key",
                     "include", "severity_id", "dominant_band", "correlation_key", "expected_event_source",
                     "role", "title"}, f"{sorted(names)}")


def test_catalogue_size_and_read_only() -> None:
    n = 0
    for sd in reg.ALL:
        oracle = _oracle(sd)
        result = reg.run(sd, 7)
        with om.memoize_observation():
            g = om.default_grader(result, copy.deepcopy(oracle))
        n += len(om.catalogue(oracle, od.derive(sd, 7, result=result), g)) - 1
    _check("the catalogue holds about 250 mutants over the three storylines (WRONG + WEAKER, identity excluded)",
           200 <= n <= 300, f"{n}")
    before = {p.name: _sha(p) for p in ORACLE_FILES}
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        od.main(["--scenario", "infra_takeover"])
        om.main(["--scenario", "infra_takeover"])
    _check("the CLIs print the shared-ground-truth LIMIT (the derived oracle detects skew, not original error)",
           "SHARES the rule YAML" in buf.getvalue() and "skew and drift" in buf.getvalue())
    _check("READ-ONLY: no oracle YAML is written by derive or mutate", before == {p.name: _sha(p) for p in ORACLE_FILES})
    _check("READ-ONLY: eval/twin/baseline.json is byte-identical to the frozen contract",
           _sha(TWIN / "baseline.json") == BASELINE_SHA256)
    p = TWIN / "oracle_strength.json"
    before_s = _sha(p)
    with contextlib.redirect_stdout(io.StringIO()):
        om.main(["--scenario", "infra_takeover"])
    _check("the gate never writes oracle_strength.json (only --update-baseline does)", before_s == _sha(p))


def main() -> int:
    test_forbidden_channel()
    test_derive_clean_tree()
    test_derive_hand_skew()
    test_derive_rule_skew()
    test_interpreter_fidelity()
    test_companion_per_event()
    test_independence()
    test_triangulation()
    test_mutation_controls()
    test_mutation_blind_grader()
    test_mutation_determinism_and_cache()
    test_waiver_hygiene()
    test_committed_artifact_and_inert_probe()
    test_catalogue_size_and_read_only()
    if FAILURES:
        print(f"\n[FAIL] {len(FAILURES)} check(s) failed:")
        for f in FAILURES:
            print(f"   - {f}")
        return 1
    print("\n[OK] oracle cross-check: every instrument passed its positive AND negative control.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
