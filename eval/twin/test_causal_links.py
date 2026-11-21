"""causal_links -- acceptance test for the link grader and gate (eval/twin/causal_links.py; ADR-012 W3a).

Standalone (NOT pytest), matching the repo twin-test style: ``[OK]``/``[FAIL]`` lines, exit 0 only when
every check passes. Run:  python eval/twin/test_causal_links.py

Hand-built fixtures only (no pipeline, no ws8). What is proved, every instrument with a positive AND a
negative control:

  (a) METRICS     precision / recall / direction accuracy / coverage on a perfect, a noisy and a lossy set,
                  each with (k, n) and a Wilson 95 % interval (checked against the ADR's "about 0.91 for
                  0 false in 40").
  (b) GRADABLE    a truth link with an unalerted endpoint is excluded from the denominator AND listed with its
                  reason; an unmapped / decoy / ambiguous / intra-step / repeated emitted link is handled
                  explicitly, never silently.
  (c) GATE        pass; insufficient_n for EACH threshold alone (gradable n, storylines, bases, per-basis n,
                  the 40 % share cap, with its exact boundary); never a pass on thin data even with a perfect
                  control; fail when the key_shuffle control is missing or does not collapse.
  (d) MUTATIONS   a grader that ignores direction, ignores the basis, or has a loosened gate constant FAILS
                  the checks above (mutated copies, restored).
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

import causal_links as cl  # noqa: E402

_FAILURES: list = []


def _check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        _FAILURES.append(name)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
KEY = {"ns": "flow", "role": "self", "h": "0123456789abcdef", "scope_trust": "observed"}


def ev(story: str, step: str) -> str:
    return f"ev-{story}-{step}"


def item(story: str, step: str, keyed: bool = True) -> dict:
    alert: dict[str, Any] = {"alert_id": f"al-{story}-{step}", "event_ids": [ev(story, step)]}
    if keyed:
        alert["causal_keys"] = [dict(KEY)]
    return {"step": step, "alert": alert}


def link(story: str, a: str, b: str, basis: str = "network_flow", order: str = "forward") -> dict:
    return {"from_event_id": ev(story, a), "to_event_id": ev(story, b), "basis": basis, "order": order,
            "from_ts_ms": 1, "to_ts_ms": 2, "trust": "observed"}


def chain(story: str, n_links: int, basis: str = "network_flow") -> tuple:
    """A perfect storyline: ``n_links`` truth links s0->s1->..., all alerted, all emitted forward."""
    steps = [f"s{i}" for i in range(n_links + 1)]
    items = [item(story, s) for s in steps]
    truth = [{"from": steps[i], "to": steps[i + 1], "basis": basis} for i in range(n_links)]
    emitted = [link(story, steps[i], steps[i + 1], basis) for i in range(n_links)]
    return items, truth, emitted


def graded(story: str, n_links: int, basis: str = "network_flow", **kw) -> dict:
    items, truth, emitted = chain(story, n_links, basis)
    return cl.grade_storyline(story, emitted, truth, items)


def shuffled_result(story: str, n_links: int, basis: str = "network_flow") -> dict:
    """What a working linker emits after key_shuffle: one wrong link, none of the truth."""
    items, truth, _ = chain(story, n_links, basis)
    return cl.grade_storyline(story, [link(story, "s0", "s2", basis)], truth, items)


def plan(spec: list) -> tuple:
    """``spec`` = [(story, n_links, basis), ...] -> (baseline results, shuffled results)."""
    return ([graded(s, n, b) for s, n, b in spec], [shuffled_result(s, n, b) for s, n, b in spec])


PASS_SPEC = [("A", 8, "network_flow"), ("B", 8, "network_flow"), ("C", 8, "process_tree"),
             ("D", 8, "process_tree"), ("E", 8, "network_flow")]  # 40 links, flow 24 / proc 16


# ---------------------------------------------------------------------------
# (a) metrics
# ---------------------------------------------------------------------------
def test_metrics() -> None:
    g = graded("A", 4)
    _check("(a) perfect set: precision, recall, direction accuracy and coverage are all 1.0",
           (g["precision"]["value"], g["recall"]["value"], g["direction_accuracy"]["value"],
            g["coverage"]["value"]) == (1.0, 1.0, 1.0, 1.0), f"{g['precision']} {g['recall']}")
    _check("(a) every rate carries k, n and a Wilson 95 % interval",
           all(g[m]["wilson95"] is not None and g[m]["n"] > 0
               for m in ("precision", "recall", "direction_accuracy", "coverage")))

    # 0 false links in 40 -> Wilson lower bound ~0.91 (ADR-012 s.3)
    p = cl.combine([graded("A", 20), graded("B", 20)])["precision"]
    _check("(a) Wilson: 40 of 40 gives a lower bound of about 0.91 (the ADR's figure)",
           p["k"] == 40 and p["n"] == 40 and abs(p["wilson95"][0] - 0.9122) < 0.002 and p["wilson95"][1] == 1.0,
           str(p["wilson95"]))

    # precision: one extra false link s0 -> s2 on a 3-link chain
    items, truth, emitted = chain("A", 3)
    noisy = cl.grade_storyline("A", emitted + [link("A", "s0", "s2")], truth, items)
    _check("(a) NEGATIVE: a false link lowers precision to 3/4 and leaves recall at 1.0",
           noisy["precision"]["value"] == 0.75 and noisy["recall"]["value"] == 1.0,
           f"{noisy['precision']['k']}/{noisy['precision']['n']}")

    # recall: one truth link never emitted
    lossy = cl.grade_storyline("A", emitted[:-1], truth, items)
    _check("(a) NEGATIVE: a missed link lowers recall to 2/3 and leaves precision at 1.0",
           lossy["recall"]["value"] == round(2 / 3, 4) and lossy["precision"]["value"] == 1.0)

    # basis is part of the claim
    wrong_basis = cl.grade_storyline("A", [dict(lk, basis="agent_session") for lk in emitted], truth, items)
    _check("(a) NEGATIVE: the right pair on the wrong basis matches nothing",
           wrong_basis["matched"] == 0 and wrong_basis["precision"]["value"] == 0.0)

    # symmetric basis: either emitted direction matches the pair; direction then decides
    rev = [dict(lk, from_event_id=lk["to_event_id"], to_event_id=lk["from_event_id"]) for lk in emitted]
    r = cl.grade_storyline("A", rev, truth, items)
    _check("(a) a symmetric basis matches the pair in either emitted direction (recall 1.0) ...",
           r["recall"]["value"] == 1.0 and r["precision"]["value"] == 1.0)
    _check("(a) ... but the reversed direction scores 0 on direction accuracy",
           r["direction_accuracy"]["value"] == 0.0 and r["direction_accuracy"]["k"] == 0)

    # directed basis: process_tree parent->child, a reversed emitted link is a different claim
    pi, pt, pe = chain("P", 3, "process_tree")
    pr = cl.grade_storyline("P", [dict(lk, from_event_id=lk["to_event_id"], to_event_id=lk["from_event_id"])
                                  for lk in pe], pt, pi)
    _check("(a) NEGATIVE: a reversed process_tree link is NOT the parent->child truth link",
           pr["matched"] == 0 and pr["precision"]["value"] == 0.0 and pr["recall"]["value"] == 0.0)

    # a conflict order counts against direction accuracy
    c = cl.grade_storyline("A", [dict(lk, order="conflict") for lk in emitted], truth, items)
    _check("(a) NEGATIVE: order 'conflict' counts against direction accuracy (and is tallied)",
           c["direction_accuracy"]["value"] == 0.0 and c["order_counts"] == {"conflict": 3}, str(c["order_counts"]))

    # coverage
    unkeyed = [item("A", "s0", keyed=False), item("A", "s1"), item("A", "s2"), item("A", "s3")]
    cv = cl.grade_storyline("A", emitted, truth, unkeyed)["coverage"]
    _check("(a) coverage = keyed alerts / alerts (3 of 4), reported beside the link scores",
           (cv["k"], cv["n"], cv["value"]) == (3, 4, 0.75))

    # nothing emitted: precision undefined (None), never a fabricated number
    e = cl.grade_storyline("A", [], truth, items)
    _check("(a) no emitted link: recall 0.0, precision None (undefined, not 0 or 1)",
           e["recall"]["value"] == 0.0 and e["precision"]["value"] is None and e["precision"]["wilson95"] is None)


# ---------------------------------------------------------------------------
# (b) gradable / unmapped handling
# ---------------------------------------------------------------------------
def test_gradable() -> None:
    items = [item("A", s) for s in ("s0", "s1", "s2")]          # s3, s4 raised no alert
    truth = [{"from": "s0", "to": "s1", "basis": "network_flow"},
             {"from": "s1", "to": "s3", "basis": "network_flow"},
             {"from": "s4", "to": "s2", "basis": "network_flow"},
             {"from": "s3", "to": "s4", "basis": "network_flow"}]
    g = cl.grade_storyline("A", [link("A", "s0", "s1")], truth, items)
    reasons = sorted((n["from"], n["to"], n["reason"]) for n in g["non_gradable"])
    _check("(b) only links with BOTH endpoints alerted are gradable (1 of 4)",
           g["n_truth"] == 4 and g["n_gradable"] == 1 and g["recall"]["n"] == 1)
    _check("(b) the other three are LISTED with their reason, never silently dropped",
           reasons == [("s1", "s3", "to_unalerted"), ("s3", "s4", "both_unalerted"),
                       ("s4", "s2", "from_unalerted")], str(reasons))
    pooled = cl.combine([g])
    _check("(b) the pooled result keeps the non-gradable list and count",
           pooled["n_non_gradable"] == 3 and len(pooled["non_gradable"]) == 3 and pooled["n_gradable"] == 1)

    items, truth, emitted = chain("A", 2)
    decoy = {"from_event_id": ev("A", "s0"), "to_event_id": "ev-decoy-1", "basis": "network_flow",
             "order": "forward", "from_ts_ms": 1, "to_ts_ms": 2, "trust": "observed"}
    d = cl.grade_storyline("A", emitted + [decoy], truth, items)
    _check("(b) NEGATIVE: a link to an event no attack alert owns (a decoy) is a FALSE link, counted",
           d["unmapped"] == 1 and d["n_predicted"] == 3 and d["precision"]["value"] == round(2 / 3, 4))

    twin_item = {"step": "s0", "alert": {"alert_id": "al-A-s0-b", "event_ids": ["ev-A-s0-b"]}}
    intra = link("A", "s0", "s0")
    intra["to_event_id"] = "ev-A-s0-b"
    i2 = cl.grade_storyline("A", emitted + [intra], truth, items + [twin_item])
    _check("(b) a link between two events of ONE step is not a step-pair claim: tallied, outside precision",
           i2["intra_step"] == 1 and i2["precision"]["value"] == 1.0 and i2["n_predicted"] == 2)

    amb = cl.grade_storyline("A", emitted, truth,
                             items + [{"step": "s2", "alert": {"alert_id": "x", "event_ids": [ev("A", "s0")]}}])
    _check("(b) a handle that names alerts of two steps is ambiguous and maps to nothing",
           amb["unmapped"] >= 1 and amb["recall"]["value"] < 1.0)

    # folded / upserted alerts: one event_ids[0] heads two steps; the endpoint time disambiguates
    fold = [{"step": "s0", "alert": {"alert_id": "f", "event_ids": ["e0"], "time": 100}},
            {"step": "s1", "alert": {"alert_id": "f", "event_ids": ["e0", "e1"], "time": 200}},
            {"step": "s2", "alert": {"alert_id": "g", "event_ids": ["e2"], "time": 300}}]
    ftruth = [{"from": "s1", "to": "s2", "basis": "network_flow"}]
    timed = {"from_event_id": "e0", "to_event_id": "e2", "basis": "network_flow", "order": "forward",
             "from_ts_ms": 200, "to_ts_ms": 300}
    _check("(b) a shared event_ids[0] is disambiguated by the endpoint time (handle + ts, as causal_order does)",
           cl.grade_storyline("A", [timed], ftruth, fold)["matched"] == 1)
    untimed = dict(timed, from_ts_ms=None, to_ts_ms=None)
    _check("(b) NEGATIVE: the same link without a time cannot be mapped (ambiguous handle), so it is a false link",
           cl.grade_storyline("A", [untimed], ftruth, fold)["unmapped"] == 1)

    dup = cl.grade_storyline("A", emitted + [dict(emitted[0])], truth, items)
    _check("(b) the same event link repeated across incident graphs counts once",
           dup["n_emitted_event_links"] == 2 and dup["precision"]["value"] == 1.0)

    items2 = items + [{"step": "s1", "alert": {"alert_id": "al-A-s1-b", "event_ids": ["ev-A-s1-b"]}}]
    many = cl.grade_storyline("A", emitted + [link("A", "s0", "s1") | {"to_event_id": "ev-A-s1-b"}], truth, items2)
    _check("(b) two event links on one step pair are ONE step-pair claim (no inflation of precision n)",
           many["n_predicted"] == 2 and many["matched"] == 2)

    # no key list at all on an alert: not keyed
    nk = {"step": "s0", "alert": {"alert_id": "n", "event_ids": ["n"], "causal_keys": []}}
    _check("(b) an alert with an empty causal_keys list is not keyed",
           cl.grade_storyline("A", [], [], [nk])["coverage"]["k"] == 0)

    # an alert with no event_ids falls back to its alert_id, as ws8 does
    fb = {"step": "s0", "alert": {"alert_id": "only-alert-id"}}
    fb2 = {"step": "s1", "alert": {"alert_id": "other-alert-id"}}
    lk = {"from_event_id": "only-alert-id", "to_event_id": "other-alert-id", "basis": "network_flow",
          "order": "forward"}
    fg = cl.grade_storyline("A", [lk], [{"from": "s0", "to": "s1", "basis": "network_flow"}], [fb, fb2])
    _check("(b) an alert without event_ids is mapped through its alert_id (ws8's own fallback)",
           fg["matched"] == 1)


# ---------------------------------------------------------------------------
# (c) the gate
# ---------------------------------------------------------------------------
def verdict(spec: list, with_shuffle: bool = True, shuffle=None) -> dict:
    base, shuf = plan(spec)
    return cl.gate(base, (shuffle if shuffle is not None else shuf) if with_shuffle else None)


def test_gate() -> None:
    g = verdict(PASS_SPEC)
    _check("(c) POSITIVE: 40 gradable links, 5 storylines, flow 24 / proc 16, max share 20 %, shuffle "
           "collapsed -> pass",
           g["verdict"] == "pass" and not g["reasons"] and not g["failures"]
           and g["claimable_bases"] == ["network_flow", "process_tree"], str(g["reasons"] + g["failures"]))
    _check("(c) the pass reports pooled intervals and the shuffle numbers",
           g["pooled"]["precision"]["wilson95"] is not None and g["key_shuffle"]["ok"] is True
           and g["max_storyline_share"] == 0.2)

    def insufficient(name: str, spec: list, needle: str, **kw) -> None:
        r = verdict(spec, **kw)
        _check(f"(c) insufficient_n: {name}",
               r["verdict"] == "insufficient_n" and any(needle in x for x in r["reasons"])
               and len(r["reasons"]) == 1 and r["key_shuffle"] is None,
               str(r["reasons"]))

    insufficient("39 gradable links (one under the bar)",
                 PASS_SPEC[:4] + [("E", 7, "network_flow")], "gradable links 39 < 40")
    insufficient("3 storylines (one under the bar)",
                 [("A", 15, "network_flow"), ("B", 15, "process_tree"), ("C", 12, "network_flow")],
                 "storylines contributing 3 < 4")
    insufficient("one basis only",
                 [(s, 8, "network_flow") for s in "ABCDE"], "bases with >= 15 gradable links: 1 < 2")
    insufficient("a second basis exists but carries only 10 links (< 15)",
                 [("A", 10, "network_flow"), ("B", 10, "network_flow"), ("C", 10, "network_flow"),
                  ("D", 10, "process_tree")], "bases with >= 15 gradable links: 1 < 2")
    insufficient("one storyline above the 40 % share cap (17 of 40 = 42.5 %)",
                 [("A", 17, "network_flow"), ("B", 8, "network_flow"), ("C", 8, "process_tree"),
                  ("D", 7, "process_tree")], "largest storyline share 0.425 > 0.4")
    ok_edge = verdict([("A", 16, "network_flow"), ("B", 8, "network_flow"), ("C", 8, "process_tree"),
                       ("D", 8, "process_tree")])
    _check("(c) the share cap is inclusive: exactly 40 % (16 of 40) passes",
           ok_edge["verdict"] == "pass" and ok_edge["max_storyline_share"] == 0.4, str(ok_edge["reasons"]))

    # never a pass on thin data, even with a perfect-looking control
    thin = verdict([("A", 6, "network_flow")])
    _check("(c) NEGATIVE: perfect scores on 6 links stay insufficient_n (never a pass on thin data)",
           thin["verdict"] == "insufficient_n" and len(thin["reasons"]) >= 3
           and thin["pooled"]["precision"]["value"] == 1.0)
    multi = verdict([("A", 30, "network_flow")])
    _check("(c) every failed threshold is listed at once (n, storylines, bases, share)",
           len(multi["reasons"]) == 4 and multi["verdict"] == "insufficient_n", str(multi["reasons"]))
    empty = cl.gate([])
    _check("(c) no results at all is insufficient_n, not an error", empty["verdict"] == "insufficient_n")

    # control handling once n is enough
    miss = verdict(PASS_SPEC, with_shuffle=False)
    _check("(c) NEGATIVE: enough n but no key_shuffle result is a FAIL, not a pass",
           miss["verdict"] == "fail" and "key_shuffle control not supplied" in miss["failures"])
    same, _ = plan(PASS_SPEC)
    flat = verdict(PASS_SPEC, shuffle=same)
    _check("(c) NEGATIVE: a key_shuffle that does not collapse (links unchanged) is a FAIL",
           flat["verdict"] == "fail" and flat["key_shuffle"]["ok"] is False)

    # the collapse rule itself, at its boundary
    base = cl.combine(plan(PASS_SPEC)[0])

    def shuffled_at(prec_k: int, prec_n: int, rec_k: int, rec_n: int) -> dict:
        return {"precision": {"value": prec_k / prec_n, "k": prec_k, "n": prec_n, "wilson95": None},
                "recall": {"value": rec_k / rec_n, "k": rec_k, "n": rec_n, "wilson95": None},
                "n_predicted": prec_n}
    _check("(c) collapse boundary: exactly 0.25 x baseline on both metrics collapses",
           cl.shuffle_collapsed(base, shuffled_at(1, 4, 10, 40))["ok"] is True)
    _check("(c) NEGATIVE: precision just above 0.25 x baseline does not collapse",
           cl.shuffle_collapsed(base, shuffled_at(2, 7, 10, 40))["ok"] is False)
    _check("(c) NEGATIVE: recall just above 0.25 x baseline does not collapse",
           cl.shuffle_collapsed(base, shuffled_at(1, 4, 11, 40))["ok"] is False)
    zero = {"precision": {"value": None, "k": 0, "n": 0, "wilson95": None},
            "recall": {"value": 0.0, "k": 0, "n": 40, "wilson95": None}, "n_predicted": 0}
    _check("(c) no link at all after the shuffle is a collapse (precision undefined, vacuous)",
           cl.shuffle_collapsed(base, zero)["ok"] is True)
    undefined_base = {"precision": {"value": None}, "recall": {"value": 1.0}, "n_predicted": 0}
    _check("(c) NEGATIVE: an undefined baseline cannot demonstrate a collapse",
           cl.shuffle_collapsed(undefined_base, zero)["ok"] is False)


# ---------------------------------------------------------------------------
# (d) mutation soundness: a broken grader must fail the checks above
# ---------------------------------------------------------------------------
def _direction_expectations() -> list:
    items, truth, emitted = chain("A", 3)
    rev = [dict(lk, from_event_id=lk["to_event_id"], to_event_id=lk["from_event_id"]) for lk in emitted]
    conflict = [dict(lk, order="conflict") for lk in emitted]
    return [cl.grade_storyline("A", emitted, truth, items)["direction_accuracy"]["value"] == 1.0,
            cl.grade_storyline("A", rev, truth, items)["direction_accuracy"]["value"] == 0.0,
            cl.grade_storyline("A", conflict, truth, items)["direction_accuracy"]["value"] == 0.0]


def _basis_expectations() -> list:
    items, truth, emitted = chain("A", 3)
    wrong = [dict(lk, basis="agent_session") for lk in emitted]
    pi, pt, pe = chain("P", 3, "process_tree")
    prev = [dict(lk, from_event_id=lk["to_event_id"], to_event_id=lk["from_event_id"]) for lk in pe]
    return [cl.grade_storyline("A", wrong, truth, items)["matched"] == 0,
            cl.grade_storyline("P", prev, pt, pi)["matched"] == 0]


def test_mutations() -> None:
    _check("(d) baseline: the direction expectations hold on the real grader", all(_direction_expectations()))
    _check("(d) baseline: the basis / directed-pair expectations hold on the real grader",
           all(_basis_expectations()))

    real = cl.direction_ok
    try:
        cl.direction_ok = lambda *_a, **_k: True  # a grader that ignores direction
        mutated = _direction_expectations()
    finally:
        cl.direction_ok = real
    _check("(d) MUTATION: a grader that ignores direction FAILS the direction checks",
           not all(mutated), str(mutated))

    real_pk = cl.pair_key
    try:
        cl.pair_key = lambda basis, a, b: tuple(sorted((str(a), str(b))))  # ignores basis AND direction
        mutated = _basis_expectations()
    finally:
        cl.pair_key = real_pk
    _check("(d) MUTATION: a grader that ignores basis and direction in the pair identity FAILS",
           not all(mutated), str(mutated))

    thin_specs = {
        "MIN_GRADABLE_LINKS": PASS_SPEC[:4] + [("E", 7, "network_flow")],
        "MIN_STORYLINES": [("A", 15, "network_flow"), ("B", 15, "process_tree"), ("C", 12, "network_flow")],
        "MIN_BASES": [(s, 8, "network_flow") for s in "ABCDE"],
        "MIN_PER_BASIS": [("A", 10, "network_flow"), ("B", 10, "network_flow"), ("C", 10, "network_flow"),
                          ("D", 10, "process_tree")],
        "MAX_STORYLINE_SHARE": [("A", 17, "network_flow"), ("B", 8, "network_flow"),
                                ("C", 8, "process_tree"), ("D", 7, "process_tree")],
    }
    for const, spec in thin_specs.items():
        _check(f"(d) baseline: the gate rejects the set built to trip {const}",
               verdict(spec)["verdict"] == "insufficient_n")
        old = getattr(cl, const)
        try:
            setattr(cl, const, 1.0 if const == "MAX_STORYLINE_SHARE" else 0)
            mutated = verdict(spec)["verdict"]
        finally:
            setattr(cl, const, old)
        _check(f"(d) MUTATION: loosening {const} lets that set through (verdict {mutated}, check FAILS)",
               mutated != "insufficient_n")
    _check("(d) the constants are restored", (cl.MIN_GRADABLE_LINKS, cl.MIN_STORYLINES, cl.MIN_BASES,
                                               cl.MIN_PER_BASIS, cl.MAX_STORYLINE_SHARE) == (40, 4, 2, 15, 0.40))


def main() -> int:
    test_metrics()
    test_gradable()
    test_gate()
    test_mutations()
    print()
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("all causal_links checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
