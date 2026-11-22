"""key_controls -- acceptance test for the four ADR-012 key controls (eval/twin/key_controls.py; W3a).

Standalone (NOT pytest): ``[OK]``/``[FAIL]`` lines, exit 0 only when every check passes. Run:

    python eval/twin/test_key_controls.py

Fixture: ONE hand-built storyline of 13 alerts on one actor, flow keys built through the REAL
``shared.causal_keys.key_hash`` so each consecutive pair shares a key (12 truth links). Every control re-runs
the REAL ws8 Correlator and re-grades with ``causal_links``.

  (a) BASELINE   the real ws8 emits all 12 links: precision = recall = direction accuracy = 1.0.
  (b) key_shuffle  deterministic (seed), multiset-preserving, role-preserving, never the identity, input not
                   mutated; precision AND recall collapse to <= 0.25 x baseline over a seed sweep. A shuffle
                   that does nothing (identity control) is caught by ``shuffle_collapsed``.
  (c) key_drop   no key, no link: zero links, recall 0, coverage 0. A "drop" that drops nothing is caught.
  (d) key_collide  bare PID / 0x0 / 0 go through the real canonicaliser: no key, no link. A broken
                   canonicaliser that keeps the weak value DOES link the pair and the verdict fails.
  (e) key_forge  a second sender replaying scope and value, and ("a|b","c") vs ("a","b|c"): no link. A hash that
                 ignores the sender, and a delimiter-joined hash, each produce a link and the verdict fails.
  (f) run_controls end to end, and the gate stays insufficient_n on this small fixture.
"""
from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path

TWIN = Path(__file__).resolve().parent
if str(TWIN) not in sys.path:
    sys.path.insert(0, str(TWIN))

import causal_links as cl  # noqa: E402
import key_controls as kc  # noqa: E402
from shared import causal_keys as ck  # noqa: E402

_FAILURES: list = []
N_ALERTS = 13
SENDER = "10.0.0.1"
SCOPE = "sensor-1"


def _check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        _FAILURES.append(name)


def make_case(hash_fn=ck.key_hash) -> dict:
    """13 alerts of one actor; alert i and i+1 share the flow key ``1000 + i`` (12 truth links s_i -> s_i+1)."""
    alerts, items, specs = [], [], {}
    for i in range(N_ALERTS):
        mine = []
        for j in (i - 1, i):  # keys 'j' join alerts j and j+1
            if 0 <= j < N_ALERTS - 1:
                mine.append({"ns": "flow", "role": "self", "scope": SCOPE, "value": str(1000 + j),
                             "sender": SENDER})
        alert = {"alert_id": f"al-{i}", "score": 10, "tenant_id": "default", "time": 10_000 + 1000 * i,
                 "mitre": {"tactic": "TA0001" if i % 2 == 0 else "TA0002"},
                 "actor": {"user": {"name": "ann"}}, "event_ids": [f"ev-{i}"],
                 "causal_keys": kc.make_keys("default", mine, hash_fn)}
        alerts.append(alert)
        items.append({"step": f"s{i}", "alert": alert})
        specs[f"ev-{i}"] = mine
    truth = [{"from": f"s{i}", "to": f"s{i + 1}", "basis": "network_flow"} for i in range(N_ALERTS - 1)]
    return {"name": "chain13", "alerts": alerts, "items": items, "truth": truth, "key_specs": specs}


def regrade(case: dict, alerts: list) -> dict:
    return cl.grade_storyline(case["name"], kc.run_correlation(alerts), case["truth"],
                              kc._items_with_keys(case["items"], alerts))


def delimiter_hash(tenant, ns, sender, scope, value):
    """A broken key hash: delimiter join, the exact flaw ADR-012 s.2 forbids."""
    return hashlib.sha256("|".join(str(p) for p in (tenant, ns, sender, scope, value)).encode()).hexdigest()[:16]


def sender_blind_hash(tenant, ns, sender, scope, value):
    """A broken key hash: the sender is not in it, so a forger who replays scope and value collides."""
    return ck.key_hash(tenant, ns, "", scope, value)


def keep_everything_hash(tenant, ns, sender, scope, value):
    """A broken canonicaliser: keeps weak values (a bare PID, 0x0) as if they were keys."""
    return hashlib.sha256(f"{tenant}|{ns}|{scope}|{value}".encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
def test_baseline(case: dict) -> dict:
    base = regrade(case, case["alerts"])
    _check("(a) the real ws8 emits all 12 flow links: precision = recall = direction accuracy = 1.0",
           (base["precision"]["value"], base["recall"]["value"], base["direction_accuracy"]["value"])
           == (1.0, 1.0, 1.0) and base["n_gradable"] == 12 and base["n_predicted"] == 12,
           f"{base['matched']}/{base['n_gradable']}")
    _check("(a) coverage is 1.0 (every alert carries a key)", base["coverage"]["value"] == 1.0)
    _check("(a) the run is deterministic (same alerts, same links)",
           kc.run_correlation(case["alerts"]) == kc.run_correlation(case["alerts"]))
    return base


def test_shuffle(case: dict, base: dict) -> None:
    before = copy.deepcopy(case["alerts"])
    s1, i1 = kc.key_shuffle(case["alerts"], seed=7)
    s2, _ = kc.key_shuffle(case["alerts"], seed=7)
    s3, _ = kc.key_shuffle(case["alerts"], seed=8)
    _check("(b) key_shuffle does not mutate its input", case["alerts"] == before)
    _check("(b) key_shuffle is deterministic per seed and differs across seeds", s1 == s2 and s1 != s3)

    def multiset(alerts):
        return sorted(k["h"] for a in alerts for k in a["causal_keys"])

    def roles(alerts):
        return [[k["role"] for k in a["causal_keys"]] for a in alerts]
    _check("(b) the multiset of key hashes is preserved and every slot keeps its role",
           multiset(s1) == multiset(case["alerts"]) and roles(s1) == roles(case["alerts"]))
    _check("(b) it is never the identity when it could move something",
           i1["moved"] > 0 and s1 != case["alerts"], str(i1))

    pooled_base = cl.combine([base])
    worst_p = worst_r = 0.0
    for seed in range(20):
        sa, info = kc.key_shuffle(case["alerts"], seed=seed)
        g = regrade(case, sa)
        worst_p = max(worst_p, g["precision"]["value"] or 0.0)
        worst_r = max(worst_r, g["recall"]["value"])
    _check("(b) over 20 seeds recall never exceeds 0.5 (chance level on this fixture)", worst_r <= 0.5,
           f"worst recall {worst_r}, worst precision {worst_p}")

    shuffled = regrade(case, s1)
    verdict = cl.shuffle_collapsed(pooled_base, cl.combine([shuffled]))
    _check("(b) seed 7: precision AND recall collapse to <= 0.25 x baseline",
           verdict["ok"], f"precision {shuffled['precision']['value']}, recall {shuffled['recall']['value']}")

    identity = cl.combine([regrade(case, case["alerts"])])
    _check("(b) NEGATIVE: an identity 'shuffle' (keys untouched) is NOT a collapse",
           cl.shuffle_collapsed(pooled_base, identity)["ok"] is False)

    # scope: a scope_fn that separates the first and second half confines the permutation to each half
    half = lambda a, k: int(a["event_ids"][0].split("-")[1]) < 7  # noqa: E731
    sh, info_h = kc.key_shuffle(case["alerts"], seed=3, scope_fn=half)
    ok = all(sorted(k["h"] for a in sh if half(a, None) == side for k in a["causal_keys"])
             == sorted(k["h"] for a in case["alerts"] if half(a, None) == side for k in a["causal_keys"])
             for side in (True, False))
    _check("(b) with a scope_fn, hashes only move INSIDE their scope (per-scope multiset preserved)", ok)


def test_drop(case: dict, base: dict) -> None:
    dropped_alerts, info = kc.key_drop(case["alerts"])
    d = regrade(case, dropped_alerts)
    v = kc.check_key_drop(base, d)
    _check("(c) key_drop: zero links, recall 0, coverage 0 (nothing stays labelled causal)",
           v["ok"] and d["n_predicted"] == 0 and d["recall"]["value"] == 0.0 and d["coverage"]["value"] == 0.0
           and info["keys_dropped"] == 24, str(v))
    _check("(c) NEGATIVE: a 'drop' that drops nothing (links and coverage survive) FAILS the check",
           kc.check_key_drop(base, regrade(case, case["alerts"]))["ok"] is False)


def test_collide(case: dict) -> None:
    for ns, value in kc.COLLIDE_VARIANTS:
        alerts, info = kc.key_collide(case["alerts"], ns, value)
        links = kc.run_correlation(alerts)
        v = kc.check_no_link(links, [info["pair"]])
        _check(f"(d) key_collide {ns}:{value}: the real canonicaliser drops it, no key attached, no link",
               info["applied"] and info["keys_attached"] == 0 and v["ok"], f"pair {info['pair']}")
        # the pair is really unrelated and in one track, so a link COULD have formed
        a, b = info["pair"]
        _check(f"(d) key_collide {ns}:{value}: the pair shares no key and sits on one actor track",
               not (kc._hashes(next(x for x in case["alerts"] if kc._handle(x) == a))
                    & kc._hashes(next(x for x in case["alerts"] if kc._handle(x) == b))))

    # NEGATIVE: a canonicaliser that keeps the weak value links the pair (proc and flow; logon never links in ws8)
    for ns, value, must_link in (("proc", "1234", True), ("flow", "0", True), ("logon", "0x0", False)):
        alerts, info = kc.key_collide(case["alerts"], ns, value, hash_fn=keep_everything_hash)
        v = kc.check_no_link(kc.run_correlation(alerts), [info["pair"]])
        _check(f"(d) NEGATIVE: a canonicaliser that keeps {ns}:{value} makes the verdict "
               f"{'FAIL (the pair links)' if must_link else 'pass (ws8 emits no logon link by design)'}",
               info["keys_attached"] == 2 and v["ok"] is (not must_link), str(v))

    one = [dict(case["alerts"][0])]
    _, info = kc.key_collide(one)
    _check("(d) fewer than two unrelated alerts: the control reports applied=False (says nothing)",
           info["applied"] is False)


def test_forge(case: dict) -> None:
    alerts, info = kc.key_forge(case["alerts"], case["key_specs"])
    links = kc.run_correlation(alerts)
    v = kc.check_forge(links, info)
    _check("(e) key_forge: a second sender replaying scope+value, and ('a|b','c') vs ('a','b|c'): no link "
           "between a forged and a genuine event, none inside the encoding pair",
           info["applied"] and v["ok"] and v["forged_events"] == 5 and not v["forged_vs_genuine"]
           and not v["encoding_pair_linked"], str(v))
    _check("(e) the forgeries do link to EACH OTHER inside the forger's own sender scope (ADR-012: not claimed "
           "to be prevented), and the genuine 12 links are untouched",
           kc.link_between(links, "forge-ev-1", "forge-ev-2") != []
           and sum(1 for lk in links if not str(lk["from_event_id"]).startswith("forge")) == 12)
    forged = [a for a in alerts if a["alert_id"].startswith("forge-")]
    genuine = {a["event_ids"][0]: a for a in case["alerts"]}
    differs = all(kc._hashes(f) != kc._hashes(genuine[g]) for f, (g, _x) in zip(forged[:3], info["pairs"][:3]))
    _check("(e) the forged keys differ from the genuine ones only through the sender", differs and len(forged) == 5)

    # NEGATIVE 1: a hash without the sender: replayed scope+value collides with the genuine event
    blind_case = make_case(sender_blind_hash)
    b_alerts, b_info = kc.key_forge(blind_case["alerts"], blind_case["key_specs"], hash_fn=sender_blind_hash)
    bv = kc.check_forge(kc.run_correlation(b_alerts), b_info)
    _check("(e) NEGATIVE: a key hash that leaves the sender out lets the forger link (verdict FAILS)",
           bv["ok"] is False and len(bv["forged_vs_genuine"]) >= 3, str(bv))

    # NEGATIVE 2: a delimiter-joined hash equates ('a|b','c') with ('a','b|c')
    d_case = make_case(delimiter_hash)
    d_alerts, d_info = kc.key_forge(d_case["alerts"], d_case["key_specs"], hash_fn=delimiter_hash)
    dv = kc.check_forge(kc.run_correlation(d_alerts), d_info)
    _check("(e) NEGATIVE: a delimiter-joined hash links the encoding pair (verdict FAILS)",
           dv["ok"] is False and dv["encoding_pair_linked"] is True, str(dv))
    _check("(e) ... while the real key_hash keeps the pair apart",
           ck.key_hash("t", "flow", "", "a|b", "c") != ck.key_hash("t", "flow", "", "a", "b|c"))

    _, none_info = kc.key_forge(case["alerts"], {})
    _check("(e) no key material supplied: applied=False", none_info["applied"] is False)


def test_run_controls(case: dict, base: dict) -> None:
    r = kc.run_controls(case, seed=7)
    _check("(f) run_controls returns baseline, shuffle, drop, collide (3 variants) and forge",
           r["baseline"]["matched"] == 12 and set(r["key_collide"]) == {"proc:1234", "logon:0x0", "flow:0"}
           and r["key_forge"]["applied"] and r["key_drop_verdict"]["ok"])
    _check("(f) every collide variant and the forge verdict pass on the real pipeline",
           all(v["verdict"]["ok"] for v in r["key_collide"].values()) and r["key_forge"]["verdict"]["ok"])
    g = cl.gate([r["baseline"]], [r["key_shuffle"]])
    _check("(f) the gate on this 12-link fixture is insufficient_n (never a pass on thin data)",
           g["verdict"] == "insufficient_n" and g["pooled"]["n_gradable"] == 12, str(g["reasons"]))
    _check("(f) run_controls is deterministic", kc.run_controls(case, seed=7)["key_shuffle"] == r["key_shuffle"])
    _check("(f) the baseline equals the standalone baseline", r["baseline"] == base)


def main() -> int:
    case = make_case()
    base = test_baseline(case)
    test_shuffle(case, base)
    test_drop(case, base)
    test_collide(case)
    test_forge(case)
    test_run_controls(case, base)
    print()
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)} check(s)")
        for f in _FAILURES:
            print(f"  - {f}")
        return 1
    print("all key_controls checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
