"""ADR-012 WP 6: causal evidence keys -> ``links[]`` on incident.graph v2.

Hand-built alerts carrying ``causal_keys`` (the shape ws4's ``causal_alert``
emits: ``{ns, role, h, scope_trust}``). Covers: the 1,000-link cap with
``links_truncated`` on a 200-member incident with 6 shared keys (1,194
candidates), redelivery / fresh-instance byte identity, cache invalidation on a
changed key, null/missing keys, PID-collision and forged-sender style keys (a
different ``h`` never links), trust (``asserted`` is never labelled causal),
cross-incident suppression + counter, and ADR-011 strict order derivation.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from test_contract import _new_correlator  # noqa: E402
from test_incident_graph_v2 import _alert  # noqa: E402
from correlator import (  # noqa: E402
    LINKS_CAP, Correlator, _causal_link_candidates)

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def K(ns, h, role="self", trust="observed"):
    return {"ns": ns, "role": role, "h": h, "scope_trust": trust}


def _a(aid, tactic, actor, keys, t, ev=None, **kw):
    a = _alert(aid, tactic=tactic, actor=actor, time_ms=t,
               event_ids=[ev or f"ev-{aid}"], **kw)
    if keys is not None:
        a["causal_keys"] = keys
    return a


def _pair(c, actor, k1, k2, t1=1000, t2=2000, ids=("p1", "p2")):
    """Two-tactic incident of two alerts; returns the actor-track graph."""
    c.ingest_alert(_a(ids[0], "TA0001", actor, k1, t1))
    incs = c.ingest_alert(_a(ids[1], "TA0002", actor, k2, t2))
    inc = next(i for i in incs if i["entity_type"] == "actor")
    return c.incident_graph(inc["incident_id"])


def _enc(g):
    return json.dumps(g, sort_keys=True, separators=(",", ":"))


def _side(c, actor):
    side, _ = c.state.snapshot(c._track_key("default", "actor", actor))
    return side


def test_cap_1194_candidates_1000_emitted():
    c = _new_correlator()
    keys = ([K("flow", f"{i:016x}") for i in range(3)]
            + [K("agent", f"{i + 16:016x}", trust="declared") for i in range(3)])
    graph = None
    for i in range(200):
        incs = c.ingest_alert(_a(f"m{i:03d}", "TA0001" if i % 2 else "TA0002", "ann",
                                 keys, 10_000 + i, ev=f"e{i:03d}"))
        if incs:
            graph = c.incident_graph(incs[0]["incident_id"])
    check(graph is not None, "cap: incident must promote")
    if graph is None:
        return
    cands, suppressed = _causal_link_candidates(_side(c, "ann"))
    check(len(cands) == 1194 and suppressed == 0,
          f"cap: expected 1194 candidates, got {len(cands)} (suppressed {suppressed})")
    check(len(graph["links"]) == LINKS_CAP == 1000, f"cap: emitted {len(graph['links'])}")
    check(graph["links_truncated"] is True, "cap: links_truncated must be true")
    check(graph["version"] == 2, "cap: version stays 2")
    sk = [(lk["basis"], lk["from_event_id"], lk["to_event_id"]) for lk in graph["links"]]
    check(sk == sorted(sk), "cap: links sorted by (basis, from, to)")
    check(all(len(lk["from_event_id"]) and lk["from_event_id"] != lk["to_event_id"]
              for lk in graph["links"]), "cap: no self-link")


def test_small_incident_no_truncation_and_shape():
    c = _new_correlator()
    g = _pair(c, "bob", [K("flow", "f" * 16)], [K("flow", "f" * 16)])
    check(g["links_truncated"] is False and len(g["links"]) == 1, f"shape: {g['links']}")
    lk = g["links"][0]
    check(set(lk) == {"from_event_id", "to_event_id", "basis", "order",
                      "from_ts_ms", "to_ts_ms", "trust"}, f"shape: keys {sorted(lk)}")
    check((lk["basis"], lk["order"], lk["trust"], lk["from_event_id"], lk["to_event_id"])
          == ("network_flow", "forward", "observed", "ev-p1", "ev-p2"), f"shape: {lk}")


def test_redelivery_and_fresh_instance_byte_identical():
    seq = [_a("r1", "TA0001", "cy", [K("flow", "a" * 16), K("agent", "b" * 16, trust="declared")], 1000),
           _a("r2", "TA0002", "cy", [K("flow", "a" * 16), K("agent", "b" * 16, trust="declared")], 2000),
           _a("r3", "TA0003", "cy", [K("flow", "a" * 16)], 3000)]

    def run(c, redeliver):
        g = None
        for a in seq:
            for i in c.ingest_alert(dict(a)):
                g = c.incident_graph(i["incident_id"]) or g
        if redeliver:
            for a in seq:
                for i in c.ingest_alert(dict(a)):
                    g = c.incident_graph(i["incident_id"]) or g
        return _enc(g)
    base = run(_new_correlator(), False)
    check(len(json.loads(base)["links"]) == 3, "redelivery: expected 3 links")
    check(run(_new_correlator(), True) == base, "redelivery: byte-identical after redelivery")
    check(run(_new_correlator(), False) == base, "redelivery: fresh instance byte-identical")


def test_changed_key_invalidates_cache():
    entry = {"alert_id": "m1", "tactic": "TA0001", "score": 1, "time": 1000,
             "time_fallback": False, "event_id": "ev-1", "cooccur": [], "typed_signal": None,
             "causal_keys": [["flow", "self", "a" * 16, "observed"]]}
    base = Correlator._graph_signature({"m1": dict(entry)})
    check(Correlator._graph_signature({"m1": dict(entry, causal_keys=[["flow", "self", "b" * 16, "observed"]])}) != base,
          "sig: changed h must change fingerprint")
    check(Correlator._graph_signature({"m1": dict(entry, causal_keys=[["flow", "self", "a" * 16, "asserted"]])}) != base,
          "sig: changed trust must change fingerprint")
    check(Correlator._graph_signature({"m1": dict(entry, causal_keys=[])}) != base,
          "sig: dropped keys must change fingerprint")
    check(Correlator._graph_signature({"m1": dict(entry)}, foreign={("flow", "x")}) != base,
          "sig: a cross-incident suppression must change fingerprint")
    check(Correlator._graph_signature({"m1": dict(entry)}) == base, "sig: stable")
    # end to end: redelivering p2 with a different key removes the link
    c = _new_correlator()
    g1 = _pair(c, "dee", [K("flow", "a" * 16)], [K("flow", "a" * 16)])
    check(len(g1["links"]) == 1, "sig e2e: baseline link")
    incs = c.ingest_alert(_a("p2", "TA0002", "dee", [K("flow", "b" * 16)], 2000))
    g2 = c.incident_graph(incs[0]["incident_id"])
    check(g2["links"] == [], f"sig e2e: changed key must drop the link, got {g2['links']}")


def test_null_and_missing_keys_no_link():
    for k1, k2, why in [(None, None, "missing causal_keys"), ([], [], "empty"),
                        ([K("flow", "")], [K("flow", "")], "empty h"),
                        ([K("flow", None)], [K("flow", None)], "null h"),
                        ("garbage", [None, 3, {"ns": "flow"}], "malformed"),
                        ([K("zzz", "a" * 16)], [K("zzz", "a" * 16)], "unknown ns"),
                        ([K("flow", "a" * 16)], None, "one side keyless")]:
        g = _pair(_new_correlator(), "eve", k1, k2)
        check(g["links"] == [] and g["links_truncated"] is False, f"null: {why} -> {g['links']}")


def test_logon_emits_no_links():
    g = _pair(_new_correlator(), "fay", [K("logon", "c" * 16)], [K("logon", "c" * 16)])
    check(g["links"] == [], f"logon: must emit no links, got {g['links']}")


def test_pid_collision_and_forged_sender_no_link():
    # same raw PID value but different scope hash => different h => no link
    g = _pair(_new_correlator(), "gus", [K("proc", "1" * 16)],
              [K("proc", "2" * 16, role="parent")])
    check(g["links"] == [], "pid: different scope hash must not link")
    # forged second sender: different h on a flow key
    g = _pair(_new_correlator(), "hal", [K("flow", "3" * 16)], [K("flow", "4" * 16)])
    check(g["links"] == [], "forge: second sender (different h) must not link")
    # positive controls: the same pairs with an equal h DO link
    g = _pair(_new_correlator(), "gus", [K("proc", "1" * 16)], [K("proc", "1" * 16, role="parent")])
    check(len(g["links"]) == 1 and g["links"][0]["basis"] == "process_tree"
          and g["links"][0]["from_event_id"] == "ev-p1", f"pid control: {g['links']}")
    # roles must be compatible: two `parent` holders alone (no self) never link
    g = _pair(_new_correlator(), "ivy", [K("proc", "1" * 16, role="parent")],
              [K("proc", "1" * 16, role="parent")])
    check(g["links"] == [], "pid: parent/parent without a self holder must not link")


def test_asserted_never_labelled_causal():
    g = _pair(_new_correlator(), "jon", [K("flow", "5" * 16, trust="asserted")],
              [K("flow", "5" * 16, trust="asserted")])
    check(len(g["links"]) == 1 and g["links"][0]["trust"] == "asserted", f"trust: {g['links']}")
    check("causal" not in _enc(g["links"]), "trust: the word causal must not appear in links")
    # weaker of the two endpoints
    g = _pair(_new_correlator(), "kim", [K("flow", "6" * 16, trust="observed")],
              [K("flow", "6" * 16, trust="asserted")])
    check(g["links"][0]["trust"] == "asserted", "trust: weaker endpoint wins (observed+asserted)")
    g = _pair(_new_correlator(), "lee", [K("flow", "6" * 16, trust="observed")],
              [K("flow", "6" * 16, trust="observed")])
    check(g["links"][0]["trust"] == "observed", "trust: observed+observed")
    g = _pair(_new_correlator(), "max", [K("agent", "7" * 16, trust="declared")],
              [K("agent", "7" * 16, trust="declared")])
    check(g["links"][0]["trust"] == "declared" and g["links"][0]["basis"] == "agent_session",
          "trust: agent_session stays declared")
    # an unknown trust value degrades to asserted, never upgrades
    g = _pair(_new_correlator(), "ned", [K("flow", "8" * 16, trust="causal")],
              [K("flow", "8" * 16, trust="observed")])
    check(g["links"][0]["trust"] == "asserted", "trust: unknown value is asserted")


def test_cross_incident_key_no_link_and_counter():
    shared = [K("flow", "9" * 16)]
    # control: a lone incident links
    c0 = _new_correlator()
    check(len(_pair(c0, "ann", shared, shared, ids=("a1", "a2"))["links"]) == 1,
          "cross: control incident links")
    check(c0.metrics()["ws8_links_cross_incident_suppressed_total"] == 0, "cross: control counter 0")
    c = _new_correlator()
    _pair(c, "ann", shared, shared, ids=("a1", "a2"))
    gb = _pair(c, "bob", shared, shared, ids=("b1", "b2"))
    check(gb["links"] == [], f"cross: key held by another incident must not link: {gb['links']}")
    check(c.metrics()["ws8_links_cross_incident_suppressed_total"] >= 1, "cross: counter incremented")
    # the other incident loses its link on its next update, too
    incs = c.ingest_alert(_a("a3", "TA0003", "ann", [], 3000))
    ga = c.incident_graph(next(i for i in incs if i["entity_value"] == "ann")["incident_id"])
    check(ga["links"] == [], "cross: peer incident also emits no link for the shared key")
    # never merged: still two separate incidents with their own member sets
    check({i["entity_value"] for i in incs} == {"ann"}, "cross: incidents never merged")
    check(ga["incident_id"] != gb["incident_id"], "cross: distinct incident ids")


def test_order_derivation():
    cases = [  # (basis keys, t_from, t_to, expected order)
        ("proc", 1000, 2000, "forward"), ("proc", 1000, 1000, "concurrent"),
        ("proc", 3000, 2000, "conflict")]
    for _ns, t_parent, t_child, want in cases:
        c = _new_correlator()
        c.ingest_alert(_a("pp", "TA0001", "ora", [K("proc", "a" * 16)], t_parent))
        incs = c.ingest_alert(_a("cc", "TA0002", "ora", [K("proc", "a" * 16, role="parent")], t_child))
        g = c.incident_graph(incs[0]["incident_id"])
        lk = g["links"][0]
        check(lk["order"] == want and lk["from_event_id"] == "ev-pp" and lk["to_event_id"] == "ev-cc",
              f"order: proc {t_parent}->{t_child} want {want} got {lk}")
        if want == "conflict":
            check("causal" not in _enc(lk), "order: conflict never labelled causal")
    # symmetric chain is time ordered regardless of arrival order
    c = _new_correlator()
    c.ingest_alert(_a("s2", "TA0001", "pat", [K("flow", "d" * 16)], 5000))
    incs = c.ingest_alert(_a("s1", "TA0002", "pat", [K("flow", "d" * 16)], 4000))
    lk = c.incident_graph(incs[0]["incident_id"])["links"][0]
    check((lk["from_event_id"], lk["to_event_id"], lk["order"]) == ("ev-s1", "ev-s2", "forward"),
          f"order: symmetric ordered by time: {lk}")
    c = _new_correlator()
    c.ingest_alert(_a("t1", "TA0001", "qui", [K("flow", "d" * 16)], 5000))
    incs = c.ingest_alert(_a("t2", "TA0002", "qui", [K("flow", "d" * 16)], 5000))
    check(c.incident_graph(incs[0]["incident_id"])["links"][0]["order"] == "concurrent",
          "order: tie is concurrent")
    # fallback-timed member: unordered, and its stand-in time never leaks
    c = _new_correlator()
    c.ingest_alert(_a("u1", "TA0001", "rex", [K("flow", "d" * 16)], 5000))
    a2 = _a("u2", "TA0002", "rex", [K("flow", "d" * 16)], None)
    a2["time"] = 0
    incs = c.ingest_alert(a2)
    lk = c.incident_graph(incs[0]["incident_id"])["links"][0]
    check(lk["order"] == "unordered" and lk["to_ts_ms"] is None and lk["from_ts_ms"] == 5000,
          f"order: fallback time must be unordered with null ts: {lk}")


def run_all():
    test_cap_1194_candidates_1000_emitted()
    test_small_incident_no_truncation_and_shape()
    test_redelivery_and_fresh_instance_byte_identical()
    test_changed_key_invalidates_cache()
    test_null_and_missing_keys_no_link()
    test_logon_emits_no_links()
    test_pid_collision_and_forged_sender_no_link()
    test_asserted_never_labelled_causal()
    test_cross_incident_key_no_link_and_counter()
    test_order_derivation()


if __name__ == "__main__":
    run_all()
    if FAILS:
        print(f"[FAIL] WS-8 incident links (ADR-012): {len(FAILS)} problem(s)")
        for f in FAILS:
            print(f"  - {f}")
        sys.exit(1)
    print("[OK] WS-8 incident links test PASS (1194 cand -> 1000 cap + truncated, byte-identical "
          "redelivery/fresh, cache invalidation, null/collision/forged -> no link, asserted never "
          "causal, cross-incident suppression + counter, order forward/concurrent/conflict)")
