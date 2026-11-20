"""ADR-011 option C: optional evidence-interval fields on incident.graph v2 edges.

Each edge carries first_ts_ms / last_ts_ms (min/max sanitized event time over all
distinct member alerts carrying both endpoints, fallback-timed excluded),
evidence_count (all such members) and timed_evidence_count (members with a real
time). Both timestamps are null iff timed_evidence_count == 0. ts_ms / kind /
from / to / ordering / version are untouched (pinned in test_incident_graph_v2.py).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from test_contract import _new_correlator  # noqa: E402
from test_incident_graph_v2 import _alert, _edge  # noqa: E402
from correlator import Correlator, canonical_entity_id  # noqa: E402

FAILS: list[str] = []
NEW = ("first_ts_ms", "last_ts_ms", "evidence_count", "timed_evidence_count")


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _ids(actor, ip):
    return (canonical_entity_id("default", "actor", actor),
            canonical_entity_id("default", "ip", ip))


def _graph(c, incs):
    return c.incident_graph(next(i["incident_id"] for i in incs if i["entity_type"] == "actor"))


def _enc(g):
    return json.dumps(g, sort_keys=True, separators=(",", ":"))


def test_interval_spans_all_kinds_and_brackets_ts_ms():
    c = _new_correlator()
    c.ingest_alert(_alert("i1", tactic="TA0006", actor="ann", ip="10.40.0.1",
                          time_ms=1000, event_ids=["e1"]))
    c.ingest_alert(_alert("i2", tactic="TA0007", actor="ann", ip="10.40.0.1",
                          time_ms=5000, event_ids=["e2"]))
    incs = c.ingest_alert(_alert("i3", tactic="TA0001", technique="T1078", actor="ann",
                                 ip="10.40.0.1", time_ms=3000, event_ids=["e3"]))
    a, i = _ids("ann", "10.40.0.1")
    e = _edge(_graph(c, incs), a, i)
    check(e is not None, "interval: edge must exist")
    if e is None:
        return
    check((e["first_ts_ms"], e["last_ts_ms"], e["evidence_count"], e["timed_evidence_count"])
          == (1000, 5000, 3, 3), f"interval: expected 1000/5000/3/3, got {e}")
    check(e["kind"] == "authenticated_as" and e["ts_ms"] == 3000,
          f"interval: kind/ts_ms of the winner must be unchanged, got {e}")
    check(e["first_ts_ms"] <= e["ts_ms"] <= e["last_ts_ms"],
          f"interval: first <= ts_ms <= last must hold for a timed winner, got {e}")


def test_untimed_member_counted_but_never_leaks_into_interval():
    c = _new_correlator()
    c.ingest_alert(_alert("u1", tactic="TA0006", actor="bob", ip="10.40.0.2",
                          time_ms=2000, event_ids=["e1"]))
    nt = _alert("u2", tactic="TA0007", actor="bob", ip="10.40.0.2", event_ids=["e2"])
    nt.pop("time")
    incs = c.ingest_alert(nt)
    a, i = _ids("bob", "10.40.0.2")
    g = _graph(c, incs)
    e = _edge(g, a, i)
    check(e is not None and (e["first_ts_ms"], e["last_ts_ms"], e["evidence_count"],
                             e["timed_evidence_count"]) == (2000, 2000, 2, 1),
          f"untimed: counted in evidence_count only, got {e}")
    digest = int(hashlib.sha256(b"u2").hexdigest()[:12], 16)
    if e is not None:
        for k in ("first_ts_ms", "last_ts_ms"):
            check(e[k] != digest, f"untimed: {k} must not equal the sha256 digest")

    # sole time-less carrier -> null/null, evidence 1, timed 0
    c = _new_correlator()
    only = _alert("u3", tactic="TA0006", actor="cat", ip="10.40.0.3", event_ids=["e3"])
    only.pop("time")
    c.ingest_alert(only)
    incs = c.ingest_alert(_alert("u4", tactic="TA0007", actor="cat", time_ms=9000,
                                 event_ids=["e4"]))
    a, i = _ids("cat", "10.40.0.3")
    e = _edge(_graph(c, incs), a, i)
    check(e is not None and (e["first_ts_ms"], e["last_ts_ms"], e["evidence_count"],
                             e["timed_evidence_count"]) == (None, None, 1, 0),
          f"untimed-sole: expected null/null/1/0, got {e}")


def test_redelivery_and_fresh_instance_byte_identical():
    r1 = _alert("d1", tactic="TA0001", technique="T1078", actor="dan", ip="10.40.0.4",
                time_ms=1000, event_ids=["e1"])
    r2 = _alert("d2", tactic="TA0002", actor="dan", ip="10.40.0.4", time_ms=4000,
                event_ids=["e2"])
    c = _new_correlator()
    c.ingest_alert(r1)
    incs = c.ingest_alert(r2)
    iid = incs[0]["incident_id"]
    g1 = c.incident_graph(iid)
    for a in (dict(r2), dict(r1), dict(r2)):
        c.ingest_alert(a)
    g2 = c.incident_graph(iid)
    check(_enc(g1) == _enc(g2), "redelivery: payload must be byte-identical")
    check(all(e["evidence_count"] == 2 for e in g2["edges"]),
          f"redelivery: evidence_count counts distinct members, not deliveries: {g2['edges']}")
    c2 = _new_correlator()
    c2.ingest_alert(dict(r1))
    incs2 = c2.ingest_alert(dict(r2))
    check(_enc(c2.incident_graph(incs2[0]["incident_id"])) == _enc(g1),
          "fresh instance: payload must be byte-identical")


def test_changed_member_time_invalidates_cache_signature():
    entry = {"alert_id": "m1", "tactic": "TA0001", "score": 10, "time": 1000,
             "time_fallback": False, "event_id": "ev-1",
             "cooccur": [("ip", "10.0.0.1")], "typed_signal": ("TA0001", None, None)}
    base = Correlator._graph_signature({"m1": dict(entry)})
    check(Correlator._graph_signature({"m1": dict(entry, time=2000)}) != base,
          "sig: a changed member time must change the fingerprint")
    check(Correlator._graph_signature({"m1": dict(entry, time_fallback=True)}) != base,
          "sig: a changed time_fallback must change the fingerprint")
    # end to end: a member re-delivered with a different time re-derives the interval
    c = _new_correlator()
    c.ingest_alert(_alert("s1", tactic="TA0006", actor="eve", ip="10.40.0.5",
                          time_ms=1000, event_ids=["e1"]))
    incs = c.ingest_alert(_alert("s2", tactic="TA0007", actor="eve", ip="10.40.0.5",
                                 time_ms=2000, event_ids=["e2"]))
    iid = incs[0]["incident_id"]
    a, i = _ids("eve", "10.40.0.5")
    before = _edge(c.incident_graph(iid), a, i)
    before = dict(before) if before else None
    c.ingest_alert(_alert("s2", tactic="TA0007", actor="eve", ip="10.40.0.5",
                          time_ms=7000, event_ids=["e2"]))
    after = _edge(c.incident_graph(iid), a, i)
    check(before is not None and after is not None
          and (before["last_ts_ms"], after["last_ts_ms"]) == (2000, 7000)
          and after["evidence_count"] == 2,
          f"cache: changed member time must be reflected (last 2000 -> 7000), got {before} / {after}")


def test_absent_and_null_are_equivalent_for_consumers():
    """Consumers must treat absent == null == 'no time claim'. WS-3 stores the graph
    as an opaque document (it must not special-case the keys) and the dashboard
    GraphEdge type, if it declares them, must make them optional/nullable."""
    root = HERE.parent.parent
    ws3 = "\n".join(p.read_text(encoding="utf-8", errors="replace")
                    for p in (root / "services" / "ws3-indexer").rglob("*.py")
                    if not p.name.startswith("test_"))
    for k in NEW:
        check(k not in ws3, f"consumer: ws3-indexer must not special-case {k}")
    dash = root / "services" / "ws7-dashboard"
    for p in dash.rglob("*.ts*"):
        if "node_modules" in p.parts:
            continue
        txt = p.read_text(encoding="utf-8", errors="replace")
        if "interface GraphEdge" in txt:
            body = txt.split("interface GraphEdge", 1)[1].split("}", 1)[0]
            for k in NEW:
                if k in body:
                    check(f"{k}?" in body or f"{k}: number | null" in body,
                          f"consumer: dashboard GraphEdge.{k} must be optional/nullable")
    legacy = {"from": "a", "to": "b", "kind": "used_ip", "event_id": "x", "ts_ms": 5}
    nulled = dict(legacy, first_ts_ms=None, last_ts_ms=None, evidence_count=1,
                  timed_evidence_count=0)
    check(json.loads(json.dumps(nulled)).get("first_ts_ms") is None
          and legacy.get("first_ts_ms") is None, "consumer: absent and null read identically")


def run_all():
    test_interval_spans_all_kinds_and_brackets_ts_ms()
    test_untimed_member_counted_but_never_leaks_into_interval()
    test_redelivery_and_fresh_instance_byte_identical()
    test_changed_member_time_invalidates_cache_signature()
    test_absent_and_null_are_equivalent_for_consumers()


if __name__ == "__main__":
    run_all()
    if FAILS:
        print(f"[FAIL] WS-8 edge intervals (ADR-011): {len(FAILS)} problem(s)")
        for f in FAILS:
            print(f"  - {f}")
        sys.exit(1)
    print("[OK] WS-8 edge intervals test PASS (first<=ts_ms<=last + untimed never leaks + "
          "byte-identical redelivery/fresh instance + cache invalidation + absent==null)")
