"""WS-8 correlation: incident.graph (ADR-009 / WP-2-C) tests.

Relationship edges with provenance, emitted alongside every incident
promotion/update. These are STANDALONE tests (no pytest), mirroring the
`check()`/FAILS/main shape of test_contract.py.

Coverage:
  (a) a single alert carrying co-occurring actor+src-ip yields an edge
      between them with that alert's event_id + ts_ms provenance;
  (b) two alerts that merely SHARE an ip (but never co-occur in one alert)
      yield NO edge between their actors -- the no-transitive-inference
      proof (also on the device leg: two alerts sharing a mac across an ip
      change yield NO ip-ip edge);
  (c) redelivering the same incident (at-least-once bus) re-emits an
      IDENTICAL graph -- same incident_id, same nodes, same edges with the
      same provenance, no duplicates -- and a FRESH correlator fed the same
      alerts deterministically re-derives the same payload;
  (d) the graph is bounded by the incident's member set (mirrors
      _sides/_last_incident's sweep discipline): edges stop growing once
      member_cap evicts, and the cached graph is pruned WITH its incident by
      the dead-track sweep;
  (e) the existing ws8 suites (test_contract.py / sensitivity / new_hunt)
      stay green -- run separately; this file re-asserts the relevant
      invariants it can see (accessor surfaces, unknown/unpromoted -> None).

Run: python services/ws8-correlation/test_incident_graph.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from test_contract import _Clock, _new_correlator  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _alert(alert_id, tactic=None, actor=None, ip=None, mac=None, hostname=None,
           score=10, tenant="default", time_ms=None, event_ids=None):
    """Same alert-shape helper as test_contract._alert, plus `event_ids`
    (the underlying-event provenance the ADR-009 edges must carry)."""
    a = {"alert_id": alert_id, "score": score, "tenant_id": tenant,
         "time": time_ms if time_ms is not None else 0}
    if tactic is not None:
        a["mitre"] = {"tactic": tactic}
    if actor is not None:
        a["actor"] = {"user": {"name": actor}}
    if ip is not None or mac is not None or hostname is not None:
        src = {}
        if ip is not None:
            src["ip"] = ip
        if mac is not None:
            src["mac"] = mac
        if hostname is not None:
            src["hostname"] = hostname
        a["src_endpoint"] = src
    if event_ids:
        a["event_ids"] = list(event_ids)
    return a


# --- (a) single-alert co-occurrence -> provenance-bearing edge -----------
def test_single_alert_cooccurrence_yields_edge_with_provenance():
    """One alert carries actor + src ip (a relationship its OWN fields
    evidence); a second actor-only alert supplies the second tactic so the
    actor track can promote. The graph must contain exactly one edge
    (actor -> ip, kind used_ip) citing THAT alert's event_id + ts_ms."""
    c = _new_correlator()
    c.ingest_alert(_alert("p1", tactic="TA0001", actor="alice", ip="10.0.0.5",
                          time_ms=1000, event_ids=["ev-1"]))
    incs = c.ingest_alert(_alert("p2", tactic="TA0002", actor="alice",
                                 time_ms=2000, event_ids=["ev-2"]))
    check(len(incs) == 1 and incs[0]["entity_type"] == "actor",
          "a: actor:alice must promote on the second distinct tactic")
    iid = incs[0]["incident_id"]
    graph = c.incident_graph(iid)
    check(graph is not None, "a: a graph payload must exist for a promoted incident")
    check(graph["version"] == 1, "a: version must be 1 (ADR-009)")
    check(graph["incident_id"] == iid, "a: graph must carry the incident's own id")
    check(graph["tenant_id"] == "default", "a: graph must carry the tenant")
    check(graph["nodes"] == ["actor:alice", "ip:10.0.0.5"],
          f"a: nodes must be the incident's member entities (type:value track "
          f"identity), got {graph['nodes']}")
    check(graph["edges"] == [{
        "from": "actor:alice", "to": "ip:10.0.0.5", "kind": "used_ip",
        "event_id": "ev-1", "ts_ms": 1000,
    }], f"a: the co-occurring actor+ip alert must yield exactly ONE "
        f"provenance-bearing edge, got {graph['edges']}")
    check(graph["tactic_sources"] == {"TA0001": ["p1"], "TA0002": ["p2"]},
          f"a: tactic_sources must attribute each tactic to its member "
          f"alerts, got {graph['tactic_sources']}")


# --- edge-kind mapping: one alert carrying actor+ip+mac ------------------
def test_all_three_edge_kinds_from_one_alert():
    """One alert carrying actor + src ip + device mac directly evidences all
    three pair relationships (actor-ip, actor-device, device-ip). Each pair
    must appear as its own canonical DIRECTED edge (fixed by pair semantics,
    never by which track promoted) with the same alert's provenance."""
    c = _new_correlator()
    c.ingest_alert(_alert("k1", tactic="TA0001", actor="karl", ip="10.0.0.7",
                          mac="AA:BB:CC:DD:EE:FF", time_ms=1000, event_ids=["ev-k1"]))
    incs = c.ingest_alert(_alert("k2", tactic="TA0002", actor="karl",
                                 time_ms=2000, event_ids=["ev-k2"]))
    graph = c.incident_graph(incs[0]["incident_id"])
    edges = graph["edges"]
    got = sorted((e["from"], e["to"], e["kind"]) for e in edges)
    want = sorted([
        ("actor:karl", "ip:10.0.0.7", "used_ip"),
        ("actor:karl", "device:AA:BB:CC:DD:EE:FF", "used_device"),
        ("device:AA:BB:CC:DD:EE:FF", "ip:10.0.0.7", "seen_at_ip"),
    ])
    check(got == want,
          f"kinds: one alert with actor+ip+mac must yield exactly the three "
          f"canonical directed edges (used_ip / used_device / seen_at_ip), "
          f"got {got}")
    check(all(e["event_id"] == "ev-k1" and e["ts_ms"] == 1000 for e in edges),
          f"kinds: every edge must carry the evidencing alert's provenance, "
          f"got {edges}")
    check(set(graph["nodes"]) == {"actor:karl", "ip:10.0.0.7",
                                  "device:AA:BB:CC:DD:EE:FF"},
          f"kinds: nodes must span actor/ip/device, got {graph['nodes']}")


# --- (b) the no-transitive-inference proof --------------------------------
def test_two_alerts_sharing_an_ip_produce_no_edge_between_their_actors():
    """ADR-009 / WS-8's core refusal, now on the graph: grace and heidi
    share src IP 198.51.100.9, but NO single alert ever carries both of them
    -- so the ip: track's incident graph must show each actor's DIRECT edge
    to the shared ip and NO edge between the two actors. An inference path
    (grace --[via ip]--> heidi) is exactly the transitive join WS-8 refuses
    to make, and any implementation that added it here is broken."""
    c = _new_correlator()  # 198.51.100.9 NOT allowlisted -- accepted-limitation path
    c.ingest_alert(_alert("s1", tactic="TA0001", actor="grace", ip="198.51.100.9",
                          time_ms=1000, event_ids=["ev-1"]))
    incs = c.ingest_alert(_alert("s2", tactic="TA0002", actor="grace",
                                 time_ms=2000, event_ids=["ev-2"]))
    grace_iid = next(i["incident_id"] for i in incs if i["entity_type"] == "actor")
    c.ingest_alert(_alert("s3", tactic="TA0001", actor="heidi", ip="198.51.100.9",
                          time_ms=3000, event_ids=["ev-3"]))
    incs2 = c.ingest_alert(_alert("s4", tactic="TA0002", actor="heidi", ip="198.51.100.9",
                                  time_ms=4000, event_ids=["ev-4"]))
    ip_iid = next(i["incident_id"] for i in incs2 if i["entity_type"] == "ip")
    check(ip_iid != grace_iid, "b: the ip: track must promote independently")

    grace_graph = c.incident_graph(grace_iid)
    check("actor:heidi" not in grace_graph["nodes"],
          f"b: grace's actor incident must not mention heidi at all, got "
          f"{grace_graph['nodes']}")
    check(grace_graph["edges"] == [{
        "from": "actor:grace", "to": "ip:198.51.100.9", "kind": "used_ip",
        "event_id": "ev-1", "ts_ms": 1000,
    }], f"b: grace's incident must carry only her own direct edge, got "
        f"{grace_graph['edges']}")

    ip_graph = c.incident_graph(ip_iid)
    check(set(ip_graph["nodes"]) == {"ip:198.51.100.9", "actor:grace", "actor:heidi"},
          f"b: the ip incident must span the shared ip and BOTH actors, got "
          f"{ip_graph['nodes']}")
    edge_pairs = {(e["from"], e["to"]) for e in ip_graph["edges"]}
    check(not any(set(pair) == {"actor:grace", "actor:heidi"} for pair in edge_pairs),
          "b: NO edge may connect the two actors -- any grace<->heidi edge "
          "would be transitive inference through the shared ip")
    check(ip_graph["edges"] == [
        {"from": "actor:grace", "to": "ip:198.51.100.9", "kind": "used_ip",
         "event_id": "ev-1", "ts_ms": 1000},
        {"from": "actor:heidi", "to": "ip:198.51.100.9", "kind": "used_ip",
         "event_id": "ev-3", "ts_ms": 3000},
    ], f"b: the ip incident must carry EXACTLY the two direct actor->ip edges "
       f"(earliest provenance each -- s4 re-asserting heidi's pair must not "
       f"add a third edge), got {ip_graph['edges']}")


def test_device_incident_graph_spans_ip_change_with_no_ip_ip_edge():
    """Same no-transitive rule on the pivot leg: one mac, two DIFFERENT ips,
    two tactics, no actor. The device incident's graph spans the device and
    BOTH ips with a seen_at_ip edge per alert -- and NO edge between the two
    ips (that would be transitive inference through the shared device)."""
    c = _new_correlator()
    c.ingest_alert(_alert("d1", tactic="TA0043", ip="10.0.0.5", mac="AA:BB:CC:DD:EE:FF",
                          time_ms=1000, event_ids=["ev-d1"]))
    incs = c.ingest_alert(_alert("d2", tactic="TA0006", ip="10.0.0.9", mac="AA:BB:CC:DD:EE:FF",
                                 time_ms=2000, event_ids=["ev-d2"]))
    dev = next(i for i in incs if i["entity_type"] == "device")
    g = c.incident_graph(dev["incident_id"])
    check(set(g["nodes"]) == {"device:AA:BB:CC:DD:EE:FF", "ip:10.0.0.5", "ip:10.0.0.9"},
          f"pivot: device incident nodes must span device + both ips, got {g['nodes']}")
    edge_pairs = {(e["from"], e["to"]) for e in g["edges"]}
    check(not any(set(pair) == {"ip:10.0.0.5", "ip:10.0.0.9"} for pair in edge_pairs),
          "pivot: NO edge may connect the two ips -- that would be transitive "
          "inference through the shared device")
    check(g["edges"] == [
        {"from": "device:AA:BB:CC:DD:EE:FF", "to": "ip:10.0.0.5", "kind": "seen_at_ip",
         "event_id": "ev-d1", "ts_ms": 1000},
        {"from": "device:AA:BB:CC:DD:EE:FF", "to": "ip:10.0.0.9", "kind": "seen_at_ip",
         "event_id": "ev-d2", "ts_ms": 2000},
    ], f"pivot: one seen_at_ip edge per alert with its provenance, and NO "
       f"ip-ip transitive edge, got {g['edges']}")


# --- (c) redelivery determinism / idempotency -----------------------------
def test_redelivery_emits_identical_graph():
    """Same incident promoted twice (at-least-once redelivery) must emit an
    IDENTICAL graph: same incident_id (first_seen-bucketed, unchanged), same
    nodes, same edges WITH the same provenance, no duplicates. And a FRESH
    correlator fed the same alerts must deterministically re-derive the same
    payload (no per-instance state anywhere in the graph)."""
    r1 = _alert("r1", tactic="TA0001", actor="frank", ip="10.1.1.1",
                time_ms=1000, event_ids=["ev-1"])
    r2 = _alert("r2", tactic="TA0002", actor="frank", time_ms=2000, event_ids=["ev-2"])

    c = _new_correlator()
    c.ingest_alert(r1)
    incs = c.ingest_alert(r2)
    iid = incs[0]["incident_id"]
    g1 = c.incident_graph(iid)

    # redeliver the SAME second alert (at-least-once bus semantics)
    incs2 = c.ingest_alert(dict(r2))
    check(incs2[0]["incident_id"] == iid,
          "c: redelivery must re-emit under the SAME incident_id")
    g2 = c.incident_graph(iid)
    check(g2 == g1, "c: redelivery must emit an IDENTICAL graph (same id, "
                    "nodes, edges, provenance)")

    # full replay of both alerts
    c.ingest_alert(dict(r1))
    incs3 = c.ingest_alert(dict(r2))
    check(incs3[0]["incident_id"] == iid, "c: full replay must keep the same id")
    check(c.incident_graph(iid) == g1, "c: full replay must keep the same graph")

    # a FRESH, independently-constructed correlator re-derives the same graph
    c2 = _new_correlator()
    c2.ingest_alert(dict(r1))
    incs_new = c2.ingest_alert(dict(r2))
    check(c2.incident_graph(incs_new[0]["incident_id"]) == g1,
          "c: a fresh instance must deterministically re-derive the same graph")

    # no duplicate edges anywhere
    check(len({(e["from"], e["to"], e["kind"]) for e in g1["edges"]}) == len(g1["edges"]),
          "c: the edge list must never contain duplicate (from,to,kind) pairs")


# --- (d) bounded by member set, swept with the incident -------------------
def test_graph_bounded_by_member_set_and_swept_with_its_incident():
    """The graph edge list and the graph cache are bounded by the incident's
    member set -- mirroring _sides/_last_incident's sweep discipline, NOT by
    how many alerts have ever hit the track. Once member_cap evicts the
    oldest members, the still-live incident's edges STOP growing, and the
    dead-track sweep prunes the cached graph together with its incident."""
    clock = _Clock()
    c = _new_correlator(horizon_s=60, member_cap=5, now_fn=clock)
    c.ingest_alert(_alert("recon", tactic="TA0043", actor="bf-user", ip="10.9.0.1",
                          time_ms=1000, event_ids=["ev-recon"]))
    ids = set()
    edge_counts = []
    stable_graph = None
    for i in range(100):
        incs = c.ingest_alert(_alert(f"bf-{i}", tactic="TA0006", actor="bf-user",
                                     ip=f"10.9.0.{i + 2}", time_ms=2000 + i,
                                     event_ids=[f"ev-bf-{i}"]))
        for inc in incs:
            ids.add(inc["incident_id"])
            g = c.incident_graph(inc["incident_id"])
            edge_counts.append(len(g["edges"]))
            stable_graph = g
    check(len(ids) == 1,
          f"d: the whole flood must stay under ONE incident_id, got {ids}")
    check(set(c._incident_graphs) == ids,
          f"d: exactly one cached graph per promoted incident (the ip: tracks "
          f"never reach 2 tactics), got {sorted(c._incident_graphs)}")
    check(max(edge_counts) <= 3 * 5,
          f"d: edges must be bounded by the member set (<=3 pairs per live "
          f"member; live members capped at member_cap=5) -- got max "
          f"{max(edge_counts)}")
    check(edge_counts[-1] == edge_counts[10],
          f"d: once the cap binds, the edge count must STABILIZE (no unbounded "
          f"growth across the remaining ~90 alerts): {edge_counts[10]} vs "
          f"{edge_counts[-1]}")
    check(len({(e["from"], e["to"], e["kind"]) for e in stable_graph["edges"]})
          == len(stable_graph["edges"]),
          "d: no duplicate edges even under the flood")
    check(all("event_id" in e and "ts_ms" in e for e in stable_graph["edges"]),
          "d: every edge carries provenance")
    check(all({e["from"], e["to"]} <= set(stable_graph["nodes"])
              for e in stable_graph["edges"]),
          "d: every edge's endpoints must be present in nodes")

    # the cached graph dies WITH its incident when the track goes stale
    gid = next(iter(ids))
    clock.advance(121)  # past the 60s horizon
    c._sweep_dead_tracks(c._now_ms())
    check(gid not in c._last_incident, "d: sweep must prune the stale incident")
    check(gid not in c._incident_graphs,
          "d: sweep must prune the cached graph WITH its incident (never an "
          "orphaned graph entry)")
    check(c.incident_graph(gid) is None,
          "d: the accessor must return None for a swept incident")


# --- accessor surface: unknown / unpromoted -------------------------------
def test_incident_graph_returns_none_for_unknown_or_unpromoted():
    c = _new_correlator()
    check(c.incident_graph("default:actor:nobody:0") is None,
          "accessor: an unknown/live-but-unpromoted incident id must give None")
    c.ingest_alert(_alert("x1", tactic="TA0001", actor="solo", ip="10.0.0.9",
                          time_ms=1000, event_ids=["ev-x"]))
    check(c.incident_graph("default:actor:solo:0") is None,
          "accessor: a single-tactic (unpromoted) track must have no graph")


def run_all():
    test_single_alert_cooccurrence_yields_edge_with_provenance()
    test_all_three_edge_kinds_from_one_alert()
    test_two_alerts_sharing_an_ip_produce_no_edge_between_their_actors()
    test_device_incident_graph_spans_ip_change_with_no_ip_ip_edge()
    test_redelivery_emits_identical_graph()
    test_graph_bounded_by_member_set_and_swept_with_its_incident()
    test_incident_graph_returns_none_for_unknown_or_unpromoted()


if __name__ == "__main__":
    run_all()
    if FAILS:
        print(f"[FAIL] WS-8 incident.graph (ADR-009/WP-2-C): {len(FAILS)} problem(s)")
        for f in FAILS:
            print(f"  - {f}")
        sys.exit(1)
    print("[OK] WS-8 incident.graph test PASS (co-occurrence provenance edges "
          "+ no-transitive-inference proof (shared-ip and device-pivot legs) "
          "+ redelivery-identical graph + member-set-bounded + sweep-pruned + "
          "kind mapping used_ip/used_device/seen_at_ip)")
