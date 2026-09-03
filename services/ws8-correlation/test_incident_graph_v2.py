"""WS-8 correlation: incident.graph (ADR-009 / WP-2-C) VERSION-2 typed-DAG tests
(WP-3-A, 2026-09-02).

v2 SUPERSEDES v1 on the incident.graph topic: the `version` field (integer
2) distinguishes the shape; the `incidents` topic payload is byte-for-byte
untouched. Nodes are canonical-entity_id objects; edges reference those ids
and carry exactly ONE kind -- the v1 field-pair kinds (used_ip/used_device/
seen_at_ip) for the same pairs, REPLACED by the typed kinds (caused_by /
invoked / authenticated_as / wrote_to / changed) when the evidencing alert's
OWN fields carry the documented semantic signal.

These are STANDALONE tests (no pytest), mirroring the check()/FAILS/main
shape of test_contract.py.

Coverage:
  (1) v2 emitted shape -- version 2, node objects carry entity_id/
      entity_type/entity_value/label, edges carry from/to as entity_ids +
      exactly one kind + event_id/ts_ms provenance, tactic_sources same
      shape as v1, the payload has exactly the six documented keys, and the
      INCIDENTS payload is byte-for-byte untouched (no graph keys, exact
      literal);
  (2) redelivery idempotency -- the same incident promoted twice, both on
      one instance and from two FRESH instances, emits byte-identical v2
      payloads (json-identical, not just eq);
  (3) IPv6 spelling variants collapse to ONE canonical node digest (matching
      ws9's compute via the identifier-agreement test) with the earliest
      provenance on the pair edge;
  (4) typed-kind derivation per kind, each with a concrete fixture, plus
      the honest negative: no signal -> the v1 field-pair kind is kept
      (never fabricate a causal label);
  (5) the no-transitive-inference proof carried into v2 (shared-ip leg: no
      edge between the two actors; device-pivot leg: no ip-ip edge);
  (6) boundedness -- edges bounded by the member set, the cached payload
      pruned WITH its incident by the dead-track sweep (v1 recipe);
  (7) identifier agreement with ws9 -- canonical_entity_id matches
      ws9-entity_id's digest for a lowercase ip, an uppercase-mixed IPv6
      spelling, a mixed-case actor (Alice vs alice) and an uppercase device
      mac, and the v2 NODE digest for an IPv6 address equals ws9's compute;
  (8) v1 byte-compat -- `_build_incident_graph` is byte-for-byte unchanged
      (source-text hash pin) and still callable, emitting a version:1
      payload with type:value string nodes/edges.

Run: python services/ws8-correlation/test_incident_graph_v2.py
"""
from __future__ import annotations

import hashlib
import inspect
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from test_contract import _Clock, _new_correlator  # noqa: E402
from correlator import (  # noqa: E402
    Correlator,
    _KIND_RANK,
    _TYPED_KIND_ORDER,
    canonical_entity_id,
    _typed_kind,
    _typed_kind_signal,
)

# The twin grader in a later wave codes against this exact shape; the
# identifier-agreement assertions below pin ws8's canonical digests to the
# WS-9 computation in the test process (both exist on a host checkout).
sys.path.insert(0, str(SERVICES / "ws9-resolver"))
import entity_id as ws9_entity_id  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _alert(alert_id, tactic=None, technique=None, actor=None, ip=None, mac=None,
           hostname=None, score=10, tenant="default", time_ms=None, event_ids=None,
           unmapped=None):
    """test_contract._alert plus the WP-3-A typed-kind signal fields: the
    full mitre block (tactic + technique) and an optional `unmapped` block
    (the documented caused_by signal source)."""
    a = {"alert_id": alert_id, "score": score, "tenant_id": tenant,
         "time": time_ms if time_ms is not None else 0}
    if tactic is not None:
        m = {"tactic": tactic}
        if technique:
            m["technique"] = technique
        a["mitre"] = m
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
    if unmapped:
        a["unmapped"] = unmapped
    return a


def _edge(graph, from_id, to_id):
    hits = [e for e in graph["edges"] if isinstance(e, dict)
            and e.get("from") == from_id and e.get("to") == to_id]
    return hits[0] if len(hits) == 1 else None


def _node(graph, entity_type):
    hits = [n for n in graph["nodes"] if isinstance(n, dict)
            and n.get("entity_type") == entity_type]
    return hits[0] if len(hits) == 1 else None


def _node_ids(graph):
    """Entity ids of the graph's node objects; a shape regression (nodes no
    longer dicts) yields an empty set -> the callers' assertions go RED
    cleanly instead of raising."""
    return {n["entity_id"] for n in graph["nodes"] if isinstance(n, dict)}


# --- (1) v2 emitted shape + incidents topic untouched -----------------------
def test_v2_emitted_shape_and_incidents_topic_untouched():
    """The accessor returns the version:2 typed DAG: nodes are entity_id
    objects, edges reference entity_ids with exactly one kind + provenance,
    tactic_sources matches v1's shape, and the INCIDENTS payload emitted
    alongside is byte-for-byte the documented v1 incident literal (no graph
    keys, same fields/values)."""
    c = _new_correlator()
    c.ingest_alert(_alert("a1", tactic="TA0001", technique="T1078.004",
                          actor="alice", ip="10.0.0.5",
                          time_ms=1000, event_ids=["ev-1"]))
    incs = c.ingest_alert(_alert("a2", tactic="TA0004", actor="alice",
                                 time_ms=2000, event_ids=["ev-2"]))
    check(len(incs) == 1 and incs[0]["entity_type"] == "actor",
          "shape: actor:alice must promote on the second distinct tactic")
    inc = incs[0]
    # incidents topic payload: byte-for-byte the documented v1 incident shape
    expected_incident = {
        "incident_id": "default:actor:alice:0",
        "tenant_id": "default",
        "entity_type": "actor",
        "entity_value": "alice",
        "first_seen": 1000,
        "last_seen": 2000,
        "tactics": ["TA0001", "TA0004"],
        "member_alert_ids": ["a1", "a2"],
        "member_count": 2,
        "severity": 20,
        "truncated": False,
    }
    check(inc == expected_incident,
          f"incidents: the incidents payload must be byte-for-byte untouched "
          f"by the graph upgrade, got {inc}")
    check(not any(k in inc for k in ("version", "nodes", "edges", "tactic_sources")),
          "incidents: the incident dict must carry NO graph keys")

    iid = inc["incident_id"]
    graph = c.incident_graph(iid)
    check(graph is not None, "shape: a graph payload must exist")
    check(graph["version"] == 2 and isinstance(graph["version"], int),
          f"shape: version must be the INTEGER 2, got {graph['version']!r}")
    check(set(graph) == {"version", "incident_id", "tenant_id", "nodes",
                         "edges", "tactic_sources"},
          f"shape: exactly the six documented v2 keys, got {sorted(graph)}")
    check(graph["incident_id"] == iid and graph["tenant_id"] == "default",
          "shape: incident_id/tenant_id must match the incident")

    alice_id = canonical_entity_id("default", "actor", "alice")
    ip_id = canonical_entity_id("default", "ip", "10.0.0.5")
    check(alice_id == "48cf022a5b59e25a19fb5aab14832d05ca4d53b90519017bc501191aa89dacf6"
          and ip_id == "66eea5d75deeec83a97d4cb42c6dac2be24a8ee77dd957bb4fe1d9888d0b67a4",
          f"shape: entity_ids must match the pinned sha256 digests, got "
          f"{alice_id} / {ip_id}")
    check(graph["nodes"] == [
        {"entity_id": alice_id, "entity_type": "actor", "entity_value": "alice",
         "label": "actor:alice"},
        {"entity_id": ip_id, "entity_type": "ip", "entity_value": "10.0.0.5",
         "label": "ip:10.0.0.5"},
    ], f"shape: nodes must be entity_id objects sorted by entity_id, got {graph['nodes']}")
    check(all(isinstance(n, dict) and set(n) == {"entity_id", "entity_type",
                                                 "entity_value", "label"}
              for n in graph["nodes"]),
          "shape: every node must carry exactly entity_id/entity_type/"
          "entity_value/label")
    check(all(isinstance(n, dict) and n["entity_type"] in ("actor", "ip", "device")
              for n in graph["nodes"]),
          "shape: entity_type must be one of actor/ip/device")
    check(graph["edges"] == [{
        "from": alice_id, "to": ip_id, "kind": "authenticated_as",
        "event_id": "ev-1", "ts_ms": 1000,
    }], f"shape: exactly one typed edge (authenticated_as on the TA0001/"
        f"T1078.004 evidence) with provenance, got {graph['edges']}")
    check(all(isinstance(e, dict) and set(e) == {"from", "to", "kind",
                                                 "event_id", "ts_ms"}
              for e in graph["edges"]),
          "shape: every edge must carry exactly from/to/kind/event_id/ts_ms")
    check(graph["tactic_sources"] == {"TA0001": ["a1"], "TA0004": ["a2"]},
          f"shape: tactic_sources must keep the v1 shape, got "
          f"{graph['tactic_sources']}")


# --- (2) redelivery idempotency, byte-identical ----------------------------
def test_redelivery_and_fresh_instance_emit_byte_identical_v2():
    """At-least-once redelivery: the same incident promoted twice -- and a
    FRESH correlator fed the same alerts -- must emit byte-identical v2
    payloads (json-identical serialization, not merely ==)."""
    r1 = _alert("r1", tactic="TA0001", technique="T1078", actor="frank",
                ip="10.1.1.1", time_ms=1000, event_ids=["ev-1"])
    r2 = _alert("r2", tactic="TA0002", actor="frank", time_ms=2000,
                event_ids=["ev-2"])

    c = _new_correlator()
    c.ingest_alert(r1)
    incs = c.ingest_alert(r2)
    iid = incs[0]["incident_id"]
    g1 = c.incident_graph(iid)
    check(g1["version"] == 2, "idem: promoted payload must be v2")

    c.ingest_alert(dict(r2))  # redeliver the SAME alert
    c.ingest_alert(dict(r1))
    c.ingest_alert(dict(r2))
    g_redelivered = c.incident_graph(iid)
    check(g_redelivered == g1,
          "idem: same-instance redelivery must re-emit an IDENTICAL v2 payload")
    check(json.dumps(g_redelivered, sort_keys=True)
          == json.dumps(g1, sort_keys=True),
          "idem: same-instance redelivery must be byte-identical (json)")

    c2 = _new_correlator()
    c2.ingest_alert(dict(r1))
    incs2 = c2.ingest_alert(dict(r2))
    g_fresh = c2.incident_graph(incs2[0]["incident_id"])
    check(g_fresh == g1,
          "idem: a fresh instance must deterministically re-derive the SAME "
          "v2 payload")
    check(json.dumps(g_fresh, sort_keys=True, separators=(",", ":"))
          == json.dumps(g1, sort_keys=True, separators=(",", ":")),
          "idem: a fresh instance must re-derive a BYTE-identical v2 payload")
    check(len({(e["from"], e["to"], e["kind"]) for e in g1["edges"]})
          == len(g1["edges"]),
          "idem: never duplicate edges" )


# --- (3) IPv6 spelling variants collapse to one canonical node digest -------
def test_ipv6_spelling_variants_collapse_to_one_canonical_digest():
    """Two spellings of ONE IPv6 address (expanded/case-variant vs
    compressed) co-occurring with the promoted actor must collapse into ONE
    v2 node whose entity_id is the canonical digest -- EXACTLY ws9's
    compute_entity_id for the canonical spelling (asserted here against ws9
    imported in-process, and re-asserted in the identifier-agreement test).
    The pair edge cites the earliest provenance and the typed kind of the
    earliest (TA0001) candidate."""
    c = _new_correlator()
    c.ingest_alert(_alert("g1", tactic="TA0001", actor="ivy",
                          ip="2001:0db8:0000:0000:0000:0000:0000:0001",
                          time_ms=1000, event_ids=["ev-1"]))
    incs = c.ingest_alert(_alert("g2", tactic="TA0002", actor="ivy",
                                 ip="2001:DB8::1",
                                 time_ms=2000, event_ids=["ev-2"]))
    iid = next(i["incident_id"] for i in incs if i["entity_type"] == "actor")
    graph = c.incident_graph(iid)
    ip_nodes = [n for n in graph["nodes"]
                if isinstance(n, dict) and n["entity_type"] == "ip"]
    check(len(ip_nodes) == 1,
          f"ipv6: exactly ONE ip node must survive the spelling variants, "
          f"got {[n['entity_value'] for n in ip_nodes]}")
    ip_node_id = canonical_entity_id("default", "ip", "2001:db8::1")
    check(ip_nodes and ip_nodes[0]["entity_id"] == ip_node_id
          and ip_nodes[0]["entity_value"] == "2001:db8::1"
          and ip_nodes[0]["label"] == "ip:2001:db8::1",
          f"ipv6: the collapsed node must carry the canonical spelling and "
          f"digest, got {ip_nodes}")
    check(ip_node_id == "5ee40ea2c1ade919df599ec4273cbf1240a6f7623bba88d4eb1867105d32aba6",
          f"ipv6: the collapsed digest must equal the pinned sha256 of "
          f"default|ip|2001:db8::1, got {ip_node_id}")
    check(ip_node_id == ws9_entity_id.compute_entity_id(
            "default", "ip",
            ws9_entity_id.canonical_entity_value("ip", "2001:DB8::1")),
          "ipv6: the v2 NODE digest for an IPv6 address must equal ws9's "
          "compute_entity_id for the same address")
    ivy_id = canonical_entity_id("default", "actor", "ivy")
    check(graph["edges"] == [{
        "from": ivy_id, "to": ip_node_id, "kind": "authenticated_as",
        "event_id": "ev-1", "ts_ms": 1000,
    }], f"ipv6: earliest provenance wins and the TA0001 member's typed kind "
        f"outranks the v1 fallback the TA0002 member would give, got "
        f"{graph['edges']}")


# --- (4) typed-kind derivation per kind (concrete fixtures) ----------------
def test_typed_kinds_derived_per_documented_table():
    """One concrete fixture per typed kind proving the derivation table in
    `_typed_kind` / INTERFACE.md: authenticated_as, invoked, caused_by,
    wrote_to, changed (both the device->ip and actor->device rows). Each
    edge kind is derived ONLY from the evidencing alert's OWN mitre/unmapped
    fields -- single-alert-only. The paired negatives prove the honest
    fallback: an alert WITHOUT the signal keeps the v1 field-pair kind."""
    # authenticated_as: actor->ip, TA0001/Valid-Accounts evidence
    c = _new_correlator()
    c.ingest_alert(_alert("au1", tactic="TA0001", technique="T1078.004",
                          actor="ada", ip="10.20.0.1",
                          time_ms=1000, event_ids=["ev-au1"]))
    incs = c.ingest_alert(_alert("au2", tactic="TA0004", actor="ada",
                                 time_ms=2000, event_ids=["ev-au2"]))
    g = c.incident_graph(incs[0]["incident_id"])
    e = _edge(g, canonical_entity_id("default", "actor", "ada"),
              canonical_entity_id("default", "ip", "10.20.0.1"))
    check(e is not None and e["kind"] == "authenticated_as"
          and e["event_id"] == "ev-au1" and e["ts_ms"] == 1000,
          f"typed: TA0001/T1078.004 evidence must yield authenticated_as, "
          f"got {e}")
    # negative: no typed signal on the pair -> v1 fallback used_ip
    c2 = _new_correlator()
    c2.ingest_alert(_alert("au3", tactic="TA0006", actor="ada2", ip="10.20.0.3",
                           time_ms=1000, event_ids=["ev-au3"]))
    incs2 = c2.ingest_alert(_alert("au4", tactic="TA0007", actor="ada2",
                                   time_ms=2000, event_ids=["ev-au4"]))
    g2 = c2.incident_graph(incs2[0]["incident_id"])
    e2 = _edge(g2, canonical_entity_id("default", "actor", "ada2"),
               canonical_entity_id("default", "ip", "10.20.0.3"))
    check(e2 is not None and e2["kind"] == "used_ip",
          f"typed: NO semantic signal -> keep the v1 field-pair kind used_ip "
          f"(never fabricate a causal label), got {e2}")

    # invoked: actor->ip, TA0011 / T1071 (C2 / app-layer-protocol) evidence
    c = _new_correlator()
    c.ingest_alert(_alert("iv1", tactic="TA0011", technique="T1071",
                          actor="bob", ip="10.20.0.2",
                          time_ms=1000, event_ids=["ev-iv1"]))
    incs = c.ingest_alert(_alert("iv2", tactic="TA0040", actor="bob",
                                 time_ms=2000, event_ids=["ev-iv2"]))
    g = c.incident_graph(incs[0]["incident_id"])
    e = _edge(g, canonical_entity_id("default", "actor", "bob"),
              canonical_entity_id("default", "ip", "10.20.0.2"))
    check(e is not None and e["kind"] == "invoked",
          f"typed: TA0011/T1071 evidence must yield invoked, got {e}")

    # wrote_to: actor->device, TA0106/T0836 (ICS Modify Parameter) evidence
    c = _new_correlator()
    c.ingest_alert(_alert("wt1", tactic="TA0106", technique="T0836",
                          actor="carla", mac="AA:BB:CC:DD:EE:FF",
                          time_ms=1000, event_ids=["ev-wt1"]))
    incs = c.ingest_alert(_alert("wt2", tactic="TA0002", actor="carla",
                                 time_ms=2000, event_ids=["ev-wt2"]))
    g = c.incident_graph(incs[0]["incident_id"])
    e = _edge(g, canonical_entity_id("default", "actor", "carla"),
              canonical_entity_id("default", "device", "AA:BB:CC:DD:EE:FF"))
    check(e is not None and e["kind"] == "wrote_to",
          f"typed: TA0106/T0836 evidence must yield wrote_to, got {e}")

    # changed (device->ip row): TA0108 (attack-ics Initial Access) evidence
    c = _new_correlator()
    c.ingest_alert(_alert("ch1", tactic="TA0108", technique="T0864",
                          mac="AA:BB:CC:DD:EE:FF", ip="10.30.0.1",
                          time_ms=1000, event_ids=["ev-ch1"]))
    incs = c.ingest_alert(_alert("ch2", tactic="TA0006", mac="AA:BB:CC:DD:EE:FF",
                                 time_ms=2000, event_ids=["ev-ch2"]))
    dev_inc = next(i for i in incs if i["entity_type"] == "device")
    g = c.incident_graph(dev_inc["incident_id"])
    e = _edge(g, canonical_entity_id("default", "device", "AA:BB:CC:DD:EE:FF"),
              canonical_entity_id("default", "ip", "10.30.0.1"))
    check(e is not None and e["kind"] == "changed",
          f"typed: TA0108 evidence must yield changed on device->ip, got {e}")

    # changed (actor->device row): TA0003 (Persistence) evidence
    c = _new_correlator()
    c.ingest_alert(_alert("ch3", tactic="TA0003", technique="T1098",
                          actor="erin", mac="AA:BB:CC:DD:EE:FF",
                          time_ms=1000, event_ids=["ev-ch3"]))
    incs = c.ingest_alert(_alert("ch4", tactic="TA0002", actor="erin",
                                 time_ms=2000, event_ids=["ev-ch4"]))
    g = c.incident_graph(incs[0]["incident_id"])
    e = _edge(g, canonical_entity_id("default", "actor", "erin"),
              canonical_entity_id("default", "device", "AA:BB:CC:DD:EE:FF"))
    check(e is not None and e["kind"] == "changed",
          f"typed: TA0003 evidence must yield changed on actor->device, got {e}")

    # caused_by: actor->device, T0855 + unmapped.ot.anomaly_type
    c = _new_correlator()
    c.ingest_alert(_alert("cb1", tactic="TA0106", technique="T0855",
                          actor="fred", mac="AA:BB:CC:DD:EE:FF",
                          unmapped={"ot": {"anomaly_type": "unauthorized_write"}},
                          time_ms=1000, event_ids=["ev-cb1"]))
    incs = c.ingest_alert(_alert("cb2", tactic="TA0108", actor="fred",
                                 time_ms=2000, event_ids=["ev-cb2"]))
    g = c.incident_graph(incs[0]["incident_id"])
    e = _edge(g, canonical_entity_id("default", "actor", "fred"),
              canonical_entity_id("default", "device", "AA:BB:CC:DD:EE:FF"))
    check(e is not None and e["kind"] == "caused_by",
          f"typed: T0855 + unmapped.ot.anomaly_type=unauthorized_write must "
          f"yield caused_by, got {e}")
    # negative: the SAME alert shape without the unmapped causal signal ->
    # the v1 field-pair kind used_device (never fabricate caused_by)
    c2 = _new_correlator()
    c2.ingest_alert(_alert("cb3", tactic="TA0106", technique="T0855",
                           actor="george", mac="AA:BB:CC:DD:EE:FF",
                           time_ms=1000, event_ids=["ev-cb3"]))
    incs2 = c2.ingest_alert(_alert("cb4", tactic="TA0108", actor="george",
                                   time_ms=2000, event_ids=["ev-cb4"]))
    g2 = c2.incident_graph(incs2[0]["incident_id"])
    e2 = _edge(g2, canonical_entity_id("default", "actor", "george"),
               canonical_entity_id("default", "device", "AA:BB:CC:DD:EE:FF"))
    check(e2 is not None and e2["kind"] == "used_device",
          f"typed: T0855 WITHOUT the unmapped causal signal must keep the v1 "
          f"field-pair kind used_device, got {e2}")

    # exactly one kind per edge, and the full kind vocabulary is closed
    check(_TYPED_KIND_ORDER == ("caused_by", "invoked", "authenticated_as",
                                "wrote_to", "changed"),
          "typed: the documented typed-kind order must stay pinned")
    check(set(_KIND_RANK) >= set(_TYPED_KIND_ORDER),
          "typed: every typed kind must have a rank")


# --- (5) no-transitive-inference proof, carried into v2 --------------------
def test_no_transitive_inference_carried_into_v2():
    """The v1 refusal, on the v2 graph: grace and heidi share src IP
    198.51.100.9 but NO single alert carries both, so no edge may connect
    their entities anywhere -- an inference path (grace --[via ip]--> heidi)
    is exactly the transitive join WS-8 refuses. Device-pivot leg: one mac,
    two ips, no actor -> no ip-ip edge either."""
    c = _new_correlator()
    c.ingest_alert(_alert("s1", tactic="TA0001", actor="grace",
                          ip="198.51.100.9", time_ms=1000, event_ids=["ev-1"]))
    incs = c.ingest_alert(_alert("s2", tactic="TA0002", actor="grace",
                                 time_ms=2000, event_ids=["ev-2"]))
    grace_iid = next(i["incident_id"] for i in incs if i["entity_type"] == "actor")
    c.ingest_alert(_alert("s3", tactic="TA0001", actor="heidi",
                          ip="198.51.100.9", time_ms=3000, event_ids=["ev-3"]))
    incs2 = c.ingest_alert(_alert("s4", tactic="TA0002", actor="heidi",
                                  ip="198.51.100.9", time_ms=4000,
                                  event_ids=["ev-4"]))
    ip_iid = next(i["incident_id"] for i in incs2 if i["entity_type"] == "ip")
    grace_id = canonical_entity_id("default", "actor", "grace")
    heidi_id = canonical_entity_id("default", "actor", "heidi")
    ip_id = canonical_entity_id("default", "ip", "198.51.100.9")
    ip_graph = c.incident_graph(ip_iid)
    node_ids = _node_ids(ip_graph)
    check(node_ids == {ip_id, grace_id, heidi_id},
          f"no-trans: the ip incident must span the shared ip and BOTH "
          f"actors, got {ip_graph['nodes']}")
    pairs = {(e["from"], e["to"]) for e in ip_graph["edges"]}
    check(not any(set(p) == {grace_id, heidi_id} for p in pairs),
          "no-trans: NO edge may connect the two actors (transitive "
          "inference through the shared ip)")
    check(len(ip_graph["edges"]) == 2,
          f"no-trans: exactly the two DIRECT actor->ip edges, got "
          f"{ip_graph['edges']}")
    grace_graph = c.incident_graph(grace_iid)
    check(heidi_id not in _node_ids(grace_graph),
          "no-trans: grace's actor incident must not mention heidi")

    # device-pivot leg: no ip-ip edge through the shared mac
    c2 = _new_correlator()
    c2.ingest_alert(_alert("d1", tactic="TA0043", ip="10.0.0.5",
                           mac="AA:BB:CC:DD:EE:FF", time_ms=1000,
                           event_ids=["ev-d1"]))
    incs3 = c2.ingest_alert(_alert("d2", tactic="TA0006", ip="10.0.0.9",
                                   mac="AA:BB:CC:DD:EE:FF", time_ms=2000,
                                   event_ids=["ev-d2"]))
    dev = next(i for i in incs3 if i["entity_type"] == "device")
    g = c2.incident_graph(dev["incident_id"])
    pairs = {(e["from"], e["to"]) for e in g["edges"]}
    ip1 = canonical_entity_id("default", "ip", "10.0.0.5")
    ip2 = canonical_entity_id("default", "ip", "10.0.0.9")
    check(not any(set(p) == {ip1, ip2} for p in pairs),
          "no-trans: NO ip-ip edge through the shared device (pivot leg)")


# --- (6) bounded by member set, pruned WITH its incident -------------------
def test_v2_bounded_by_member_set_and_swept_with_incident():
    """v2 mirrors v1's boundedness exactly: edges bounded by the live member
    set (<=3 pairs per member, one edge per pair), edge count STABILIZES
    once member_cap evicts, and the sweep prunes the cached v2 payload WITH
    its incident (same _sweep_dead_tracks recipe as the v1 test)."""
    clock = _Clock()
    c = _new_correlator(horizon_s=60, member_cap=5, now_fn=clock)
    c.ingest_alert(_alert("recon", tactic="TA0043", actor="bf-user",
                          ip="10.9.0.1", time_ms=1000, event_ids=["ev-recon"]))
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
          f"bound: the whole flood must stay under ONE incident_id, got {ids}")
    check(set(c._incident_graphs) == ids,
          f"bound: exactly one cached v2 graph per promoted incident, got "
          f"{sorted(c._incident_graphs)}")
    check(max(edge_counts) <= 3 * 5,
          f"bound: edges must be bounded by the member set (<=3 pairs per "
          f"live member; live members capped at member_cap=5), got max "
          f"{max(edge_counts)}")
    check(edge_counts[-1] == edge_counts[10],
          f"bound: once the cap binds the edge count must STABILIZE, got "
          f"{edge_counts[10]} vs {edge_counts[-1]}")
    node_ids = _node_ids(stable_graph)
    check(all({e["from"], e["to"]} <= node_ids for e in stable_graph["edges"]),
          "bound: every edge's endpoints must be present in node ids")
    check(all(e["kind"] == "used_ip" for e in stable_graph["edges"]),
          "bound: the TA0043/TA0006 flood carries no typed signal -- the "
          "field-pair kind used_ip must be kept")

    gid = next(iter(ids))
    clock.advance(121)  # past the 60s horizon
    c._sweep_dead_tracks(c._now_ms())
    check(gid not in c._last_incident, "bound: sweep must prune the stale incident")
    check(gid not in c._incident_graphs,
          "bound: sweep must prune the cached v2 graph WITH its incident")
    check(c.incident_graph(gid) is None,
          "bound: the accessor must return None for a swept incident")


# --- (7) identifier agreement with ws9 -------------------------------------
def test_identifier_agreement_with_ws9():
    """canonical_entity_id mirrors services/ws9-resolver/entity_id.py EXACTLY
    (imported in this test process): the sha256 hexdigest of the pipe-joined
    (tenant, entity_type, canonical_value) with ip -> valid_ip-lowercased,
    actor -> strip+casefold, device -> strip+lower. The required samples: a
    lowercase ip, an uppercase-mixed IPv6 spelling (2001:DB8::1), a
    mixed-case actor (Alice vs alice -- ONE identity), and an uppercase
    device mac. Un-normalizable values return None on BOTH sides."""
    samples = [
        ("default", "ip", "10.0.0.5"),
        ("default", "ip", "2001:DB8::1"),
        ("acme", "actor", "Alice"),
        ("default", "device", "AA:BB:CC:DD:EE:FF"),
    ]
    for tenant, etype, raw in samples:
        ws9_value = ws9_entity_id.canonical_entity_value(etype, raw)
        check(ws9_value is not None,
              f"agree: ws9 must normalize {raw!r} to {etype}")
        ws9_digest = ws9_entity_id.compute_entity_id(tenant, etype, ws9_value)
        mine = canonical_entity_id(tenant, etype, raw)
        check(mine == ws9_digest,
              f"agree: canonical_entity_id({tenant!r}, {etype!r}, {raw!r}) "
              f"must equal ws9's {ws9_digest}, got {mine}")
        check(isinstance(mine, str) and len(mine) == 64,
              "agree: the digest must be a 64-char sha256 hexdigest")

    # actor casing: Alice / ALICE / alice are ONE identity
    alice = canonical_entity_id("acme", "actor", "Alice")
    alice_lower = canonical_entity_id("acme", "actor", "alice")
    check(alice == alice_lower,
          f"agree: Alice and alice must collapse to ONE actor digest, got "
          f"{alice} vs {alice_lower}")
    check(alice == ws9_entity_id.compute_entity_id(
            "acme", "actor", ws9_entity_id.canonical_entity_value("actor", "ALICE")),
          "agree: the collapsed actor digest must equal ws9's for the "
          "case-folded value")

    # distinct types/tenants must never collide
    check(canonical_entity_id("acme", "actor", "Alice")
          != canonical_entity_id("acme", "device", "alice"),
          "agree: a casefolded actor must never collide with a lowercased "
          "device (the entity_type is part of the preimage)")
    check(canonical_entity_id("acme", "actor", "alice")
          != canonical_entity_id("beta", "actor", "alice"),
          "agree: tenant is part of the preimage")

    # un-normalizable values: None on both sides (degrade, never fabricate)
    check(canonical_entity_id("default", "ip", "not-an-ip") is None
          and ws9_entity_id.canonical_entity_value("ip", "not-an-ip") is None,
          "agree: a non-IP must be un-identifiable on both sides")
    check(canonical_entity_id("default", "actor", 5) is None
          and ws9_entity_id.canonical_entity_value("actor", 5) is None,
          "agree: a non-string actor must be un-identifiable on both sides "
          "(never str()-coerced)")
    try:
        canonical_entity_id("default", "widget", "x")
        check(False, "agree: an unknown entity_type must raise ValueError "
                     "(mirroring ws9)")
    except ValueError:
        pass


# --- (8) v1 builder byte-for-byte ------------------------------------------
# SHA-256 of inspect.getsource(Correlator._build_incident_graph) captured at
# WP-3-A land time (2026-09-02) -- the v1 builder must remain BYTE-FOR-BYTE
# unchanged (same name, same output) so v1 consumers and the byte-compat
# test keep passing while the accessor/cache emit v2.
_V1_BUILDER_SOURCE_SHA256 = "2ad96b4974744ba1eca502016e38038a56ee80a0744efbbf5487c2622b74f1fa"


def test_v1_builder_byte_for_byte_unchanged():
    """The v1 `_build_incident_graph` must stay byte-for-byte (source-text
    hash pin) and still be CALLABLE with live side-table state, emitting a
    version:1 payload with type:value string nodes and edges -- the v1 shape
    v1 consumers and the byte-compat test depend on."""
    src = inspect.getsource(Correlator._build_incident_graph)
    src_hash = hashlib.sha256(src.encode("utf-8")).hexdigest()
    check(src_hash == _V1_BUILDER_SOURCE_SHA256,
          f"v1-compat: _build_incident_graph source text must stay "
          f"byte-for-byte unchanged (hash {src_hash} != pinned "
          f"{_V1_BUILDER_SOURCE_SHA256})")

    # behavioral: the v1 builder still emits the v1 payload from live state
    c = _new_correlator()
    c.ingest_alert(_alert("v1a", tactic="TA0001", actor="v1-user",
                          ip="10.0.0.9", time_ms=1000, event_ids=["ev-1"]))
    incs = c.ingest_alert(_alert("v1b", tactic="TA0002", actor="v1-user",
                                 time_ms=2000, event_ids=["ev-2"]))
    inc = incs[0]
    key = c._track_key(inc["tenant_id"], inc["entity_type"], inc["entity_value"])
    side = c._sides[key]
    v1 = c._build_incident_graph(inc["tenant_id"], inc["entity_type"],
                                 inc["entity_value"], inc, side)
    check(v1 is not None and v1["version"] == 1,
          f"v1-compat: the v1 builder must still emit version 1, got "
          f"{v1 and v1['version']!r}")
    check(v1["nodes"] == ["actor:v1-user", "ip:10.0.0.9"],
          f"v1-compat: v1 nodes must stay type:value STRINGS, got {v1['nodes']}")
    check(v1["edges"] == [{
        "from": "actor:v1-user", "to": "ip:10.0.0.9", "kind": "used_ip",
        "event_id": "ev-1", "ts_ms": 1000,
    }], f"v1-compat: v1 edges must stay type:value refs with the v1 kind, "
        f"got {v1['edges']}")
    # the ACCESOR, in contrast, must return v2 (produce source for the topic)
    check(c.incident_graph(inc["incident_id"])["version"] == 2,
          "v1-compat: the ACCESSOR must return the v2 payload even though "
          "the v1 builder stays callable")


# --- (x) typed-kind derivation is a pure function of the alert -----------
def test_typed_kind_signal_is_pure_and_bounded():
    """`_typed_kind_signal` reads only the alert's OWN fields (mitre tactic/
    technique, unmapped.ot.anomaly_type) and ignores everything else -- a
    redelivered alert re-derives the same signal; a malformed mitre/unmapped
    block degrades to no signal, never crashing."""
    base = _alert("x1", tactic="TA0106", technique="T0855", actor="x",
                  unmapped={"ot": {"anomaly_type": "unauthorized_write"},
                            "irrelevant": {"x": "y"}})
    signal = _typed_kind_signal(base)
    check(signal == ("TA0106", "T0855", "unauthorized_write"),
          f"signal: the exact (tactic, technique, anomaly) tuple, got {signal}")
    check(_typed_kind_signal(dict(base)) == signal,
          "signal: a re-delivered identical alert must re-derive the SAME "
          "signal")
    check(_typed_kind_signal({}) == (None, None, None),
          "signal: an alert without mitre/unmapped must yield an all-None "
          "signal")
    check(_typed_kind_signal({"mitre": "TA0001", "unmapped": 5})
          == (None, None, None),
          "signal: a malformed (non-dict) mitre/unmapped must degrade to no "
          "signal, never crash")
    check(_typed_kind("actor", "device", ("TA0106", "T0855",
                                          "unauthorized_write")) == "caused_by"
          and _typed_kind("actor", "ip", ("TA0001", "T1078.004", None))
          == "authenticated_as"
          and _typed_kind("actor", "ip", ("TA0006", None, None)) is None,
          "signal: _typed_kind must be the documented pure mapping")


# --- (9) graph_sig cache: skips rebuild on a no-op redelivery, rebuilds on
#         a real change, and its fingerprint is mutation-sound --------------
def test_graph_cache_skips_rebuild_on_unchanged_member_set():
    """The `_graph_sigs` fingerprint cache (2026-09-03, efficiency finding)
    must skip `_build_incident_graph_v2` when a promoted track's live member
    set is unchanged since the last build -- proven here with a call-count
    spy, not just by checking the OUTPUT is correct (which a naive
    always-rebuild implementation would also pass)."""
    c = _new_correlator()
    a1 = _alert("cache1", tactic="TA0001", technique="T1078.004", actor="cache-user",
               ip="10.30.0.1", time_ms=1000, event_ids=["ev-cache1"])
    a2 = _alert("cache2", tactic="TA0004", actor="cache-user",
               time_ms=1500, event_ids=["ev-cache2"])
    c.ingest_alert(a1)
    incs = c.ingest_alert(a2)
    check(len(incs) == 1 and incs[0]["entity_type"] == "actor",
          "cache: setup must promote exactly one incident (actor:cache-user)")
    incident_id = incs[0]["incident_id"]
    g_before = c.incident_graph(incident_id)

    calls: list = []
    real_build = c._build_incident_graph_v2

    def _spy(*args, **kwargs):
        calls.append(1)
        return real_build(*args, **kwargs)

    c._build_incident_graph_v2 = _spy
    try:
        # Redeliver the SAME alerts (identical content, same alert_ids): the
        # live member set and every graph-relevant field are unchanged, so
        # the rebuild must be SKIPPED and the cached graph object reused.
        c.ingest_alert(dict(a1))
        c.ingest_alert(dict(a2))
        check(len(calls) == 0,
              f"cache: redelivering unchanged members must skip "
              f"_build_incident_graph_v2, got {len(calls)} rebuild(s)")
        check(c.incident_graph(incident_id) == g_before,
              "cache: the served graph after a no-op redelivery must be "
              "byte-identical to before")

        # A genuinely NEW member for the SAME track changes the fingerprint
        # -- the rebuild must happen exactly once.
        a3 = _alert("cache3", tactic="TA0004", actor="cache-user",
                   ip="10.30.0.9", time_ms=2000, event_ids=["ev-cache3"])
        c.ingest_alert(a3)
        check(len(calls) == 1,
              f"cache: a new member must trigger exactly one rebuild, got "
              f"{len(calls)}")
    finally:
        del c._build_incident_graph_v2  # drop the instance override


def test_graph_signature_is_mutation_sound():
    """Mutation-soundness for the cache's fingerprint (2026-09-03): a
    fingerprint that omitted a field `_build_incident_graph_v2` reads off a
    member's entry could produce a FALSE cache hit -- two different member
    states hashing to the SAME fingerprint would silently serve a stale
    graph. Proven directly against `Correlator._graph_signature` (not
    reimplemented here) by building pairs of `side` states that differ in
    exactly ONE field each and asserting the fingerprint changes for every
    one of them."""
    base_entry = {
        "alert_id": "m1", "tactic": "TA0001", "score": 10, "time": 1000,
        "time_fallback": False, "event_id": "ev-1",
        "cooccur": [("ip", "10.0.0.1")], "typed_signal": ("TA0001", "T1078.004", None),
    }
    base_side = {"m1": dict(base_entry)}
    base_sig = Correlator._graph_signature(base_side)

    mutations = {
        "time": 2000,
        "tactic": "TA0004",
        "event_id": "ev-2",
        "time_fallback": True,
        "cooccur": [("ip", "10.0.0.2")],
        "typed_signal": ("TA0004", None, None),
    }
    for field, new_value in mutations.items():
        mutated_entry = dict(base_entry)
        mutated_entry[field] = new_value
        mutated_side = {"m1": mutated_entry}
        mutated_sig = Correlator._graph_signature(mutated_side)
        check(mutated_sig != base_sig,
              f"sig: changing entry field {field!r} alone must change the "
              f"fingerprint (else a change to it could be served from a "
              f"stale cached graph)")

    # A membership change (new member id) must also change the fingerprint.
    added_member_side = {"m1": dict(base_entry), "m2": dict(base_entry, alert_id="m2")}
    check(Correlator._graph_signature(added_member_side) != base_sig,
          "sig: adding a member must change the fingerprint")

    # Identical content, freshly-copied dicts (simulating a real redelivery's
    # freshly-built entry) -- the fingerprint must be identical.
    check(Correlator._graph_signature({"m1": dict(base_entry)}) == base_sig,
          "sig: two structurally-identical side states must fingerprint "
          "identically (else a harmless redelivery would never hit cache)")


def run_all():
    test_v2_emitted_shape_and_incidents_topic_untouched()
    test_redelivery_and_fresh_instance_emit_byte_identical_v2()
    test_ipv6_spelling_variants_collapse_to_one_canonical_digest()
    test_typed_kinds_derived_per_documented_table()
    test_no_transitive_inference_carried_into_v2()
    test_v2_bounded_by_member_set_and_swept_with_incident()
    test_identifier_agreement_with_ws9()
    test_v1_builder_byte_for_byte_unchanged()
    test_typed_kind_signal_is_pure_and_bounded()
    test_graph_cache_skips_rebuild_on_unchanged_member_set()
    test_graph_signature_is_mutation_sound()


if __name__ == "__main__":
    run_all()
    if FAILS:
        print(f"[FAIL] WS-8 incident.graph v2 (WP-3-A): {len(FAILS)} problem(s)")
        for f in FAILS:
            print(f"  - {f}")
        sys.exit(1)
    print("[OK] WS-8 incident.graph v2 test PASS (typed causal DAG: v2 shape "
          "+ incidents byte-untouched + fresh-instance redelivery "
          "byte-identical + IPv6 canonical-node collapse + per-kind typed "
          "derivation fixtures (authenticated_as/invoked/wrote_to/changed/"
          "caused_by) with v1-kind fallback + no-transitive-inference proof "
          "+ member-set bounded + sweep-pruned with incident + ws9 "
          "identifier agreement + v1 builder byte-for-byte)")