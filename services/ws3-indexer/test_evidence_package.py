"""WP-3-B evidence-package tests: build -> verify round trip, tamper
detection (single-byte flip, reorder, incident swap, chain edit),
determinism (byte-identical + rebuild-stable package_id), the
contracts/reporting.md request mapping, the optional graph block, and
mutation soundness — the tamper test exercises the REAL hash chain, not a
mock (deleting the chain-verification code must make the tamper invisible).

INTERFACE NOTE (standalone artifact): evidence_package.py is not wired into
triage_api.py / reporting.py / main.py; the orchestrator decides later
whether a route consumes it. Its only seam is contracts/reporting.md via
to_reporting_payload(), which fills the contract's open "events is currently
always []" follow-up from the package's event blocks.

Run: python services/ws3-indexer/test_evidence_package.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import evidence_package  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


NOW_MS = 1751510000000
PREFIX = "pkg"


def _incident():
    return {
        "incident_id": "default:actor:alice:19700",
        "tenant_id": "default",
        "entity_type": "actor",
        "entity_value": "alice",
        "first_seen": 1751499900000,
        "last_seen": 1751500002000,
        "tactics": ["TA0001", "TA0002"],
        "member_alert_ids": ["a1", "a2"],
        "member_count": 2,
        "severity": 20,
        "truncated": False,
    }


def _alerts():
    return [
        {
            "alert_id": "a1", "time": 1751500000000, "rule_id": "rule-1",
            "level": "critical", "score": 85, "mitre": ["T1078"],
            "src_endpoint": {"ip": "10.0.0.9"}, "actor": {"user": {"name": "alice"}},
            "event_ids": ["evt-1", "evt-2", "ing-3", "ghost-9"],
        },
        {
            "alert_id": "a2", "time": 1751500002000, "rule_id": "rule-2",
            "level": "high", "score": 60, "mitre": ["T1110"],
            "src_endpoint": {"ip": "10.0.0.9"}, "actor": {"user": {"name": "alice"}},
            "event_ids": ["evt-1"],
        },
    ]


def _events():
    return [
        {"event_id": "evt-1", "siem": {"ingest_id": "ing-1", "raw": {"rawmsg": "pam: failed login"}},
         "time": 1751499900000, "class_uid": 4003, "category_uid": 4,
         "type_uid": 400301, "activity_id": 1, "severity_id": 2},
        {"event_id": "evt-2", "time": 1751499950000, "class_uid": 4003,
         "category_uid": 4, "type_uid": 400301, "activity_id": 1, "severity_id": 2},
        {"siem": {"ingest_id": "ing-3"}, "time": 1751499970000, "class_uid": 4003,
         "category_uid": 4, "type_uid": 400301, "activity_id": 1, "severity_id": 2},
        {"event_id": "evt-9", "time": 1751499980000, "class_uid": 4003},
    ]


def _graph():
    return {"version": 2, "nodes": ["a1", "a2"], "edges": [["a1", "evt-1"]]}


def _build(graph=None, now_ms=NOW_MS):
    return evidence_package.build_evidence_package(
        _incident(), _alerts(), _events(), graph, now_ms=now_ms, package_id_prefix=PREFIX)


def _tamper_alert_content(pkg, alert_id):
    """Flip one literal byte of an alert block's canonical content and
    reparse — a genuine single-byte mutation that leaves the stored
    content_hash (and everything else) untouched."""
    blocks = [dict(b) for b in pkg["blocks"]]
    idx = next(i for i, b in enumerate(blocks)
               if b.get("type") == "alert" and (b.get("content") or {}).get("alert_id") == alert_id)
    blk = dict(blocks[idx])
    canon = evidence_package._canonical_json(blk["content"])
    pos = next(i for i, ch in enumerate(canon) if ch.isdigit())
    flipped = canon[:pos] + ("0" if canon[pos] != "0" else "1") + canon[pos + 1:]
    check(flipped != canon, "internal: the byte flip must change the canonical form")
    blk["content"] = json.loads(flipped)
    blocks[idx] = blk
    return {**pkg, "blocks": blocks}


# -- (a) a built package verifies clean -------------------------------------

def test_built_package_verifies_clean():
    pkg = _build(graph=_graph())
    fails = evidence_package.verify_evidence_package(pkg)
    check(fails == [], f"a freshly built package must verify clean, got {fails}")
    types = [b["type"] for b in pkg["blocks"]]
    check(types == ["incident", "alert", "alert", "event", "event", "event", "event", "graph"],
          f"block layout must be incident -> alerts -> events -> graph, got {types}")
    check(pkg["primary_alert_id"] == "a1", "primary alert must be the chronological first member")
    check(pkg["blocks"][0]["prev_hash"] == evidence_package.ZERO_HASH,
          "the genesis incident block must anchor on the zero hash")
    check(all(b["content_hash"] == evidence_package._block_content_hash(b["content"])
              for b in pkg["blocks"]),
          "every block must carry the sha256 of its own canonical content")
    check(len(pkg["chain"]["head_hash"]) == 64, "head_hash must be a sha256 hex digest")
    check(pkg["chain"]["head_hash"] == evidence_package._header_hash(pkg["blocks"][-1]),
          "head_hash must be the last block's header hash")
    for prev_blk, blk in zip(pkg["blocks"], pkg["blocks"][1:]):
        check(blk["prev_hash"] == evidence_package._header_hash(prev_blk),
              f"block {blk['block_id']} must carry the previous block's header hash "
              "(real Merkle link, not a mock)")
    prov = {p["alert_id"]: p for p in pkg["provenance"]}
    check(prov["a1"]["unresolved_event_ids"] == ["ghost-9"],
          "a dangling event id must be listed honestly as unresolved")
    handles = [r["event_handle"] for r in prov["a1"]["resolved"]]
    check(handles == ["evt-1", "evt-2", "ing-3"],
          "provenance must join alert.event_ids onto event_id AND siem.ingest_id")
    raw = next(r for r in prov["a1"]["resolved"] if r["event_handle"] == "evt-1")["raw_fragment"]
    check(raw == {"rawmsg": "pam: failed login"},
          "provenance must carry the raw payload fragment down to the raw event")


# -- (b) single-byte tamper fails and names the block ------------------------

def test_flip_one_byte_in_alert_content_fails_naming_block():
    pkg = _build(graph=_graph())
    tampered = _tamper_alert_content(pkg, "a1")
    fails = evidence_package.verify_evidence_package(tampered)
    check(fails, "a single-byte content flip must break verification")
    check(any("a1" in f for f in fails), f"a failure must name the tampered block, got {fails}")
    check(any("content_hash" in f for f in fails), "the failure must be a content-hash mismatch")


# -- (c) same inputs twice -> byte-identical package and identical package_id

def test_same_inputs_twice_byte_identical_same_package_id():
    pkg1 = _build(graph=_graph(), now_ms=NOW_MS)
    pkg2 = _build(graph=_graph(), now_ms=NOW_MS)
    check(json.dumps(pkg1, sort_keys=True) == json.dumps(pkg2, sort_keys=True),
          "same inputs + same now_ms must produce a byte-identical package")
    check(pkg1["package_id"] == pkg2["package_id"], "package_id must be identical across builds")
    pkg3 = _build(graph=_graph(), now_ms=NOW_MS + 12345)
    check(pkg3["package_id"] == pkg1["package_id"],
          "package_id must NOT depend on build time (idempotent under at-least-once redelivery)")
    check(pkg3["built_at_ms"] == NOW_MS + 12345,
          "built_at_ms must reflect the injected now_ms, never the wall clock")


# -- (d) to_reporting_payload matches contracts/reporting.md request schema --

def test_to_reporting_payload_matches_reporting_request_schema():
    pkg = _build(graph=_graph())
    payload = evidence_package.to_reporting_payload(pkg)
    check(set(payload) == {"alert", "triage", "events", "requested_at"},
          f"payload keys must match contracts/reporting.md's request schema, got {sorted(payload)}")
    check(payload["alert"]["alert_id"] == "a1", "alert must be the primary member alert")
    check(isinstance(payload["triage"], dict) and payload["triage"]["status"] == "new",
          "triage must be the open pipeline's default triage state")
    check(isinstance(payload["requested_at"], (int, float)),
          "requested_at must be a number (build time in seconds)")
    want = {"evt-1", "evt-2", "ing-3"}
    got = [e.get("event_id") or (e.get("siem") or {}).get("ingest_id") for e in payload["events"]]
    check(len(payload["events"]) == 3 and set(got) == want,
          f"events must be the primary alert's underlying events, got {got}")
    block_events = {
        evidence_package._event_handle(b["content"]): b["content"]
        for b in pkg["blocks"] if b["type"] == "event"
    }
    for ev in payload["events"]:
        handle = evidence_package._event_handle(ev)
        check(block_events.get(handle) == ev,
              f"payload event {handle} must be its packaged event block content")


# -- (e) a package built without a graph still verifies ----------------------

def test_package_without_graph_still_verifies():
    pkg = _build(graph=None)
    check(not any(b["type"] == "graph" for b in pkg["blocks"]),
          "graph=None must produce no graph block (graph block optional)")
    fails = evidence_package.verify_evidence_package(pkg)
    check(fails == [], f"a graph-less package must verify clean, got {fails}")
    payload = evidence_package.to_reporting_payload(pkg)
    check(len(payload["events"]) == 3, "a graph-less package still feeds the reporting seam")


# -- (f) mutation soundness: deleting the chain code makes tamper invisible --

def test_deleting_hash_chain_verification_makes_tamper_invisible():
    pkg = _build(graph=_graph())
    tampered = _tamper_alert_content(pkg, "a1")
    check(evidence_package.verify_evidence_package(tampered),
          "precondition: the REAL chain must catch the tamper (test b)")
    real_chain = evidence_package._verify_chain
    evidence_package._verify_chain = lambda pkg_, failures_: None
    try:
        without_chain = evidence_package.verify_evidence_package(tampered)
    finally:
        evidence_package._verify_chain = real_chain
    check(without_chain == [],
          "deleting the hash-chain verification code must make the tamper go unnoticed — "
          "proving test (b) exercises the REAL chain, not a mock")
    check(evidence_package.verify_evidence_package(tampered),
          "restoring the chain verification must re-arm tamper detection")


# -- extra tamper surfaces ---------------------------------------------------

def test_reordering_blocks_breaks_verification():
    pkg = _build(graph=_graph())
    blocks = [dict(b) for b in pkg["blocks"]]
    i = next(i for i, b in enumerate(blocks) if b["block_id"] == "event:evt-2")
    j = next(i for i, b in enumerate(blocks) if b["block_id"] == "event:evt-9")
    blocks[i], blocks[j] = blocks[j], blocks[i]
    blocks[i]["index"] = i  # fix the index bookkeeping too: only the chain can catch this
    blocks[j]["index"] = j
    fails = evidence_package.verify_evidence_package({**pkg, "blocks": blocks})
    check(fails, "reordering blocks must break verification")
    check(any("prev_hash" in f or "chain" in f for f in fails),
          f"the reorder must be caught by the hash-chain links, got {fails}")


def test_swapping_the_incident_breaks_verification():
    pkg = _build(graph=_graph())
    blocks = [dict(b) for b in pkg["blocks"]]
    blk = dict(blocks[0])
    other = dict(_incident())
    other["incident_id"] = "acme:actor:bob:999"
    blk["content"] = other
    blocks[0] = blk
    fails = evidence_package.verify_evidence_package({**pkg, "blocks": blocks})
    check(fails, "swapping the incident must break verification")
    check(any("incident" in f for f in fails), f"a failure must name the incident, got {fails}")


def test_altering_the_hash_chain_breaks_verification():
    pkg = _build(graph=_graph())
    tampered = {**pkg, "chain": {"block_count": pkg["chain"]["block_count"], "head_hash": "f" * 64}}
    fails = evidence_package.verify_evidence_package(tampered)
    check(any("head_hash" in f for f in fails),
          f"an edited chain head must be detected, got {fails}")


def main():
    tests = [
        ("built package verifies clean with real Merkle links", test_built_package_verifies_clean),
        ("single-byte alert-content tamper fails, naming the block", test_flip_one_byte_in_alert_content_fails_naming_block),
        ("same inputs twice -> byte-identical package + same package_id",
         test_same_inputs_twice_byte_identical_same_package_id),
        ("to_reporting_payload matches contracts/reporting.md request schema",
         test_to_reporting_payload_matches_reporting_request_schema),
        ("graph=None package still verifies", test_package_without_graph_still_verifies),
        ("deleting hash-chain verification makes the tamper invisible (mutation soundness)",
         test_deleting_hash_chain_verification_makes_tamper_invisible),
        ("reordering blocks breaks the chain links", test_reordering_blocks_breaks_verification),
        ("swapping the incident breaks verification", test_swapping_the_incident_breaks_verification),
        ("altering the chain head breaks verification", test_altering_the_hash_chain_breaks_verification),
    ]
    ok = True
    for name, fn in tests:
        before = len(FAILS)
        fn()
        new_fails = FAILS[before:]
        if new_fails:
            ok = False
            print(f"[FAIL] {name}")
            for f in new_fails:
                print("   -", f)
        else:
            print(f"[OK] {name}")
    if not ok:
        sys.exit(1)
    print(f"[OK] evidence package: all {len(tests)} tests passed — hash-chain verified, "
          "tamper-evident, deterministic, reporting-seam mapping intact")


if __name__ == "__main__":
    main()