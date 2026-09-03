"""WP-3-B evidence package: an immutable, hash-chained incident artifact.

STORY: an auditor hands an incident to a regulator and must prove the story —
which alerts fired, which underlying normalized events back them, in what
order, with a tamper-evident chain. This module builds that artifact (and
verifies it) purely from the already-indexed docs the WS-3 pipeline holds:
the incidents-topic document, its member alert docs, and the underlying
normalized OCSF events, plus the optional incident.graph payload.

INTERFACE NOTE (delivered standalone): this is a NEW artifact. Nothing in the
existing ws3-indexer code imports it — no triage_api.py, reporting.py or
main.py change. The orchestrator decides later whether a route consumes it.
The only seam it feeds is contracts/reporting.md (frozen, no new cross-repo
contract): to_reporting_payload() renders the reporting REQUEST payload
(alert / triage / events / requested_at) from a built package, filling the
contract's explicitly open follow-up ("events is currently always []") with
the package's event blocks.

Hash-chain design (Merkle-style hash list, documented here):

    blocks = [ incident, alert*, event*, graph? ]   (graph block optional)

Every block carries:
    type         'incident' | 'alert' | 'event' | 'graph'
    block_id     unique within the package
    index        position in the chain (0-based)
    content      the evidence payload itself (deep-copied from the input)
    content_hash sha256 hex over the canonical JSON of `content`
    prev_hash    header hash of the previous block ('0'*64 for the first)

    header hash of a block := sha256(canonical{type, block_id, index,
    prev_hash, content_hash}) — the entire header, including its content
    commitment and its link to the previous block.

The chain is a linear Merkle chain (a hash list): each block's header commits
to every block before it, and chain.head_hash is the root — the header hash
of the last block. Verification recomputes every content hash, walks every
prev_hash link, checks the head, and re-derives the package_id digest; any
single-byte mutation of a block's content, a reordering of blocks, a swapped
incident, or an edited link/head breaks at least one check and the failure
names the offending block.

Determinism: canonical form is json.dumps(sort_keys=True,
separators=(",", ":")). now_ms is injected and never read from the clock
inside this module — the same inputs plus the same now_ms produce a
byte-identical package.

package_id determinism:
    package_id = f"{package_id_prefix}:{incident_id}:{digest}" where digest
    is sha256 over the canonical JSON of the ordered list of each block's
    {type, block_id, content_hash}. It never includes built_at_ms, so
    building the same incident twice — even at different wall-clock times —
    yields the same package_id (idempotent under at-least-once redelivery,
    the same discipline as alert_id / report_id).
"""
from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter

SCHEMA = "fengarde.evidence-package.v1"
ZERO_HASH = "0" * 64
_BLOCK_TYPES = ("incident", "alert", "event", "graph")


def _canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _block_content_hash(content) -> str:
    return _sha256_hex(_canonical_json(content))


def _header_hash(block: dict) -> str:
    """Header digest of one block: commits to type, block_id, position, the
    previous link and the content commitment. This is what the next block's
    prev_hash (and the chain head) references."""
    header = {
        "type": block.get("type"),
        "block_id": block.get("block_id"),
        "index": block.get("index"),
        "prev_hash": block.get("prev_hash"),
        "content_hash": block.get("content_hash"),
    }
    return _sha256_hex(_canonical_json(header))


def _package_digest(blocks: list[dict]) -> str:
    """Content digest of the whole chain: sha256 over the canonical form of
    each block's {type, block_id, content_hash} in chain order. Never includes
    build time, so the package_id is rebuild-stable."""
    knots = [
        {"type": b.get("type"), "block_id": b.get("block_id"), "content_hash": b.get("content_hash")}
        for b in blocks
    ]
    return _sha256_hex(_canonical_json(knots))


def _make_block(btype: str, block_id: str, index: int, content, prev_hash: str) -> dict:
    return {
        "type": btype,
        "block_id": block_id,
        "index": index,
        "prev_hash": prev_hash,
        "content_hash": _block_content_hash(content),
        "content": content,
    }


def _sort_time(value) -> "int | float":
    return value if isinstance(value, (int, float)) else 0


def _event_handle(ev: dict) -> str | None:
    """The joinable handle for a normalized event: event_id, else
    siem.ingest_id, else None. Provenance joins alert.event_ids on this."""
    ev_id = ev.get("event_id")
    if ev_id is not None and ev_id != "":
        return str(ev_id)
    siem = ev.get("siem")
    if isinstance(siem, dict) and siem.get("ingest_id") not in (None, ""):
        return str(siem["ingest_id"])
    return None


def _dedupe_events(events: list) -> list:
    """Keep the first occurrence of each event (keyed by handle, else by
    canonical content), then order chronologically for the story order."""
    seen, out = set(), []
    for ev in events:
        handle = _event_handle(ev)
        key = handle if handle is not None else "content:" + _canonical_json(ev)
        if key not in seen:
            seen.add(key)
            out.append(ev)
    out.sort(key=lambda ev: (_sort_time(ev.get("time")), _event_handle(ev) or ""))
    return out


def _raw_fragment(ev: dict):
    """The raw payload fragment when the normalized event carried one
    (siem.raw, else raw); None when it did not. The chain reaches the raw
    event handle either way via event_id / siem.ingest_id."""
    siem = ev.get("siem")
    if isinstance(siem, dict) and siem.get("raw") is not None:
        return siem["raw"]
    return ev.get("raw")


def _build_provenance(alerts_sorted: list, blocks: list) -> list:
    """alert -> its event_ids -> the packaged event block + raw fragment.
    Every event maps by BOTH event_id and siem.ingest_id so the join works
    whichever handle the alert references. Unresolvable ids are listed
    honestly under unresolved_event_ids rather than dropped."""
    by_handle = {}
    for blk in blocks:
        if blk.get("type") != "event":
            continue
        content = blk.get("content") or {}
        handle = _event_handle(content)
        siem_value = content.get("siem")
        siem: dict = siem_value if isinstance(siem_value, dict) else {}
        for key in (handle, content.get("event_id"), siem.get("ingest_id")):
            if key is not None:
                by_handle[str(key)] = blk
    entries = []
    for alert in alerts_sorted:
        alert_id = alert.get("alert_id")
        event_ids = [str(e) for e in (alert.get("event_ids") or [])]
        resolved, unresolved = [], []
        for event_id in event_ids:
            blk = by_handle.get(event_id)
            if blk is None:
                unresolved.append(event_id)
                continue
            ev = blk.get("content") or {}
            resolved.append({
                "event_handle": _event_handle(ev),
                "block_id": blk.get("block_id"),
                "time": ev.get("time"),
                "class_uid": ev.get("class_uid"),
                "raw_fragment": _raw_fragment(ev),
            })
        entries.append({
            "alert_id": alert_id,
            "block_id": f"alert:{alert_id}",
            "event_ids": event_ids,
            "resolved": resolved,
            "unresolved_event_ids": unresolved,
        })
    return entries


def build_evidence_package(incident: dict, alerts: list, events: list, graph,
                           *, now_ms: int, package_id_prefix: str) -> dict:
    """Build an immutable, hash-chained evidence package for an incident.

    `incident` is an incidents-topic document (incident_id, tenant_id,
    entity_type, entity_value, first_seen, last_seen, tactics,
    member_alert_ids, member_count, severity, truncated). `alerts` are the
    member alert docs (alert_id, time, rule_id, level, score, mitre,
    src_endpoint, actor, event_ids), `events` the underlying normalized OCSF
    events (event_id / siem.ingest_id, time, class_uid, ...). `graph` is the
    incident.graph payload (v1 or v2) or None — treated as an opaque evidence
    block; None means no graph block. `now_ms` is injected (never read from
    the clock) so the same inputs plus the same now_ms produce a
    byte-identical package. `package_id_prefix` names the producer's
    namespace; the resulting package_id is deterministic per incident content
    and rebuild-stable (see module docstring).

    Block layout: incident (genesis) -> alerts (chronological) -> events
    (chronological) -> optional graph. The primary alert, used by
    to_reporting_payload, is the chronological first member alert.
    """
    if not isinstance(incident, dict) or not incident.get("incident_id"):
        raise ValueError("incident must be an incidents-topic doc with an incident_id")
    incident_id = str(incident["incident_id"])
    alerts_sorted = sorted(alerts, key=lambda a: (_sort_time(a.get("time")), str(a.get("alert_id", ""))))
    blocks = [_make_block("incident", "incident", 0, copy.deepcopy(incident), ZERO_HASH)]
    for alert in alerts_sorted:
        blocks.append(_make_block("alert", f"alert:{alert.get('alert_id')}", len(blocks),
                                  copy.deepcopy(alert), _header_hash(blocks[-1])))
    for event in _dedupe_events(events):
        handle = _event_handle(event)
        block_id = f"event:{handle}" if handle is not None else f"event:#{len(blocks)}"
        blocks.append(_make_block("event", block_id, len(blocks),
                                  copy.deepcopy(event), _header_hash(blocks[-1])))
    if graph is not None:
        blocks.append(_make_block("graph", "graph", len(blocks),
                                  copy.deepcopy(graph), _header_hash(blocks[-1])))

    digest = _package_digest(blocks)
    return {
        "schema": SCHEMA,
        "package_id": f"{package_id_prefix}:{incident_id}:{digest}",
        "incident_id": incident_id,
        "tenant_id": incident.get("tenant_id"),
        "built_at_ms": now_ms,
        "primary_alert_id": alerts_sorted[0]["alert_id"] if alerts_sorted else None,
        "blocks": blocks,
        "chain": {"block_count": len(blocks), "head_hash": _header_hash(blocks[-1])},
        "provenance": _build_provenance(alerts_sorted, blocks),
    }


def verify_evidence_package(pkg: dict) -> list[str]:
    """Return a list of failure strings; an empty list means the package is
    valid. Recomputes every block's content hash, walks every prev_hash link,
    checks the chain head and block count, re-derives the package_id digest,
    and validates the envelope (schema, block order/indices, unique ids,
    incident identity). Mutating any block's content, reordering blocks,
    swapping the incident, or altering the hash chain yields at least one
    failure that names the offending block. Never raises on malformed input —
    it returns failure strings instead."""
    failures: list[str] = []
    _verify_envelope(pkg, failures)
    _verify_chain(pkg, failures)
    return failures


def _verify_envelope(pkg: dict, failures: list[str]) -> None:
    if not isinstance(pkg, dict):
        failures.append(f"package must be a dict, got {type(pkg).__name__}")
        return
    for key in ("schema", "package_id", "incident_id", "built_at_ms", "blocks", "chain", "provenance"):
        if key not in pkg:
            failures.append(f"package missing required key {key!r}")
    if pkg.get("schema") != SCHEMA:
        failures.append(f"package schema must be {SCHEMA!r}, got {pkg.get('schema')!r}")
    blocks = pkg.get("blocks")
    if not isinstance(blocks, list):
        if "blocks" in pkg:
            failures.append(f"package blocks must be a list, got {type(blocks).__name__}")
        return
    if not blocks:
        failures.append("package has no blocks (an incident block is mandatory)")
        return
    for position, blk in enumerate(blocks):
        if not isinstance(blk, dict):
            failures.append(f"blocks[{position}] must be a dict, got {type(blk).__name__}")
            continue
        if blk.get("type") not in _BLOCK_TYPES:
            failures.append(f"block {blk.get('block_id')!r} has unknown type {blk.get('type')!r}")
        if blk.get("index") != position:
            failures.append(f"block {blk.get('block_id')!r} index {blk.get('index')} != chain position {position}")
    if isinstance(blocks[0], dict):
        if blocks[0].get("type") != "incident":
            failures.append("first block must be the incident block")
        content0 = blocks[0].get("content")
        if not isinstance(content0, dict):
            failures.append("incident block content must be a dict")
        elif content0.get("incident_id") != pkg.get("incident_id"):
            failures.append(f"incident block content.incident_id {content0.get('incident_id')!r} "
                            f"!= package incident_id {pkg.get('incident_id')!r}")
    ids = []
    for b in blocks:
        if isinstance(b, dict) and isinstance(b.get("block_id"), str):
            ids.append(b["block_id"])
    # Counter, not `ids.count(x)` inside a loop (O(n) instead of O(n^2) in
    # block count, and each duplicated id is named ONCE instead of once per
    # occurrence).
    dups = sorted(x for x, n in Counter(ids).items() if n > 1)
    if dups:
        failures.append(f"block_ids not unique: {dups}")
    chain = pkg.get("chain")
    if not isinstance(chain, dict):
        failures.append("package chain must be a dict")
        return
    head_hash = chain.get("head_hash")
    if not isinstance(head_hash, str) or len(head_hash) != 64:
        failures.append("chain.head_hash must be a 64-char sha256 hex digest")


def _verify_chain(pkg: dict, failures: list[str]) -> None:
    """The hash-chain verification: recompute every content hash, walk every
    prev_hash link up to the head, and re-derive the package_id digest. This
    is the single function the mutation-soundness test removes; deleting it
    must make content tampering invisible."""
    blocks = pkg.get("blocks")
    if not isinstance(blocks, list) or not blocks:
        return
    prev = ZERO_HASH
    for blk in blocks:
        if not isinstance(blk, dict):
            continue
        block_id = blk.get("block_id")
        if blk.get("content_hash") != _block_content_hash(blk.get("content")):
            failures.append(f"block {block_id!r} ({blk.get('type')}) content_hash mismatch: "
                            "tampered content")
        if blk.get("prev_hash") != prev:
            failures.append(f"block {block_id!r} prev_hash does not link to the previous "
                            "block (reordered or hash chain altered)")
        prev = _header_hash(blk)
    chain = pkg.get("chain")
    if isinstance(chain, dict):
        if chain.get("block_count") != len(blocks):
            failures.append(f"chain.block_count {chain.get('block_count')} != {len(blocks)} blocks")
        if chain.get("head_hash") != prev:
            failures.append("chain.head_hash does not match the recomputed chain root "
                            "(hash chain altered)")
    digest = _package_digest(blocks)
    pid = str(pkg.get("package_id", ""))
    if not pid.endswith(":" + digest):
        failures.append(f"package_id {pid!r} does not end with the recomputed content digest "
                        "(package altered)")
    else:
        incident_id = pkg.get("incident_id")
        if incident_id is not None and not pid[: -(len(digest) + 1)].endswith(str(incident_id)):
            failures.append(f"package_id {pid!r} does not name packaged incident {incident_id!r}")


def to_reporting_payload(pkg: dict) -> dict:
    """Map a built evidence package onto contracts/reporting.md's REQUEST
    payload (keys: alert, triage, events, requested_at) so the reporting seam
    can consume the package directly.

    NOTE: the package is the provenance-linked source that multiple views
    render from — analyst timeline, incident report, regulatory draft,
    customer communication, management summary, postmortem; no view is built
    here, this function only produces the reporting request.

    Mapping rules:
      - 'alert' is the package's primary member alert (chronological first,
        pkg['primary_alert_id']) full document as packaged — the reporting
        seam is alert-scoped (POST /alerts/{alert_id}/report).
      - 'events' is that alert's contributing normalized events, resolved
        from the package's event blocks via the provenance join
        (alert.event_ids -> event_id / siem.ingest_id), in chain order. This
        fills contracts/reporting.md's explicitly open follow-up ("events is
        currently always []") from an immutable, hash-verified artifact.
      - 'triage' is reporting.py's default open-pipeline triage state (the
        package carries no triage doc).
      - 'requested_at' is the package's build time in seconds (float).

    Call verify_evidence_package(pkg) first; this function does not
    re-verify. Fail-open: an empty alert dict if the package has no alerts.
    """
    blocks = pkg.get("blocks") or []
    target_id = pkg.get("primary_alert_id")
    alert: dict = {}
    for blk in blocks:
        if isinstance(blk, dict) and blk.get("type") == "alert":
            content = blk.get("content") or {}
            if target_id is None or content.get("alert_id") == target_id:
                alert = dict(content)
                break
    wanted = {str(e) for e in (alert.get("event_ids") or [])}
    events = []
    for blk in blocks:
        if not isinstance(blk, dict) or blk.get("type") != "event":
            continue
        ev = blk.get("content") or {}
        siem_value = ev.get("siem")
        siem: dict = siem_value if isinstance(siem_value, dict) else {}
        ev_id = ev.get("event_id")
        ingest_id = siem.get("ingest_id")
        if (ev_id is not None and str(ev_id) in wanted) \
                or (ingest_id is not None and str(ingest_id) in wanted):
            events.append(dict(ev))
    triage = {"status": "new", "note": "", "updated_at": None}
    return {
        "alert": alert,
        "triage": triage,
        "events": events,
        "requested_at": float(pkg.get("built_at_ms", 0)) / 1000.0,
    }