# ADR 010: incident.graph v2 — typed causal DAG (Phase 3, WP-3-A)

**Status:** Accepted (owner-ratified 2026-09-02 via clarify — the roadmap §5.2
sign-off gate for bus message-schema changes was explicitly triggered and
granted; he chose "v2 supersedes v1 on incident.graph, version field
distinguishes"). **Date:** 2026-09-02. **Supersedes the payload half of
ADR-009's Topic B note** — see ADR-009 (whose Topic A and WS-9 service parts are
unchanged) for the entity-plane contract this upgrades.

## Context

ADR-009 (2026-08-28) introduced `incident.graph` at **version 1**: three
field-pair edge kinds (`used_ip`, `used_device`, `seen_at_ip`), nodes as the
incident's track refs (`actor:alice`, `ip:10.0.0.5`), per-edge `event_id` +
`ts_ms` provenance, and the **no-transitive-inference** rule. It explicitly
declared Phase 3's `version: 2` typed-causal-DAG upgrade to be the seam that
carries the canonical form — "(The WP-2-B canonical sha256 `entity_id` is NOT
recomputed here ... Phase 3's `version: 2` typed-DAG upgrade is the seam that
carries the canonical form.")" and the roadmap §5.2 standing guardrail:
*"Ask the founder before: ... bus message-schema changes ... explicit sign-off,
not an implicit yes."*

An analyst looking at a version-1 graph sees *that* an actor touched an IP and
a device, but not *what* each relationship was — whether the actor authenticated
as something, invoked a tool, wrote to a device, or a change was caused by a
prior action. Phase 3 (WP-3-A) names those relationships, not to infer beyond
the evidence (the no-transitive rule is unchanged and this ADR keeps it), but
to label each single-alert-evidenced edge with the semantic kind the evidencing
alert itself supports.

## Decision

`incident.graph` gains a **version 2** payload. Per the owner's ratification:

1. **v2 supersedes v1 as the emitted payload** — WS-8 (and any future
   producer) emits the v2 shape; consumers distinguish by the `version` field
   (integer 2). The v1 builder stays in code byte-for-byte as the compatibility
   reference and is covered by the existing v1 tests.
2. **Typed edge kinds** — alongside v1's `used_ip` / `used_device` /
   `seen_at_ip`, edges may carry one of: `caused_by`, `invoked`,
   `authenticated_as`, `wrote_to`, `changed`. A typed kind is a **label on a
   single-alert-evidenced edge**, derived deterministically from the evidencing
   alert's own fields (documented per-kind in the ws8 INTERFACE.md); when an
   alert carries no signal for a typed kind, the edge keeps its v1 field-pair
   kind. It is **never** a license to join two alerts that merely share an
   entity (no transitive inference, unchanged).
3. **Canonical node identity** — nodes are the WS-9 canonical sha256
   `entity_id` digests (`sha256(tenant|entity_type|canonical_value)`), with the
   human-readable `entity_type` / `entity_value` preserved on the node (the
   incident's own track spelling) and a `label` carrying the v1-style track
   ref, so the graph is machine-canonical AND analyst-readable. WS-8 mirrors
   WS-9's canonicalization (shared.ip_utils.valid_ip for ip, case-folded actor,
   lowercased device) via a module helper; it does not import ws9. An
   identifier-agreement test pins that ws8's digest equals ws9's for the same
   identity.
4. **Boundedness, idempotency, provenance** — unchanged from v1: bounded by the
   live member set, cached one-entry-per-incident and pruned with the incident
   by the same dead-track sweep, deterministic under redelivery (same incident
   promoted twice → byte-identical v2 payload), every edge carries `event_id` +
   `ts_ms`.
5. **`incidents` payload is byte-for-byte untouched**; the tactic-accumulation
   path is untouched (same additive discipline as ADR-009).

## Consequences

- **Additive/self-describing**: the `version` field already present since v1
  makes v2 a bump consumers can branch on. v1 payloads are no longer *emitted*,
  but the v1 builder + tests remain as the byte-compat reference.
- **Graph = canonical identities**: consumers can now join graph nodes to
  `entity.updates` by `entity_id` without re-deriving the hash — the Phase 2
  gap ADR-009 left open ("the entity plane maps each node to its canonical
  `entity_id` on consumption") is closed at emission.
- **Phase 3-C depends on this**: the twin's `chain_fidelity` metric (frozen
  baseline `null` → real number) grades against the v2 graph.
- **No transitive inference remains the immutable rule.** A typed kind is a
  richer label, never a join license.

## Status

Accepted 2026-09-02 (owner ratification, roadmap §5.2 gate). Implemented
alongside WP-3-B/C/D/E (evidence package, twin chain-fidelity grading, ws5
executor, ot-points business_context).
