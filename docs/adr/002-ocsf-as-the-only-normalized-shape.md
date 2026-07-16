# ADR 002: OCSF as the only normalized event shape

**Status:** Accepted, live. **Date:** v0.1 (2026-06); backfilled 2026-07-16.

## Context

A SIEM's detection rules need to reason about events from many sources (SSH,
firewalls, Active Directory, industrial control systems, AI-agent tool calls)
without each rule knowing which parser produced the event. Most self-hosted
SIEMs retrofit a common schema onto whatever their parsers already emit — a
per-vendor field name here, an ECS-flavored mapping there — so the
"normalized" shape ends up being the least-common-denominator of whichever
sources existed when the schema was bolted on, and drifts further with every
new parser.

## Decision

[OCSF](https://schema.ocsf.io/) (Open Cybersecurity Schema Framework) is the
**only** shape a normalized event is allowed to have, enforced from the very
first parser, not retrofitted. Every parser (`services/ws2-normalization/parsers/`)
turns its source-specific input into the same `class_uid`/`activity_id`/
`type_uid` structure. Two invariants are structurally enforced, not just
documented:

- `type_uid` is **derived**, never hand-set (`make_type_uid()` in
  `services/shared/ocsf.py`, called from the one shared `base_event()`
  helper every parser uses) — a copy-paste bug can't silently produce an
  inconsistent id.
- Every emitted event is validated in CI against a frozen JSON schema
  (`contracts/ocsf-event.schema.json`, `tools/validate_contract.py`) — an
  event that doesn't validate is dead-lettered, not silently indexed.

A `siem.*` namespace (`sector`, `source_type`, `ingest_id`, and as of Envelope
v1: `tenant`, `trace_id`) carries FENGARDE-specific routing metadata
additively, without colliding with OCSF's own fields — see
`contracts/bus-topics.md`'s "Envelope v1" section.

## Consequences

- **Positive (the actual payoff):** a detection rule written against OCSF's
  Authentication class (3002) fires identically whether the failed login came
  from `sshd`, Active Directory, or an OPC UA engineering session — the rule
  doesn't know or care which parser produced the event. Add a tenth parser and
  every existing authentication rule already covers it, with zero rule
  changes. This is why the anti-dormancy guardrail
  (`tools/check_rule_producers.py`) is checking *producer coverage*, not rule
  logic — the schema-first design already solved rule reuse.
- **Cost:** discipline. Every new parser must map into OCSF's class/activity
  taxonomy even when a source's native shape doesn't map cleanly (documented
  per-parser, e.g. the OPC UA parser's class-mapping rationale in
  `opcua_audit.py`'s docstring) — occasionally a judgment call, always
  written down, never silently approximated.
- **Cost, caught and fixed three times in this repo's history:** a rule can
  reference a field or class no parser actually emits (a *dormant* rule).
  The anti-dormancy CI gate exists specifically because schema-first design
  makes this failure mode possible (rules and parsers are decoupled by the
  same OCSF contract that makes reuse work) — the fix for the risk the
  decision introduces is itself now permanent CI infrastructure.
- See `docs/posts/ocsf-native.md` for the full public-facing rationale this
  ADR summarizes.
