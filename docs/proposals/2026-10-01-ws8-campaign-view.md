# Proposal: a campaign view over WS-8 incidents

**Status:** read-side function shipped; persisting / emitting / indexing it is **awaiting an owner decision**.
**Date:** 2026-10-01 · **Touches:** `services/ws8-correlation/campaigns.py` (new, pure), the evaluation harness. **Does not touch:** promotion logic, incident ids, the `incidents` / `incident.graph` topics, any index mapping.

## The problem, measured

WS-8 promotes one incident per entity track (actor / ip / device) and, by ratified design (ADR-009, ADR-010), never merges tracks: no compound key, no transitive join across a shared entity. That is the right default. It is what stops a shared NAT address from pulling unrelated people into a false incident.

The cost showed up the first time the harness ran an attack that *pivots*. `it_intrusion` (scan → SSH brute force → login → lateral movement → privilege grant → DNS exfil) is carried by three entities that overlap pairwise: the attacker's address, the stolen account, the internal foothold address. No single entity spans it, so WS-8 reports it as several incidents (3 promoted at seed 7), and the oracle's "one campaign = one incident" expectation fails (`incident_membership_ok=False`). `ai_to_ot` is reported as 2 incidents for the same reason (an `actor:` and an `ip:` track).

## What was built (safe, read-side)

`link_campaigns(incidents)` groups incidents that **share at least one member alert**.

Why shared *alert*, not shared *entity*: one alert carries its own actor, source address and device together. An alert that sits in both the `actor:deploy` track and the `ip:10.50.0.46` track *is* the observation "deploy was seen at 10.50.0.46" — a single-event fact, the same standard the `incident.graph` edges already hold themselves to ("a typed kind is a label on a single-alert-evidenced edge, NEVER a transitive join"). Two unrelated users behind one NAT share the NAT's `ip:` track but **no alert**, so they do not link. That case is a unit test (`test_campaigns.py`), and the harness has a control showing a decoy that genuinely shares the attacker's address *is* absorbed, so the check can go red.

Measured on the three storylines (seed 7):

| storyline | incidents (as emitted) | campaigns (shared-alert view) | one campaign covers the whole attack |
|---|---|---|---|
| `ai_to_ot` | 2 | 1 | yes |
| `it_intrusion` | 3 | 1 | **yes** (per-incident membership fails) |
| `infra_takeover` | 1 | 1 | yes |

Benign decoys on disjoint entities stay out of the campaign (contamination 0.0 on both decoy-bearing storylines).

## Decision needed from the owner

Nothing above changes what WS-8 emits. To make the campaign visible to an analyst it has to be *carried* somewhere, and each option is a contract change:

1. **Compute on read** in WS-3's incident API (`GET /incidents`, `/incidents/{id}`): `related_incident_ids` / `campaign_id` derived at query time from the stored incidents. No schema change if returned as a computed field; no index mapping change. *Recommended first step.*
2. **Persist `campaign_id` on the incident document.** Requires an `incidents.json` mapping bump (the index is `dynamic: false`, so an unmapped field is stored but not searchable) and a decision on id stability, because a campaign's membership grows and its id would change.
3. **Emit a `campaigns` topic.** New bus contract (`contracts/bus-topics.md` is frozen); only worth it if a second consumer needs it.

## Risks to weigh

- **Transitive chains.** Linking is transitive across a chain of shared alerts, which is the point (a pivot *is* a chain), but a long chain through a busy shared host could in principle grow a campaign larger than the real attack. Mitigation already in the code: tenant-scoped, linear (inverted-index) cost, input bounded; and the existing `shared_infrastructure` allowlist already keeps allowlisted addresses from opening `ip:` tracks at all, so they cannot be the bridge.
- **Display, not detection.** A campaign must not change severity, scoring or triage routing unless that is decided separately; ADR-005 (deterministic controls decide, LLMs explain) is unaffected.
- **No claim of causality.** "Same campaign" means "linked by shared direct evidence", not "A caused B". The harness's `directional_discrimination` finding (the WS-8 graph cannot encode causal order) stands and is a separate question.
