# WS-9 Entity Resolver — Interface Declaration

**Status (2026-08-28): zero-infra proven (WP-2-B).** Implements the entity
resolution workstream of `docs/adr/009-entity-plane-bus-topics.md` (ratified)
and the `entity.updates` topic amendment in `contracts/bus-topics.md`. Adds
the first persistent *entity identity* the pipeline had: a deterministic
`entity_id` per (tenant, entity_type, canonical_value), idempotent under
at-least-once redelivery.

## Purpose

The detection pipeline ends at incidents — WS-8 promotes a per-entity track
(`actor:{name}`/`ip:{addr}`/`device:{mac}`) once its live members carry ≥2
distinct MITRE tactics. What an analyst could not previously ask was *"what
else did this actor touch?"*: there was no persistent entity identity. WS-9 is
the resolver half of that question — it owns **who is who**: a deterministic,
fully-decomposable identity (`entity_id`, `entity_type`, `tenant_id`,
`entity_value`) plus first/last-seen per entity, emitted as `entity.updates`.

**SAFETY: WS-9 is a resolver/analyzer, not a control path.** It never
decides or issues an action — it cannot block, drop, suppress, quarantine, or
modify any alert/event/incident, and holds no authority over any other
workstream. Its only output is resolved entity state; every control decision
stays with WS-4 / WS-8 / the analyst (see `main.py` module docstring).

## Consumes

- Topic `alerts`, group `cg-entity` — the same enriched-alert payload WS-3
  (`cg-index`) and WS-8 (`cg-correlate`) already consume, as a **third,
  independent** consumer group on the same topic. Redis Streams consumer
  groups fan out independently, so WS-9 cannot block or slow the indexer or
  the correlator, and WS-9 never imports WS-3/WS-4 (bus-only coupling,
  ADR 004).
- Topic `entity.updates`, group `cg-entity-self` — merges our own redelivered
  emissions under the ADR no-op upsert (a non-newer `last_seen_ms` changes
  nothing). **Not yet a WS-6 producer**: WS-6's inventory worker does not
  currently write `entity.updates` (it is a `raw.events` producer only); the
  `assets.updates`→`entity.updates` bridge is a planned follow-up, NOT built
  (see "Deliberately not built"). The `cg-entity-self` group exists so that
  bridge (and any replay) is already wired when it lands.
- Contracts: B (bus); the alert shape WS-4/WS-5 produce; ADR-009.

**Source-topic choice — `alerts`, not `normalized.events` or `incidents`:**
`normalized.events` is every benign event (full pipeline volume of non-security
noise); `incidents` is WS-8's already-aggregated, promoted view (too late,
entities already joined into tracks). `alerts` is the first bus message
carrying exactly the enriched, correlated entity fields the plane needs
(actor / src+dst / device) at the volume the "what else did this actor touch?"
question actually targets, and it sits beside WS-8's `cg-correlate` on the
same topic under the repo's bus-only coupling model.

## Produces

- Topic `entity.updates`, partition key `entity_id`, payload exactly per
  ADR-009 / contracts/bus-topics.md:

  | Field | Meaning |
  |---|---|
  | `entity_id` | `sha256("{tenant}\|{entity_type}\|{canonical_value}")` hexdigest (64 chars). Deterministic, idempotent under redelivery — same discipline as WS-4 `Rule.alert_key()` (engine.py:585-647). |
  | `entity_type` | `actor` \| `ip` \| `device` — mirrors WS-8's three track kinds exactly (correlator.py:579/591/610), so a later `incident.graph` node is the SAME identity space WS-8 promotes. As of WP-3-A (2026-09-02, `incident.graph` v2) the graph's nodes ARE WS-9's canonical `entity_id` digests (`sha256(tenant|type|canonical_value)`), with `entity_type`/`entity_value` preserved on the node — see `docs/adr/010-incident-graph-v2-typed-causal-dag.md`. |
  | `tenant_id` | validated at the edge, `"default"` fallback; invalid → `InvalidTenant` raised (reject, never normalize — WS-8/WS-6 discipline). |
  | `entity_value` | the **canonical** value (see normalization below), not the raw alert value. |
  | `first_seen_ms` / `last_seen_ms` | min / max over all evidence ever seen on this still-live entity; never regress. An upsert with the same `entity_id` + non-newer `last_seen_ms` is a no-op (ADR-009 line 53-54). |
  | `attributes` | stable aggregates: `member_count` (bounded dedup'd alert set), `truncated` (cap ever evicted), `mitre_tactics`, `first_alert_id`/`last_alert_id` (provenance edges). |

## Entity extraction (mirrors WS-8 `correlator.py:564-612`)

One alert can resolve up to **four** entities, in this order:

1. `actor` — `actor.user.name` (`correlator.py:569-573`; a malformed
   plain-string `user` degrades to no actor, never crashes).
2. `ip` — `src_endpoint.ip` (`correlator.py:574-575`).
3. `ip` — `dst_endpoint.ip` (**additive over WS-8**: WS-8 tracks src-only;
   WS-9 resolves the destination side too, so an endpoint's identity is the
   same whichever side of an alert it appears on).
4. `device` — `src_endpoint.mac` falling back to `.hostname`
   (`correlator.py:576`).

An alert naming no resolvable entity is an **observable no-op**, recorded in
`metrics()` under `ws9_skipped_alerts_by_reason` (`unresolvable_value` for a
field of the right kind that fails canonicalization, e.g. a non-IP in
`src_endpoint.ip`) — never silent (mirror of WS-8's skip reasons,
`correlator.py:614-626`).

## Canonicalization (the ADR edge normalization — `entity_id.py`)

`canonical_value` is normalized at the edge per ADR-009 lines 49-52, so two
spellings of one real-world identity hash to ONE `entity_id`:

| type | rule | source |
|---|---|---|
| `ip` | `shared.ocsf.valid_ip` — collapses `::ffff:a.b.c.d` → `a.b.c.d`, rejects non-IPs → `None` (skipped) | shared/ocsf.py:54-84; identical to the parsers' edge (`parsers/cef.py:98-106`, `cloudtrail.py:96-98`) and therefore identical to what WS-8 keys on raw (`correlator.py:574`) |
| `device` | lowercased (`str.lower`) — MACs per ADR's "MACs lowercased"; the `hostname` fallback too (case-insensitive identifier, RFC 1035) | ADR-009:50-51 |
| `actor` | case-folded (`str.casefold`) — `Alice` / `ALICE` / `alice` are one identity | ADR-009:51-52 |

Note the one deliberate textual divergence from WS-8: WS-8 stores actor/device
**raw** into its track keys today (`correlator.py:581/610` and line 573) and
relies on the parsers to have `valid_ip`'d IPs. WS-9 applies the ADR's
canonicalization at its own edge for all three kinds, so an identity seen in
raw form by WS-8 (e.g. an un-normalized `::ffff:` mapped IPv6, or a
mixed-case username) may key a different WS-8 track than the WS-9 canonical
`entity_id` — the two identifier spaces are related but not byte-identical
off the parser happy path. WS-9 additionally lowercases IPv6 (case-insensitive
addresses must be one identity) and strips actor/device whitespace. WS-8
tightening its own edge to the same canonical forms later is purely additive
(it could only ever SHRINK its track set, never conflict with a WS-9 id).

## Idempotency under redelivery (ADR-009 lines 47-54)

- `entity_id` is a pure function of the preimage — redelivery re-derives the
  same id (never a fresh uuid).
- Member accounting dedups on alert identity (`_member_id`, mirroring WS-8
  `correlator.py:295-345`), so replaying the same alert never inflates
  `member_count`, never moves `first_seen_ms`/`last_seen_ms`, and re-emitting
  is a strict no-op (`apply_update` returns False). Tested: replay the same
  alert twice → exactly one logical entity state per id (test (d)/(e)).
- `member_cap` (env `ENTITY_MEMBER_CAP`, default 200) bounds the per-entity
  live member set; stable aggregates survive eviction (mirror of WS-8's
  `member_cap`/`_side_meta`, `correlator.py:461-471`).

## Time discipline

Alert `time` is attacker-controlled, so it is run through the same
skew-future/NaN guard WS-4 (`engine.py::_MAX_CLOCK_SKEW_MS`) and WS-8
(`correlator.py:143-161`) apply: a non-numeric or >5-min-future timestamp is
rejected. **A rejected (time-less) alert is anchored on a DETERMINISTIC digest
of its member id, not wall-clock** — so redelivering a time-less alert
re-derives the same anchors and last_seen_ms never moves (the wall-clock
fallback made replay non-identical). Past timestamps always pass — that is
replay.

## Boundedness (attacker-controlled keys)

- `member_cap` bounds each entity's live member set (see Idempotency).
- The **entity table itself is bounded** by `horizon_s` (default 86400s = 24h),
  exactly like WS-8's `_sweep_dead_tracks`: an entity not touched for a full
  horizon is swept (a full scan every 256 sightings). A distinct-attacker-id
  spray thus cannot grow the entity count without limit.
- `entity_value` is bounded to 448 bytes (truncate + stable sha256 suffix,
  mirroring WS-8) so a crafted username/hostname cannot be an unbounded
  memory/doc-id vector; distinct long values keep distinct ids.
- `resolved_updates` counts genuine state changes: a member re-added after cap
  eviction (redelivery) is not double-counted (a bounded evicted-member LRU
  carries the memory).

## Environment

- `PORT` (default `8009`) — health/metrics listener port (`shared.runner.serve`).
- `BUS_BACKEND` (default `memory` for tests, `redis` in the Docker profile).
- `ENTITY_MEMBER_CAP` (default `200`).
- `ENTITY_HORIZON_S` (default `86400`) — entity-table sweep horizon.
- `TENANT_ID` — via `shared.envelope.default_tenant`; the resolver reads
  `tenant_id` off each alert (fallback `"default"`), the same field every
  other service stamps.

## Contract tests

- `python test_contract.py` — standalone (no pytest), run from inside
  `services/ws9-resolver`. Covers the WS-9 acceptance contract:
  (a) deterministic id; (b) distinct tenant/type/value ⇒ distinct id;
  (c) canonicalization (IP variants incl. mapped-IPv6, MAC casing, username
  casing ⇒ same id; invalid IP ⇒ None/skip); (d) replay idempotency (same
  alert twice ⇒ one logical entity state, same id, no last_seen regression);
  (e) redelivery-safe — incl. a live memory-bus round trip that produces one
  alert, drives it through the real `main.py` handler wiring (`cg-entity`),
  and asserts the deterministic-`entity_id` `entity.updates` payloads appear.

## Deliberately not built (this pass)

- `incident.graph` (ADR-009 Topic B) — that is WP-2-C (relationship edges /
  provenance); WS-9 is the resolver half only.
- `assets.updates`→`entity.updates` bridging for WS-6 — a **planned follow-up,
  not built**. WS-6's inventory worker is a `raw.events` producer today; it
  does NOT write `entity.updates`. The `cg-entity-self` consumer is already
  wired so the bridge (and any replay) needs no new plumbing when it lands.
- Shared-infrastructure allowlist suppression (WS-8's `ip:`/`device:` skip):
  the WS-8 allowlist prevents false incident *correlation* through NAT/proxy
  chokepoints. WS-9's job is identity resolution of everything an analyst may
  pivot on; suppressing an entity would hide legitimate state, and ADR-009 does
  not ask for it. Documented divergence.

## Run locally

- `python main.py` (memory bus unless `BUS_BACKEND=redis`).
- `python test_contract.py` — zero-infra contract gate.
- `python demo_round_trip.py` — prints the emitted `entity.updates` payloads
  for one alert (live memory-bus round trip).
