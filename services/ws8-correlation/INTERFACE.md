# WS-8 Correlation — Interface Declaration

**Status (2026-08-19): zero-infra proven, one live smoke test (2026-08-18) +
pivot-correlation (device: track) added 2026-08-19, zero-infra proven.
2026-08-28: incident.graph (ADR-009/WP-2-C) added, zero-infra proven.**
Implements `docs/superpowers/specs/2026-08-18-ws8-correlation-build-plan.md`
and the approved design in `fengarde-sec`'s
`docs/2026-08-11-cross-alert-correlation-design.md` (private repo — read
that first for the full rationale; this file only states the shipped
interface).

## Purpose

Closes the gap named in the 2026-07-29 architecture review (Design-C,
`SSOT.md` §2): every detection rule evaluates independently against its own
short window, so a low-and-slow attacker who paces each technique under its
own rule's threshold produces N isolated alerts, never one aggregated
incident. WS-8 is a second, independent consumer of the `alerts` topic that
tracks per-entity activity over a much longer horizon and promotes a track
to an "incident" once it shows real multi-stage behavior (>=2 distinct
MITRE tactics), not just repeated single-tactic noise.

## Consumes

- Topic `alerts` (group `cg-correlate`) — the exact same enriched-alert
  payload WS-3 already indexes (`services/ws4-detection/main.py::make_alert`
  shape: `alert_id, time, rule_id, level, score, mitre, tenant_id,
  src_endpoint, actor, event_ids`). A **second, independent** consumer
  group on the same topic WS-3's `cg-index` already reads — Redis Streams
  consumer groups fan out independently, so WS-8 falling behind or dying
  cannot block or slow WS-3's indexing path, and WS-8 never imports WS-3 or
  WS-4 (bus-only coupling, ADR 004).
- Contracts: B (bus), the alert shape WS-4 already produces.

## Produces

- Topic `incidents` — one document per promoted entity track:
  `incident_id, tenant_id, entity_type, entity_value, first_seen, last_seen,
  tactics[], member_alert_ids[], member_count, severity, truncated`. When an
  attacker-controlled entity_value was too long for the OpenSearch doc-id
  budget it is stored bounded (`entity_value`, 448-byte UTF-8 cap, stable
  sha256 suffix so two long values never false-merge) with the full original
  preserved in the additive `entity_value_full` field (2026-08-26).
  `incident_id` is deterministic
  (`{tenant}:{entity_type}:{entity_value}:{horizon_bucket}`), mirroring
  `Rule.alert_key()`'s fixed-epoch-bucket discipline (T7) — WS-8 re-emits a
  growing incident under the SAME id so WS-3's existing OCC/CAS path updates
  one document instead of accumulating duplicates under at-least-once
  redelivery.
- Topic `incident.graph` (ADR-009, WP-2-C, 2026-08-28) — emitted alongside
  EVERY `incidents` promotion/update via
  `correlator.incident_graph(incident["incident_id"])` (the produce source;
  partition key `incident_id`, same as `incidents`). Purely ADDITIVE: the
  `incidents` payload above is unchanged. See "Incident graph" below for the
  full contract.

## Incident graph (ADR-009, WP-2-C, 2026-08-28)

Every incident promotion/update ALSO produces an `incident.graph` payload:

`{version: 1, incident_id, tenant_id, nodes: [type:value…], edges: [{from, to,
kind, event_id, ts_ms}], tactic_sources}`

- **Nodes** are the incident's member entities — the actor/user, ip, and
  device values its member alerts reference — identified by the SAME track
  identity the incident already captures, `{entity_type}:{entity_value}`
  (e.g. `actor:alice`, `ip:10.0.0.5`, `device:AA:BB:CC:DD:EE:FF`). Values
  pass through the same 448-byte `_bounded_entity_value` doc-id cap as the
  incident's own `entity_value`. The WP-2-B canonical sha256 `entity_id`
  (WS-9 resolver's computation) is NOT recomputed here — WS-8 emits its own
  proven track identity, and Phase 3's `version: 2` typed-DAG upgrade is the
  seam that carries the canonical form.
- **Edges** are ONLY relationships a SINGLE alert's own fields provide —
  never inferred across alerts. Version-1 kinds (field-pair semantics, in
  the ADR-009 `kind` field):

  | kind          | from → to      | evidenced by one alert carrying                          |
  |---------------|----------------|----------------------------------------------------------|
  | `used_ip`     | actor → ip     | `actor.user.name` AND `src_endpoint.ip`                  |
  | `used_device` | actor → device | `actor.user.name` AND `src_endpoint.mac` (or hostname)   |
  | `seen_at_ip`  | device → ip    | `src_endpoint.mac`/`hostname` AND `src_endpoint.ip`      |

  Direction is fixed by the pair semantics, never by which track promoted —
  the same pair renders the same directed edge in every incident. One alert
  carrying actor + ip + mac yields all three edges. (An allowlisted shared-
  infra ip/hostname still appears as a node/edge endpoint from the recording
  alert's own evidence — a fact, never a cross-alert merge; it still never
  opens its own track.)
- **No transitive inference** (WP-2-C encodes, on the graph, the exact
  refusal the track model already makes): an edge `(u,v,k)` exists iff at
  least one MEMBER alert of the incident's track carries BOTH `u` and `v` in
  its own fields. Two alerts that merely share an entity (two actors on one
  NAT'd source IP; two IPs on one MAC) never produce an edge between their
  other entities — the shared node appears, the inferred relationship does
  not. Same-type pairs (actor-actor, ip-ip, device-device) have no kind and
  are never emitted.
- **Provenance on every edge**: `event_id` = the evidencing alert's first
  `event_ids` element when present, else the alert-level member id
  (`alert_id`, or the deterministic synthetic id for id-less alerts);
  `ts_ms` = the alert's sanitized `time` (same `_valid_window_time` basis as
  `first_seen`/`last_seen`). When several members evidence the same pair,
  the edge cites the EARLIEST `(ts_ms, event_id)`.
- **`tactic_sources`**: tactic → member alert ids (live members) carrying
  it, mirroring the incident's own `member_alert_ids` attribution; a tactic
  whose only member was member-cap-evicted still appears (exactly as it
  does in the incident's `tactics`) with an empty source list.
- **Deterministic + idempotent under redelivery**: the payload is REBUILT
  from the track's live members on every promotion call, so the same
  incident promoted twice emits the SAME `incident_id`, nodes, edges, and
  provenance (even across a fresh process — no per-instance state).
- **Bounded** (mirrors `_sides`/`_last_incident`'s sweep discipline): edges
  ≤ 3 × live members (three possible pairs per alert), nodes = the anchor +
  distinct co-occurring values across live members; the in-memory cache is
  exactly one entry per incident_id, written and pruned TOGETHER with
  `_last_incident` by the same `_sweep_dead_tracks` sweep — never an
  orphaned or growing side table.

### Accessor

`correlator.incident_graph(incident_id) -> dict | None` returns the last
emitted graph payload for a live incident (a deep copy; None for unpromoted
or already-swept incidents). The bus wiring (main.py) pairs each incident it
publishes with this payload on the `incident.graph` topic; the `incidents`
emission itself is byte-for-byte unchanged.

## Correlation model

- **Per-entity tracks, never merged.** Every alert updates an `actor:{name}`
  track, an `ip:{addr}` track, and (2026-08-19) a `device:{mac-or-hostname}`
  track, all three independently. None of them join. This is deliberate
  (design divergence #2): a compound key would make the engine blind to the
  exact "same account, new host" pivot it exists to catch; a transitive
  entity graph would let one NAT gateway merge unrelated tenants' alerts
  into a useless mega-incident.
  **Pivot-correlation (2026-08-19, closes the accepted limitation this row
  used to name):** an authenticated actor pivoting IP was ALREADY correlated
  before this change — `actor:{name}` keys on identity alone, no IP
  component, so two alerts naming the same actor from two different IPs
  land on the same track without any special handling. The real unclosed
  case was activity with NO captured actor identity (pre-auth recon,
  unauthenticated probing) that moves IP mid-attack on the same host — nothing
  linked those before. `device:{mac-or-hostname}` (`src_endpoint.mac`,
  falling back to `.hostname`, both real parser-populated OCSF fields, never
  inferred) now catches that: a DHCP lease renewal or NAT re-mapping changes
  `src_endpoint.ip` between two alerts, but the device track sees the same
  host and promotes on 2 distinct tactics even though neither `ip:` track
  alone ever does. No allowlist check applies to `device:` — unlike an IP, a
  mac/hostname identifies one specific host, not a shared chokepoint many
  unrelated actors pass through, so the NAT/proxy false-merge risk the `ip:`
  allowlist exists for doesn't apply the same way.
  **Residual accepted limitation, now narrower and named precisely:** two
  alerts with no `mac`/`hostname` captured at all (some parsers don't emit
  either), or an attacker who genuinely switches to a different physical
  host under a brand-new, never-before-seen identity, still surface as
  separate incidents — there is no real signal left to link them without
  fabricating one, and this project's fail-closed philosophy means that
  residual case stays deliberately unlinked rather than guessed at.
  **Allowlist (2026-08-26):** shared infrastructure now never opens a
  `device:` track either — a hostname is as spoofable/unauthenticated as
  the `src_endpoint.ip` the `ip:` leg already allowlists, so the same
  `shared_infrastructure.yml` suppression applies to the `device:` value
  (mac or hostname). Fails closed: an unloadable allowlist matches nothing.
  A suppressed no-op alert is recorded in metrics
  (`ws8_skipped_alerts_by_reason`), never silent.
- **Promotion trigger is tactic diversity, not score-sum.** A track is
  promoted to an incident when its live members carry >=2 DISTINCT
  `mitre.tactic` values. Score-sum survives as the incident's `severity`
  field (ranking), not the trigger — a single chatty rule firing fifty times
  is one tactic, not a kill chain, and must never promote on volume alone.
  Alerts with no `mitre` block (only `agent_tool_call_burst` today) still
  join a track as a member but can never themselves trigger promotion.
- **Window state**: `services/shared/window.py`'s existing (moved here from
  `services/ws4-detection/` 2026-08-18 specifically so WS-8 can reuse it
  without a cross-workstream import — see ADR 007)
  `RedisWindowCounter`/`DequeWindowCounter` (same primitive WS-4's stateful
  rules use), keyed `ws8:corr:{tenant}:{entity_type}:{entity_value}`, with
  `CORRELATION_HORIZON_SECONDS` (default 86400 = 24h — a starting default,
  not a measured one, same "untuned guess" caveat as WS-1's backpressure
  rate default until it's tuned against real traffic). Redis `EXPIRE`
  self-cleans a quiet track; there is no separate reaper to test or get
  wrong.
- **Tenant isolation**: tenant is part of the track key, not a filter
  (rejected-at-edge via the same `_validated_tenant`-style check
  `services/ws3-indexer/router.py` uses) — a tenant-agnostic key would
  silently correlate across customers, a data-isolation breach, not merely
  a wrong result.
- **Shared-infrastructure allowlist**: `contracts/allowlists/
  shared_infrastructure.yml` (CIDR/exact match, shipped EMPTY, same
  fail-open-until-populated convention as `service_accounts.yml`/
  `corp_ranges.yml`). An `ip:` track is never opened at all for an
  allowlisted address — the primary defense against one NAT gateway or
  proxy polluting unrelated alerts into a false incident.
- **Hard member cap** per incident. `member_cap` (default 200) bounds BOTH
  the emitted payload and the in-memory side table itself (`_sides[key]`,
  2026-08-26: it used to bound only the payload, so a sustained attack past
  the cap grew memory unboundedly). On overflow the OLDEST members are
  evicted and `truncated: true` is set — and the incident's `tactics`/
  `first_seen` come from a stable per-track aggregate (`_side_meta`), so a
  1-recon + N-brute-force track keeps re-emitting under ONE incident_id
  with both tactics instead of silently freezing (2026-08-26 gap-hunt
  finding: alerts #199-399 emitted nothing). Score-sum severity clamps at
  1000.

## Environment

- `PORT` (default `8008`) — health/metrics listener port.
- `BUS_BACKEND` (default `memory` for tests, `redis` in the Docker profile).
- `CORRELATION_HORIZON_SECONDS` (default `86400`).
- `CORRELATION_MEMBER_CAP` (default `200`).
- `FENGARDE_ALLOWLISTS_DIR` (default `contracts/allowlists`, same env every
  other allowlist-consuming service already reads).

## Contract tests

- `python test_contract.py` — the 8 scenarios from the design doc's test
  plan (positive low-and-slow, no false merge on single tactic, NAT/DHCP
  allowlist, unbounded-growth EXPIRE, tenant isolation, single-tactic
  non-promotion, replay idempotency, no transitive merge) plus 3
  pivot-correlation scenarios (device: promotes across an ip change,
  hostname fallback when mac is absent, device: never merges with actor:/ip:)
  plus 2 dead-track-sweep scenarios (2026-08-20: `_sides`/`_last_incident`
  prune correctly once a track's own `_last_touch` ages past the horizon, a
  still-live track survives, and the sweep is actually wired into
  `_update_track` at the right cadence — see `correlator.py`'s
  `_sweep_dead_tracks`).
- `python test_contract.py` — plus 9 gap-hunt scenarios (2026-08-26):
  member-cap memory boundedness + stable tactics/first_seen under a 1-recon
  + 400-brute-force flood (the stock-default reproduction; also runnable
  standalone as `_gap_hunt_repro.py`), severity cap, stale-PROMOTED-track
  sweep pruning `_last_incident`, WS-5 alert skip-with-reason,
  missing-alert_id synthetic member fallback, entity_value bounding under
  the OpenSearch doc-id limit, device-track allowlisting, `actor.user`
  plain-string degrade, and the `ws8:corr` Redis namespace wiring.
- `python test_correlator_sensitivity.py` — mutate-and-must-fail checks on
  the promotion trigger, the no-merge guarantee, and the device pivot-link
  (same "a negative assertion that cannot fail is not a test" bar
  `eval/attack/test_fire_check.py` established).
- `python test_incident_graph.py` — WP-2-C (2026-08-28): single-alert
  co-occurrence → provenance-bearing edges (all three kinds), the
  no-transitive-inference proof (shared-ip leg AND device-pivot leg: two
  alerts sharing an entity never yield an edge between their other
  entities), redelivery emits an IDENTICAL graph (same id/nodes/edges/
  provenance, also deterministically re-derived by a fresh instance),
  member-set boundedness (edges ≤ 3 × live members; count stabilizes once
  member_cap binds) + the cached graph is pruned WITH its incident by the
  dead-track sweep, and the accessor surface (None for unknown/unpromoted).

## Deliberately not built (this pass)

Dashboard visual design beyond a plain table (design doc's own stated
non-goal; device: now gets its own stat tile, still no deeper redesign).
Tagging `agent_tool_call_burst` with a `mitre` block — still not built:
no defensible single-technique mapping exists for it, not a scheduling gap.
A tuned (vs. default) `CORRELATION_HORIZON_SECONDS` — still the untuned
86400s default; tuning this needs real production traffic shape, which
this project doesn't have yet, not something a code change can close.
Pivot-correlation across a changed IP (device: track, mac/hostname-keyed)
shipped 2026-08-19 — see the correlation model section above for what it
closes and the narrower residual limitation it leaves.

## Run locally

- `python main.py` (memory bus unless `BUS_BACKEND=redis`)
