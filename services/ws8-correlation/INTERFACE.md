# WS-8 Correlation — Interface Declaration

**Status (2026-08-19): zero-infra proven, one live smoke test (2026-08-18) +
pivot-correlation (device: track) added 2026-08-19, zero-infra proven.
2026-08-28: incident.graph (ADR-009/WP-2-C) added, zero-infra proven.
2026-09-02 (WP-3-A): incident.graph upgraded to VERSION 2 — the typed causal
DAG — zero-infra proven; v2 SUPERSEDES v1 on the topic.**
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

## Incident graph (ADR-009, WP-2-C; VERSION 2 — typed causal DAG, WP-3-A 2026-09-02)

Every incident promotion/update ALSO produces an `incident.graph` payload.
**Version 2 SUPERSEDES version 1 on the `incident.graph` topic** (owner-
ratified 2026-09-02): the `version` field (integer 2) distinguishes the
shape, and the `incidents` topic payload is byte-for-byte untouched. The v1
builder `correlator._build_incident_graph` remains in the codebase
byte-for-byte (same name, same output — pinned by a source-hash test in
`test_incident_graph_v2.py`), so a v1 consumer/byte-compat test keeps
passing, but the ACCESSOR `incident_graph()` — the produce source for the
bus topic — returns the v2 payload.

```
{version: 2, incident_id, tenant_id,
 nodes: [{entity_id, entity_type, entity_value, label}, …],
 edges: [{from, to, kind, event_id, ts_ms}, …],
 tactic_sources}
```

- **Nodes** are the incident's member entities as OBJECTS:
  - `entity_id` — the ADR-009 canonical identity: sha256 hexdigest of the
    pipe-joined `tenant|entity_type|canonical_value`, computed by the
    module-level `canonical_entity_id(tenant, entity_type, entity_value)`,
    which mirrors `services/ws9-resolver/entity_id.py` EXACTLY without
    importing it (WS-8's container ships only `shared/` + `contracts/`;
    `shared.ip_utils` IS available and is the shared canonicalization
    source). Canonical value: `ip` → `valid_ip` then lowercased (one digest
    across IPv6 case/compression spellings), `actor` → `strip().casefold()`
    (`Alice`/`ALICE`/`alice` are ONE identity), `device` → `strip().lower()`
    (macs/hostnames). An un-normalizable value returns None and the caller
    SKIPS that node — degrade, never fabricate, never str()-coerce (the
    WS-9 skip discipline). Identifier agreement with ws9 is pinned by
    `test_incident_graph_v2.py::test_identifier_agreement_with_ws9`.
  - `entity_type` — one of `actor`, `ip`, `device`.
  - `entity_value` — the incident's OWN track spelling (what WS-8 stored,
    e.g. `Alice` as captured; already 448-byte-bounded at store time).
  - `label` — the v1-style track ref, `{entity_type}:{entity_value}`
    (e.g. `actor:Alice`).
- **Edges** reference nodes by their `entity_id` strings as `from`/`to`,
  and carry EXACTLY ONE `kind`. Kinds are ONLY relationships a SINGLE
  alert's own fields provide — never inferred across alerts (the v1
  no-transitive rule is inherited verbatim: an edge exists iff ONE member
  alert carries both endpoints in its own fields; two alerts that merely
  share an entity never yield an edge between their other entities;
  same-type pairs never emit). The v1 field-pair kinds are retained for the
  same pairs and REFLECTED-REPLACED by the typed kinds when the evidencing
  alert carries the documented semantic signal:

  | kind               | from → to      | v1 pair semantics (kept)            |
  |--------------------|----------------|-------------------------------------|
  | `used_ip`          | actor → ip     | actor.user.name AND src_endpoint.ip |
  | `used_device`      | actor → device | actor.user.name AND src_endpoint.mac (or hostname) |
  | `seen_at_ip`       | device → ip    | src_endpoint.mac/hostname AND src_endpoint.ip |

  **Typed kinds (WP-3-A)** — the STORY: an analyst wants the graph to name
  WHAT the relationship is (caused, invoked, authenticated as, wrote to,
  changed), not just that two entities co-occurred. Derivation is a PURE
  FUNCTION of the evidencing alert's OWN fields — the minimal, bounded
  signal `(mitre.tactic, mitre.technique, unmapped.ot.anomaly_type)` is
  captured on the member entry at STORE time (`entry["typed_signal"]`, the
  same additive pattern as `cooccur`/`event_id`), so it is redelivery-
  stable, single-alert-only, and never a transitive inference. When several
  members evidence one pair with different kinds, the highest-ranked kind
  wins (typed kinds outrank the field-pair fallback; the documented order
  `caused_by, invoked, authenticated_as, wrote_to, changed` breaks ties
  among typed kinds), then the EARLIEST `(ts_ms, event_id)` provenance —
  matching v1's earliest-wins dedup. If no member carries a signal, the v1
  field-pair kind is kept — never fabricate a causal label.

  | typed kind         | from → to      | derived when the alert's OWN fields carry            | shipped-rule evidence (mitre/unmapped shapes) |
  |--------------------|----------------|-----------------------------------------------------|-----------------------------------------------|
  | `authenticated_as` | actor → ip     | `mitre.tactic == TA0001` (Initial Access) OR `mitre.technique` startswith `T1078` (Valid Accounts): the actor acted under an authenticated identity at/from this ip | `cloud_root_console_login` (TA0001/T1078.004), `common_impossible_travel` (TA0001/T1078), `common_after_hours_admin` (TA0004/T1078), `n8n_workflow_modified_after_hours` (TA0004/T1078) |
  | `invoked`          | actor → ip     | `mitre.tactic == TA0011` (Command & Control) OR `mitre.technique` startswith `T1071` (Application Layer Protocol): the actor initiated/commanded the exchange | `agent_egress_non_allowlisted_domain` (TA0011/T1071), `common_beaconing` (TA0011/T1071), `common_dns_exfil` (TA0011/T1071.004) |
  | `caused_by`        | actor → device | `unmapped.ot.anomaly_type == "unauthorized_write"` AND `mitre.technique` startswith `T0855`: the device-side unauthorized state this alert evidences was CAUSED by the actor's command message | **No shipped alert today** — `make_alert` forwards a fixed field list and does not copy `unmapped`; the modbus rules read the field off the raw event. The derivation ships (one-line `make_alert` passthrough wires it) and `test_incident_graph_v2.py` proves it with a concrete fixture. Honest gap, not a bug. |
  | `wrote_to`         | actor → device | `mitre.tactic == TA0106` AND `mitre.technique == T0836` (ICS Modify Parameter): the actor wrote a value/parameter to the device | `ot_write_outside_maintenance` (TA0106/T0836), `ot_config_change` (TA0106/T0836) — both carry `actor.user.name` in their fields |
  | `changed`          | actor → device | `mitre.tactic == TA0003` (Persistence): the actor changed account/identity state on the device | `common_priv_grant` (TA0003/T1098), `common_rapid_account_lifecycle` (TA0003/T1136), `n8n_new_webhook_exposed` (TA0003/T1133) |
  | `changed`          | device → ip    | `mitre.tactic == TA0108` (attack-ics Initial Access): the device's presence at this ip changed (new/transient device) | `ot_new_device_on_segment` (TA0108/T0864), `ot_new_engineering_connection` (TA0108/T0864) |

  Honesty notes: `caused_by` is the one typed kind NO shipped rule's alert
  evidences today (see the table — the `unmapped` passthrough does not
  exist in `make_alert`); every other typed kind is evidenced by at least
  one shipped rule's mitre block, subject to the graph's standing rule that
  an edge only exists when ONE alert carries both endpoints in its own
  fields (e.g. an OT write whose alert has no `src_endpoint.mac`/hostname
  still forms no device edge — the signal is real but the pair isn't).
  An alert with no relevant signal (e.g. `agent_tool_call_burst`, which has
  no mitre block) keeps the v1 field-pair kind.

- **Direction** stays fixed by the pair semantics, never by which track
  promoted — the same pair renders the same directed edge in every
  incident. (An allowlisted shared-infra ip/hostname still appears as a
  node/edge endpoint from the recording alert's own evidence — a fact,
  never a cross-alert merge; it still never opens its own track.)
- **Provenance on every edge** (unchanged from v1): `event_id` = the
  evidencing alert's first `event_ids` element when present, else the
  alert-level member id; `ts_ms` = the alert's sanitized `time` (same
  `_valid_window_time` basis); the wall-clock-fallback digest path for
  time-less alerts is inherited verbatim.
- **`tactic_sources`** — identical to v1: tactic → live member alert ids
  carrying it, mirroring the incident's `member_alert_ids` attribution.
- **Deterministic + idempotent under redelivery**: rebuilt from the track's
  live members on every promotion — the same incident promoted twice, even
  from a FRESH process, emits the SAME v2 nodes/edges/provenance
  (byte-identical, json-pinned by `test_incident_graph_v2.py`). Same
  IPv6/actor/device canonicalization means spelling variants collapse to
  ONE node digest.
- **Bounded** (mirrors `_sides`/`_last_incident`'s sweep discipline,
  unchanged from v1): edges ≤ 3 × live members (three possible pairs per
  alert, one edge per pair), nodes = the anchor + distinct co-occurring
  values across live members; the in-memory cache is exactly one entry per
  incident_id, written and pruned TOGETHER with `_last_incident` by the
  same `_sweep_dead_tracks` sweep — the v2 cached payload dies with its
  incident in the same sweep, never an orphaned side table.

### Accessor

`correlator.incident_graph(incident_id) -> dict | None` returns the last
emitted graph payload for a live incident (a deep copy; None for unpromoted
or already-swept incidents). Since WP-3-A the returned/cached payload is
VERSION 2 (the typed DAG above); v1's `_build_incident_graph` stays
callable byte-for-byte for the byte-compat test only. The bus wiring
(main.py) pairs each incident it publishes with this payload on the
`incident.graph` topic (unchanged — it emits whatever the accessor
returns); the `incidents` emission itself is byte-for-byte unchanged.

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
- `python test_incident_graph.py` — WP-2-C (2026-08-28), accessor shape
  updated to VERSION 2 (WP-3-A): single-alert co-occurrence →
  provenance-bearing edges (all three pair kinds, with typed-kind
  replacement — e.g. `authenticated_as` on TA0001/Valid-Accounts evidence),
  the no-transitive-inference proof (shared-ip leg AND device-pivot leg: two
  alerts sharing an entity never yield an edge between their other
  entities), redelivery emits an IDENTICAL graph (same id/nodes/edges/
  provenance, also deterministically re-derived by a fresh instance),
  member-set boundedness (edges ≤ 3 × live members; count stabilizes once
  member_cap binds) + the cached graph is pruned WITH its incident by the
  dead-track sweep, and the accessor surface (None for unknown/unpromoted).
- `python test_incident_graph_v2.py` — WP-3-A (2026-09-02) typed-DAG suite:
  v2 emitted shape pinned exactly (version 2, node objects, entity_id
  edges, exactly-one-kind) + the incidents payload byte-for-byte untouched;
  redelivery byte-identity (same instance AND fresh instance, json-pinned);
  IPv6 spelling variants collapse to ONE canonical node digest; per-kind
  typed-derivation fixtures (authenticated_as / invoked / wrote_to /
  changed — both rows / caused_by) each with its honest no-signal fallback
  to the v1 field-pair kind; the no-transitive proof carried into v2;
  membership-bounded + sweep-pruned-with-incident (v1 recipe); identifier
  agreement with ws9's `entity_id.py` (imported in the test process: a
  lowercase ip, `2001:DB8::1`, `Alice` vs `alice`, an uppercase device mac,
  un-normalizable → None on both sides) including the v2 node digest for an
  IPv6 address; and the v1 BUILDER byte-for-byte source-hash pin.

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
