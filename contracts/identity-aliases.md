# Identity alias map and window clock (WS-4)

Two operator-facing knobs that close (or narrow) the evasion findings in
`eval/adversarial/evasion_findings.yaml`. Both default to safe, conservative behaviour.

## F2: per-tenant realm alias map

`contracts/identity_aliases.yaml` (override: `FENGARDE_IDENTITY_ALIASES=/path.yaml`, the file must then exist).

```yaml
version: 1
tenants:
  acme:
    default_realm: corp          # optional: a bare "jdoe" is taken to be in this realm
    realms:
      - [CORP, corp.example]     # CORP\jdoe == jdoe@corp.example
```

- WS-4 groups an account by `strip().casefold()` (ADR-009). With a map, `DOMAIN\name` and `name@upn` whose realm is
  listed for the event's tenant become `name@<first spelling>`, so one burst split over those spellings still counts as one.
- **No map, no merge.** The shipped map is empty; an unlisted realm, an unlisted tenant, or a bare name without
  `default_realm` is never merged. The code does not guess that two names are the same person.
- **Per tenant only.** Entries live under a tenant id; there is no wildcard tenant, no global section, no
  tenant-qualified realm (`:` `/` `*` `\` `@` or whitespace in a realm is rejected), realm groups of one tenant must be
  disjoint. Window keys and alert ids stay tenant-namespaced, so a map cannot mix tenants.
- **Fail closed.** A malformed or missing (env-pointed) map raises `IdentityAliasError` from `load_rules()`: boot fails,
  a hot reload keeps the previous rules AND the previous map. WS-4 never runs with a half-read map.
  An empty file, a file with only `version: 1`, or `tenants:` with no value counts as truncated and fails; the explicit
  empty map is `version: 1` plus `tenants: {}`. The file is read by WS-4 on rule (re)load and by WS-8/WS-9 at start only,
  so restart WS-8 and WS-9 after editing the map (until then their tracks and entity ids use the old one).
  A map file that was loaded earlier and is now MISSING (rename-and-replace deploy, ConfigMap swap, remount) also raises and
  keeps the previous map; a file cut in the middle of a multibyte character is an `IdentityAliasError` too. The map and the
  rule set swap together: a reload that fails on a rule keeps the previous map as well as the previous rules. A truncated
  file that still parses (cut after a complete group) cannot be detected, so deploy the file with an atomic write (write a
  temp file, then rename it over the old one).
- **Folded everywhere the canonical actor is used.** WS-4 window groups and alert keys, WS-8 actor tracks, incident ids,
  incident graph nodes and canonical entity ids, WS-9 entity ids (`shared.entity_helpers.canonical_entity_value(..., tenant)`).
  All three services load the same file at start (`shared.identity_aliases.configure()`) and refuse to start on a bad one.
  A WS-8 alert with no matching alias is processed as the SAME object it received (byte-identical to before).
- Ids stay deterministic and idempotent: `alert_key` is a pure function of (rule, tenant, canonical group, bucket), WS-8/WS-9
  entity ids are `sha256(tenant|type|canonical value)`, so redelivery and a second spelling land on the same ids.
- **Deployments MUST configure their realms.** The shipped map is empty on purpose (no guessing), so a tenant that has not
  listed its realms keeps the residual: a burst split over `DOMAIN\name` and `name@upn` stays under threshold. The evasion
  harness reports that unmapped row as the registered residual and, separately, `respelling_evades_mapped` under a fixture map
  (`eval/adversarial/evasion_alias_fixture.yaml`), which is false for every rule set.
- Changing a tenant's map changes the `alert_key` of that tenant's mapped accounts once.
- **Cut-over for live incidents (measured 2026-10-23, same alert stream with the map off and on).** An incident that
  already exists keeps its id and members but is never updated again: from the switch on, that identity's alerts feed a
  NEW incident under the folded id (`acme:actor:jdoe:20749` stays frozen, `acme:actor:jdoe@corp:20749` starts empty and
  needs its own two-tactic evidence). Unmapped actors keep their ids unchanged. So turning the map on for a tenant with open
  incidents splits each affected identity's incident once and leaves the old one orphaned; there is no automatic merge or
  re-key. Introduce the map at a quiet time, or accept one split per mapped identity and close the old incidents by hand.

## F4: window clock (`FENGARDE_WINDOW_TIME_SOURCE`)

| Value | Window time | Use |
|---|---|---|
| `clamp` (default) | record time; if it differs from `siem.received_ms` by MORE than the skew limit (either direction) the receipt time, and `siem.time_clamped: true` | live ingestion |
| `event` | record time always (pre-2026-10-21 behaviour) | **historical replay / backfill**: record times are legitimately far from receipt time |
| `ingest` | receipt time always | strictest; breaks replay |

`FENGARDE_WINDOW_MAX_SKEW_SECONDS` (default `600`, non-negative number; invalid values fall back to 600 with a warning).
**The limit is window-aware: `min(that value, window_seconds / 2)` per rule.** Record times inside +-window/2 of receipt span at
most one window, so a burst that arrives together is counted in one sliding window whatever times the log author forges.
Exactly at the limit is trusted. No usable `siem.received_ms` falls back to the record time (cannot be measured).
Periodicity rules always use the record time (their verdict is the spacing of the record times; a receipt clock would
destroy it). An unknown mode value falls back to `clamp`, never to `event`.
Metric: `detection_time_clamped_total` on WS-4 `/metrics`; flag `siem.time_clamped` on the event.

**Replay / backfill:** set `FENGARDE_WINDOW_TIME_SOURCE=event` on the WS-4 that processes historical data, otherwise record
times older than the limit are replaced by receipt time ("now"). **Shipper lag:** a record delayed by less than the per-rule
limit (e.g. under 150 s for a 300 s window) keeps its record time; a longer-delayed record is counted at its arrival time,
which is the correct live behaviour but can bunch a large post-outage backlog into one window.
The eval harness stamps `received_at` equal to the synthetic event time, so the clamp does not change its measurements.
Live proof: `docs/live-proof-f2-f4-2026-10-22.md`.
