# Sizing and retention guide

Operator guidance for picking a deployment size and for how long events stay.
Every capacity number here is a **measured** number from
[`benchmark/loadtest.md`](../benchmark/loadtest.md) — running a live Docker
stack on ONE contended laptop (Intel i5-8365U, 8 vCPU / 7.9 GB Docker VM,
OpenSearch 512 MB heap). **Nothing here is extrapolated to other hardware or
to SIEM scale.** If a number for your situation is not in this file, it has
not been measured; assume nothing between the rows.

## Measured capacity (headline numbers)

| Configuration | Sustained rate (measured) | Evidence |
|---|---|---|
| 1 WS-4 replica, current engine (bulk ws3 writes, batched alert writes, single-EVALSHA window ops, capped evidence) | **~150 events/s** for 12 min, no loss — but not a flat-lag hold at the edge (event-path lag grew in the second half while the host got busier) | loadtest §5c (108,015 events) |
| 3 WS-4 replicas (both WS-2 ×1 and WS-4 ×3 in the full pipeline) | **~300 events/s**, held with lag ~0-280 across the step | loadtest §5b ramp (300/s: WS-4 302.4, lag 279) |

Supporting measured points (same contended laptop, use with the caveats):

- 100 events/s, 12-min soak: held with **no loss** (72,010 events; §4d).
  One replica holds 100 in a ramp comfortably (§5b/§4c).
- 60 events/s, 12-min soak: held, small alert-path backlog (§3b).
- 500 events/s for 12 min (§7a, CONTENDED host): event path no loss, but
  **not steady state** — WS-8 correlation (1 replica) fell behind on the
  alerts stream (lag growing ~1,150 messages/min) and Redis ran at 94% of a
  core. This is the highest rate soaks were run at; section 7's whole run is
  explicitly treated as lower bounds on a shared machine.

The numbers above are NOT a sizing table for arbitrary rates. The measured
points give you: 1 replica ≈ up to ~150 events/s (contended), 3 replicas ≈ up
to ~300 events/s (contended). What sits between or beyond (e.g. "what do I
need for 250 events/s on an idle 8-core server?") is **not measured** — size
from the nearest measured point and leave headroom, or measure it yourself
with `tools/fengarde_loadtest_live.py` on your host.

### What was measured about the machine

From loadtest.md's own limits section — everything below applies to the rows
above and nothing more:

- **Not measured:** a verified-idle host (every run had neighbours at 27-78%
  host CPU), runs longer than 12 minutes, a clean rate above ~500-800
  events/s, multi-node OpenSearch, real WS-1 UDP ingest, a
  Windows/Sysmon-heavy log mix, more than one replica of ws2/ws8. "This is
  not evidence of SIEM-scale (thousands of events/s) capacity; the live stack
  as shipped does not reach it on this host."
- **Scale-out caveat:** with several WS-4 replicas the shared consumer group
  means per-source ordering is no longer strict; alert ids stay deterministic
  and the global window counter keeps threshold counts correct.
- **Bottleneck order observed:** ws3-indexer single-doc writes (fixed by bulk,
  §3), then WS-4's Redis window round trips (fixed by EVALSHA + per-event
  batching, §5/§6), then WS-2/Redis contention near ~250-300+ events/s (§6b,
  §7), then WS-8 correlation at 500 events/s (§7a).

### Memory observations (measured, this host)

- OpenSearch heap: 512 MB default; peaks 75-77% of it under the soaks
  (§2/§3b/§4d). No upward trend inside a run; growth comes from more data,
  which the ISM policies below bound.
- Redis: max ~52 MB in the 60/s soak, 441 MB in the 500/s soak (§3b/§7a —
  the second is inflated by the lagging WS-8 consumer group holding streams
  back).
- Pipeline services: peak RSS stays under ~100 MB per process at 20,000
  events in the zero-infra runs (loadtest §1).

## Retention (ISM policies)

Retention is enforced by OpenSearch Index State Management policies in
[`contracts/opensearch-mappings/`](../contracts/opensearch-mappings/), applied
by `infra/provision.sh` via `ism_template` index patterns (auto-attach to
new daily indices). All policies are **age-based** — WS-3 writes daily
date-suffixed indices directly (no write alias), so ES-style rollover does
not apply.

| Index pattern | Policy file | Lifecycle |
|---|---|---|
| `events-common-*` | `ism-events-common-90d.json` | hot → **delete at 90d** |
| `events-*` (data-center events) | `ism-events-90d.json` | hot 7d → warm (`force_merge` 1 segment) → **delete at 90d** |
| `events-*` (banking, PCI-DSS) | `ism-events-400d-pci.json` | hot 30d → warm (`force_merge` 1 segment + `read_only`) → **delete at 400d** (PCI-DSS minimum 1 year) |
| `alerts-*` (incl. tenant-scoped `alerts-<tenant>-*`) | `ism-alerts-365d.json` | hot → **delete at 365d** |
| `incidents-*` | `ism-incidents-365d.json` | hot → **delete at 365d** (matches the alerts lifetime: an incident is only as substantiable as the member alerts it cites) |
| `reports-*` | `ism-reports-365d.json` | hot → **delete at 365d** (matches alerts; a NIS2/compliance report must not outlive the alert it cites) |

`force_merge` + `read_only` (warm state) shrink storage and stop writes to
aged indices; deletion is a hard delete of the whole index at the stated age.
Indices not matched by any pattern keep no ISM policy — retention does not
apply to them (e.g. experiment/dev indices; give them their own policy or
delete them yourself).

## Storage estimate (events/sec to bytes — measured anchor only)

OpenSearch disk use for events was not measured as a bytes-per-event number
in any loadtest table. Size storage from the daily index growth you observe
(`events-*` grew at exactly the offered rate in every soak) and the retention
window above: `bytes ≈ daily_docs × avg_doc_bytes × retention_days`. The
average document size is deployment-shaped (raw payload + OCSF fields +
detection metadata) — measure it from your own indices; no number is
invented here.
