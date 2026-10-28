# FENGARDE load test: throughput, latency, saturation

Measured 2026-10-28 on one laptop: "before" at commit `dd6f7d0` (harness on top
of `33e340f`), "after" with the bulk-write change that follows it. Raw outputs: [`raw/`](raw/). Everything below is a measured number for
**this machine only**; nothing here is a statement about SIEM-scale capacity.

**Headline (updated after the bulk-write fix).** On the live stack (Redis bus +
OpenSearch) the first measurement (per-document writes, commit `dd6f7d0`) held
**20 events/s for 12 min and fell behind from ~25 events/s**; the bottleneck was
`ws3-indexer`'s one-HTTP-request-per-document write path. After batching those
writes through `/_bulk` (this change), the same stack **holds 60 events/s for 12
min** (all stage rates equal the offered rate), ws3 throughput rose ~7x
(~55 -> ~370 messages/s in a short smoke, up to ~500 messages/s in the ramp), and
the next limits are WS-4's consume path (~75-100 events/s) and, slowly, the
per-document CAS path for alerts. The zero-infra CPU ceiling (~900-1,500
events/s end to end) is still far above the live number, so the live rate remains
set by I/O design, not Python speed. Laptop-scale result only; see the limits at
the end.

## Machine

| | |
|---|---|
| CPU / RAM | Intel Core i5-8365U (4 cores / 8 threads, 1.6 GHz base), 15.3 GB, Windows 11 Pro |
| Docker Desktop | 8 vCPU, 7.9 GB for the VM; OpenSearch heap `-Xms512m -Xmx512m` (compose default) |
| Python | 3.13.3 |
| Neighbours | Not an idle reference host: another compose project (`infra`, plus a small `ws8proof` one) and other editor sessions ran concurrently. Zero-infra run-to-run spread below is partly that. |

## 1. Zero-infra (no Docker): `tools/fengarde_loadtest.py`

```sh
python tools/fengarde_loadtest.py --repeat 3 --max-events 20000 --out benchmark/raw/zero-infra-2026-10-28.json
```

46 rules loaded (the full set). Each scenario is its own process (clean peak
RSS). Values are the median of 3 repeats, spread in brackets. Latency for the
stage rows is per-event service time; for the paced `e2e` rows it is
completion minus scheduled arrival, so queueing shows once offered > capacity.
In-memory sink instead of a bus; `MemoryStore` instead of OpenSearch.

Profiles: **realistic** = ~60% syslog / 20% ssh / 20% ASA from mostly unique
sources plus one 10-line brute-force burst per 500 events (alerts = 1.25% of
events). **alert-heavy** = the older `fengarde_bench.py` mix where every ssh
line trips a rule (~1.3 alerts per event), a worst-case stress, not a
realistic ratio.

Per stage, closed loop, 20,000 events:

| Profile | Stage | events/s | p50 ms | p95 ms | peak RSS |
|---|---|---|---|---|---|
| realistic | WS-2 normalize | 2,098 (2,008-2,161) | 0.34 | 1.1 (0.9-1.2) | 43 MB |
| realistic | WS-4 detect+emit | 4,553 (3,986-5,190) | 0.075 | 0.6 (0.5-0.7) | 89 MB |
| alert-heavy | WS-2 normalize | 2,420 (2,340-2,452) | 0.30 | 0.86 | 41 MB |
| alert-heavy | WS-4 detect+emit | 311 (303-387) | 0.40 | 12.5 (9.5-12.9) | 88 MB |

End to end (WS-2 -> WS-4 -> WS-3 `MemoryStore`), paced open loop, one thread:

| Profile | Offered events/s | Achieved | Sustained (>=95%) | p50 ms | p95 ms | peak RSS |
|---|---|---|---|---|---|---|
| realistic | 100 | 100 | yes | 1.3 | 6.4 | 33 MB |
| realistic | 250 | 250 | yes | 2.3 | 16 | 38 MB |
| realistic | 500 | 499 | yes | 3.5 | 22 | 46 MB |
| realistic | 1,000 | 880-933 | **no** | 28-425 | 625-1,281 | 63 MB |
| realistic | 2,000 | 862-1,220 | **no** | 2,800-5,970 | 6,200-12,300 | 96 MB |
| realistic | unpaced max | 1,161 (871-1,460) | n/a | 0.6 | 1.9 | 96 MB |
| alert-heavy | 100 | 100 | yes | 3.3 | 14 | 33 MB |
| alert-heavy | 250 | 229-240 | **no** | 29-74 | 320-818 | 38 MB |
| alert-heavy | unpaced max | 255 (206-331) | n/a | 0.95 | 13 | 94 MB |

Reading it: single-process saturation is ~900-1,200 events/s for the realistic
mix and ~250 events/s when nearly every event is an alert (alert construction
and window bookkeeping dominate WS-4). Peak RSS stays under ~100 MB at 20,000
events; the earlier 425 MB README figure was measured with Docker Desktop and
other work running on the host and is not reproduced here.

Limits: only three log sources are generated, so the `class_uid` prefilter
skips most of the 46 rules for most events; a mix heavy in Windows/Sysmon
events would exercise more rules. Wall-clock timing on a shared laptop is noisy
(the brackets above are real run-to-run spread).

## 2. Live stack (Redis streams + OpenSearch): `tools/fengarde_loadtest_live.py`

Sections 2a-2c below are the **before** measurement (per-document writes, `dd6f7d0`). The **after** measurement is section 3.

Isolated compose project `fgloadtest` (overlay
[`infra/docker-compose.loadtest.yml`](../infra/docker-compose.loadtest.yml):
no fixed container names, ports 16379/19200) with redis, opensearch,
provision, ws2, ws3, ws4, ws5 (stub LLM), ws8, ws9. Torn down with
`down -v` afterwards. WS-1 is bypassed (events are `XADD`ed straight onto
`raw.events`, as `devkit-feeder` does). Same realistic mix as above, unique
`ingest_id` per event. Sampled every 3 s: `XINFO GROUPS` (read/lag/pending),
OpenSearch `_nodes/stats`, `docker stats`.

```sh
export COMPOSE_PROJECT_NAME=fgloadtest LT_REDIS_PORT=16379 LT_OS_PORT=19200
docker compose -f infra/docker-compose.yml -f infra/docker-compose.loadtest.yml up -d --build \
  redis opensearch provision ws2-normalization ws3-indexer ws4-detection ws5-ai ws8-correlation ws9-resolver
python tools/fengarde_loadtest_live.py --rates 25 50 75 100 150 200 --step-s 60 --drain-timeout-s 1500 --out benchmark/raw/live-ramp-2026-10-28
python tools/fengarde_loadtest_live.py --rates --soak-rate 20 --soak-min 12 --out benchmark/raw/live-soak-2026-10-28
python tools/fengarde_os_probe.py          # OpenSearch ceiling probe
docker compose -f infra/docker-compose.yml -f infra/docker-compose.loadtest.yml down -v
```

### Ramp (60 s per step, no drain between steps)

`ws3 msgs/s` counts every message the indexer consumed (each event produces a
`normalized.events` and a `scored.events` message, plus alerts), so ~2.1
messages per input event. "Total lag" is the sum of consumer-group lag +
pending across all streams at the end of the step.

| Offered ev/s | WS-2 read/s | WS-4 read/s | ws3 msgs/s | Total lag at step end | Max container CPU (mean %) |
|---|---|---|---|---|---|
| 25 | 25 | 25 | 48 | 1,318 | opensearch 97, ws4 54 |
| 50 | 50 | 50 | 64 | 5,488 | opensearch 110 |
| 75 | 75 | 75 | 75 | 13,147 | opensearch 94, ws4 51 |
| 100 | 100 | 93 | 47 | 26,299 | opensearch 104, ws4 74 |
| 150 | 150 | 105 | 74 | 43,091 | opensearch 186, ws4 70 |
| 200 | 200 | 88 | 64 | 67,519 | opensearch 112, ws4 73 |

WS-2 kept up with every offered rate (its input stream lag was 0 throughout).
WS-4 held up to ~75 events/s and lagged beyond (a consequence of
back-pressure/CPU on a shared host; not isolated further). `ws3-indexer` was
behind from the first step: its throughput of 47-75 messages/s means roughly
**22-35 events/s** end to end. After stopping the producer, the 67,519-message
backlog drained in **1,103 s at ~70 ws3 messages/s**, the clearest
single capacity number: the indexer, working flat out, clears ~70 messages/s
(~30 events/s). OpenSearch heap peaked at 75-77% of 512 MB; the node stats
did not expose a write-queue rejection count.

### Bottleneck before the fix: `ws3-indexer` single-document writes

`tools/fengarde_os_probe.py`, run against the idle stack:

| OpenSearch write pattern | docs/s |
|---|---|
| serial `PUT /_doc`, fresh connection each (what the ws3 daemon does) | 48 |
| serial `PUT /_doc`, one keep-alive connection | 58 |
| `_bulk`, 500 docs per request | 4,745 |

The daemon's observed 47-75 messages/s matches the single-PUT ceiling, while
OpenSearch has ~80x headroom via bulk. In the ramp, `ws3-indexer` itself used
only 10-17% CPU (it is waiting on round trips), and OpenSearch used 95-185% of a
core. The module docstring in `services/ws3-indexer/storage/opensearch.py`
said at the time that the daemon path was deliberately not batched (the batch
path, `run()`, used by tests and `demo_e2e`, was). Why each PUT costs ~17-20 ms on
this host (request-level translog fsync on Docker Desktop's disk is the
likely cause) was **not** investigated.

### Soak: 20 events/s for 12 minutes

| | |
|---|---|
| Offered / produced | 20.0 events/s, 14,402 events |
| WS-2 and WS-4 | 20.0 events/s each, steady every minute |
| OpenSearch `events-*` growth | 19.9 docs/s mean (19.5-20.6 per minute) |
| Total lag | 0-240 messages, bounded (peaks 90 in minutes 7-8); backlog cleared in 4-6 s after stop |
| OpenSearch heap | 69-78% of 512 MB (401 MB max), no upward trend |
| Redis memory | max 19 MB |
| CPU (mean) | opensearch 44%, ws3 22%, ws4 16%, ws2 12%, redis 20% |
| `index_failed` counter | 183 by end of run; shown to be create-only 409s, see section 3c |

20 events/s is the highest rate **tested and held** for >=10 minutes. Rates
between 20 and 25 events/s were not run; 25 events/s showed lag growth in a
60 s window, not a long soak.

## 3. After: batched daemon writes (`/_bulk`)

Change: `ws3-indexer`'s daemon now gathers each read pass (up to `WS3_BULK_MAX`
= 500 messages) and writes it with ONE `/_bulk` request
(`BatchIndexHandler` in `services/ws3-indexer/main.py`, `OpenSearchStore.bulk_write`,
batch path in `services/shared/runner.py`). Semantics kept: `normalized.events`
use bulk `create` (a per-item 409 is success), other topics bulk `index` (idempotent
upsert on the deterministic id); alerts stay on the per-document CAS path so analyst
`triage` is preserved; messages are acked only after the bulk response is known,
per item (failed items stay unacked for redelivery, 429/5xx items are retried
in-process up to `WS3_BULK_RETRIES`=3, a whole-request failure acks nothing);
`WS3_BULK=0` restores the old path. Contract test:
`services/ws3-indexer/test_bulk_handler.py`.

Same procedure and same isolated project as section 2 (rebuilt images, fresh
volumes). Neighbours during these runs: the `infra` compose project (all services
idle, 0-5% CPU each) and no other active Docker project at the start of the
runs (`docker ps`); other editor sessions may have been running. The "before"
runs had the same neighbours, so the comparison is like for like to the extent a
shared laptop allows.

### 3a. Ramp (45 s per step, then drain)

```sh
python tools/fengarde_loadtest_live.py --rates 25 50 100 150 200 300 400 --step-s 45 --drain-timeout-s 1800 --out benchmark/raw/live-ramp-bulk-2026-10-28
```

| Offered ev/s | WS-2 read/s | WS-4 read/s | ws3 msgs/s | OpenSearch `events-*` docs/s | Total lag at step end |
|---|---|---|---|---|---|
| 25 | 25 | 25 | 68 | 25 | 4 |
| 50 | 50 | 50 | 135 | 50 | 17 |
| 100 | 100 | 98.5 | 260 | 100 | 705 |
| 150 | 150 | 90 | 293 | 151 | 3,904 |
| 200 | 203 | 78 | 334 | 204 | 9,496 |
| 300 | 274 | 82 | 397 | 275 | 18,163 |
| 400 | 341 | 94 | 498 | 345 | 32,718 |

Reading it: up to 50 events/s everything keeps pace; at 100 it is at the edge
(WS-4 98.5/s, lag 705); beyond that WS-4 reads only ~78-94 events/s while WS-2
and the indexer keep going, so `normalized.events` backs up (lag 26,573 of the
32,718 at 400/s). `ws3-indexer` is no longer the limiter: at 400 events/s it
handled ~500 messages/s using 45% CPU, versus a hard ceiling of ~55-75
messages/s before. WS-2 itself starts to trail at 300-400 events/s (274, 341).
After the producer stopped, the 32,718-message backlog drained in 431 s, with
WS-4 draining at ~74 events/s using ~62% CPU and Redis ~31%: WS-4 looks
latency-bound on its per-message bus round trips here rather than CPU-bound
(zero-infra WS-4 does ~4,500 events/s); this was not profiled further.

| | Before (per-doc, section 2) | After (bulk) |
|---|---|---|
| ws3 messages/s achieved | 47-75 (ceiling ~70) | 68 at 25 ev/s up to 498 at 400 ev/s (not saturated) |
| Highest offered rate with near-zero lag growth | below 25 events/s (lag already 1,318 at the end of the 25/s step; 20/s was the soak rate) | 50 events/s (lag 17); 100 borderline (lag 705, WS-4 98.5/s) |
| Backlog drain | ~70 ws3 messages/s (~30 events/s): 67,519 msgs in 1,103 s | ~74 events/s (WS-4-bound): 32,718 msgs in 431 s |
| Limiting stage | ws3-indexer (single PUT per doc) | WS-4 consume path, ~75-100 events/s |

### 3b. Soak: 60 events/s for 12 minutes

```sh
python tools/fengarde_loadtest_live.py --rates --soak-rate 60 --soak-min 12 --out benchmark/raw/live-soak-bulk-2026-10-28
```

| | |
|---|---|
| Offered / produced | 60.0 events/s, 43,206 events |
| WS-2 and WS-4 | 60.0 events/s each (WS-4 54.4 in one minute, 59.9-61.3 otherwise) |
| OpenSearch `events-*` growth | 60.0 docs/s mean (57.9-60.9 per minute) |
| Total lag | rose from ~230 to ~1,600 in the first 7 minutes, then ~1,550-1,650 for the remaining 5; cleared 86 s after the producer stopped |
| Where the lag sits | `alerts` stream, `cg-index` group (1,361 mid-run, 1,779 near the end): alerts still use the per-document CAS path (GET + conditional PUT); event streams stayed at 0-60 |
| OpenSearch heap | 71-77% of 512 MB (398 MB max) |
| Redis memory | max 52 MB |
| CPU (mean) | opensearch 87%, ws4 54%, redis 52%, ws2 31%, ws3 30% |
| Bulk counters (ws3 `/metrics`, whole session) | 0 failed items, 0 retried items |

So 60 events/s was held for 12 minutes with stage rates equal to the offered rate
and OpenSearch growth equal to the offered rate (no loss), but with a small
backlog in the alert path that grew from ~1,361 to ~1,779 across the second half
of the run, so a flat lag is only shown for the event path. Rates between 60 and
100 events/s were not soaked. The claim is 3x the "before" soak rate (20 -> 60
events/s), not more.

### 3c. `index_failed` = 183 (before) explained

The OpenSearch node stat `indexing.index_failed` was 183 after the first soak with
no errors in service logs. Evidence it is create-only 409s, not real failures:

1. `tools/fengarde_os_conflict_probe.py` against the live node
   (`raw/os-conflict-probe-2026-10-28.json`): `op_type=create` on a new id: HTTP
   201, counter +0; the same create again: HTTP 409
   `version_conflict_engine_exception`, counter **+1**; a plain index of an
   existing id: 200, +0; a `_bulk` create of [existing id, new id]: statuses
   [409, 201], counter **+1**. (A mapping-violating write returned 400
   `mapper_parsing_exception` and did NOT move the counter, so this counter does
   not reflect that kind of failure at all.)
2. In the bulk build ws3 counts per-item 409s itself. After the soak the
   `normalized.events` `conflicts_409` was 12,083 for the soak while the node's
   `index_failed` ended at 12,085 (+2 from the probe's own two deliberate
   conflicts; the ramp's 845 conflicts were already in the counter at the start of
   the soak). `failed_items` = 0 and `retried_items` = 0.
3. Why 409s happen: `normalized.events` and `scored.events` are written by
   independent threads to the same document id; when the scored copy lands
   first, the normalized create-only write conflicts and is (by design) dropped.
   In the soak that was 12,083 of 43,206 events (28%).

So the 183 were conflicts of the intended kind: noise in an OpenSearch counter,
not lost writes. A dashboard alerting on `index_failed` would false-alarm.

## What this does and does not show

* Measured: zero-infra CPU ceilings per stage and end to end; live-stack
  saturation before (~25 events/s) and after (~75-100 events/s) the bulk change,
  12-minute holds at 20 events/s (before) and 60 events/s (after), consumer-group
  lag, OpenSearch heap and indexing, and where the bottleneck moved.
* Not measured: any rate above 400 events/s offered on the live stack (200 in the
  before run), soaks above 60 events/s, more
  than one replica per service, a multi-node OpenSearch, real WS-1 UDP ingest,
  a Windows/Sysmon-heavy mix, an idle reference host, runs longer than 12
  minutes. **This is not evidence of SIEM-scale (thousands of events/s)
  capacity; the live stack as shipped does not reach it on this host.**
* Next bottlenecks, not fixed here: WS-4's live consume path (~75-100 events/s,
  not CPU-bound, cause not profiled) and the per-document alert CAS path in
  ws3 (slow lag growth at 60 events/s). Nothing has been measured above ~100
  events/s sustained.
