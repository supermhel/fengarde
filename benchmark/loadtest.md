# FENGARDE load test: throughput, latency, saturation

Measured 2026-10-28 on one laptop: "before" at commit `dd6f7d0` (harness on top
of `33e340f`), "after" with the bulk-write change that follows it. Raw outputs: [`raw/`](raw/). Everything below is a measured number for
**this machine only**; nothing here is a statement about SIEM-scale capacity.

**Headline (updated after the second round).** Three live-stack states, same
laptop, isolated compose project:

| | Held for 12 min | Started falling behind |
|---|---|---|
| Original (one PUT per document in ws3, `dd6f7d0`) | 20 events/s | ~25 events/s |
| + ws3 bulk writes (`f734d3a`), 1 WS-4 replica | 60 events/s (alert backlog drifted up) | ~100 events/s |
| + ws3 batched alert writes, **3 WS-4 replicas** | **100 events/s, alert backlog flat** | not found: 200 events/s still kept pace; 300-400 inconclusive (neighbour contention) |
| + single-EVALSHA window ops and capped alert evidence (round three), **1 WS-4 replica** | 150 events/s for 12 min, no loss, lag flat only for the first 6 min (see 5c) | ~170-215 events/s; with 3 replicas ~300 events/s kept pace, then WS-2/Redis saturate near 190-255 (contended host) |

What moved: first the `ws3-indexer` one-request-per-document writes, then the
alert read-modify-write path, and WS-4 turned out to be bound by Redis round
trips of its window counter (4.4 of ~5.7 ms per event), which scale-out
(`--scale ws4-detection=3`, the replica design the global window counter exists
for) removes. The zero-infra CPU ceiling (~900-1,500 events/s end to end) is
still far above the live number. Laptop-scale result only; see the limits at the
end. Sections: 1 zero-infra, 2 original live runs, 3 bulk writes, 4 WS-4
profile, alert batching and replicas, 5 window-op round trips and alert evidence,
6 per-event window batching and WS-2 vs Redis, 7 the 300-800 events/s run and
500 events/s soak (contended host).

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
sources plus one 10-line brute-force burst per 500 events (the zero-infra run
emits 250 alert *messages* per 20,000 events, 1.25%; the live harness stamps every
event "now", so its windows fill much faster and alert messages were ~25% of
events, see section 4d. Alert messages are not alerts: one burst re-emits the
same `alert_id` for every event past the threshold, and 17,940 messages in the
100 events/s soak were only 358 distinct alert documents). **alert-heavy** = the older `fengarde_bench.py` mix where every ssh
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
`triage` is preserved (*superseded by section 4b: alerts are now read and written in bulk*); messages are acked only after the bulk response is known,
per item (failed items stay unacked for redelivery, 429/5xx items are retried
in-process up to `WS3_BULK_RETRIES`=3, a whole-request failure acks nothing);
`WS3_BULK=0` switches the bulk batching off (per-document writes again), but it is not byte-for-byte the old path: the per-document handler now runs `index_doc(..., strict=True)`, so an alert whose CAS retries are exhausted raises `AlertCasExhausted` (left unacked, redelivered, dead-lettered at the cap) where the original code logged and acked it. Contract test:
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

## 4. Round two: WS-4 profile, batched alert writes, WS-4 replicas

### 4a. Why WS-4 stops near 75-100 events/s

`tools/fengarde_ws4_profile.py` runs the real `Detector` one event at a time
against a real Redis (window counter on Redis, as the daemon wires it), from
inside the compose network (`raw/ws4-profile-2026-10-28.txt`):

| WS-4 per-event path | events/s (under cProfile) | ms/event | Redis round trips/event |
|---|---|---|---|
| window counter on Redis (as deployed) | 177 | 5.65 | 1.67 (window ops only) |
| window counter in-process (deque) | 788 | 1.27 | 0 |

So ~4.4 of 5.65 ms per event (78%) is the stateful rules' window-counter calls:
`_evaluate_stateful` is 89% of the profile, mostly `hit_distinct` (1.2 calls per
event: the password-spray / credential-stuffing rules evaluate on every auth
event) and `hit`. Each call is a separate Redis `MULTI` pipeline round trip. The
Redis round trip itself is slow on this host (`tools/fengarde_redis_rtt.py`,
`raw/redis-rtt-2026-10-28.txt`): PING 0.48 ms, the current 4-command `MULTI`
pipeline 1.42 ms, the same four steps as one `EVALSHA` 0.76 ms (the no-`MULTI`
pipeline did not help: 1.42 ms). ws4's container CPU stayed at 55-75% while its
throughput was capped: it waits on Redis; it is not computing.

What I did NOT change: moving the window ops to a Lua script would cut each call
~45% on this host, but `RedisWindowCounter` is shared with ws8 and has five test
fakes built around the pipeline call shape, and other branches are editing it
(`ws8-*`), so it is a separate, riskier change; per-event batching of all rules'
window ops into one pipeline needs an engine restructure. Both are listed under
open items. Instead I measured the supported scale-out: the window counter is
global in Redis precisely so that several WS-4 replicas share one count
(`main.py`, T6 comment), and the work is round-trip-bound, so replicas overlap it.

### 4b. Batched alert writes in ws3

Alert messages used to take the per-document read-modify-write path (GET, then a
conditional PUT, plus a cross-index search for unknown ids), and one burst
re-emits the same `alert_id` for every event past the threshold, so they were the
lagging stream at 60 events/s (lag 1,361 -> 1,779 in the earlier soak). Now a
batch is collapsed to the last payload per `alert_id`, read with one `_mget`,
and the known ids are written as one conditional bulk (`if_seq_no` /
`if_primary_term`) with the analyst's `triage` carried over; a stale version
(someone triaged in between) comes back as a per-item 409 and re-runs the old
per-document CAS path; unknown ids still use the old path (which also does the
routing-drift check). Tests: `test_bulk_handler.py` (triage survives, repeats
collapse to one mget and one conditional item, a triage written during the race
survives, a failed read leaves the alert unacked).

### 4c. Ramps (40 s steps). Neighbour state matters here

A different session's HA proof stack was running during these runs
(`siem-store-ha-*` OpenSearch nodes at 30-99% CPU, `ws8haproof-*`), listed per
run in `raw/neighbours-*.txt`. Treat single steps as noisy.

| Offered ev/s | 1 WS-4 replica: WS-4 read/s, total lag | 3 WS-4 replicas: WS-4 read/s, total lag |
|---|---|---|
| 50 | 49.9, 17 | |
| 75 | 74.8, 47 (alerts lag 0) | |
| 100 | 63.3, 1,180 | 100.1, 10 |
| 150 | 115.5, 2,583 | 151.3, 30 |
| 200 | 78.5, 6,710 | 199.8, 180 |
| 300 | | 105.0, 7,005 (WS-2 itself fell to 119/s) |
| 400 | | 51.1, 20,261 (WS-2 at 58/s) |

One replica again tops out at ~65-115 events/s depending on neighbour load.
Three replicas keep pace through 200 events/s. At 300 and 400 even WS-2, which
the replica count does not touch, fell to 119 and 58 events/s while the
neighbour's OpenSearch nodes were at 60-99% CPU, so those two steps measure the
contended laptop, not the pipeline, and are not a capacity number. After the
400/s step, the backlog drained with WS-4 at ~140 events/s and ws3 at ~380
messages/s.

### 4d. Soak: 100 events/s for 12 minutes, 3 WS-4 replicas

```sh
COMPOSE_PROJECT_NAME=fgloadtest LT_REDIS_PORT=16379 LT_OS_PORT=19200 docker compose -f infra/docker-compose.yml -f infra/docker-compose.loadtest.yml up -d --no-recreate --scale ws4-detection=3 ws4-detection
python tools/fengarde_loadtest_live.py --rates --soak-rate 100 --soak-min 12 --out benchmark/raw/live-soak-alerts-ws4x3-2026-10-28
```

| | 60 events/s soak, bulk only (section 3b) | 100 events/s soak, + alert batching, 3 WS-4 replicas |
|---|---|---|
| Events produced | 43,206 | 72,010 |
| WS-2 / WS-4 rate | 60.0 / 60.0 | 99.7 / 99.6 |
| OpenSearch `events-*` growth | 60.0 docs/s | 99.6 docs/s (99.3-108 per minute) |
| `alerts` stream lag (cg-index) | 1,361 mid-run, 1,779 near end | 0-3 throughout |
| Total lag | ~230 -> ~1,600 plateau, ~2,100 at the end | 52 at start, 19-402 per minute, 424 at the end (event path, transient), cleared 10 s after stop |
| Alert path counters (ws3 `bulk` counters, whole session incl. the ramps, covering the bulk path only) | n/a (per-document) | `bulk_docs` 18,166 in 15,617 bulk requests (~1.16 docs per request); `bulk_docs` counts items AFTER the per-`alert_id` collapse; 0 CAS conflicts, 0 failed, 0 retried (bulk path only, see the note below) |
| Alert messages consumed over the same session | n/a | ~34.5k: the `alerts`/`cg-index` read counter was 16,514 at the start of the soak window and 34,454 at the end (+17,940 in the soak), against 18,166 documents written, i.e. the within-batch collapse removed roughly half of all alert messages before they hit OpenSearch |
| Alert messages in the soak window | n/a | 17,940 messages = 25.1% of the 71,338 events, but only 358 distinct alert documents |
| OpenSearch heap | 71-77% | 66-77% (398 MB max) |
| CPU (mean) | opensearch 87%, ws4 54%, redis 52% | opensearch 64%, ws4 73% (3 replicas summed), redis 43%, ws3 34% |
| `index_failed` vs `conflicts_409` | 12,085 vs 12,083 (+2 probe) | 16,416 vs 16,430 for the whole session (within 14: the two reads were taken a few events apart) |

What the alert-batching numbers do and do not show:

* The collapse of repeated `alert_id`s inside a batch was exercised heavily: about
  34.5k alert messages became 18.2k bulk documents (roughly 1.9 messages per
  document). The ~1.16 documents per bulk *request* is a separate, small number:
  each read pass carries few distinct alert ids, so requests stay small.
* The ws3 counters (`cas_conflicts`, `failed_items`, `retried_items`, `bulk_docs`)
  only count the bulk path. Fresh alert ids and stale-CAS fallbacks go through the
  per-document `_index_alert_preserving_triage` (`get_versioned` + `find_alert_versioned`
  + `index_cas`, one alert at a time, after the bulk), and nothing counts them. So
  "0 CAS conflicts / 0 failed" does not cover those paths; whether the stale-version
  fallback was hit live is unknown. That path, the coalescing of same-id versions,
  the no-resurrection of a cleared triage and the exhausted-CAS no-ack are covered by
  unit tests only (`test_bulk_handler.py`).
* Performance note: because fresh alert ids are written one at a time, a burst of
  *new* alert ids gets no bulk benefit; the batching helps repeats of known ids.

So: 100 events/s held for 12 minutes with no loss, the alert backlog stays flat,
and the node's `index_failed` counter again equals ws3's own 409 count.
Neighbour state during the soak: the other session's HA OpenSearch nodes were at
45-70% CPU at the start and a Sentinel proof at 5-9% per container at the end
(`raw/neighbours-soak.txt`), so these are not idle-host numbers either.

## 5. Round three (stacked on #128): single-EVALSHA window ops, capped alert evidence, 300-600 events/s

Two WS-4 changes, found by profiling WS-4 against the real Redis **bus** (the
section 4a profile used the in-memory bus for produce/ack by mistake:
`fengarde_bench` forces `BUS_BACKEND=memory` at import, so it had missed the
alert path; fixed in `tools/fengarde_ws4_profile.py`):

1. `RedisWindowCounter.hit` / `hit_distinct` run as ONE `EVALSHA` instead of a
   4-command `MULTI` pipeline (same four steps in the same order, atomic like
   `MULTI/EXEC`; pipelines kept for fakes, `use_lua=False`, and Redis < 6.2).
2. `make_alert` read the ENTIRE window zset (`ZRANGE 0 -1`) per alert to cite at most
   50 ids; a 24 h credential-stuffing window holds thousands of values, and on a
   stream where a quarter of the messages are alerts that read was 64% of WS-4's
   per-event time (22.8 of 35.5 s in the profile, 750 `distinct_members` calls).
   `members_capped` does `ZRANGE 0..cap-1` + `ZCARD` in one round trip and returns the
   same ids and the same `omitted` count.

Equivalence evidence: `services/ws4-detection/test_window_lua_live.py` (runs in CI's
redis-integration job; output in `raw/window-lua-parity-2026-10-29.txt`) drives the
original pipelines and the new path side by side on a real Redis: 2,000 randomized
`hit`/`hit_distinct` calls (stale and out-of-order timestamps, repeated members,
short windows so entries age out) must return equal counts and leave identical zsets
and TTLs, the capped read must equal the slice of the full read, and the real
`Detector` over a 549-event stream (bursts, many-source stuffing, many-account
spray, shuffled arrival, then a redelivery pass) must emit identical `alert_id`
sequences (203 alert messages in the first pass, 298 on replay, identical under
both). `test_window_lua.py` (zero-infra, in the gate) pins the call shapes and the
fallbacks. The existing `test_window*.py` suites are unchanged and pass.

### 5a. WS-4 per event (real Redis bus, in-container, 3,000 events, under cProfile)

| Variant | events/s | ms/event |
|---|---|---|
| before: MULTI pipelines + full-window evidence read | 98 | 10.2 |
| + single EVALSHA | 131 | 7.6 |
| + capped evidence read (this change) | 197 | 5.1 |
| window state in-process (no Redis window I/O), for reference | 701 | 1.4 |

Single runs on a shared host; an earlier run of the last configuration gave 294
events/s, so treat the absolute numbers as +-50%, the ordering as solid. EVALSHA
vs the MULTI pipeline on this host (`raw/redis-rtt-2026-10-29.txt`): 0.40 vs 1.27 ms.

### 5b. Live ramps (isolated project, 40 s steps)

Host state, from `raw/neighbours-lua-*.txt`: **not an idle host.** Docker neighbours
were only the idle `infra` dev stack (all services 0-17% CPU, `siem-bus` /
`siem-store` 1-8%), no other compose project, but the Windows host itself ran at
27-65% CPU with 1.1-1.6 GB free RAM (other applications), so these are contended
numbers.

| Offered ev/s | 1 WS-4 replica: WS-4 read/s, lag at step end | 3 WS-4 replicas: WS-4 read/s, lag at step end |
|---|---|---|
| 100 | 100.2, 30 | |
| 150 | 150.3, 49 | |
| 200 | 167.7, 1,352 | |
| 300 | 208.1, 4,682 | 302.4, 279 |
| 400 | 216.0, 12,159 | 255.7, 5,720 (WS-2 at 254.7, raw lag 5,450) |
| 500 | | 190.6, 18,038 (WS-2 at 191.2, raw lag 17,800) |
| 600 | | 252.3, 32,466 (WS-2 at 254.5, raw lag 32,220) |

- **Loss:** none observed. After each step the producer was stopped and the whole
  backlog drained (12,159 messages in 48 s at 259 WS-4 events/s for one replica;
  32,466 in 114 s at 286 events/s for three); the OpenSearch event-doc growth rate
  tracked what WS-2/WS-4 processed, not more.
- **One replica** now keeps pace through 150 events/s (was 60-100) and saturates
  around 170-215 events/s (WS-4 CPU ~55-58%, Redis 55-72%).
- **Three replicas** keep pace at 300 events/s (lag 279) and then saturate at about
  190-255 events/s of *WS-2* throughput: from 400 events/s the lag sits in
  `raw.events` (WS-2's input), not `normalized.events`. At that point WS-2 used
  45-68% CPU, Redis 70-85% and `ws3-indexer` ~47%; WS-2 is one consumer thread and
  Redis is a single thread, and I did not isolate which of the two is the limit.
  The 400-600 steps overlap in time with host CPU rising from 27% to 42%, so the
  decline from 255 to 191 events/s between the 400 and 500 steps is as likely host
  contention as pipeline behaviour; no clean capacity number is claimed above
  ~300 events/s with three WS-4 replicas.

### 5c. Soak: one WS-4 replica, 150 events/s, 12 minutes

| | |
|---|---|
| Produced / WS-2 / OpenSearch event docs | 150.0 / 150.0 / 150.1 per s (108,015 events) |
| WS-4 | 143.4 events/s mean over the window |
| Total lag | 35 at start; **first 6 minutes: 29-616**; second 6 minutes: 542-2,701, 4,852 at the end (all in `normalized.events`/`cg-detect`; `raw.events` and `alerts` ~0); cleared 32 s after the producer stopped |
| Neighbours at the end of the run | host CPU 65%, `infra-ws9-resolver` 42%, `siem-store` 37%: the idle dev stack woke up during the second half |
| `index_failed` vs ws3 `conflicts_409` | 11,018 vs 11,018 (exact), `failed_items` 0, `cas_conflicts` 0 |
| CPU (mean) | opensearch 80%, redis 60%, ws4 55%, ws3 46%, ws9 48%, ws2 34% |

So 150 events/s sustained with no loss for 12 minutes, but **not a flat-lag hold**:
one replica is at its edge there (lag flat for six minutes, then growing while the
host got busier). The earlier 100 events/s soak needed three replicas; one replica
now holds 100 (ramp) comfortably and 150 marginally.

## 6. Round four (stacked on #132): one Redis round trip per event for all window ops; what limits above ~250 events/s

### 6a. Per-event batching of window ops

`Detector.process` used to call each stateful rule's `evaluate()` in turn, one Redis
round trip per rule. It now plans every count/distinct stateful rule's window op first
(`Rule.begin_evaluate`), sends them all with `RedisWindowCounter.hit_many` (one
non-transactional pipeline of the same `EVALSHA`s, in rule order), then finishes each
rule (`finish_evaluate`). Window keys include the rule id, so the ops are independent and
the batch leaves the same state and verdicts as the sequential loop. Periodic (beacon)
rules, a different counter object, stateless rules and any rule whose `evaluate` was
replaced on the instance keep the plain path; `FENGARDE_WINDOW_PIPELINE=0` switches the
batching off.

Equivalence evidence: `test_window_pipeline.py` (zero-infra, in the gate): per-event
matched rule ids and final window state equal between sequential and batched evaluation,
one `hit_many` per event, same total number of window ops. `test_window_lua_live.py`
(CI redis-integration; `raw/window-pipeline-parity-2026-10-29.txt`) on a real Redis:
549 events twice (shuffled, bursts, many-source stuffing, many-account spray): identical
per-event matched rules, identical `alert_id` sequence (298 alert messages), and 2,175
identical window zsets (members, scores, TTLs within 2 s) between `seq` and `pipe`.

Per event, real Redis bus, in-container, 3,000 events, alternating A/B on the same
stack (`raw/ws4-profile-pipeline-ab-2026-10-29.txt`):

| `FENGARDE_WINDOW_PIPELINE` | events/s (cProfile) | ms/event | Redis round trips/event |
|---|---|---|---|
| 0 (sequential) | 447, 486 | 2.24, 2.06 | 2.68 |
| 1 (batched) | 517, 572 | 1.93, 1.75 | 1.83 |

So about +16% events/s and -32% round trips. (The absolute numbers are higher than the
section 5a profile because the host was quieter this time; compare only within this
table.)

### 6b. Is WS-2 or Redis the limit above ~250 events/s? Controlled experiments

Host during these runs: Windows host CPU 20-37% (was 27-65% before), 1.0-1.6 GB free
RAM; Docker neighbours only the idle `infra` stack (`raw/neighbours-*.txt`). Still not a
verified-idle host.

**E1, WS-2 alone** (`tools/fengarde_ws2_isolate.py`, `raw/ws2-isolate-2026-10-29.json`):
ws3/ws4/ws5/ws8/ws9 stopped, a 30,000-event backlog prefilled on `raw.events`, K WS-2
replicas drain it:

| WS-2 replicas | drain rate (events/s) | WS-2 CPU (per replica) | Redis CPU mean / max | Redis ops/s mean / max |
|---|---|---|---|---|
| 1 | 1,346 (second run 1,144) | 60% / 65% | 21% / 30% | 2,584 / 3,870 |
| 2 | 1,707 | 63% | 28% / 38% | 3,231 / 5,885 |
| 3 | 1,740 | 49% | 33% / 52% | 4,051 / 6,691 |

One WS-2 process normalizes ~1,150-1,350 events/s when nothing else competes (5x the
~250 it showed inside the full ramp), and going from 2 to 3 replicas adds almost
nothing (1,707 -> 1,740) while Redis sat at 33% CPU and no slowlog entry appeared:
neither WS-2's own code nor Redis was the limit at 250 events/s. (`redis-benchmark`
inside the container: 69,500 XADD/s with 8 clients, 222,800/s pipelined by 16; PING 48,000/s.)

**E2, full pipeline, WS-4 x3, WS-2 x1 vs x2** (40 s steps, `raw/live-ramp-pipeline-ws2x{1,2}-*`):

| Offered ev/s | WS-2 x1: WS-2 / WS-4 read/s, raw lag | WS-2 x2: WS-2 / WS-4 read/s, raw lag |
|---|---|---|
| 300 | 289 / 288, 360 | 300 / 300, 0 |
| 400 | 400 / 400, 39 | 400 / 401, 0 |
| 500 | 394 / 395, **3,850** | 500 / 500, 49 |

Redis in these runs: 7,300-10,800 ops/s mean (peaks 13-14k) at 300-500 events/s,
CPU 49-88% of a core, slowlog (commands over 10 ms) 31-45 entries cumulative. After the
x1 run stopped, the 4,036-message backlog drained in 12 s.

What the evidence says, in order of how firmly:

* **Measured:** a single WS-2 replica holds 400 events/s and falls behind at 500
  (394/s processed, raw lag 3,850); two replicas hold 500 events/s with WS-4 x3
  (lag 49). Nothing was lost in either run (every backlog drained). The previous
  round's ~190-255 events/s ceiling with three WS-4 replicas did not reproduce on the
  quieter host with batched window ops: 300 and 400 events/s are now held with one WS-2.
* **Measured:** WS-2 is not intrinsically slow (E1: 1,150-1,350 events/s alone). Its
  ~400 events/s ceiling inside the full pipeline is a contention effect: the same process
  slows ~3x when ws3, 3 WS-4 replicas, OpenSearch and Redis share the CPUs.
* **Measured, not conclusive:** Redis is not saturated by operation count (13-14k ops/s peak
  vs a 69.5k XADD/s ceiling) but ran at 78-88% of a core at 500 events/s with 10-67 ms
  stalls in the slowlog, and its heaviest commands by total time were `EVALSHA`
  (245k calls, 50 us each, 12.3 s), `XREADGROUP` (120k calls, 80 us, 9.7 s) and `XADD`
  (1.04M calls, 9 us, 9.1 s; `raw/redis-commandstats-2026-10-29.txt`). So Redis is the
  next resource to saturate but I did not push it to saturation: no run above 500 events/s
  was made.
* **Not shown:** which resource saturates first above 500 events/s; whether the ~3x
  slowdown of WS-2 under load is CPU contention in the Docker VM or Redis queueing (no
  per-core accounting inside the VM).

## 7. 300-800 events/s run (CONTENDED host: not idle)

Run 2026-10-29 15:44-16:09 UTC after the owner confirmed no other session was running
anything. **The host was not idle and this is a contended run.** Pre-run check:
`docker ps` showed only this project plus the owner's `infra` dev stack (all services
under 5% CPU); the Windows host was at 62% CPU with 1.7 GB free RAM, top processes
Explorer, a mouse-mover utility, two old Python processes (started 15 Oct), Chrome, the
Claude desktop app, Hermes and Docker Desktop. I closed nothing that was not mine. A
5-second host log across the whole run (`raw/hostcpu-idle-run-2026-10-29.txt`, 243
samples): mean 78% CPU, min 14%, max 100%, free RAM 0.6-1.7 GB; around the individual
runs the instantaneous readings were 10-28% (`raw/neighbours-idle-*.txt`). Treat all
numbers below as lower bounds of what an idle machine would do.

Config: WS-2 x2, WS-4 x1 then x3, ws3/5/8/9 x1, OpenSearch 512 MB heap, 40 s steps.

| Offered ev/s | WS-4 x1: WS-4 read/s, `normalized` lag at step end | WS-4 x3: WS-2 / WS-4 read/s, total lag at step end |
|---|---|---|
| 300 | 286, 440 | 299 / 300, 50 |
| 400 | 353, 2,398 | 400 / 401, 124 |
| 500 | 347, 7,559 | 499 / 497, 756 |
| 600 | 329, 18,250 | 557 / 431, 9,386 (raw lag 2,780, normalized 4,220) |
| 800 | 282, 37,859 | 707 / 555, 21,100 (raw lag 6,060, normalized 10,628) |

* **No loss at any rate:** every backlog drained after the producer stopped (38,191
  messages in 102 s for x1; 21,100 in 42 s for x3).
* **One WS-4 replica** saturates around 330-350 events/s (WS-4 CPU 48-58%: it waits on
  Redis, as in section 5); **three** keep pace through 500 events/s and saturate between
  500 and 600.
* **Which resource saturates first:** at 500 events/s Redis is at 66-89% of a core (13.7k
  ops/s) and at 600-800 events/s it is at 78-87% while WS-2 (2 replicas, 84-90% summed)
  and WS-4 (3 replicas, 98-119% summed) both start to fall behind together. That
  pattern (neither consumer pegged, Redis highest and stalled commands in the
  slowlog) points to the single-threaded Redis as the shared limit above ~500
  events/s, but with this contended host I cannot separate it from CPU shortage in
  the Docker VM, and I did not run `redis-benchmark` while the full load was on.

### 7a. Soak: 500 events/s for 12 minutes (WS-2 x2, WS-4 x3)

```sh
python tools/fengarde_loadtest_live.py --rates --soak-rate 500 --soak-min 12 --out benchmark/raw/live-soak-idle-500-2026-10-29
```

| | |
|---|---|
| Produced / WS-2 / WS-4 / OpenSearch event docs | 500.0 / 500.0 / 500.0 / 500.1 per s (360,050 events): no loss |
| Event path lag (`raw`, `normalized`, `scored`) | 0-60 throughout |
| **Total lag** | 185 at start -> **14,251 at the end, growing ~1,150 messages per minute**; cleared 54 s after the producer stopped |
| Where the lag sits | the `alerts` stream, consumer group **`cg-correlate` = WS-8 correlation** (2,549 -> 5,809 -> 13,985 across the run); every other group stayed at 0-30 |
| Redis | 94% of a core mean, 13,451 ops/s mean (17,496 max), 441 MB (streams held back by the lagging WS-8 group), 92 slowlog entries |
| Other CPU (mean) | WS-4 x3 120% summed, opensearch 87%, WS-2 x2 63% summed, ws3 55%, ws9 60%, ws8 49% |
| `index_failed` vs `conflicts_409` | 67,365 vs 67,398 (within 33; the two reads were taken seconds apart) |
| ws3 bulk counters | `failed_items` 0, `retried_items` 0, `cas_conflicts` 0 on every topic |

So **500 events/s is held on the event path for 12 minutes without loss, but not as a
steady state:** WS-8 (one replica, ~49% CPU) falls behind on alert messages (about a
quarter of events at this mix, ~125/s) and its backlog grows linearly. It is the first
consumer to fall behind in this configuration, and Redis, at 94% of a core, is the
other resource close to its limit. WS-8 was not scaled or profiled here.

## What this does and does not show

* Measured: zero-infra CPU ceilings per stage and end to end; live-stack
  saturation at each stage (~25, ~100, and 200+ events/s with 3 WS-4 replicas),
  12-minute holds at 20, 60 and 100 events/s, consumer-group lag, OpenSearch
  heap and indexing, and where the bottleneck moved each time.
* Not measured: any clean rate above 200 events/s on the live stack, soaks above
  100 events/s, more
  than one replica per service, a multi-node OpenSearch, real WS-1 UDP ingest,
  a Windows/Sysmon-heavy mix, an idle reference host, runs longer than 12
  minutes. **This is not evidence of SIEM-scale (thousands of events/s)
  capacity; the live stack as shipped does not reach it on this host.**
* Next bottlenecks, not fixed here: WS-8 correlation falls behind on the `alerts`
  stream at 500 events/s (single consumer, lag growing ~1,150 messages/min) and Redis
  (one thread) is at 94% of a core there; no run above 800 events/s offered, no run
  on a verified-idle host (the 300-800 events/s run in section 7 had a host mean of 78%
  CPU), WS-2 vs Redis above 500 events/s not separated.
* Scale-out caveat: with several WS-4 replicas the same consumer group is shared,
  so events of one source are no longer processed strictly in order. The global
  Redis window counter makes the threshold count correct, and alert ids are
  deterministic (idempotent), but strict per-source ordering is not preserved.
