# FENGARDE load test: throughput, latency, saturation

Measured 2026-10-28 on one laptop, commit `33e340f` plus the harness in this
change. Raw outputs: [`raw/`](raw/). Everything below is a measured number for
**this machine only**; nothing here is a statement about SIEM-scale capacity.

**Headline.** On the live stack (Redis bus + OpenSearch), the pipeline sustains
**~20 events/s for 12 minutes with bounded lag, and falls behind from ~25
events/s**. The bottleneck is `ws3-indexer`'s one-HTTP-request-per-document
write path (OpenSearch accepts ~50-58 such PUTs/s here, versus ~4,700 docs/s
via `_bulk`). WS-2 and WS-4 are not the limiter below ~100 events/s. The
zero-infra CPU ceiling is far higher (~900-1,500 events/s end to end for a
realistic mix), so the live number is set by I/O design, not Python speed.

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

### Bottleneck: `ws3-indexer` single-document writes

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
already says the daemon path is deliberately not batched; the batch path
(`run()`, used by tests and `demo_e2e`) is. Why each PUT costs ~17-20 ms on
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
| `index_failed` counter | 183 by end of run (OpenSearch stat; the create-only `normalized.events` writes return 409 when the scored copy won the race, so this is probably expected; not verified) |

20 events/s is the highest rate **tested and held** for >=10 minutes. Rates
between 20 and 25 events/s were not run; 25 events/s showed lag growth in a
60 s window, not a long soak.

## What this does and does not show

* Measured: zero-infra CPU ceilings per stage and end to end; live-stack
  saturation (~25 events/s on this laptop), a 12-minute hold at 20 events/s,
  consumer-group lag, OpenSearch heap and indexing, and the bottleneck.
* Not measured: any rate above ~200 events/s on the live stack (the producer
  was stopped there; offered load beyond that only deepens the backlog), more
  than one replica per service, a multi-node OpenSearch, real WS-1 UDP ingest,
  a Windows/Sysmon-heavy mix, an idle reference host, runs longer than 12
  minutes. **This is not evidence of SIEM-scale (thousands of events/s)
  capacity; the live stack as shipped does not reach it on this host.**
* Likely fix (not done here, out of scope): batch the `ws3-indexer` daemon
  writes via `bulk_index`. The probe suggests ~two orders of magnitude of
  headroom in OpenSearch; the gain end to end would still need a re-run.
