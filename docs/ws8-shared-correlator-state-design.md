# WS-8 shared correlator state - design (2026-10-28)

Problem: per-track tactics/first_seen, member entries (score, time, cooccur) and the
incident cache lived in process memory; only window membership lived in Redis. After a
restart members were counted but tactics gone; two replicas each saw half the tactics.

Design (`services/ws8-correlation/track_state.py`):

- `TrackState` interface with two backends: `MemoryTrackState` (default, the old dicts,
  `Correlator._sides/_side_meta` still alias them) and `RedisTrackState`. Selected in
  `main.make_correlator()` exactly like the window counter: `BUS_BACKEND` in
  {redis, redis-sentinel} -> Redis, else memory. Same client, same `decode_responses`.
- Keys (namespace `ws8:state`, distinct from the window zsets `ws8:corr:*`), per track key K:
  - `ws8:state:side:K` HASH member_id -> JSON entry (alert_id, tactic, score, time,
    time_fallback, event_id, cooccur, typed_signal)
  - `ws8:state:meta:K` HASH first_seen (min), truncated ("1")
  - `ws8:state:tac:K`  SET of every tactic ever seen on the track
  - `ws8:state:inc:ID` STRING claim marker for an incident id
  All track keys get EXPIRE horizon_s+1 on every touch (same TTL basis as the window zset),
  so abandoned tracks self-delete; no sweep needed on Redis.
- Atomicity: one Lua `record` script per alert (HSET entry, first_seen = min, SADD tactic,
  EXPIRE x3). Every write is commutative/idempotent (entry keyed by deterministic member id,
  min, set-add), so replicas racing on one track converge to the union regardless of order.
- Race rule: read side BEFORE window members (window.hit happens before record, so any entry
  seen in the side snapshot is already in the later-read window; a replica never prunes a
  peer's fresh entry as "stale"). Prune (HDEL stale / cap-evict oldest) is idempotent.
- Incident ids stay deterministic (tenant:type:value:bucket(first_seen)), so two replicas
  that both promote emit the SAME id; WS-3's CAS collapses them to one document. No
  distributed lock needed. `claim_incident` (SET NX EX) makes `is_new`/promotions_total
  count once per incident across replicas instead of once per replica.
- Restart: the next alert for the track reads tactics/members from Redis, so promotion
  happens as if no restart. Graph cache (`_incident_graphs`, `_graph_sigs`) is derived and
  stays process-local; it is rebuilt from the shared side table after a restart.
- Failure: a Redis error raises out of the handler -> runner leaves the message unacked ->
  redelivery re-records the same member id (idempotent). Same path as #124's Sentinel work.
- Sticky incident id (2026-10-28, closes the old horizon-boundary limit): the id was `bucket(first_seen)` and
  `first_seen` is the min over what has been recorded so far, so two alerts of one chain whose stamps straddle a
  horizon boundary, arriving out of order, could mint two ids (one before, one after the early alert landed),
  on one replica or two. Fix: the id is bound to the TRACK, not recomputed. `TrackState.bind_incident_id(track,
  candidate)` stores the first candidate (Redis `SET NX EX`, key `ws8:state:cid:<track>`, same TTL basis as the
  track; memory: a dict dropped with the track) and returns the stored one, so every replica and every
  redelivery emits the id the first promoter minted. Race: two replicas promoting at once both offer a
  candidate, SET NX picks one, both read it back. `first_seen` in the payload stays the true min.
- Trade-off: the id is now fixed by the FIRST promotion's `first_seen` bucket, not by the final min, so it is
  order-dependent across different arrival orders of the same alert set (it was already, between promotions);
  it is identical across replicas and redeliveries, which is what WS-3's CAS needs. A track that goes idle past
  the TTL starts a new id, as before.

## Live proof (2026-10-28, isolated compose project ws8proof, plain Redis 7)

```
### A. restart survival: tactic 1 -> kill ws8 -> restart -> tactic 2
ws8:state:side:acme:actor:alice
ws8:state:meta:acme:actor:alice
ws8:state:tac:acme:actor:alice
acme:actor:alice:20754 ['TA0006', 'TA0008'] members=2
RESULT A: PASS (incident formed across a restart)
### B. two replicas share state: 10 chains, alerts split across both replicas
name cg-correlate-1-139624280790720 pending 0 idle 402 inactive 18723 
name cg-correlate-1-139679019288256 pending 0 idle 299 inactive 14108 
name cg-correlate-1-140667156129472 pending 0 idle 128733 inactive 136984 
distinct incident ids for 10 chains: 10 ; emissions with both members: 10
RESULT B: PASS (one incident per chain, 2 members each)
```

## Live proof, Sentinel path (2026-10-28, isolated project ws8sentproof)

`infra/docker-compose.ws8-sentinel-proof.yml`: 1 primary + 2 replicas + 3 Sentinels (same flags, static IPs and
`redis-sentinel-entrypoint.sh` as `docker-compose.ha.yml`), two ws8 replicas, `BUS_BACKEND=redis-sentinel`,
`WS8_TRACE_ALERTS=1`. The per-alert lines (`  b-N-x -> [replica]`) are trimmed here; the script prints all 40.

```
master at start: 172.29.88.11
ws8a: track_state": "RedisTrackState"
ws8b: track_state": "RedisTrackState"

### B. two replicas, per-alert trace (20 chains = 40 alerts)
alerts traced: 40; per replica: {'ws8a': 23, 'ws8b': 17}; chains split across replicas: 13 [1, 2, 4, 5, 6, 7, 10, 11, 12, 13, 17, 18, 20]
distinct incident ids: 20 ; emissions with both members: 20
RESULT B: PASS (both replicas handled alerts, 13
 chains had their tactics on different replicas, one incident per chain)

### A. kill the Redis MASTER between the two tactics
ws8b {"ts": "2026-10-28T11:09:17Z", "level": "info", "service": "ws8-correlation", "trace_id": "1793185757948-0", "msg": "handled alert", "alert_id": "c-1", "replica": "35bc440bf304"}
state keys for carol before the kill:
['ws8:state:meta:acme:actor:carol', 'ws8:state:side:acme:actor:carol', 'ws8:state:tac:acme:actor:carol']
 Container ws8sentproof-redis-1-1 Killing 
 Container ws8sentproof-redis-1-1 Killed 
redis-1 (master 172.29.88.11) KILLED at 12:09:29
new master: 172.29.88.12 (after ~2s of polling)
ws8a {"ts": "2026-10-28T11:09:39Z", "level": "info", "service": "ws8-correlation", "trace_id": "1793185777486-0", "msg": "handled alert", "alert_id": "c-2", "replica": "b33b00e6f8e9"}
acme:actor:carol:20754 ['TA0006', 'TA0008'] members=2
carol emissions=1 distinct incident ids=1
RESULT A: PASS (master killed mid-chain, failover to 172.29.88.12, one incident id with 2 members, emissions=1)
```
Closed by the sections below (full stack, load, outage).

## Live proof, failover under load (2026-10-28, isolated project ws8sentproof)

`python tools/ws8_failover_load_proof.py load --chains 350 --kills 4`: 350 two-alert chains (700 alerts, steady ~9.5/s, 74 s)
produced through the real bus while the Redis MASTER is killed four times (the killed node is restarted 3 s later and rejoins as a
replica), two ws8 replicas, HA-profile Redis/Sentinel topology. Chains are counted only if both alerts reached the bus, so
bus-level loss is separated from ws8 correctness.

```
[13:49:16] KILL 1/4: master 172.29.88.11 (redis-1)
[13:49:22]   new master 172.29.88.12 after 5.6s
[13:49:31] KILL 2/4: master 172.29.88.12 (redis-2)
[13:49:35]   new master 172.29.88.13 after 4.0s
[13:49:46] KILL 3/4: master 172.29.88.13 (redis-3)
[13:49:51]   new master 172.29.88.11 after 5.5s
[13:50:01] KILL 4/4: master 172.29.88.11 (redis-1)
[13:50:07]   new master 172.29.88.12 after 5.4s
[13:50:15] producer: {'acked': 700, 'failed': [], 'producer_retries': 0, 'seconds': 74.0}
[13:51:10]   drain: ok=350/350 pending=0 emissions=351
[13:51:22]   drain: ok=350/350 pending=0 emissions=351
[13:51:33]   drain: ok=350/350 pending=0 emissions=351
SUMMARY chains=350 eligible=350 ok=350 lost=0 forked_ids=0 wrong_members=0 bus_lost_alerts=0 duplicate_alert_msgs=0 incident_ids=350 emissions=351 kills=4 producer_failed=0
RESULT load: PASS
```

Detail (`incident_emissions` 351 vs 350 ids = one alert left pending by a failover and reclaimed after the 60 s idle limit; re-handled
under the same id, so WS-3's CAS sees one document): `{"chains": {"eligible": 350, "ok": 350, "lost": 0, "forked": 0, "wrong_members": 0, "bus_lost_alerts": 0}, "lost_chains": [], "forked_chains": [], "wrong_member_chains": [], "alert_messages_in_stream": 700, "duplicate_alert_messages": 0, "incident_ids": 350, "incident_emissions": 351, "extra_emissions_same_id": 1, "groups": [{"name": "cg-correlate", "pending": 0, "lag": 0, "entries-read": 700}], "producer": {"acked": 700, "failed": [], "producer_retries": 0, "seconds": 74.0}}`

Same load, same topology, the PRE-CHANGE ws8 image (commit 33e340f, window membership in Redis but tactics/scores in process memory):

```
SUMMARY chains=350 eligible=350 ok=238 lost=112 forked_ids=0 wrong_members=0 bus_lost_alerts=0 duplicate_alert_msgs=0 incident_ids=238 emissions=238 kills=4 producer_failed=0
```
112 of 350 chains never promoted: their two tactics landed on different replicas, so neither replica held both.
Limits: ~9.5 alerts/s for 74 s with four failovers; the producer saw 0 errors with the shared state (4 retried produce calls in
the pre-change run), so this does not show behaviour at higher rates or with the full app stack under load.

## Live proof, both Redis replicas lost (2026-10-28, isolated project ws8sentproof)

`python tools/ws8_failover_load_proof.py outage`: first tactic processed; ws8a/ws8b stopped; second tactic produced; BOTH replicas
killed, so the primary (`redis-1`; at the time of that run the only node started with `--min-replicas-to-write 1`, since fixed, see the follow-up section) refuses writes; ws8 started against it
and observed for 40 s; replicas restarted. (An earlier attempt used `docker compose start`, which also started the killed
replicas through `depends_on`; the script now uses `docker start`.)

```
[13:58:29] master=172.29.88.11; sending the first tactic and letting it complete
[13:58:41] primary refuses writes (NOREPLICAS) after 0.6s
[13:59:25] ws8 containers during the outage: {'ws8a': 'running restarts=0 exit=0', 'ws8b': 'running restarts=0 exit=0'}
[13:59:25] alerts consumer group during outage: name cg-correlate consumers 2 pending 0 last-delivered-id 1793192310760-0 entries-read 1 lag 1 
[13:59:27] ws8 error/warn lines during outage: 16; sample: Traceback (most recent call last):
[13:59:40] incident after recovery (11s): "acme:actor:dave:20754 ['TA0006', 'TA0008'] 2"
[13:59:46] alerts group after recovery: [{"name": "cg-correlate", "pending": 0, "lag": 0, "entries-read": 2}]
SUMMARY primary_refused_writes_after=0.6s ws8_during={'ws8a': 'running restarts=0 exit=0', 'ws8b': 'running restarts=0 exit=0'} incidents_stream_len_during=0 error_lines_during=16 incident_after_recovery="acme:actor:dave:20754 ['TA0006', 'TA0008'] 2" ws8_after={'ws8a': 'running restarts=0', 'ws8b': 'running restarts=0'}
RESULT outage: PASS
```
During the outage the second alert stayed unread and unacked (group lag 1, pending 0), ws8 logged `NOREPLICAS` tracebacks and kept
running (0 restarts); after recovery it was consumed once and the incident formed with both tactics.

## Live proof, full docker-compose.ha.yml stack (2026-10-28, isolated project ws8haproof)

`docker-compose.ha.yml` + `infra/docker-compose.ws8-ha-proof.yml` (host ports/fixed names/heap only), ws1..ws9, Redis primary + 2 replicas
+ 3 Sentinels, 3-node OpenSearch. `python tools/ws8_ha_stack_proof.py`: 20 denied ports then 12 ssh failures from one source IP,
as raw events into ws2; ws8 killed between the two tactics.

```
[14:07:08] OpenSearch cluster: status=green nodes=3
[14:07:08] Redis master via Sentinel: 172.28.0.11
[14:07:09] ws8 startup: _id": "-", "msg": "window counter selected", "backend": "redis-sentinel", "counter": "RedisWindowCounter", "track_state": "RedisTrackState"}
[14:07:09]   ws1-collectors: running/healthy
[14:07:09]   ws2-normalization: running/healthy
[14:07:09]   ws3-indexer: running/healthy
[14:07:10]   ws4-detection: running/healthy
[14:07:10]   ws5-ai: running/healthy
[14:07:10]   ws6-inventory: running/healthy
[14:07:10]   ws7-dashboard: running/healthy
[14:07:11]   ws8-correlation: running/healthy
[14:07:11]   ws9-resolver: running/healthy
[14:07:11] tenant ws8ha-261b3450: tactic 1 = port scan (20 denied ports from 203.0.113.9)
[14:07:17] port-scan alert indexed after 5s
[14:07:17] alert: {'alert_id': '1d2c3b4a-5e6f-4708-8a91-0b1c2d3e4f05:ws8ha-261b3450:11:203.0.113.9:29886546', 'rule_id': '1d2c3b4a-5e6f-4708-8a91-0b1c2d3e4f05', 'mitre': {'tactic': 'TA0007', 'technique': 'T1046'}}
[14:07:17] incident docs after tactic 1: 0 (a single tactic must not promote)
[14:07:17] killing ws8-correlation between the two tactics
[14:08:16] ws8 state: running restarts=0
[14:08:16] tactic 2 = ssh brute force (12 failures from 203.0.113.9)
[14:08:23] ip incident indexed after 5s
[14:08:23] alerts indexed: [('1d2c3b4a-5e6f-4708-8a91-0b1c2d3e4f05', 'TA0007'), ('1d2c3b4a-5e6f-4708-8a91-0b1c2d3e4f05', 'TA0007'), ('6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01', 'TA0006'), ('6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01', 'TA0006')]
[14:08:23] incident doc(s): [{'incident_id': 'ws8ha-261b3450:ip:203.0.113.9:20754', 'entity_type': 'ip', 'entity_value': '203.0.113.9', 'tactics': ['TA0006', 'TA0007'], 'member_count': 4}]
```
ws8 reported 4 member alert ids, all of which are indexed alert documents (the script checks this); each rule shows two alert documents,
which was not investigated further here. The `docker kill` of ws8 was followed by the script waiting up to 40 s for the restart policy and then
starting the container itself, so the restart count of 0 does not show a policy restart.

## Follow-up live proofs (2026-10-28): min-replicas on every node, 3/4 replicas, full stack under load

**HA config gap closed.** Only `redis-1` used to carry `--min-replicas-to-write 1`; a replica ignores the setting while replicating and
enforces it when promoted, so after a failover the new master would have accepted unreplicated writes. redis-2/redis-3 now carry the
same flags (`docker-compose.ha.yml`, `docker-compose.ws8-sentinel-proof.yml`) and `tools/check_ha_min_replicas.py` (wired into
`run_all_tests.sh`, with a self-test) fails when a `redis-server` line lacks them.
`ws8_failover_load_proof.py promoted`: flags on all three nodes read back as 1; two promotions (redis-1 -> redis-3 in 4.9 s, redis-3 ->
redis-2 in 4.3 s, killed node restarted and re-synced each time); the promoted master accepted a write with two replicas, then returned
`NOREPLICAS` 0.8 s after both replicas were killed. Control (same node with the flag forced to 0, i.e. what an unflagged node does):
write accepted. `ws8_failover_load_proof.py outage` against that promoted master (redis-2): refused after 0.8 s, ws8a/ws8b 0 restarts,
16 error lines, second alert unread and unacked (lag 1, pending 0), one incident `[TA0006, TA0008]` with 2 members after recovery, group lag 0 / pending 0.

**3 and 4 ws8 replicas** (`load --chains 350 --kills 4 --rate 10`, 74 s, fresh stack per run): 3 replicas ok 350/350, lost 0, forked ids 0,
wrong member sets 0, 700 alerts handled once each (207/297/196 per replica), 179 chains had their tactics on different replicas; 4 replicas
ok 350/350, lost 0, forked 0, wrong 0, 187/234/94/185 per replica, 183 split chains; duplicate alert messages 0; 350 incident ids and 350
emissions in both runs; failover 3.6-5.7 s (3 replicas) and 4.4-5.3 s (4 replicas), on the proof-compose Sentinel settings down-after 3000 / failover-timeout 10000 (the shipped HA compose uses down-after 5000 / failover-timeout 20000).

**Full HA stack under load** (`tools/ws8_ha_load_proof.py`; stack beside the dev stack; two ws8 replicas; chains injected on `alerts`, plus 100
benign background raw events through ws2 -> ws4 -> ws3 (target 100/s, 261-1950 sent per run; no alerts come from them, the chains' alerts are injected into `alerts`); 3 master kills per run, Sentinel at the HA-compose settings of that time, down-after 5000 / failover-timeout 20000; verdict read from OpenSearch because `shared/bus.py trim_acked` removes
acked stream prefixes):

| target alerts/s | achieved | chains | lost | forked ids | wrong members | alerts indexed/acked | split chains | failovers (s) |
|---|---|---|---|---|---|---|---|---|
| 20 | 10.1 | 160 | 0 | 0 | 0 | 320/320 | 39 | 5.0, 5.5, 5.1 |
| 50 | 17.4 | 400 | 0 | 0 | 0 | 800/800 | 151 | 6.8, 7.4, 6.4 |
| 100 | 10.4 | 800 | 0 | 0 | 0 | 1600/1600 | 364 | 2.9, 5.8, 44.9 |

Where it breaks: not in correctness. The producers (docker-exec Python on the same 8-CPU / 7.4 GB host as ~25 containers, 3 OpenSearch nodes)
could not reach the target rate, and ws3 indexing lags far behind ws8 under backlog (ws8 had emitted 1200 incident ids while ws3 had indexed a
few hundred documents); the pipeline drained to lag 0 / pending 0 each time. Sentinel failover stretched to 44.9 s once under CPU
saturation (split vote), and an aborted earlier 100/s attempt saw a failover not complete within 65 s three times. ws8 replicas handled more
alert deliveries than alerts (e.g. 1846 for 1600) because unacked messages are reclaimed after a failover; no duplicate incident ids resulted.
Harness bugs found and fixed along the way: a failed OpenSearch read was counted as "0 documents" (one invalid 50/s run reported 400 lost
chains while OpenSearch held all 400 incidents), and the bus streams cannot be used as the verdict after the drain.

(The not-proven items of this section were worked in the second round below; what remains is listed there.)

## Second round (2026-10-28): real high rates, 6/8 replicas, Sentinel failover distribution

**Generator fixed.** The first-round producers (one `Bus.produce` per alert from `docker exec` Python) topped out at 10-17 alerts/s. They now pipeline
XADD of the same `{key, payload}` shape straight into the `alerts` stream (`tools/ws8_ha_load_proof.py`, 3-12 processes, catch-up batches), so the target
rate is actually driven. Same full HA stack, 2 ws8 replicas, benign background raw events through ws2 -> ws4 -> ws3 (target 100/s, 350-1950 sent per run; the chains' alerts are injected straight into `alerts`), 3 master kills per run at down-after 5000 / failover-timeout 20000, verdict from OpenSearch:

| target alerts/s | achieved | chains | lost | forked ids | wrong members | alerts indexed/acked | split chains | failovers (s) | producer retries |
|---|---|---|---|---|---|---|---|---|---|
| 50 | 49.7 | 400 | 0 | 0 | 0 | 800/800 | 135 | 2.4, 6.2, 7.1 | 22 |
| 100 | 99.4 | 800 | 0 | 0 | 0 | 1600/1600 | 275 | 5.6, 45.5, 6.1 | 8 |
| 200 | 200.0 | 1600 | 0 | 0 | 0 | 3200/3200 | 620 | 5.9, 2.0, 6.0 | 26 |
| 400 | 229.4 | 3200 | 0 | 0 | 0 | 6400/6400 | 1427 | 4.9, 1.7, 7.6 | 234 |

The 400 target was not reached: producers ran 25-28 s instead of 16 s; at that point the producer container (ws2) sat at 82% CPU and the OpenSearch nodes at
~120% each, host total ~520% of 800%. The limiting resource was not isolated beyond that sample. During the 100-400 runs another session's Docker stack
(`fgloadtest-*`, its OpenSearch ~115% CPU) shared the host, so these are not clean-room numbers. The pipeline drained to lag 0 / pending 0 after each run.

**6 and 8 replicas** (`load --chains 350 --kills 4 --rate 10`, fresh stack per run): 6 replicas ok 350/350, lost 0, forked 0, wrong 0 (alerts per replica
65/142/146/53/142/153), 202 chains split across replicas, 1 alert delivered to two replicas; 8 replicas ok 350/350, lost 0, forked 0, wrong 0
(46/35/130/320/41/45/43/42), 194 split chains, 2 alerts on two replicas, 351 emissions for 350 ids (one reclaimed redelivery, same incident id).
Failovers 3.5-6.2 s.

**Sentinel failover under CPU saturation.** `tools/ws8_sentinel_failover_dist.py`: 3 Redis + 3 Sentinels, 16 busy-loop containers on the 8-CPU host, kill the master, time
until the new master accepts a write (includes ~3-4 s of `docker exec` probe overhead; Sentinel's own `+switch-master` was ~6 s), restart, wait for resync, 12 rounds per config.

| down-after / failover-timeout | min | median | p90 | max | `-failover-abort-not-elected` | TILT |
|---|---|---|---|---|---|---|
| 5000 / 20000 (shipped default) | 8.7 | 10.2 | 11.5 | 50.8 | 3 log lines (rounds not counted) | not counted |
| 5000 / 5000 (candidate, unproven) | 9.9 | 10.65 | 11.9 | 22.6 | 3 log lines (rounds not counted) | not counted |

What this shows and does not show: the 44.9 s, 45.5 s and 50.8 s outliers fit a split vote (Sentinels reach ODOWN within milliseconds of each other, nobody is elected, the retry is gated at 2x failover-timeout = 40 s at 20000). The abort lines were counted in total, not per round, so which rounds aborted is not established; the script now counts aborts and TILTs per round. A 20-round rerun per config was started and aborted because another session's load stretched every round to 2-3 minutes. With 12 rounds each the median is the same and the worst round was shorter with 5000 (22.6 s vs 50.8 s), which is not enough to claim an improvement; the shipped default therefore stays failover-timeout 20000 and 5000 is an unproven candidate (it also bounds replica reconfiguration time, untested with large datasets). ws8's reconnect is not the limiter (it follows the master change).

Remaining limits: other hardware (cannot be closed on this host); the 400 alerts/s target (229.4 reached); whether failover-timeout 5000 beats 20000; more than 8 replicas.

## Hot track and ws8 consume rate (2026-10-28, review follow-up)

ws8 alone, 2 replicas, 3000 alerts injected straight into `alerts` as fast as one pipeline writes (`tools/ws8_hot_track_cost.py`, shared host, another session's load running): every alert its own actor (1-member tracks) drained at 105.5 and 50.2 alerts/s; every alert on ONE actor (one track at the member cap of 200, both replicas hitting it) drained at 17.9 and 13.7 alerts/s, i.e. 3-8x slower (each alert reads the whole side table: HGETALL + json.loads of up to 200 entries), and emitted ~3000 incident updates for the one incident. So the per-alert cost is O(member_cap) and a hot track limits ws8 to roughly 14-18 alerts/s on this host with two replicas; the 200 alerts/s full-stack runs used one track per alert pair and say nothing about hot tracks.

`achieved` in the load tables is the XADD producer rate. ws8's consume rate and drain time were NOT measured in the full-stack runs (the harness now records them but the runs were not repeated); the only ws8-alone consume figures are the 50-105 alerts/s (spread) and 14-18 alerts/s (hot track) above, so at 200 alerts/s injected ws8 was backlogged and caught up afterwards (every run ended at lag 0 / pending 0); nothing is claimed about ws8 not being the limit.

Not proven: hot-track cost on a quiet host; a mitigation (the cost is the full side-table read per alert, a cap below 200 or an incremental read would change it); ws8 drain time in the full stack.
