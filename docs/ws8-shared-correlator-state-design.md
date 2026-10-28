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
killed, so the primary (`redis-1`, the only node started with `--min-replicas-to-write 1`) refuses writes; ws8 started against it
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
