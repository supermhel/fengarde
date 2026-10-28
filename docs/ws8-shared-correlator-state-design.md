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
Not covered: the full docker-compose.ha.yml stack, failover under load, loss of both replicas. One failover, one chain.
