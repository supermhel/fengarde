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
- Known limit kept: first_seen is min over what has been recorded; a replica promoting before
  an earlier-stamped alert from a peer lands could emit under a different bucket id only when
  the two timestamps straddle a horizon boundary (pre-existing out-of-order behaviour).

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
Not covered: redis-sentinel profile live, failover mid-chain.
