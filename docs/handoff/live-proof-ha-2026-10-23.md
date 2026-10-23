> Raw logs and the reproduction scripts of this run are kept outside the repository (`_live-proof-2026-10-23/out`, `scripts`). The commands and output below are copied from them. Fixes made because of these findings: PR #124 (ws8 startup log, `pel_evicted` warning, one-replica note), PR #126 (`OLLAMA_TIMEOUT_SECONDS`, HA compose note), PR #119 (alias-map cut-over note, dashboard AI-verdict join).

# Live proof: HA stack, 2026-10-23

All output below is real command output from this machine (Docker 29.6.1, 8 CPU / 7.4 GB VM), copied from the raw logs in `out/` (same folder). Times are mixed: host-local (`HH:MM`, UTC+2) in my script lines, UTC (`Z`) in service JSON logs.

## Setup

| What | Value |
|---|---|
| Build | worktree at `a84ec02` = tip of `origin/claude/ws8-sentinel-window-state-06083c`. `origin/main` (`1ec704d`, PR #125 merge) is an ancestor, so the merge was a fast-forward: **build = origin/main + the Sentinel fix**. |
| Compose | `docker compose -p lpha -f infra/docker-compose.yml -f infra/docker-compose.ha.yml -f override.yml --profile ha` |
| Isolation | Project name `lpha`, own network (`lpha_ha`, 172.28.0.0/24, no clash found) and volumes. `override.yml` only moves host ports (ws6 18000, ws7 18080, ws1 15514/udp), renames `ws3-indexer-init` (its fixed name `siem-ws3-indexer-init` is taken by an exited container of the live `infra` stack, which I did not touch), and sets the env noted per item. The live `infra` stack was never touched. |
| Overrides that deviate from the shipped config | ws6 `INVENTORY_BASELINE_SECONDS=0` (item 4); OpenSearch heap 512 MB instead of 1 GB (VM RAM); ws5 `AI_MAX_WORKERS=1` plus a **proof-only code patch** (item 6, diff in `out/item6_proofpatch.diff`). |
| Helpers | `dc.sh` (compose wrapper), `run.sh` (runs a script from `scripts/` inside the ws8 image on the HA network, real `shared.bus` / Sentinel client), `scripts/*.py`, `item*.sh`. |
| Cleanup | Done, see the end. No commit, no push, no PR. |

## Result summary

| # | Item | Result |
|---|---|---|
| 1 | ws8 service under HA, master killed mid-stream | **PASS** (with caveats below) |
| 2 | 5 master kills, 700 alerts at 1/s for 11 min 40 s | **PASS** |
| 3 | Two ws8 replicas on one Sentinel-backed window store | **PARTIAL**: window membership is shared, correlation is not (documented gap) |
| 4 | WS-6 inventory in the loop | **PASS** (needed `INVENTORY_BASELINE_SECONDS=0` for the downstream event) |
| 5 | OpenSearch 3-node HA | **PASS** |
| 6 | Real LLM (Ollama, qwen2.5:0.5b) through WS-5 | **PASS for wiring only**, with a real defect found (8 s timeout) |
| 7 | Alias map vs existing incident ids | **Answered**: existing incident ids are not rewritten, but they are orphaned |

---

## Item 1: ws8 service under `docker-compose.ha.yml`

Entrypoint: `CMD python main.py` (the Dockerfile), not `make_correlator()` called by hand.

**Which window counter?** ws8 does not log it. Two pieces of evidence instead (`out/item1_pre.log`):

```
$ docker exec lpha-ws8-correlation-1 env | grep -E 'BUS_BACKEND|SENTINEL'
REDIS_SENTINEL_HOSTS=redis-sentinel-1:26379,redis-sentinel-2:26379,redis-sentinel-3:26379
REDIS_SENTINEL_MASTER=mymaster
BUS_BACKEND=redis-sentinel
--- feed 6 alerts (3 actors) via the real Bus() ---
master: ('172.28.0.11', 6379)
ws8:corr keys: 3 ['ws8:corr:default:actor:base-actor-0', 'ws8:corr:default:actor:base-actor-1', 'ws8:corr:default:actor:base-actor-2']
default:actor:base-actor-0:20749 ('actor', 'base-actor-0', 2, ['TA0001', 'TA0002'])   (x3 actors, 3 incidents)
```

The `ws8:corr:*` zsets exist in Redis only because the running service's `RedisWindowCounter` wrote them (the old code fell through to the in-process deque for `redis-sentinel` and would write nothing). That the client follows a failover is shown by the kills below (a pinned client would go READONLY). Surprise: **no log line says which counter was picked**; the only startup line is `serving ... topics:[alerts]`. Worth one `log.info` in `make_correlator()`.

**Kill 1, at 1 alert/s** (`out/item1_run.log`, `item1_feed.log`, `item1_post.log`):

```
16:51:14 KILL master: docker kill siem-bus-ha-1
16:51:22 sentinel master now 172.28.0.13 after 6s
14:51:15 PRODUCE-ERR fo-000012: ConnectionError: Error 111 connecting to 172.28.0.11:6379. Connection refused.
14:51:26 PRODUCE-ERR fo-000012: TimeoutError: Timeout connecting to server
DONE produced=45 produce_exceptions=2
Sentinel log: +odown ... #quorum 2/2 -> +promoted-slave 172.28.0.13 -> +failover-end -> +switch-master 172.28.0.11 -> 172.28.0.13
ws8 /metrics: {"alerts": {"acked": 51, "bus_error": 1}}   restarts=0 health=healthy (ws8 and ws4)
state: master ('172.28.0.13', 6379)  alerts group cg-correlate pending=0 lag=0
window membership: checked=51 missing_from_window=0
incident fo-actor-0: 45 members, tactics [TA0001, TA0002]
```

45 alerts produced, 45 in the window, 44 incident updates under **one** incident id (`default:actor:fo-actor-0:20749`), none lost or duplicated. Failover took 6 s.

**Caveat on "the one failed delivery is redelivered".** In this run the failure was on the *consume* side (`bus_error: 1`, a `ConnectionError` out of `xreadgroup`) plus 2 produce errors in my feeder (retried). **No handler failed**, so no redelivery was exercised. I therefore ran two more kills (`item1b`, `item1c`):

- `item1b`: 600 alerts at 20/s, `docker kill` of the master. Again no handler failure: `acked 651, bus_error 2`, 600/600 in window, 0 pending.
- `item1c`: 500 alerts at 20/s, `docker pause` of the master (sockets stay open, then unpause after promotion). **This produced the real failure** (`out/item1c_post.log`, `item1c_recover.log`):

```
ws8 /metrics: {"alerts": {"acked": 731, "bus_error": 2, "failed": 420}}
redis.exceptions.ResponseError: Command # 1 (ZADD ws8:corr:default:actor:fc-actor-0 ...) of pipeline caused error: NOREPLICAS Not enough good replicas to write.
alerts group cg-correlate pending= 420   window membership: checked=500 missing_from_window=279
--- 45 s later (default 60 s idle reclaim) ---
{"alerts": {"acked": 1151, "bus_error": 2, "failed": 420}}   pending= 0   missing_from_window=0
distinct incident ids for the actor: 1
```

So **420** deliveries failed (not "one"): the new master refused writes with `NOREPLICAS` while its replicas were still re-attaching (the `min-replicas-to-write 1` setting from FIX 23 doing its job). All 420 stayed unacked, were reclaimed by the runner, and the window ended complete (0 missing, 0 pending, 0 dead-lettered, ws8 never restarted). The branch's unit test (`a84ec02`) pins the same behaviour; this is the live confirmation.

Result: **PASS**. Redis kill: Sentinel promoted in 6 to 7 s every time, ws8/ws4 stayed up, incidents continued after failover.

## Item 2: five consecutive kills, 1 alert/s, more than 10 minutes

`soak.sh`: 700 alerts at 1/s (20 per actor, 35 actors) plus one raw `linux_ssh` event per second into `raw.events` so ws2 and ws4 are in the loop. Five rounds of: `docker kill <current master>`, wait for promotion, `docker start` the killed node, wait for `connected_slaves:2`, sleep 95 s. Start 16:59:35, feeder finished 17:11:19 (`DONE produced=700 ... elapsed=700s`). Raw: `out/item2_run.log`, `item2_post.log`.

```
ROUND 1: master=.13 (siem-bus-ha-3) -> kill   promoted .11 (siem-bus-ha-1) in 6s   after restart: connected_slaves:2
ROUND 2: master=.11 (siem-bus-ha-1) -> kill   promoted .13 (siem-bus-ha-3) in 6s   after restart: connected_slaves:2
ROUND 3: master=.13 (siem-bus-ha-3) -> kill   promoted .11 (siem-bus-ha-1) in 7s   after restart: connected_slaves:2
ROUND 4: master=.11 (siem-bus-ha-1) -> kill   promoted .12 (siem-bus-ha-2) in 5s   after restart: connected_slaves:2
ROUND 5: master=.12 (siem-bus-ha-2) -> kill   promoted .13 (siem-bus-ha-3) in 7s   after restart: connected_slaves:2
```

| Counter | Value |
|---|---|
| ws2 / ws4 / ws8 restarts and health after | 0 / 0 / 0, all `healthy` (started `14:49:34Z`, unchanged) |
| ws2 `/metrics` | `raw.events: acked 700, bus_error 7`, normalized 700, dropped 0 |
| ws4 `/metrics` | `normalized.events: acked 700, bus_error 7` (700 raw events, all processed) |
| ws8 `failed` counter | 420 before the soak, **420 after**: zero handler failures during the 5 kills |
| ws8 `bus_error` | 2 before, 8 after (consume-side connection errors, one per kill and one extra) |
| Feeder | 700 produced, 6 produce exceptions (retried), 0 lost |
| JSON `level:error` log lines (ws2/ws4/ws8) | 0 each. Tracebacks in logs (21/22/24) are the `ConnectionError` stack traces behind `bus_error` |
| `alerts` group | `pending=0 lag=0`; 3235 acked = stream length |
| Window membership of the 700 soak alerts | **checked=700 missing_from_window=0** |
| Incidents | 41 distinct incident ids on the stream after the whole session |

Not measured: ws4's own Redis window (`ws4:win:*`) membership. I only checked ws8's. ws4's counters show every event processed and no failures.

Result: **PASS**.

## Item 3: two ws8 replicas, one Sentinel-backed window

`docker compose up --scale ws8-correlation=2`. To make routing deterministic (a consumer group splits alerts arbitrarily), I stopped one replica at a time with `docker stop` (not pause: a paused consumer would keep a blocked XREADGROUP and swallow the message). `out/item3.log`:

```
SPLIT: actor rep-split. split-1 (TA0001) handled only by replica 2, split-2 (TA0002) only by replica 1
lpha-ws8-correlation-2 acked= 1 active_tracks= 1 promotions= 0
lpha-ws8-correlation-1 acked= 1 active_tracks= 1 promotions= 0
window zset in the shared Redis: ws8:corr:default:actor:rep-split -> ['split-1', 'split-2'] ttl= 86392
incidents for rep-split: distinct incidents: 0
CONTROL: same two alerts, actor rep-same, both on replica 1
ws8:corr:default:actor:rep-same -> ['same-1', 'same-2']
default:actor:rep-same:20749 ('actor', 'rep-same', 2, ['TA0001', 'TA0002'])   distinct incidents: 1
```

- **Visible across replicas: yes for membership.** One zset holds an id written by replica 2 and an id written by replica 1.
- **Shared correlation: no.** The same two alerts yield an incident on one replica and **none** when split. The decision needs each member's tactic, which lives in the in-process `_sides` table. This is exactly the "Known gap" in `services/ws8-correlation/INTERFACE.md` (lines 272-278). The doc is accurate; the practical consequence is that **running two ws8 replicas under a shared consumer group silently weakens detection** (incidents only form when both tactics land on the same replica). I did not test whether the Redis partition key (`key=actor`) pins one actor to one replica; with plain consumer-group XREADGROUP there is no key affinity.

Result: **PARTIAL** (membership shared: pass; correlation sharing: fail, known and documented).

## Item 4: WS-6 inventory in the loop

WS-6 ran in the stack from the start (healthy, `serving ... assets.updates`). `out/item4a-d.log`.

1. Produced to `assets.updates`: `{"mac":"de:ad:be:ef:00:44","ip":"10.77.0.44","hostname":"lp-proof-host3","seen_at":"2026-10-23T15:16:02Z","sector":"datacenter","device_type":"server"}`.
2. Inventory API (`http://127.0.0.1:18000`) returned the asset:
   `{"mac": "de:ad:be:ef:00:44", "hostname": "lp-proof-host3", "ip_current": "10.77.0.44", "sector": "datacenter", "status": "active", "last_seen": "2026-10-23T15:16:02Z", ...}`
3. Dashboard path (ws7 nginx to ws6, the call the Inventory view makes, `api.ts:156-157`): `curl :18080/api/inventory/assets?limit=200` and `/api/inventory/assets/de:ad:be:ef:00:44` both HTTP 200 with the same record. I only checked the proxy over HTTP; I did **not** render the React Inventory view.
4. Downstream consumer: ws6 published the new-device notification and ws2 normalized it (`ws6 log: "new device detected, published inventory-diff notification"`; `raw.events` 700 to 701 with `source_type: inventory_diff`; `normalized.events` 700 to 701: `class_uid 4001`, `message: "New device de:ad:be:ef:00:44 (server) on 10.77.0.44"`, `src_endpoint.mac` set).

Things that surprised me:

- **The first two devices produced no downstream event.** ws6 only publishes a new-device event after the tenant's baseline window closes (default 3600 s, stored per tenant at first sighting). Changing the env to `1` did not help for the already-opened tenant; `INVENTORY_BASELINE_SECONDS=0` did (`store.py:429`). So on a fresh stack the first hour of devices never reaches ws2/ws4. By design (initial population), but invisible unless you read the code.
- ws2 does **not** use the inventory to *enrich* events (no ws2 code reads ws6). The "downstream consumer" here is ws2 normalizing the `inventory_diff` event ws6 itself emits. No ws4 alert fired for the device (the `ot_new_device_on_segment` rule has conditions I did not try to satisfy).

Result: **PASS** (store, API, dashboard proxy, ws6 to ws2 hand-off). Not proven: enrichment from inventory, UI rendering, a ws4 alert.

## Item 5: OpenSearch 3-node HA

The repo has one: `infra/docker-compose.ha.yml` (`opensearch-1..3`, `provision-ha`, ws3 pointed at all three nodes). Used as-is except heap (512 MB). `out/item5a.log`, `item5b.log`:

```
$ curl :9201/_cluster/health
"cluster_name":"fengarde","status":"green","number_of_nodes":3,"number_of_data_nodes":3,"unassigned_shards":0,"active_shards_percent_as_number":100.0
$ _cat/nodes   opensearch-1, opensearch-2 (cluster_manager *), opensearch-3
provision-ha: "Provisioning complete."   ws3 OPENSEARCH_URL=http://opensearch-1:9200,http://opensearch-2:9200,http://opensearch-3:9200   ws3 healthy
```

Indexing through the real pipeline (15 raw ssh failures, ws2 to ws4 to ws3 to OpenSearch): index `alerts-2026.10.23` got the alert `...:default:12:203.0.113.77:...` ("Authentication brute-force from single source", TA0006/T1110). Then:

```
BEFORE: alert count via node 2 (:9202): {"count":2}
docker stop siem-store-ha-1   (the first node in ws3's URL list)
health via node 3: {"status":"yellow","number_of_nodes":2,"unassigned_shards":5,"active_shards_percent_as_number":75.0}
search via node 3 for the earlier alert (203.0.113.77): {"hits":{"total":{"value":2}}}
15 new ssh failures from 203.0.113.88 while node 1 is down
search via node 3 for the NEW alert (203.0.113.88): total 3 hits (3 rules fired), e.g. "Authentication brute-force from single source"
AFTER: alert count via node 2: {"count":4}
ws3: health=healthy restarts=0, alerts acked 57, no dead letters;  dashboard /api/alerts via ws7: http=200
docker start siem-store-ha-1 -> {"status":"green","number_of_nodes":3}
```

Indexing and search continued with one node down, no ws3 restart, cluster back to green after the node returned. Not tested: stopping the elected cluster manager (`opensearch-2`) or two nodes.

Result: **PASS**.

## Item 6: real LLM through WS-5 (wiring only)

`ollama/ollama` (v0.40.9, 8.43 GB image), `ollama pull qwen2.5:0.5b` (397 MB), `OLLAMA_URL=http://lpha-ollama:11434`, `OLLAMA_MODEL=qwen2.5:0.5b`. **This proves wiring, not verdict quality.** Evidence `out/item6*.log`.

Final state: the enriched alert WS-5 emitted for event `oshaF-203.0.113.102-14` is in the 3-node OpenSearch cluster (`alerts-2026.10.23/_id ai-oshaF-203.0.113.102-14`):

```
"ai": {"verdict": "unknown", "level": "medium", "engine": "ollama", "model": "qwen2.5:0.5b",
       "summary": "The alert is a benign noise. The detection rules triggered include 'Authentication brute-force from single source' and 'Sustained credential stuffing ...'. These are not specific to a malicious activity ..."}
q=ai.engine:ollama -> 2 docs.   ai.results stream: {('llm', 'ollama', 'qwen2.5:0.5b'): 2}
```

The model text is poor (a brute-force alert described as "benign noise", verdict out of enum so coerced to `unknown`, and an earlier sample logged `llm verdict coerced out-of-enum to safe default`). That is expected from 0.5B parameters and says nothing about the pipeline.

**Defect found, and the patch I used to get past it.** With the shipped code the first attempts all fell back to the stub (`engine: stub`, `llm primary failed; degrading to backup ... "error": "timed out"`; Ollama logged `500 | 8.01s | POST /api/generate`). `OllamaLLM.__init__` hardcodes `timeout=8.0` and `make_llm()` has no env override. A direct call with a *short* hand-made event took 2.1 to 2.4 s (`engine: ollama`), but the real WS-5 prompt on this CPU took 7.9 to 8.8 s per call, straddling the cutoff. Also, after one timeout the adapter marks the primary unavailable and serves the stub until the next probe, so the stub persists across later alerts. I tried `AI_MAX_WORKERS=1` first (to rule out queueing): still timed out. What made it work was a **proof-only edit in my throwaway worktree, not committed**:

```
-                 timeout: float = 8.0):
+                 timeout: float = float(os.getenv("OLLAMA_TIMEOUT_PROOF", "8.0"))):
```

with `OLLAMA_TIMEOUT_PROOF=90`. Without that, a CPU Ollama with even a 0.5B model does not reliably produce a verdict through WS-5. A small slice of that: the 8 s limit should be configurable (env) and documented, since `llm_adapter.py` itself states it "has NOT been run against a live Ollama server" and this run shows the gap.

Result: **PASS for wiring** (real model output, WS-5 to bus to WS-3 to OpenSearch), **with the timeout defect above**.

## Item 7: incident ids when the alias map is turned on

Branch `origin/claude/evasion-f2-f4-c47e66` (`aad9d16`), ws8 service in Docker (`BUS_BACKEND=redis`, plain Redis, `FENGARDE_IDENTITY_ALIASES` mounted), same alert stream and fixed alert times in every run. Map: tenant `acme`, `default_realm: corp`, realm group `[CORP, corp.example]`. `out/item7.log`, `item7b.log`.

**Same stream with and without the map** (alerts: `a1 jdoe/TA0001, a2 jdoe/TA0002, a3 CORP\jdoe/TA0001, a4 jdoe@corp.example/TA0002, a5,a6 bob@other.example` TA0001/TA0002):

```
NO MAP:  acme:actor:bob@other.example:20749 (a5,a6)      acme:actor:jdoe:20749 (a1,a2)             -> 2 incident ids; a3/a4 never merge
MAP ON:  acme:actor:bob@other.example:20749 (a5,a6)      acme:actor:jdoe@corp:20749 (a1,a2,a3,a4)  -> 2 incident ids
```

The unmapped actor (`bob@other.example`) keeps the identical id. The mapped actor's id changes from `acme:actor:jdoe:20749` to `acme:actor:jdoe@corp:20749`.

**An incident that already exists, then the map is switched on** (same Redis, ws8 restarted with the map, same horizon bucket 20749):

```
before map:        acme:actor:jdoe:20749      members [a1,a2]  tactics [TA0001,TA0002]
after map ON, then jdoe alerts a7 (TA0003) and a9 (TA0001):
                   acme:actor:jdoe:20749      members [a1,a2]  tactics [TA0001,TA0002]   <- old incident, frozen, never updated again
                   acme:actor:jdoe@corp:20749 members [a7,a9]  tactics [TA0001,TA0003]   <- NEW incident for the same person
control (no map, no restart): a1,a2 then a8 TA0003 -> ONE id acme:actor:jdoe:20749 with members [a1,a2,a8]
```

Answer: **the id of an existing incident is not rewritten, but turning the map on does change what id the same identity gets from then on.** Ongoing activity by an already-incident actor opens a *second* incident under the folded id and abandons the old one (its members stay at the pre-map set; the new track starts empty: a7 alone produced no incident, it took a9). So you get a split incident, an orphaned open document in the indexer, and no automatic merge. If the map is introduced for a tenant with live incidents, expect that once per affected identity. A migration or a deliberate cut-over (accept the split, or re-key/close the old incidents) is needed; nothing in the branch handles it.

Caveat: ws8 was restarted with the map in the "existing incident" case, so `_sides` was also lost on restart (separate known gap). That does not change the id outcome: the new key `jdoe@corp` is a different window key regardless.

---

## Other findings worth a ticket (all observed live)

1. No startup log of the window counter type in ws8 (item 1).
2. Two ws8 replicas split a consumer group and silently weaken incident formation (item 3).
3. `OllamaLLM` timeout fixed at 8 s, not configurable; one timeout pins the stub until a re-probe (item 6).
4. ws6 first-hour devices never reach ws2/ws4 (item 4).
5. `docker-compose.ha.yml` fixed `container_name`s (`siem-bus-ha-*`, `siem-store-ha-*`, `siem-sentinel-ha-*`, `siem-provision-ha`) mean a second HA project on one host cannot coexist; `ws3-indexer-init` collides with the single-node stack's fixed name `siem-ws3-indexer-init` when that exited container exists.
6. `runner` metrics provider warns `'_RedisSentinelBus' object has no attribute 'pel_evicted'` (seen in ws5/ws8 logs): a missing method on the Sentinel bus wrapper.
7. The `fcb` benchmark container that disappeared during the run was the full-corpus benchmark: it had finished and the parent session removed it (not this run's doing). Results: `benchmark/README.md`.

## Cleanup

`compose -p lpha down -v --remove-orphans` (all volumes and the `lpha_ha` network removed), `docker rm -f lpha-ollama lp7-redis`, network `lp7` and `lpha_default` removed, images `lpha-*` and `ollama/ollama` removed (`out/teardown.log`). The live `infra-*` and `siem-*` containers were left running. Both throwaway worktrees (`wt`, `wt-evasion`) were removed with `git worktree remove --force`; the only edit in them was the item 6 proof patch, saved in `out/item6_proofpatch.diff`. Raw logs and the scripts to reproduce stay in this folder.
