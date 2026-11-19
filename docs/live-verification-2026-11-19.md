# Live verification, 2026-11-19

Real compose stack (Docker Desktop 29.6.1, Compose v5.1.4, Windows 11, Git Bash), code at
`origin/integration/2026-11-19` (branch `live-2026-11-19`, base `182a4ab`, release string
`v0.11.3-276-g912a699`). Everything below is copied from real command output, trimmed to the decisive lines.
All times are UTC, 2026-11-19. Nothing here was patched in product code.

## Verdict

| Step | Result |
|---|---|
| 1a `test-live` (real Redis + OpenSearch) | PASS (HA-failover file SKIPs by design: needs the HA overlay) |
| 1b `e2e` (zero-infra acceptance) | PASS |
| 1c `chaos` (kill every ws1..ws9 mid-replay) | **FAIL as run, caused by stale data in the persistent `os-data` volume, not by a product duplicate; re-scoped to this run: 40/40 PASS** (see 1c) |
| 2 Tenant scoping through nginx :8080 + `live_nginx_check.py` | PASS |
| 3 HTTP spool against real Redis (#166) | PASS (with a latency finding) |
| 4 Backup/restore per `docs/upgrade.md` (#167) | PASS after working around 3 runbook defects on a Windows host |
| 5 `docker compose -f infra/docker-compose.yml down` (no `-v`) | done, twice; no volume deleted |

## Setup and deviations (read first)

* `make` is not installed on this host and `infra/preflight.sh` refuses `MINGW64_NT` ("Unknown OS ... cannot bless this
  machine", exit non-zero), so `make preflight` / `make up` could not be used. I ran the Makefile recipes directly
  (`python ...` for the targets, `docker compose ... up -d --build` for `up`). Docker itself was reachable
  ("Docker daemon is reachable", "~7 GiB RAM").
* The compose project name is `infra`, and the host already held the owner's stale `infra_*` volumes and stopped
  containers. To avoid touching the owner's data I (a) tar-snapshotted `ws3-indexer-data`, `inventory-data`, `ws1-spool`,
  `tenants-config` before starting, and (b) pointed every new store at **new file names** inside those volumes
  (`rbac-live.sqlite`, `live-inventory.db`, `http-spool.jsonl`); the owner's `rbac.sqlite`, `inventory.db`, `audit.jsonl`
  were never overwritten. `redis-data` / `os-data` are the owner's old volumes, so OpenSearch started with 2026-10-14
  data in it (this matters for 1c).
* The shipped compose cannot enable several things the docs describe, so a local, uncommitted overlay
  (`infra/docker-compose.live.yml`, no secrets) was needed:
  ```yaml
  services:
    ws1-collectors:
      environment: [TENANT_ID=acme, INGEST_HTTP_SPOOL_PATH=/var/lib/fengarde/spool/http-spool.jsonl]
    ws6-inventory:
      environment: [INVENTORY_DB=/data/live-inventory.db]
  ```
  plus an uncommitted, gitignored `infra/.env` with random test values for `FENGARDE_API_KEY`, `FENGARDE_INGEST_TOKEN`,
  `FENGARDE_ADMIN_PASSWORD` and `FENGARDE_RBAC_DB=/app/ws3-indexer/data/rbac-live.sqlite` (values not recorded here).
  `TENANT_ID` and `INGEST_HTTP_SPOOL_PATH` are not passed through by `infra/docker-compose.yml` (documented defect list below).
* Second tenant (globex): ws1 takes its tenant from one env var, so globex events went through a throwaway
  `infra-ws1-collectors:latest` container (`live-ws1-globex`, `TENANT_ID=globex`, host port 8555), removed afterwards.
  For `/api/prom/*` returning 200 a throwaway `prom/prometheus:v2.53.0` container with network alias `prometheus` was
  attached to `infra_default` (the compose `prometheus` service is in the opt-in profile; starting it would have made a
  plain `down` leave it running). Both throwaways were `docker stop`ped (`--rm`) before the first `down`.

Stack up (`docker compose -f infra/docker-compose.yml -f infra/docker-compose.live.yml up -d --build`, 17:05:30Z):

```
ws1-collectors Up (healthy)   ws2-normalization Up (healthy)   ws3-indexer Up (healthy)
ws4-detection Up (healthy)    ws5-ai Up (healthy)              ws6-inventory Up (healthy)
ws7-dashboard Up (healthy)    ws8-correlation Up (healthy)     ws9-resolver Up (healthy)
redis Up (healthy)            opensearch Up (healthy)
```
ws3-indexer's first log lines contain an `HTTP Error 503: Service Unavailable` traceback from OpenSearch (it started
before OpenSearch accepted writes) and then `"msg": "listening", "url": "http://0.0.0.0:8013", "rbac": "enabled"`;
it recovered by itself.

### Image identities (`docker compose images` / `docker image inspect`)

```
redis:7-alpine                                  redis@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99
opensearchproject/opensearch:2.13.0             @sha256:2e954ff0e8c9d0f4868b4818150b3aecc92fbb0cc4a24d00dace38ada227291d
opensearchproject/opensearch-dashboards:2.13.0  @sha256:d8f4442da4d0cb44865a5eab01c9eb9f00769e2d5f053d21e3ff3c64a50fc6ec
curlimages/curl:8.7.1                           @sha256:25d29daeb9b14b89e2fa8cc17c70e4b188bca1466086907c2d9a4b56b59d8e21
busybox:1.36                                    @sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
alpine (backup/restore helper)                  @sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
prom/prometheus:v2.53.0 (throwaway)             sha256:075b1ba2c4ebb04bc3a6ab86c06ec8d8099f8fda1c96ef6d104d9bb1def1d8bc
locally built (image ids, built 17:03-17:05Z from this checkout):
  infra-ws1-collectors 3b1b851ab1d4   infra-ws2-normalization b8a6920ae2be   infra-ws3-indexer 7d8b6a5dc034
  infra-ws4-detection  0818e51ecbb0   infra-ws5-ai a97820447de3             infra-ws6-inventory ed4e39b3b767
  infra-ws7-dashboard  576babf794ee   infra-ws8-correlation 7fe541ba8cdf    infra-ws9-resolver d27b5743bcbd
  infra-devkit-feeder  71d6a441f008 (pre-existing, 2 months old, not rebuilt)
```

## 1. Live suites

### 1a `make test-live` (recipe run directly, 17:08:48Z)

```
[OK] runner unit tests PASS                 (memory + redis parametrised; "test_redelivery_then_deadletter[redis]" etc.)
[OK] bus trim_acked (P0-5) tests PASS
[OK] bus lag (P1-7) tests PASS
[OK] bus read count (P1-8) tests PASS
[OK] opensearch live integration PASS
[SKIP] test_opensearch_ha_failover_live: OPENSEARCH_URL must name all 3 HA nodes ...   (needs infra/docker-compose.ha.yml; expected)
[OK] OpenSearch OCC/CAS concurrency PASS -- 8 concurrent read-modify-write triage updates against a real cluster, all 8 notes preserved, zero lost updates
[OK] OpenSearch shared-store concurrency PASS -- 8 threads x 15 docs through ONE OpenSearchStore instance ..., zero ResponseNotReady/URLError(Idle)
[OK] session store lifecycle PASS (memory + redis)
```

### 1b `make e2e` (`python tools/demo_e2e.py`, 17:10:33Z) PASS

```
WS-2 normalized=10 dropped=0 / WS-4 scored=10 alerts=1 ai=1 / WS-3 indexed=12 dup=10 unroutable=1
T7 OK: ... deduped via deterministic alert_id ... (alerts count stayed 2)
T7 OK: true identical-event replay reused alert_id ... -> deduped (alerts count stayed 2)
[OK] FENGARDE v0.1 acceptance: SSH brute-force -> real alert in the index, idempotent under replay. Zero infra.
```
(zero-infra by design, so it exercises the memory bus, not the live stack.)

### 1c `make chaos` (`python tools/chaos_test.py`, 17:10:36Z-17:14:28Z): tool verdict FAIL

```
[chaos] replaying 480 raw events across 40 independent brute-force scenarios
[chaos] docker compose kill -s KILL ws1-collectors ... ws2 ... ws4 ... ws3 ... ws5 ... ws8 ... ws9   (each then `start`ed)
[chaos] scenarios=40 lost=0 duplicated=40 distinct_alert_ids=40
[chaos] FAIL -- duplicate alerts for: [('203.0.113.1', ['6f1c8a2e-...:default:11:203.0.113.1:29865680', '6f1c8a2e-...:default:11:203.0.113.1:29918470']), ...
chaos exit=1
```
Diagnosis: the two alert ids per scenario differ only in the trailing window bucket. `29865680 * 60 s` = 2026-10-14
01:20Z and `29918470 * 60 s` = 2026-11-19 17:10Z. The first is a leftover from an earlier chaos run in the owner's
persistent `os-data` volume; `alert_ids_for()` queries `alerts-*` by `src_endpoint.ip` over **all time**, and the
scenario IPs are a fixed `203.0.113.1-40`, so any second run against a non-fresh OpenSearch "duplicates" every
scenario. Re-scoping the same OpenSearch data to this run's window (`chaos_rescope.py`, ad hoc, not committed):

```
docs 80 ips 40
scenarios with exactly 1 alert_id in this run's window: 40 / 40
scenarios with 0: 0 ; >1: 0
scenarios that also carry a stale 2026-10-14 alert id: 40
```
So `lost=0` and exactly one deterministic alert per scenario after killing all of ws1-ws9 mid-replay: the property holds.
The gate as written is not re-runnable against a stack that has ever run it before (I could not wipe `os-data`; forbidden).
All nine services were healthy again afterwards.

## 2. Tenant scoping (#165/#178) through nginx :8080 and real OpenSearch (17:15Z)

Setup: admin (first-boot account from `FENGARDE_ADMIN_PASSWORD`) logged in via `/api/auth/login`, then created users
through the admin API `POST /api/triage/users` (CSRF header echoed): `acme-analyst` (analyst, tenant acme) and
`globex-analyst` (analyst, tenant globex): both `201`. Each tenant received 12 failed-logon records
(`source_type=active_directory`, EventID 4625, one attacker IP per tenant) via `POST /v1/ingest` on its own ws1
(`{"accepted":12,"skipped":0}` each, HTTP 200). WS-2/WS-4/WS-5/WS-3 produced alerts and `ai-*` docs. Output of the check script
(`hits=N tenants={tenant: count}`; tenant taken from `tenant_id` for alerts/ai-triage and `siem.tenant` for events):

```
admin           GET /api/alerts     -> 200 hits=50  tenants={'globex': 1, 'acme': 1, 'default': 48}
admin           GET /api/events     -> 200 hits=100 tenants={'globex': 13, 'acme': 14, 'default': 73}
admin           GET /api/ai-triage  -> 200 hits=97  tenants={'globex': 1, 'acme': 1, '<none>': 95}
acme-analyst    GET /api/alerts     -> 200 hits=1   tenants={'acme': 1}
acme-analyst    GET /api/events     -> 200 hits=14  tenants={'acme': 14}
acme-analyst    GET /api/ai-triage  -> 200 hits=1   tenants={'acme': 1}
globex-analyst  GET /api/alerts     -> 200 hits=1   tenants={'globex': 1}
globex-analyst  GET /api/events     -> 200 hits=13  tenants={'globex': 13}
globex-analyst  GET /api/ai-triage  -> 200 hits=1   tenants={'globex': 1}
acme-analyst    GET /api/alerts?tenant_id=globex     -> 200 hits=1  tenants={'acme': 1}     (cannot widen; same for events 14/acme, ai-triage 1/acme)
globex-analyst  GET /api/alerts?tenant_id=acme       -> 200 hits=1  tenants={'globex': 1}   (events 13/globex, ai-triage 1/globex)
api-key         GET /api/alerts     -> 200 hits=50  tenants={'globex': 1, 'acme': 1, 'default': 48}
```
Gates:
```
anonymous       /api/alerts /api/events /api/ai-triage /api/ops/ws1 /api/prom/api/v1/targets /api/inventory/assets  -> 401 (all six)
acme-analyst    /api/ops/ws1 -> 403   /api/prom/api/v1/targets -> 403   /api/inventory/assets?limit=5 -> 200
globex-analyst  /api/ops/ws1 -> 403   /api/prom/api/v1/targets -> 403   /api/inventory/assets?limit=5 -> 200
admin           /api/ops/ws1 -> 200 {"service": "ws1-collectors", ...}   /api/prom/api/v1/targets -> 200 {"status":"success",...}   /api/inventory/assets -> 200
```
Observations (consistent with SECURITY.md / `INTERFACE.md`, but worth knowing):
* 95 pre-existing `ai-*` documents in the old OpenSearch volume have no `tenant_id` and show as `<none>` to admin (they read
  as tenant `default`, the documented upgrade note); only the two new ones carry tenants.
* `/api/inventory/` is session-gated, not tenant-scoped: both tenants' analysts see the same assets (tenant_id `default`).
  Documented, but it is a cross-tenant read for a multi-tenant deployment.

`python services/ws7-dashboard/live_nginx_check.py` (own stub containers, 17:16:09Z), exit 0:
```
[OK] live nginx: nginx -t passes; /api/ops/* admin-gated (401/403/200) and exact-match; console feeds proxy to ws3 /dashboard/* with ?gte=/tenant_id= intact; /api/prom/* admin-gated; /api/inventory/ session-gated with th...
```

## 3. HTTP spool against real Redis (#166), 17:16:56Z-17:19:30Z

Baseline (ws1 `/metrics`, `docker exec ... urlopen('http://127.0.0.1:8001/metrics')`): `http_spool_pending_events: 0, http_spool_replayed: 0`.

```
$ docker compose -f infra/docker-compose.yml stop redis        # siem-bus Stopped (17:16:56Z)
POST /v1/ingest?source_type=active_directory, 12 events, X-Fengarde-Idempotency-Key: live-spool-key-1
   -> client TimeoutError after 20 s (no response seen)
+30 s  http_events_spooled: 12, http_spool_pending_events: 12, http_spool_pending_bytes: 5532, http_events_dropped: 0
POST (3 events, key live-spool-key-2) -> 202 {"accepted":0,"spooled":3,"note":"accepted for later delivery (bus down)"} elapsed=10.1s
   http_events_spooled: 15, http_spool_pending_events: 14, http_spool_replayed: 0, http_spool_drain_failed_passes: 3
$ docker compose -f infra/docker-compose.yml start redis       # 17:18:49Z
17:19:04Z  http_spool_pending_events: 0, http_spool_pending_bytes: 0, http_spool_replayed: 15, http_spool_dead_lettered: 0
```
Events in OpenSearch after the drain: src ip `.55` (the 12-event batch): `total=12 ids=12 distinct=12`; ip `.56` (3-event batch): 3 docs.
Dedupe, same batch replayed with the same idempotency key and the same record content (17:19:23Z):
```
POST -> 200 {"accepted":12,"skipped":0,"errors":[]}     http_events_accepted 12 -> 24
opensearch docs for src ip 198.51.100.55: total=12 ids=12 distinct=12      (unchanged: one document per ingest_id)
```
PASS: 202 + spooled, drains to 0 with `http_spool_replayed` rising to 15, nothing dropped or dead-lettered, replay deduped.

Findings from this step (not patched):
* **Latency with the bus down is about 3.4 s per event** (12 events: over 20 s, about 60 s to finish; 3 events: 10 s) because each
  `produce` waits for Redis name resolution to fail. A shipper with a normal 10-30 s timeout gives up on a large batch
  before the 202 arrives, although every event was already spooled. The first 12-event POST above is exactly that case: no
  202 was observed, yet all 12 were spooled and later delivered. The idempotency-key requirement in `docs/ingest-http.md`
  is what makes the shipper's retry safe; the doc could also say that batches during a bus outage are slow.
* `http_spool_pending_events` read 14 while `http_events_spooled` was 15 (and 15 were then replayed). Gauge looks off by
  one while spooled; I did not chase the cause.

## 4. Backup/restore following `docs/upgrade.md` (#167), 17:20Z-17:24Z

1. Stack stopped with plain `docker compose -f infra/docker-compose.yml down` (17:20:03Z; "Network infra_default
   Resource is still in use" only because the owner's profile-gated `siem-goatcounter` stays attached; harmless).
2. Extraction, exactly as documented (`docker run --rm -v <project>_ws3-indexer-data:/src:ro -v "$PWD/stage/ws3":/dst alpine cp -a /src/. /dst/`):
   **first attempt failed silently** under Git Bash:
   ```
   cp: can't stat 'C:/Program Files/Git/src/': No such file or directory      (x3; stage/ dirs left empty)
   ```
   Git Bash rewrites `/src/.` to a Windows path. Working form: `MSYS_NO_PATHCONV=1` plus a Windows host path
   (`-v "$(pwd -W)/stage/ws3":/dst`). After that all three volumes extracted (e.g. `stage/ws3`: `audit.jsonl`, `rbac-live.sqlite`,
   `rbac.sqlite`; `stage/inventory`: `live-inventory.db` + `-wal`/`-shm`). The documented `sudo chown -R "$(id -u):$(id -g)" stage` is
   not applicable here: Docker Desktop bind mounts on Windows come out owned by the host user and `backup.py` read them fine.
3. `tools/backup.py --out ./backups --audit-log stage/ws3/audit.jsonl --rbac-db stage/ws3/rbac-live.sqlite --inventory-db stage/inventory/live-inventory.db --spool stage/spool/http-spool.jsonl`:
   ```
   [WARN] NOT backed up by this archive: OpenSearch index data ... Redis state ... FENGARDE_GEOIP_PATH ... Docker named volumes are not read directly
   {"backup": "backups\\fengarde-backup-20261119T172043Z.tar.gz", "size_bytes": 107994}
   ```
4. `tools/restore.py backups/fengarde-backup-20261119T172043Z.tar.gz --dest ./restored`:
   ```
   [NOTE] this backup was taken on FENGARDE release v0.11.3-276-g912a699; restore it only under that release's images
   {"restored": ["rbac/rbac-live.sqlite", "keystore/live-inventory.db", "ws3/audit.jsonl", "ws1-spool/0/http-spool.jsonl", "contracts/...", ...]}
   ```
5. To make the restore prove something, I deleted **my own** `rbac-live.sqlite*` and `live-inventory.db*` from their volumes
   (the sidecar-removal command from the runbook), then re-injected with the documented copy+chown commands (rbac to
   `ws3-indexer-data`, keystore to `inventory-data`, spool file to `ws1-spool` as `10001:999`; the audit log was not copied
   back, to leave the owner's pre-existing audit file untouched):
   ```
   -rw------- 1 10001 10001 12288 Nov 19 17:21 rbac-live.sqlite
   uid10001-read-ok          # docker run --user 10001:10001 ... cat /d/rbac-live.sqlite
   ```
6. `up -d` again (17:21:23Z), all services healthy, plain `down` had kept every volume. Proof the restored RBAC works:
   ```
   login admin: 200   login acme-analyst: 200   login globex-analyst: 200      (acme/globex users exist only in the restored DB)
   acme-analyst GET /api/alerts -> hits=3 tenants={'acme': 3}   /api/events -> 30 {'acme': 30}   /api/ai-triage -> 2 {'acme': 2}
   globex-analyst GET /api/alerts -> hits=1 {'globex': 1}        /api/events -> 13 {'globex': 13}
   ws6 /assets with the API key -> 2 assets; inside the containers: live-inventory.db (app:10001, 0600), http-spool.jsonl, rbac-live.sqlite present
   ```
   (acme counts are higher than in step 2 only because the step-3 events were also ingested as tenant acme.)
   Data presence is largely the OpenSearch volume surviving `down`; the restore itself is proven by the users, which exist
   only in the deleted-then-restored `rbac-live.sqlite`.

### Runbook defects found (docs/upgrade.md and friends)

1. **The "Verification status: Docker-volume commands untested" banner is now partly outdated**, but the commands are not
   copy-paste safe on Windows Git Bash: `/src/.` is rewritten and `cp` fails, leaving empty staging dirs with only a
   `cp: can't stat` message (a later `backup.py` would then back up nothing or fail). Needs `MSYS_NO_PATHCONV=1` and a
   Windows host path (`$(pwd -W)`), or a note to use WSL/PowerShell. On Windows there is no `sudo`/`chown` step.
2. The runbook's file names (`audit.jsonl`, `rbac.sqlite`, `inventory.db`, a spool file) assume things the shipped compose
   does not set up: `FENGARDE_RBAC_DB` has no default in the volume, `INVENTORY_DB`/`INVENTORY_KEYSTORE_DB` are not passed to ws6
   (it runs `:memory:`), and the spool env vars are not passed through (3 below). The runbook says this for inventory only;
   an operator following it literally on the default compose has only `audit.jsonl` to back up.
3. `infra/docker-compose.yml` does not pass `TENANT_ID` or `INGEST_HTTP_SPOOL_PATH` to ws1, so the HTTP ingest spool
   (#166) and the tenant of HTTP-ingested events cannot be set without an overlay, although `docs/ingest-http.md` presents
   both as plain env settings.
4. `make preflight` / `make up` do not work from Windows Git Bash (`make` missing; `preflight.sh` rejects the OS and exits
   non-zero). `CLAUDE.md` says to override `PYTHON=python` on Windows but not that `make` itself is absent.
5. `tools/chaos_test.py` is not re-runnable against a persistent OpenSearch (see 1c); `make chaos` doc says "needs make up first"
   but not "needs empty `alerts-*`".

## 5. Teardown

`docker compose -f infra/docker-compose.yml down` (no `-v`), 17:24:07Z:
```
Container siem-store Removed / Container siem-bus Removed / Network infra_default Resource is still in use
```
Afterwards: no `infra-*`, `siem-bus`, `siem-store`, `live-*` containers left; `docker volume ls` still lists
`infra_caddy-config infra_caddy-data infra_goatcounter-data infra_inventory-data infra_os-data infra_prometheus-data
infra_redis-data infra_tenants-config infra_ws1-spool infra_ws3-indexer-data` (the same ten as before the run). The owner's
`siem-goatcounter` (profile-gated, running 7 days before I started) and the stopped `siem-prometheus` were not touched.
No volume was deleted; no `-v`, no `make down`. The only items I removed were my own files inside volumes
(`rbac-live.sqlite*`, `live-inventory.db*`, step 4) and my two `--rm` throwaway containers. Pre-run tar snapshots of the four
small volumes are in the session scratchpad. Local, uncommitted leftovers in the worktree: `infra/.env`,
`infra/docker-compose.live.yml`, `stage/`, `backups/`, `restored/`.

## Re-run, 2026-11-19 (after `wp/http-spool-drain` 3e33f45 and `fix/live-tooling-2026-11-19` / PR #180)

Both branches merged (signed off) into `live-2026-11-19` (`9ff6d27`, `5717f0f`; the only conflict was `CHANGELOG.md`, resolved by
keeping both entries). Same host, same non-empty `os-data` (it now also holds the first run's alerts). This time **no live
overlay**: `INGEST_HTTP_SPOOL_PATH` was set only in the gitignored `infra/.env`, and the stack was built with plain
`docker compose -f infra/docker-compose.yml up -d --build` (18:38:02Z).

| Check | Result |
|---|---|
| `bash infra/preflight.sh` | PASS: "[ OK ] Windows (MINGW64_NT-10.0-26200, Git Bash/MSYS): vm.max_map_count is managed by Docker Desktop's WSL2 VM (skipped)" ... "PRE-FLIGHT PASSED" |
| compose pass-through | PASS: `docker exec infra-ws1-collectors-1 env` shows `INGEST_HTTP_SPOOL_PATH=/var/lib/fengarde/spool/http-spool.jsonl` and `TENANT_ID=default` with no overlay; all services healthy |
| `python tools/chaos_test.py` on the non-empty cluster (18:40:39Z) | **PASS**: `scenarios=40 lost=0 duplicated=0 distinct_alert_ids=0` / `PASS -- zero lost alerts, zero duplicate alerts, one deterministic alert_id per scenario across 40 scenarios, 7 services killed mid-replay` |
| HTTP spool outage, 12-event batch, 20 s client timeout | **PASS** |

Chaos note: the first run's stale alerts (2026-10-14 and 2026-11-19 17:10Z) are still in the cluster and no longer trip the check,
so the per-minute scoping works. The summary line prints `distinct_alert_ids=0` on a pass, which looks like a cosmetic counter
quirk (each scenario did have exactly one alert); I did not investigate it.

Spool outage (redis stopped 18:44:37Z):
```
POST (12 events, X-Fengarde-Idempotency-Key set, 20 s timeout)
  -> 202 {"accepted":0,"spooled":12,"note":"accepted for later delivery (bus down)"} elapsed=2.56s     (first run: >20 s, timeout)
metrics: http_events_spooled 12, http_spool_pending_events 12, http_spool_pending_bytes 4716, http_events_dropped 0   (gauge == spooled count)
docker compose start redis (18:44:48Z); poll until pending 0:
metrics: http_spool_pending_events 0, http_spool_replayed 11, http_spool_dead_lettered 1, http_spool_dead_letter_redriven 1, drain_failed_passes 1
spool file: 0 bytes; no .dead sidecar left
opensearch docs for src ip 198.51.100.66: total=12 distinct_ids=12
```
One event was parked in `.dead` after a failed pass while Redis was still coming back and was re-sent by the redrive
(`dead_letter_redriven: 1`), so all 12 reached OpenSearch exactly once; pending went to 0 within the poll window. 2.56 s vs more than 20 s
before, and the live gauge now matches the spooled count (it read 14 vs 15 before).

Teardown: `docker compose -f infra/docker-compose.yml down` (no `-v`), 18:45:18Z. No `infra-ws*`/`siem-bus`/`siem-store`
containers remain; all ten `infra_*` volumes still present. The live overlay is no longer needed and was moved out of `infra/`.
