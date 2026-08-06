# FENGARDE SIEM — Architecture & Reliability Audit (HA + Distributed-Systems Deep Dive)

**Date:** 2026-08-06  
**Scope:** Every distributed-systems claim in the SSOT §2 table, the HA opt-in profile, bus delivery semantics, idempotency, failure modes, and the defect-pattern catalog from `architecture-reliability-review/references/defect-patterns.md`.  
**Method:** Every finding below cites exact `file:line` + verbatim code. Claims were treated as claims, not ground truth — each was verified against the real code path that would have to be true for it to hold.

---

## Per-Area Grades

| Area | Grade | Summary |
|---|---|---|
| **Bus delivery semantics** (XAUTOCLAIM/XPENDING/DLQ/trim-acked) | **A−** | Disciplined, carefully safety-proofed implementation. Generator failover fix is correct. Caveat: at-least-once claim is only true up to the broker's own ACK — see Finding 3. |
| **Idempotency** (alert_id, doc_id, index naming) | **B+** | `alert_key()` is deterministic and tenant-namespaced. Index naming correctly uses event content time, not process time. **But** ingest-edge ingest_id is non-deterministic (uuid4), defeating replay dedup at the source — see Finding 6. |
| **HA / Failover** (Sentinel, OpenSearch cluster, state persistence) | **B** | After the 2026-08-05 live-verification pass, Sentinel config, master discovery, and state persistence are solid. The generator-failover fix closes the worst gap. Remaining: single-endpoint OpenSearch writer (Finding 2), async-replication durability (Finding 3), and the env-gated detection branch (Finding 1). |
| **Coupling claims** (zero cross-workstream imports) | **A** | **Claim HOLDS.** Grepped: zero hits for `from ws[0-9]-... import` / `import ws[0-9]-`. The only cross-package imports are into `services/shared/`. |
| **Failure modes** (SILENT ones specifically) | **C+** | One CRITICAL env-gated feature branch, racy counters under concurrency, non-deterministic ingest_id shadowing a deterministic fallback. |
| **HA compose vs base** | **B+** | All 7 services now correctly wired after the documented 2026-08-05 fixes. The base file (`docker-compose.yml`) has zero HA leakage. The profiles exclusion fix (`[standard]` instead of `[ha]`) is correct. |
| **Runner / health / watchdog / backpressure** | **A** | `/health` 503 on bus failure, depth watchdog uses `lag()` (true backlog), traceback throttling, graceful shutdown. Prometheus metrics correctly labeled and escaped. |

**Overall Grade: B** — A disciplined core with excellent bus/runner/health infrastructure, undermined by a CRITICAL detection-silencing bug in the HA path, a single-endpoint OpenSearch writer, unverified async-replication durability, and non-atomic ingest-edge counters. The HA layer has received heroic late-stage fixes (2026-08-05 pass found and fixed 6 real bugs), but the env-gated detection branch survived that pass and would disable brute-force/port-scan/beaconing detection under the only deployment topology that needs it. Fix that first.

---

## Findings

### Finding 1 [CRITICAL] — Env-gated feature branch silently disables stateful detection under HA

**Defect pattern:** Pattern 1 — env-gated feature branch that silently DISABLES a capability for a sibling value.  
**File:** `services/ws4-detection/main.py`, lines 314-339

```python
# main.py:314
if os.getenv("BUS_BACKEND", "memory").lower() == "redis":
    try:
        import redis
        from window import RedisWindowCounter
        client = redis.Redis.from_url(
            os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            decode_responses=True)
        counter = RedisWindowCounter(client)
        detector._window_counter = counter
        for r in detector.rules:
            if r.stateful:
                r.set_counter(counter)
    except ImportError:
        get_logger("ws4-detection").warn(
            "BUS_BACKEND=redis requested but redis-py is not installed; "
            "falling back to per-replica window counter (NOT safe across "
            "multiple WS-4 replicas)")
```

**The gate on line 314 checks `== "redis"`.** The three documented `BUS_BACKEND` values are: `memory`, `redis`, `redis-sentinel`. Under the HA profile (`docker-compose.ha.yml` line 370: `BUS_BACKEND=redis-sentinel`), this gate **does not match**. The `RedisWindowCounter` is never attached. Every stateful rule (`common_bruteforce`, `common_port_scan`, `common_password_spray`, `common_beaconing`, `common_impossible_travel`, etc.) silently falls back to the per-replica `DequeWindowCounter`.

**Impact:** With ≥2 WS-4 replicas, the count splits across processes and no single replica reaches the threshold. Brute-force, port-scan, lateral-movement, beaconing, and every other stateful rule **never fires** — a silent detection failure in exactly the deployment the HA profile exists for. The health endpoint still returns 200 (the code still runs, just with per-replica counters). The SSOT correctly claims "WS-4 redelivery + DLQ on real Redis" and "deterministic alert_id" are proven; neither of those claims is contradicted, but they are irrelevant if detection itself is silently offline.

**Confidence:** HIGH. The code shape is the exact Pattern 1 signature. The conditional omits `redis-sentinel`. The fallback comment on line 338 itself warns "NOT safe across multiple WS-4 replicas" — the code knows this is wrong but the gate doesn't match the HA config value. `docker-compose.ha.yml` line 370 sets `BUS_BACKEND=redis-sentinel`. The Redis client construction inside the block (line 318-320) also reads `REDIS_URL`, which the HA profile does NOT set for ws4-detection (it sets `REDIS_SENTINEL_HOSTS` + `REDIS_SENTINEL_MASTER` instead), so even if the gate were fixed to `in ("redis", "redis-sentinel")`, the client would point at a non-existent node — the fix needs to either create a proper `RedisWindowCounter` through the Sentinel-discovered master or (simpler) use `Bus()` factory instead of raw `redis.Redis.from_url`.

---

### Finding 2 [HIGH] — Single-endpoint-pinned OpenSearch writer in 3-node HA cluster

**Defect pattern:** Pattern 2 — single-endpoint-pinned client inside an "N-node HA" cluster.  
**File:** `services/ws3-indexer/storage/opensearch.py`, lines 72-85; `infra/docker-compose.ha.yml`, line 392

**The writer holds one `http.client.HTTPConnection` to one host:**

```python
# opensearch.py:71-85
def __init__(self, url: str | None = None, timeout: float = 10.0) -> None:
    url_str: str = url or os.getenv("OPENSEARCH_URL") or "http://localhost:9200"
    parsed = urllib.parse.urlsplit(url_str)
    self._host: str = parsed.hostname or "localhost"
    self._port = parsed.port or (443 if parsed.scheme == "https" else 9200)
    ...
    self._conn: http.client.HTTPConnection | None = None

def _connection(self) -> http.client.HTTPConnection:
    if self._conn is None:
        cls = http.client.HTTPSConnection if self._https else http.client.HTTPConnection
        self._conn = cls(self._host, self._port, timeout=self.timeout)
    return self._conn
```

**The HA compose file sets a single URL:**

```yaml
# docker-compose.ha.yml:392
ws3-indexer:
  environment:
    - OPENSEARCH_URL=http://opensearch-1:9200
```

**Impact:** The 3-node cluster gives durability (replica shards) and read-HA (dashboards-ha lists all 3 nodes), but the application has **zero write failover**. If `opensearch-1` goes down, all indexing stalls — events accumulate unacked in Redis for `max_redeliveries` then dead-letter, while `/_cluster/health` is green (reads still work via nodes 2 and 3). This is the "cluster green, app dead" trap. The dashboards-ha service (line 294) correctly lists all 3 nodes in `OPENSEARCH_HOSTS`, but the INDEXER (the only writer) pins to node-1.

**Note:** The module docstring (lines 27-35) explicitly states batching is NOT attempted for the daemon path because "the daemon acks each message individually right after its handler returns — correctness-critical for at-least-once redelivery." This is the correct call for correctness, but it means the writer is single-host AND single-message-per-request. A `Retry + round-robin` or `opensearch-py` client with host-list would address the write-failover without changing the ack semantics.

**Confidence:** HIGH. `self._host` is singular. `_connection()` builds one `http.client.HTTPConnection` to that host. No host list, no rotation, no failover retry to a different node (the retry in `_request()` and `index()` only retries to the same host).

---

### Finding 3 [HIGH] — Async-replication durability contradicts at-least-once "zero lost" claim

**Defect pattern:** Pattern 3 — async-replication durability vs at-least-once claim.  
**Files:** `infra/docker-compose.ha.yml`, lines 57-58, 97-98, 116-117; `SSOT.md` line 94

**Redis HA config:**

```yaml
# redis-1, redis-2, redis-3 all use:
--appendonly yes --requirepass "$$REDIS_PASSWORD"
```

No `--min-replicas-to-write`, no `--min-replicas-max-lag`, no `WAIT` command in the application. The replicas are plain async (`--replicaof`).

**SSOT claim:**

> `make chaos` (M1 gate): `scenarios=40 lost=0 duplicated=0` — at-least-once delivery + Redis-backed window counters + deterministic alert_id genuinely give effectively-once alerting through a SIGKILL of every pipeline stage. | **Proven**

**Reality:** `make chaos` kills consumer processes, not the Redis primary. The `lost=0` metric proves consumers recover from crashes (redelivery works). It does NOT prove a primary failover loses zero. With async replication, a write ACK'd to the primary but not yet replicated is silently lost when the primary dies — the producer already got a success response and will never retransmit. This is a durability gap, not a connectivity gap (the generator-failover fix covers connectivity). The SSOT's "zero lost" claim is only true for consumer crashes, not primary crashes.

**Grep confirmation:** Zero hits for `WAITAOF`, `waitaof`, `MIN-REPLICAS`, `min-replicas`, `WAIT` across `infra/`, `services/`, and `tools/`.

**Impact:** A hard primary failover (power loss, OOM kill) loses the tail of not-yet-replicated writes — the number of lost events is bounded by the replication lag window (sub-second in normal operation, but potentially larger under load). Zero signal to the operator.

**Confidence:** HIGH. The Redis command lines are verbatim in the compose file. No WAIT/WAITAOF in any application code. The `chaos_test.py` only kills consumers, not the Redis primary.

---

### Finding 4 [HIGH] — HA path never exercised by an automated gate

**Defect pattern:** Pattern 4 — the HA/failover/chaos path is never exercised by an automated gate.  
**Files:** `.github/workflows/ci.yml` (all jobs), `Makefile` (all targets), `tools/chaos_test.py`

**What CI runs:**
- `contract-tests` — zero-infra memory bus
- `redis-integration` — single-instance `redis:7` (not Sentinel)
- `docker-build` — builds base `docker-compose.yml` only

**What CI does NOT run:**
- No Sentinel, no multi-node Redis
- No multi-node OpenSearch
- No HA compose profile
- `make chaos` is NOT run in CI (it's in the Makefile at line 81 but not in any workflow)

**What `make test-live` covers:** Only `BUS_BACKEND=redis` (single instance), never `redis-sentinel`.

**`test_sentinel_failover.py`:** Uses `_DeadBus`/`_LiveBus` fakes (lines 43, 72) — no real Redis. Correctly tests the failover *wrapper logic*, but cannot catch the env-gated detection branch (Finding 1) or real Sentinel connectivity issues.

**Impact:** The HA layer is the highest-defect surface in the project and the least-tested. Finding 1 (the CRITICAL one) shipped because there is no automated test that brings up the HA profile and asserts detection fires. Every finding in the docker-compose.ha.yml comments (6 bugs discovered in the 2026-08-05 manual bring-up) was found manually, not by CI.

**Confidence:** HIGH. All CI job definitions are in `ci.yml`. No job references `docker-compose.ha.yml`, `sentinel`, or `BUS_BACKEND=redis-sentinel`.

---

### Finding 5 [HIGH] — Racy counters outside lock under worker pool

**Defect pattern:** Pattern 5 — racy counters incremented outside the lock under a worker pool.  
**File:** `services/ws1-collectors/collectors/syslog_udp_server.py`, lines 300-324

```python
# syslog_udp_server.py:300-324
def _handle_datagram(self, data: bytes, peer_ip: str) -> None:
    ...
    if not self._buckets.take(tenant_id or ""):
        if self._try_spool(peer_ip, event):
            self.events_spooled += 1       # line 308 — NOT under _shed_lock
            return
        self._count_shed(peer_ip, ...)     # line 310 — IS under _shed_lock
        return
    try:
        self.bus.produce(self.topic, key=peer_ip, payload=event)
    except Exception as exc:
        if self._try_spool(peer_ip, event):
            self.events_spooled += 1       # line 316 — NOT under any lock
            return
        self.events_dropped += 1           # line 318 — NOT under any lock
        ...
        return
    self.events_produced += 1              # line 324 — NOT under any lock
```

`self._shed_lock` (line 277) only guards `_count_shed()` (lines 342-361) which protects `events_shed`, `events_lost`, and the log-throttle timestamp. The three counters on the success + spool paths — `events_spooled`, `events_dropped`, `events_produced` — are all incremented **outside** any lock, called concurrently by `DEFAULT_WORKERS=4` handler threads (line 83).

`+=` on a Python `int` attribute is a non-atomic read-modify-write. Under load, these operator-facing counters **undercount** — the exact metrics the design exists to surface.

**Also affected:** `events_queue_full` at line 408-409 IS correctly under `_shed_lock` — credit where due. But `events_produced` (the headline throughput counter) is not.

**Impact:** At production rates, the operator's `/metrics` endpoint under-reports actual throughput, spool usage, and drop counts. The undercount grows with load — exactly when you need the numbers most.

**Confidence:** HIGH. 4 worker threads, 3 counters on the hot path, all bare `+=`. The `_shed_lock` lock guard is explicitly present on the shed path but absent on the success path.

---

### Finding 6 [MEDIUM] — Non-deterministic ingest_id in production shadows deterministic fallback

**Defect pattern:** Pattern 6 — non-deterministic id in production where a deterministic fallback exists.  
**Files:** `services/ws1-collectors/collectors/syslog_udp_server.py` lines 194-207, 304; `services/ws2-normalization/parsers/generic_syslog.py`

```python
# syslog_udp_server.py:194-207
def build_raw_event(line: str, *, deterministic_id: bool = False) -> dict:
    if deterministic_id:
        ingest_id = _deterministic_ingest_id(line)  # SHA-256 of line content
    else:
        ingest_id = str(uuid.uuid4())                # random — DEFAULT
    return {..., "meta": stamp_meta({..., "ingest_id": ingest_id})}

# Called at line 304 — deterministic_id defaults to False (the __init__ default)
event = build_raw_event(line, deterministic_id=self.deterministic_id)
# main.py never passes deterministic_id=True to SyslogUDPServer
```

The `_deterministic_ingest_id()` function (line 188-191) exists — `SHA-256(content)` → deterministic UUID-like string. It is tested and working. But `main.py` (lines 121-126) never passes `deterministic_id=True` to `SyslogUDPServer`. In the WS-2 parser, there is a content-hash fallback for missing `ingest_id`, which IS correct idempotency design. But because the collector ALWAYS stamps a random UUID, the fallback is **dead code** for this source.

**Impact:** UDP is connectionless — the same datagram can be retransmitted by the network or re-sent by the device. Each retransmission gets a different `uuid4()`, producing a different `ingest_id` → different `alert_id` → duplicate alerts in OpenSearch. Bus-level redelivery dedup still works (same payload carries same ingest_id), but **ingest-edge dedup** does not. The fix is trivial: pass `deterministic_id=True` (or make it the default).

**Confidence:** HIGH. `deterministic_id` defaults to `False` in `SyslogUDPServer.__init__` (line 261). `main.py` never passes it.

---

### Finding 7 [MEDIUM] — OpenSearch health check reports green while writes fail (the "cluster green, app dead" trap)

**Defect pattern:** Related to Pattern 2 — health check does not verify write path.  
**File:** `infra/docker-compose.ha.yml`, lines 231, 256, 281

```yaml
# All three OpenSearch nodes:
healthcheck:
  test: ["CMD-SHELL", "curl -sf http://localhost:9200/_cluster/health || exit 1"]
```

Each node checks itself (localhost). `/_cluster/health` returns green as long as the cluster has a master and all shards are assigned — which is true even if `opensearch-1` (the one the writer is pinned to) is completely unreachable, because nodes 2 and 3 can still form a quorum and serve reads.

**Impact:** In a node-1 outage scenario, the orchestrator sees 3/3 green health checks while WS-3 loops on `ConnectionError` to `opensearch-1:9200`. The compose `depends_on` with `condition: service_healthy` is satisfied — opensearch-1 IS healthy, just not reachable from the indexer. This is a compose-level gap, not an application bug, but it compounds Finding 2.

**Confidence:** HIGH. The health check is localhost-only. No write-path probe.

---

### Finding 8 [LOW / INFO] — Cleartext-at-rest spool

**Defect pattern:** Pattern 7 — cleartext-at-rest opt-in surface.  
**File:** `services/ws1-collectors/collectors/syslog_udp_server.py` (spool path); `SECURITY.md` §8

The `BoundedSpool` (enabled by setting `SYSLOG_SPOOL_PATH`) writes full event payloads (including raw syslog lines that may contain credentials) to disk unencrypted. SECURITY.md §8 discloses this. The residual risk: the spool file lives on a named Docker volume that outlives the container; there is no lifecycle management to purge it after replay.

**Rating:** LOW because it's disclosed and opt-in (disabled by default). Worth documenting, not fixing urgently.

---

### Finding 9 [INFO — VERIFIED] — Bus-only coupling (zero cross-workstream imports) **holds**

**Defect pattern:** Pattern 9 (verification).  
**Grep:** `grep -rnE "from ws[0-9]-[a-z]+ import|import ws[0-9]-" services --include="*.py"`

**Result:** Zero hits. The only cross-package imports are into `services/shared/`. The claim in SSOT §2 ("Bus-only coupling — Proven — Grepped, zero hits — confirmed twice") is **verified correct**. Every service communicates exclusively through the message bus (`shared.bus`).

---

### Finding 10 [INFO — VERIFIED] — Idempotency across time boundaries correctly uses event content time

**Defect pattern:** Pattern 8 verification.  
**File:** `services/ws3-indexer/router.py`, lines 36-41, 64-83

```python
def _date_suffix(epoch_ms: int | None) -> str:
    if epoch_ms:
        dt = datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
    else:
        dt = datetime.now(tz=timezone.utc)  # fallback for missing time
    return dt.strftime("%Y.%m.%d")

def route(doc: dict) -> tuple[str, str]:
    ...
    return f"{base}-{_date_suffix(doc.get('time'))}", str(doc["alert_id"])
```

The index date suffix is derived from `doc.get('time')` — the **event's own timestamp**, not `datetime.now()`. This means redelivery across midnight still maps to the same index name, and the `_id`-based upsert (OpenSearch `PUT /{index}/_doc/{id}`) correctly deduplicates. This is correctly implemented. The `else: datetime.now()` fallback is for events missing a `time` field — a degenerate case that would produce cross-boundary duplicates, but those events are malformed to begin with.

---

### Finding 11 [INFO — VERIFIED] — Bus delivery semantics: XAUTOCLAIM/XPENDING/DLQ/trim-acked are correct and well-tested

**File:** `services/shared/bus.py`, lines 206-252 (claim_pending), 317-398 (trim_acked); `services/shared/runner.py`, lines 231-266 (_process_message)

- **XAUTOCLAIM** (lines 222-240): Correctly loops with cursor, handles deleted entries (empty fields), and decodes via `_decode_entry` (which quarantines poison entries). Correct.
- **XPENDING per-message delivery counter** (lines 242-252): Reads authoritative `times_delivered` from Redis via `xpending_range`. This counter survives consumer restarts (it's Redis-side state, not in-process). Correct.
- **DLQ** (runner.py lines 243-252): When `delivery_count > max_redeliveries`, messages are routed to `<topic>.deadletter` and acked. Correct.
- **trim_acked** (bus.py lines 317-398): Nearly a research paper in a docstring. Safety proof is correct: computes the minimum frontier across all consumer groups, using the group's oldest PENDING id (must keep) or last-delivered-id+1 (everything through it is done). Never trims a topic with no consumer groups. Uses `approximate=False` for exact trim. Correct and conservative.
- **Generator failover fix** (bus.py lines 468-504): The `_iter_with_failover` vs `_with_failover` distinction is correct. Generator methods delegate via `yield from` so iteration (where I/O happens) is inside the try. Live-verified 2026-08-05. Correct.

**Redis-integration CI job** (`ci.yml` lines 50-87): Runs `test_runner.py`, `test_bus_trim_acked.py`, `test_bus_lag.py`, `test_bus_read_count.py` against a real `redis:7` service container with `BUS_BACKEND=redis`. Covers the core Streams mechanics.

---

### Finding 12 [INFO — VERIFIED] — /health 503, depth watchdog, backpressure, Prometheus, runner error handling are correct

- **`/health` 503** (`runner.py` lines 84-105, 197-203): `HealthState.bus_ok` flag. Workers call `state.mark_error()` on consume/claim exceptions. `/health` returns `503 {"status": "degraded"}` with the error string when `bus_ok` is False. Compose health checks (all 7 services) ping `/health` and will restart the container. Correct.

- **Depth watchdog** (`runner.py` lines 419-458): Uses `bus.lag()` (true per-group consumer backlog = undelivered + pending), NOT `bus.depth()` (XLEN = total stream entries including acked). This is the correct signal for backpressure alerting. Correct.

- **Backpressure** (`syslog_udp_server.py` lines 66-72, 272): Token-bucket shedding at the ingest edge (`SYSLOG_MAX_EVENTS_PER_SEC`, default 2000/s). Per-tenant isolation via `TenantTokenBuckets`. Spool fallback for shed/dropped events. The "protects against OOM" claim is SSOT-acknowledged as "unit-tested, not load-tested" (SSOT line 91). Honest.

- **Prometheus metrics** (`runner.py` lines 138-172): `render_prometheus()` produces valid exposition format. Label values are escaped per spec (`_sanitize_label`). One counter per (topic, result) — correct.

- **Runner loop error handling** (`runner.py` lines 269-319): `_topic_worker` catches exceptions on both `claim_pending` and `consume`, marks health state, throttles tracebacks (30s window per topic+exception type), sleeps on empty reads, respects shutdown. Correct.

- **Traceback throttling** (`runner.py` lines 52-81): `_throttled_print_exc` prevents a poison-message redelivery loop from flooding stderr. Reports suppression count. Correct.

---

## Summary of HA Profile (docker-compose.ha.yml vs base)

### What the HA profile changes (verified against docker-compose.ha.yml):
- Disables single-instance `redis`, `opensearch`, `dashboards`, `provision`, `devkit-feeder` via `profiles: [standard]` (line 40-48 — fixed from `[ha]` which was inverted)
- Adds 3 Redis nodes (primary + 2 replicas) with static IPs on the `ha` network
- Adds 3 Sentinels with state persistence to `/data/sentinel.conf`
- Adds 3-node OpenSearch cluster
- Adds HA dashboards (multi-host)
- Adds `provision-ha` (with corrected `networks: [ha]`)
- Overrides all 7 application services: `BUS_BACKEND=redis-sentinel`, `REDIS_SENTINEL_HOSTS`, `REDIS_SENTINEL_MASTER`, `REDIS_PASSWORD`
- WS-7 (dashboard) has `BUS_BACKEND=redis-sentinel` but **only WS-7** — WS-7 is a read-only dashboard frontend (nginx + static HTML). It does not consume from the bus. Setting `BUS_BACKEND` on WS-7 is harmless (it never constructs a Bus) but unnecessary.
- WS-6 (inventory) override was added in the M7 Track Y follow-up (lines 423-431) — correct.
- `networks: [default, ha]` on all app services so they can reach both each other and the HA backends.
- `depends_on: !override {...}` to prevent merge with base's `depends_on`.

### BUS_BACKEND wiring: ✅ Every service that matters has `BUS_BACKEND=redis-sentinel`:
- ws1-collectors (line 370) — produces to bus ✅
- ws2-normalization (line 379) — consumes + produces ✅
- ws3-indexer (line 388) — consumes ✅
- ws4-detection (line 400) — consumes + produces ✅
- ws5-ai (line 409) — consumes + produces ✅
- ws6-inventory (line 426) — consumes ✅
- ws7-dashboard (line 435) — doesn't use bus, harmless ✅

### What the HA profile does NOT change (gaps):
- **No `REDIS_URL` override** — the application service overrides in ha.yml set `BUS_BACKEND=redis-sentinel` and Sentinel host configs, but do NOT override `REDIS_URL`. `_RedisSentinelBus.__init__` (bus.py line 412) accepts a `url` parameter but falls back to `REDIS_URL` env for its initial connection. Since ha.yml doesn't override `REDIS_URL`, it stays at the base file's value (`redis://...@redis:6379`). The Sentinel discovery path in `_refresh_master()` overwrites this on first successful discovery, so this is only a startup robustness gap (if Sentinel is unreachable at boot, the initial `_RedisBus` points at the non-existent single-instance `redis` host).

---

## Top-3 Highest-Leverage Fixes

1. **Fix the env-gated detection branch (Finding 1).** Change `ws4-detection/main.py` line 314 from `== "redis"` to `in ("redis", "redis-sentinel")` AND fix the Redis client construction inside the block to use `Bus()` factory (which handles Sentinel discovery) or create a client through the Sentinel-discovered master. One-line gate change, detection comes back online for all 12+ stateful rules under HA.

2. **Add OpenSearch write failover (Finding 2).** Either use `opensearch-py` with a host list, or implement a simple round-robin/retry across the 3 nodes in the existing `_request()` method. The retry in `index()` already exists (3 attempts, exponential backoff) — it just needs to try a different host on failure.

3. **Fix racy ingest-edge counters (Finding 5).** Move `events_produced += 1`, `events_spooled += 1`, `events_dropped += 1` under `self._shed_lock` (or use `itertools.count` which is atomic in CPython). The lock already exists and already guards the shed counters — extending it to the success path is a 3-line change.

---

## What's Genuinely Well Done (credit where due)

- **Bus implementation quality:** The `trim_acked` safety proof (lines 347-398) is exceptionally well-reasoned. The poison-message handling in `_decode_entry` (lines 141-170, quarantining without wedging the consumer) is the right call. The `lag()` implementation (lines 265-315) correctly sums undelivered + pending across all groups — this is subtle and was live-verified.
- **Runner discipline:** One thread per topic, ack-after-handler, redelivery→DLQ, graceful shutdown with worker join, traceback throttling. This is production-grade infrastructure.
- **Deterministic alert_id:** `engine.py` `alert_key()` (lines 515-577) is a pure function of the triggering event, correctly tenant-namespaced, with a documented window-bucket boundary behavior. The content-hash fallback for ingest-less events is correct.
- **Index naming from event time:** `router.py` `_date_suffix()` uses `doc.get('time')`, not `datetime.now()`. Correct for cross-boundary dedup.
- **The 2026-08-05 HA bring-up pass:** Finding and fixing 6 real bugs (sentinel tilt, generator failover, provision-ha network isolation, network attachment, ip_range collision, entrypoint resolution timeout) in a single live session is impressive. The documentation of each bug in the compose file comments is valuable.
- **Zero cross-workstream imports:** Verified, not eyeballed. The architectural discipline holds.

---

## Consistent SSOT vs Code Claims Check

| SSOT Claim | Verdict | Notes |
|---|---|---|
| Bus-only coupling (zero cross-workstream imports) | **VERIFIED TRUE** | Grep: zero hits |
| WS-4 redelivery + DLQ on real Redis (XAUTOCLAIM/XPENDING) | **TRUE** | Code correct, CI exercises it |
| Deterministic alert_id | **TRUE** | `alert_key()` is deterministic and tenant-namespaced |
| `make chaos` zero lost | **TRUE for consumer crashes** | Does NOT test primary failover durability |
| HA opt-in profile: Sentinel master discovery | **TRUE (now)** | Fixed in 2026-08-05 pass |
| Application layer failover PROVEN | **PARTIALLY TRUE** | True for produce/ack/depth/lag; consumer failover fixed 2026-08-05; OpenSearch writer still single-endpoint |
| ILM/retention policies enforced on live OpenSearch | **PROVEN LIVE** | ISM policies install + auto-attach verified |
| F4 per-tenant throughput isolation | **PROVEN** | `TenantTokenBuckets` at ingest edge, tested |
| B2 backpressure protects Redis under real flood | **UNIT-TESTED, not load-tested** | Honest admission in SSOT — not misrepresenting |

---

*End of audit. This report was compiled from direct code inspection, grep verification, and the existing documentation's own bug-discovery logs. No claims were assumed true without independent code-path verification.*