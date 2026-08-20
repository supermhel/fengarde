# FENGARDE — Performance Review

**Reviewer role:** Performance (high-throughput network/security data systems)
**Scope:** ingestion → parsing → detection → indexing hot paths, in light of the "thousands+ events/sec" SIEM target
**Method:** direct source review of `services/shared/bus.py`, `services/ws1-collectors/collectors/syslog_udp_server.py`, `services/ws2-normalization/{main.py,parsers/*,enrichment}`, `services/ws4-detection/{engine.py,window.py,main.py,tenants.py,scoring.py}`, `services/ws3-indexer/storage/{opensearch.py,memory.py}`, `services/ws5-ai/{main.py,llm_adapter.py}`, `services/shared/{runner.py,log.py,ocsf.py}`, plus `tools/validate_contract.py` and the published bench numbers in `README.md`.

**Context worth stating up front:** this codebase has already been through several perf-focused audit passes (P0-4 UDP recv/dispatch decoupling, P1-3 one-`Bus()`-per-worker instead of per-event, P1-4 OpenSearch persistent connections + real `_bulk`, P1-5 O(1) window member-dedup, P1-8 XREADGROUP batch size, B1 rule class_uid bucketing). Those closed the historically worst hotspots and each carries a code comment citing what was live-measured. The findings below are what's left on top of that baseline, not a rediscovery of already-fixed issues.

---

## Ranked findings

### 1. [HIGH] Detection engine re-tokenizes and re-parses every rule's condition string on every single event

**File:** [services/ws4-detection/engine.py:396-413](services/ws4-detection/engine.py:396) (`Rule._eval_condition`), also [engine.py:352-361](services/ws4-detection/engine.py:352) (`_selection_matches` → `get_path`)

```python
def _eval_condition(self, event: dict) -> bool:
    matched = {name: self._selection_matches(sel, event) for name, sel in self.selections.items()}
    expr = self.condition.strip() or " and ".join(self.selections)
    tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[\w.]+", expr)   # <-- every event
    try:
        value, end = _parse_or(tokens, 0, matched)                     # <-- every event
        return bool(value) if end == len(tokens) else False
    except (ValueError, IndexError, RecursionError):
        return False
```

`self.condition` is a **static string fixed at rule-load time** (it comes straight from the rule's YAML and never changes for the life of the `Rule` object — `reload()` builds fresh `Rule` instances rather than mutating this one). Yet every call to `evaluate()` re-runs `re.findall` over it and re-walks the whole recursive-descent boolean parser (`_parse_or`/`_parse_and`/`_parse_not`/`_parse_atom`) from scratch. This happens **once per candidate rule per event** — and `Detector.process()`'s class_uid bucketing (B1) only prunes rules by class, not by count, so a class with several overlapping rules (e.g. every `common_*` auth rule sharing class 3002) pays this on every matching event, at whatever the real ingest rate is.

`get_path()` ([engine.py:55-61](services/ws4-detection/engine.py:55)) compounds this: every selection's dotted OCSF path (`"src_endpoint.ip"`, `"actor.user.name"`, ...) is `.split(".")`'d fresh on every lookup, for every selection, for every rule, for every event — also static per rule.

**Why it matters at SIEM volumes:** this is pure-Python interpreter overhead (regex engine invocation + recursive function calls) sitting directly in the per-event critical path of WS-4, the one stage every event must pass through before scoring. At the README's own measured ~13k EPS zero-infra baseline, shaving redundant per-event work here is the highest-leverage, lowest-risk win available — it's CPU the code is spending to reconstruct a value that never changes.

**Fix (quick win, no behavior change):** cache the tokens once in `Rule.__init__`:
```python
self._tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[\w.]+",
                           self.condition.strip() or " and ".join(self.selections))
```
and reuse `self._tokens` in `_eval_condition` instead of recomputing `expr`/`tokens` per call. Same for each selection's dotted path — split once at load time (e.g. precompute `list[tuple[str, ...]]` per selection) and have `get_path` walk pre-split tuples. Neither change touches evaluation semantics; both are mechanical hoist-out-of-loop fixes safe to unit-test against the existing rule-firing suite (`eval/attack/fire_check.py`, `test_v05_beaconing.py`, etc.) byte-for-byte.

---

### 2. [MEDIUM-HIGH] Enrichment IOC/GeoIP lookups are unindexed linear scans, unbounded by feed size, with no per-IP cache

**File:** [services/ws2-normalization/enrichment/__init__.py:87-116](services/ws2-normalization/enrichment/__init__.py:87) (`_reputation_for`, `_location_for`)

```python
def _reputation_for(self, ip_str: str) -> Optional[dict]:
    ...
    for net, record in self._ioc_nets:            # linear scan, every event
        if addr.version == net.version and addr in net:
            ...
def _location_for(self, ip_str: str) -> Optional[dict]:
    ...
    for net, country in self._geo_nets:            # linear scan, every event
        if addr.version == net.version and addr in net:
            ...
```

Both run on **every enriched event** ([ws2-normalization/main.py:87](services/ws2-normalization/main.py:87) calls `enrich(event)` unconditionally in `normalize_one`). The exact-IP path is an O(1) dict hit, but any CIDR-shaped entry falls through to a full `for net, ... in self._ioc_nets` / `self._geo_nets` scan with no early exit (it has to check every network to find the *longest-prefix* match). Today's shipped `contracts/enrichment/ioc.yml`/`geoip.yml` are presumably small, so this is invisible in dev — but a real threat-intel IOC feed (the whole point of the reputation field) is routinely thousands to tens of thousands of CIDR ranges, and a real GeoIP CIDR table is tens of thousands of ranges. At that size this becomes an O(n) tax **per event**, and it hits hardest exactly during the traffic this SIEM is built to catch: a single attacker IP repeating across a brute-force/port-scan burst re-runs the identical scan on every one of those hundreds of events instead of reusing the first answer.

**Fix:**
- **Quick win:** memoize `_reputation_for`/`_location_for` by `ip_str` (an `lru_cache`-style bounded cache, same LRU-with-cap pattern already used in `tenants.py`'s `_CACHE`/`_CACHE_MAXSIZE`). This alone erases the cost for any repeated-IP burst, which is the dominant real-world case.
- **Structural, if feed size grows:** replace the linear CIDR list with a structure that supports true O(log n) or O(1) longest-prefix lookup — a sorted-by-network-address list with `bisect` + walk-up, or a small radix/patricia trie keyed on address bits. Not urgent while feeds stay small; becomes necessary the moment a real IOC feed is wired in.

---

### 3. [MEDIUM] WS-5 AI tier is a single blocking consumer thread — no concurrency for LLM/classifier calls

**File:** [services/ws5-ai/main.py:94-113](services/ws5-ai/main.py:94) (`main`), [services/ws5-ai/llm_adapter.py:136-169](services/ws5-ai/llm_adapter.py:136) (`OllamaLLM.analyze`)

`serve({"ai.requests": ("cg-ai", handler)}, ...)` gives `ai.requests` exactly **one** worker thread ([shared/runner.py](services/shared/runner.py) starts one thread per topic, and WS-5 registers one topic). `handler()` calls `worker.handle()` synchronously, which for the `"llm"` tier does a **blocking** `urllib.request.urlopen(...)` POST to Ollama ([llm_adapter.py:154](services/ws5-ai/llm_adapter.py:154), `timeout=8.0`). That means WS-5's entire throughput ceiling is `1 / (LLM round-trip latency)` — a single Ollama call taking even 1-2 seconds (typical for a local model) caps this tier at well under 1 event/sec, with every other queued `ai.requests` message sitting in the PEL behind it.

This is architecturally decoupled from the hot path correctly (WS-4 never blocks on it, `ai.requests` has its own backpressure watchdog), so it will not stall ingestion/detection/indexing — but the scoring funnel is explicitly designed to route a real fraction of traffic here (`classifier_min` and `llm_min` in `scoring.yaml`), and under sustained real attack/incident volume (exactly when triage matters most), a single serial worker means the AI triage backlog grows unboundedly behind live traffic, so alerts sit un-triaged for however long the queue takes to drain at 1-at-a-time.

**Fix:** give WS-5 a small worker pool for the `ai.requests` topic (either N `runner` workers via multiple registered handlers/threads, or a bounded `ThreadPoolExecutor` inside the single handler so N Ollama calls are in flight concurrently). The `"classifier"` tier (`classifier.py`, no network call) is presumably cheap and not the bottleneck; scoping the pool to the LLM path specifically avoids over-engineering the cheap tier.

---

### 4. [LOW-MEDIUM] `MemoryStore.list_alerts`/`list_events` do a full unbounded scan + sort on every call, with no retention/eviction

**File:** [services/ws3-indexer/storage/memory.py:90-116](services/ws3-indexer/storage/memory.py:90)

```python
def list_alerts(self, *, tenant_id=None, status=None, limit=50) -> list[dict]:
    docs: list[dict] = []
    for index, bucket in self._indices.items():
        if not index.startswith("alerts"):
            continue
        docs.extend(bucket.values())          # every alert ever indexed, every index
    ...
    docs.sort(key=lambda d: d.get("time") or 0, reverse=True)   # full sort before slicing to `limit`
    return docs[:limit]
```

`MemoryStore` (the `STORAGE_BACKEND=memory` dev/test backend) never expires anything — every document ever indexed across every day's index stays in the process dict forever, and `list_alerts`/`list_events` materialize and fully sort the *entire* history on every call just to return the top `limit`. This is fine for tests and short-lived demos (the intended use), but is a real O(n log n)-growing-with-n cost if `STORAGE_BACKEND=memory` is ever left running against real sustained traffic (a misconfigured demo, a long-lived CI soak, etc.) rather than the intended `opensearch` backend. Since real deployments use `OpenSearchStore` (which delegates sort/limit to the cluster), this is scoped strictly to the dev backend — flagging it so it's not mistaken for a production-path issue, and so nobody reaches for `STORAGE_BACKEND=memory` as a "lightweight" production option without knowing this ceiling exists.

**Fix (only if this backend is ever meant to run long-lived):** cap retained documents per index (ring-buffer or count-based eviction) the way the window counters already bound their own state; not worth the complexity otherwise given `OpenSearchStore` is the real target.

---

### 5. [LOW] `RedisWindowCounter.hit_periodic()` doubles Redis round trips for periodicity/beaconing rules

**File:** [services/ws4-detection/window.py:246-253](services/ws4-detection/window.py:246)

```python
def hit_periodic(self, key, now_ms, window_ms, member=None):
    zkey = f"{self.ns}:{key}"
    count = self.hit(key, now_ms, window_ms, member)          # 1 pipelined round trip (ZADD/ZREMRANGEBYSCORE/ZCARD/EXPIRE)
    times = sorted(int(score) for _, score in self.r.zrange(zkey, 0, -1, withscores=True))  # a SECOND round trip
    return count, _coefficient_of_variation(times)
```

Every other stateful-rule path (`hit`, `hit_distinct`) is a single pipelined Redis round trip. `hit_periodic` (used by `common_beaconing.yml` and any future periodicity rule) issues that same pipeline *plus* a separate, non-pipelined `ZRANGE ... WITHSCORES` over the whole window to compute the coefficient of variation. At today's rule count (one beaconing rule) this is negligible; if periodicity rules proliferate, each one doubles its Redis RTT cost relative to a plain count/distinct-count rule of the same window size.

**Fix, if this becomes a hot rule class:** fold the ZRANGE into the same pipeline as the ZADD/ZREMRANGEBYSCORE/ZCARD/EXPIRE batch (pipelines already return a list of per-command results, so this is a one-line addition to the existing `pipe` — no separate network round trip needed). Not worth doing pre-emptively for a single rule; worth doing before periodicity rules become a substantial fraction of the stateful rule set.

---

## Quick wins vs. deeper work

| Finding | Effort | Risk | Payoff |
|---|---|---|---|
| #1 Cache rule condition tokens + pre-split paths | Small (hoist to `__init__`) | Very low — no semantic change, existing fire-check/hot-reload tests cover it | Direct per-event CPU reduction in the one stage every event passes through |
| #2 LRU-cache enrichment IP lookups | Small (same pattern as `tenants.py`) | Very low | Removes O(n) repeat cost for the exact traffic shape (bursts from one IP) this SIEM targets |
| #2b CIDR structure upgrade | Larger | Low (isolated to `Enricher`) | Only matters once real large IOC/GeoIP feeds are wired in — not urgent today |
| #3 WS-5 worker pool for LLM calls | Medium (runner/threading change, scoped to one service) | Low-medium (must preserve ack-after-success semantics per in-flight request) | Prevents AI-triage backlog collapse under real incident volume |
| #4 MemoryStore retention cap | Small, but low priority | Low | Only matters if the dev backend is ever run long-lived; not a production-path fix |
| #5 Fold periodicity ZRANGE into the pipeline | Small | Very low | Only matters if periodicity rules become a large share of stateful rules |

## What's already solid (no action needed)

- One `Bus()` per worker thread, not per event (`P1-3`) — the single biggest historical per-event cost (fresh Redis TCP connect) is gone.
- UDP ingest: recv loop and dispatch are already decoupled via a bounded queue + worker pool (`P0-4`), with the real kernel-drop counter (`RcvbufErrors`) surfaced instead of a misleading all-healthy app-level metric.
- Rule matching is already bucketed by `class_uid` (`B1`) so an event only evaluates the subset of rules that could possibly match it, not the full rule set.
- Window-counter member dedup is already O(1) via a mirrored set (`P1-5`), not the prior O(window-size) linear scan — this was previously the classic O(n²) brute-force-burst trap and is already fixed.
- OpenSearch client already reuses a persistent connection and has a real `_bulk` API for the batch/tooling path (`P1-4`); per-message indexing in the live daemon is a deliberate, disclosed correctness-over-throughput tradeoff (batching would need a redesign of ack timing), not an oversight.
- Structured logging is level-gated before serialization (`P2-3`) and the UDP path's former per-datagram log line is gone — no accidental I/O tax on the hot path.
- Tenant-disabled-rules lookup is already cache-bounded (LRU with a hard cap), the exact pattern finding #2 above recommends applying to enrichment lookups too.
