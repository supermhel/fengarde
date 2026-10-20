# FENGARDE — Bug Hunter Report

Role: functional bug hunter (part of a multi-reviewer swarm — architecture, security, performance, and quality are covered separately). Scope: full repo, read-only static + dynamic (executed) analysis. Focus per brief: off-by-one errors, incorrect log-format parsing, race conditions, swallowed exceptions, null/missing-field handling, timezone/timestamp correctness, detection-rule edge cases (false positive/negative), state management.

Method: four parallel audits (WS1+WS2, WS3+WS4, WS5+WS6+WS7+shared bus, tools/eval/contracts), each required to reproduce findings against the real code where feasible rather than report from static reading alone. Findings below are only cases with a concrete file/line citation and a reproduced or clearly traceable failure scenario — speculative "could be improved" items were discarded during the hunt.

This codebase already carries a dense prior audit history (inline comments tagged P0/P1/P2/T6/T7/F1/B1/A3/C1/C3, 2026-07-21). Most findings here are gaps those passes left behind — a fix applied at one call site but not a structurally identical sibling — rather than never-considered bugs.

## Severity summary

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 6 |
| Medium-High | 2 |
| Medium | 3 |
| Low-Medium | 1 |
| Low | 3 |

---

## Critical

### C1. `DequeWindowCounter` assumes monotonically increasing event time — out-of-order events get stuck in-window forever, inflating correlation counts

**File:** [services/ws4-detection/window.py](services/ws4-detection/window.py) — `hit()` (~148-171), `hit_distinct()` (~173-187)

Both methods evict stale entries only from the **front** of the deque (`while w and w[0][0] < horizon: w.popleft()`), while new entries are always appended to the back regardless of their own timestamp. This is only correct if `now_ms` is non-decreasing per key. It isn't: per `contracts/bus-topics.md`, event time can differ from ingest order under replay, clock skew, or forwarded/batched logs, and the bus's Redis backend does not actually implement per-key ordering (`_RedisBus` XADDs to one shared stream, consumer group members round-robin batches). Several stateful rules group on fields that guarantee interleaving by design — `common_password_spray.yml` and `common_impossible_travel.yml`/`common_lateral_movement.yml` group by `actor.user.name` across many distinct source IPs.

`RedisWindowCounter` (same file, ~214-244) evicts via `ZREMRANGEBYSCORE`, which has no such ordering assumption — the two backends silently diverge under reordering.

**Reproduced:**
```
window_ms = 300_000
hit_distinct("alice", now=0,      value="ip1") -> 1
hit_distinct("alice", now=299000, value="ip2") -> 2
hit_distinct("alice", now=5000,   value="ip3") -> 3   # late-arriving
hit_distinct("alice", now=302000, value="ip4") -> 3
hit_distinct("alice", now=310000, value="ip5") -> 4   # WRONG, correct = 3
```
At `now=310000` the window is `[10000, 310000]`; `ip3` (t=5000) is outside it but stays counted because it's wedged behind `ip2`, which hasn't expired yet.

**Failure scenario:** For `common_password_spray.yml` (8 distinct source IPs / 300s), a single out-of-order delivery — plausible any time multiple collectors or XREADGROUP batch interleaving are involved — can leave a phantom "distinct IP" entry permanently stuck in the window, padding the count and firing the rule early, or on the wrong set of sources. Direction is always overcounting (never masks a real attack), so this is an alert-integrity/false-positive-timing bug, not a missed detection. It also gives active, high-cardinality keys (busy usernames/hosts) an unbounded-memory-growth path, since the idle-key sweep only drops keys with no recent activity — a steadily-active key with stuck stale entries never gets cleaned.

No existing test drives a non-monotonic sequence (`test_window.py`, `test_window_distinct.py`, `test_window_periodic.py` are all strictly increasing).

**Fix:** Evict by absolute timestamp rather than front-position only (e.g. keep the deque time-sorted via `bisect.insort` on insert so the front invariant holds, or do a full filter pass). If O(1) insert must be preserved, at minimum track a per-key high-water-mark and drop an incoming event outright if it's already older than `high_water_mark - window_ms`.

---

## High

### H1. WS5 daemon creates a fresh `Bus()` per message — output silently discarded under the memory backend

**File:** [services/ws5-ai/main.py:105-113](services/ws5-ai/main.py)

```python
def handler(payload: dict) -> None:
    bus = Bus()
    ...
    bus.produce("ai.results", ...)
    bus.produce("alerts", ...)
```

`Bus()` returns a brand-new, isolated `_MemoryBus()` instance every call when `BUS_BACKEND=memory` (confirmed: `Bus() is Bus()` → `False`; one instance's writes are invisible to another's reads). Calling `Bus()` fresh inside the per-message handler means every `ai.results`/`alerts` message is written into a throwaway bus nothing else ever reads.

This exact bug class was already found and fixed elsewhere in the same codebase — `services/ws2-normalization/main.py:113-119` and `services/ws4-detection/main.py:286-292` both carry a `P1-3 (2026-07-21 audit)` comment explaining the fix ("ONE Bus() per worker, not one per event... fresh redis-py client per event [is] the single biggest avoidable per-event cost"). WS5's `main()` never received the same fix.

**Failure scenario:** Run `ws5-ai` as a daemon with `BUS_BACKEND=memory` — the project's documented zero-infra dev mode — and every triaged `ai.requests` message vanishes silently; `ai.results` and `alerts` stay empty forever, handler returns normally and acks. Under `BUS_BACKEND=redis` it's not data loss but opens a new unbounded `redis.Redis` connection per single AI-triage message.

**Fix:** Hoist `bus = Bus()` once before defining `handler`, same as WS2/WS4 (`handler_bus = Bus()`).

### H2. WS6 inventory upsert has no staleness check — out-of-order writes regress asset state and invert history intervals

**File:** [services/ws6-inventory/store.py:86-125](services/ws6-inventory/store.py) (`_upsert_locked`)

`_upsert_locked` applies whatever `seen_at` a caller sends without comparing it to `row["last_seen"]` first. Delivery is at-least-once everywhere per project convention, and `POST /assets/upsert` is served by a `ThreadingHTTPServer` with no cross-request ordering guarantee.

**Reproduced:**
```
newer obs first:  mac X -> ip 10.0.0.9 @ 12:05
stale obs after:  mac X -> ip 10.0.0.5 @ 12:00   (delayed retry/redelivery)

Result:
  ip_current = 10.0.0.5   WRONG (regressed)
  last_seen  = 12:00      WRONG (regressed)
  ip_history = [{ip:10.0.0.5, from:12:00, to:None},
                {ip:10.0.0.9, from:12:05, to:12:00}]   <- to_ts BEFORE from_ts, inverted interval
```
The inverted interval breaks `resolve()`'s historical-correctness guarantee for that MAC going forward. `test_contract.py` only tests forward-ordered updates, so this is untested.

**Fix:** Compare `seen` against `row["last_seen"]` (and the open `ip_history` interval's `from_ts`) before applying; skip or merge-without-regressing when the incoming observation is older than what's on file.

### H3. `MemoryStore.index_cas` is a non-atomic check-then-act — concurrent triage writes silently lose an update while both report success

**File:** [services/ws3-indexer/storage/memory.py:80-87](services/ws3-indexer/storage/memory.py) (`index_cas`)

```python
def index_cas(self, index, doc_id, document, version) -> bool:
    if version is None:
        self.index(index, doc_id, document); return True
    if self._versions.get((index, doc_id), 0) != version:   # (A) read
        return False
    self.index(index, doc_id, document)                     # (B) write
    return True
```
No lock spans (A) and (B). `services/ws3-indexer/triage_api.py:551-570` explicitly claims this is safe ("MemoryStore's version counter ... checked-and-incremented atomically by the store itself") — that claim is false; nothing enforces atomicity across the check and the write.

**Reproduced** (widened the race window to force the interleaving the GIL normally makes rare but doesn't prevent):
```
store.index(..., "a1", {"score": 70})       # version 1
Thread A reads version=1; Thread B reads version=1  (both before either writes)
Thread A: index_cas(..., {"status": "A"}, version=1) -> True
Thread B: index_cas(..., {"status": "B"}, version=1) -> True
final doc = {"status": "B"}   # A's update silently gone, both callers told "success"
```
This is live under the **default** backend: `services/ws3-indexer/main.py` uses `MemoryStore` unless `STORAGE_BACKEND=opensearch` is set, and `triage_api.serve()` runs a real threaded HTTP server — i.e. this fires in the "normal dev loop" path, not just a contrived unit test. Production OpenSearch's `index_cas` (`storage/opensearch.py:289-307`) is genuinely safe (`if_seq_no`/`if_primary_term` enforced server-side) — only the in-memory backend has this gap. `test_storage_cas.py`'s 20-thread concurrency test currently passes only because the natural race window is narrow under CPython's GIL, not because the logic is correct.

**Fix:** Wrap the check-then-write in a single `threading.Lock` inside `MemoryStore.index_cas`.

### H4. Three parsers discard `valid_ip()`'s normalized return value — dual-stack IPv6-mapped IPs get dead-lettered

**Files:** [services/ws2-normalization/parsers/cef.py:97,103](services/ws2-normalization/parsers/cef.py), [cloudtrail.py:96-97](services/ws2-normalization/parsers/cloudtrail.py), [k8s_audit.py:110-111](services/ws2-normalization/parsers/k8s_audit.py)

`shared/ocsf.py::valid_ip()` returns the **normalized** address (its docstring explains why: `::ffff:a.b.c.d` — what dual-stack/Windows hosts emit — parses fine via `ipaddress.ip_address` but fails Contract A's `ip` schema pattern, which forbids dots in the IPv6 branch). Every other parser (`db_audit.py`, `active_directory.py`, `n8n_audit.py`, `modbus_anomaly.py`, `opcua_audit.py`, `vmware_vsphere.py`, `windows_eventlog.py`, `sysmon.py`) assigns the *returned* value. These three parsers use `valid_ip()` only as a boolean gate, then assign the original unnormalized string.

**Reproduced:**
```
CEF line: src=::ffff:10.0.0.5
-> src_endpoint.ip = "::ffff:10.0.0.5"   (unnormalized)
valid_ip("::ffff:10.0.0.5") = "10.0.0.5"  (i.e. it WAS valid — just not what got stored)
validate(event) -> FAIL: ".src_endpoint.ip: '::ffff:10.0.0.5' does not match pattern"
```
The entire event is dead-lettered, not just the IP field.

**Fix:** `src_ip = valid_ip(src_ip)` then use `src_ip`, matching every other parser, at all three sites.

### H5. Six parsers use pre-`timeutil` timestamp logic — ISO-8601 timestamps silently become "now"

**Files:** [db_audit.py:121-126](services/ws2-normalization/parsers/db_audit.py), [n8n_audit.py:144-149](services/ws2-normalization/parsers/n8n_audit.py), [opcua_audit.py:168-173](services/ws2-normalization/parsers/opcua_audit.py), [mcp_agent.py:221-226](services/ws2-normalization/parsers/mcp_agent.py), [modbus_anomaly.py:136-141](services/ws2-normalization/parsers/modbus_anomaly.py), [vmware_vsphere.py:114-119](services/ws2-normalization/parsers/vmware_vsphere.py)

`services/ws2-normalization/parsers/timeutil.py` was written to fix two bug shapes in the old one-liner `int(x*1000) if x < 1e12 else int(x)`: (1) an ISO-8601 string fails `isinstance(x, (int, float))` and silently falls back to `now()`, losing the real event time; (2) a Windows FILETIME-scale number is misread as milliseconds. `active_directory.py`, `windows_eventlog.py`, `sysmon.py`, `k8s_audit.py`, `cloudtrail.py` were migrated to `timeutil.to_epoch_ms()`; the six files above still run the record's own timestamp field through the old buggy check.

**Reproduced:**
```python
rec = {'operation':'GRANT', ..., 'timestamp':'2026-07-20T10:15:03Z'}
ev = DbAuditParser().parse({'source_type':'db_audit','raw':rec,'meta':{}})
-> event time_ms == int(time.time()*1000) exactly — real event time silently replaced with "now"
```
No existing fixture (`test_db_audit.py`, `test_n8n_audit.py`, `test_opcua_audit.py`, `test_mcp_agent.py`, `test_modbus_anomaly.py`, `test_vmware_vsphere.py`) uses a string timestamp — all use epoch-ms integers — so this gap is untested and only surfaces once a real collector or vendor with a native ISO format feeds one through. **Critical for a SIEM correlating events across sources by time.**

**Fix:** Route each parser's timestamp field through `timeutil.to_epoch_ms()`, same as the five already-migrated parsers. Their `meta.get("received_at")` fallback paths are fine as-is (always collector-supplied numeric).

### H6. `tools/validate_contract.py` crashes on a type-mismatched `class_uid`/`activity_id`, silently skipping validation of every later file in the run

**File:** [tools/validate_contract.py:87-96](tools/validate_contract.py) (`check_invariant`), called from `validate_event` at line 102

`check_invariant()` only guards a `KeyError` (missing field). If `class_uid`/`activity_id` is present with the wrong type (e.g. a fixture typo `"class_uid": "3002"`), `c * 100 + a` raises an unhandled `TypeError` that propagates out of `main()`'s `for f in files:` loop.

**Reproduced:** `python3 -c "... class_uid='3002' ..."` → `TypeError: can only concatenate str (not "int") to str`.

**Failure scenario:** One malformed fixture crashes validation with a raw traceback instead of a clean `[FAIL]` report, and **every fixture alphabetically after the offending one is never checked in that run** — real, unrelated contract violations in those files go unreported that run. `run_all_tests.sh` still sets `fail=1` (non-zero exit), so this isn't a false-PASS, but it silently narrows the tool's own "check every fixture" guarantee.

**Fix:** Type-check before the arithmetic:
```python
if not all(isinstance(x, int) and not isinstance(x, bool) for x in (c, a, t)):
    return
```

### H7. Detection-accuracy oracle's business-hours boundary disagrees with the real engine at exactly 18:00

**Files:** [eval/detection_accuracy/evtx_eval.py:161-165](eval/detection_accuracy/evtx_eval.py) (`in_business_hours`) vs. real logic at [services/ws4-detection/engine.py:177-219](services/ws4-detection/engine.py) (`_time_outside_hours`)

```python
def in_business_hours(t_ms):
    ...
    return 8 <= dt.hour < 18 or (dt.hour == 18 and dt.minute == 0)
```
The real engine computes `within = start <= minute_of_day < end` for `start=480, end=1080` (08:00–18:00) — i.e. the entire minute 18:00:00–18:00:59 is `outside` hours and the rule should fire. The oracle's extra clause treats that same minute as `inside` hours — the opposite of the engine.

**Failure scenario:** Any privilege-use record timestamped `HH:18:00:00`–`18:00:59` UTC on a weekday makes the real engine correctly fire `common_after_hours_admin`, but the oracle reports "not expected" — logged as a false-positive mismatch, corrupting the confusion matrix and any precision/recall reported for that rule. `eval/detection_accuracy/splunk_eval.py` inherits the same bug (reuses `evtx_eval.oracle()` verbatim).

**Fix:**
```python
minute_of_day = dt.hour * 60 + dt.minute
return 480 <= minute_of_day < 1080
```

---

## Medium-High

### M1. CEF parser misclassifies a blocked/denied authentication attempt as a successful logon

**File:** [services/ws2-normalization/parsers/cef.py:74-79](services/ws2-normalization/parsers/cef.py), interacting with [services/ws2-normalization/parsers/base.py:72-75](services/ws2-normalization/parsers/base.py) (`_FAILURE_TOKENS`)

When a CEF line carries `suser`/`duser`, `cef.py` classifies it as Authentication via `status_from_outcome(extension, keys=("outcome","act"))`. The shared `_FAILURE_TOKENS` vocabulary includes `denied`/`deny`/`reject`/`rejected` but **not** `blocked`/`drop`/`dropped` — even though `cef.py`'s own local `_DENY_TOKENS` (used on the network branch) does include them. A CEF line with an identity present and `act=blocked` falls through to `status_from_outcome`'s default of `"Success"`.

**Reproduced:**
```
CEF: suser=admin src=203.0.113.5 act=blocked
-> class_uid: 3002 (Authentication), activity_id: 1 (Logon), status: 'Success'
```
A blocked login is recorded as a successful one — `base.py`'s own docstring warns against exactly this ("a security-relevant event ... recorded as Success suppresses the very rules that watch for it"). Silently suppresses brute-force detection on this source.

**Fix:** Add `blocked`/`drop`/`dropped` to `base.py::_FAILURE_TOKENS`, or pass `cef.py`'s local `_DENY_TOKENS` into the auth-branch `status_from_outcome` call.

### M2. WS6 `seen_at` contract mismatch — collectors emit epoch int, store expects ISO-8601 string

**Files:** [services/ws6-inventory/store.py:18-19](services/ws6-inventory/store.py) (`_parse`) vs. [services/ws1-collectors/collectors/snmp_collector.py:55,74](services/ws1-collectors/collectors/snmp_collector.py) and [syslog_collector.py:74,97](services/ws1-collectors/collectors/syslog_collector.py)

`InventoryStore._parse()` does `ts.replace("Z","+00:00")` then `datetime.fromisoformat(ts)`, assuming an ISO-8601 string. Both WS1 collectors set `seen_at = int(time.time())` (raw epoch seconds), matching the `assets.updates` bus topic shape WS6's own `INTERFACE.md` documents as its (not-yet-wired) input.

**Reproduced:**
```python
store.upsert({'mac':'AA:...', 'ip':'10.0.0.9', 'seen_at': 1750000000})
store.resolve('10.0.0.9', '2026-06-16T09:00:00+00:00')
# -> ValueError: Invalid isoformat string: '1750000000'
```
SQLite's TEXT affinity silently stringifies the int on write, so `upsert()` itself doesn't error — corruption only surfaces later in `resolve()` (crashes) or in the dashboard (renders raw epoch digits, unparsed).

**Fix:** Standardize on one representation — either collectors emit ISO-8601, or `InventoryStore` normalizes both epoch numbers and ISO strings on ingest.

---

## Medium

### N1. `mcp_agent.py` — substring keyword match misclassifies benign tool calls as destructive deletes

**File:** [services/ws2-normalization/parsers/mcp_agent.py:68](services/ws2-normalization/parsers/mcp_agent.py) (`_DELETE_KEYWORDS`), used at `_classify` (~200-211)

`_DELETE_KEYWORDS = ("delete", "remove", "rm", "drop")` matched via plain substring containment (`if kw in t`), not word boundaries. The 2-character `"rm"` matches inside many unrelated tool names.

**Reproduced:**
```
perform_backup, format_report, confirm_action, terminate_session, warm_cache
-> all matched "rm" (false positive); only read_file correctly returned None
```
Any MCP tool call whose name merely contains "rm" gets `activity_id=4` (Delete) and high severity, mislabeling routine tool calls as destructive and inflating false-positive rate for detection rules keyed on delete activity. Delete is checked first in `_classify`, pre-empting correct classification even when a write/update keyword would otherwise apply.

**Fix:** Match `"rm"` on token boundaries (split on `_`/`-`/camelCase, or `re.search(r'\brm\b', t)`); the other keywords are long enough that substring matching is low-risk.

### N2. `demo_e2e.py`'s T7 "idempotency" test doesn't actually replay the same event

**File:** docstring [tools/demo_e2e.py:15-17](tools/demo_e2e.py) vs. implementation ~122-149

The docstring claims T7 proves "re-processing the same triggering event yields the SAME deterministic alert_id." The actual "replay" sends a brand-new 11th synthetic event (`ssh_fail(10)`) with a distinct `ingest_id`, raw text, and timestamp from the original triggering event (`ssh_fail(9)`) — never resends the literal original event.

**Failure scenario:** This only proves `alert_id` is deterministic across distinct new events landing in the same rule window (real and useful — proves indexer-level dedup by `alert_id`), but is **not** a test of true redelivery/idempotency (the same raw event redelivered after an at-least-once bus retry, exercising WS-2's `ingest_id` dedup path specifically). A regression that broke `ingest_id`-based dedup at WS-2 would not be caught by this acceptance test, despite the "idempotent under replay" claim.

**Fix:** Either reword the docstring to be precise about what's proven, or add a true replay case resending the exact original payload (same `ingest_id`, raw text, timestamp).

### N3. WS5 has no idempotency check before calling the LLM

**File:** [services/ws5-ai/main.py:39-61](services/ws5-ai/main.py) (`AiWorker.handle`)

`handle()` calls `self.llm.analyze()` unconditionally for every `ai.requests` delivery — no dedup keyed on `event_id`/`ingest_id` before the LLM call. No dedup logic exists anywhere in `main.py`, `llm_adapter.py`, or `classifier.py`; `test_contract.py` doesn't exercise redelivery.

**Failure scenario:** A handler crash after the LLM call but before ack (or Redis `claim_pending()` reclaiming an idle PEL entry) redelivers the same message — the LLM is called a second time for the same event. Final artifacts use a deterministic `alert_id = f"ai-{event_id}"`, so *indexed* data stays correct, but the LLM call itself duplicates — real cost/rate-limit impact.

**Fix:** Track processed `event_id`s (or dedupe on embedded `ingest_id`) before invoking `self.llm.analyze()`.

---

## Low-Medium

### L1. Unguarded `_seq` race in `_MemoryBus.produce()`

**File:** [services/shared/bus.py:63-65](services/shared/bus.py)

```python
def produce(self, topic, key, payload):
    self._seq += 1
    self._streams[topic].append(Message(topic, key, payload, str(self._seq)))
```
`self._seq += 1` is an unsynchronized read-modify-write. `deque.append()` is atomic in CPython (no message loss), but the counter isn't — concurrent `produce()` on one shared `_MemoryBus` can hand two messages the same `id`. Not hypothetical: `SyslogUDPServer` (`services/ws1-collectors/collectors/syslog_udp_server.py`) runs multiple worker threads calling `bus.produce()` on one shared bus instance by design.

Impact today is low — nothing uses `Message.id` as a dedup key (real idempotency runs on `ingest_id`/`event_id` in the payload) — but it's a genuine race in the module flagged as highest-priority shared state, and would bite the moment anything (a future DLQ tool, a metrics exporter) trusts `Message.id` for uniqueness.

**Fix:** Wrap the increment and deque append in a `threading.Lock`, mirroring the lock WS6's `InventoryStore` already uses.

---

## Low

### O1. `validate_rules.py`'s `_SECTORS` allowlist accepts `"dc"`, a value the OCSF schema's `siem.sector` enum doesn't permit

**File:** [tools/validate_rules.py:49](tools/validate_rules.py) vs. [contracts/ocsf-event.schema.json:93](contracts/ocsf-event.schema.json) (`enum: ["bank","datacenter","common"]`)

`_SECTORS = {"common", "bank", "dc", "datacenter"}` conflates the filename-prefix convention (`contracts/sigma-convention.md`: `<sector>_<name>.yml`, sector ∈ `common|bank|dc`) with the actual `siem.sector` **field value**, which must be `datacenter` per the schema. Currently dormant (no rule uses `sector: dc`), but a future contributor writing `sector: dc` (a plausible typo given the filename convention) would pass validation while never matching any real event.

**Fix:** Remove `"dc"` from `_SECTORS`, or derive the set from the schema's enum directly.

### O2. `validate_contract.py`'s hand-rolled schema validator never enforces `additionalProperties: false`

**File:** [tools/validate_contract.py:70-78](tools/validate_contract.py)

Latent gap, not currently active — the schema's `additionalProperties` is `true` everywhere it's set today, matching the validator's permissive behavior. But if a future schema edit tightens an object to `additionalProperties: false` (e.g. to catch typo'd field names), the validator will keep silently accepting extras on that object.

**Fix:** Implement enforcement, or add an explicit note that the schema must not rely on `additionalProperties: false` while this validator is in use.

### O3. Latent check-then-act race in `_MemoryBus.consume()`

**File:** [services/shared/bus.py:67-71](services/shared/bus.py)

```python
def consume(self, topic, group=None, block_ms=0):
    q = self._streams[topic]
    while q:
        yield q.popleft()
```
If two threads ever ran `consume()` concurrently on the same topic of the same `_MemoryBus` instance, thread A's `while q:` check can pass, yield (generator suspends), thread B drains the last item, and A's resumed `popleft()` raises `IndexError`. Not currently reachable in production (`runner.py` gives each topic one dedicated worker thread; `Bus()` normally hands out a fresh isolated instance per call) — only reachable via the deliberate `bus_factory=lambda: shared_bus` pattern `services/shared/test_runner.py:292-313` uses for testing, which doesn't currently run two consumers on one topic. Flagging as a trap for whoever extends that test pattern next.

---

## Checked, not flagged (verified correct or already fixed)

- `timeutil.to_epoch_ms()` itself — FILETIME math, ISO-Z handling, seconds/ms/FILETIME boundary constants all correct.
- `linux_ssh.py`, `cisco_asa.py`, `dns_query.py`, `cef.py`'s `_time_ms` — only ever feed collector-supplied numeric `received_at` through the old-style check; not part of H5.
- `parsers/__init__.py` content-sniff routing table (AD vs. Sysmon vs. windows_eventlog EventID disambiguation, OPC UA vs. n8n disambiguation) — correctly scoped, no collisions.
- `spool.py::drain_into()` lock-release-during-network-I/O logic — sound under the append-only invariant.
- `syslog_udp_server.py` recv/worker-pool decoupling — counters consistently protected by `_shed_lock`, token bucket by its own lock.
- `enrichment/__init__.py` — correctly fail-open/additive-only.
- `engine.py` rule-matching (`_selection_matches`, `_operator_matches`, `_numeric_compare`, `evaluate()`'s group_by/time guards) — fails closed consistently on missing/malformed fields; every case traced already has a documented audit fix and matching test.
- `RedisWindowCounter`, `_RedisBus` PEL/XAUTOCLAIM/XPENDING/trim_acked/lag logic — heavily audited, correct.
- `llm_adapter.py` (`OllamaLLM`/`FallbackLLM`/`_normalize_verdict`) — response-size capping, non-JSON degradation, exception coverage (incl. `UnicodeDecodeError`, `json.JSONDecodeError`) correct and tested.
- WS6 `authz.py` — uses `hmac.compare_digest` correctly.
- WS7 `index.html` — escapes all dynamic content, handles an async/Promise footgun with an inline comment documenting a past bug.
- `validate_rules.py` threshold/operator/condition parsing — reuses real engine internals directly, well hardened.
- `check_rule_producers.py` — per-event satisfiability check correct; `collect_producible()` is unused dead code but harmless.
- `eval/attack/fire_check.py`, `coverage_layer.py` — tenant-namespaced replay avoids window-state leakage, span-aware off-hours anchor search, division-by-zero guarded by callers.
- Threshold/window values in `common_bruteforce*.yml`, `common_password_spray.yml`, `common_lateral_movement.yml`, `common_priv_grant.yml` match the eval oracle exactly (except H7's boundary bug).
- `tools/integration_e2e.py`, `run_all_tests.sh`, `Makefile` — no swallowed failures, every step propagates non-zero exit.
- All `contracts/**/*.json` and `contracts/**/*.yml` parse cleanly, no structural defects.
- `tools/fuzz/*.py` atheris harnesses — correctly treat a parser exception or schema-invalid output as the only findings; `None` (clean rejection) correctly treated as success.
