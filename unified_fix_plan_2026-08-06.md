# FENGARDE — Unified Fix Plan

**Date:** 2026-08-06 · **HEAD:** `d701c2f`
**Scope:** 39 findings (1 CRIT · 13 HIGH · 16 MED · 9 LOW) + 20 enhancement recommendations
**Sources:** Independent audit + swarm subagents + prior swarm report + CI/CD audit + enhancement analysis

---

## How to Use This Plan

Each fix includes:
- **What** — the problem
- **Where** — exact file:line
- **How** — the fix (code or config)
- **Verify** — how to confirm it's fixed
- **Effort** — estimated time

Phases are ordered by impact-to-effort ratio. Complete Phase 1 and 2 to reach **B+ → A−** grade.

---

## Phase 1: Critical + Quick Wins (do first, ~2h total)

> These are the highest-ROI fixes: the one CRITICAL, the detection-integrity holes, and the one-liner security fixes.

### FIX 1 (CRITICAL) — HA silently breaks all stateful detection

**What:** `ws4-detection/main.py:314` gates `RedisWindowCounter` on `BUS_BACKEND == "redis"` exactly. HA compose sets `redis-sentinel`. 12 stateful rules silently fall back to per-process counters that never fire at scale.

**Where:** `services/ws4-detection/main.py:314-325`

**Current code:**
```python
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
        ...  # fallback warning
```

**Fix:**
```python
_backend = os.getenv("BUS_BACKEND", "memory").lower()
if _backend in ("redis", "redis-sentinel"):
    try:
        import redis
        from window import RedisWindowCounter
        if _backend == "redis-sentinel":
            from redis.sentinel import Sentinel
            sentinel_hosts = []
            for part in os.getenv("REDIS_SENTINEL_HOSTS", "").split(","):
                part = part.strip()
                if not part:
                    continue
                host, _, port = part.partition(":")
                sentinel_hosts.append((host.strip(), int(port.strip()) if port else 26379))
            master_name = os.getenv("REDIS_SENTINEL_MASTER", "mymaster")
            password = os.getenv("REDIS_PASSWORD", "")
            sentinel = Sentinel(sentinel_hosts, password=password or None,
                                socket_timeout=1, decode_responses=True)
            host, port = sentinel.discover_master(master_name)
            client = redis.Redis(host=host, port=port,
                                 password=password or None,
                                 decode_responses=True)
        else:
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
            f"BUS_BACKEND={_backend} requested but redis-py is not installed; "
            "falling back to per-replica window counter (NOT safe across "
            "multiple WS-4 replicas)")
```

**Verify:** `docker compose -f infra/docker-compose.ha.yml up -d`, inject SSH brute-force burst, confirm `common_bruteforce` alert fires.

**Effort:** 30 min · **Phase 1**

---

### FIX 2 (HIGH) — Poison-pill: guard stateful arithmetic + validate at load time

**What:** `engine.py:654` and `:680` run `window_ms = self.window_seconds * 1000` and `count >= self.threshold` OUTSIDE the condition-phase try/except. String `"60" * 1000` or `count >= "10"` raises uncaught TypeError → consumer jam.

**Where:** `services/ws4-detection/engine.py:509-513, 654, 680` + `Rule.__init__`

**Fix (Part A — wrap arithmetic):** Move lines 640-680 (the entire `_evaluate_stateful` logic) inside the existing try/except at `:509-513`, adding a catch for `TypeError`:

```python
try:
    value, end = _parse_or(tokens, 0, matched)
    if not (value and end == len(tokens)):
        return False
    # --- stateful check moved inside try/except ---
    return self._evaluate_stateful(event)
except (ValueError, IndexError, RecursionError, TypeError):
    return False
```

**Fix (Part B — validate at load time in Rule.__init__):** Add after `self.window_seconds` and `self.threshold` are set:

```python
if self.window_seconds is not None and not isinstance(self.window_seconds, (int, float)):
    raise ValueError(f"rule {rule_dict.get('id')}: window_seconds must be numeric, got {type(self.window_seconds).__name__}")
if self.threshold is not None and not isinstance(self.threshold, (int, float)):
    raise ValueError(f"rule {rule_dict.get('id')}: threshold must be numeric, got {type(self.threshold).__name__}")
```

**Fix (Part C — wire validate_rules into load path):** In `Detector.load_rules()`, run `validate_rules.validate_rules_dict()` on every loaded rule YAML before constructing `Rule()` objects. The validator already exists at `tools/validate_rules.py`; just import and call it.

**Verify:** Create rule with `window_seconds: "60"`, load via `Detector()`, confirm ValueError raised at construction time (not at evaluate time).

**Effort:** 20 min · **Phase 1**

---

### FIX 3 (HIGH) — GRANT SELECT downgrade in db_audit parser

**What:** `_OP_MAP` iterates dict in insertion order. `"select"` checked before `"grant"`. Substring match means `"GRANT SELECT ON t"` matches `"select"` first → emitted as activity 1 (read) instead of 5 (privilege).

**Where:** `services/ws2-normalization/parsers/db_audit.py:39-51`

**Current:**
```python
_OP_MAP = {
    "select": (1, SEV_BY_CATEGORY["read"]),
    "query": (1, SEV_BY_CATEGORY["read"]),
    "insert": (2, SEV_BY_CATEGORY["write"]),
    "write": (2, SEV_BY_CATEGORY["write"]),
    "update": (3, SEV_BY_CATEGORY["modify"]),
    "delete": (4, SEV_BY_CATEGORY["destroy"]),
    "drop": (4, SEV_BY_CATEGORY["destroy"]),
    "grant": (5, SEV_BY_CATEGORY["privilege"]),
    "revoke": (5, SEV_BY_CATEGORY["privilege"]),
    "alter": (5, SEV_BY_CATEGORY["privilege"]),
    "create user": (5, SEV_BY_CATEGORY["privilege"]),
}
```

**Fix — privilege/rare-first ordering:**
```python
_OP_MAP: list[tuple[str, tuple[int, int]]] = [
    # Privilege ops (checked FIRST — substring 'create' would match 'create user'
    # so the longer compound key appears before the shorter one)
    ("create user", (5, SEV_BY_CATEGORY["privilege"])),
    ("grant", (5, SEV_BY_CATEGORY["privilege"])),
    ("revoke", (5, SEV_BY_CATEGORY["privilege"])),
    ("alter", (5, SEV_BY_CATEGORY["privilege"])),
    # Destructive ops
    ("drop", (4, SEV_BY_CATEGORY["destroy"])),
    ("delete", (4, SEV_BY_CATEGORY["destroy"])),
    # Modify
    ("update", (3, SEV_BY_CATEGORY["modify"])),
    # Write
    ("insert", (2, SEV_BY_CATEGORY["write"])),
    ("write", (2, SEV_BY_CATEGORY["write"])),
    # Read (catch-all — checked LAST so privilege ops can't hide behind reads)
    ("select", (1, SEV_BY_CATEGORY["read"])),
    ("query", (1, SEV_BY_CATEGORY["read"])),
]
```

And update the loop at line 73 from `_OP_MAP.items()` to `_OP_MAP` (now a list of tuples):
```python
for kw, (aid, sev) in _OP_MAP:
    if kw in operation:
        activity_id, severity_id = aid, sev
        break
```

**Verify:** Parse `{"operation": "GRANT SELECT ON users TO bob"}` → assert `activity_id=5`, `severity_id=5` (CRITICAL). Also verify `"SELECT * FROM users"` still → `activity_id=1`.

**Effort:** 10 min · **Phase 1**

---

### FIX 4 (HIGH) — Webhook redirect filter (SSRF)

**What:** `urllib.request.urlopen()` follows 30x redirects by default. A compromised receiver can pivot HMAC-signed alert POST to internal hosts.

**Where:** `services/ws3-indexer/webhooks.py:154-157`; same pattern in `reporting.py:128` and `llm_adapter.py:150,173`

**Fix:**
```python
# Replace this (line 156):
with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:

# With:
class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # never follow

_no_redirect_opener = urllib.request.build_opener(_NoRedirectHandler)

with _no_redirect_opener.open(req, timeout=_TIMEOUT_S) as resp:
```

Apply the same `_no_redirect_opener` to all 4 call sites. Consider extracting into `services/shared/http.py` as `no_redirect_urlopen(url, data=None, timeout=10)`.

**Verify:** Start test HTTP server returning 302 to `http://localhost:9200`, configure webhook pointing at it, verify the request is NOT followed (raises `HTTPError: 302`).

**Effort:** 15 min · **Phase 1**

---

### FIX 5 (HIGH) — Session signing (forgeable admin)

**What:** `RedisSessionStore.resolve()` does raw `HGETALL` with no server-side signature. Anyone writing Redis forges admin sessions.

**Where:** `services/shared/sessions.py:117-143`

**Fix:**
```python
import hmac

def _session_secret() -> bytes:
    s = os.getenv("FENGARDE_SESSION_SECRET", "")
    if not s:
        s = secrets.token_urlsafe(32)
        # In production, set the env var. For now, warn.
        get_logger("sessions").warn(
            "FENGARDE_SESSION_SECRET not set; session signing is disabled. "
            "Set FENGARDE_SESSION_SECRET for production deployments.")
    return s.encode("utf-8")

def _sign(data: dict) -> str:
    payload = json.dumps(data, sort_keys=True)
    return hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()

# In create(), after building data dict:
sig = _sign(data)
pipe.hset(key, "sig", sig)

# In resolve(), after hgetall:
sig = data.pop("sig", None)
if not sig or not _session_secret():
    pass  # no secret = no signing (backward compat)
elif not hmac.compare_digest(sig, _sign(data)):
    return None  # signature mismatch = forged
# then continue to construct Session from data
```

**Verify:** `HSET fengarde:session:faketoken username=admin role=admin tenant_id=* expires_at=9999999999 csrf_token=known` → `resolve("faketoken")` returns `None`.

**Effort:** 20 min · **Phase 1**

---

### FIX 6 (HIGH) — Default-open auth enforcement mode

**What:** `authz.py:23-25` returns `True` (allow all) when `FENGARDE_API_KEY` is unset. No way to enforce auth in production without external reverse-proxy.

**Where:** `services/shared/authz.py:23-25`

**Fix — add in `warn_if_disabled()` (or new `require_auth()` function):**
```python
def require_auth_or_die(service: str) -> None:
    """Exit with a clear message if auth is required but not configured."""
    if os.getenv("FENGARDE_REQUIRE_AUTH", "").lower() not in ("1", "true", "yes"):
        return
    missing = []
    if not os.getenv("FENGARDE_API_KEY"):
        missing.append("FENGARDE_API_KEY")
    if os.getenv("FENGARDE_RBAC_DB") and not os.getenv("FENGARDE_ADMIN_PASSWORD"):
        missing.append("FENGARDE_ADMIN_PASSWORD (RBAC DB set, no admin)")
    if os.getenv("BUS_BACKEND") in ("redis", "redis-sentinel") and not os.getenv("REDIS_PASSWORD"):
        missing.append("REDIS_PASSWORD (Redis bus with no auth)")
    if missing:
        print(json.dumps({"level": "fatal", "service": service,
              "msg": f"FENGARDE_REQUIRE_AUTH=1 but auth is incomplete",
              "missing": missing}), flush=True)
        sys.exit(1)
```

Call `require_auth_or_die("ws3-indexer")` at the top of `ws3-indexer/main.py`'s `main()`.

**Verify:** `FENGARDE_REQUIRE_AUTH=1 FENGARDE_API_KEY="" python services/ws3-indexer/main.py` → exits code 1 with clear message.

**Effort:** 15 min · **Phase 1**

---

### FIX 7 (HIGH) — linux_ssh IPv4-mapped IPv6 dead-letter

**What:** `_valid_ip()` accepts `::ffff:10.0.0.5` but the raw string fails downstream Contract A IPv6 validation. Auth events from dual-stack hosts silently dead-lettered.

**Where:** `services/ws2-normalization/parsers/linux_ssh.py:64-73`

**Fix — replace local `_valid_ip` with shared helper:**
```python
# Remove lines 64-73 (the local _valid_ip function)
# Replace the call at line 100:
#   if not _valid_ip(ip): continue
# With:
from shared.ocsf import valid_ip
...
if not valid_ip(ip):
    continue
# valid_ip normalizes ::ffff:10.0.0.5 -> 10.0.0.5, which passes Contract A
```

**Verify:** Feed SSH event with `src_ip=::ffff:10.0.0.5`, assert emitted event has `src_endpoint.ip="10.0.0.5"`, event appears in normalized events stream (not dead-lettered).

**Effort:** 5 min · **Phase 1**

---

### FIX 8 (HIGH) — inventory_diff time 1000× error

**What:** `isinstance(seen, (int, float)) → return int(seen)` with no seconds→ms conversion. Epoch-seconds returned as ms → 55 years off.

**Where:** `services/ws2-normalization/parsers/inventory_diff.py:89-95`

**Fix — replace inline time handling:**
```python
# Remove lines 89-95:
#   if isinstance(seen, (int, float)):
#       return int(seen)
# Replace with:
from shared.timeutil import to_epoch_ms
...
time_ms = to_epoch_ms(rec.get("seen_at") or meta.get("received_at") or time.time() * 1000)
```

**Verify:** Parse with `seen_at=1751500000.0` (epoch seconds) → assert `time_ms ≈ 1751500000000` (epoch ms). Also test `seen_at=1751500000000` (already ms) → passes through unchanged. Also test FILETIME `seen_at=133500000000000000` → correct timestamp.

**Effort:** 5 min · **Phase 1**

---

### FIX 9 (HIGH) — Grafana default credential documented

**What:** `GF_SECURITY_ADMIN_PASSWORD=admin` is hardcoded but never mentioned in SECURITY.md.

**Where:** `SECURITY.md` — add a new section or bullet under §1

**Fix — add to SECURITY.md §1 after the existing port-binding note:**
```markdown
- **Grafana** (opt-in `observability` profile, `127.0.0.1:3000`) ships with a
  default `admin`/`admin` credential. Change `GF_SECURITY_ADMIN_PASSWORD` in
  `infra/docker-compose.yml` before enabling the profile on any host where
  port 3000 is reachable beyond loopback.
```

**Verify:** SECURITY.md grep for "Grafana" returns the new text.

**Effort:** 2 min · **Phase 1**

---

### FIX 10 (HIGH) — devkit-feeder requirements.txt

**What:** Inline `pip install redis==5.0.8` in Dockerfile escapes pip-audit and SBOM. Version skew vs 8.1.0.

**Where:** `services/devkit-feeder/` (new file + Dockerfile change + SBOM generator change)

**Fix:**
1. Create `services/devkit-feeder/requirements.txt`:
   ```
   redis==8.1.0
   ```
2. Update `services/devkit-feeder/Dockerfile:4`:
   ```dockerfile
   COPY requirements.txt /tmp/
   RUN pip install --no-cache-dir -r /tmp/requirements.txt
   ```
3. Update `tools/generate_sbom.py:32-39` — add to `REQUIREMENTS_FILES`:
   ```python
   "services/devkit-feeder/requirements.txt",
   ```

**Verify:** `pip-audit --requirement services/devkit-feeder/requirements.txt --strict` → exit 0. `python tools/generate_sbom.py --check` → exit 0.

**Effort:** 5 min · **Phase 1**

---

## Phase 2: Medium Severity Fixes (~2h total)

> These close the remaining logic defects, CI gaps, and hardening items that separate B+ from A−.

### FIX 11 (MED) — .lower() crash on non-string operation fields

**Where:** `services/ws2-normalization/parsers/db_audit.py:71` and `vmware_vsphere.py:69`

**Fix:** Replace `(rec.get("operation") or "").lower()` with:
```python
str(rec.get("operation") or "").strip().lower()
```
Same pattern already used in `__init__.py:135`.

**Verify:** Parse `{"operation": 5}` through both parsers → no crash, returns None or dead-letters gracefully.

**Effort:** 5 min

---

### FIX 12 (MED) — VM.Undeploy misclassification

**Where:** `services/ws2-normalization/parsers/vmware_vsphere.py:39-48`

**Fix:** Reorder `_OP_MAP` to check `"delete"`, `"destroy"`, `"remove"` BEFORE `"deploy"`, `"create"`. Same pattern as FIX 3 (db_audit). Convert to list-of-tuples for guaranteed order.

**Verify:** Parse `{"operation": "VM.Undeploy"}` → assert `activity_id=4` (Destroy).

**Effort:** 5 min

---

### FIX 13 (MED) — class_uid=None double-include bug

**Where:** `services/ws4-detection/main.py:153`

**Fix:**
```python
# Current:
cands = by_class.get(event_class, []) + by_class[None]
# Fixed:
if event_class is None:
    cands = by_class[None]  # don't add catch-all twice
else:
    cands = by_class.get(event_class, []) + by_class[None]
```

**Verify:** Load one catch-all rule, send event with no class_uid, confirm rule evaluated exactly once, not twice.

**Effort:** 3 lines

---

### FIX 14 (MED) — not_in allowlist fail-posture fix

**Where:** `services/ws4-detection/engine.py:125-131` and docstring

**Problem:** Docstring says "fail CLOSED (never match)" when file missing, but code actually fails OPEN (keeps firing = noise flood).

**Fix:** Change the code to match the documented intent — fail-closed is safer for a detection allowlist. When allowlist file is missing/malformed, `_load_allowlist` should return an allowlist that `matches()` always returns True (suppresses everything → rule never fires = fail-closed). Then fix the docstring to describe the ACTUAL behavior.

Or, simpler: when file missing, return `Allowlist([], ok=True)` which means "allow everything" → `not_in` suppresses all matches → rule never fires. Update the WARNING message from "fail closed" to accurately say "file missing, rule will never fire (fail-closed)."

**Verify:** Point `not_in: file:` at nonexistent path, verify the rule never fires on matching events.

**Effort:** 10 min

---

### FIX 15 (MED) — 6 parsers timeutil migration

**Where:** `linux_ssh.py:166`, `cisco_asa.py:120`, `cef.py:117`, `dns_query.py:82`, `cloudtrail.py:118`, `k8s_audit.py:136`

**Fix:** Replace each old one-liner `int(raw*1000) if raw < 1e12 else int(raw)` with `to_epoch_ms(raw)`. Import `from shared.timeutil import to_epoch_ms` where missing. `cloudtrail.py` and `k8s_audit.py` already partially use timeutil; complete the migration.

**Verify:** Parse FILETIME value through each parser → correct timestamp. ISO-8601 string → correct timestamp (not `now()` fallback).

**Effort:** 15 min

---

### FIX 16 (MED) — CI: add test_sessions and test_window to redis-integration

**Where:** `.github/workflows/ci.yml:50-87`

**Fix:** Add two new steps to the `redis-integration` job:
```yaml
- name: Session store (memory + Redis backends) on real Redis
  env:
    BUS_BACKEND: redis
    REDIS_URL: redis://localhost:6379/0
    SESSION_TEST_REDIS: "1"
  run: python services/shared/test_sessions.py
- name: Stateful window counter on real Redis
  env:
    BUS_BACKEND: redis
    REDIS_URL: redis://localhost:6379/0
  run: python services/ws4-detection/test_window.py
```

**Verify:** CI `redis-integration` job passes green with both new steps.

**Effort:** 10 min

---

### FIX 17 (MED) — CI: remove || true from Dockerfiles

**Where:** 5 Dockerfiles: `ws1-collectors/Dockerfile:6`, `ws2-normalization/Dockerfile:12`, `ws3-indexer/Dockerfile:6`, `ws4-detection/Dockerfile:6`, `ws5-ai/Dockerfile:5`

**Fix:** Remove `|| true` suffix from each `pip install` line. `ws6-inventory/Dockerfile` already doesn't have it — match that.

**Verify:** `docker compose build` with a deliberately broken requirements.txt (typo'd package name) → build fails.

**Effort:** 5 min

---

### FIX 18 (MED) — Sigma import: reject unescaped . in regex

**Where:** `tools/import_sigma_rules.py:74`

**Current:**
```python
if re.fullmatch(r"[a-zA-Z0-9_.\-/ ]*", pat):
    return pat
```

**Fix:**
```python
# Reject patterns containing unescaped '.' not part of '.*'
# A bare '.' in regex matches any char; translated to glob it becomes
# literal dot — silently narrowing the rule. Reject with warning instead.
if re.fullmatch(r"[a-zA-Z0-9_.\-/ ]*", pat):
    if "." in pat and ".*" not in pat:
        return None  # reject — '.' without '*' is silently narrowed
    return pat
```

**Verify:** `_safe_glob_from_regex("foo.bar")` → returns `None` (rejected with warning). `_safe_glob_from_regex("foo.*bar")` → returns `"foo*bar"` (correct).

**Effort:** 5 min

---

### FIX 19 (MED) — CI: gitleaks in pre-commit

**Where:** `.pre-commit-config.yaml`

**Fix:** Add after the existing repos:
```yaml
- repo: https://github.com/gitleaks/gitleaks
  rev: v8.18.4
  hooks:
    - id: gitleaks
```

**Verify:** `pre-commit run gitleaks --all-files` → passes. Commit a fake secret → hook blocks commit.

**Effort:** 3 min

---

### FIX 20 (MED) — Racy counters under lock

**Where:** `services/ws1-collectors/collectors/syslog_udp_server.py:300-324`

**Fix:** Move all counter increments inside `self._shed_lock` context. `_shed_lock` already exists at line 277. Currently only `_count_shed()` uses it. Extend scope to cover `events_produced`, `events_spooled`, `events_dropped`.

```python
def _handle_datagram(self, data, peer_ip):
    line = data.decode("utf-8", errors="replace").rstrip("\r\n")
    if not line:
        return
    event = build_raw_event(line, deterministic_id=self.deterministic_id)
    tenant_id = event.get("meta", {}).get("tenant_id")
    if not self._buckets.take(tenant_id or ""):
        if self._try_spool(peer_ip, event):
            with self._shed_lock:
                self.events_spooled += 1
            return
        self._count_shed(peer_ip, lost_to_full_spool=self._spool is not None)
        return
    try:
        self.bus.produce(self.topic, key=peer_ip, payload=event)
    except Exception as exc:
        if self._try_spool(peer_ip, event):
            with self._shed_lock:
                self.events_spooled += 1
            return
        with self._shed_lock:
            self.events_dropped += 1
        if self.log is not None:
            self.log.warn(...)
        return
    with self._shed_lock:
        self.events_produced += 1
```

**Verify:** Run 4 workers at high rate for 30s → counters sum equals total events.

**Effort:** 10 min

---

### FIX 21 (MED) — UDP ingest_id deterministic mode

**Where:** `services/ws1-collectors/collectors/syslog_udp_server.py:304`

**Fix:**
```python
# Change:
event = build_raw_event(line, deterministic_id=self.deterministic_id)
# To:
event = build_raw_event(line, deterministic_id=True)
# UDP is connectionless — retransmission is the normal case, not an edge case.
```

Or, alternatively, make `deterministic_id` default to `True` for UDP in `SyslogUDPServer.__init__`. The SHA-of-content fallback in the parser is dead code when a random UUID is always stamped.

**Verify:** Send same UDP datagram twice → same `meta.ingest_id` both times → only one alert produced.

**Effort:** 1 line

---

### FIX 22 (MED) — LLM funnel dedup per alert key

**Where:** `services/ws4-detection/scoring.py:28-41`

**Fix:** Add a small in-memory cache of recently-enqueued alert keys:

```python
# In Scorer.__init__:
self._recent_llm_enqueues: dict[str, float] = {}  # alert_key -> timestamp
self._llm_cooldown_s = 300  # 5 minutes

# In routing_score or the caller that enqueues to ai.requests:
def _should_enqueue_llm(self, alert_key: str, now: float) -> bool:
    last = self._recent_llm_enqueues.get(alert_key, 0)
    if now - last < self._llm_cooldown_s:
        return False
    self._recent_llm_enqueues[alert_key] = now
    # Prune stale entries occasionally
    if len(self._recent_llm_enqueues) > 1000:
        cutoff = now - self._llm_cooldown_s * 2
        self._recent_llm_enqueues = {k: v for k, v in self._recent_llm_enqueues.items() if v > cutoff}
    return True
```

**Verify:** Fire same rule on same group 10 times within window → only 1 LLM request enqueued. Different groups → enqueued separately.

**Effort:** 20 min

---

### FIX 23 (MED) — Redis async-replication durability (WAITAOF)

**Where:** `infra/docker-compose.ha.yml` and `infra/redis-sentinel-entrypoint.sh`

**Fix — add to redis config in entrypoint:**
```bash
--min-replicas-to-write 1
--min-replicas-max-lag 10
```

This means the primary refuses writes if no replica is connected, rather than silently losing the tail on failover. Document the tradeoff in SSOT §2: the chaos test proves consumer-failure durability, not primary-failover durability (which requires WAITAOF/MIN-REPLICAS that introduce a write-availability tradeoff).

**Verify:** Bring up HA, stop all replicas, try to produce → verify write is rejected (not silently accepted and then lost).

**Effort:** 10 min + docs

---

### FIX 24 (MED) — FENGARDE_API_KEY_PEPPER documentation

**Where:** `SECURITY.md` §2 or new §10

**Fix — add to SECURITY.md:**
```markdown
### 10. API key pepper defaults empty

`FENGARDE_API_KEY_PEPPER` (WS-6 keystore) defaults to an empty byte string.
When unset, HMAC-SHA256 is computed with an empty key. The pepper's
defense-in-depth (protecting against a DB-only leak without the pepper)
is inactive. A startup warning is logged. Set `FENGARDE_API_KEY_PEPPER`
to a high-entropy random value for production deployments.
```

**Verify:** SECURITY.md contains the pepper documentation.

**Effort:** 2 min

---

### FIX 25 (MED) — CI: mutmut blocking after baseline

**Where:** `.github/workflows/ci.yml:117-121`

**Fix:**
```yaml
- name: mutmut (blocking at measured baseline)
  run: |
    pip install mutmut
    python -m mutmut run  # no || true — fails CI if kill rate drops below baseline
```

First, measure the current kill rate as a baseline (already done: ~72% on `sessions.py`). Set the floor at measured − 5% to allow some variance. Configure in `pyproject.toml`:
```toml
[tool.mutmut]
# ... existing config ...
min_survival_rate = 72.0
```

**Verify:** Mutate a test to be weaker → mutmut fails CI.

**Effort:** 15 min

---

### FIX 26 (MED) — CI: OpenSearch service container

**Where:** `.github/workflows/ci.yml` — new job

**Fix — add after redis-integration:**
```yaml
  opensearch-integration:
    runs-on: ubuntu-latest
    services:
      opensearch:
        image: opensearchproject/opensearch:2.13.0
        env:
          discovery.type: single-node
          DISABLE_SECURITY_PLUGIN: "true"
        ports: ["9200:9200"]
        options: >-
          --health-cmd "curl -s http://localhost:9200/_cluster/health"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97
        with:
          python-version: "3.12"
      - name: Install deps
        run: pip install pyyaml
      - name: Live OpenSearch integration tests
        env:
          OPENSEARCH_URL: http://localhost:9200
        run: |
          python services/ws3-indexer/storage/test_opensearch_live.py
          python tools/test_migrate_opensearch.py
```

**Verify:** New CI job passes green against real OpenSearch.

**Effort:** 20 min

---

## Phase 3: Low Severity + Polish (~1.5h)

| # | What | Where | Fix | Effort |
|---|---|---|---|---|
| L1 | Clock-skew silent drops | `engine.py:287` | Add metrics counter `events_clock_skewed` + log at WARN when dropping | 5 min |
| L2 | Empty allowlists on rules | `contracts/rules/*.yml` | Add comment to each: `# allowlist: populate with your org's ...` | 5 min |
| L3 | mcp_agent 'put' false-positive | `mcp_agent.py:67` | Word-boundary match or exact token check for short keywords | 5 min |
| L4 | No API rate limiting | `triage_api.py` | Add token-bucket rate limiter middleware (off by default) | 30 min |
| L5 | LoginRateLimiter memory-only | `rbac.py:56` | Document single-process scope in code comment; note Redis variant as TODO | 2 min |
| L6 | Webhook secrets from env vars | `webhooks.py:143` | Document in SECURITY.md; add Docker secrets note | 2 min |
| L7 | CI Python version skew | `ci.yml` | Bump quality+fuzz jobs to python 3.12 | 2 min |
| L8 | Fuzz only 3/17 parsers | `fuzz.yml` | Add `db_audit` and `vmware_vsphere` to matrix | 5 min |
| L9 | inventory_diff unguarded hostname | `inventory_diff.py:49,77` | Wrap in `safe_str()` | 2 min |

---

## Phase 4: Enhancement Implementation (~2-3 days)

> Forward-looking features, not bug fixes. Pick from this list based on roadmap priority.

### Security (4 items)

| # | What | Effort | Notes |
|---|---|---|---|
| E1 | Audit log for admin actions | ~150 lines | New `audit.events` stream. Triage, login, key provisioning all logged. MSSP compliance. |
| E2 | Encrypted spool at rest | ~30 lines | AES-256-GCM per entry with `FENGARDE_SPOOL_KEY`. |
| E3 | MFA/TOTP for dashboard login | ~100 lines + dep | `pyotp` or stdlib HMAC-based TOTP. Per-user opt-in. |
| E4 | mTLS between services | ~50 lines YAML + certs | Opt-in `docker-compose.tls.yml` profile. 3 inter-service calls only. |

### Observability (2 items)

| # | What | Effort | Notes |
|---|---|---|---|
| E5 | Grafana rule-health panel verification | Config only | Complete the live-Docker verification of `rule_last_fired` timestamps in Grafana. Data already collected. |
| E6 | Per-source syslog metrics | ~80 lines | `{source="10.0.1.5"}` labels on Prometheus counters. Bounded LRU map. |

### Administration (3 items)

| # | What | Effort | Notes |
|---|---|---|---|
| E7 | Admin UI (rule/parser/key management) | ~300 lines | `/admin` routes on WS-3, admin panels in dashboard `index.html`. List/enable/disable rules per tenant, provision keys, view audit log. |
| E8 | Rule hot-reload via API | ~40 lines | `POST /admin/rules/reload` triggers `Detector.reload()`. Validate first, fail-closed. |
| E9 | Tenant provisioning wizard | ~200 lines | `POST /admin/tenants` — creates tenant dir, provisions key, creates RBAC user. Single API call. |

### UX (4 items)

| # | What | Effort | Notes |
|---|---|---|---|
| E10 | Alert correlation view | UI only | `GET /api/v1/alerts?actor=&src_ip=` already exists. Add "Show related" button in dashboard. Timeline visualization. |
| E11 | Alert lifecycle + playbooks | ~100 lines | Status transitions: new→investigating→contained→closed. `playbook` markdown field on rules shown to analysts. |
| E12 | Saved searches | ~50 lines JS | localStorage-persisted filter queries. Named watchlists. |
| E13 | Dark mode + accessibility | ~50 lines CSS | `prefers-color-scheme: dark`, `aria-label` attributes, keyboard nav. |

---

## Verification Checklist (run after each phase)

### Phase 1 Post-Fix Verification

- [ ] `docker compose -f infra/docker-compose.ha.yml up -d` → all services healthy
- [ ] Inject SSH brute-force → `common_bruteforce` alert fires on HA
- [ ] Rule with `window_seconds: "60"` rejected at load time (ValueError, not crash)
- [ ] `GRANT SELECT ON users` → `activity_id=5` (privilege)
- [ ] Webhook 302 redirect → not followed (HTTPError)
- [ ] Forged Redis session token → resolved as None
- [ ] `FENGARDE_REQUIRE_AUTH=1` without API key → exit 1
- [ ] `::ffff:10.0.0.5` SSH event → appears in normalized events (not dead-lettered)
- [ ] `inventory_diff` `seen_at=1751500000.0` → correct 2025 timestamp
- [ ] `pip-audit --requirement services/devkit-feeder/requirements.txt` → exit 0
- [ ] `python tools/generate_sbom.py --check` → exit 0

### Phase 2 Post-Fix Verification

- [ ] `db_audit.parse({"operation": 5})` → no crash (returns None or dead-letter)
- [ ] `VM.Undeploy` → `activity_id=4` (Destroy)
- [ ] `class_uid=None` event with catch-all rule → evaluated exactly once
- [ ] Missing allowlist file → `not_in` rule never fires (fail-closed)
- [ ] FILETIME value parsed correctly by all 6 syslog-text parsers
- [ ] `redis-integration` CI job passes with `test_sessions.py` + `test_window.py`
- [ ] Broken `requirements.txt` → `docker compose build` fails
- [ ] `_safe_glob_from_regex("foo.bar")` → returns None
- [ ] `pre-commit run gitleaks` blocks secret commits
- [ ] Counters sum to total under concurrent load
- [ ] Duplicate UDP datagram → same `ingest_id` → one alert
- [ ] Hot rule fires 10x → only 1 LLM request
- [ ] Redis primary rejects writes when replicas offline
- [ ] `ci.yml` `mutmut` step → no `\|\| true`

---

## Summary

| Phase | Fixes | Effort | Cumulative Grade |
|---|---|---|---|
| **Phase 1** | CRITICAL + 8 HIGHs + 1 docs | ~2h | B → B+ |
| **Phase 2** | 14 MEDIUMs + 1 CI job | ~2h | B+ → A− |
| **Phase 3** | 9 LOWs | ~1h | A− → A− |
| **Phase 4** | 13 enhancements | ~2-3 days | A− → A |

**Bottom line:** FENGARDE is a genuinely strong codebase. The 39 findings above are almost all local, verifiable, low-effort fixes. The CRITICAL HA bug is 1 line of logic + ~20 lines of Sentinel-aware client construction. The exact file:line citations and fix code are provided for every item. Phase 1 alone eliminates the highest-risk gaps and can be completed in a single afternoon.

---

*Plan compiled 2026-08-06. Based on 4-source audit (independent + swarm subagents + prior report + CI/CD review) at commit `d701c2f`.*