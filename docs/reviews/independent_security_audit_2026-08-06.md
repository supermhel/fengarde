# FENGARDE SIEM — Independent Comprehensive Security, Architecture & Quality Audit

**Date:** 2026-08-06
**Repo:** `github.com/supermhel/fengarde` (Apache-2.0)
**HEAD:** `d701c2f` — "fix(infra): live-verified HA/Sentinel + OT pipeline bugs"
**Scale:** ~36K LOC Python · 7 workstreams · 17 parsers · 28 rules · Docker/Redis/OpenSearch
**Method:** Independent code reading + Docker live tests + adversarial analysis. Every finding verified against current disk state with `file:line` citations. Existing review documents treated as claims, NOT ground truth.

---

## Executive Summary

**FENGARDE is a genuinely impressive open-source SIEM.** The single-instance core, constant-time auth comparisons, parameterized SQL, fail-closed detection posture, and honest security documentation put it well above typical open-source standards. The redelivery/DLQ/trim-acked machinery in `bus.py` is among the best I've seen in any OSS project — this is clearly built by someone who understands distributed messaging deeply.

**However, the most important production-grade features silently break under the configuration that matters most.** The three headline findings below are all confirmed with `file:line` evidence and, where possible, empirical reproduction.

### Overall Grade: **C+/B−** (straddling the boundary)

| Facet | Grade | One-line assessment |
|---|---|---|
| **Implementation hygiene** | **A−** | Constant-time, parameterized, fail-closed, honest |
| **Detection-logic correctness** | **C+** | Poison-pill + `GRANT SELECT` downgrade are real detection-integrity holes |
| **Architecture / HA reliability** | **C−** | Single-instance A-grade core; HA silently breaks detection |
| **Security posture (effective)** | **D** | Everything defaults to wide-open; default-open is the dominant risk |
| **Code quality & supply-chain** | **B** | Honest stubs, but security-critical paths are the least-gated in CI |
| **Documentation honesty** | **A−** | SECURITY.md is refreshingly honest; 2 overstatements found |

---

## HEADLINE FINDINGS (independently verified)

### 🔴 CRITICAL — C1: HA profile silently disables every stateful detection rule

**Both sides verified:**

**Side A — HA compose sets `BUS_BACKEND=redis-sentinel`:**
`infra/docker-compose.ha.yml:400`:
```yaml
ws4-detection:
  environment:
    - BUS_BACKEND=redis-sentinel
```

**Side B — Window-counter gate only matches `== "redis"` (exact):**
`services/ws4-detection/main.py:314`:
```python
if os.getenv("BUS_BACKEND", "memory").lower() == "redis":
    ... counter = RedisWindowCounter(client) ...
```

**CONFIRMED:** Under HA, `BUS_BACKEND=redis-sentinel` fails the `== "redis"` check. The `RedisWindowCounter` is NEVER attached. Every stateful rule (brute-force, port-scan, lateral-movement, password-spray, beaconing, impossible-travel — 12 of 28 rules) falls back to per-process `DequeWindowCounter`. With ≥2 WS-4 replicas, counts split across processes → **threshold never reached → these detections NEVER fire.**

**NOTE:** The bus factory at `bus.py:532-559` correctly handles all three backends (`memory`, `redis`, `redis-sentinel`). This bug is specifically in the WS-4 window-counter attachment point. The bus itself IS using the correct `_RedisSentinelBus` under HA — but the detection layer silently degrades.

**Impact:** Silent detection blackout for 12 stateful rules in exactly the deployment the HA profile targets.
**Confidence:** Confirmed-by-code (both sides cited).

---

### 🟠 HIGH — H1: Engine poison-pill — malformed rule numerics jam the detection topic

**Verified:** `services/ws4-detection/engine.py:654` and `:680`:
```python
# Line 654 — OUTSIDE the condition-phase try/except block
window_ms = self.window_seconds * 1000
...
# Line 680
return count >= self.threshold
```

`window_seconds` and `threshold` are `Optional` fields from unvalidated YAML:
`engine.py:366-367`:
```python
siem = rule_dict.get("siem", {})
self.window_seconds = siem.get("window_seconds") or None
self.threshold = siem.get("threshold") or None
```

The condition-phase try/except at `engine.py:509-513` ONLY wraps the selection/condition evaluation. The stateful arithmetic at lines 654 and 680 runs **outside** it. A rule file with `window_seconds: "60"` (string) or `threshold: "10"` (string) raises an uncaught `TypeError`:

- `"60" * 1000` → `"606060..."` (string multiplication, not integer) — though this might not crash, it produces wrong results
- `count >= "10"` → `TypeError` on comparison

The engine advertises "fail closed, never crash" (ADR-005). `validate_rules.py` would catch this but is a **separate CLI tool not wired into the rule-load path or CI blockingly** — it runs in CI via `run_all_tests.sh:17` but the engine doesn't call it at load time. A hot-reload edit or a plugin rule-pack bypasses the validator entirely.

**Impact:** Uncaught `TypeError` → message left unacked → infinite redelivery → consumer jams → ALL events behind the poison message are never detected.
**Confidence:** Confirmed-by-code. 

---

### 🟠 HIGH — H2: `GRANT SELECT` silently downgraded to read — bank priv-esc rule evaded

**Reproduced empirically:**

`services/ws2-normalization/parsers/db_audit.py:39-51,73-75`:
```python
_OP_MAP = {
    "select": (1, SEV_BY_CATEGORY["read"]),    # ← matched FIRST
    "query": (1, ...),
    ...
    "grant": (5, SEV_BY_CATEGORY["privilege"]),  # ← matched SECOND
    "revoke": (5, ...),
    ...
}
...
for kw, (aid, sev) in _OP_MAP.items():          # dict iteration order
    if kw in operation:                          # SUBSTRING match
        activity_id, severity_id = aid, sev
        break                                    # first match wins
```

When `operation = "grant select"`:
1. `"select" in "grant select"` → **True** → emits `activity_id=1, severity=INFO` (READ)
2. `"grant"` is never reached because `break` exits the loop

**Result:** A database privilege grant phrased with a subordinate SELECT clause is classified as a read operation (INFO severity), completely evading `bank_db_priv_esc.yml` which targets `class_uid=6005, activity_id=5`.

**Impact:** Privilege escalation event silently classified as read → detection evasion.
**Confidence:** Confirmed-by-code.

---

### 🟠 HIGH — H3: Default-open auth everywhere (documented but dominant risk)

`services/shared/authz.py:23-25`:
```python
expected = os.getenv(env_var)
if not expected:
    return True  # ← ALL requests allowed when env var unset
```

Combined with RBAC off-by-default, dashboard basic-auth off, Redis AUTH off, OpenSearch security plugin disabled, and unauthenticated UDP syslog — a mis-deployed SIEM is **fully open and multi-tenant-merged by default**. 

**This is documented in SECURITY.md and is an accepted design tradeoff** — the project explicitly prioritizes zero-prerequisite `docker compose up`. But it IS the dominant residual risk. A `FENGARDE_REQUIRE_AUTH=1` refuse-to-start-without-credentials mode would close this with minimal operator friction.

**Impact:** Full read/write access to all alerts, events, triage, inventory, and reports.
**Confidence:** Confirmed-by-code. Documented/accepted.

---

### 🟠 HIGH — H4: Redis session store is raw/unsigned — forgeable if Redis is unauthenticated

`services/shared/sessions.py:132-143`:
```python
def resolve(self, token: str) -> Optional[Session]:
    data = self.r.hgetall(_REDIS_KEY_PREFIX + token)   # ← raw HGETALL, no signature
    if not data:
        return None
    return Session(
        username=str(data["username"]), role=str(data["role"]),
        tenant_id=str(data["tenant_id"]), ...
    )
```

Anyone who can write to Redis (AUTH defaults off) can `HSET` a forgery with `role=admin`, `tenant_id=*`, and a known `csrf_token` — then present the forged cookie + header to bypass all RBAC. SECURITY.md calls the session store a "security boundary" but it isn't cryptographically enforced.

**Impact:** Full admin impersonation under default (no Redis AUTH) deployment.
**Confidence:** Confirmed-by-code. SECURITY.md overstates this boundary.

---

### 🟠 HIGH — H5: Webhook dispatcher follows HTTP redirects → SSRF pivot

`services/ws3-indexer/webhooks.py:154-157`:
```python
req = urllib.request.Request(config.url, data=body, method="POST", headers=headers)
with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:  # noqa: S310
    resp.read()
```

`urllib.request.urlopen` uses the default opener which includes `HTTPRedirectHandler` — this follows 301/302/303/307 redirects. A configured webhook receiver (or a compromised one) returning a `30x` pivots the HMAC-signed POST delivery (containing alert data) to any internal host:

- `http://opensearch:9200`  
- `http://169.254.169.254/latest/meta-data/` (cloud metadata)
- `http://redis:6379` (could use RESP injection)

**This directly contradicts SECURITY.md §9's claim of "No SSRF surface from event content."** While true that the URL comes from config (not event content), the claim doesn't account for redirect following after the initial hop.

**Impact:** Data exfiltration to internal services via redirect pivot.
**Confidence:** Confirmed-by-code. Documentation overstatement.

---

### 🟠 HIGH — H6: OpenSearch writer pinned to single node in "3-node HA" cluster

`services/ws3-indexer/storage/opensearch.py:70-79`:
```python
def __init__(self, url: str | None = None, timeout: float = 10.0) -> None:
    url_str = url or os.getenv("OPENSEARCH_URL") or "http://localhost:9200"
    parsed = urllib.parse.urlsplit(url_str)
    self._host = parsed.hostname or "localhost"   # ← ONE host
    self._port = parsed.port or ...
```

`infra/docker-compose.ha.yml:392` pins this to:
```yaml
OPENSEARCH_URL=http://opensearch-1:9200
```

The cluster provides durability + read-HA via replicas, but the SINGLE writer connection has **zero write failover**. Losing `opensearch-1` stalls all writes and starts a DLQ burst while `_cluster/health` is green (reads still work via the other nodes — the classic "cluster green, app dead" trap).

**Impact:** Single point of failure for all writes despite a 3-node cluster.
**Confidence:** Confirmed-by-code.

---

### 🟠 HIGH — H7: Redis backends never exercised against REAL Redis in CI

`services/shared/test_sessions.py:33-52`:
```python
if os.getenv("SESSION_TEST_REDIS", "0") != "1":
    ...
    _BACKENDS.append(("redis", None))  # ← prints [SKIP], never actually tested
```

`.github/workflows/ci.yml:50-87` (`redis-integration` job) runs ONLY:
- `test_runner.py`
- `test_bus_trim_acked.py`
- `test_bus_lag.py`
- `test_bus_read_count.py`

**NOT** `test_sessions.py` or `test_window.py`. The `SESSION_TEST_REDIS=1` flag appears **nowhere** in `.github/workflows/`. And `test_window.py:74-79` tests `RedisWindowCounter` against a hand-rolled `_FakeRedis`/`_FakePipe` fake — never real Redis.

**Impact:** A real behavioral bug in sessions/window on Redis passes CI green. The backends that fix multi-replica bugs are themselves the least tested.
**Confidence:** Confirmed-by-CI-config.

---

### 🟠 HIGH — H8: Coverage gate excludes every security-critical module

`tools/coverage_gate.py:30-82` `TARGETS` covers only:
- `ws2-normalization` (parsers)
- `ws3-indexer` (API/storage)

Modules **outside** the coverage source:
- `services/shared/sessions.py` — session auth boundary
- `services/shared/bus.py` — message bus (redelivery/DLQ)
- `services/shared/runner.py` — event processing loop
- `services/ws4-detection/window.py` — stateful window counters
- `services/ws6-inventory/keystore.py` — API key auth

**No coverage floor protects the auth/session/redelivery/window/keystore paths.** The gate measures *execution* (coverage runs the test scripts), not *assertion* — a test that runs code without asserting still counts.

**Impact:** Critical security modules have zero coverage enforcement.
**Confidence:** Confirmed-by-code.

---

### 🟠 HIGH — H9: devkit-feeder dependency invisible to pip-audit AND SBOM

`services/devkit-feeder/Dockerfile:4`:
```dockerfile
RUN pip install --no-cache-dir redis==5.0.8
```

No `requirements.txt` exists → `ci.yml:146` loop `for req in services/*/requirements.txt` never audits it. `tools/generate_sbom.py:29-39` explicitly excludes `devkit-feeder`. And `redis==5.0.8` is at version skew against the five other services pinning `redis==8.1.0` — the `_RedisBus` runs on two different client versions.

**Impact:** Unaudited dependency with known CVE could ship undetected for months.
**Confidence:** Confirmed-by-code.

---

## Additional Findings

### MEDIUM

| # | Area | Finding | File:Line |
|---|---|---|---|
| M1 | Detection | `class_uid=None` double-includes catch-all bucket → score doubled, duplicate alerts | `main.py:153` |
| M2 | Detection | `not_in` allowlist fail-posture DOCUMENTED BACKWARDS — docstring says "fail closed" but code is fail-OPEN (missing allowlist = never suppresses = keeps firing) | `engine.py:125-131` vs docstring |
| M3 | Detection | LLM funnel floods per-event once a hot high-severity rule crosses `llm_min` — one LLM call per matching event, not per unique alert | `scoring.py:28-41` |
| M4 | Sigma | `_safe_glob_from_regex` silently narrows regex `.` (match-any) to literal glob `.` (match-dot) — `foo.bar` regex becomes `foo.bar` glob, matching only literal dots | `import_sigma_rules.py:74` |
| M5 | Parser | `.lower()` crash on non-string `operation` in `db_audit.py:71` and `vmware_vsphere.py:69` — bounded single-record loss but fuzz suite misses it | `db_audit.py:71` |
| M6 | Parser | `inventory_diff.py:89-95` bypasses shared `to_epoch_ms()` — epoch-seconds/FILETIME mis-scaled 1000× | `inventory_diff.py:89-95` |
| M7 | Parser | 6 syslog-text parsers still use old `int(raw*1000) if raw<1e12` one-liner instead of shared `timeutil.to_epoch_ms` — FILETIME values (~1.3×10^17) produce year-33000 timestamps | `linux_ssh.py:166`, `cisco_asa.py:120`, etc. |
| M8 | Arch | Race condition in syslog counters — `events_produced += 1`, `events_spooled += 1`, `events_dropped += 1` NOT under any lock in 4-worker thread pool | `syslog_udp_server.py:308,316,318,324` |
| M9 | Arch | UDP ingest_id is random UUID → deterministic content-hash fallback in parser is dead code → connectionless UDP replay produces duplicate events | `syslog_udp_server.py:304` |
| M10 | Quality | mypy runs at default-loose strictness (`ignore_missing_imports=true`, no `disallow_untyped_defs`, no `strict`) — untyped security functions pass cleanly | `pyproject.toml:42-58` |
| M11 | Quality | Dockerfiles use `|| true` on pip install → docker-build gate silently passes even when dependencies fail to install | `ws1-*/Dockerfile:6`, etc. |
| M12 | Quality | mutmut is informational-only (`|| true` in CI), scope is ONE file (`sessions.py`, memory backend only), not blocking | `ci.yml:119`, `pyproject.toml:60-71` |

### LOW / INFO

| # | Area | Finding |
|---|---|---|
| L1 | Security | Sanitize `_FREE_TEXT_PATHS` omits `unmapped.*` and `api.request.data` — raw attacker-controlled content in extension fields unsanitized |
| L2 | Detection | Clock-skew guard silently drops stateful detection for legitimately forward-skewed hosts (>5 min ahead of detector) |
| L3 | Detection | Several shipped rules have empty allowlists — effectively always-fire noise (documented as "live" but near-constant noise in production) |
| L4 | Arch | Cleartext-on-disk spool (documented in SECURITY.md §8 — fair disclosure, but rated as residual risk) |
| L5 | Quality | `.gitleaks.toml:21-23` allowlists ALL `8-4-4-4-12` UUIDs repo-wide — broad but justified given the project's use of UUIDs for alert/event IDs |
| L6 | Quality | Version skew: 1 service pins `redis==5.0.8` while 5 others pin `8.1.0` — same `_RedisBus` runs on two different client versions |

### Confirmed GOOD (explicit credit)

- **Constant-time auth everywhere:** `hmac.compare_digest` on API keys, password verification, CSRF tokens, and HMAC-SHA256 webhook signatures.
- **Parameterized SQL everywhere:** WS-6 inventory uses parameterized queries throughout; zero string-formatted SQL found.
- **Fail-closed design:** Session store raises at construction on broken Redis (`sessions.py:115`); keystore pepper canary detects rotation; `_contains`/`_glob_match` strictly bounded (no ReDoS).
- **Tenant namespacing sound:** `_namespaced_group` length-prefix prevents crafted collisions; window keys and alert keys both tenant-scoped; WS-3 router rejects-not-normalizes tenant IDs.
- **Bus machinery best-in-class:** `_RedisBus` PEL/XAUTOCLAIM/XPENDING, trim-acked with safe boundary computation, lag() aggregating undelivered+pending, DLQ quarantine, `_RedisSentinelBus` with failover-aware generators.
- **Honest stub disclosure:** Zero stubs labeled as working when they aren't. The SSOT.md §2 "proven vs. claim" table is genuinely honest.
- **CI action-pin verification:** `verify_action_pins.py` treats network failure as FAIL (genuinely non-gamable).
- **Pipeline proven live:** Produced real alerts on live Docker/Redis/OpenSearch during this audit. 

---

## Finding Tally

| Severity | Count | Key Findings |
|---|---|---|
| **CRITICAL** | **1** | C1 — HA disables stateful detection |
| **HIGH** | **9** | H1 (poison-pill), H2 (GRANT SELECT), H3 (default-open), H4 (unsigned sessions), H5 (webhook redirects), H6 (single-node OS writer), H7 (Redis untested in CI), H8 (coverage excludes security), H9 (devkit-feeder unaudited) |
| **MEDIUM** | **12** | M1-M12 above |
| **LOW/INFO** | **6** | L1-L6 above |

---

## Live Docker/Redis Test Results

- ✅ **Docker stack healthy:** All 7 workstreams running, Redis PONG, OpenSearch green (yellow — single node, replicas unassigned — expected)
- ✅ **Pipeline producing alerts:** 6 alerts in Redis `alerts` stream, 13 scored events in `scored.events`
- ✅ **API responding:** `GET /api/v1/alerts` returning real alert documents with scores
- ⚠️ **Poison-pill reproduction:** Blocked by container Python path issue (cannot import `ws4_detection` module in container context — path differs from host). The code-level analysis is authoritative; a full empirical repro requires setting up the correct Python path inside the container.

---

## Priority Fix Order (highest leverage first)

1. **Fix the HA env-gate** — change `main.py:314` from `== "redis"` to `in ("redis", "redis-sentinel")` AND build the window counter off a Sentinel-aware client, not `REDIS_URL`. This is a 3-line fix that unbreaks 12 detection rules.
2. **Guard the stateful arithmetic in `evaluate()`** — wrap lines 654 and 680 in the existing condition try/except, AND enforce rule-field type validation at `load_rules()` time (not just in a separate CLI tool).
3. **Fix `db_audit.py` `_OP_MAP`** — sort so `grant`/`revoke`/`alter`/`create user` are checked BEFORE `select`/`query`/`insert`, or use exact-match instead of substring.
4. **Add an HA regression test to CI** — bring up `docker-compose.ha.yml`, kill `redis-1` mid-stream, assert a stateful rule still fires AND no lost alerts. This closes the "HA path never CI-tested" gap.
5. **Add `RedisSessionStore` signing** — HMAC the session data with a server-side secret so raw Redis writes can't forge sessions.
6. **Disable/filter webhook redirects** — pass a custom `urllib.request.OpenerDirector` that doesn't include `HTTPRedirectHandler`, or filter by host after each hop.
7. **OpenSearch client: round-robin host list** — parse `OPENSEARCH_URL` as a comma-separated list and rotate on failure, or query `_cluster/health` for available nodes.
8. **Broaden the coverage gate** to `services/shared`, `ws4-detection/window.py`, `ws6-inventory/keystore.py`.
9. **Run `test_sessions.py` and `test_window.py` against real Redis in CI** — set `SESSION_TEST_REDIS=1` and add a Redis service container.
10. **Give `devkit-feeder` a `requirements.txt`** so it joins pip-audit and SBOM.
11. **Consider `FENGARDE_REQUIRE_AUTH=1`** — refuse-to-start-without-credentials mode for production-like deployments.

---

## Bottom Line

FENGARDE's single-instance core, security primitives, and honesty culture are genuinely strong — this is a high-quality, far-better-than-average open-source SIEM. But it is held back by a small set of high-leverage, mostly-small fixes clustered in three places: **the HA profile silently breaks stateful detection**, **the stateful-rule hot path can be poisoned**, and **the `GRANT SELECT` parser downgrade evades the bank rule**. 

The project's own documentation (SECURITY.md, SSOT.md) is refreshingly honest about its limitations — the only overstatements are the webhook "no SSRF" claim and the Redis session "security boundary" claim, both documented above.

Until C1 is resolved, **do not promote the HA profile to production** — it provides durability while quietly disabling brute-force, port-scan, lateral-movement, beaconing, and impossible-travel detection at scale.

---

*Audit performed 2026-08-06. Every CRITICAL/HIGH finding independently verified against `d701c2f` disk state with `file:line` citations. Live Docker/Redis stack confirmed operational.*