# FENGARDE — Swarm Review: Security, Logic, Code Quality & Intent

**Repo:** `github.com/supermhel/fengarde` (Apache-2.0 open-source SIEM)
**HEAD:** `d701c2f` (2026-08-05) · **Scale:** ~31.8k LOC Python, 7 workstreams, 17 parsers, 28 rules
**Method:** 5 independent parallel reviewer swarms (security / detection-logic / parsers / architecture / code-quality), each reading current disk state (existing review docs treated as claims, not truth), then **every flagship finding independently re-verified by me against the code**. Several defects were *empirically reproduced* (executed) by the swarms, not just read.

---

## Executive Summary

FENGARDE is a genuinely well-engineered SIEM — **well above the typical open-source bar**. Constant-time auth compares, parameterized SQL everywhere, fail-closed detection posture, honest tenant-namespacing that survived red-team scrutiny, and a security doc that openly discloses its own limitations. The redelivery/DLQ/trim-acked machinery in `bus.py` is best-in-class for an OSS project.

**But the flagship claims hide silent failures.** The single most important finding (independently confirmed): **the HA profile — the feature the SSOT makes its strongest "proven live" claims about — silently disables all stateful detection.** And the security posture's dominant risk is the *legitimate but dangerous* default-open stance plus two **undocumented** gaps (webhook redirect-following, raw Redis sessions).

### Overall Composite Grade: **B−**

Breakdown by facet:

| Lens | Grade | One-line characterization |
|---|---|---|
| **Implementation hygiene** (auth/tenancy/error-handling) | **A−** | constant-time, parameterized, fail-closed, honest |
| **Intent honesty** (code vs. docs) | **B+** | two docs overstate (SSRF, Redis-session boundary) |
| **Detection-logic correctness** (WS-4 + rules) | **B−** | poison-pill risk + 6 medium logic defects |
| **Parser / data integrity** (WS-2) | **B−** | 1 real detection hole (`GRANT SELECT`), 2 crash paths |
| **Architecture / reliability** | **B** | A-grade single-instance core, C-grade HA |
| **Effective auth/tenancy posture** | **D** | everything lapses to open/merged by default |
| **Code quality & supply-chain** | **B+** | honest stubs, but security paths are the least-gated |

---

## HEADLINE FINDINGS (independently verified)

### 🔴 CRITICAL — C1: HA profile silently disables every stateful detection rule
`services/ws4-detection/main.py:314` attaches the distributed `RedisWindowCounter` **only** when `BUS_BACKEND == "redis"` (exact match). But `infra/docker-compose.ha.yml:400` sets `BUS_BACKEND=redis-sentinel` for ws4 in the HA profile. So under HA:
- Every stateful rule (brute-force, port-scan, lateral-movement, password-spray, beaconing, impossible-travel) falls back to the **per-process** `DequeWindowCounter`.
- With ≥2 WS-4 replicas — the entire point of HA — the same group's count is split across replicas → **threshold is never reached → these detections never fire**, silently.
- Compounding: even if the gate were broadened, the client is built from `REDIS_URL` (`main.py:318`) which HA never overrides and which points at a hostname that doesn't exist in the HA profile.

This is the exact failure `window.py:4-12` says the Redis counter exists to prevent. **Not a crash — a silent detection blackout in the very deployment the profile targets.** I verified both sides of this independently.

### 🟠 HIGH — Engine poison-pill: malformed rule numerics hang detection
`engine.py:654` `window_ms = self.window_seconds * 1000` and `:680` `count >= self.threshold` run **outside** the condition-phase try/except (`:509-513`); `window_seconds`/`threshold` are unvalidated `Optional` from YAML. A rule with `window_seconds: "60"` or `threshold: "10"` (string) raises an uncaught `TypeError` → message left unacked → **infinite redelivery → consumer jams → every event behind it is never detected**. `validate_rules.py` would catch it but is a separate tool **not wired into load or CI**. Reachable via hot-reload edits or any plugin rule-pack.

### 🟠 HIGH — `GRANT SELECT` silently downgraded → bank priv-esc evasion (reproduced)
`db_audit.py:39-51` — `_OP_MAP` iterates select-first, matches by substring. `operation="grant select"` hits `"select"` first → emitted as `activity_id 1 / severity 1` (read/INFO) instead of `5/CRITICAL`. **Reproduced live:** `GRANT SELECT → activity 1, severity 1`. The `bank_db_priv_esc` rule targets class 6005 `activity_id 5` — so a privilege grant phrased with a subordinate verb **silently evades the rule and the severity floor**.

### 🟠 HIGH — `BUS_BACKEND=redis-sentinel` + `== "redis"` gate (root cause of C1, tracked separately above)

---

## Consolidated Finding Tally (all five swarms)

| Severity | Security | Detection | Parsers | Architecture | Code-qual | **Total** |
|---|---|---|---|---|---|---|
| **CRITICAL** | 0 | 0 | 0 | 1 (HA detection break) | 0 | **1** |
| **HIGH** | 3* | 1 | 1 | 3 | 4 | **12** |
| **MEDIUM** | 3 | 6 | 4 | 5 | 9 | **27** |
| **LOW** | 3 | 6 | 4 | 4 | 6 | **23** |
| **INFO** | 12 | 5 | 0 | – | 13 | **30** |

\*Security HIGHs are all *documented/accepted* posture (default-open APIs, disabled OpenSearch plugin, spoofable syslog), not silent bugs — see Area 1 below.

---

## Area 1 — Security (grade: C+; implementation hygiene A−, posture D)

### Real, non-documented gaps
- **W1 (MED, confirmed)** — Webhook dispatcher follows HTTP redirects: `webhooks.py:154-157` uses default `urlopen` w/ `HTTPRedirectHandler`. A configured/compromised receiver returning `30x` pivots delivery to any internal host (`http://opensearch:9200`, `169.254.169.254`…), carrying the HMAC-signed alert doc. **Contradicts SECURITY.md §9's "No SSRF surface" claim** (docs overstate).
- **A1 (MED, confirmed)** — Redis session backend is raw/unsigned: `sessions.py:132-143` pure `HGETALL`, no server-side signature. Anyone who can write an unauthenticated Redis (the default) can `HSET` an `admin`/`*`-tenant session and mint full admin. SECURITY.md calls Redis sessions "a security boundary" but it isn't cryptographically enforced.

### Documented/accepted (honest, but dominant risk)
- **D1 (HIGH, claimed-accurate)** — API-key auth OFF by default: `authz.py:23-25` unset env = every request allowed, one warning. WS-3 triage R/W, WS-6 inventory R/W, alerts/events/rules all open in default install.
- **D2 (HIGH)** — OpenSearch security plugin disabled; mitigation is network-boundary only.
- **D3 (MED)** — Syslog UDP `0.0.0.0:5514`, spoofable, token-bucket-sheddable → log forgery / detection poisoning / triage & LLM poisoning.

### Confirmed GOOD
- Password/API-key hashing sound (scrypt + HMAC-pepper, constant-time, decoy-timing). Tenant window/alert-key namespacing authentic (`_namespaced_group` length-prefix defeats crafted collisions). WS-6 store fully parameterized + `(tenant_id, mac)` PK. Rules/`tenants` path handling hardened (no taint-to-path). LLM verdict enum-clamped, advisory-only. mcp_agent regex-safe.

---

## Area 2 — Detection Engine & Rules (grade: B−)

- **HIGH** unguarded stateful arithmetic (poison-pill) — see headline.
- **MED** `class_uid=None` event double-includes the catch-all bucket (`main.py:153`); score summed twice, 2 alerts, spurious LLM enqueue. Latent (all 28 shipped rules carry `class_uid`), triggered by any plugin catch-all rule.
- **MED** `not_in` allowlist fail-posture documented backwards: docstring/warning say "fail CLOSED (never match)" while code is fail-**OPEN** (a broken allowlist makes the rule *keep firing* = noise flood, misread as false-negative).
- **MED** LLM funnel floods per-event once a hot high-severity rule crosses `llm_min` — one LLM call per matching event, not per unique alert (10k-spray ≈ 9,990 calls).
- **MED** Sigma importer silently narrows unescaped regex `.` to a literal glob `.` → imported rule is a false-negative with no warning.
- **MED** several shipped rules ship "live" with empty allowlists (near-constant noise).
- **LOW** clock-skew guard silently drops stateful detection for legitimately forward-skewed hosts; `member=str(now)` ms-collision undercount; ghost `_live_members` entry; `dc_mass_vm_delete` not source-scoped.
- **Verified GOOD:** window-counter core correct, Redis/deque parity holds, tenant+rule keying correct, no off-by-one, prior 5 known bugs fixed completely, ReDoS-safe glob/contains.

---

## Area 3 — Parsers & Data Integrity (grade: B−)

- **HIGH** `GRANT SELECT` downgrade (reproduced) — see headline.
- **MED** `.lower()` crash on non-string `operation` in `db_audit.py:71` / `vmware_vsphere.py:69` → bounded single-record loss (per-record guard contains it), but the flagship fuzz suite fails to catch it.
- **MED** `inventory_diff.py:89-95` bypasses `to_epoch_ms` — epoch-seconds/FILETIME `seen_at` mis-scales time (reproduced: `1577836800 → 1970`), breaking OT correlation.
- **MED** fuzz blind spot: `test_property_hardening.py` builds random-keyed dicts, so hostile `operation`/`port`-type values are almost never generated; all 17 parsers "pass 100 fuzz examples" yet the crash reproduces by hand.
- **MED/LOW** `test_parser_hardening` etc. pass; `timeutil` correct but not uniformly applied (6 syslog-text parsers still on old one-liner); sanitize `_FREE_TEXT_PATHS` omits `unmapped.*`/`api.request.data`.
- **Verified GOOD:** registry routing source_type-authoritative + dead-letters on ambiguity; `status_from_outcome` never masks failures; OCSF/type_uid invariants hold; A5 enrichment correctly additive & fail-open.

---

## Area 4 — Architecture & Reliability (grade: B; single-instance A, HA C)

- **CRITICAL** HA disables distributed stateful detection (headline C1).
- **HIGH** OpenSearch "3-node HA" is HA to no one that matters: `opensearch.py` holds one connection to `opensearch-1` only, no failover → losing one node stalls all writes while `_cluster/health` is green ("cluster green, app dead").
- **HIGH** Redis failover loses the acked-but-unreplicated tail (no WAITAOF/MIN-REPLICAS); contradicts SSOT "0 lost" claim; producer only re-produces on exception.
- **HIGH** No automated HA regression gate: Sentinel/3-node/primary-kill never exercised in CI or `test-live`.
- **MED** UDP ingest_id is random UUID → deterministic dedup is dead code for UDP; racy loss counters under the 4-worker pool; spool cleartext unencrypted; unauthenticated UDP surface; DLQ is inspection-only (acked = gone forever).
- **Verified GOOD:** zero cross-workstream imports holds; idempotent storage (explicit `_id`, daily index from event time) correct; CAS + in-process lock sound; Sentinel config correctness solid; `/health` 503 + Prometheus correct.

---

## Area 5 — Code Quality, Testing & Supply-Chain (grade: B+)

- **HIGH** The only percentage coverage gate excludes every security-critical module (only WS-2/WS-3); `sessions/runner/bus/window/keystore` unprotected; gate measures *execution*, not *assertion* — gameable by non-asserting tests (already drifted once).
- **HIGH** Redis session & window backends never hit real Redis in CI (opt-in flags never turned on, hand-rolled fakes) — a real behavioral bug in either would pass green CI.
- **HIGH** `devkit-feeder`'s `redis==5.0.8` is inline-pinned with no requirements.txt → invisible to pip-audit **and** SBOM.
- **MED** mypy runs at default (loose) strictness — untyped security functions pass cleanly; version skew `redis 5.0.8` vs `8.1.0`; `|| true` on pip installs makes docker-build gate fail-open.
- **Verified GOOD:** honest stubs (never labeled working), zero bare `except:`, fail-closed keystore/session-factory, action-pin/actionlint gate is best-in-repo and non-gamable, digest-pinned base images, clean CI secrets.

---

## Priority Fix Order (highest leverage first)

1. **Treat `"redis-sentinel"` (and any non-`memory`) as distributed** in `ws4/main.py:314`; build the window counter off a Sentinel-aware client, not `REDIS_URL`. *(Closes the CRITICAL.)*
2. **Guard/wrap the stateful arithmetic in `evaluate()`** and enforce rule-field type validation at `load_rules`/CI. *(Closes the poison-pill.)*
3. **Fix `db_audit` `_OP_MAP`** — check `grant/revoke/alter/create user` before read/write verbs (or exact-match). *(Closes the priv-esc evasion.)*
4. **Add an HA regression job** to CI / `make test-live`: bring up `docker-compose.ha.yml`, kill `redis-1` mid-stream, assert no-loss/no-dup + a stateful rule still fires.
5. **WS-3 OpenSearch client:** round-robin / `_cluster/health`-aware host list (stop single-URL pin).
6. **Disable/filter webhook redirects** + **sign Redis sessions** (or strengthen their threat-boundary text + default `REDIS_PASSWORD`).
7. **Broaden the coverage gate** to `services/shared`, `ws4-detection/window.py`, `ws6-inventory/keystore.py`; run `test_sessions.py`/`test_window.py` real-Redis in CI.
8. **Give devkit-feeder a requirements.txt** so its deps join pip-audit + SBOM.
9. Default-open: consider a `FENGARDE_REQUIRE_AUTH=1` refuse-to-start-without-credentials mode.

---

## Bottom Line

FENGARDE's **single-instance core, security primitives, and honesty culture are genuinely strong** — this is a high-quality, far-better-than-average open-source SIEM. But it is a **B− overall**, held back by a small set of high-leverage, mostly-small fixes clustered in exactly three places: the **HA profile silently breaks stateful detection**, the **stateful-rule hot path can be poisoned**, and the **`GRANT SELECT` parser downgrade evades a bank rule**. None require architectural rework; all are local, verifiable fixes. Until C1 is resolved, **do not promote the HA profile to production** — it provides durability while quietly disabling brute-force/port-scan/lateral-movement/beaconing detection at scale.
