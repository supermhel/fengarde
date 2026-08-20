# FENGARDE — Architecture Review (Adversarial Swarm Pass)

**Reviewer role:** Architecture (security/network/SIEM specialist lens)
**Date:** 2026-07-29
**Scope:** module boundaries, data flow, coupling, scalability, ingestion → normalization → detection → indexing/alerting layering, multi-tenant isolation.
**Method:** direct code reading (`services/**`, `contracts/**`, `infra/docker-compose.yml`), cross-checked against `SSOT.md` and the prior `docs/superpowers/specs/2026-07-02-fengarde-architecture-review.md`. Every finding below cites the file/line it's grounded in; nothing is repeated from the older review without independently re-verifying it against current code first.

---

## 1. Verdict

The bus-only, OCSF-only, stateless-worker architecture (ADR 001/002/004) is real and still holds under a fresh grep (`from ws[0-9]`/`import ws[0-9]` across `services/**` returns one hit, and it's a comment in `ws3-indexer/rules_view.py` *asserting* the independence, not violating it). The v0.3 rule-prefilter fix and the M4 multi-tenancy work are genuine, code-verified improvements since the last review. The system is architecturally disciplined where it counts.

The gaps that remain are concentrated in three places: **infra-level single points of failure that no service-level discipline can fix** (Redis and OpenSearch), **one workstream that the multi-tenancy initiative never reached** (WS-6 inventory), and **compute-level tenant isolation** (data is isolated; CPU/Redis-ops/bus-throughput are not). None of this requires re-architecting the core; it requires finishing work that was scoped out or deferred, honestly, elsewhere in the docs.

---

## 2. What's well-designed (independently re-verified, not assumed)

- **Bus-only coupling holds.** Re-grepped `services/**` for cross-workstream imports myself — one match, and it's `ws3-indexer/rules_view.py`'s own comment explaining why it *doesn't* import `ws4-detection`'s `Rule` class, reading the same frozen contract files instead ([rules_view.py:3-7](services/ws3-indexer/rules_view.py)).
- **Rule-matching scales past O(all rules).** `Detector._load()` buckets rules by `class_uid` equality selection; `process()` only evaluates the candidate bucket plus the class_uid-agnostic catch-all ([main.py:84-92](services/ws4-detection/main.py), [main.py:120-136](services/ws4-detection/main.py)). This is the v0.3 B1 fix and it's real.
- **Stateful correlation is genuinely horizontally scalable.** `RedisWindowCounter` centralizes window state in Redis sorted sets via an atomic pipeline (ZADD/ZREMRANGEBYSCORE/ZCARD/EXPIRE) so every WS-4 replica sees the same global count ([window.py:197-224](services/ws4-detection/window.py)) — a local per-process deque would silently split counts across replicas and brute-force alerts would never fire under horizontal scaling. Wired in at startup ([main.py:271-284](services/ws4-detection/main.py)).
- **Tenant isolation on the detection path is real and was hardened twice.** The window-counter key is tenant-namespaced ([engine.py:503-513](services/ws4-detection/engine.py)), and — after an adversarial follow-up caught that the *counter* was namespaced but the *returned alert_id* wasn't — both the stateful and non-stateful `alert_key()` branches now include tenant explicitly ([engine.py:415-477](services/ws4-detection/engine.py)). This F1/P1-1 fix is exactly the class of bug that matters for an MSP deployment (overlapping RFC1918 source IPs across customers), and the fix is in the code, not just a doc claim.
- **Delivery correctness is solved, not aspirational.** At-least-once + deterministic `alert_id` + real Redis PEL/XAUTOCLAIM redelivery + DLQ quarantine on unparseable entries ([bus.py:131-160](services/shared/bus.py), [runner.py:231-266](services/shared/runner.py)) — and this was chaos-tested live (`make chaos`: 40 scenarios, 5 services SIGKILLed mid-replay, zero lost/duplicated, per SSOT.md §1).
- **Kafka is now honestly scoped.** Both `bus.py`'s docstring and `contracts/bus-topics.md` explicitly say Kafka is a candidate for a future central tier, not implemented — the prior review's R-A doc-accuracy complaint is resolved.
- **RBAC/tenant read-scoping on WS-3 is real**, not just storage-layer: `triage_api.py` gates every alert/report read by `can_access_tenant(session.role, session.tenant_id, doc.get("tenant_id"))` and silently overrides a caller-requested `tenant_id` with the session's own for non-admin roles ([triage_api.py:205-263](services/ws3-indexer/triage_api.py)).
- **Retention is a real, tiered ISM design** (30d/90d/400d-PCI event tiers, 365d alerts), live-verified installing and auto-attaching via `ism_template` (SSOT.md §2).

---

## 3. Findings, ranked by severity

### [HIGH] F1 — WS-6 Inventory is the one workstream multi-tenancy never reached

`InventoryStore`'s schema has **no tenant column anywhere**: `assets(mac PRIMARY KEY, ...)`, `ip_history(mac, ip, ...)`, `protocols(mac, protocol)` ([store.py:37-60](services/ws6-inventory/store.py)). `app.py`'s HTTP routes (`GET /assets`, `GET /assets/resolve`, `POST /assets/upsert`) take no tenant parameter and apply no tenant filter anywhere ([app.py:90-141](services/ws6-inventory/app.py)); auth is a single shared `FENGARDE_API_KEY` bearer check with no per-tenant scoping (`authz.check_api_key`).

Contrast this with WS-3 (tenant-scoped indices + RBAC tenant gate) and WS-4 (tenant-namespaced window keys and alert ids, hardened twice via F1/P1-1). WS-6 was never touched by the M4 multi-tenancy pass or the F1-F6 adversarial bug hunt.

**Failure scenario:** two MSP customers sharing one `ws6-inventory` deployment (the only inventory deployment topology that exists — there's no per-tenant instance story) each report a device whose MAC happens to collide — plausible with locally-administered/randomized MACs, VM/container virtual NICs, or simply two customers on the same equipment vendor's OUI block reusing a serial-derived MAC in a lab/test segment. `upsert()` does a bare `SELECT ... WHERE mac=?` with no tenant predicate, so the second customer's observation **overwrites the first customer's asset record** ([store.py:89-117](services/ws6-inventory/store.py)) — silent cross-tenant data corruption, not an error. Separately, any caller holding the one shared API key can `GET /assets` and enumerate **every tenant's entire asset inventory** — hostnames, IPs, protocols, vendor — with zero isolation. For a SIEM whose whole pitch is per-tenant data separation, this is a real gap in the one place nobody looked.

**Recommendation:** either (a) add `tenant_id` to the schema + route/query layer, matching the WS-3/WS-4 pattern, before this is used in any multi-tenant deployment, or (b) explicitly document — the way `docs/superpowers/specs/2026-07-21-ha-design.md` already does for WS-6's SQLite-not-clustered status — that inventory is single-tenant-only today and must not be shared across customers. Silence is the actual risk here, not the gap itself.

### [HIGH] F2 — Redis carries three coupled responsibilities behind one uninstrumented single instance

`infra/docker-compose.yml` runs exactly one `redis:7-alpine` container ([docker-compose.yml:5-26](infra/docker-compose.yml)). That single instance is simultaneously: (1) the **only** message bus (every topic, every workstream), (2) the **only** correlation-state store (`RedisWindowCounter`'s sorted sets — the thing that makes brute-force/lateral-movement/impossible-travel detection stateful), and (3) — when `FENGARDE_SESSION_BACKEND=redis` is opted into — the RBAC session store. The B5 design doc (`docs/superpowers/specs/2026-07-21-ha-design.md`) recommends Redis Sentinel; per SSOT.md §1 that milestone is explicitly **"CLOSED — decision only, no code."** No Sentinel wiring exists in `docker-compose.yml`.

**Failure scenario:** Redis dies (OOM, host reboot, disk full on the AOF volume). In one event: ingestion stops (bus down — WS-1 can't produce, WS-2/3/4/5 can't consume), every in-flight correlation window is lost (a brute-force burst straddling the outage under-counts on recovery), and — if session backend is Redis — every logged-in analyst is instantly logged out. This is three independent failure *classes* (transport, application state, auth state) bundled into a single dependency with no automatic failover. The application layer did the hard part correctly (idempotent alert_id, PEL-based redelivery, tenant-namespaced state) — none of that protects against the shared substrate itself going away.

**Recommendation:** this is explicitly flagged in the project's own roadmap as a "conscious Phase-3 decision" (prior review R-B, SSOT's B5 entry) — the right ask here is not "build Sentinel now" but to make sure that decision doesn't keep sliding as a design-only doc while the compose file it's supposed to inform stays single-instance. Worth an explicit go/no-go from the owner on when this becomes real, not just decided.

### [MEDIUM] F3 — OpenSearch is also single-node, compounding F2

`opensearch` runs with `discovery.type=single-node` and `DISABLE_SECURITY_PLUGIN=true` ([docker-compose.yml:28-46](infra/docker-compose.yml)). Combined with F2, **the entire stack's durability rests on two uninstrumented single instances** with no automated failover for either. This is the same gap the 2026-07-02 review flagged (R-B) — restating it here because it's still true a month of feature work later, and because F2+F3 together (not just individually) define the actual blast radius: there is currently no tier of this deployment that survives a single-node failure of either component. Correct and accepted for the documented local/air-gapped tier; still open for the "central tier" the 3-tier roadmap describes.

### [MEDIUM] F4 — No compute/throughput isolation between tenants sharing one deployment

M4 isolates tenant *data* (separate OpenSearch indices, tenant-namespaced Redis keys) and now *read access* (WS-3 RBAC tenant gate), but every tenant sharing one deployment still flows through the **same** detection-engine process(es), the **same** bus topics, and the **same** global backpressure knob. The only ingest-edge shedding mechanism is a single global token bucket, `SYSLOG_MAX_EVENTS_PER_SEC` ([main.py:101-102](services/ws1-collectors/main.py)) — not per-tenant, not even per-source. There is no per-tenant rate limit, no per-tenant CPU/fairness scheduling on rule evaluation, and no per-tenant cap on Redis ops.

**Failure scenario:** in a shared MSP deployment, one tenant's compromised host generating a syslog flood (or simply a noisy, badly-configured device) consumes the shared token bucket, backs up the shared `normalized.events`/`scored.events` topics (watched only in aggregate by `start_depth_watchdog`, [runner.py:419-458](services/shared/runner.py)), and degrades detection latency for every *other* tenant on that deployment — with no isolation boundary to stop it and no per-tenant signal to attribute the backlog to its source. This is the standard "noisy neighbor" risk of a shared-tenancy control plane and it isn't discussed anywhere in the multi-tenancy docs (`contracts/tenants/README.md` only covers rule *enablement*, not resource fairness).

**Recommendation:** decide (don't necessarily build yet) whether the multi-tenancy story is "one shared deployment, many tenants" (needs per-tenant fairness/quotas — a real feature) or "one deployment per tenant, shared codebase" (no cross-tenant compute contention by construction, but no operational cost-sharing either). The current code is architecturally consistent with the *second* model (each rule/window/index-set already assumes isolation is a deployment choice) but the docs market the *first* model ("MSP-grade multi-tenancy"). That mismatch is worth resolving explicitly.

### [MEDIUM] F5 — No ingestion-edge redundancy story, undocumented

Exactly one `ws1-collectors` container binds the syslog UDP listener (port 5514, [docker-compose.yml:70-90](infra/docker-compose.yml)). UDP has no delivery guarantee back to the sender, so if this single container is down (crash, OOM, redeploy), every remote device sending logs during that window loses those events silently — `restart: unless-stopped` brings the container back, but there is no active/passive pair, no anycast/VIP, not even a documented acceptance of the gap the way Redis/OpenSearch single-instance status is written down in ADRs and SSOT. Given the project's own stated bar ("a bank cannot lose security events," `docs/superpowers/specs/2026-07-02...`'s R-C discussion), an undocumented gap at the literal front door of ingestion is worth calling out even though it's the least surprising of the single-instance findings.

### [MEDIUM] F6 — AI triage has no intra-replica concurrency; still a throughput ceiling

`shared/runner.py`'s model is one thread per topic per replica ([runner.py:386-397](services/shared/runner.py)); for WS-5, that means one `ai.requests` consumer thread per replica calls the LLM (Ollama or stub) **synchronously, one request at a time**. A slow/hung Ollama call blocks that entire thread until timeout; the only scale-out lever is adding whole WS-5 replicas, not concurrency within one. This is the same R-D finding from the 2026-07-02 review — re-verified against current `runner.py` and confirmed still true: nothing added a worker pool or async dispatch inside a replica since then. The buffered `ai.requests` topic correctly decouples this from the hot detection path (so it's not a correctness bug), but it is still the first ceiling under the "millions in → handful out" throughput story the docs describe.

### [LOW] F7 — Shipped Docker packaging silently defeats the hot-reload feature it advertises

`ws4-detection`'s Dockerfile `COPY`s `contracts/` into the image rather than volume-mounting it (self-disclosed in SSOT.md §1's B4 entry). The opt-in mtime-poll rule hot-reload (`RULES_RELOAD_INTERVAL_S`) is real code and works on a bare-host/bind-mount deployment, but the **only packaging this project ships** (`infra/docker-compose.yml`) never gets a live rule edit without an image rebuild. This is a deployment-topology inconsistency between what the feature docs promise ("edit a rule, it hot-reloads") and what the shipped `docker compose up` path actually delivers — already disclosed, but worth surfacing here as an architecture-packaging mismatch rather than purely a feature-completeness note.

### [LOW] F8 — Partition-key rationale is slightly overstated relative to how correctness is actually achieved

`contracts/bus-topics.md` says events are partitioned by `src_endpoint.ip` so stateful detection "runs without distributed locks" across workers. In the only backend that's actually deployed in production (`_RedisBus` + `RedisWindowCounter`), correctness of the window count does **not** depend on partition affinity at all — `RedisWindowCounter.hit()` is a single atomic Redis pipeline keyed by rule+tenant+group, so it would give the same correct global count no matter which worker/partition happened to receive the event ([window.py:210-224](services/ws4-detection/window.py)). Partitioning by source IP is still valuable (Redis op locality, no head-of-line blocking across unrelated hosts, useful if a future backend lacks a centralized atomic counter), but the contract doc's causal claim ("this is *why* correlation doesn't need locks") is slightly off from what the code actually relies on. Worth a doc tweak so a future reader doesn't assume partition affinity is a correctness requirement it isn't.

---

## 4. Scaling re-check (10x, current code vs. the 2026-07-02 baseline)

- **10x rules:** class_uid bucketing (B1, confirmed above) means this ceiling moved from "~50 rules" to whatever one class_uid bucket's rule count grows to — still single-threaded per event within a replica, so a very hot class_uid (e.g. auth events) with hundreds of rules is the next version of this problem. Not urgent at 27 rules.
- **10x tenants (not events):** F1 and F4 are the live ceilings — inventory correctness breaks (F1) and compute fairness breaks (F4) well before detection logic does.
- **10x events/sec:** unchanged from the prior review — WS-3 OpenSearch indexing and WS-5 LLM calls (F6) are the first ceilings; WS-4 itself scales via replicas + the global Redis counter.
- **Any single-instance failure (Redis or OpenSearch):** full-stack outage, not a degraded mode (F2/F3) — this is the ceiling that matters most for a security product's actual uptime SLA, more than raw throughput.

---

## 5. Summary table

| # | Finding | Severity | Status |
|---|---|---|---|
| F1 | WS-6 inventory has zero tenant isolation (schema, routes, auth) | HIGH | Open, unaddressed by M4 |
| F2 | Redis is a single instance serving 3 coupled roles (bus/state/sessions), no HA | HIGH | Open, design-only (B5) |
| F3 | OpenSearch single-node, compounds F2's blast radius | MEDIUM | Open, accepted for local tier |
| F4 | No per-tenant compute/throughput isolation on the shared pipeline | MEDIUM | Open, undocumented |
| F5 | No ingestion-edge (WS-1/UDP) redundancy, undocumented | MEDIUM | Open |
| F6 | WS-5 AI triage has no intra-replica concurrency | MEDIUM | Open, known since 2026-07-02 |
| F7 | Docker packaging defeats the shipped hot-reload feature | LOW | Disclosed, unfixed |
| F8 | Partition-key doc rationale overstates its necessity vs. actual Redis-backed correctness | LOW | Doc-accuracy only |

---

## 6. Bottom line

Nothing here says rebuild. The core (bus-only coupling, OCSF absorption at the edge, stateless workers with externalized state, idempotent delivery) is sound and the team has repeatedly hardened it under adversarial review (F1/F3/P1-1/P1-2 tenant-namespacing fixes are genuinely good work, verified in the code, not just claimed). The open items cluster in two honest categories: **infra HA that was consciously deferred to a "Phase-3 decision"** (F2/F3) and **one workstream (WS-6) that the multi-tenancy initiative simply didn't reach** (F1) plus its natural extension, compute-level tenant fairness (F4). Both are worth a deliberate decision from the owner — the same way B5's HA doc and the Kafka-honesty fix already got one — rather than continuing to accumulate as "known but not written down" gaps.
