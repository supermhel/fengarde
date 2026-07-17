---
tags: [fengarde, milestone, status/green]
milestone: M4
version-target: v0.6.0
role: the launch gate
---

# M4 — MSP-grade (the launch gate)

PLAN_C Tier 3. Parent: [[Home]]. **Done 2026-07-16**, and this is the hard gate for
[[M6-Launch-Readiness]] (M5 is preferred in the launch narrative but not required).

## What shipped (all done, all gated by a real test)

- **Multi-tenancy (M4.1)** — `tenant_id` threaded collector→WS-2→WS-4→WS-3.
  Non-`default` tenants get their own `events-{family}-{tenant}-{date}` /
  `alerts-{tenant}-{date}` indices; the `default` tenant (every pre-M4 deployment)
  keeps the exact old naming, zero migration. Per-tenant rule enablement via
  `contracts/tenants/<id>.yml`. Gate: `tools/test_multi_tenant_isolation.py`.
  **Explicitly not built**: true OpenSearch Data Streams API, per-tenant retention
  override, per-tenant allowlist customization.
- **RBAC (M4.2)** — opt-in via `FENGARDE_RBAC_DB`. `UserStore` (SQLite,
  scrypt-hashed passwords), `SessionStore` (in-memory, 8h TTL), `role_at_least()` /
  `can_access_tenant()` (fail-closed on unrecognized role/tenant), `LoginRateLimiter`.
  Cross-tenant access returns 404 never 403. First-boot admin gets a random
  printed-once password — no default credential ever. **Explicitly not built**: TLS
  anywhere, multi-replica session sharing (in-process only), WS-6 inventory API RBAC
  coverage (WS-6 stays API-key-only).
- **Versioned REST API (M4.3)** — `contracts/triage-api.yaml` (OpenAPI 3.1), every
  route reachable bare and under `/api/v1/...`. Three new read endpoints
  (`/alerts`, `/events`, `/rules`), all tenant-scoped and forced to the caller's own
  session tenant for non-admins. `GET /rules` deliberately never returns a rule's raw
  `condition` — no rule-write endpoint at all, by design (SECURITY.md §3).
- **Outbound webhooks (M4.4)** — opt-in via `contracts/webhooks/*.yml` (ships
  empty). HMAC-SHA256 signed, own consumer group (never delays indexing), bounded
  retries (4xx permanent, 5xx/connection-error retried).
- **Plugin interface (M4.5)** — `fengarde.parsers` / `fengarde.rule_packs` entry
  points, collision-safe by construction (built-in always wins). No sandboxing —
  plugin code runs at full trust, same posture as rule files.
- **Ops lifecycle (M4.6)** — SQLite schema migration via `PRAGMA user_version`,
  versioned OpenSearch index templates + `tools/migrate_opensearch.py`, scripted
  backup/restore (`tools/backup.py`/`restore.py`), disk-headroom guardrails.
  **A real gap found and disclosed while building this**: OpenSearch ILM/retention
  policies were never actually installable on a live cluster — the policy file is
  written in Elasticsearch ILM syntax, but this stack runs OpenSearch ISM, a
  different schema at a different endpoint. Tracked as an open item, not silently
  worked around — needs a live cluster to fix correctly.

## Post-plan: the adversarial bug hunt found real holes in this surface

See [[Adversarial-Bug-Hunt]] — F1–F6 were all found in the M4/M5 code paths above
(tenant isolation, RBAC, ops lifecycle). All fixed and regression-tested.

## Open

- ILM/ISM policy schema mismatch (see Ops lifecycle above) — needs a live cluster.
- Everything under "explicitly not built" above is real and disclosed, not silently
  dropped — see [[Open-Items]].

## Gate (from the plan)

> Two-tenant test green ✅; RBAC gate green ✅; OpenAPI published ✅; webhook HMAC
> gate green ✅; plugin discovery gate green ✅; users.db migration gate green ✅;
> OpenSearch template migration gate green ✅ (fake-transport level); backup/restore
> gate green ✅ (real files); disk-headroom gate green ✅ (real filesystem).

**Met.** M4 is fully done — this is the one hard M6 gate that's actually green.
