---
tags: [fengarde, milestone, status/yellow]
milestone: M3
version-target: v0.5.0
---

# M3 — Product completeness

PLAN_A gaps, runs parallel to M1/M2. Parent: [[Home]]. See also [[Open-Items]].

## Done

- **Agent rule pack complete** — R4 (`agent_egress_non_allowlisted_domain.yml`) and
  R5 (`agent_destructive_command.yml`) join R1–R3. All 5 rules proven firing on real
  `mcp_agent` parser output, including R1+R3 together on one session log.
- **`tools/agent_log_shipper.py`** — the missing real ingestion path for MCP/agent
  JSONL logs (file, `--follow`, or stdin) into `raw.events`. Found while writing the
  monitoring doc that this didn't exist yet.
- **`docs/agent-monitoring.md`**, **`docs/deployment.md`** (reverse-proxy TLS via
  Caddy — documented as a pattern, not enforced/tested), **`docs/vs.md`** (honest
  FENGARDE vs Wazuh/Elastic Security/Security Onion comparison), new-rule issue
  template.

## Open — verified by direct filesystem check, not just the plan text

- **Dashboard session-login UI is NOT wired.** [[M4-MSP-Grade|M4.2's RBAC]] built a
  real `/auth/login` / `/auth/logout` / `/auth/me` API on the WS-3 triage port with
  scrypt-hashed passwords, sessions, and a first-boot random admin credential — but
  grepping `services/ws7-dashboard/` for any reference to `/auth/login` or a login
  form returns nothing. The RBAC *backend* is real and tested; the dashboard *UI*
  still has no login screen calling it.
- **CSRF pass — not done.** No `csrf` reference anywhere in `services/shared/` or
  the WS-3 triage API. Named in the plan as an M3 item, never implemented.
- Clean-machine timed quickstart validation (the unchecked launch-checklist
  prerequisite) — not run.
- **v0.5.0 has not been cut** as a signed release tag — the plan calls for this at
  the end of M3; still pending.

## Gate (from the plan)

> PLAN_A Phase 1/2/3 acceptance criteria all met; `make test` + both e2e paths green.

**Partially met** — `make test` and both e2e paths are genuinely green (verified this
session), but the dashboard-login/CSRF/release-cut items above are real gaps, not
just unconfirmed claims.
