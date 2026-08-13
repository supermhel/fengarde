# FENGARDE for MSSPs — quickstart

**Draft — not yet linked from README or announced.** Written to be reviewed before it's
public; see the open question at the bottom before treating this as final.

## Who this is for

You run a managed security service and want to offer SIEM/detection to your customers
without a Splunk-scale contract or an SSPL-style license that blocks reselling. FENGARDE
is Apache-2.0 — you can deploy it, white-label it, and run it for as many customers as
you want, today, with no registration and no fee. This doc is about doing that well, not
about permission you don't already have.

## What's actually real for a multi-customer deployment

Everything below is code-verified, not aspirational (see `SSOT.md` in this repo for the
proof trail if you want to check any of it yourself):

- **Real multi-tenancy**, not a single shared pool with a filter bolted on: `tenant_id` is
  threaded from collector through normalization, detection, and indexing. Each tenant's
  alerts/events land in their own OpenSearch indices. Proven by
  `tools/test_multi_tenant_isolation.py`.
- **Per-tenant rule enablement** — `contracts/tenants/<tenant_id>.yml` lists rule ids
  disabled for one tenant; every tenant gets the full global rule set unless you opt them
  out of specific rules. See [contracts/tenants/README.md](../contracts/tenants/README.md).
- **Per-tenant credentials on WS-6 (inventory)** — `services/ws6-inventory/manage_keys.py`
  provisions/revokes/lists scoped API keys per tenant, hashed at rest (HMAC-SHA256 keyed
  by a server-side pepper — scrypt was tried first and replaced; see `keystore.py`'s
  module docstring for why a memory-hard KDF is the wrong primitive for a high-entropy
  random token), never logged in plaintext after issuance. Rotation is provision-new →
  cutover → revoke-old, no forced downtime.
- **Per-tenant users and roles** — the opt-in RBAC layer (`FENGARDE_RBAC_DB`) has a real
  `tenant_id` column on every user; your customer's analysts can get their own logins
  scoped to their own tenant, not a shared account.
- **Outbound webhooks per tenant** — `contracts/webhooks/<id>.yml` supports an optional
  `tenant_id` filter, so you can route one customer's alerts to their ticketing/SOAR
  system without touching another customer's config. HMAC-signed, see
  [docs/webhooks.md](webhooks.md).
- **A real plugin mechanism** if you need a source parser or rule pack specific to one
  vertical — a separate installable Python package via entry points, no fork required.
  See [docs/plugin-development.md](plugin-development.md).
- **Backup/restore and schema migration** for the one persistent local datastore (the RBAC
  DB) plus your `contracts/` customizations — see [docs/ops-lifecycle.md](ops-lifecycle.md).

## Onboarding one new customer, end to end

1. Decide their `tenant_id` (a short slug, e.g. `acme`). Whatever sets it upstream — a
   dedicated collector instance, or `meta["tenant_id"]` on ingest — needs to set it
   consistently; there's no correction step downstream.
2. (Optional) If this customer needs fewer rules than the global set — e.g. no OT rules
   for a pure-office customer — add `contracts/tenants/acme.yml` with their
   `disabled_rules` list.
3. Provision their WS-6 inventory key: `python manage_keys.py provision acme`. Store the
   printed key now — it's shown once.
4. (Optional) If they have their own RBAC users: `create_user(..., tenant_id="acme")`
   against the RBAC DB (see `services/shared/users.py`), or your own provisioning wrapper
   around it — there's no CLI for this yet, see the gap list below.
5. (Optional) If they want alerts routed to their own ticketing/SOAR: add
   `contracts/webhooks/acme-ticketing.yml` with `tenant_id: acme`, set the HMAC secret as
   an env var, restart `ws3-indexer`.
6. Put TLS in front of the dashboard if they'll reach it remotely —
   [docs/deployment.md](deployment.md) has a ready-to-use Caddy config.

## White-labeling — honest scope

Apache-2.0 permits you to rebrand freely — rename it, restyle it, ship it under your own
product name. **There is no built-in multi-brand theming system today.** Rebranding means
forking the dashboard's static assets (`services/ws7-dashboard/`) and changing them
yourself, the same way you'd rebrand any open-source project's frontend. If you need to
run visually distinct instances per customer, that's per-deployment asset changes, not a
config flag.

## Gaps worth knowing before you commit to a customer SLA

Stated plainly, not smoothed over — same disclosure standard this project applies to its
own technical claims:

- **Per-tenant fairness is order-bounded, not compute-isolated.** Rate-limiting at the
  syslog listener is per-tenant (proven). Downstream, WS-4 detection and WS-5 AI triage now
  round-robin each consume batch by tenant (`services/shared/fairness.py`, default on) so a
  flooding tenant can no longer occupy every consecutive turn ahead of another tenant — but
  the underlying consumer is still one thread processing one message at a time, so total
  throughput is still shared. A large enough flood still adds latency for everyone, just no
  longer disproportionately to the quiet tenant specifically. If a customer's SLA needs true
  compute isolation (not just fair ordering), plan tenant-per-deployment for them rather
  than relying on this.
- **No tenant-provisioning admin UI.** Everything above is a CLI/YAML-file workflow. There
  is no dashboard "add a customer" wizard yet.
- **OpenSearch's own high-availability profile (3-node) has never been live-failure-tested.**
  Redis/Sentinel HA has been (kill-tested, proven). If uptime-under-node-failure is part of
  your customer promise, verify this yourself before relying on it, or ask what's changed
  since this doc was written.
- **WS-5 AI triage is single-threaded.** Under heavy multi-tenant incident load it becomes
  the throughput ceiling for LLM-based triage specifically (rule-based detection is
  unaffected).

## Running this for customers today

Nothing above requires registering anywhere — Apache-2.0 gives you these rights already.
If you'd like a relationship channel (a name on a partner list, MSSP-specific doc
updates, optional co-marketing — no legal weight, no fee), open an [MSSP partner
registration issue](../../../issues/new?template=mssp_partner_registration.md).

## Status

Per-tenant fair consume ordering (the must-fix-before-outreach item) landed
2026-08-07 — see the gap list above for its real, bounded scope. This doc is still
unlinked from README pending your own review of its content, not any remaining
engineering blocker.
