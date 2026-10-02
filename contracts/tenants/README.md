# Per-tenant rule enablement (M4 multi-tenancy)

One optional file per tenant: `<tenant_id>.yml`, listing rule ids DISABLED
for that tenant (`disabled_rules`) and, for default-off rules, ids the tenant
opts in to (`enabled_rules`). A tenant with no file here gets every global rule
(`contracts/rules/*.yml`) — missing config never silently reduces detection
coverage, same convention as `contracts/allowlists/`.

```yaml
# contracts/tenants/acme.yml
disabled_rules:
  - 6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01   # common_bruteforce.yml's id
```

## Default-off rules and per-tenant opt-in

A rule that ships with `siem.default_enabled: false` is NOT evaluated for any
tenant until that tenant opts in. Today that is
`ot_opcua_write_unauthorized_node` (`e7a14b6d-3c52-4d90-8f1b-5a9c0d2e6b47`): its
node allowlist ships empty, so enabling it before populating the list alerts on
every OPC UA write. Opt in per tenant with `enabled_rules`:

```yaml
# contracts/tenants/acme.yml
enabled_rules:
  - e7a14b6d-3c52-4d90-8f1b-5a9c0d2e6b47   # ot_opcua_write_unauthorized_node.yml
```

Rules of the road:

- **Opt-in is explicit.** A missing, unreadable or malformed tenant file (or an
  `enabled_rules` that is not a list) never turns a default-off rule ON, and never
  turns a default-on rule off.
- **`disabled_rules` wins.** A rule listed in both `disabled_rules` and
  `enabled_rules` is OFF for that tenant.
- Listing a default-ON rule in `enabled_rules` is a harmless no-op.
- A `companion_of` rule whose sibling is default-off is itself default-off; opting
  in the sibling does not opt in the companion (list it too).
- Single-tenant installs can skip the tenant file: set the environment variable
  `FENGARDE_OPT_IN_RULES=<rule id>[,<rule id>...]` on the WS-4 detection service to
  opt those rules in for every tenant. (`Detector(opt_in_rules=[...])` does the
  same in tests and the eval harness.)
- Edits to a tenant file are picked up by the hot-reload watcher, no restart.
- `GET /rules` (WS-3) reports `default_enabled`, `opt_in` and the resulting
  `enabled` per tenant so the dashboard can say why a rule is off.

`tenant_id` comes from envelope v1 (`siem.tenant` on events, `tenant_id` on
alerts — see `services/shared/envelope.py` and `contracts/bus-topics.md`'s
"Envelope v1" section). Loaded and cached by
`services/ws4-detection/tenants.py::load_disabled_rules()`, consumed by
`Detector.process()` in `services/ws4-detection/main.py`.

This directory ships empty (no tenant files) — every deployment's events
carry `tenant_id: "default"` unless something upstream (a per-customer
collector, an explicit `meta["tenant_id"]` override) sets it otherwise, and
`default` has no config file here either, so nothing changes for a
single-tenant install.

This is an ENABLEMENT list, not a full per-tenant rule-pack system: every
tenant shares the same global rule set and condition logic, just a
different enabled/disabled subset. See
`tools/test_multi_tenant_isolation.py` for the proof this actually changes
detection behavior between two tenants on one shared stack.
