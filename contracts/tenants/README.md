# Per-tenant rule enablement (M4 multi-tenancy)

One optional file per tenant: `<tenant_id>.yml`, listing rule ids DISABLED
for that tenant. A tenant with no file here gets every global rule
(`contracts/rules/*.yml`) — missing config never silently reduces detection
coverage, same convention as `contracts/allowlists/`.

```yaml
# contracts/tenants/acme.yml
disabled_rules:
  - 6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01   # common_bruteforce.yml's id
```

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
